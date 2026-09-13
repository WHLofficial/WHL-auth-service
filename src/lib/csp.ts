import type { Context } from "hono";
import type { AppEnv } from "../env";
import { parseUris } from "./util";

/**
 * 基础策略：无脚本、只放行内联样式，表单默认只允许提交到同源。
 *
 * form-action 额外放行各 client 回调 origin 的原因（浏览器实测）：
 * Chromium 会把「表单提交触发的整条重定向链」都按 form-action 校验，
 * 登录表单 POST /login → 303 /authorize → 303 <client>/api/auth/callback，
 * 最后一跳是跨 origin 的，只写 'self' 时会被静默拦下——页面停在登录页、
 * 输入值还在、无任何可见报错，用户表现就是「登不上去」（而 auth 侧会话其实已建立）。
 * 白名单按 app 表里已注册的回调地址派生，本地与生产两套 client 自动覆盖，新增 client 无需改代码。
 */
const BASE_CSP = "default-src 'self'; style-src 'unsafe-inline'; form-action 'self'";
const TAIL_CSP = "; base-uri 'none'; frame-ancestors 'none'";

const TTL_MS = 60_000;
// 读库失败后的重试间隔：别让一次抖动把白名单状态冻结整个 TTL
const RETRY_MS = 5_000;

// isolate 级缓存：CSP 头每个响应都要写，避免每请求打一次 D1
let cache: { at: number; sources: string } = { at: 0, sources: "" };

/**
 * 从 app 表的注册地址取出 origin 白名单片段。
 * 读库失败时沿用上次成功结果（有的话）并在 RETRY_MS 后重试；从未成功过则退回只允许同源，
 * 也就是修复前的行为——登录跳不回 client，但不至于让页面失去全部限制。
 */
async function clientOrigins(c: Context<AppEnv>): Promise<string> {
  const now = Date.now();
  if (now - cache.at > TTL_MS) {
    try {
      const rows = await c.env.DB.prepare("SELECT redirect_uris, post_logout_redirect_uris FROM app").all<{
        redirect_uris: string;
        post_logout_redirect_uris: string;
      }>();
      const origins = new Set<string>();
      for (const row of rows.results) {
        for (const uri of [...parseUris(row.redirect_uris), ...parseUris(row.post_logout_redirect_uris)]) {
          try {
            const url = new URL(uri);
            // 只认 http(s)：其它协议的 origin 是字符串 "null"，塞进 CSP 只是无效源
            if (url.protocol === "http:" || url.protocol === "https:") origins.add(url.origin);
          } catch {
            // 注册数据里混进非法 URL 不该让整站策略失效
          }
        }
      }
      cache = { at: now, sources: [...origins].sort().map((o) => ` ${o}`).join("") };
    } catch (err) {
      console.error("读取 client 回调 origin 失败，form-action 沿用上次结果", err);
      cache = { at: now - TTL_MS + RETRY_MS, sources: cache.sources };
    }
  }
  return cache.sources;
}

/**
 * 只有 HTML 文档里可能存在表单，故仅对 HTML 响应派生 client origin；
 * 机器接口（/token、/userinfo、/jwks.json 等）保持最短策略，也不引入一次 D1 查询。
 */
export async function contentSecurityPolicy(c: Context<AppEnv>): Promise<string> {
  const isHtml = (c.res.headers.get("Content-Type") ?? "").includes("text/html");
  const extra = isHtml ? await clientOrigins(c) : "";
  return `${BASE_CSP}${extra}${TAIL_CSP}`;
}
