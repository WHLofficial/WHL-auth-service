// 机器端点共用门（原在 src/routes/machine.ts，增量 8 抽出供 routes/admin.ts 复用）：
// 限流 → 验签 → 取 raw body。契约与竞猜系统 verifyPluginRequest 逐字一致：
// X-Sign = HMAC-SHA256(secret, "POST|path|ts|raw")，path 含 query，只支持 POST。
import type { Context } from "hono";
import type { AppEnv } from "../env";
import { verifyBindSignature } from "./hmac";
import { rateLimit } from "./ratelimit";
import { clientIp } from "./util";

// 纵深防御（TEST_REPORT L-2）：HMAC 已把门，限流只用于挡签名密钥泄漏/插件失控后的高速滥用。
// 键按 CF-Connecting-IP（CF 边缘注入、外部不可伪造），所有机器端点共用一条 300/15min 的桶；
// 配额宽松是有意的——scripts/smoke-bind.mjs 连跑几轮不该被自己的限流卡住。
export async function machineAllowed(c: Context<AppEnv>): Promise<boolean> {
  return rateLimit(c.env, `machine:${clientIp(c)}`, 300, 900);
}

export async function machineGate(c: Context<AppEnv>): Promise<{ raw: string } | { err: Response }> {
  if (!(await machineAllowed(c))) {
    return { err: c.json({ error: "rate_limited", message: "请求太频繁，请稍后再试" }, 429) };
  }
  const secret = c.env.BIND_SECRET ?? "";
  if (!secret) return { err: c.json({ error: "server_error", message: "服务端未配置 BIND_SECRET" }, 500) };
  const raw = await c.req.text();
  const url = new URL(c.req.url);
  if (
    !(await verifyBindSignature(secret, "POST", url.pathname + url.search, raw, c.req.header("X-Timestamp"), c.req.header("X-Sign")))
  ) {
    return { err: c.json({ error: "bad sign" }, 401) };
  }
  return { raw };
}

export function parseJson(raw: string): Record<string, unknown> | null {
  try {
    const v: unknown = JSON.parse(raw);
    if (typeof v !== "object" || v === null || Array.isArray(v)) return null;
    return v as Record<string, unknown>;
  } catch {
    return null;
  }
}

export const str = (v: unknown) => (typeof v === "string" ? v.trim() : "");
export const int = (v: unknown) => {
  const n = Number(v);
  return Number.isInteger(n) ? n : null;
};
