// 机器端点 HMAC 验签（P0-8 绑定通道），契约与竞猜系统 verifyPluginRequest / 插件
// utils/sync_sign.py 逐字一致（WHL-Daily-Activities-System/docs/astrbot-sync-api.md）：
//   X-Sign      = 小写 hex( HMAC-SHA256(secret, "METHOD|path含query|秒级ts|rawBody") )
//   X-Timestamp = Unix 秒字符串，±300 秒时钟偏差
// 管理通道（v4.0.0）在 ts 与 body 之间多插一个 nonce：
//   "METHOD|path含query|ts|X-Nonce|rawBody"
// 绑定插件保持旧规范（无 nonce）以兼容存量部署；管理通道强制 nonce 并落库去重。
import type { Bindings } from "../env";
import { timingSafeEqual } from "./util";
import { nowIso } from "./util";

export const SIGN_WINDOW_SECONDS = 300;

async function hmacHex(secret: string, canonical: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(canonical));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function verifyBindSignature(
  secret: string,
  method: string,
  pathWithQuery: string,
  rawBody: string,
  tsHeader: string | undefined,
  signHeader: string | undefined,
  nonce?: string,
): Promise<boolean> {
  if (!secret || !tsHeader || !signHeader) return false;
  const ts = Number(tsHeader);
  if (!Number.isInteger(ts) || Math.abs(Math.floor(Date.now() / 1000) - ts) > SIGN_WINDOW_SECONDS) return false;
  const canonical = nonce
    ? `${method}|${pathWithQuery}|${ts}|${nonce}|${rawBody}`
    : `${method}|${pathWithQuery}|${ts}|${rawBody}`;
  const expect = await hmacHex(secret, canonical);
  if (signHeader.length !== expect.length) return false;
  return timingSafeEqual(expect, signHeader.toLowerCase());
}

/** 每日清理过期的 nonce 行；签名窗口外的 nonce 已无重放价值 */
export async function clearExpiredHmacNonces(env: Bindings): Promise<void> {
  await env.DB.prepare("DELETE FROM hmac_nonce WHERE expires_at <= ?").bind(nowIso()).run();
}
