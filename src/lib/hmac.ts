// 机器端点 HMAC 验签（P0-8 绑定通道），契约与竞猜系统 verifyPluginRequest / 插件
// utils/sync_sign.py 逐字一致（WHL-Daily-Activities-System/docs/astrbot-sync-api.md）：
//   X-Sign      = 小写 hex( HMAC-SHA256(secret, "METHOD|path含query|秒级ts|rawBody") )
//   X-Timestamp = Unix 秒字符串，±300 秒时钟偏差
// 用途隔离：这里验 BIND_SECRET（绑定专用密钥，不复用竞猜的 SYNC_SECRET——泄漏面隔离）。
import { timingSafeEqual } from "./util";

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
): Promise<boolean> {
  if (!secret || !tsHeader || !signHeader) return false;
  const ts = Number(tsHeader);
  if (!Number.isInteger(ts) || Math.abs(Math.floor(Date.now() / 1000) - ts) > SIGN_WINDOW_SECONDS) return false;
  const expect = await hmacHex(secret, `${method}|${pathWithQuery}|${ts}|${rawBody}`);
  if (signHeader.length !== expect.length) return false;
  return timingSafeEqual(expect, signHeader.toLowerCase());
}
