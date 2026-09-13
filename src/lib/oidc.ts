import { SignJWT, calculateJwkThumbprint, jwtVerify, type JWTPayload } from "jose";
import type { Bindings } from "../env";
import { timingSafeEqual } from "./util";

/**
 * OIDC 签名核心（TECH_DESIGN §3/§8）：
 * - RS256，私钥只存 Worker Secret（AUTH_JWT_PRIVATE_KEY），JWKS 只发公钥；
 * - kid 取公钥 JWK 指纹（RFC 7638）自动派生：同一把密钥永远同一个 kid，换密钥即自动换 kid；
 * - 校验侧算法钉死 RS256，绝不信 token header 自带的 alg（防算法混淆）。
 */

type SigningKey = {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  kid: string;
  /** JWKS 输出：公钥三件套 + kid/use/alg，不含任何私钥分量 */
  publicJwk: { kty: "RSA"; n: string; e: string; kid: string; use: "sig"; alg: "RS256" };
};

// 密钥解析一次约几毫秒，按 isolate 缓存；secret 字符串本身作缓存键，换密钥自动失效
let cached: { src: string; key: SigningKey } | null = null;

function derFromPemOrBase64(src: string): Uint8Array {
  // 兼容三种形态：带 armor 的 PEM、单行 base64、带换行的裸 base64（wrangler secret 粘贴常见）
  const b64 = src.replace(/\s+/g, "").replace(/-----(BEGIN|END)[^-]*-----/g, "");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export async function signingKey(env: Bindings): Promise<SigningKey> {
  const src = env.AUTH_JWT_PRIVATE_KEY;
  if (!src)
    throw new Error(
      "AUTH_JWT_PRIVATE_KEY 未配置：本地放 .dev.vars（node scripts/generate-oidc-key.mjs 生成），生产 npx wrangler secret put",
    );
  if (cached?.src === src) return cached.key;
  const der = derFromPemOrBase64(src);
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    der,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    true, // 需要可导出，JWKS 才能从私钥推出公钥
    ["sign"],
  );
  const privateJwk = (await crypto.subtle.exportKey("jwk", privateKey)) as JsonWebKey;
  const { kty, n, e } = privateJwk;
  if (kty !== "RSA" || !n || !e) throw new Error("AUTH_JWT_PRIVATE_KEY 不是可用的 RSA PKCS8 密钥");
  // RSA-2048 起步：base64url 的 n 长度 ×3/4 ≈ 模长字节数，短于 256 字节（2048 位）直接拒绝
  if (n.length * 0.75 < 256) throw new Error("RSA 密钥强度不足（要求 ≥2048 位）");
  const bare = { kty, n, e } as const;
  const kid = await calculateJwkThumbprint(bare, "sha256");
  const publicKey = await crypto.subtle.importKey(
    "jwk",
    bare,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const key: SigningKey = {
    privateKey,
    publicKey,
    kid,
    publicJwk: { kty, n, e, kid, use: "sig", alg: "RS256" },
  };
  cached = { src, key };
  return key;
}

/** 签发 RS256 JWT：claims 原样进 payload，iss/iat/exp 由这里统一管 */
export async function signRs256(
  env: Bindings,
  iss: string,
  claims: Record<string, unknown>,
  ttlSec: number,
): Promise<string> {
  const key = await signingKey(env);
  const now = Math.floor(Date.now() / 1000);
  const payload: JWTPayload = { ...claims, iss, iat: now, exp: now + ttlSec };
  return new SignJWT(payload).setProtectedHeader({ alg: "RS256", kid: key.kid }).sign(key.privateKey);
}

export type VerifiedAccess = { sub: string; aud: string; scope: string; jti: string };

/** access token 校验：签名 + iss + 有效期（jose 内建），另要求 sub/aud/scope/jti 齐全 */
export async function verifyAccessToken(
  env: Bindings,
  iss: string,
  token: string,
): Promise<VerifiedAccess | null> {
  try {
    const key = await signingKey(env);
    const { payload } = await jwtVerify(token, key.publicKey, { issuer: iss, algorithms: ["RS256"] });
    if (
      typeof payload.sub !== "string" ||
      typeof payload.aud !== "string" ||
      typeof payload.scope !== "string" ||
      typeof payload.jti !== "string"
    )
      return null;
    return { sub: payload.sub, aud: payload.aud, scope: payload.scope, jti: payload.jti };
  } catch {
    return null;
  }
}

/** id_token_hint 校验（end_session 用）：只确认是本站签的，不校验 aud */
export async function verifyIdTokenHint(
  env: Bindings,
  iss: string,
  token: string,
): Promise<{ sub: string } | null> {
  try {
    const key = await signingKey(env);
    const { payload } = await jwtVerify(token, key.publicKey, { issuer: iss, algorithms: ["RS256"] });
    return typeof payload.sub === "string" ? { sub: payload.sub } : null;
  } catch {
    return null;
  }
}

/** back-channel 登出通知（OIDC Back-Channel Logout 1.0）：
 *  - 必带 events/jti + sid、sub 之一，绝不能带 nonce（RP 靠「有 nonce 即拒」防误用）；
 *  - 不设 exp：一次性通知消息，签名即失效边界，重放无害（RP 只按 sid 吊销）。 */
export async function signLogoutToken(
  env: Bindings,
  iss: string,
  claims: { aud: string; sub: string; sid: string; jti: string },
): Promise<string> {
  const key = await signingKey(env);
  const payload: JWTPayload = {
    iss,
    aud: claims.aud,
    sub: claims.sub,
    sid: claims.sid,
    jti: claims.jti,
    iat: Math.floor(Date.now() / 1000),
    events: { "http://schemas.openid.net/event/backchannel-logout": {} },
  };
  return new SignJWT(payload).setProtectedHeader({ alg: "RS256", kid: key.kid }).sign(key.privateKey);
}

/** RFC 7636 S256：base64url(sha256(verifier)) 与 challenge 常数时间比对 */
export async function verifyPkce(challenge: string, verifier: string): Promise<boolean> {
  if (!/^[A-Za-z0-9\-._~]{43,128}$/.test(verifier)) return false;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  let bin = "";
  for (const b of new Uint8Array(digest)) bin += String.fromCharCode(b);
  const computed = btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return timingSafeEqual(computed, challenge);
}
