// TOTP（RFC 6238，SHA-1/6 位/30 秒）——超管强制二次验证用。
// 只依赖 WebCrypto，不引第三方库；secret 为 base32（RFC 4648，无填充）。
import { timingSafeEqual } from "./util";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const STEP_SECONDS = 30;
const DIGITS = 6;

export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(input: string): Uint8Array {
  const s = input.toUpperCase().replace(/[\s=-]/g, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of s) {
    const idx = ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error("invalid base32");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

/** 20 字节随机 secret（160 bit，RFC 4226 推荐长度） */
export function generateTotpSecret(): string {
  return base32Encode(crypto.getRandomValues(new Uint8Array(20)));
}

async function hmacSha1(key: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", k, message);
  return new Uint8Array(sig);
}

export async function totpCode(secret: string, step: number): Promise<string> {
  const counter = new ArrayBuffer(8);
  new DataView(counter).setUint32(4, step, false);
  const mac = await hmacSha1(base32Decode(secret), new Uint8Array(counter));
  const offset = mac[mac.length - 1] & 0x0f;
  const value =
    ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(value % 10 ** DIGITS).padStart(DIGITS, "0");
}

export function currentTotpStep(): number {
  return Math.floor(Date.now() / 1000 / STEP_SECONDS);
}

/**
 * 校验验证码，只接受严格大于 lastStep 的时间窗（防同一 30 秒内重放）。
 * @returns 命中的 step；失败为 null
 */
export async function verifyTotp(
  secret: string,
  code: string,
  lastStep = 0,
  window = 1,
): Promise<number | null> {
  const normalized = code.replace(/\s/g, "");
  if (!new RegExp(`^\\d{${DIGITS}}$`).test(normalized)) return null;
  const now = currentTotpStep();
  for (let delta = -window; delta <= window; delta++) {
    const step = now + delta;
    if (step <= lastStep) continue;
    const expected = await totpCode(secret, step);
    if (timingSafeEqual(expected, normalized)) return step;
  }
  return null;
}

export function otpauthUri(issuer: string, account: string, secret: string): string {
  const label = `${issuer}:${account}`;
  const params = new URLSearchParams({ secret, issuer, algorithm: "SHA1", digits: String(DIGITS), period: String(STEP_SECONDS) });
  return `otpauth://totp/${encodeURIComponent(label)}?${params.toString()}`;
}
