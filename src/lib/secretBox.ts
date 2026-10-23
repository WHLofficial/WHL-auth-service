// TOTP secret 的静态加密（AES-GCM）。MFA_ENC_KEY 建议用 32 字节随机值的 base64；
// 若配置成其他字符串，则先 SHA-256 派生 32 字节密钥（仍要求高熵，不要用弱口令）。
const VERSION = "enc:v1";

function b64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function unb64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function aesKey(envKey: string): Promise<CryptoKey> {
  const trimmed = envKey.trim();
  let raw: Uint8Array;
  try {
    const decoded = unb64(trimmed);
    raw = decoded.length === 32 ? decoded : new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(trimmed)));
  } catch {
    raw = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(trimmed)));
  }
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

export async function sealSecret(envKey: string, plaintext: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await aesKey(envKey);
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plaintext));
  return `${VERSION}:${b64(iv)}:${b64(new Uint8Array(cipher))}`;
}

export async function openSecret(envKey: string, sealed: string): Promise<string | null> {
  const parts = sealed.split(":");
  if (parts.length !== 4 || `${parts[0]}:${parts[1]}` !== VERSION) return null;
  try {
    const iv = unb64(parts[2]);
    const cipher = unb64(parts[3]);
    const key = await aesKey(envKey);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher);
    return new TextDecoder().decode(plain);
  } catch {
    return null;
  }
}

export function isSealed(value: string): boolean {
  return value.startsWith(`${VERSION}:`);
}
