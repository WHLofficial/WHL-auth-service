// 机器端点共用门（原在 src/routes/machine.ts，v2.0.0 抽出供 routes/admin.ts 复用）：
// 限流 → 验签 → 取 raw body。绑定通道契约与竞猜系统 verifyPluginRequest 逐字一致：
// X-Sign = HMAC-SHA256(secret, "POST|path|ts|raw")，path 含 query，只支持 POST。
//
// v4.0.0 管理通道分离：/api/admin/* 改验 ADMIN_SECRET，并要求 X-Nonce（签名串见 lib/hmac.ts），
// nonce 落库去重，签名窗口内不可重放。BIND_SECRET 只留给 QQ 插件绑定通道。
import type { Context } from "hono";
import type { AppEnv } from "../env";
import { verifyBindSignature } from "./hmac";
import { rateLimit } from "./ratelimit";
import { clientIp, nowIso } from "./util";

export type MachineScope = "bind" | "admin";

// 纵深防御（TEST_REPORT L-2）：HMAC 已把门，限流只用于挡签名密钥泄漏/插件失控后的高速滥用。
// 键按 CF-Connecting-IP（CF 边缘注入、外部不可伪造）；两类通道各用一条桶，避免管理台
// 批量操作与绑定插件互相挤占配额。
export async function machineAllowed(c: Context<AppEnv>, scope: MachineScope = "bind"): Promise<boolean> {
  const bucket = scope === "admin" ? "machine-admin" : "machine";
  const limit = scope === "admin" ? 120 : 300;
  return rateLimit(c.env, `${bucket}:${clientIp(c)}`, limit, 900);
}

export async function machineGate(
  c: Context<AppEnv>,
  scope: MachineScope = "bind",
): Promise<{ raw: string } | { err: Response }> {
  if (!(await machineAllowed(c, scope))) {
    return { err: c.json({ error: "rate_limited", message: "请求太频繁，请稍后再试" }, 429) };
  }
  const secret = (scope === "admin" ? c.env.ADMIN_SECRET : c.env.BIND_SECRET) ?? "";
  if (!secret) {
    return {
      err: c.json(
        { error: "server_error", message: scope === "admin" ? "服务端未配置 ADMIN_SECRET" : "服务端未配置 BIND_SECRET" },
        500,
      ),
    };
  }
  // P0 的密钥分离必须是硬约束：两个通道共用一把密钥时，插件侧泄漏会重新等于管理端 root。
  if (scope === "admin" && c.env.BIND_SECRET && c.env.ADMIN_SECRET === c.env.BIND_SECRET) {
    console.error("ADMIN_SECRET and BIND_SECRET must be different");
    return { err: c.json({ error: "server_error", message: "ADMIN_SECRET 不能与 BIND_SECRET 相同" }, 500) };
  }
  const nonce = c.req.header("X-Nonce")?.trim();
  const raw = await c.req.text();
  const url = new URL(c.req.url);
  if (
    !(await verifyBindSignature(
      secret,
      "POST",
      url.pathname + url.search,
      raw,
      c.req.header("X-Timestamp"),
      c.req.header("X-Sign"),
      nonce,
    ))
  ) {
    // 管理通道的验签失败是「密钥泄漏/调用方失陷」的早期信号，留给 Workers 日志做告警；
    // 不写 audit（未认证请求可被用来灌表）。
    if (scope === "admin") console.warn("admin.signature_rejected", { ip: clientIp(c), path: url.pathname });
    return { err: c.json({ error: "bad sign" }, 401) };
  }
  // 先验签再挑剔 nonce：坏签名统一回 bad sign，不泄漏「服务端要求 nonce」这一层。
  if (scope === "admin") {
    if (!nonce) return { err: c.json({ error: "missing nonce" }, 401) };
    if (!/^[A-Za-z0-9_-]{16,128}$/.test(nonce)) return { err: c.json({ error: "bad nonce" }, 401) };
  }
  // 验签通过才消耗 nonce：坏签名不能用来占坑。UNIQUE 冲突 = 同一 nonce 第二次出现。
  if (nonce) {
    const now = Date.now();
    const inserted = await c.env.DB.prepare(
      "INSERT INTO hmac_nonce (nonce, created_at, expires_at) VALUES (?, ?, ?) ON CONFLICT(nonce) DO NOTHING",
    )
      .bind(nonce, nowIso(), new Date(now + 300_000).toISOString())
      .run();
    if (inserted.meta.changes !== 1) {
      if (scope === "admin") console.warn("admin.nonce_replayed", { ip: clientIp(c), path: url.pathname });
      return { err: c.json({ error: "replayed request" }, 401) };
    }
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
