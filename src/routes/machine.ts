// 机器端点（P0-8）：积分插件 ↔ auth 的 QQ 绑定通道，HMAC 验签、无 cookie。
// 插件侧契约（handlers/sync.py）：POST /api/bind/claim {code, qq_id} → 200 {ok, displayName}，
// 业务错误 400 {error, message}（invalid_code / qq_bound / user_bound / not_bound），验签失败 401。
// 审计行与业务写入同一 batch（同库隐式事务）：绑定变更必有审计，不出现「已绑定但无审计」。
import { Hono } from "hono";
import type { Context } from "hono";
import type { AppEnv } from "../env";
import { sha256Hex } from "../lib/crypto";
import { verifyBindSignature } from "../lib/hmac";
import { rateLimit } from "../lib/ratelimit";
import { clientIp, nowIso } from "../lib/util";

const app = new Hono<AppEnv>();

async function displayNameOf(c: { env: AppEnv["Bindings"] }, accountId: number): Promise<string | null> {
  const row = await c.env.DB.prepare("SELECT name FROM account WHERE id = ?")
    .bind(accountId)
    .first<{ name: string }>();
  return row?.name ?? null;
}

// 纵深防御（TEST_REPORT L-2）：HMAC 已把门，限流只用于挡签名密钥泄漏/插件失控后的高速滥用。
// 键按 CF-Connecting-IP（CF 边缘注入、外部不可伪造），两端点共用一条 300/15min 的桶；
// 配额宽松是有意的——scripts/smoke-bind.mjs 连跑几轮不该被自己的限流卡住。
async function machineAllowed(c: Context<AppEnv>): Promise<boolean> {
  return rateLimit(c.env, `machine:${clientIp(c)}`, 300, 900);
}

app.post("/api/bind/claim", async (c) => {
  if (!(await machineAllowed(c))) return c.json({ error: "rate_limited", message: "请求太频繁，请稍后再试" }, 429);
  const secret = c.env.BIND_SECRET ?? "";
  if (!secret) return c.json({ error: "server_error", message: "服务端未配置 BIND_SECRET" }, 500);
  const raw = await c.req.text();
  const pathWithQuery = new URL(c.req.url).pathname + new URL(c.req.url).search;
  if (!(await verifyBindSignature(secret, "POST", pathWithQuery, raw, c.req.header("X-Timestamp"), c.req.header("X-Sign")))) {
    return c.json({ error: "bad sign" }, 401);
  }
  let body: { code?: unknown; qq_id?: unknown };
  try {
    body = JSON.parse(raw);
  } catch {
    return c.json({ error: "bad body", message: "请求体不是合法 JSON" }, 400);
  }
  const code = typeof body.code === "string" ? body.code.trim() : "";
  const qq = typeof body.qq_id === "string" ? body.qq_id.trim() : "";
  if (!code || !qq) return c.json({ error: "bad body", message: "缺少 code 或 qq_id" }, 400);
  // QQ 号纯数字（插件取消息发送者 id，本来就是数字串）；这里收紧格式，防脏数据进 identity
  if (!/^\d{5,20}$/.test(qq)) return c.json({ error: "bad body", message: "qq_id 格式不对" }, 400);

  const now = nowIso();
  const row = await c.env.DB.prepare(
    "SELECT code_hash, account_id FROM bind_code WHERE code_hash = ? AND used_at IS NULL AND expires_at > ?",
  )
    .bind(await sha256Hex(code), now)
    .first<{ code_hash: string; account_id: number }>();
  if (!row) return c.json({ error: "invalid_code", message: "绑定码无效或已过期，请在认证中心重新生成" }, 400);

  // 双向唯一前置检查（identity 的 UNIQUE 兜底并发）：与竞猜现状同口径——
  // 同 QQ 已被绑（含绑在自己账号上重复申请）报 qq_bound，账号已绑了别的 QQ 报 user_bound
  const bound = await c.env.DB.prepare(
    "SELECT provider_uid, account_id FROM identity WHERE provider = 'qq' AND (provider_uid = ? OR account_id = ?)",
  )
    .bind(qq, row.account_id)
    .first<{ provider_uid: string; account_id: number }>();
  if (bound) {
    return c.json(
      {
        error: bound.provider_uid === qq ? "qq_bound" : "user_bound",
        message: bound.provider_uid === qq ? "该 QQ 已绑定过账号" : "该账号已绑定过其他 QQ",
      },
      400,
    );
  }

  // 原子核销：identity 写入、码置已用、审计三句同批提交；码复用被 used_at IS NULL 挡住
  try {
    await c.env.DB.batch([
      c.env.DB.prepare(
        "INSERT INTO identity (account_id, provider, provider_uid, verified_at, bound_at) VALUES (?, 'qq', ?, ?, ?)",
      ).bind(row.account_id, qq, now, now),
      c.env.DB.prepare("UPDATE bind_code SET used_at = ? WHERE code_hash = ? AND used_at IS NULL").bind(now, row.code_hash),
      c.env.DB.prepare(
        "INSERT INTO audit_log (account_id, event, detail, ip, created_at) VALUES (?, 'bind.claim', ?, ?, ?)",
      ).bind(row.account_id, JSON.stringify({ qq }), clientIp(c), now),
    ]);
  } catch {
    // 并发撞 UNIQUE（同 QQ/同账号两路并发）：按业务冲突回应
    return c.json({ error: "qq_bound", message: "该 QQ 已绑定过账号" }, 400);
  }
  return c.json({ ok: true, displayName: (await displayNameOf(c, row.account_id)) ?? "" });
});

app.post("/api/identity/unbind", async (c) => {
  if (!(await machineAllowed(c))) return c.json({ error: "rate_limited", message: "请求太频繁，请稍后再试" }, 429);
  const secret = c.env.BIND_SECRET ?? "";
  if (!secret) return c.json({ error: "server_error", message: "服务端未配置 BIND_SECRET" }, 500);
  const raw = await c.req.text();
  const pathWithQuery = new URL(c.req.url).pathname + new URL(c.req.url).search;
  if (!(await verifyBindSignature(secret, "POST", pathWithQuery, raw, c.req.header("X-Timestamp"), c.req.header("X-Sign")))) {
    return c.json({ error: "bad sign" }, 401);
  }
  let body: { qq_id?: unknown };
  try {
    body = JSON.parse(raw);
  } catch {
    return c.json({ error: "bad body", message: "请求体不是合法 JSON" }, 400);
  }
  const qq = typeof body.qq_id === "string" ? body.qq_id.trim() : "";
  if (!/^\d{5,20}$/.test(qq)) return c.json({ error: "bad body", message: "缺少 qq_id 或格式不对" }, 400);

  const row = await c.env.DB.prepare(
    "SELECT id, account_id FROM identity WHERE provider = 'qq' AND provider_uid = ?",
  )
    .bind(qq)
    .first<{ id: number; account_id: number }>();
  if (!row) return c.json({ error: "not_bound", message: "该 QQ 未绑定过账号" }, 400);

  const now = nowIso();
  await c.env.DB.batch([
    c.env.DB.prepare("DELETE FROM identity WHERE id = ?").bind(row.id),
    c.env.DB.prepare(
      "INSERT INTO audit_log (account_id, event, detail, ip, created_at) VALUES (?, 'bind.unbind', ?, ?, ?)",
    ).bind(row.account_id, JSON.stringify({ qq }), clientIp(c), now),
  ]);
  return c.json({ ok: true, displayName: (await displayNameOf(c, row.account_id)) ?? "" });
});

export default app;
