// 机器端点（P0-8 / 增量 7）：无 cookie 的 HMAC 通道。
// QQ 绑定（积分插件 ↔ auth）：POST /api/bind/claim {code, qq_id} → 200 {ok, displayName}；
//   POST /api/identity/unbind {qq_id}。业务错误 400 {error, message}
//   （invalid_code / qq_bound / user_bound / not_bound），验签失败 401。
// 球队绑定（增量 7，tour/club 双入口）：绑定关系唯一真源在本库，双方经只读 AUTH_DB 派生——
//   /api/team/bindcode 发码、/api/team/bind 烧码（写绑定+烧码+审计同 batch，杜绝撕裂写）、
//   /api/team/unbind 解绑、/api/team/register 目录 upsert、/api/team/link 俱乐部关联。
// 审计行与业务写入同一 batch（同库隐式事务）：绑定变更必有审计，不出现「已绑定但无审计」。
import { Hono } from "hono";
import type { Context } from "hono";
import type { AppEnv } from "../env";
import { sha256Hex, generateCode } from "../lib/crypto";
import { int, machineGate, parseJson, str } from "../lib/machineGate";
import { clientIp, nowIso } from "../lib/util";

const app = new Hono<AppEnv>();

async function displayNameOf(c: { env: AppEnv["Bindings"] }, accountId: number): Promise<string | null> {
  const row = await c.env.DB.prepare("SELECT name FROM account WHERE id = ?")
    .bind(accountId)
    .first<{ name: string }>();
  return row?.name ?? null;
}

// ---------- QQ 绑定（P0-8，TECH_DESIGN §7） ----------

app.post("/api/bind/claim", async (c) => {
  const gate = await machineGate(c);
  if ("err" in gate) return gate.err;
  const body = parseJson(gate.raw);
  if (!body) return c.json({ error: "bad body", message: "请求体不是合法 JSON" }, 400);
  const code = str(body.code);
  const qq = str(body.qq_id);
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
  const gate = await machineGate(c);
  if ("err" in gate) return gate.err;
  const body = parseJson(gate.raw);
  if (!body) return c.json({ error: "bad body", message: "请求体不是合法 JSON" }, 400);
  const qq = str(body.qq_id);
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

// ---------- 球队绑定（增量 7：tour/club 双入口，真源在本库） ----------

const VIAS = new Set(["tour", "club"]);

// 按 team_id / tour_team_id / club_id 三选一定位目录行（调用方按自己系统选键）。
// 参数不合法或目录无此队都返回现成错误 Response，命中返回 { team }。
async function resolveTeam(
  c: Context<AppEnv>,
  body: Record<string, unknown>,
): Promise<{ team: { id: number } } | { err: Response }> {
  const teamId = int(body.team_id);
  const tourTeamId = int(body.tour_team_id);
  const clubId = int(body.club_id);
  const given = [teamId !== null, tourTeamId !== null, clubId !== null].filter(Boolean).length;
  if (given !== 1) {
    return { err: c.json({ error: "bad body", message: "team_id / tour_team_id / club_id 恰好给一个" }, 400) };
  }
  const [col, val] = teamId !== null ? ["id", teamId] : tourTeamId !== null ? ["tour_team_id", tourTeamId] : ["club_id", clubId];
  const row = await c.env.DB.prepare(`SELECT id FROM team WHERE ${col} = ?`).bind(val).first<{ id: number }>();
  if (!row) {
    return { err: c.json({ error: "team_not_found", message: "球队目录没有这支队，请先登记（register）或关联（link）" }, 400) };
  }
  return { team: row };
}

app.post("/api/team/bindcode", async (c) => {
  const gate = await machineGate(c);
  if ("err" in gate) return gate.err;
  const body = parseJson(gate.raw);
  if (!body) return c.json({ error: "bad body", message: "请求体不是合法 JSON" }, 400);
  const via = str(body.via);
  if (!VIAS.has(via)) return c.json({ error: "bad body", message: "via 必须是 tour 或 club" }, 400);
  const team = await resolveTeam(c, body);
  if ("err" in team) return team.err;

  const ttl = body.ttl_hours === undefined ? 24 : int(body.ttl_hours);
  if (ttl === null || ttl < 1 || ttl > 720) {
    return c.json({ error: "bad body", message: "ttl_hours 须在 1–720 之间（缺省 24）" }, 400);
  }
  const now = nowIso();
  const expiresAt = new Date(Date.now() + ttl * 3600_000).toISOString();
  const code = generateCode(8);
  await c.env.DB.batch([
    c.env.DB.prepare(
      "INSERT INTO team_bind_code (team_id, code_hash, via, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
    ).bind(team.team.id, await sha256Hex(code), via, expiresAt, now),
    c.env.DB.prepare(
      "INSERT INTO audit_log (account_id, event, detail, ip, created_at) VALUES (NULL, 'team.bindcode', ?, ?, ?)",
    ).bind(JSON.stringify({ team_id: team.team.id, via, expires_at: expiresAt }), clientIp(c), now),
  ]);
  // 明码只在本次响应出现一次
  return c.json({ ok: true, code, expires_at: expiresAt });
});

app.post("/api/team/bind", async (c) => {
  const gate = await machineGate(c);
  if ("err" in gate) return gate.err;
  const body = parseJson(gate.raw);
  if (!body) return c.json({ error: "bad body", message: "请求体不是合法 JSON" }, 400);
  const via = str(body.via);
  if (!VIAS.has(via)) return c.json({ error: "bad body", message: "via 必须是 tour 或 club" }, 400);
  const accountId = int(body.account_id);
  if (accountId === null || accountId < 1) return c.json({ error: "bad body", message: "account_id 不合法" }, 400);
  const code = str(body.code).toUpperCase();
  if (code.length !== 8) return c.json({ error: "bad body", message: "code 应为 8 位字母数字" }, 400);

  const now = nowIso();
  const row = await c.env.DB.prepare(
    "SELECT id, team_id FROM team_bind_code WHERE code_hash = ? AND used_by IS NULL AND (expires_at IS NULL OR expires_at > ?)",
  )
    .bind(await sha256Hex(code), now)
    .first<{ id: number; team_id: number }>();
  if (!row) return c.json({ error: "invalid_code", message: "认证码无效或已过期" }, 400);

  // 一账号一队先查再烧：查不出已绑时不烧码，提示更友好（与两侧现行 /bind 口径一致）
  const existing = await c.env.DB.prepare("SELECT team_id FROM team_binding WHERE account_id = ?")
    .bind(accountId)
    .first<{ team_id: number }>();
  if (existing) return c.json({ error: "already_bound", message: "该账号已经绑定了球队，解绑需联系管理员" }, 400);

  // 原子核销三句同批：烧码是条件 UPDATE；绑定写入以「码已由本请求烧掉」为条件
  // （INSERT...SELECT ... WHERE used_by = 本账号）。同码两账号并发竞速时，第二路的
  // UPDATE 改不到行、INSERT...SELECT 也查不到行 → 整批零写入，按 invalid_code 回应；
  // 同账号并发撞 UNIQUE(account_id) 时批内异常回滚，按 already_bound 回应。
  // 审计与业务写入同批：绑定变更必有审计，不出现「已绑定但无审计」。
  try {
    const results = await c.env.DB.batch([
      c.env.DB.prepare("UPDATE team_bind_code SET used_by = ?, used_at = ? WHERE id = ? AND used_by IS NULL").bind(
        accountId,
        now,
        row.id,
      ),
      c.env.DB.prepare(
        `INSERT INTO team_binding (account_id, team_id, bound_via, bound_at)
         SELECT ?, team_id, ?, ? FROM team_bind_code WHERE id = ? AND used_by = ?`,
      ).bind(accountId, via, now, row.id, accountId),
      c.env.DB.prepare(
        "INSERT INTO audit_log (account_id, event, detail, ip, created_at) VALUES (?, 'team.bind', ?, ?, ?)",
      ).bind(accountId, JSON.stringify({ team_id: row.team_id, via }), clientIp(c), now),
    ]);
    if ((results[1].meta.changes ?? 0) !== 1) {
      // 条件未满足（码已被并发请求烧掉）：本批什么都没写
      return c.json({ error: "invalid_code", message: "认证码无效或已过期" }, 400);
    }
  } catch {
    // 并发撞 UNIQUE(account_id)（同账号两路并发烧码）：按业务冲突回应
    return c.json({ error: "already_bound", message: "该账号已经绑定了球队，解绑需联系管理员" }, 400);
  }
  return c.json({ ok: true, teamId: row.team_id });
});

app.post("/api/team/unbind", async (c) => {
  const gate = await machineGate(c);
  if ("err" in gate) return gate.err;
  const body = parseJson(gate.raw);
  if (!body) return c.json({ error: "bad body", message: "请求体不是合法 JSON" }, 400);
  const accountId = int(body.account_id);
  if (accountId === null || accountId < 1) return c.json({ error: "bad body", message: "account_id 不合法" }, 400);

  const row = await c.env.DB.prepare("SELECT team_id FROM team_binding WHERE account_id = ?")
    .bind(accountId)
    .first<{ team_id: number }>();
  if (!row) return c.json({ error: "not_bound", message: "该账号未绑定球队" }, 400);

  const now = nowIso();
  await c.env.DB.batch([
    c.env.DB.prepare("DELETE FROM team_binding WHERE account_id = ?").bind(accountId),
    c.env.DB.prepare(
      "INSERT INTO audit_log (account_id, event, detail, ip, created_at) VALUES (?, 'team.unbind', ?, ?, ?)",
    ).bind(accountId, JSON.stringify({ team_id: row.team_id }), clientIp(c), now),
  ]);
  return c.json({ ok: true, teamId: row.team_id });
});

// 目录登记：tour 建队后调（只带 tour_team_id+name），或迁移脚本一次性建全量目录。
// club_id 冲突（别的队已关联该俱乐部）按业务冲突回 club_taken。
app.post("/api/team/register", async (c) => {
  const gate = await machineGate(c);
  if ("err" in gate) return gate.err;
  const body = parseJson(gate.raw);
  if (!body) return c.json({ error: "bad body", message: "请求体不是合法 JSON" }, 400);
  const tourTeamId = int(body.tour_team_id);
  const name = str(body.name);
  const clubId = body.club_id === undefined || body.club_id === null ? null : int(body.club_id);
  if (tourTeamId === null || tourTeamId < 1 || !name || name.length > 100) {
    return c.json({ error: "bad body", message: "tour_team_id 与 name（≤100 字）必填" }, 400);
  }
  if (clubId !== null && clubId < 1) return c.json({ error: "bad body", message: "club_id 不合法" }, 400);

  const now = nowIso();
  try {
    // 登记与审计同批（同库隐式事务）：目录变更必有审计
    await c.env.DB.batch([
      c.env.DB.prepare(
        `INSERT INTO team (tour_team_id, club_id, name, created_at) VALUES (?, ?, ?, ?)
         ON CONFLICT(tour_team_id) DO UPDATE SET name = excluded.name, club_id = COALESCE(excluded.club_id, team.club_id)`,
      ).bind(tourTeamId, clubId, name, now),
      c.env.DB.prepare(
        "INSERT INTO audit_log (account_id, event, detail, ip, created_at) VALUES (NULL, 'team.register', ?, ?, ?)",
      ).bind(JSON.stringify({ tour_team_id: tourTeamId, club_id: clubId, name }), clientIp(c), now),
    ]);
  } catch {
    return c.json({ error: "club_taken", message: "该俱乐部已关联其他球队" }, 400);
  }
  const row = await c.env.DB.prepare("SELECT id FROM team WHERE tour_team_id = ?").bind(tourTeamId).first<{ id: number }>();
  return c.json({ ok: true, teamId: row?.id ?? null });
});

// 俱乐部关联：迁移脚本按名字匹配建目录后，人工修正/改绑走这里
app.post("/api/team/link", async (c) => {
  const gate = await machineGate(c);
  if ("err" in gate) return gate.err;
  const body = parseJson(gate.raw);
  if (!body) return c.json({ error: "bad body", message: "请求体不是合法 JSON" }, 400);
  const tourTeamId = int(body.tour_team_id);
  const clubId = int(body.club_id);
  if (tourTeamId === null || tourTeamId < 1 || clubId === null || clubId < 1) {
    return c.json({ error: "bad body", message: "tour_team_id 与 club_id 必填" }, 400);
  }

  try {
    // 关联与审计同批（同库隐式事务）：目录变更必有审计
    const results = await c.env.DB.batch([
      c.env.DB.prepare("UPDATE team SET club_id = ? WHERE tour_team_id = ?").bind(clubId, tourTeamId),
      c.env.DB.prepare(
        "INSERT INTO audit_log (account_id, event, detail, ip, created_at) VALUES (NULL, 'team.link', ?, ?, ?)",
      ).bind(JSON.stringify({ tour_team_id: tourTeamId, club_id: clubId }), clientIp(c), nowIso()),
    ]);
    if ((results[0].meta.changes ?? 0) !== 1) {
      return c.json({ error: "team_not_found", message: "球队目录没有这支队，请先 register" }, 400);
    }
  } catch {
    return c.json({ error: "club_taken", message: "该俱乐部已关联其他球队" }, 400);
  }
  return c.json({ ok: true });
});

export default app;
