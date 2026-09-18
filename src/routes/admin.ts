// 管理机器端点（增量 8，PRD P1-1）：把管理能力落到 auth，管理界面仍留在 tour。
//
// 为什么长这样：账号真源 2026-09-14 收口到本库后，tour 管理台的写操作仍打自己的库
// （worker/routes/admin/accounts.ts 与 worker/routes/admin.ts 共 6 处死写），改角色/解锁/
// 重置密码/开放注册开关/生成注册码全部失效。本轮把这些动作收口到本文件，走既有 HMAC 机器通道
// （与 routes/machine.ts 同一把 BIND_SECRET、同一契约），tour 侧只做界面与权限门。
//
// 鉴权边界（已拍板）：本文件的每个端点只验 HMAC——「谁有权做管理动作」仍由调用方（tour）用它自己的
// 权限点（tour.accounts.manage / tour.org.settings）判定；操作者身份经 actor_id 带入审计。
//
// 性能约定（本增量硬要求：省 D1 读、缩短等待）：
//   - 列表禁止 N+1：账号页 + 角色 IN 查询，两次读、一次往返两次；会话不进列表
//   - 详情一次返回：账号/角色/授予/会话/QQ 五条语句走一个 DB.batch（一次往返）
//   - 角色目录（8 角色 + 17 权限点）按 isolate 内存缓存 60s（先例：lib/csp.ts 的 clientOrigins）
//   - 写操作「业务写入 + 审计」同 batch 提交（同库隐式事务），杜绝增量 7 那种撕裂写
import { Hono } from "hono";
import type { Context } from "hono";
import type { AppEnv } from "../env";
import { auditStatement } from "../lib/audit";
import { generateCode, hashPassword, PBKDF2_ITERATIONS, sha256Hex } from "../lib/crypto";
import { int, machineGate, parseJson, str } from "../lib/machineGate";
import {
  accountRevokeStatements,
  notifyBackchannel,
  sessionRevokeStatements,
  sessionsOfAccount,
} from "../lib/session";
import { nowIso } from "../lib/util";

const app = new Hono<AppEnv>();

const bad = (c: Context<AppEnv>, error: string, message: string, status: 400 | 403 | 404 | 409) =>
  c.json({ error, message }, status);

const rowsOf = <T,>(r: { results?: unknown[] } | undefined): T[] => (r?.results ?? []) as T[];

// ---------- 角色/权限点目录（静态数据，isolate 内存缓存） ----------

type CatalogRole = { id: number; app_id: string | null; key: string; name: string };
type CatalogPermission = { id: number; app_id: string; key: string; description: string | null };
type Catalog = {
  apps: { client_id: string; name: string }[];
  roles: CatalogRole[];
  permissions: CatalogPermission[];
  /** 角色→权限点映射：管理界面据此算出「角色带来的权限」与「额外授予的权限」的并集 */
  role_permissions: { role_id: number; permission_id: number }[];
};

/** 目录只在迁移/播种时变（0002_seed.sql、seed-grants.mjs），缓存 60s 足够；
 *  失败不写缓存，下次请求自然重试。 */
const CATALOG_TTL_MS = 60_000;
let catalogCache: { at: number; value: Catalog } | null = null;

async function loadCatalog(c: Context<AppEnv>): Promise<Catalog> {
  if (catalogCache && Date.now() - catalogCache.at < CATALOG_TTL_MS) return catalogCache.value;
  const [apps, roles, perms, rolePerms] = await c.env.DB.batch([
    c.env.DB.prepare("SELECT client_id, name FROM app ORDER BY client_id"),
    c.env.DB.prepare("SELECT id, app_id, key, name FROM role ORDER BY app_id IS NOT NULL, app_id, key"),
    c.env.DB.prepare("SELECT id, app_id, key, description FROM permission ORDER BY app_id, key"),
    c.env.DB.prepare("SELECT role_id, permission_id FROM role_permission"),
  ]);
  const value: Catalog = {
    apps: rowsOf<{ client_id: string; name: string }>(apps),
    roles: rowsOf<CatalogRole>(roles),
    permissions: rowsOf<CatalogPermission>(perms),
    role_permissions: rowsOf<{ role_id: number; permission_id: number }>(rolePerms),
  };
  catalogCache = { at: Date.now(), value };
  return value;
}

/** user_role 里的角色在 claims 里带 app 前缀（如 club.admin），全局角色裸键（superadmin）——
 *  与 routes/oidc.ts 的 rolesForAud 同一口径，管理界面拿到的键可直接与角色列表对齐 */
const roleKey = (r: { app_id: string | null; key: string }) => (r.app_id === null ? r.key : `${r.app_id}.${r.key}`);
// 权限点不要再拼 app 前缀：0002_seed.sql 里 permission.key 本身已是全键名（如 tour.org.settings），
// app_id 只是归属标记（两者冗余）。oidc.ts 的 permissionsFor 也直接下发 p.key，口径必须一致。
const permKey = (p: { key: string }) => p.key;
// 查询结果里的列被别名成 role_key / perm_key（role.key 与 app 表同名列在 JOIN 后会歧义），
// 于是另配一对同口径的取值函数，避免每个调用点手工拼前缀。
const roleKeyOf = (r: { app_id: string | null; role_key: string }) => roleKey({ app_id: r.app_id, key: r.role_key });
const permKeyOf = (p: { perm_key: string }) => permKey({ key: p.perm_key });

/** 目标账号是否是全局超管：超管经 CROSS JOIN 已持全部权限点，本增量的管理动作对它要么无意义
 *  （授予权限点）要么危险（重置密码/改角色），沿用 tour 管理台既有规则一并拦住。 */
const IS_SUPER_SQL = `EXISTS(SELECT 1 FROM user_role ur JOIN role r ON r.id = ur.role_id
   WHERE ur.account_id = a.id AND r.app_id IS NULL AND r.key = 'superadmin') AS is_super`;

/** 取操作的公共前置：账号存在性 + 超管标记 + locked + 停用态 + 「不能操作自己」。读一次，写操作共用 */
async function loadTarget(
  c: Context<AppEnv>,
  accountId: number | null,
  actorId: number | null | undefined,
): Promise<{ err: Response } | { name: string; isSuper: boolean; locked: boolean; disabledAt: string | null }> {
  if (accountId === null) return { err: bad(c, "bad body", "缺少 account_id", 400) };
  if (actorId !== null && actorId !== undefined && actorId === accountId) {
    return { err: bad(c, "self_forbidden", "不能对自己执行这个操作", 403) };
  }
  const row = await c.env.DB.prepare(
    `SELECT a.name, a.locked, a.disabled_at, ${IS_SUPER_SQL} FROM account a WHERE a.id = ?`,
  )
    .bind(accountId)
    .first<{ name: string; locked: number; disabled_at: string | null; is_super: number }>();
  if (!row) return { err: bad(c, "account_not_found", "账号不存在", 404) };
  return {
    name: row.name,
    isSuper: row.is_super === 1,
    locked: row.locked === 1,
    disabledAt: row.disabled_at,
  };
}

/** 机器端点的统一外壳：验签 → 解析 JSON → 取 actor_id（调用方传入，用于审计）。
 *  空请求体按 {} 处理：读类端点（目录、列表、设置读取）本来就不需要 body，签名对空串照样成立。 */
async function machineBody(
  c: Context<AppEnv>,
): Promise<{ err: Response } | { body: Record<string, unknown>; actorId: number | undefined }> {
  const gate = await machineGate(c);
  if ("err" in gate) return { err: gate.err };
  const body = gate.raw.trim() === "" ? {} : parseJson(gate.raw);
  if (!body) return { err: bad(c, "bad body", "请求体不是合法 JSON", 400) };
  return { body, actorId: int(body.actor_id) ?? undefined };
}

// ---------- 目录与账号读取 ----------

// GET-like：读角色/权限点目录（供界面渲染勾选项）
app.post("/api/admin/catalog", async (c) => {
  const m = await machineBody(c);
  if ("err" in m) return m.err;
  const cat = await loadCatalog(c);
  return c.json({
    apps: cat.apps,
    roles: cat.roles,
    permissions: cat.permissions,
    role_permissions: cat.role_permissions,
  });
});

// 账号列表：两次读（账号页 + 该页账号的角色），代码层合并，禁止 N+1。
// 会话不进列表（只在 detail 按需查）——列表要翻页浏览，逐行带会话计数会把它变成 N 次子查询。
app.post("/api/admin/accounts/list", async (c) => {
  const m = await machineBody(c);
  if ("err" in m) return m.err;
  const q = str(m.body.q);
  const after = int(m.body.after);
  const limit = Math.min(Math.max(int(m.body.limit) ?? 100, 1), 500);

  const where: string[] = [];
  const binds: unknown[] = [];
  if (q) {
    where.push("a.name LIKE ?");
    binds.push(`%${q}%`);
  }
  if (after !== null && after > 0) {
    where.push("a.id > ?"); // keyset 翻页：比 OFFSET 少扫全表，配上主键索引是稳定代价
    binds.push(after);
  }
  const accounts = await c.env.DB.prepare(
    `SELECT a.id, a.name, a.email, a.locked, a.must_change_pw, a.created_at, a.disabled_at, ${IS_SUPER_SQL},
            t.tour_team_id AS team_id, t.name AS team_name
       FROM account a
       LEFT JOIN team_binding b ON b.account_id = a.id
       LEFT JOIN team t ON t.id = b.team_id
       ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
      ORDER BY a.id LIMIT ?`,
  )
    .bind(...binds, limit)
    .all<{
      id: number;
      name: string;
      email: string | null;
      locked: number;
      must_change_pw: number;
      created_at: string;
      disabled_at: string | null;
      is_super: number;
      team_id: number | null;
      team_name: string | null;
    }>();

  const ids = accounts.results.map((a) => a.id);
  const roleRows = ids.length
    ? await c.env.DB.prepare(
        `SELECT ur.account_id, r.app_id, r.key AS role_key, r.name AS role_name
           FROM user_role ur JOIN role r ON r.id = ur.role_id
          WHERE ur.account_id IN (${ids.map(() => "?").join(",")})
          ORDER BY r.key`,
      )
        .bind(...ids)
        .all<{ account_id: number; app_id: string | null; role_key: string; role_name: string }>()
    : { results: [] as { account_id: number; app_id: string | null; role_key: string; role_name: string }[] };

  const byAccount = new Map<number, { key: string; name: string }[]>();
  for (const r of roleRows.results) {
    const list = byAccount.get(r.account_id) ?? [];
    list.push({ key: roleKeyOf(r), name: r.role_name });
    byAccount.set(r.account_id, list);
  }
  return c.json({
    accounts: accounts.results.map((a) => ({
      id: a.id,
      name: a.name,
      email: a.email,
      locked: a.locked === 1,
      must_change_pw: a.must_change_pw === 1,
      disabled: a.disabled_at !== null,
      disabled_at: a.disabled_at,
      is_super: a.is_super === 1,
      created_at: a.created_at,
      roles: byAccount.get(a.id) ?? [],
      // 绑定球队随列表一起返回（同一次查询 LEFT JOIN，零额外往返）：
      // 管理台原本要在 tour 侧全表扫 team_binding 自己拼，现在由 auth 一次给全。
      team_id: a.team_id,
      team_name: a.team_name,
    })),
    next_after: accounts.results.length === limit ? accounts.results[accounts.results.length - 1].id : null,
  });
});

// 账号详情：账号 + 角色 + 账号级权限点授予 + 活跃会话 + 已绑 QQ，五条语句一个 batch（一次往返）
app.post("/api/admin/accounts/detail", async (c) => {
  const m = await machineBody(c);
  if ("err" in m) return m.err;
  const accountId = int(m.body.account_id);
  if (accountId === null) return bad(c, "bad body", "缺少 account_id", 400);

  const now = nowIso();
  const [acct, roles, grants, sessions, qq] = await c.env.DB.batch([
    c.env.DB.prepare(
      `SELECT a.id, a.name, a.email, a.locked, a.must_change_pw, a.created_at, a.disabled_at, ${IS_SUPER_SQL}
         FROM account a WHERE a.id = ?`,
    ).bind(accountId),
    c.env.DB.prepare(
      `SELECT r.app_id, r.key AS role_key, r.name AS role_name, ur.granted_at, ur.granted_by
         FROM user_role ur JOIN role r ON r.id = ur.role_id
        WHERE ur.account_id = ? ORDER BY r.key`,
    ).bind(accountId),
    c.env.DB.prepare(
      `SELECT p.app_id, p.key AS perm_key, p.description, ap.granted_at
         FROM account_permission ap JOIN permission p ON p.id = ap.permission_id
        WHERE ap.account_id = ? ORDER BY p.app_id, p.key`,
    ).bind(accountId),
    c.env.DB.prepare(
      `SELECT token_hash, created_at, expires_at, last_seen_at, ip
         FROM session
        WHERE account_id = ? AND revoked_at IS NULL AND expires_at > ?
        ORDER BY created_at DESC LIMIT 50`,
    ).bind(accountId, now),
    c.env.DB.prepare("SELECT provider_uid, bound_at FROM identity WHERE account_id = ? AND provider = 'qq' LIMIT 1").bind(
      accountId,
    ),
  ]);

  const account = rowsOf<{
    id: number;
    name: string;
    email: string | null;
    locked: number;
    must_change_pw: number;
    created_at: string;
    disabled_at: string | null;
    is_super: number;
  }>(acct)[0];
  if (!account) return bad(c, "account_not_found", "账号不存在", 404);
  return c.json({
    account: {
      id: account.id,
      name: account.name,
      email: account.email,
      locked: account.locked === 1,
      must_change_pw: account.must_change_pw === 1,
      disabled: account.disabled_at !== null,
      disabled_at: account.disabled_at,
      is_super: account.is_super === 1,
      created_at: account.created_at,
    },
    roles: rowsOf<{ app_id: string | null; role_key: string; role_name: string }>(roles).map((r) => ({
      key: roleKeyOf(r),
      name: r.role_name,
    })),
    grants: rowsOf<{ app_id: string; perm_key: string; description: string | null; granted_at: string }>(grants).map(
      (p) => ({ key: permKeyOf(p), description: p.description, granted_at: p.granted_at }),
    ),
    sessions: rowsOf<{
      token_hash: string;
      created_at: string;
      expires_at: string;
      last_seen_at: string | null;
      ip: string | null;
    }>(sessions).map((s) => ({
      // token_hash 只用于「强制下线」定位，无法反推出会话 token，可以给管理台
      session_hash: s.token_hash,
      created_at: s.created_at,
      expires_at: s.expires_at,
      last_seen_at: s.last_seen_at,
      ip: s.ip,
    })),
    qq: rowsOf<{ provider_uid: string }>(qq)[0]?.provider_uid ?? null,
  });
});

// ---------- 账号写操作 ----------

// 角色授权：传入该账号「应有的角色全集」，服务端算差集后增删。
// 为什么传全集而不是增删指令：幂等。界面反复保存同一个状态不会产生副作用与审计噪音。
app.post("/api/admin/accounts/roles", async (c) => {
  const m = await machineBody(c);
  if ("err" in m) return m.err;
  const accountId = int(m.body.account_id);
  if (!Array.isArray(m.body.roles)) return bad(c, "bad body", "roles 必须是数组", 400);
  const target = await loadTarget(c, accountId, m.actorId);
  if ("err" in target) return target.err;

  const want = [...new Set(m.body.roles.filter((r): r is string => typeof r === "string"))];
  const cat = await loadCatalog(c);
  const roleByKey = new Map(cat.roles.map((r) => [roleKey(r), r]));
  const unknown = want.filter((k) => !roleByKey.has(k));
  if (unknown.length) return bad(c, "bad_role", `角色不存在：${unknown.join("、")}`, 400);

  const current = await c.env.DB.prepare(
    `SELECT r.app_id, r.key AS role_key FROM user_role ur JOIN role r ON r.id = ur.role_id WHERE ur.account_id = ?`,
  )
    .bind(accountId)
    .all<{ app_id: string | null; role_key: string }>();
  const has = new Set(current.results.map(roleKeyOf));
  const wantSet = new Set(want);
  const toAdd = want.filter((k) => !has.has(k));
  const toRemove = [...has].filter((k) => !wantSet.has(k));

  // 全局超管角色不通过本端点授予或回收：它是账号系统的最后一道保险（授予=普升，回收=管理员把自己锁死）
  const touched = [...toAdd, ...toRemove].filter((k) => k === "superadmin");
  if (touched.length) {
    return bad(c, "superadmin_locked", "超级管理员角色不能在管理台改动，请直接改库", 403);
  }
  if (!toAdd.length && !toRemove.length) return c.json({ ok: true, granted: [], revoked: [], changed: false });

  const now = nowIso();
  await c.env.DB.batch([
    ...toRemove.map((k) =>
      c.env.DB.prepare("DELETE FROM user_role WHERE account_id = ? AND role_id = ?").bind(
        accountId,
        roleByKey.get(k)!.id,
      ),
    ),
    ...toAdd.map((k) =>
      c.env.DB.prepare("INSERT INTO user_role (account_id, role_id, granted_by, granted_at) VALUES (?, ?, ?, ?)").bind(
        accountId,
        roleByKey.get(k)!.id,
        m.actorId ?? null,
        now,
      ),
    ),
    ...toAdd.map((k) => auditStatement(c, "role.grant", { accountId, detail: { actor_id: m.actorId, role: k } })),
    ...toRemove.map((k) => auditStatement(c, "role.revoke", { accountId, detail: { actor_id: m.actorId, role: k } })),
  ]);
  return c.json({ ok: true, granted: toAdd, revoked: toRemove, changed: true });
});

// 账号级权限点额外授予（「只加不减」的第二来源，与 user_role 平行）：
// 取消勾选只删本表的行，角色带来的权限点删不掉——界面上这两块必须分开展示，别让管理员以为能靠它减权。
app.post("/api/admin/accounts/grants", async (c) => {
  const m = await machineBody(c);
  if ("err" in m) return m.err;
  const accountId = int(m.body.account_id);
  if (!Array.isArray(m.body.permissions)) return bad(c, "bad body", "permissions 必须是数组", 400);
  const target = await loadTarget(c, accountId, m.actorId);
  if ("err" in target) return target.err;

  const want = [...new Set(m.body.permissions.filter((p): p is string => typeof p === "string"))];
  const cat = await loadCatalog(c);
  const permByKey = new Map(cat.permissions.map((p) => [permKey(p), p]));
  const unknown = want.filter((k) => !permByKey.has(k));
  if (unknown.length) return bad(c, "bad_permission", `权限点不存在：${unknown.join("、")}`, 400);

  const current = await c.env.DB.prepare(
    "SELECT permission_id FROM account_permission WHERE account_id = ?",
  )
    .bind(accountId)
    .all<{ permission_id: number }>();
  const has = new Set(current.results.map((r) => r.permission_id));
  const toAdd = want.filter((k) => !has.has(permByKey.get(k)!.id));
  const toRemove = [...has].filter((id) => !want.some((k) => permByKey.get(k)!.id === id));
  if (!toAdd.length && !toRemove.length) return c.json({ ok: true, granted: [], revoked: [], changed: false });

  const now = nowIso();
  const revokedKeys = toRemove.map((id) => permKeyOf({ perm_key: cat.permissions.find((p) => p.id === id)!.key }));
  await c.env.DB.batch([
    ...toRemove.map((id) =>
      c.env.DB.prepare("DELETE FROM account_permission WHERE account_id = ? AND permission_id = ?").bind(accountId, id),
    ),
    ...toAdd.map((k) => {
      const p = permByKey.get(k)!;
      return c.env.DB.prepare(
        "INSERT INTO account_permission (account_id, permission_id, granted_by, granted_at) VALUES (?, ?, ?, ?)",
      ).bind(accountId, p.id, m.actorId ?? null, now);
    }),
    ...toAdd.map((k) => auditStatement(c, "perm.grant", { accountId, detail: { actor_id: m.actorId, permission: k } })),
    ...toRemove.map((id) =>
      auditStatement(c, "perm.revoke", {
        accountId,
        detail: { actor_id: m.actorId, permission: permKeyOf({ perm_key: cat.permissions.find((p) => p.id === id)!.key }) },
      }),
    ),
  ]);
  return c.json({ ok: true, granted: toAdd, revoked: revokedKeys, changed: true });
});

/** 临时密码：用 generateCode 的字母表（去掉了 0/O/1/I/L），管理员要口头/截图转达，不能有歧义字符。
 *  12 位约 59 bit，配合登录三重限流够用；用户首次登录被 must_change_pw 拦下强制改密。 */
const genTempPassword = () => `${generateCode(6)}-${generateCode(6)}`;

// 重置密码（P1-1）：设临时密码 + 置 must_change_pw + 吊销该账号全部会话（含 OIDC refresh 与 back-channel 通知）。
// 吊销是必须的：密码重置是「怀疑账号失守」时的处置动作，留着旧会话等于没处置。
app.post("/api/admin/accounts/password", async (c) => {
  const m = await machineBody(c);
  if ("err" in m) return m.err;
  const accountId = int(m.body.account_id);
  const target = await loadTarget(c, accountId, m.actorId);
  if ("err" in target) return target.err;
  if (target.isSuper) return bad(c, "superadmin_locked", "超级管理员的密码不能在管理台重置", 403);

  const tempPassword = genTempPassword();
  const now = nowIso();
  const bySession = await sessionsOfAccount(c, accountId!);
  const revoked = bySession.size;
  await c.env.DB.batch([
    // 有的账号只有 QQ 身份没有密码（identity 走绑定、credential 无行）：upsert 一句话覆盖两种情况
    c.env.DB.prepare(
      `INSERT INTO credential (account_id, type, hash, iterations, updated_at) VALUES (?, 'password', ?, ?, ?)
       ON CONFLICT(account_id, type) DO UPDATE SET hash = excluded.hash, iterations = excluded.iterations, updated_at = excluded.updated_at`,
    ).bind(accountId, await hashPassword(tempPassword), PBKDF2_ITERATIONS, now),
    c.env.DB.prepare("UPDATE account SET must_change_pw = 1 WHERE id = ?").bind(accountId),
    ...accountRevokeStatements(c, accountId!, now),
    auditStatement(c, "pw.reset", { accountId, detail: { actor_id: m.actorId, sessions_revoked: revoked } }),
    ...(revoked
      ? [
          auditStatement(c, "session.revoke", {
            accountId,
            detail: { actor_id: m.actorId, scope: "account", reason: "pw.reset", count: revoked },
          }),
        ]
      : []),
  ]);
  await notifyBackchannel(
    c,
    [...bySession].flatMap(([sid, clients]) =>
      clients.map((clientId) => ({ sub: String(accountId), sid, clientId })),
    ),
  );
  return c.json({ ok: true, temp_password: tempPassword, sessions_revoked: revoked });
});

// 解锁观众号：locked 是「观众号」语义（能登录、受限），解锁仅影响绑队/提交阵容等业务判定。
// 已解锁时直接返回且不写审计，避免管理台重复点击刷出无意义的审计行。
app.post("/api/admin/accounts/unlock", async (c) => {
  const m = await machineBody(c);
  if ("err" in m) return m.err;
  const accountId = int(m.body.account_id);
  const target = await loadTarget(c, accountId, m.actorId);
  if ("err" in target) return target.err;
  if (!target.locked) return c.json({ ok: true, changed: false });

  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE account SET locked = 0 WHERE id = ?").bind(accountId),
    auditStatement(c, "account.unlock", { accountId, detail: { actor_id: m.actorId, name: target.name } }),
  ]);
  return c.json({ ok: true, changed: true });
});

// 停用/启用：单开 disabled_at，locked（观众号）语义完全不动——见 migrations/0009_admin.sql 的说明。
// 停用即吊销该账号全部会话并逐 client 通知（与登出同一条链路）。
app.post("/api/admin/accounts/disable", async (c) => {
  const m = await machineBody(c);
  if ("err" in m) return m.err;
  const accountId = int(m.body.account_id);
  if (typeof m.body.disabled !== "boolean") return bad(c, "bad body", "缺少 disabled（布尔）", 400);
  const target = await loadTarget(c, accountId, m.actorId);
  if ("err" in target) return target.err;
  if (target.isSuper) return bad(c, "superadmin_locked", "超级管理员账号不能被停用", 403);

  const now = nowIso();
  if (!m.body.disabled) {
    if (target.disabledAt === null) return c.json({ ok: true, changed: false });
    await c.env.DB.batch([
      c.env.DB.prepare("UPDATE account SET disabled_at = NULL WHERE id = ?").bind(accountId),
      auditStatement(c, "account.enable", { accountId, detail: { actor_id: m.actorId, name: target.name } }),
    ]);
    return c.json({ ok: true, changed: true });
  }
  if (target.disabledAt !== null) return c.json({ ok: true, changed: false });

  const bySession = await sessionsOfAccount(c, accountId!);
  const revoked = bySession.size;
  await c.env.DB.batch([
    c.env.DB.prepare("UPDATE account SET disabled_at = ? WHERE id = ?").bind(now, accountId),
    ...accountRevokeStatements(c, accountId!, now),
    auditStatement(c, "account.disable", {
      accountId,
      detail: { actor_id: m.actorId, name: target.name, sessions_revoked: revoked },
    }),
    ...(revoked
      ? [
          auditStatement(c, "session.revoke", {
            accountId,
            detail: { actor_id: m.actorId, scope: "account", reason: "account.disable", count: revoked },
          }),
        ]
      : []),
  ]);
  await notifyBackchannel(
    c,
    [...bySession].flatMap(([sid, clients]) =>
      clients.map((clientId) => ({ sub: String(accountId), sid, clientId })),
    ),
  );
  return c.json({ ok: true, changed: true, sessions_revoked: revoked });
});

// 强制下线：给 session_hash 踢单个，不给则踢该账号全部（撤销全部 refresh 并通知各 client）
app.post("/api/admin/sessions/revoke", async (c) => {
  const m = await machineBody(c);
  if ("err" in m) return m.err;
  const accountId = int(m.body.account_id);
  if (accountId === null) return bad(c, "bad body", "缺少 account_id", 400);
  const sessionHash = str(m.body.session_hash);

  if (sessionHash) {
    // 先确认行存在再写：会话已被用户自己登出时不该留下一条 session.revoke 审计（无效动作不入账）
    const exists = await c.env.DB.prepare(
      "SELECT 1 AS ok FROM session WHERE token_hash = ? AND account_id = ? AND revoked_at IS NULL",
    )
      .bind(sessionHash, accountId)
      .first<{ ok: number }>();
    if (!exists) return bad(c, "session_not_found", "会话不存在或已结束", 404);
    const now = nowIso();
    await c.env.DB.batch([
      ...sessionRevokeStatements(c, sessionHash, accountId, now),
      auditStatement(c, "session.revoke", {
        accountId,
        detail: { actor_id: m.actorId, scope: "one", sid: sessionHash.slice(0, 12) },
      }),
    ]);
    const clients = await c.env.DB.prepare("SELECT DISTINCT client_id FROM oidc_refresh WHERE session_hash = ?")
      .bind(sessionHash)
      .all<{ client_id: string }>();
    await notifyBackchannel(
      c,
      clients.results.map((r) => ({ sub: String(accountId), sid: sessionHash, clientId: r.client_id })),
    );
    return c.json({ ok: true, revoked: 1 });
  }

  const bySession = await sessionsOfAccount(c, accountId);
  const revoked = bySession.size;
  if (revoked === 0) return c.json({ ok: true, revoked: 0 });
  const now = nowIso();
  await c.env.DB.batch([
    ...accountRevokeStatements(c, accountId, now),
    auditStatement(c, "session.revoke", {
      accountId,
      detail: { actor_id: m.actorId, scope: "account", reason: "admin", count: revoked },
    }),
  ]);
  await notifyBackchannel(
    c,
    [...bySession].flatMap(([sid, clients]) =>
      clients.map((clientId) => ({ sub: String(accountId), sid, clientId })),
    ),
  );
  return c.json({ ok: true, revoked });
});

// ---------- 组织设置与注册码（真源在本库：tour 侧同名接口已改为死写） ----------

// 开放注册开关：不带 allow_open_reg = 读；带 = 写。哨兵值用 undefined 区分「没传」与「传了 false」。
app.post("/api/admin/org-settings", async (c) => {
  const m = await machineBody(c);
  if ("err" in m) return m.err;
  if (typeof m.body.allow_open_reg !== "boolean") {
    const row = await c.env.DB.prepare("SELECT allow_open_reg FROM organization WHERE id = 1").first<{
      allow_open_reg: number;
    }>();
    return c.json({ allow_open_reg: row?.allow_open_reg === 1 });
  }
  const want = m.body.allow_open_reg ? 1 : 0;
  await c.env.DB.batch([
    c.env.DB.prepare(
      "INSERT INTO organization (id, allow_open_reg) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET allow_open_reg = excluded.allow_open_reg",
    ).bind(want),
    auditStatement(c, "org.open_reg", { detail: { actor_id: m.actorId, allow_open_reg: want === 1 } }),
  ]);
  return c.json({ ok: true, allow_open_reg: want === 1 });
});

// 生成注册码：明码只在这条响应里出现一次（库存 sha256），审计只记指纹不记明码
app.post("/api/admin/signup-codes/create", async (c) => {
  const m = await machineBody(c);
  if ("err" in m) return m.err;
  const maxUsesRaw = int(m.body.max_uses);
  const maxUses = maxUsesRaw !== null && maxUsesRaw > 0 ? maxUsesRaw : null; // null = 不限次
  const hoursRaw = int(m.body.expires_in_hours);
  const expiresAt = hoursRaw !== null && hoursRaw > 0 ? new Date(Date.now() + hoursRaw * 3600_000).toISOString() : null;

  const code = generateCode(8);
  const codeHash = await sha256Hex(code);
  const now = nowIso();
  await c.env.DB.batch([
    c.env.DB.prepare(
      "INSERT INTO signup_code (code_hash, expires_at, max_uses, used_count, created_by, created_at) VALUES (?, ?, ?, 0, ?, ?)",
    ).bind(codeHash, expiresAt, maxUses, m.actorId ?? null, now),
    auditStatement(c, "signup_code.create", {
      accountId: m.actorId ?? undefined,
      detail: { actor_id: m.actorId, code_hash_prefix: codeHash.slice(0, 12), max_uses: maxUses, expires_at: expiresAt },
    }),
  ]);
  return c.json({ code, max_uses: maxUses, expires_at: expiresAt }, 201);
});

// 注册码使用记录：明码不可回查（只有 sha256），只给次数/过期/状态与不可逆指纹前缀
app.post("/api/admin/signup-codes/list", async (c) => {
  const m = await machineBody(c);
  if ("err" in m) return m.err;
  const rows = await c.env.DB.prepare(
    `SELECT code_hash, max_uses, used_count, expires_at, created_by, created_at
       FROM signup_code ORDER BY created_at DESC, code_hash DESC LIMIT 50`,
  ).all<{
    code_hash: string;
    max_uses: number | null;
    used_count: number;
    expires_at: string | null;
    created_by: number | null;
    created_at: string;
  }>();
  return c.json({
    codes: rows.results.map((r) => ({
      id: r.code_hash.slice(0, 12),
      max_uses: r.max_uses,
      used_count: r.used_count,
      expires_at: r.expires_at,
      created_by: r.created_by,
      created_at: r.created_at,
    })),
  });
});

export default app;
