import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import type { Context } from "hono";
import type { AppEnv, SessionUser } from "../env";
import { roleFromRoleRows } from "./accounts";
import { randomToken, sha256Hex } from "./crypto";
import { signLogoutToken } from "./oidc";
import { clientIp, nowIso } from "./util";

export const SESSION_COOKIE = "whl_session";
const TTL_SECONDS = 7 * 24 * 3600;
/** 「最后活跃」埋点节流窗口：getSessionUser 挂在全站每请求热路径上（src/index.ts），
 *  不节流就是每请求一次 D1 写。5 分钟精度对管理台看会话够用。 */
const TOUCH_INTERVAL_MS = 5 * 60_000;

/** 配置 COOKIE_DOMAIN 时用主域根，同主域子系统共享登录态；否则 host-only */
function cookieDomain(c: Context<AppEnv>): { domain?: string } {
  return c.env.COOKIE_DOMAIN ? { domain: c.env.COOKIE_DOMAIN } : {};
}

/**
 * 会话创建：只写 auth D1 session 表（token_hash），供 OIDC 与主动吊销使用；TTL 7 天。
 * 共享 KV 兼容桥（tour 登录时代的 sess:{token} 双写）已停写——四系统 2026-09-14 全量切 OIDC，
 * guess/club 残留的 KV 兜底读到空即回退 OIDC 静默登录，主链路无感；旧 KV 条目随 7 天 TTL 自然清空。
 * 少一次 KV 写在登录热路径上（性能整治）。
 * @returns 明文会话令牌（调用方需要 sessionHash 时直接复用，避免再算一次）
 */
export async function createSession(c: Context<AppEnv>, userId: number): Promise<string> {
  const token = randomToken();
  await c.env.DB.prepare(
    "INSERT INTO session (token_hash, account_id, family_id, created_at, expires_at, last_seen_at, ip) VALUES (?, ?, ?, ?, ?, ?, ?)",
  )
    .bind(
      await sha256Hex(token),
      userId,
      randomToken(),
      nowIso(),
      new Date(Date.now() + TTL_SECONDS * 1000).toISOString(),
      nowIso(),
      clientIp(c), // v2.0.0：管理台「活跃会话」要显示来源，建会话时留一次
    )
    .run();
  setCookie(c, SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: "Lax",
    path: "/",
    secure: new URL(c.req.url).protocol === "https:",
    maxAge: TTL_SECONDS,
    ...cookieDomain(c),
  });
  // 切换共享域后清掉历史 host-only 同名 cookie，避免新旧两个 whl_session 并存、读取歧义
  if (c.env.COOKIE_DOMAIN) deleteCookie(c, SESSION_COOKIE, { path: "/" });
  return token;
}

export async function getSessionUser(c: Context<AppEnv>): Promise<SessionUser | null> {
  const token = getCookie(c, SESSION_COOKIE);
  if (!token) return null;
  // 账号收口（P0-11，TECH_DESIGN §9.1 ③）+ 登录提速：会话与账号一条 JOIN 拿齐
  // （原来会话、账号、角色 3 次串行 D1 往返，全站每个请求都跑）。过期判定仍必须在服务端做：
  // cookie 的 Max-Age 只在浏览器侧生效，被复制的 token 不受它约束。
  const sessionHash = await sha256Hex(token);
  const row = await c.env.DB.prepare(
    `SELECT a.id, a.name, a.locked, a.must_change_pw, a.disabled_at, s.revoked_at, s.expires_at, s.last_seen_at
       FROM session s JOIN account a ON a.id = s.account_id
      WHERE s.token_hash = ?`,
  )
    .bind(sessionHash)
    .first<{
      id: number;
      name: string;
      locked: number;
      must_change_pw: number;
      disabled_at: string | null;
      revoked_at: string | null;
      expires_at: string;
      last_seen_at: string | null;
    }>();
  // 停用账号（v2.0.0）与已吊销/已过期会话同等对待：判定必须在这里做而不是只靠停用时批量吊销——
  // 漏吊销一次（并发、写入失败）这里是最后一道闸。
  if (!row || row.revoked_at || row.expires_at <= nowIso() || row.disabled_at) return null;
  touchSession(c, sessionHash, row.last_seen_at);
  const roles = await c.env.DB.prepare(
    "SELECT r.app_id AS app_id, r.key AS role_key FROM user_role ur JOIN role r ON r.id = ur.role_id WHERE ur.account_id = ?",
  )
    .bind(row.id)
    .all<{ app_id: string | null; role_key: string }>();
  return {
    id: row.id,
    name: row.name,
    role: roleFromRoleRows(roles.results),
    locked: row.locked === 1,
    mustChangePassword: row.must_change_pw === 1,
  };
}

/**
 * 「最后活跃」（session.last_seen_at，0001 起存在但从未写入，v2.0.0 启用）：管理台会话列表用。
 * 本函数被 src/index.ts 挂成全站每请求热路径，所以两件事必须做到：
 * 1) 节流——只有为空或超过 TOUCH_INTERVAL_MS 才写；
 * 2) 不 await——写走 waitUntil 后台，不让一次时间戳更新拖慢登录后的每个请求。
 * 写失败只记日志：活跃时间不准远好过让请求失败。
 */
function touchSession(c: Context<AppEnv>, sessionHash: string, lastSeenAt: string | null): void {
  if (lastSeenAt && Date.now() - Date.parse(lastSeenAt) < TOUCH_INTERVAL_MS) return;
  const job = c.env.DB.prepare("UPDATE session SET last_seen_at = ? WHERE token_hash = ?")
    .bind(nowIso(), sessionHash)
    .run()
    .catch((err) => console.error("更新会话活跃时间失败", err));
  try {
    c.executionCtx.waitUntil(job);
  } catch {
    // app.request 直调（测试）没有 executionCtx：让它自己跑完，不阻塞当前请求
  }
}

export async function destroySession(c: Context<AppEnv>): Promise<void> {
  const token = getCookie(c, SESSION_COOKIE);
  if (token) {
    // KV 兼容桥已停写（见 createSession），这里也不再删 KV
    await c.env.DB.prepare("UPDATE session SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL")
      .bind(nowIso(), await sha256Hex(token))
      .run();
  }
  // 删除需 Name+Domain+Path 全匹配：共享域下漏掉 domain 会删不掉，登出后仍带登录态
  deleteCookie(c, SESSION_COOKIE, { path: "/", ...cookieDomain(c) });
  // 兜底清掉切换共享域前遗留的 host-only 同名 cookie
  if (c.env.COOKIE_DOMAIN) deleteCookie(c, SESSION_COOKIE, { path: "/" });
}

/** 登出/改密联动：吊销该会话签发的全部 OIDC refresh（TECH_DESIGN §3 登出语义）。
 *  所有销毁会话的入口（POST /logout、GET /logout、改密轮换）都必须调用 */
export async function revokeSessionTokens(c: Context<AppEnv>, sessionHash: string): Promise<void> {
  await c.env.DB.prepare("UPDATE oidc_refresh SET revoked_at = ? WHERE session_hash = ? AND revoked_at IS NULL")
    .bind(nowIso(), sessionHash)
    .run();
}

/**
 * back-channel 登出扇出（TECH_DESIGN §8.7 / PRD P0-9）：逐个向相关 client 的
 * backchannel_logout_uri POST logout_token JWT，client 据此清掉自己的本地登录态。
 * sid = 会话指纹，RP 存下来即可被精准命中；同一会话对多个 client 各推一条。
 * 地址一次查齐（原先每个 client 一次 D1），推送走 waitUntil 不拖慢登出响应；
 * 单个 client 失败只记日志（RP 侧还有 refresh 7 天兜底）。
 */
export async function notifyBackchannel(
  c: Context<AppEnv>,
  targets: { sub: string; sid: string; clientId: string }[],
): Promise<void> {
  if (targets.length === 0) return;
  const clients = [...new Set(targets.map((t) => t.clientId))];
  const rows = await c.env.DB.prepare(
    `SELECT client_id, backchannel_logout_uri FROM app WHERE client_id IN (${clients.map(() => "?").join(",")})`,
  )
    .bind(...clients)
    .all<{ client_id: string; backchannel_logout_uri: string | null }>();
  const uris = new Map<string, string>();
  for (const r of rows.results) if (r.backchannel_logout_uri) uris.set(r.client_id, r.backchannel_logout_uri);
  if (uris.size === 0) return;
  const iss = new URL(c.req.url).origin;
  let waitUntil: ((p: Promise<unknown>) => void) | null = null;
  try {
    waitUntil = c.executionCtx.waitUntil.bind(c.executionCtx);
  } catch {
    // app.request 直调（测试）没有 executionCtx：退化为就地 await
  }
  for (const t of targets) {
    const uri = uris.get(t.clientId);
    if (!uri) continue;
    const job = (async () => {
      try {
        const token = await signLogoutToken(c.env, iss, {
          aud: t.clientId,
          sub: t.sub,
          sid: t.sid,
          jti: randomToken(16),
        });
        const res = await fetch(uri, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ logout_token: token }).toString(),
        });
        if (!res.ok) console.error(`back-channel 登出通知 ${t.clientId} 失败：HTTP ${res.status}`);
      } catch (err) {
        console.error(`back-channel 登出通知 ${t.clientId} 失败：`, err);
      }
    })();
    if (waitUntil) waitUntil(job);
    else await job;
  }
}

/**
 * 某账号的存活会话 → 会话指纹到「曾用该会话换过 token 的 client」的映射（v2.0.0 管理动作共用）。
 * 只查一次 D1；吊销语句与通知扇出都复用这份结果，避免管理动作里按会话循环往返。
 */
export async function sessionsOfAccount(c: Context<AppEnv>, accountId: number): Promise<Map<string, string[]>> {
  const rows = await c.env.DB.prepare(
    `SELECT DISTINCT s.token_hash AS session_hash, rf.client_id AS client_id
       FROM session s LEFT JOIN oidc_refresh rf ON rf.session_hash = s.token_hash
      WHERE s.account_id = ? AND s.revoked_at IS NULL`,
  )
    .bind(accountId)
    .all<{ session_hash: string; client_id: string | null }>();
  const bySession = new Map<string, string[]>();
  for (const r of rows.results) {
    const list = bySession.get(r.session_hash) ?? [];
    if (r.client_id) list.push(r.client_id);
    bySession.set(r.session_hash, list);
  }
  return bySession;
}

/** 吊销某账号全部会话及其签发的全部 refresh 的语句（两条），供调用方塞进自己的 DB.batch——
 *  管理动作要求「业务写入 + 审计 + 会话吊销」同批提交，不能各写各的。 */
export function accountRevokeStatements(c: Context<AppEnv>, accountId: number, now: string): D1PreparedStatement[] {
  return [
    c.env.DB.prepare("UPDATE session SET revoked_at = ? WHERE account_id = ? AND revoked_at IS NULL").bind(now, accountId),
    c.env.DB.prepare(
      `UPDATE oidc_refresh SET revoked_at = ?
        WHERE revoked_at IS NULL
          AND session_hash IN (SELECT token_hash FROM session WHERE account_id = ?)`,
    ).bind(now, accountId),
  ];
}

function targetsOf(accountId: number, bySession: Map<string, string[]>): { sub: string; sid: string; clientId: string }[] {
  return [...bySession].flatMap(([sid, clients]) =>
    clients.map((clientId) => ({ sub: String(accountId), sid, clientId })),
  );
}

export async function revokeSessionAndNotify(c: Context<AppEnv>, sessionHash: string): Promise<void> {
  // 取该会话换过 token 的全部 client，不按 revoked_at 过滤：refresh 已被吊销（授权码重放检测、
  // RP 自己调过 /revoke）不代表 RP 的本地登录态没了，正是这些 client 最需要收到通知。
  const rows = await c.env.DB.prepare(
    "SELECT DISTINCT client_id, account_id FROM oidc_refresh WHERE session_hash = ?",
  )
    .bind(sessionHash)
    .all<{ client_id: string; account_id: number }>();
  await revokeSessionTokens(c, sessionHash);
  if (rows.results.length === 0) return;
  const sub = String(rows.results[0].account_id); // 同一会话只可能属于一个账号
  await notifyBackchannel(
    c,
    rows.results.map((r) => ({ sub, sid: sessionHash, clientId: r.client_id })),
  );
}

/**
 * 吊销某账号全部会话并逐个通知（v2.0.0：管理台「停用」「重置密码」整批吊销用）。
 * 原先只有单会话粒度的 revokeSessionAndNotify，账号级动作没有对应函数——直接循环调它会
 * 每会话一次 D1 往返。这里固定 2 次读/写 + 一次地址查询。
 * @returns 被吊销的会话数
 */
export async function revokeAccountSessionsAndNotify(c: Context<AppEnv>, accountId: number): Promise<number> {
  const bySession = await sessionsOfAccount(c, accountId);
  if (bySession.size === 0) return 0;
  await c.env.DB.batch(accountRevokeStatements(c, accountId, nowIso()));
  await notifyBackchannel(c, targetsOf(accountId, bySession));
  return bySession.size;
}

/** 吊销单个会话及其 refresh 的语句（两条），与 accountRevokeStatements 同理供调用方并入自己的 batch。
 *  必须带 account_id 条件，防止越权吊销别人的会话。 */
export function sessionRevokeStatements(
  c: Context<AppEnv>,
  sessionHash: string,
  accountId: number,
  now: string,
): D1PreparedStatement[] {
  return [
    c.env.DB.prepare(
      "UPDATE session SET revoked_at = ? WHERE token_hash = ? AND account_id = ? AND revoked_at IS NULL",
    ).bind(now, sessionHash, accountId),
    c.env.DB.prepare("UPDATE oidc_refresh SET revoked_at = ? WHERE session_hash = ? AND revoked_at IS NULL").bind(
      now,
      sessionHash,
    ),
  ];
}

/**
 * 吊销单个会话并通知（v2.0.0：管理台「强制下线」）。
 * 与 revokeSessionAndNotify 的区别：这个会把 session.revoked_at 写上（管理动作要真的踢下线，
 * 而不是依赖调用方先 destroySession）。
 * @returns 是否真的吊销了一行（false = 会话不存在、不属于该账号、或已吊销）
 */
export async function revokeOneSessionAndNotify(
  c: Context<AppEnv>,
  accountId: number,
  sessionHash: string,
): Promise<boolean> {
  const now = nowIso();
  const results = await c.env.DB.batch(sessionRevokeStatements(c, sessionHash, accountId, now));
  if ((results[0]?.meta.changes ?? 0) !== 1) return false;
  const rows = await c.env.DB.prepare("SELECT DISTINCT client_id FROM oidc_refresh WHERE session_hash = ?")
    .bind(sessionHash)
    .all<{ client_id: string }>();
  await notifyBackchannel(
    c,
    rows.results.map((r) => ({ sub: String(accountId), sid: sessionHash, clientId: r.client_id })),
  );
  return true;
}
