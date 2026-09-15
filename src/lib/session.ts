import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import type { Context } from "hono";
import type { AppEnv, SessionUser } from "../env";
import { roleFromRoleRows } from "./accounts";
import { randomToken, sha256Hex } from "./crypto";
import { signLogoutToken } from "./oidc";
import { nowIso } from "./util";

export const SESSION_COOKIE = "whl_session";
const TTL_SECONDS = 7 * 24 * 3600;

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
    "INSERT INTO session (token_hash, account_id, family_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
  )
    .bind(
      await sha256Hex(token),
      userId,
      randomToken(),
      nowIso(),
      new Date(Date.now() + TTL_SECONDS * 1000).toISOString(),
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
  const row = await c.env.DB.prepare(
    `SELECT a.id, a.name, a.locked, a.must_change_pw, s.revoked_at, s.expires_at
       FROM session s JOIN account a ON a.id = s.account_id
      WHERE s.token_hash = ?`,
  )
    .bind(await sha256Hex(token))
    .first<{
      id: number;
      name: string;
      locked: number;
      must_change_pw: number;
      revoked_at: string | null;
      expires_at: string;
    }>();
  if (!row || row.revoked_at || row.expires_at <= nowIso()) return null;
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
 * 全局登出传播（TECH_DESIGN §8.7 / PRD P0-9）：在吊销之外，逐个向该会话换过 token 的
 * client 的 backchannel_logout_uri POST logout_token JWT，client 据此清掉自己的本地登录态。
 * 推送走 waitUntil 不拖慢登出响应；单个 client 失败只记日志（RP 侧还有 refresh 7 天兜底）。
 * 三个销毁会话的入口都应改调本函数而不是 revokeSessionTokens。
 */
export async function revokeSessionAndNotify(c: Context<AppEnv>, sessionHash: string): Promise<void> {
  // 取该会话换过 token 的全部 client，不按 revoked_at 过滤：refresh 已被吊销（授权码重放检测、
  // RP 自己调过 /revoke）不代表 RP 的本地登录态没了，正是这些 client 最需要收到通知。
  const rows = await c.env.DB.prepare(
    "SELECT DISTINCT client_id, account_id FROM oidc_refresh WHERE session_hash = ?",
  )
    .bind(sessionHash)
    .all<{ client_id: string; account_id: number }>();
  await revokeSessionTokens(c, sessionHash);
  const clients = [...new Set(rows.results.map((r) => r.client_id))];
  if (clients.length === 0) return;
  const iss = new URL(c.req.url).origin;
  const sub = String(rows.results[0].account_id); // 同一会话只可能属于一个账号
  let waitUntil: ((p: Promise<unknown>) => void) | null = null;
  try {
    waitUntil = c.executionCtx.waitUntil.bind(c.executionCtx);
  } catch {
    // app.request 直调（测试）没有 executionCtx：退化为就地 await
  }
  for (const clientId of clients) {
    const appRow = await c.env.DB.prepare("SELECT backchannel_logout_uri FROM app WHERE client_id = ?")
      .bind(clientId)
      .first<{ backchannel_logout_uri: string | null }>();
    if (!appRow?.backchannel_logout_uri) continue;
    const uri = appRow.backchannel_logout_uri;
    const job = (async () => {
      try {
        const token = await signLogoutToken(c.env, iss, {
          aud: clientId,
          sub,
          sid: sessionHash,
          jti: randomToken(16),
        });
        const res = await fetch(uri, {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ logout_token: token }).toString(),
        });
        if (!res.ok) console.error(`back-channel 登出通知 ${clientId} 失败：HTTP ${res.status}`);
      } catch (err) {
        console.error(`back-channel 登出通知 ${clientId} 失败：`, err);
      }
    })();
    if (waitUntil) waitUntil(job);
    else await job;
  }
}
