import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import type { Context } from "hono";
import type { AppEnv, SessionUser } from "../env";
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
 * 兼容会话桥双写（TECH_DESIGN §5.3）：
 * 1. 共享 KV 写 `sess:{token}`（值形状与 tour 完全一致），tour/guess/club 零改动读取；
 * 2. auth D1 session 表记录 token_hash，供 OIDC 与主动吊销使用。
 * 两处 TTL 一致（7 天，对齐现状）。
 */
export async function createSession(c: Context<AppEnv>, userId: number): Promise<void> {
  const token = randomToken();
  await c.env.SESSION_KV.put(`sess:${token}`, JSON.stringify({ userId }), {
    expirationTtl: TTL_SECONDS,
  });
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
}

export async function getSessionUser(c: Context<AppEnv>): Promise<SessionUser | null> {
  const token = getCookie(c, SESSION_COOKIE);
  if (!token) return null;
  const raw = await c.env.SESSION_KV.get(`sess:${token}`);
  if (!raw) return null;
  let userId: number;
  try {
    const parsed = JSON.parse(raw) as { userId?: unknown };
    if (typeof parsed.userId !== "number") return null;
    userId = parsed.userId;
  } catch {
    return null;
  }
  // auth 侧主动吊销（全局登出/管理台）即时生效；tour 登录页产生的老会话无 D1 记录，
  // 依赖 KV 删除传播（最长 ~60s，TECH_DESIGN §8.7 已按假设评估）
  const sess = await c.env.DB.prepare("SELECT revoked_at FROM session WHERE token_hash = ?")
    .bind(await sha256Hex(token))
    .first<{ revoked_at: string | null }>();
  if (sess?.revoked_at) return null;
  // 过渡期账号真源在 tour 库（TECH_DESIGN §5.3）；收口后改查 auth account
  const row = await c.env.TOUR_DB.prepare(
    "SELECT id, name, role, locked, must_change_pw FROM user WHERE id = ?",
  )
    .bind(userId)
    .first<{ id: number; name: string; role: SessionUser["role"]; locked: number; must_change_pw: number }>();
  return row
    ? {
        id: row.id,
        name: row.name,
        role: row.role,
        locked: row.locked === 1,
        mustChangePassword: row.must_change_pw === 1,
      }
    : null;
}

export async function destroySession(c: Context<AppEnv>): Promise<void> {
  const token = getCookie(c, SESSION_COOKIE);
  if (token) {
    await c.env.SESSION_KV.delete(`sess:${token}`);
    await c.env.DB.prepare("UPDATE session SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL")
      .bind(nowIso(), await sha256Hex(token))
      .run();
  }
  // 删除需 Name+Domain+Path 全匹配：共享域下漏掉 domain 会删不掉，登出后仍带登录态
  deleteCookie(c, SESSION_COOKIE, { path: "/", ...cookieDomain(c) });
  // 兜底清掉切换共享域前遗留的 host-only 同名 cookie
  if (c.env.COOKIE_DOMAIN) deleteCookie(c, SESSION_COOKIE, { path: "/" });
}

/** 登出/改密联动：吊销该兼容会话签发的全部 OIDC refresh（TECH_DESIGN §3 登出语义）。
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
  // 先取参与 client 再吊销：吊销后按 revoked_at 查就是空集
  const rows = await c.env.DB.prepare(
    "SELECT DISTINCT client_id, account_id FROM oidc_refresh WHERE session_hash = ? AND revoked_at IS NULL",
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
