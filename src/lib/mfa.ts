// MFA 的持久化小件：登录挑战、恢复码、设置期的待确认 secret。
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import type { Context } from "hono";
import type { AppEnv } from "../env";
import { generateCode, randomToken, sha256Hex } from "./crypto";
import { nowIso } from "./util";

export const MFA_CHALLENGE_COOKIE = "whl_mfa";
const CHALLENGE_TTL_SECONDS = 5 * 60;
const MAX_ATTEMPTS = 8;
const PENDING_TTL_MS = 10 * 60_000;

function challengeCookie(c: Context<AppEnv>, token: string): void {
  setCookie(c, MFA_CHALLENGE_COOKIE, token, {
    httpOnly: true,
    sameSite: "Lax",
    path: "/",
    secure: new URL(c.req.url).protocol === "https:",
    maxAge: CHALLENGE_TTL_SECONDS,
  });
}

export type MfaChallenge = {
  token_hash: string;
  account_id: number;
  next_path: string;
  attempts: number;
  expires_at: string;
};

/** 新建登录挑战：同一账号只保留最新一条，避免旧挑战被继续尝试 */
export async function createMfaChallenge(
  c: Context<AppEnv>,
  accountId: number,
  nextPath: string,
): Promise<void> {
  const token = randomToken();
  const now = nowIso();
  await c.env.DB.batch([
    c.env.DB.prepare("DELETE FROM mfa_challenge WHERE account_id = ?").bind(accountId),
    c.env.DB.prepare(
      "INSERT INTO mfa_challenge (token_hash, account_id, next_path, created_at, expires_at, attempts) VALUES (?, ?, ?, ?, ?, 0)",
    ).bind(
      await sha256Hex(token),
      accountId,
      nextPath,
      now,
      new Date(Date.now() + CHALLENGE_TTL_SECONDS * 1000).toISOString(),
    ),
  ]);
  challengeCookie(c, token);
}

export async function readMfaChallenge(c: Context<AppEnv>): Promise<MfaChallenge | null> {
  const token = getCookie(c, MFA_CHALLENGE_COOKIE);
  if (!token) return null;
  const row = await c.env.DB.prepare(
    "SELECT token_hash, account_id, next_path, attempts, expires_at FROM mfa_challenge WHERE token_hash = ?",
  )
    .bind(await sha256Hex(token))
    .first<MfaChallenge>();
  if (!row) return null;
  if (row.expires_at <= nowIso()) {
    await clearMfaChallenge(c, row.token_hash);
    return null;
  }
  return row;
}

export async function clearMfaChallenge(c: Context<AppEnv>, tokenHash: string): Promise<void> {
  await c.env.DB.prepare("DELETE FROM mfa_challenge WHERE token_hash = ?").bind(tokenHash).run();
  deleteCookie(c, MFA_CHALLENGE_COOKIE, { path: "/" });
}

/** 失败计数；达到上限直接作废挑战，返回 true 表示已作废 */
export async function failMfaChallenge(c: Context<AppEnv>, challenge: MfaChallenge): Promise<boolean> {
  const attempts = challenge.attempts + 1;
  if (attempts >= MAX_ATTEMPTS) {
    await clearMfaChallenge(c, challenge.token_hash);
    return true;
  }
  await c.env.DB.prepare("UPDATE mfa_challenge SET attempts = ? WHERE token_hash = ?")
    .bind(attempts, challenge.token_hash)
    .run();
  return false;
}

export function recoveryCode(): string {
  const raw = generateCode(10);
  return `${raw.slice(0, 5)}-${raw.slice(5)}`;
}

const normalizeRecovery = (code: string) => code.toUpperCase().replace(/[\s-]/g, "");

/** 启用 MFA 时一次性生成 8 个恢复码；明文只在本次响应里出现 */
export async function issueRecoveryCodes(c: Context<AppEnv>, accountId: number): Promise<string[]> {
  const codes = Array.from({ length: 8 }, recoveryCode);
  const now = nowIso();
  const stmts = [c.env.DB.prepare("DELETE FROM mfa_recovery_code WHERE account_id = ?").bind(accountId)];
  for (const code of codes) {
    stmts.push(
      c.env.DB.prepare(
        "INSERT INTO mfa_recovery_code (account_id, code_hash, created_at) VALUES (?, ?, ?)",
      ).bind(accountId, await sha256Hex(normalizeRecovery(code)), now),
    );
  }
  await c.env.DB.batch(stmts);
  return codes;
}

export async function consumeRecoveryCode(
  c: Context<AppEnv>,
  accountId: number,
  code: string,
): Promise<boolean> {
  const normalized = normalizeRecovery(code);
  if (normalized.length < 8) return false;
  const hash = await sha256Hex(normalized);
  const res = await c.env.DB.prepare(
    "UPDATE mfa_recovery_code SET used_at = ? WHERE account_id = ? AND code_hash = ? AND used_at IS NULL",
  )
    .bind(nowIso(), accountId, hash)
    .run();
  return res.meta.changes === 1;
}

export type TotpRow = { secret: string | null; enabled_at: string | null; last_step: number | null };

export async function loadTotpRow(c: Context<AppEnv>, accountId: number): Promise<TotpRow | null> {
  return c.env.DB.prepare(
    "SELECT totp_secret AS secret, totp_enabled_at AS enabled_at, totp_last_step AS last_step FROM account WHERE id = ?",
  )
    .bind(accountId)
    .first<TotpRow>();
}

/** 原子占用一个时间窗：并发提交同一验证码时只有一个请求能成功 */
export async function claimTotpStep(c: Context<AppEnv>, accountId: number, step: number): Promise<boolean> {
  const res = await c.env.DB.prepare(
    "UPDATE account SET totp_last_step = ? WHERE id = ? AND (totp_last_step IS NULL OR totp_last_step < ?)",
  )
    .bind(step, accountId, step)
    .run();
  return res.meta.changes === 1;
}

export async function savePendingSecret(c: Context<AppEnv>, accountId: number, sealed: string): Promise<void> {
  await c.env.DB.prepare("UPDATE account SET totp_pending_secret = ?, totp_pending_at = ? WHERE id = ?")
    .bind(sealed, nowIso(), accountId)
    .run();
}

export async function loadPendingSecret(c: Context<AppEnv>, accountId: number): Promise<string | null> {
  const row = await c.env.DB.prepare(
    "SELECT totp_pending_secret AS secret, totp_pending_at AS at FROM account WHERE id = ?",
  )
    .bind(accountId)
    .first<{ secret: string | null; at: string | null }>();
  if (!row?.secret || !row.at) return null;
  if (Date.now() - Date.parse(row.at) > PENDING_TTL_MS) return null;
  return row.secret;
}

export async function enableTotp(
  c: Context<AppEnv>,
  accountId: number,
  sealed: string,
  step: number,
): Promise<void> {
  await c.env.DB.prepare(
    `UPDATE account
        SET totp_secret = ?, totp_enabled_at = ?, totp_last_step = ?,
            totp_pending_secret = NULL, totp_pending_at = NULL
      WHERE id = ?`,
  )
    .bind(sealed, nowIso(), step, accountId)
    .run();
}

export async function clearExpiredMfa(env: AppEnv["Bindings"]): Promise<void> {
  const now = nowIso();
  await env.DB.batch([
    env.DB.prepare("DELETE FROM mfa_challenge WHERE expires_at <= ?").bind(now),
    env.DB.prepare("DELETE FROM mfa_challenge WHERE account_id NOT IN (SELECT id FROM account)"),
  ]);
}
