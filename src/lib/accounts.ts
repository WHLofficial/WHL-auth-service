import type { Context } from "hono";
import type { AppEnv, Role, SessionUser } from "../env";

/**
 * 账号收口（P0-11，TECH_DESIGN §5.3 终态）：账号/凭证真源 = auth 库 account/credential，
 * tour user 表自此只读归档、auth 不再读写。role 不再是账号列，而是 user_role 授权的投影：
 * 全局 superadmin 角色 → 'superadmin'；持有 tour.recorder → 'admin'；否则 'coach'。
 * （鉴权判定走 userinfo 下发的权限点（各 client 的 requirePermission），这里的 role 只服务
 * auth 自身页面的展示。）
 */
export type AccountUser = SessionUser & { email: string | null; disabledAt: string | null };

/** user_role 行 → role 投影（loadAccountUser 与 getSessionUser 共用，口径必须一致）：
 * 全局 superadmin 角色 → 'superadmin'；持有 tour.recorder → 'admin'；否则 'coach'。 */
export function roleFromRoleRows(rows: { app_id: string | null; role_key: string }[]): Role {
  if (rows.some((r) => r.app_id === null && r.role_key === "superadmin")) return "superadmin";
  if (rows.some((r) => r.app_id === "tour" && r.role_key === "recorder")) return "admin";
  return "coach";
}

export async function loadAccountUser(c: Context<AppEnv>, accountId: number): Promise<AccountUser | null> {
  const account = await c.env.DB.prepare(
    "SELECT id, name, email, locked, must_change_pw, disabled_at FROM account WHERE id = ?",
  )
    .bind(accountId)
    .first<{
      id: number;
      name: string;
      email: string | null;
      locked: number;
      must_change_pw: number;
      disabled_at: string | null;
    }>();
  if (!account) return null;
  const roles = await c.env.DB.prepare(
    "SELECT r.app_id AS app_id, r.key AS role_key FROM user_role ur JOIN role r ON r.id = ur.role_id WHERE ur.account_id = ?",
  )
    .bind(accountId)
    .all<{ app_id: string | null; role_key: string }>();
  return {
    id: account.id,
    name: account.name,
    email: account.email,
    role: roleFromRoleRows(roles.results),
    locked: account.locked === 1,
    mustChangePassword: account.must_change_pw === 1,
    disabledAt: account.disabled_at,
  };
}
