// 权限点投影：角色派生 ∪ 账号级额外授予。
// 从 routes/oidc.ts 抽出（v4.0.0 管理端也要做服务端权限校验），口径与 userinfo 完全一致。
// 全局角色只放行 superadmin：未来新增全局角色时，其权限不会默认泄漏到所有 aud。
import type { Context } from "hono";
import type { AppEnv } from "../env";

export async function permissionsFor(c: Context<AppEnv>, aud: string, accountId: number): Promise<string[]> {
  const rows = await c.env.DB.prepare(
    `SELECT p.key AS perm_key
       FROM user_role ur
       JOIN role r ON r.id = ur.role_id
       JOIN role_permission rp ON rp.role_id = r.id
       JOIN permission p ON p.id = rp.permission_id
      WHERE ur.account_id = ?
        AND (r.app_id = ? OR (r.app_id IS NULL AND r.key = 'superadmin'))
     UNION
     SELECT p.key AS perm_key
       FROM account_permission ap
       JOIN permission p ON p.id = ap.permission_id
      WHERE ap.account_id = ? AND p.app_id = ?`,
  )
    .bind(accountId, aud, accountId, aud)
    .all<{ perm_key: string }>();
  return rows.results.map((r) => r.perm_key);
}
