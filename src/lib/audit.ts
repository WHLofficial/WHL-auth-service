import type { Context } from "hono";
import type { AppEnv } from "../env";
import { clientIp, nowIso } from "./util";

export type AuditEvent =
  | "login.ok"
  | "login.fail"
  | "login.rate_limited"
  | "register.ok"
  | "register.rate_limited"
  | "pw.change"
  | "logout"
  | "oidc.code_replay"
  | "oidc.refresh_reuse"
  // 管理动作（增量 8）：TECH_DESIGN §8.8 明确要求 role.grant/revoke 与 session.revoke 入审计，
  // 收口前因没有管理入口而缺失；随管理机器端点一并补齐。account_id 记「被操作的账号」，
  // 操作者由 tour 带进 detail.actor_id（通道已是 HMAC，tour 是可信调用方）。
  | "role.grant"
  | "role.revoke"
  | "perm.grant"
  | "perm.revoke"
  | "session.revoke"
  | "pw.reset"
  | "account.disable"
  | "account.enable"
  | "account.unlock"
  | "signup_code.create"
  | "org.open_reg";

/** 关键事件入 audit_log（auth D1）。account_id = auth account.id（收口时与 tour user.id 同值迁移）；
 *  传 null 表示「事件本身不针对某个账号」（如管理员生成注册码、改开放注册开关）。 */
export async function audit(
  c: Context<AppEnv>,
  event: AuditEvent,
  opts: { accountId?: number | null; detail?: Record<string, unknown> } = {},
): Promise<void> {
  await auditStatement(c, event, opts).run();
}

/**
 * 审计行的 D1 语句形式，供 DB.batch 使用：管理动作要求「业务写入与审计同批提交」
 * （同库隐式事务），否则断开两条 run 会出现「角色已改但审计缺失」的撕裂状态——
 * 增量 7 的球队绑定（src/routes/machine.ts 烧码）已按此口径实现，管理端点沿用。
 */
export function auditStatement(
  c: Context<AppEnv>,
  event: AuditEvent,
  opts: { accountId?: number | null; detail?: Record<string, unknown> } = {},
): D1PreparedStatement {
  return c.env.DB.prepare(
    "INSERT INTO audit_log (account_id, event, detail, ip, created_at) VALUES (?, ?, ?, ?, ?)",
  ).bind(
    opts.accountId ?? null,
    event,
    opts.detail ? JSON.stringify(opts.detail) : null,
    clientIp(c),
    nowIso(),
  );
}
