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
  | "oidc.refresh_reuse";

/** 关键事件入 audit_log（auth D1）。过渡期 account_id = tour user.id 同值 */
export async function audit(
  c: Context<AppEnv>,
  event: AuditEvent,
  opts: { accountId?: number; detail?: Record<string, unknown> } = {},
): Promise<void> {
  await c.env.DB.prepare(
    "INSERT INTO audit_log (account_id, event, detail, ip, created_at) VALUES (?, ?, ?, ?, ?)",
  )
    .bind(
      opts.accountId ?? null,
      event,
      opts.detail ? JSON.stringify(opts.detail) : null,
      clientIp(c),
      nowIso(),
    )
    .run();
}
