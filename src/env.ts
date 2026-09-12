export type Role = "coach" | "admin" | "superadmin";

export type Bindings = {
  /** auth 自有库：session / identity / app / permission / role / audit_log（TECH_DESIGN §5.3） */
  DB: D1Database;
  /** 过渡期绑定赛事平台账号库（user / signup_code 读写），同 guess 现状模式；步骤③收口后移除 */
  TOUR_DB: D1Database;
  /** 共享会话 KV（与 tour/guess 同一 namespace）：写 sess:* 兼容键，三系统零改动读取；收口后移除 */
  SESSION_KV: KVNamespace;
  /** auth 自有 KV：rl:* 限流等，与共享会话 KV 隔离（TECH_DESIGN §8.4） */
  RL_KV: KVNamespace;
  /** 会话 cookie 的 Domain 属性（".whleague.win"），同主域子系统共享登录态；不配则 host-only。生产用 secret 配置 */
  COOKIE_DOMAIN?: string;
};

export type SessionUser = {
  id: number;
  name: string;
  role: Role;
  locked: boolean;
  mustChangePassword: boolean;
};

export type AppEnv = {
  Bindings: Bindings;
  Variables: { user: SessionUser | null };
};
