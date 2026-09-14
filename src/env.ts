export type Role = "coach" | "admin" | "superadmin";

export type Bindings = {
  /** auth 自有库：account/credential/session/identity/app/role/audit_log 等，账号真源（TECH_DESIGN §5.3 终态） */
  DB: D1Database;
  /** 共享会话 KV（与 tour/guess 同一 namespace）：写 sess:* 兼容键，三系统零改动读取；收口后随 P0-13 停写移除 */
  SESSION_KV: KVNamespace;
  // 限流计数已迁 D1 rate_limit 表（TEST_REPORT F-E）：不再需要 RL_KV 绑定
  /** 会话 cookie 的 Domain 属性（".whleague.win"），同主域子系统共享登录态；不配则 host-only。生产用 secret 配置 */
  COOKIE_DOMAIN?: string;
  /** OIDC RS256 签名私钥（PKCS8，PEM 或单行 base64 均可），kid 取公钥 JWK 指纹自动派生（TECH_DESIGN §9.4） */
  AUTH_JWT_PRIVATE_KEY?: string;
  /** QQ 绑定通道密钥（积分插件 ↔ auth 机器端点验签，TECH_DESIGN §7.4）。独立密钥，不复用 guess 的 SYNC_SECRET */
  BIND_SECRET?: string;
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
