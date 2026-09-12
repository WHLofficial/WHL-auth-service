-- 中央账号模型建表（TECH_DESIGN §5.2）
-- 与文档 DDL 的微调（文档注明"实现时可微调"）：
-- 1. account 侧外键（session/identity/user_role 的 account_id）不加 REFERENCES：
--    过渡期（步骤①②）account/credential 尚未写入，真源在 TOUR_DB.user，
--    这些列的取值与 tour user.id 同值延续；收口（步骤③）一次性复制后同值生效。
--    audit_log 同理（文档 DDL 本就未加）。
-- 2. credential 加 UNIQUE(account_id, type)：每账号每种凭证类型仅一条。
-- 3. session/audit_log 补查询索引（登出全部会话 / 审计按时间筛选）。
-- 4. signup_code.expires_at 允许 NULL：与 tour 现表语义一致（永久码）。

CREATE TABLE account (
  id INTEGER PRIMARY KEY,              -- 收口时 = tour user.id 同值延续，三系统业务外键零改动
  name TEXT NOT NULL UNIQUE,           -- 昵称兼登录名（继承）
  email TEXT,                          -- 可选、未验证（继承）
  locked INTEGER NOT NULL DEFAULT 0,
  must_change_pw INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE credential (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL,
  type TEXT NOT NULL DEFAULT 'password',   -- 预留 'totp'（P2 2FA）
  hash TEXT NOT NULL,                      -- pbkdf2$iter$salt_b64$hash_b64（与 tour 格式一致）
  iterations INTEGER NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (account_id, type)
);

CREATE TABLE identity (
  id INTEGER PRIMARY KEY,
  account_id INTEGER NOT NULL,
  provider TEXT NOT NULL,                  -- 'qq'（预留 'club_team' 等）
  provider_uid TEXT NOT NULL,
  verified_at TEXT,
  bound_at TEXT NOT NULL,
  UNIQUE (provider, provider_uid)          -- 一个 QQ 只能绑一个账号
);
CREATE UNIQUE INDEX idx_identity_acct_provider ON identity(account_id, provider);
-- 双向唯一：一个账号在每个 provider 下也只有一个身份（吸收 guess user_binding 约束）

CREATE TABLE session (
  token_hash TEXT PRIMARY KEY,             -- sha256(token)，token 本身不落库
  account_id INTEGER NOT NULL,
  family_id TEXT NOT NULL,                 -- refresh 轮换族：重用检测→吊销整族
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  last_seen_at TEXT,
  revoked_at TEXT
);
CREATE INDEX idx_session_account ON session(account_id);

CREATE TABLE app (
  client_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  redirect_uris TEXT NOT NULL,             -- JSON 数组，精确匹配
  backchannel_logout_uri TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE permission (
  id INTEGER PRIMARY KEY,
  app_id TEXT NOT NULL REFERENCES app(client_id),
  key TEXT NOT NULL,                       -- 全键名，如 guess.event.manage
  description TEXT,
  UNIQUE (app_id, key)
);

CREATE TABLE role (
  id INTEGER PRIMARY KEY,
  app_id TEXT REFERENCES app(client_id),   -- NULL = 全局角色（superadmin）
  key TEXT NOT NULL,
  name TEXT NOT NULL,
  UNIQUE (app_id, key)
);

CREATE TABLE role_permission (
  role_id INTEGER NOT NULL REFERENCES role(id),
  permission_id INTEGER NOT NULL REFERENCES permission(id),
  PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_role (
  account_id INTEGER NOT NULL,
  role_id INTEGER NOT NULL REFERENCES role(id),
  granted_by INTEGER,
  granted_at TEXT NOT NULL,
  PRIMARY KEY (account_id, role_id)
);

CREATE TABLE signup_code (                 -- 机制照搬 tour（sha256 存储、过期、次数）
  code_hash TEXT PRIMARY KEY,
  expires_at TEXT,                         -- NULL = 永久
  max_uses INTEGER,                        -- NULL = 不限次
  used_count INTEGER NOT NULL DEFAULT 0,
  created_by INTEGER,
  created_at TEXT NOT NULL
);

CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY,
  account_id INTEGER,                      -- 过渡期 = tour user.id 同值
  event TEXT NOT NULL,                     -- login.ok/login.fail/bind.claim/role.grant/...
  detail TEXT,                             -- JSON
  ip TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_audit_account ON audit_log(account_id);
CREATE INDEX idx_audit_created ON audit_log(created_at);
