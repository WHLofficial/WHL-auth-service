-- OIDC Provider 工件表（P0-4：authorize/token/userinfo/jwks，TECH_DESIGN §3 端点清单的实现载体）
-- 文档 DDL（§5.2）未单列这两张表，属"实现时可微调"范围：
-- §8.2 要求 code 一次性 ≤60s 绑定 client+redirect_uri+challenge，§8.6 要求 refresh 轮换 +
-- 重用检测吊销整族，两者都需要服务端持久化，哈希落库（明文 token 不存）。
-- 与 session 表的关系：session 行是兼容会话记录（token_hash 对应 whl_session cookie），
-- oidc_refresh 的 family_id 是 token 轮换族，两者独立；oidc_code.session_hash 记录
-- 发码时的登录会话，供 /logout 吊销「该会话签发的全部 token」（§3 logout 端点语义）。

-- RP 发起登出的合法跳转白名单（JSON 数组精确匹配）；初值 = 各系统首页，接入时可改
ALTER TABLE app ADD COLUMN post_logout_redirect_uris TEXT NOT NULL DEFAULT '[]';
UPDATE app SET post_logout_redirect_uris = '["https://tour.whleague.win/"]'  WHERE client_id = 'tour';
UPDATE app SET post_logout_redirect_uris = '["https://guess.whleague.win/"]' WHERE client_id = 'guess';
UPDATE app SET post_logout_redirect_uris = '["https://club.whleague.win/"]'  WHERE client_id = 'club';

CREATE TABLE oidc_code (
  code_hash             TEXT PRIMARY KEY,        -- sha256(code)，code 本身不落库
  account_id            INTEGER NOT NULL,        -- 过渡期 = tour user.id 同值
  client_id             TEXT NOT NULL REFERENCES app(client_id),
  redirect_uri          TEXT NOT NULL,           -- 发码时的精确值，换 code 时必须逐字一致
  scope                 TEXT NOT NULL,
  nonce                 TEXT,                    -- 原样进 ID token，防重放
  code_challenge        TEXT NOT NULL,           -- S256
  code_challenge_method TEXT NOT NULL,
  session_hash          TEXT NOT NULL,           -- 发码时的兼容会话（登出联动吊销）
  created_at            TEXT NOT NULL,
  expires_at            TEXT NOT NULL,           -- 60 秒
  consumed_at           TEXT                     -- 原子置位实现一次性；置位后再出现 = 重放
);
CREATE INDEX idx_oidc_code_session ON oidc_code(session_hash);

CREATE TABLE oidc_refresh (
  token_hash  TEXT PRIMARY KEY,                  -- sha256(token)
  account_id  INTEGER NOT NULL,                  -- 过渡期 = tour user.id 同值
  client_id   TEXT NOT NULL REFERENCES app(client_id),
  scope       TEXT NOT NULL,
  code_hash   TEXT,                              -- 签发来源授权码（code 重放时整链吊销）
  family_id   TEXT NOT NULL,                     -- 轮换族：重用检测 → 吊销整族（§8.6）
  session_hash TEXT NOT NULL,                     -- 所属登录会话（登出联动吊销）
  created_at  TEXT NOT NULL,
  expires_at  TEXT NOT NULL,                     -- 7 天，对齐 auth 会话
  rotated_at  TEXT,                              -- 非 NULL = 已轮换，再次出现即为重用
  revoked_at  TEXT
);
CREATE INDEX idx_oidc_refresh_account ON oidc_refresh(account_id);
CREATE INDEX idx_oidc_refresh_family ON oidc_refresh(family_id);
CREATE INDEX idx_oidc_refresh_session ON oidc_refresh(session_hash);
