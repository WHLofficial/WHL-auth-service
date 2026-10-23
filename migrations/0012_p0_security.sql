-- v4.0.0（P0 安全修复）：管理通道分离 / MFA / HMAC 防重放
-- 1. 账号 TOTP：totp_secret 只存 AES-GCM 密文（enc:v1:...），totp_last_step 防同一时间窗内重放；
--    totp_pending_* 是「已扫码、未验证」的临时态，10 分钟后由设置页重新生成。
-- 2. 登录二次验证挑战：短时一次性 token（只存 sha256），next_path 保留 OIDC 回跳链路。
-- 3. 恢复码：只存 sha256，used_at 标记一次性。
-- 4. HMAC nonce 防重放：管理通道每个请求必须带唯一 X-Nonce，落库去重，按签名窗口过期。
ALTER TABLE account ADD COLUMN totp_secret TEXT;
ALTER TABLE account ADD COLUMN totp_enabled_at TEXT;
ALTER TABLE account ADD COLUMN totp_last_step INTEGER;
ALTER TABLE account ADD COLUMN totp_pending_secret TEXT;
ALTER TABLE account ADD COLUMN totp_pending_at TEXT;

CREATE TABLE mfa_challenge (
  token_hash TEXT PRIMARY KEY,              -- sha256(whl_mfa cookie 明文)
  account_id INTEGER NOT NULL,
  next_path TEXT NOT NULL DEFAULT '/',      -- 已过 safeNext 的站内路径
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_mfa_challenge_account ON mfa_challenge(account_id);
CREATE INDEX idx_mfa_challenge_expires ON mfa_challenge(expires_at);

CREATE TABLE mfa_recovery_code (
  account_id INTEGER NOT NULL,
  code_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  used_at TEXT,
  PRIMARY KEY (account_id, code_hash)
);

CREATE TABLE hmac_nonce (
  nonce TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX idx_hmac_nonce_expires ON hmac_nonce(expires_at);
