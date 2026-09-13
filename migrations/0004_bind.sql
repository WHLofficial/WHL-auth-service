-- QQ 绑定一次性码（P0-8，TECH_DESIGN §7）：登录用户在绑定页生成，QQ 群「绑定 <码>」
-- 由积分插件 HMAC 调 /api/bind/claim 核销。机制照搬 signup_code：sha256 存储、明文码不落库
-- （6 位数字空间只有 10^6，库泄露时不能让人直接拿走活码）。
CREATE TABLE bind_code (
  code_hash  TEXT PRIMARY KEY,             -- sha256(code)
  account_id INTEGER NOT NULL,             -- 过渡期 = tour user.id 同值
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,                -- 10 分钟
  used_at    TEXT                        -- 原子置位实现一次性
);
CREATE INDEX idx_bind_code_account ON bind_code(account_id);
