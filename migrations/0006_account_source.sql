-- 账号收口（P0-11，TECH_DESIGN §9.1 ③）：组织级注册开关随账号真源一并迁入 auth。
-- 初值由 scripts/migrate-accounts.mjs 从 tour 库 organization 表复制；tour user 表自此对 auth 只读。
CREATE TABLE organization (
  id INTEGER PRIMARY KEY,
  allow_open_reg INTEGER NOT NULL DEFAULT 0
);
INSERT INTO organization (id, allow_open_reg) VALUES (1, 0);
