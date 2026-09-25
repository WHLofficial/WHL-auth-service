-- v2.0.0：管理能力落地 auth（账号级权限点额外授予 / 账号停用 / 会话来源 IP）
-- 背景：账号真源 2026-09-14 收口到本库后，tour 管理台的写操作仍打自己的库（改角色、解锁、
-- 重置密码、开放注册开关、注册码生成/列出 共 6 处死写），管理员日常入口批量失效。
-- 本迁移补齐 auth 侧管理动作所需的结构；管理界面仍留在 tour，经机器端点（HMAC）改本库。
-- 三处变更互相独立，均不涉及存量数据改写。
-- 审计表（audit_log）无需变更：0001_init.sql 的 event 列注释里已预留 role.grant 等事件名。

-- 1. 账号级权限点额外授予：与 user_role 平行的第二来源，用于「这个人只需要这一个权限点，
--    但不该给他整个角色」的场景。只加不减——取消勾选只删本表的行，角色带来的权限点删不掉。
--    路径解析见 src/routes/oidc.ts 的 permissionsFor（角色来源与授予来源一次 UNION 取齐）。
CREATE TABLE account_permission (
  account_id    INTEGER NOT NULL,
  permission_id INTEGER NOT NULL REFERENCES permission(id),
  granted_by    INTEGER,
  granted_at    TEXT NOT NULL,
  PRIMARY KEY (account_id, permission_id)   -- 主键索引即覆盖按 account_id 的查询，不另建索引
);

-- 2. 账号停用：locked 是「观众号」（能登录、受限，解锁前不能绑队/提交阵容）的既有语义，
--    不能挪作他用（迁去当封禁会导致「停不住人」或打死观众号概念），故单开字段。
--    NULL = 正常；非 NULL = 已停用（记停用时刻）。生效点见 lib/session.ts 的 getSessionUser
--    与 routes/pages.ts 的登录 handler。
ALTER TABLE account ADD COLUMN disabled_at TEXT;

-- 3. 会话来源 IP：管理台「活跃会话」列表要显示来源。last_seen_at 列自 0001 起就存在但从未写入，
--    本增量启用（写点与节流见 lib/session.ts）。
ALTER TABLE session ADD COLUMN ip TEXT;
