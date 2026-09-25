-- v3.1.0：权限点语义对齐 + 审计查询支撑（PRD P1-3）
--
-- ① 删除死权限点 tour.team.bindcode.issue：v1.0.0 把球队认证码签发收进 auth 机器端点
--    （/api/team/bindcode，按绑定关系校验、不经权限点），tour 全仓从未 requirePermission 检查过它——
--    目录里有、claims 里下发、无人消费，徒增 superadmin/recorder 的 claims 体积。先删关联行再删目录行；
--    account_permission（账号级授予）同带 REFERENCES，防御性一并清掉再删目录行。
-- ② audit_log 事件筛选索引：/api/admin/audit/query（P1-3）支持按 event 过滤，
--    0001 只有 account/created 两个单列索引，event 维度会全表扫。

DELETE FROM role_permission
WHERE permission_id IN (SELECT id FROM permission WHERE key = 'tour.team.bindcode.issue');

DELETE FROM account_permission
WHERE permission_id IN (SELECT id FROM permission WHERE key = 'tour.team.bindcode.issue');

DELETE FROM permission WHERE key = 'tour.team.bindcode.issue';

CREATE INDEX idx_audit_event ON audit_log(event, created_at);
