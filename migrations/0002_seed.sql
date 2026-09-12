-- 权限点目录 + 角色播种（TECH_DESIGN §6.1/§6.2）
-- 行为等价原则：只播种目录与角色，账号级授权（user_role）由迁移脚本按 §6.2 映射执行，
-- 保证上线第一天各系统管理员的可见/可用范围与迁移前完全一致。
-- app.redirect_uris 为 Phase ② 各系统接入时的初值，接入实现时可在 D1 中修正。

INSERT INTO app (client_id, name, redirect_uris, backchannel_logout_uri, created_at) VALUES
  ('tour',  '赛事平台',   '["https://tour.whleague.win/api/auth/callback"]',  'https://tour.whleague.win/api/auth/backchannel-logout',  '2026-09-12T00:00:00.000Z'),
  ('guess', '竞猜系统',   '["https://guess.whleague.win/api/auth/callback"]', 'https://guess.whleague.win/api/auth/backchannel-logout', '2026-09-12T00:00:00.000Z'),
  ('club',  '俱乐部平台', '["https://club.whleague.win/api/auth/callback"]',  'https://club.whleague.win/api/auth/backchannel-logout',  '2026-09-12T00:00:00.000Z');

INSERT INTO permission (app_id, key, description) VALUES
  -- tour（对应 tour 现有判定：requireAdmin 录入 / requireSuperadmin 账号管理）
  ('tour', 'tour.match.manage',        '赛事与场次录入管理'),
  ('tour', 'tour.team.bindcode.issue', '生成球队认证码'),
  ('tour', 'tour.accounts.manage',     '账号管理（重置密码、解锁）'),
  ('tour', 'tour.org.settings',        '组织设置（开放注册开关等）'),
  ('tour', 'tour.team.bind',           '教练绑队'),
  -- guess（对应 requireManager 开盘结算发奖 / api.ts 管理台）
  ('guess', 'guess.event.manage',      '竞猜开盘、结算、发奖'),
  ('guess', 'guess.users.manage',      '竞猜账号列表与发起人设置'),
  ('guess', 'guess.payout.reverse',    '发奖冲正'),
  ('guess', 'guess.recon.view',        '对账查看'),
  -- club
  ('club', 'club.clubs.manage',        '建队与球队管理'),
  ('club', 'club.bindings.unbind',     '解绑球员/球队'),
  ('club', 'club.players.import',      '球员导入'),
  ('club', 'club.ledger.manage',       '账本与期初导入'),
  ('club', 'club.registrations.manage', '报名审核'),
  ('club', 'club.compliance.view',     '合规查看'),
  ('club', 'club.squad.manage',        '教练排阵'),
  ('club', 'club.registrations.submit', '教练提交报名');

INSERT INTO role (app_id, key, name) VALUES
  (NULL,    'superadmin', '超级管理员'),
  ('tour',  'recorder',   '录入员'),
  ('tour',  'coach',      '教练'),
  ('guess', 'admin',      '竞猜管理员'),
  ('guess', 'initiator',  '发起人'),
  ('club',  'admin',      '俱乐部管理员'),
  ('club',  'coach',      '俱乐部教练');

-- superadmin（全局）：持有全部权限点
INSERT INTO role_permission (role_id, permission_id)
SELECT r.id, p.id FROM role r CROSS JOIN permission p
WHERE r.app_id IS NULL AND r.key = 'superadmin';

-- tour 录入员（= 现 tour admin 的录入职能）
INSERT INTO role_permission (role_id, permission_id)
SELECT r.id, p.id FROM role r JOIN permission p ON p.app_id = r.app_id
WHERE r.app_id = 'tour' AND r.key = 'recorder'
  AND p.key IN ('tour.match.manage', 'tour.team.bindcode.issue');

-- tour 教练
INSERT INTO role_permission (role_id, permission_id)
SELECT r.id, p.id FROM role r JOIN permission p ON p.app_id = r.app_id
WHERE r.app_id = 'tour' AND r.key = 'coach' AND p.key = 'tour.team.bind';

-- guess 管理员（= 现 guess 对 tour admin/superadmin 的映射）
INSERT INTO role_permission (role_id, permission_id)
SELECT r.id, p.id FROM role r JOIN permission p ON p.app_id = r.app_id
WHERE r.app_id = 'guess' AND r.key = 'admin'
  AND p.key IN ('guess.event.manage', 'guess.users.manage', 'guess.payout.reverse', 'guess.recon.view');

-- guess 发起人（= 现 initiators 表各行）
INSERT INTO role_permission (role_id, permission_id)
SELECT r.id, p.id FROM role r JOIN permission p ON p.app_id = r.app_id
WHERE r.app_id = 'guess' AND r.key = 'initiator' AND p.key = 'guess.event.manage';

-- club 管理员
INSERT INTO role_permission (role_id, permission_id)
SELECT r.id, p.id FROM role r JOIN permission p ON p.app_id = r.app_id
WHERE r.app_id = 'club' AND r.key = 'admin'
  AND p.key IN ('club.clubs.manage', 'club.bindings.unbind', 'club.players.import',
                'club.ledger.manage', 'club.registrations.manage', 'club.compliance.view');

-- club 教练
INSERT INTO role_permission (role_id, permission_id)
SELECT r.id, p.id FROM role r JOIN permission p ON p.app_id = r.app_id
WHERE r.app_id = 'club' AND r.key = 'coach'
  AND p.key IN ('club.squad.manage', 'club.registrations.submit');
