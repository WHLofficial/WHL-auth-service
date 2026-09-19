INSERT OR IGNORE INTO team (tour_team_id, club_id, name, created_at)
VALUES (1, NULL, '巴黎圣日耳曼', datetime('now'));
INSERT OR IGNORE INTO team (tour_team_id, club_id, name, created_at)
VALUES (2, NULL, '里昂', datetime('now'));
INSERT OR IGNORE INTO team (tour_team_id, club_id, name, created_at)
VALUES (3, NULL, '利物浦', datetime('now'));
INSERT OR IGNORE INTO team (tour_team_id, club_id, name, created_at)
VALUES (4, NULL, '曼联', datetime('now'));
INSERT OR IGNORE INTO team (tour_team_id, club_id, name, created_at)
VALUES (5, NULL, '慕尼黑1860', datetime('now'));
INSERT OR IGNORE INTO team (tour_team_id, club_id, name, created_at)
VALUES (6, NULL, '巴塞罗那(CPU)', datetime('now'));
INSERT OR IGNORE INTO team (tour_team_id, club_id, name, created_at)
VALUES (7, NULL, '纽卡斯尔联', datetime('now'));
INSERT OR IGNORE INTO team (tour_team_id, club_id, name, created_at)
VALUES (8, NULL, '尤文图斯', datetime('now'));
INSERT OR IGNORE INTO team (tour_team_id, club_id, name, created_at)
VALUES (9, NULL, '佛罗伦萨', datetime('now'));
INSERT OR IGNORE INTO team (tour_team_id, club_id, name, created_at)
VALUES (10, NULL, '切尔西', datetime('now'));
INSERT OR IGNORE INTO team (tour_team_id, club_id, name, created_at)
VALUES (12, NULL, '皇家贝蒂斯', datetime('now'));
INSERT OR IGNORE INTO team (tour_team_id, club_id, name, created_at)
VALUES (13, NULL, '阿斯顿维拉', datetime('now'));
INSERT OR IGNORE INTO team (tour_team_id, club_id, name, created_at)
VALUES (14, NULL, '拜仁慕尼黑', datetime('now'));
INSERT OR IGNORE INTO team (tour_team_id, club_id, name, created_at)
VALUES (15, NULL, '阿森纳', datetime('now'));
INSERT OR IGNORE INTO team (tour_team_id, club_id, name, created_at)
VALUES (16, NULL, '曼城(CPU)', datetime('now'));
INSERT OR IGNORE INTO team (tour_team_id, club_id, name, created_at)
VALUES (17, NULL, '奥林匹亚科斯', datetime('now'));
INSERT OR IGNORE INTO team (tour_team_id, club_id, name, created_at)
VALUES (18, NULL, '诺丁汉森林', datetime('now'));
INSERT OR IGNORE INTO team (tour_team_id, club_id, name, created_at)
VALUES (19, NULL, 'RB莱比锡(CPU)', datetime('now'));
INSERT OR IGNORE INTO team (tour_team_id, club_id, name, created_at)
VALUES (20, NULL, '皇家马德里', datetime('now'));
INSERT OR IGNORE INTO team (tour_team_id, club_id, name, created_at)
VALUES (21, NULL, 'AC米兰(CPU)', datetime('now'));
INSERT OR IGNORE INTO team_binding (account_id, team_id, bound_via, bound_at)
VALUES (1, (SELECT id FROM team WHERE tour_team_id = 2), 'tour', '2026-09-03T13:36:37.678Z');
INSERT OR IGNORE INTO team_binding (account_id, team_id, bound_via, bound_at)
VALUES (2, (SELECT id FROM team WHERE tour_team_id = 2), 'tour', '2026-09-04T00:13:42.426Z');
INSERT OR IGNORE INTO team_binding (account_id, team_id, bound_via, bound_at)
VALUES (3, (SELECT id FROM team WHERE tour_team_id = 8), 'tour', '2026-09-04T00:37:44.896Z');
INSERT OR IGNORE INTO team_binding (account_id, team_id, bound_via, bound_at)
VALUES (5, (SELECT id FROM team WHERE tour_team_id = 4), 'tour', '2026-09-07T01:50:53.790Z');
INSERT OR IGNORE INTO team_binding (account_id, team_id, bound_via, bound_at)
VALUES (6, (SELECT id FROM team WHERE tour_team_id = 15), 'tour', '2026-09-07T03:12:44.580Z');
INSERT OR IGNORE INTO team_binding (account_id, team_id, bound_via, bound_at)
VALUES (8, (SELECT id FROM team WHERE tour_team_id = 20), 'tour', '2026-09-07T10:19:37.995Z');
INSERT OR IGNORE INTO team_binding (account_id, team_id, bound_via, bound_at)
VALUES (9, (SELECT id FROM team WHERE tour_team_id = 17), 'tour', '2026-09-07T10:18:55.060Z');
INSERT OR IGNORE INTO team_binding (account_id, team_id, bound_via, bound_at)
VALUES (10, (SELECT id FROM team WHERE tour_team_id = 12), 'tour', '2026-09-10T12:58:14.879Z');
INSERT OR IGNORE INTO team_binding (account_id, team_id, bound_via, bound_at)
VALUES (11, (SELECT id FROM team WHERE tour_team_id = 10), 'tour', '2026-09-12T04:11:41.784Z');
INSERT OR IGNORE INTO team_binding (account_id, team_id, bound_via, bound_at)
VALUES (12, (SELECT id FROM team WHERE tour_team_id = 7), 'tour', '2026-09-11T15:59:59.591Z');

