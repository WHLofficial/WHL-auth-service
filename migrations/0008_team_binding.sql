-- 球队绑定上收（v1.0.0 裁决，推翻本仓 TECH_DESIGN §5.3「球队不进 auth」旧裁定）：
-- tour/club 双入口发码烧码，绑定关系唯一真源在本库；两侧经只读 D1 绑定（AUTH_DB）派生。
-- team 是 tour team ↔ club club 的目录（1:1，未关联侧可空）；team_binding 一账号一队
-- （UNIQUE(account_id)，与 tour team_member / club club_bindings 现行约束同口径），一队可多账号。
CREATE TABLE team (
  id           INTEGER PRIMARY KEY,
  tour_team_id INTEGER UNIQUE,            -- 比赛系统 team.id
  club_id      INTEGER UNIQUE,            -- 平台 clubs.id（NULL = 尚未关联）
  name         TEXT NOT NULL,
  created_at   TEXT NOT NULL
);
CREATE INDEX idx_team_club ON team(club_id);

CREATE TABLE team_bind_code (
  id         INTEGER PRIMARY KEY,
  team_id    INTEGER NOT NULL REFERENCES team(id),
  code_hash  TEXT NOT NULL UNIQUE,        -- sha256(code)，明码只在发码响应出现一次
  via        TEXT NOT NULL,               -- 发码入口 'tour' | 'club'
  expires_at TEXT,
  used_by    INTEGER,                     -- 烧码账号 account.id
  used_at    TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_team_bind_code_team ON team_bind_code(team_id, id DESC);

CREATE TABLE team_binding (
  account_id INTEGER NOT NULL,            -- auth account.id（过渡期 = tour user.id 同值）
  team_id    INTEGER NOT NULL REFERENCES team(id),
  bound_via  TEXT NOT NULL,               -- 烧码入口 'tour' | 'club'
  bound_at   TEXT NOT NULL,
  PRIMARY KEY (account_id, team_id)
);
CREATE UNIQUE INDEX idx_team_binding_account ON team_binding(account_id); -- 一账号一队
CREATE INDEX idx_team_binding_team ON team_binding(team_id);
