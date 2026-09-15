// 球队绑定一次性迁移（增量 7，TECH_DESIGN §5.3 改判后新表 team/team_bind_code/team_binding）：
// 目录 = tour team ↔ club clubs 按名字精确匹配建行（team.tour_team_id / club_id）；
// 绑定 = tour team_member 为基准全量迁 team_binding（account_id = tour user.id 同值延续，
// bound_via='tour'）；club club_bindings 只做校对：账号已在 team_member 且目录 club_id
// 与之相符 → 确认（不再单独写）；对不上 / 只有 club 绑定 → 人工裁决清单（本脚本不自动迁）。
//
// 用法（输出 SQL 不直接执行，同 seed-grants.mjs 约定）：
//   SQL=$(node scripts/migrate-team-bindings.mjs) && npx wrangler d1 execute whl-auth --local --command "$SQL"
// 生产 --remote 读 tour/club 线上库，人工核对报告后执行到 auth 线上库（先跑 migrate-accounts + seed-grants）。
// 幂等：INSERT OR IGNORE（team 靠 UNIQUE(tour_team_id)/UNIQUE(club_id)，team_binding 靠 PK+UNIQUE(account_id)）。
// 重复执行不覆盖既有行：目录补关联走 /api/team/link 机器端点，绑定修复走报告里的裁决 SQL。
//
// 冲突/单边报告写 --report（默认仓库根 migrate-team-bindings-report.md）。
import { writeFileSync } from 'node:fs';
import { d1Query, TOUR_STATE, CLUB_STATE } from './lib/d1.mjs';

const argv = process.argv.slice(2);
const argOf = (name, dflt) => {
  const i = argv.indexOf(name);
  const v = i === -1 ? undefined : argv[i + 1];
  return v === undefined || v.startsWith('--') ? dflt : v;
};
const remote = argv.includes('--remote');
const tourDb = argOf('--tour-db', 'whl');
const clubDb = argOf('--club-db', 'whl-club');
const reportPath = argOf('--report', 'migrate-team-bindings-report.md');

function sqlStr(v) {
  return v === null || v === undefined ? 'NULL' : `'${String(v).replace(/'/g, "''")}'`;
}
function sqlNum(v) {
  const n = Number(v);
  if (!Number.isInteger(n)) throw new Error(`非整数值：${JSON.stringify(v)}`);
  return String(n);
}

// ---- 读源库与 auth 库现状 ----
const sourceOpts = { remote, persistTo: remote ? undefined : TOUR_STATE };
const clubOpts = { remote, persistTo: remote ? undefined : CLUB_STATE };
const teams = d1Query(tourDb, 'SELECT id, name FROM team ORDER BY id', sourceOpts);
const clubs = d1Query(clubDb, 'SELECT id, name FROM clubs ORDER BY id', clubOpts);
const members = d1Query(tourDb, 'SELECT team_id, user_id, created_at FROM team_member ORDER BY user_id', sourceOpts);
const clubBinds = d1Query(clubDb, 'SELECT club_id, user_id, user_name, bound_at FROM club_bindings ORDER BY user_id', clubOpts);
// auth 现状（幂等 awareness + 缺 account 行检查）
const accounts = new Set(d1Query('whl-auth', 'SELECT id FROM account ORDER BY id', { remote }).map((r) => Number(r.id)));
const authTeams = d1Query('whl-auth', 'SELECT id, tour_team_id, club_id FROM team ORDER BY id', { remote });
const authBindings = new Map(
  d1Query('whl-auth', 'SELECT account_id, team_id FROM team_binding ORDER BY account_id', { remote }).map((r) => [Number(r.account_id), Number(r.team_id)]),
);

if (!teams.length && !clubs.length) {
  throw new Error(`tour（${tourDb}）与 club（${clubDb}）都读不到数据——本地跑先在各自仓库 dev 过一次落盘，或用 --remote 读线上库`);
}

// ---- 目录匹配：名字精确相等（两侧都 trim）；一个 club 名匹配到多个 tour team 视为冲突 ----
const clubByName = new Map(clubs.map((c) => [String(c.name).trim(), c]));
const dirRows = teams.map((t) => {
  const club = clubByName.get(String(t.name).trim()) ?? null;
  return { tourTeamId: Number(t.id), clubId: club ? Number(club.id) : null, name: String(t.name) };
});
// 名字撞多队：同名 tour team >1 → 该 club 不自动关联
const nameCounts = new Map();
for (const t of teams) {
  const key = String(t.name).trim();
  nameCounts.set(key, (nameCounts.get(key) ?? 0) + 1);
}
const dirConflicts = [];
for (const row of dirRows) {
  const key = row.name.trim();
  if ((nameCounts.get(key) ?? 0) > 1) {
    dirConflicts.push(`- 队名「${key}」在赛事系统有 ${nameCounts.get(key)} 支同名球队，club_id 不自动登记（须人工裁决后用 /api/team/link）`);
    row.clubId = null;
  }
}

// ---- 绑定迁移（tour team_member 为基准） ----
const dirByTourTeamId = new Map(dirRows.map((r) => [r.tourTeamId, r]));
const stmts = [];
const migrated = [];
const bindConflicts = [];
const byUser = new Map();
for (const m of members) {
  const uid = Number(m.user_id);
  byUser.set(uid, [...(byUser.get(uid) ?? []), m]);
}
for (const [uid, rows] of byUser) {
  if (rows.length > 1) {
    bindConflicts.push(`- 账号 ${uid} 在赛事系统属于 ${rows.length} 支球队（${rows.map((r) => r.team_id).join('、')}）——一账号一队冲突，须人工裁决`);
    continue;
  }
  const m = rows[0];
  const dir = dirByTourTeamId.get(Number(m.team_id));
  if (!dir) {
    bindConflicts.push(`- 账号 ${uid} 的球队 ${m.team_id} 不在 tour team 表？目录缺行，跳过`);
    continue;
  }
  if (!accounts.has(uid)) {
    bindConflicts.push(`- 账号 ${uid} 在 auth account 表缺行（先跑 migrate-accounts.mjs），跳过`);
    continue;
  }
  if (authBindings.has(uid)) {
    migrated.push(`| ${uid} | ${dir.name} | 已存在（auth team_id=${authBindings.get(uid)}），跳过 |`);
    continue;
  }
  stmts.push(
    `INSERT OR IGNORE INTO team_binding (account_id, team_id, bound_via, bound_at)\n` +
      `VALUES (${sqlNum(uid)}, (SELECT id FROM team WHERE tour_team_id = ${sqlNum(dir.tourTeamId)}), 'tour', ${sqlStr(m.created_at)});`,
  );
  migrated.push(`| ${uid} | ${dir.name}（tour team ${dir.tourTeamId}） | 迁移 |`);
}

// ---- club_bindings 校对：按目录对齐 ----
// 期望值：账号的球队（tour team_member 优先，否则用 auth 已有绑定行反查目录）→ 目录 club_id
// 应与 club_bindings.club_id 相同
const authTeamById = new Map(authTeams.map((r) => [Number(r.id), r]));
function expectedDirFor(uid) {
  const rows = byUser.get(uid);
  if (rows && rows.length === 1 && dirByTourTeamId.has(Number(rows[0].team_id))) {
    return dirByTourTeamId.get(Number(rows[0].team_id));
  }
  const authTeamId = authBindings.get(uid);
  if (authTeamId === undefined) return undefined; // auth 无绑定行
  const at = authTeamById.get(authTeamId);
  if (!at || at.tour_team_id === null) return null; // auth 有绑定但映射不到目录行
  return dirByTourTeamId.get(Number(at.tour_team_id)) ?? null;
}
const confirmed = [];
const clubOnly = [];
const clubConflicts = [];
for (const cb of clubBinds) {
  const uid = Number(cb.user_id);
  const dir = expectedDirFor(uid);
  if (dir === undefined) {
    // 没进 team_member 的 club 绑定：单边，人工裁决（裁决后可手写 INSERT via='club'）
    clubOnly.push(`| ${uid} | ${cb.user_name ?? 'NULL'} | club ${cb.club_id}（${sqlStr(cb.bound_at)}） | 无赛事系统入队记录 |`);
    continue;
  }
  if (dir === null) {
    clubConflicts.push(`- 账号 ${uid}（${cb.user_name ?? 'NULL'}）：auth 绑定行映射不到目录行，但平台绑定记录为 club ${cb.club_id}——须人工核对目录`);
    continue;
  }
  if (dir.clubId === null) {
    clubConflicts.push(`- 账号 ${uid}（${cb.user_name ?? 'NULL'}）：球队 ${dir.name}（tour ${dir.tourTeamId}）目录未关联俱乐部，但 club 侧绑定了俱乐部 ${cb.club_id}——先 /api/team/link 关联，再核对是否同一俱乐部`);
    continue;
  }
  if (dir.clubId === Number(cb.club_id)) {
    confirmed.push(`| ${uid} | ${dir.name} | club ${cb.club_id} | 一致 |`);
  } else {
    clubConflicts.push(`- 账号 ${uid}（${cb.user_name ?? 'NULL'}）：赛事系统球队「${dir.name}」目录关联 club ${dir.clubId}，但平台绑定记录为 club ${cb.club_id}——须人工裁决（解绑其一或改目录）`);
  }
}
const unmatchedTeams = dirRows.filter((r) => r.clubId === null);
const unmatchedClubNames = [...clubByName.keys()].filter((name) => !teams.some((t) => String(t.name).trim() === name));

// ---- SQL 输出（stdout 只放纯 SQL） ----
const teamStmts = dirRows.map(
  (r) =>
    `INSERT OR IGNORE INTO team (tour_team_id, club_id, name, created_at)\n` +
    `VALUES (${sqlNum(r.tourTeamId)}, ${r.clubId === null ? 'NULL' : sqlNum(r.clubId)}, ${sqlStr(r.name)}, datetime('now'));`,
);
const sql = [...teamStmts, ...stmts].join('\n');
console.log(sql ? `${sql}\n` : '');

// ---- 报告（Markdown，人工裁决用） ----
const lines = [
  '# 球队绑定迁移报告（增量 7）',
  '',
  `- 源：tour ${tourDb}（team ${teams.length} / team_member ${members.length}）+ club ${clubDb}（clubs ${clubs.length} / club_bindings ${clubBinds.length}）`,
  `- 产出：目录行 ${teamStmts.length}、绑定 INSERT ${stmts.length}（SQL 见脚本 stdout，执行到 whl-auth）`,
  '',
  '## 目录匹配（按队名精确相等）',
  '',
  '| tour team | club | 状态 |',
  '| --- | --- | --- |',
  ...dirRows.map((r) => `| ${r.tourTeamId} ${r.name} | ${r.clubId ?? '—'} | ${r.clubId ? '已关联' : '未匹配（club_id NULL，可后补 /api/team/link）'} |`),
  '',
  '## 绑定迁移（tour team_member → auth team_binding，via=tour）',
  '',
  '| 账号 | 球队 | 动作 |',
  '| --- | --- | --- |',
  ...(migrated.length ? migrated : ['| — | — | 无 |']),
  '',
  `## club_bindings 校对：确认一致（${confirmed.length}）`,
  '',
  '| 账号 | 球队 | club | 结论 |',
  '| --- | --- | --- | --- |',
  ...(confirmed.length ? confirmed : ['| — | — | — | — |']),
  '',
  `## 冲突（须人工裁决：${bindConflicts.length + clubConflicts.length + dirConflicts.length}）`,
  '',
  ...(dirConflicts.length ? dirConflicts : []),
  ...(bindConflicts.length ? bindConflicts : []),
  ...(clubConflicts.length ? clubConflicts : []),
  ...(dirConflicts.length + bindConflicts.length + clubConflicts.length ? [] : ['- 无']),
  '',
  `## 单边：只有 club 绑定、无赛事系统入队记录（${clubOnly.length}）`,
  '',
  '| 账号 | 姓名 | club | 绑定时间 |',
  '| --- | --- | --- | --- |',
  ...(clubOnly.length ? clubOnly : ['| — | — | — | — |']),
  '',
  `## 单边：未匹配俱乐部的赛事球队（${unmatchedTeams.length}） / 未匹配赛事球队的俱乐部（${unmatchedClubNames.length}）`,
  '',
  ...(unmatchedTeams.length ? unmatchedTeams.map((r) => `- tour team ${r.tourTeamId}「${r.name}」未匹配到同名俱乐部`) : []),
  ...(unmatchedClubNames.length ? unmatchedClubNames.map((n) => `- 俱乐部「${n}」未匹配到同名赛事球队`) : []),
  ...(unmatchedTeams.length + unmatchedClubNames.length ? [] : ['- 无']),
  '',
  '## 执行说明',
  '',
  '1. 前置：migrate-accounts.mjs（account 行）与 seed-grants.mjs（user_role）已执行。',
  '2. `SQL=$(node scripts/migrate-team-bindings.mjs --remote)` → 人工核对本报告 → `npx wrangler d1 execute whl-auth --remote --command "$SQL"`。',
  '3. 执行后抽查：`SELECT b.account_id, t.name, t.club_id FROM team_binding b JOIN team t ON t.id=b.team_id ORDER BY b.account_id;`',
  '4. 冲突/单边项裁决后：目录补关联用 club 侧管理端发码（自愈 register）或 /api/team/link；单边 club 绑定按裁决手写 INSERT（bound_via 按裁决入口取 tour/club）。',
];
writeFileSync(reportPath, lines.join('\n') + '\n');
console.error(
  `migrate-team-bindings：目录 ${teamStmts.length}（已关联 ${dirRows.length - unmatchedTeams.length}）、绑定 ${stmts.length}、校对确认 ${confirmed.length}；冲突 ${dirConflicts.length + bindConflicts.length + clubConflicts.length}、单边 ${clubOnly.length} → 报告 ${reportPath}`,
);
