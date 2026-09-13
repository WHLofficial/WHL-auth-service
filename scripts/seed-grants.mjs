// 账号级授权播种（P0-10，TECH_DESIGN §6.2）：行为等价——上线第一天各系统管理员的
// 可见/可用范围与迁移前完全一致。输出 SQL 而不直接执行（同 seed-local-users.mjs 约定）：
//   SQL=$(node scripts/seed-grants.mjs) && npx wrangler d1 execute whl-auth --local --command "$SQL"
// 生产改用 --db <tour 账号库> --remote 读账号、再由人为确认后执行到 auth 库（P0-13 runbook）。
// 幂等：INSERT OR IGNORE + user_role 复合主键，可重复执行。
//
// 竞猜发起人（收口补播，§6.2 末两行）：initiators 名单在 guess 库，主流程读不到；
// 带 --guess-db whl-guess 时一并读出（users.tour_id 关联回 tour user.id = auth account.id）
// 播 guess.initiator 角色，合入同一段 SQL 一次执行。
//
// coach 补播的等价性依据（P0-10 判定映射）：
// - tour admin 现可通过 club 的 requireCoach（admin OR coach）→ 收口后教练端点走
//   club.coach 的权限点，需补 club.coach 才不掉权；
// - tour admin 在 tour 侧需保留 coach 端点可达（tour.team.bind）→ 补 tour.coach。
//   club 本地 admin 同理经 requireCoach 获得 coach 端点，「admin 统一补 coach」一并覆盖。
import { d1Query, GUESS_STATE } from "./lib/d1.mjs";

const argv = process.argv.slice(2);
const argOf = (name, dflt) => {
  const i = argv.indexOf(name);
  const v = i === -1 ? undefined : argv[i + 1];
  return v === undefined || v.startsWith("--") ? dflt : v;
};
const db = argOf("--db", "whl");
const guessDb = argOf("--guess-db");
const remote = argv.includes("--remote");

// §6.2 映射：tour user.role → 角色键。locked 不进授权（是账号状态，
// client 端保留「locked→viewer」映射），故这里只看 role 列。
const GRANTS = {
  superadmin: [[null, "superadmin"]], // 全局角色，已持有全部权限点
  admin: [
    ["tour", "recorder"],
    ["tour", "coach"], // 补播：tour admin 保留 coach 端点可达（见文件头等价性依据）
    ["guess", "admin"],
    ["club", "admin"],
    ["club", "coach"], // 补播：tour admin 现可通过 club requireCoach（见文件头等价性依据）
  ],
  coach: [
    ["tour", "coach"],
    ["club", "coach"],
  ],
};

const users = d1Query(db, "SELECT id, role FROM user WHERE role IN ('superadmin','admin','coach') ORDER BY id", { remote });
if (!users.length) throw new Error(`库 ${db} 中未读到可授权账号（role 均为 viewer 或库为空）`);

const rows = new Map(); // "app|role_key" → account_id 列表
for (const u of users) {
  const keys = GRANTS[u.role];
  if (!keys) throw new Error(`未覆盖的角色：${u.name ?? u.id} role=${u.role}（映射见 TECH_DESIGN §6.2）`);
  for (const [app, key] of keys) {
    const k = `${app ?? ""}|${key}`;
    rows.set(k, [...(rows.get(k) ?? []), Number(u.id)]);
  }
}

// guess 发起人：按 guess 库 initiators 名单补播 guess.initiator（users.tour_id 为空的孤儿行跳过）；
// 本地读 guess 仓库自己的状态目录（发起人数据在 guess 的本地库里）
let initiatorCount = 0;
if (guessDb) {
  const initIds = d1Query(
    guessDb,
    "SELECT u.tour_id AS tour_id FROM initiators i JOIN users u ON u.id = i.user_id WHERE u.tour_id IS NOT NULL ORDER BY u.tour_id",
    { remote, persistTo: remote ? undefined : GUESS_STATE },
  ).map((r) => Number(r.tour_id));
  if (initIds.length) {
    rows.set("guess|initiator", [...new Set([...(rows.get("guess|initiator") ?? []), ...initIds])]);
    initiatorCount = initIds.length;
  }
}

// 一条语句一个角色：账号 id 走 json_each，避免 UNION ALL/VALUES 的复合 SELECT 项数上限
//（D1 在 28 项即报 too many terms in compound SELECT）。app_id 用 IS 比较：全局角色为 NULL。
const stmts = [];
for (const [k, ids] of rows) {
  const [app, key] = k.split("|");
  stmts.push(
    "INSERT OR IGNORE INTO user_role (account_id, role_id, granted_at)\n" +
      `SELECT j.value, (SELECT id FROM role WHERE app_id IS ${app === "" ? "NULL" : `'${app}'`} AND key = '${key}'), datetime('now')\n` +
      `FROM json_each('[${ids.join(",")}]') j`,
  );
}
// 摘要走 stderr：stdout 只输出纯 SQL（--command 传参时 `--` 开头行会被 wrangler 当 flag）
console.error(`seed-grants：${users.length} 个可授权账号${guessDb ? ` + ${initiatorCount} 个竞猜发起人（guess.initiator）` : ""}`);
console.log(stmts.join(";\n") + ";");
