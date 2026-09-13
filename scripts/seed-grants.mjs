// 账号级授权播种（P0-10，TECH_DESIGN §6.2）：行为等价——上线第一天各系统管理员的
// 可见/可用范围与迁移前完全一致。输出 SQL 而不直接执行（同 seed-local-users.mjs 约定）：
//   SQL=$(node scripts/seed-grants.mjs) && npx wrangler d1 execute whl-auth --local --command "$SQL"
// 生产改用 --db <tour 账号库> --remote 读账号、再由人为确认后执行到 auth 库（P0-13 runbook）。
// 幂等：INSERT OR IGNORE + user_role 复合主键，可重复执行。
// 跨库注意：guess「发起人」在 guess 库，无法在此读取；收口（步骤③）时按
// 角色 guess.initiator 补播（见 TECH_DESIGN §6.2 末两行）。
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const argv = process.argv.slice(2);
const argOf = (name, dflt) => {
  const i = argv.indexOf(name);
  const v = i === -1 ? undefined : argv[i + 1];
  return v === undefined || v.startsWith("--") ? dflt : v;
};
const db = argOf("--db", "whl");
const remote = argv.includes("--remote");

// §6.2 映射：tour user.role → 角色键。locked 不进授权（是账号状态，
// client 端保留「locked→viewer」映射），故这里只看 role 列。
const GRANTS = {
  superadmin: [[null, "superadmin"]], // 全局角色，已持有全部权限点
  admin: [
    ["tour", "recorder"],
    ["guess", "admin"],
    ["club", "admin"],
  ],
  coach: [
    ["tour", "coach"],
    ["club", "coach"],
  ],
};

const wrangler = fileURLToPath(new URL("../node_modules/wrangler/bin/wrangler.js", import.meta.url));
const out = execFileSync(
  process.execPath,
  [wrangler, "d1", "execute", db, remote ? "--remote" : "--local", "--json", "--command",
   "SELECT id, role FROM user WHERE role IN ('superadmin','admin','coach') ORDER BY id"],
  { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] },
);
const parsed = JSON.parse(out);
const users = Array.isArray(parsed) ? (parsed[0]?.results ?? []) : [];
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
console.log(stmts.join(";\n") + ";");
