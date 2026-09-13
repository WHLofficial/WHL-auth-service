// 账号收口一次性迁移（P0-11，TECH_DESIGN §9.1 ③ / §5.3 终态）：
// tour 库 user / organization.allow_open_reg / signup_code → auth 库 account / credential /
// organization / signup_code，account.id = tour user.id 同值延续（三系统业务外键零改动）。
// 只迁移、不播种授权：user_role 由 seed-grants.mjs 负责（§6.2 映射），两步都过才可切读。
//
// 用法（同 seed-local-users.mjs 约定，输出 SQL 不直接执行）：
//   SQL=$(node scripts/migrate-accounts.mjs) && npx wrangler d1 execute whl-auth --local --command "$SQL"
// 生产改用 --remote 读 tour 线上库，人工确认后执行到 auth 线上库（P0-13 runbook）。
// 幂等：account/credential/organization 走 upsert（重复执行以 tour 现值覆盖）；
// signup_code 走 INSERT OR IGNORE（auth 是收口后的注册码真源，不得回灌覆盖 used_count）。
// 切读闸门：执行后必须跑 verify-accounts.mjs，不过不切读。
import { d1Query } from "./lib/d1.mjs";

const argv = process.argv.slice(2);
const argOf = (name, dflt) => {
  const i = argv.indexOf(name);
  const v = i === -1 ? undefined : argv[i + 1];
  return v === undefined || v.startsWith("--") ? dflt : v;
};
const tourDb = argOf("--tour-db", "whl");
const remote = argv.includes("--remote");

function sqlStr(v) {
  return v === null || v === undefined ? "NULL" : `'${String(v).replace(/'/g, "''")}'`;
}
function sqlNum(v) {
  if (v === null || v === undefined) return "NULL";
  const n = Number(v);
  if (!Number.isInteger(n)) throw new Error(`非整数值：${JSON.stringify(v)}`);
  return String(n);
}

const users = d1Query(tourDb, "SELECT id, name, email, password_hash, locked, must_change_pw, created_at FROM user ORDER BY id", { remote });
if (!users.length) throw new Error(`库 ${tourDb} 中没有账号，无从迁移`);
for (const u of users) {
  if (!/^\d+$/.test(String(u.id))) throw new Error(`user.id 非整数：${JSON.stringify(u.id)}`);
  // 迁移前就地校验哈希格式（与 src/lib/crypto.ts 的 verifyPassword 解析口径一致），
  // 防止脏哈希进 credential 后全线登录失败
  const parts = String(u.password_hash).split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2" || !/^\d+$/.test(parts[1]) || !parts[2] || !parts[3]) {
    throw new Error(`user ${u.id}（${u.name}）password_hash 不是 pbkdf2$iter$salt$hash 格式，中止迁移`);
  }
}

const org = d1Query(tourDb, "SELECT allow_open_reg FROM organization WHERE id = 1", { remote });
const codes = d1Query(tourDb, "SELECT code_hash, expires_at, max_uses, used_count, created_by, created_at FROM signup_code ORDER BY code_hash", { remote });

const stmts = [];
// 1. account：同值延续 id；重复执行按 tour 现值覆盖（迁移脚本重跑 = 以源库为准）
for (const u of users) {
  stmts.push(
    `INSERT INTO account (id, name, email, locked, must_change_pw, created_at) VALUES ` +
      `(${sqlNum(u.id)}, ${sqlStr(u.name)}, ${sqlStr(u.email)}, ${sqlNum(u.locked ?? 0)}, ${sqlNum(u.must_change_pw ?? 0)}, ${sqlStr(u.created_at)}) ` +
      `ON CONFLICT(id) DO UPDATE SET name = excluded.name, email = excluded.email, locked = excluded.locked, ` +
      `must_change_pw = excluded.must_change_pw, created_at = excluded.created_at`,
  );
}
// 2. credential：hash 存完整 pbkdf2$iter$salt$hash 串（与 tour 格式逐字节一致，verifyPassword 可直接验）
for (const u of users) {
  const hash = String(u.password_hash);
  stmts.push(
    `INSERT INTO credential (account_id, type, hash, iterations, updated_at) VALUES ` +
      `(${sqlNum(u.id)}, 'password', ${sqlStr(hash)}, ${sqlNum(hash.split("$")[1])}, ${sqlStr(u.created_at)}) ` +
      `ON CONFLICT(account_id, type) DO UPDATE SET hash = excluded.hash, iterations = excluded.iterations, updated_at = excluded.updated_at`,
  );
}
// 3. signup_code：INSERT OR IGNORE——注册码消费计数以 auth 为准，不回灌
for (const sc of codes) {
  stmts.push(
    `INSERT OR IGNORE INTO signup_code (code_hash, expires_at, max_uses, used_count, created_by, created_at) VALUES ` +
      `(${sqlStr(sc.code_hash)}, ${sqlStr(sc.expires_at)}, ${sqlNum(sc.max_uses)}, ${sqlNum(sc.used_count ?? 0)}, ${sqlNum(sc.created_by)}, ${sqlStr(sc.created_at)})`,
  );
}
// 4. 组织级开放注册开关（migrations/0006 建表，初值 0）
if (org.length) {
  stmts.push(
    `INSERT INTO organization (id, allow_open_reg) VALUES (1, ${sqlNum(org[0].allow_open_reg ?? 0)}) ` +
      `ON CONFLICT(id) DO UPDATE SET allow_open_reg = excluded.allow_open_reg`,
  );
}

// 摘要走 stderr：stdout 只输出纯 SQL（--command 传参时 `--` 开头行会被 wrangler 当 flag）
console.error(`migrate-accounts：${users.length} 个账号、${codes.length} 个注册码、allow_open_reg=${org.length ? org[0].allow_open_reg : "（源库无 organization 行，跳过）"}`);
console.log(stmts.join(";\n") + ";");
