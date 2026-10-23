#!/usr/bin/env node
// 带外超管初始化（v4.0.0）：注册接口不再把首个账号提升为 superadmin，空库/新环境用本脚本。
//
// 用法（本地）：
//   node scripts/bootstrap-superadmin.mjs --name root > /tmp/bootstrap.sql
//   npx wrangler d1 execute whl-auth --local --file /tmp/bootstrap.sql
// 生产把 --local 换成 --remote，并确认脚本打印的「当前超管数」为 0。
//
// 安全默认：
// - 只要库里已存在任一全局 superadmin，三条 INSERT 全部不命中（NOT EXISTS 守卫），可重复执行；
// - 密码随机生成，只在 stderr 显示一次；不写进 SQL 注释、不落文件；
// - 生成的 hash 与 src/lib/crypto.ts 的 pbkdf2$25000$salt$hash 格式一致，首次登录可被透明重哈希。
import { pbkdf2Sync, randomBytes } from "node:crypto";

const argv = process.argv.slice(2);
const argOf = (name, dflt) => {
  const i = argv.indexOf(name);
  const v = i === -1 ? undefined : argv[i + 1];
  return v === undefined || v.startsWith("--") ? dflt : v;
};

const name = argOf("--name", "bootstrap-admin").trim();
if (!/^[\p{L}\p{N}_.-]{1,32}$/u.test(name)) {
  console.error("昵称需 1-32 个字符，仅限字母、数字、下划线、点、短横线");
  process.exit(1);
}
const password = argOf("--password", randomBytes(18).toString("base64url"));
if (password.length < 12) {
  console.error("密码至少 12 位");
  process.exit(1);
}
const iterations = 25_000;
const salt = randomBytes(16);
const hash = pbkdf2Sync(password, salt, iterations, 32, "sha256");
const stored = `pbkdf2$${iterations}$${salt.toString("base64")}$${hash.toString("base64")}`;
const q = (s) => s.replace(/'/g, "''");
const n = q(name);
const h = q(stored);

const sql = `-- v4.0.0 带外超管初始化：仅当不存在全局 superadmin 时插入
-- 预检（应为 0）：SELECT COUNT(*) FROM user_role ur JOIN role r ON r.id = ur.role_id
--                  WHERE r.app_id IS NULL AND r.key = 'superadmin';
-- 用临时表锁定「本次脚本刚建出的账号」：同名旧账号即使没有密码，也不会被补密码后提权。
DROP TABLE IF EXISTS _bootstrap_created;
CREATE TABLE _bootstrap_created (id INTEGER PRIMARY KEY);

INSERT INTO account (name, email, locked, created_at)
SELECT '${n}', NULL, 0, datetime('now')
WHERE NOT EXISTS (
  SELECT 1 FROM user_role ur JOIN role r ON r.id = ur.role_id
   WHERE r.app_id IS NULL AND r.key = 'superadmin'
)
AND NOT EXISTS (SELECT 1 FROM account WHERE name = '${n}');

INSERT INTO _bootstrap_created (id)
SELECT a.id FROM account a
 WHERE a.name = '${n}' AND a.id = last_insert_rowid()
   AND NOT EXISTS (
     SELECT 1 FROM user_role ur JOIN role r ON r.id = ur.role_id
      WHERE r.app_id IS NULL AND r.key = 'superadmin'
   );

INSERT INTO credential (account_id, type, hash, iterations, updated_at)
SELECT a.id, 'password', '${h}', ${iterations}, datetime('now')
  FROM account a JOIN _bootstrap_created b ON b.id = a.id
 WHERE NOT EXISTS (SELECT 1 FROM credential c WHERE c.account_id = a.id AND c.type = 'password');

INSERT OR IGNORE INTO user_role (account_id, role_id, granted_at)
SELECT a.id, r.id, datetime('now')
  FROM account a
  JOIN _bootstrap_created b ON b.id = a.id
  JOIN role r ON r.app_id IS NULL AND r.key = 'superadmin'
 WHERE NOT EXISTS (
   SELECT 1 FROM user_role ur2 JOIN role r2 ON r2.id = ur2.role_id
    WHERE r2.app_id IS NULL AND r2.key = 'superadmin'
 );

DROP TABLE _bootstrap_created;
`;

console.error(`账号：${name}`);
console.error(`初始密码（只显示一次，请立即保存）：${password}`);
console.error("执行：node scripts/bootstrap-superadmin.mjs --name <name> | 保存为 .sql 后");
console.error("  npx wrangler d1 execute whl-auth --local --file bootstrap.sql（生产用 --remote）");
console.log(sql);
