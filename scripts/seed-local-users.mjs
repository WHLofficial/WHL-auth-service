// 本地冒烟测试的固定用户（写入本地 miniflare 的 whl 库）：
//   node scripts/seed-local-users.mjs | xargs -0 ... 或
//   SQL=$(node scripts/seed-local-users.mjs) && npx wrangler d1 execute whl --local --command "$SQL"
// 仅用于本地开发（生产库绝不执行）；密码明文只在脚本里。
import { pbkdf2Sync, randomBytes } from "node:crypto";

function hash(pw) {
  const salt = randomBytes(16);
  return `pbkdf2$25000$${salt.toString("base64")}$${pbkdf2Sync(pw, salt, 25000, 32, "sha256").toString("base64")}`;
}

const users = [
  ["oidctest", "test@example.com", hash("TestPass123"), "admin", 0, 0],
  ["oidctest2", "test2@example.com", hash("OldPass999"), "coach", 0, 1],
];

const rows = users
  .map(([name, email, h, role, locked, must]) => `('${name}', '${email}', '${h}', '${role}', ${locked}, ${must})`)
  .join(", ");

console.log(
  "INSERT INTO user (name, email, password_hash, role, locked, must_change_pw) VALUES " +
    rows +
    " ON CONFLICT(name) DO UPDATE SET password_hash=excluded.password_hash, must_change_pw=excluded.must_change_pw, locked=excluded.locked",
);
