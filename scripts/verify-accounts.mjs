// 账号收口迁移校验（P0-11）：迁移执行的验收闸门——校验不过不切读（TECH_DESIGN §9.1 ③）。
// 与 migrate-accounts.mjs 成对使用：先跑迁移，再跑本校验，全绿才上线切读。
//
//   node scripts/verify-accounts.mjs                     # 本地库校验
//   node scripts/verify-accounts.mjs --remote            # 线上库校验（P0-13 runbook）
//   node scripts/verify-accounts.mjs --name 某昵称 --password 某密码   # 抽样验证迁移后的哈希可登录
//
// 校验项：账号数量与逐字段一致、密码哈希逐字节一致、管理员/教练的 user_role 授权覆盖
// （viewer 不要求，收口后以权限点判定）、开放注册开关一致、注册码存在且计数不回退。
// 任一项失败进程退出码非零。
import { pbkdf2Sync } from "node:crypto";
import { d1Query } from "./lib/d1.mjs";

const argv = process.argv.slice(2);
const argOf = (name, dflt) => {
  const i = argv.indexOf(name);
  const v = i === -1 ? undefined : argv[i + 1];
  return v === undefined || v.startsWith("--") ? dflt : v;
};
const tourDb = argOf("--tour-db", "whl");
const authDb = argOf("--auth-db", "whl-auth");
const sampleName = argOf("--name");
const samplePassword = argOf("--password");
const remote = argv.includes("--remote");
// --allow-extra：auth 侧账号可以多于 tour（收口后 auth 自主注册是合法状态），只校验 tour ⊆ auth。
// 初次迁移的验收（P0-13 runbook）不用此开关——数量必须相等，多出来的账号要人工确认来历。
const allowExtra = argv.includes("--allow-extra");

const failures = [];
const check = (ok, label) => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${label}`);
  if (!ok) failures.push(label);
};
const eq = (a, b) => (a ?? null) === (b ?? null);

const tourUsers = d1Query(tourDb, "SELECT id, name, email, role, locked, must_change_pw, password_hash FROM user ORDER BY id", { remote });
const accounts = d1Query(authDb, "SELECT id, name, email, locked, must_change_pw FROM account ORDER BY id", { remote });
const creds = d1Query(authDb, "SELECT account_id, hash FROM credential WHERE type = 'password'", { remote });
const authHashes = new Map(creds.map((r) => [Number(r.account_id), String(r.hash)]));
const granted = new Set(d1Query(authDb, "SELECT DISTINCT account_id AS id FROM user_role", { remote }).map((r) => Number(r.id)));

check(tourUsers.length > 0, `tour 库读到账号（${tourUsers.length} 个）`);
if (allowExtra) {
  check(accounts.length >= tourUsers.length, `auth 账号覆盖 tour 全量（tour ${tourUsers.length} ⊆ auth ${accounts.length}）`);
} else {
  check(tourUsers.length === accounts.length, `账号数量一致：tour ${tourUsers.length} = auth ${accounts.length}`);
}

const authById = new Map(accounts.map((r) => [Number(r.id), r]));
for (const u of tourUsers) {
  const id = Number(u.id);
  const a = authById.get(id);
  if (!a) {
    check(false, `auth 缺账号 id=${id}（${u.name}）`);
    continue;
  }
  const fieldsOk =
    eq(a.name, u.name) && eq(a.email, u.email) && eq(a.locked, u.locked) && eq(a.must_change_pw, u.must_change_pw);
  if (!fieldsOk) {
    check(false, `字段不一致 id=${id}（${u.name}）：name/email/locked/must_change_pw 中有出入`);
    continue;
  }
  const tourHash = String(u.password_hash);
  check(authHashes.get(id) === tourHash, `密码哈希逐字节一致 id=${id}（${u.name}）`);
  // 授权覆盖：收口后角色/权限只认 user_role，可授权角色（§6.2）必须有行
  if (["superadmin", "admin", "coach"].includes(String(u.role))) {
    check(granted.has(id), `user_role 授权覆盖 id=${id}（${u.name}，role=${u.role}）`);
  }
}

const orgTour = d1Query(tourDb, "SELECT allow_open_reg FROM organization WHERE id = 1", { remote });
const orgAuth = d1Query(authDb, "SELECT allow_open_reg FROM organization WHERE id = 1", { remote });
check(
  orgTour.length === 0 || (orgAuth.length === 1 && eq(orgAuth[0].allow_open_reg, orgTour[0].allow_open_reg)),
  `开放注册开关一致：tour=${orgTour[0]?.allow_open_reg} auth=${orgAuth[0]?.allow_open_reg}`,
);

const tourCodes = d1Query(tourDb, "SELECT code_hash, expires_at, max_uses, used_count FROM signup_code", { remote });
const authCodes = new Map(d1Query(authDb, "SELECT code_hash, expires_at, max_uses, used_count FROM signup_code", { remote }).map((r) => [String(r.code_hash), r]));
for (const sc of tourCodes) {
  const ac = authCodes.get(String(sc.code_hash));
  if (!ac) {
    check(false, `auth 缺注册码 ${String(sc.code_hash).slice(0, 8)}…`);
    continue;
  }
  // used_count 允许 auth 领先（收口后 auth 是消费真源）；回退才算失败
  check(
    eq(ac.expires_at, sc.expires_at) && eq(ac.max_uses, sc.max_uses) && Number(ac.used_count) >= Number(sc.used_count),
    `注册码 ${String(sc.code_hash).slice(0, 8)}… 字段一致（used_count auth=${ac.used_count} ≥ tour=${sc.used_count}）`,
  );
}

if (sampleName !== undefined || samplePassword !== undefined) {
  if (!sampleName || !samplePassword) {
    failures.push("--name 与 --password 必须成对提供");
    console.log("FAIL  --name 与 --password 必须成对提供");
  } else {
    const row = d1Query(
      authDb,
      `SELECT cr.hash AS hash FROM account a JOIN credential cr ON cr.account_id = a.id AND cr.type = 'password' WHERE a.name = '${sampleName.replace(/'/g, "''")}'`,
      { remote },
    );
    const hash = row[0]?.hash ? String(row[0].hash) : null;
    let ok = false;
    if (hash) {
      const parts = hash.split("$");
      if (parts.length === 4 && parts[0] === "pbkdf2") {
        const derived = pbkdf2Sync(samplePassword, Buffer.from(parts[2], "base64"), Number(parts[1]), 32, "sha256");
        ok = derived.equals(Buffer.from(parts[3], "base64"));
      }
    }
    check(ok, `抽样登录验证：${sampleName} 的密码可通过 auth 库哈希校验`);
  }
}

if (failures.length) {
  console.error(`\n校验未通过（${failures.length} 项）——不得切读。逐项修复后重跑迁移 + 校验。`);
  process.exit(1);
}
console.log(`\n全部通过：${tourUsers.length} 个账号可安全切读。`);
