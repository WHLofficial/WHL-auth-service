// 注册矩阵回归：注册码（有效/过期/耗尽/伪造）、开放注册开关、重名、密码与昵称规则、CSRF、IP 限流。
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { Client } from "../lib/client.mjs";
import * as H from "../lib/harness.mjs";

const PW = "TestPass123";
const loc = (res) => new URL(res.headers.get("location"), H.BASE);

function newCode() {
  return `TST${randomBytes(6).toString("hex").toUpperCase()}`;
}

/** 直接建码，便于精确断言 used_count */
function mkCode({ expiresAt = null, maxUses = null, usedCount = 0 } = {}) {
  const code = newCode();
  H.sqlExec(
    `INSERT INTO signup_code (code_hash, expires_at, max_uses, used_count, created_by, created_at)
     VALUES ('${H.sha256Hex(code)}', ${expiresAt ? `'${expiresAt}'` : "NULL"}, ${maxUses ?? "NULL"}, ${usedCount}, 'e2e', '${new Date().toISOString()}');`,
  );
  return code;
}

const usedCount = (code) => H.sql(`SELECT used_count FROM signup_code WHERE code_hash = '${H.sha256Hex(code)}';`)[0].used_count;
const accountOf = (name) => H.sql(`SELECT id, locked, must_change_pw FROM account WHERE name = '${name}';`)[0];

function setOpenReg(on) {
  H.sqlExec(`UPDATE organization SET allow_open_reg = ${on ? 1 : 0} WHERE id = 1;`);
}

test("有效注册码：建号即登录，locked=0，码的 used_count 递增", async () => {
  const code = mkCode({ maxUses: 2 });
  assert.equal(usedCount(code), 0);
  const c = new Client(H.BASE);
  const name = H.uniqueName("reg");
  const r = await H.register(c, { name, code });
  assert.equal(r.status, 303, `有效码应注册成功，实际 ${r.status}`);
  assert.equal(loc(r.res).pathname, "/");
  assert.ok(c.jar.get("whl_session"), "注册成功应建立会话");
  const row = accountOf(name);
  assert.equal(row.locked, 0, "持码注册不得是锁定观众号");
  assert.equal(row.must_change_pw, 0);
  assert.equal(usedCount(code), 1, "用码应计数");
});

test("无码注册：组织开关关闭时 400，开启时建 locked=1 观众号", async () => {
  setOpenReg(false);
  try {
    const c1 = new Client(H.BASE);
    const n1 = H.uniqueName("noopen");
    const r1 = await H.register(c1, { name: n1, code: "" });
    assert.equal(r1.status, 400, "开关关闭且无码应 400");
    assert.match(await r1.res.text(), /需要注册码/);
    assert.equal(H.sql(`SELECT id FROM account WHERE name = '${n1}';`).length, 0, "不得建号");
  } finally {
    setOpenReg(false);
  }

  setOpenReg(true);
  try {
    const c2 = new Client(H.BASE);
    const n2 = H.uniqueName("open");
    const r2 = await H.register(c2, { name: n2, code: "" });
    assert.equal(r2.status, 303, "开关开启且无码应放行为观众号");
    const row = accountOf(n2);
    assert.equal(row.locked, 1, "无码注册必须是 locked=1（待解锁绑队）");
    // locked 不是封禁：仍可正常登录访问首页（生态既有语义）
    assert.equal((await c2.get("/")).status, 200, "locked 观众号仍可访问 /");
  } finally {
    setOpenReg(false);
  }
});

test("重名 + 有效码：409 且不消耗注册码", async () => {
  const code = mkCode({ maxUses: 5 });
  const first = new Client(H.BASE);
  const name = H.uniqueName("dup");
  assert.equal((await H.register(first, { name, code })).status, 303);
  const after = usedCount(code);

  const dup = new Client(H.BASE);
  const r = await H.register(dup, { name, code });
  assert.equal(r.status, 409, "重名应 409");
  assert.match(await r.res.text(), /已被占用/);
  assert.equal(usedCount(code), after, "重名失败不得烧掉注册码（校验先于核销）");
  assert.ok(!dup.jar.has("whl_session"), "失败不得建立会话");
});

test("无效注册码三态：伪造 / 过期 / 已用完，均 400 且文案可区分", async () => {
  const forged = new Client(H.BASE);
  const n1 = H.uniqueName("fg");
  const r1 = await H.register(forged, { name: n1, code: newCode() });
  assert.equal(r1.status, 400);
  assert.match(await r1.res.text(), /注册码无效/);

  const expiredCode = mkCode({ expiresAt: "2000-01-01T00:00:00.000Z" });
  const expired = new Client(H.BASE);
  const r2 = await H.register(expired, { name: H.uniqueName("ex"), code: expiredCode });
  assert.equal(r2.status, 400);
  assert.match(await r2.res.text(), /注册码已过期/);

  const spentCode = mkCode({ maxUses: 1, usedCount: 1 });
  const spent = new Client(H.BASE);
  const r3 = await H.register(spent, { name: H.uniqueName("sp"), code: spentCode });
  assert.equal(r3.status, 400);
  assert.match(await r3.res.text(), /注册码已用完/);
  assert.equal(usedCount(spentCode), 1, "失败不得改动已耗尽码的计数");
});

test("注册码并发双花：同一 max_uses=1 的码只放行一个账号", async () => {
  const code = mkCode({ maxUses: 1 });
  const names = [H.uniqueName("race"), H.uniqueName("race"), H.uniqueName("race")];
  const clients = names.map(() => new Client(H.BASE));
  const results = await Promise.all(clients.map((c, i) => H.register(c, { name: names[i], code })));
  const okCount = results.filter((r) => r.status === 303).length;
  assert.equal(okCount, 1, `只应有一个注册成功，实际 ${results.map((r) => r.status).join(",")}`);
  assert.equal(usedCount(code), 1, "码只应被核销一次");
  assert.equal(H.sql(`SELECT id FROM account WHERE name IN (${names.map((n) => `'${n}'`).join(",")});`).length, 1, "只应建出一个账号");
});

test("密码与昵称规则：弱密码 / 超长昵称 / 空昵称 / 坏邮箱一律 400", async () => {
  const cases = [
    [{ password: "short1" }, /至少 8 位/],
    [{ password: "alllettersx" }, /至少 8 位/],
    [{ password: "1234567890" }, /至少 8 位/],
    [{ name: "x".repeat(33) }, /昵称需要 1-32 个字符/],
    [{ name: "" }, /昵称需要 1-32 个字符/],
    [{ email: "not-an-email" }, /邮箱格式不对/],
  ];
  for (const [over, expect] of cases) {
    const c = new Client(H.BASE);
    const name = over.name === undefined ? H.uniqueName("rule") : over.name;
    if (over.name === "x".repeat(33)) {
      // 超长昵称：先确认它不会以 500 崩掉（历史上曾因 KV 键长 522 触发 500）
      const r = await H.register(c, { name, password: over.password || PW, email: over.email ?? "", code: mkCode() });
      assert.equal(r.status, 400, "超长昵称应被业务校验拒绝，而不是 500");
      continue;
    }
    const r = await H.register(c, { name, password: over.password || PW, email: over.email ?? "", code: mkCode() });
    assert.equal(r.status, 400, `case=${JSON.stringify(over)} 应 400，实际 ${r.status}`);
    assert.match(await r.res.text(), expect);
  }
});

test("缺/错 CSRF 的注册一律 403，不建号", async () => {
  const c = new Client(H.BASE);
  const name = H.uniqueName("csrf");
  const r = await c.postForm("/register", { name, password: PW }, { retry: false });
  assert.equal(r.status, 403);
  assert.equal(H.sql(`SELECT id FROM account WHERE name = '${name}';`).length, 0);

  await c.csrf("/register");
  const r2 = await c.postForm("/register", { csrf: "forged", name, password: PW }, { retry: false });
  assert.equal(r2.status, 403);
  assert.equal(H.sql(`SELECT id FROM account WHERE name = '${name}';`).length, 0);
});

test("注册 IP 限流 5/小时：同一 IP 第 6 次请求 429", async () => {
  const c = new Client(H.BASE);
  for (let i = 0; i < 5; i++) {
    const r = await c.postForm("/register", { name: H.uniqueName("rl") }, { retry: false });
    assert.equal(r.status, 403, `第 ${i + 1} 次应因缺 CSRF 被 403（限流尚未触发），实际 ${r.status}`);
  }
  const over = await c.postForm("/register", { name: H.uniqueName("rl") }, { retry: false });
  assert.equal(over.status, 429, "第 6 次应被注册 IP 桶拦下");
  assert.match(await over.text(), /注册太频繁/);
});

test("已登录用户访问 /register 与 /login：直接回跳，不出现重复登录入口", async () => {
  const c = new Client(H.BASE);
  const r = await H.register(c, { name: H.uniqueName("signed") });
  assert.equal(r.status, 303);
  const reg = await c.get("/register");
  assert.equal(reg.status, 303);
  assert.equal(loc(reg).pathname, "/");
  const login = await c.get("/login");
  assert.equal(login.status, 303);
  assert.equal(loc(login).pathname, "/");
});
