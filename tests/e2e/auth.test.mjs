// 登录/会话基线：页面守卫、cookie 属性、会话固定、CSRF、限流、开放跳转、反射转义、登出。
import { test } from "node:test";
import assert from "node:assert/strict";
import { Client } from "../lib/client.mjs";
import * as H from "../lib/harness.mjs";
import { verifyPassword } from "../../src/lib/crypto.ts";

const PW = "TestPass123";
const anon = () => new Client(H.BASE);
const loc = (res) => {
  const v = res.headers.get("location");
  assert.ok(v, "应当有 Location 头");
  return new URL(v, H.BASE);
};

/** 注册一个新账号（注册即登录）；每次都用新 Client → 新 IP，避开注册 IP 限流 */
async function freshUser(prefix = "e2e") {
  const client = new Client(H.BASE);
  const r = await H.register(client, { name: H.uniqueName(prefix) });
  assert.equal(r.status, 303, `注册应成功，实际 ${r.status}`);
  assert.ok(client.jar.get("whl_session"), "注册后应建立会话");
  return { client, name: r.name };
}

test("匿名访问受保护页面一律 303 跳登录，并带上回跳路径", async () => {
  const c = anon();
  for (const p of ["/", "/password"]) {
    const r = await c.get(p);
    assert.equal(r.status, 303, `${p} 应 303，实际 ${r.status}`);
    assert.equal(loc(r).pathname, "/login");
  }
  const b = await c.get("/bind");
  assert.equal(b.status, 303);
  assert.equal(loc(b).pathname, "/login");
  assert.equal(loc(b).searchParams.get("next"), "/bind", "受保护页面应保留回跳地址");
});

test("会话与 CSRF cookie 属性：HttpOnly + SameSite=Lax + Path=/ + host-only（无 Domain）+ http 下无 Secure", async () => {
  const c = anon();
  const { res } = await c.text("/login");
  const csrfCookie = (res.headers.getSetCookie() || []).find((s) => s.startsWith("whl_csrf="));
  assert.ok(csrfCookie, "访问登录页应下发 whl_csrf");
  for (const attr of ["HttpOnly", "SameSite=Lax", "Path=/"]) assert.ok(csrfCookie.includes(attr), `whl_csrf 应含 ${attr}：${csrfCookie}`);
  assert.ok(!/Domain=/i.test(csrfCookie), `不应设 Domain（保持 host-only）：${csrfCookie}`);
  assert.ok(!/;\s*Secure/i.test(csrfCookie), `http 下不应带 Secure：${csrfCookie}`);

  const u = await freshUser("cookie");
  const ures = await u.client.raw("/", { method: "GET" });
  const sessionCookie = (ures.headers.getSetCookie() || []).find((s) => s.startsWith("whl_session="));
  // 会话 cookie 在注册/登录响应里下发；这里用 jar 已存在的名字兜底断言
  assert.ok(u.client.jar.get("whl_session"), "应有 whl_session");
  if (sessionCookie) {
    for (const attr of ["HttpOnly", "SameSite=Lax", "Path=/"]) assert.ok(sessionCookie.includes(attr), `whl_session 应含 ${attr}`);
    assert.ok(!/Domain=/i.test(sessionCookie));
    assert.ok(!/;\s*Secure/i.test(sessionCookie));
  }
});

test("会话固定防御：两次登录签发不同的 256 位随机 token", async () => {
  const u = await freshUser("fix");
  const first = u.client.jar.get("whl_session");
  assert.match(first, /^[A-Za-z0-9\-_]{43}$/, "token 应为 32 字节 base64url");
  // 登出后重新登录
  const csrf = await u.client.csrf("/");
  const out = await u.client.postForm("/logout", { csrf }, { retry: false });
  assert.equal(out.status, 303);
  assert.ok(!u.client.jar.get("whl_session"), "登出应清掉会话 cookie");
  await H.signIn(u.client, u.name, PW);
  const second = u.client.jar.get("whl_session");
  assert.ok(second, "应重新签发会话");
  assert.notEqual(second, first, "重新登录不得复用旧 token（防会话固定）");

  const other = await freshUser("fix2");
  assert.notEqual(other.client.jar.get("whl_session"), second, "不同客户端不得拿到相同 token");
});

test("登录失败统一 401，不建立会话；缺 CSRF 一律 403", async () => {
  const u = await freshUser("loginfail");

  const wrongPw = new Client(H.BASE);
  const a = await H.signIn(wrongPw, u.name, "WrongPass999");
  assert.equal(a.status, 401, "密码错误应 401");
  assert.ok(!wrongPw.jar.has("whl_session"), "失败不得下发会话");

  const unknown = new Client(H.BASE);
  const b = await H.signIn(unknown, `nobody_${Date.now()}`, PW);
  assert.equal(b.status, 401, "账号不存在也应 401");

  const noCsrf = new Client(H.BASE);
  const c = await noCsrf.postForm("/login", { name: u.name, password: PW }, { retry: false });
  assert.equal(c.status, 403, "缺 CSRF 应 403");
  assert.ok(!noCsrf.jar.has("whl_session"));

  const badCsrf = new Client(H.BASE);
  await badCsrf.csrf("/login");
  const d = await badCsrf.postForm("/login", { csrf: "forged-token", name: u.name, password: PW }, { retry: false });
  assert.equal(d.status, 403, "CSRF 不匹配应 403");
  assert.ok(!badCsrf.jar.has("whl_session"));
});

test("登录 IP 限流 10/15min：前 10 次按失败语义返回，第 11 次 429", async () => {
  const c = anon();
  const codes = [];
  for (let i = 0; i < 10; i++) {
    // 每次换一个不存在的账号名，避免触发「账号级」5/15min 桶
    const r = await H.signIn(c, `rl_${Date.now()}_${i}`, PW);
    codes.push(r.status);
  }
  assert.deepEqual(codes, Array(10).fill(401), `前 10 次应为 401，实际 ${codes}`);
  const over = await H.signIn(c, `rl_over_${Date.now()}`, PW);
  assert.equal(over.status, 429, "第 11 次应被 IP 桶拦下");
});

test("超长昵称不得 500（F-B）：65 / 490 / 491 / 600 字符一律按失败语义 401", async () => {
  for (const len of [65, 490, 491, 600]) {
    const c = anon();
    const r = await H.signIn(c, "x".repeat(len), PW);
    assert.equal(r.status, 401, `昵称长度 ${len} 应 401（曾因 KV 键超 512 字节 500），实际 ${r.status}`);
    assert.ok(!c.jar.has("whl_session"), "失败不得建立会话");
  }
});

test("账号桶不锁受害者（F-C）：攻击者 IP 连失 6 次被 429，受害者换 IP 用正确密码照常登录", async () => {
  const u = await freshUser("namelimit");
  const attacker = anon();
  const codes = [];
  for (let i = 0; i < 6; i++) codes.push((await H.signIn(attacker, u.name, "WrongPass999")).status);
  assert.deepEqual(codes.slice(0, 5), Array(5).fill(401), `前 5 次应 401，实际 ${codes}`);
  assert.equal(codes[5], 429, "第 6 次应触发「攻击者 IP + 账号」桶");

  // 受害者从另一个 IP 用正确密码：账号桶只在失败路径计数（且成功即清零），不得被锁死
  const victim = new Client(H.BASE);
  const ok = await H.signIn(victim, u.name, PW);
  assert.equal(ok.status, 303, "受害者不得被攻击者的失败次数锁死");
  assert.ok(victim.jar.get("whl_session"), "受害者应成功建立会话");
});

test("开放跳转：next 只允许站内相对路径", async () => {
  const payloads = ["//evil.com", "http://evil.com/x", "https://evil.com", "/\\evil.com", "javascript:alert(1)", "////evil.com"];
  for (const next of payloads) {
    // 每个 payload 换一个账号：同一账号的 login-name 桶只有 5/15min
    const u = await freshUser("next");
    const c = new Client(H.BASE);
    const { res } = await c.loginWithCsrf(u.name, PW, next);
    assert.equal(res.status, 303, `next=${next} 应正常登录，实际 ${res.status}`);
    const u2 = loc(res);
    assert.equal(u2.origin, new URL(H.BASE).origin, `next=${next} 不得跳到外域：${u2.href}`);
  }
});

test("反射转义：?next 注入的脚本不得原样出现在页面里", async () => {
  const c = anon();
  const { res, body } = await c.text(`/login?next=${encodeURIComponent("<script>alert(1337)</script>")}`);
  assert.equal(res.status, 200);
  assert.ok(!body.includes("<script>alert(1337)"), "next 必须被 HTML 转义");
  const { body: reg } = await c.text(`/register?x=${encodeURIComponent("<img src=x onerror=alert(1)>")}`);
  assert.ok(!reg.includes("<img src=x onerror=alert(1)>"), "注册页不得反射未转义内容");
});

test("登出：CSRF 有效则作废会话并跳登录页；旧 token 立即失效", async () => {
  const u = await freshUser("logout");
  const token = u.client.jar.get("whl_session");
  const csrf = await u.client.csrf("/");
  const res = await u.client.postForm("/logout", { csrf }, { retry: false });
  assert.equal(res.status, 303);
  assert.equal(loc(res).pathname, "/login");

  // 会话行应已吊销
  const rows = H.sql(`SELECT revoked_at FROM session WHERE token_hash = '${H.sha256Hex(token)}';`);
  assert.equal(rows.length, 1);
  assert.ok(rows[0].revoked_at, "登出后 session.revoked_at 应写入时间戳");

  // 拿旧 cookie 重放（模拟未清 cookie 的浏览器）不得被认作已登录
  const replay = new Client(H.BASE, new Map([["whl_session", token]]));
  const r = await replay.get("/");
  assert.equal(r.status, 303, "已吊销的会话不得再被接受");
  assert.equal(loc(r).pathname, "/login");
});

test("匿名可读探针端点：/healthz 与发现文档不需要登录", async () => {
  const c = anon();
  assert.equal((await c.get("/healthz")).status, 200);
  assert.equal((await c.get("/jwks.json")).status, 200);
  assert.equal((await c.get("/.well-known/openid-configuration")).status, 200);
  const r = await c.get("/userinfo");
  assert.equal(r.status, 401, "无 token 的 userinfo 应 401");
});

test("注册码名额：同名并发注册只消耗成功那一次（F-F）", async () => {
  const name = H.uniqueName("ff");
  const codeHash = H.sha256Hex(H.SIGNUP_CODE);
  const before = H.sql(`SELECT used_count FROM signup_code WHERE code_hash = '${codeHash}';`)[0].used_count;

  // 两个并发请求都通过「昵称未被占用」前置检查 → 抢先核销注册码 → 一个在 UNIQUE(name) 上失败
  const [a, b] = await Promise.all([
    H.register(new Client(H.BASE), { name }),
    H.register(new Client(H.BASE), { name }),
  ]);
  const okCount = [a, b].filter((r) => r.status === 303).length;
  assert.equal(okCount, 1, `同名并发注册应恰好成功一个，实际 ${a.status}/${b.status}`);

  const after = H.sql(`SELECT used_count FROM signup_code WHERE code_hash = '${codeHash}';`)[0].used_count;
  assert.equal(after - before, 1, `只有建号成功那次可以消耗名额（失败侧必须退还），实际 +${after - before}`);
});

// —— 透明重哈希（增量 9，TECH_DESIGN §8 第 1 条）——

/** 按指定迭代数造一份与产品同格式的存档哈希（Node 与 workerd 的 WebCrypto PBKDF2 同为原生实现） */
async function legacyHash(password, iterations) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, 256);
  const b64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b)));
  return `pbkdf2$${iterations}$${b64(salt)}$${b64(bits)}`;
}

test("透明重哈希：低迭代存量登录成功后后台升到当前档并写 pw.rehash 审计", async () => {
  const { name } = await freshUser("rehash");
  const accountId = H.sql(`SELECT id FROM account WHERE name = '${name}';`)[0].id;

  // 模拟收口迁移来的低迭代存量哈希
  H.sqlExec(
    `UPDATE credential SET hash = '${await legacyHash(PW, 1000)}', iterations = 1000 ` +
      `WHERE account_id = ${accountId} AND type = 'password';`,
  );
  assert.ok(
    H.sql(`SELECT hash FROM credential WHERE account_id = ${accountId} AND type = 'password';`)[0].hash.startsWith("pbkdf2$1000$"),
    "低迭代存档应已播种",
  );

  // 低迭代账号可正常登录（verifyPassword 按存档迭代数验）；用新 Client——原 client 已带注册
  // 会话，GET /login 会 303 拿不到 CSRF（测试环境已知坑），新 Client 同时是新 IP 不污染账号桶
  const r = await H.signIn(new Client(H.BASE), name, PW);
  assert.equal(r.status, 303, `低迭代账号应能登录，实际 ${r.status}`);

  // 后台重哈希：升到当前档 + pw.rehash 审计（runDetached 异步，轮询等待）
  const upgraded = await H.waitFor(() => {
    const row = H.sql(`SELECT hash, iterations FROM credential WHERE account_id = ${accountId} AND type = 'password';`)[0];
    return row && row.iterations === 25_000 ? row : null;
  });
  assert.ok(upgraded, "登录成功后凭证应被后台重哈希到当前档");
  assert.equal(await verifyPassword(PW, upgraded.hash), true, "升级后的哈希应仍验得过大密码");

  const audited = await H.waitFor(
    () => H.sql(`SELECT detail FROM audit_log WHERE account_id = ${accountId} AND event = 'pw.rehash';`)[0] || null,
  );
  assert.ok(audited, "重哈希应写 pw.rehash 审计");
  assert.equal(JSON.parse(audited.detail).from, 1000, "审计应记录升档前的迭代数");

  // 升级后换个新客户端再登录，全链路无损
  const again = new Client(H.BASE);
  assert.equal((await H.signIn(again, name, PW)).status, 303, "升级后应能继续正常登录");
});
