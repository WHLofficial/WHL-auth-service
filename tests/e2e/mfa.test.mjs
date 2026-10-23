// 两步验证（v4.0.0，P0）：TOTP 启用 → 密码后二次挑战 → 会话建立；恢复码一次性；
// 超管未启用 MFA 时全站被挡在 /mfa/setup。
import { test } from "node:test";
import assert from "node:assert/strict";
import { Client } from "../lib/client.mjs";
import * as H from "../lib/harness.mjs";
import { currentTotpStep, totpCode } from "../../src/lib/totp.ts";

const PW = "TestPass123";
const Q = (s) => `'${String(s).replace(/'/g, "''")}'`;

function csrfOf(body) {
  const m = /name="csrf" value="([^"]+)"/.exec(body);
  assert.ok(m, "页面应含 csrf 隐藏域");
  return m[1];
}

async function logout(c) {
  const csrf = await c.csrf("/");
  await c.postForm("/logout", { csrf });
}

async function enableMfa(c) {
  const setup = await c.text("/mfa/setup");
  assert.equal(setup.res.status, 200, `设置页应可打开：${setup.body.slice(0, 120)}`);
  const secret = /<code>([A-Z2-7]{20,})<\/code>/.exec(setup.body)?.[1];
  assert.ok(secret, "设置页应显示 base32 密钥");
  const again = await c.text("/mfa/setup");
  const secretAgain = /<code>([A-Z2-7]{20,})<\/code>/.exec(again.body)?.[1];
  assert.equal(secretAgain, secret, "刷新设置页不能更换待确认密钥，否则旧验证码必然失效");
  const step = currentTotpStep();
  const code = await totpCode(secret, step);
  const res = await c.postForm("/mfa/setup", { csrf: csrfOf(setup.body), password: PW, code });
  const body = await res.text();
  assert.equal(res.status, 200, `启用应成功：${body.slice(0, 160)}`);
  assert.match(body, /恢复码/, "启用后应展示恢复码");
  const codes = [...body.matchAll(/<li><code>([A-Z2-9]{5}-[A-Z2-9]{5})<\/code><\/li>/g)].map((m) => m[1]);
  assert.equal(codes.length, 8, "应一次性生成 8 个恢复码");
  return { secret, step, codes };
}

test("启用 TOTP 后，密码只算第一步；正确验证码建立会话并写 login.ok", async () => {
  const c = new Client(H.BASE);
  const u = await H.register(c, { name: H.uniqueName("mfa") });
  assert.equal(u.status, 303);
  const { secret, step } = await enableMfa(c);

  assert.ok(H.sql(`SELECT totp_enabled_at FROM account WHERE name = ${Q(u.name)};`)[0].totp_enabled_at);
  const sealed = H.sql(`SELECT totp_secret FROM account WHERE name = ${Q(u.name)};`)[0].totp_secret;
  assert.match(sealed, /^enc:v1:/, "TOTP secret 必须密文落库");
  assert.ok(!sealed.includes(secret), "库里不得出现明文 secret");

  await logout(c);

  const c2 = new Client(H.BASE);
  const first = await H.signIn(c2, u.name, PW);
  assert.equal(first.status, 303);
  assert.equal(first.location, "/mfa", "有 TOTP 时密码通过后应先跳挑战页");
  assert.equal(c2.jar.get("whl_session"), undefined, "挑战阶段不得发会话");

  const page = await c2.text("/mfa");
  assert.equal(page.res.status, 200);
  assert.match(page.body, /两步验证/);
  const now = currentTotpStep();
  const code = await totpCode(secret, now > step ? now : now + 1);
  const ok = await c2.postForm("/mfa", { csrf: csrfOf(page.body), code });
  assert.equal(ok.status, 303, `二次验证应通过：${(await ok.text()).slice(0, 120)}`);
  assert.equal(ok.headers.get("location"), "/");
  assert.ok(c2.jar.get("whl_session"), "验证通过后才发会话");
  assert.equal((await c2.get("/")).status, 200);

  const events = H.sql(`SELECT event FROM audit_log WHERE account_id = (SELECT id FROM account WHERE name = ${Q(u.name)}) ORDER BY id;`).map((r) => r.event);
  assert.ok(events.includes("login.mfa_required"), events.join());
  assert.ok(events.includes("login.ok"), events.join());
  assert.ok(events.includes("mfa.enable"), events.join());
});

test("恢复码一次性：用过即失效，事件可审计", async () => {
  const c = new Client(H.BASE);
  const u = await H.register(c, { name: H.uniqueName("mfarec") });
  const { codes } = await enableMfa(c);
  await logout(c);

  const c2 = new Client(H.BASE);
  assert.equal((await H.signIn(c2, u.name, PW)).location, "/mfa");
  const page = await c2.text("/mfa");
  const ok = await c2.postForm("/mfa", { csrf: csrfOf(page.body), code: codes[0] });
  assert.equal(ok.status, 303);
  assert.ok(c2.jar.get("whl_session"));

  const accountId = H.sql(`SELECT id FROM account WHERE name = ${Q(u.name)};`)[0].id;
  const events = H.sql(`SELECT event, detail FROM audit_log WHERE account_id = ${accountId} ORDER BY id;`);
  assert.ok(events.some((r) => r.event === "mfa.recovery_used"), "应记 mfa.recovery_used");
  assert.ok(events.some((r) => r.event === "login.ok" && String(r.detail).includes("recovery")));

  await logout(c2);
  const c3 = new Client(H.BASE);
  assert.equal((await H.signIn(c3, u.name, PW)).location, "/mfa");
  const page3 = await c3.text("/mfa");
  const reuse = await c3.postForm("/mfa", { csrf: csrfOf(page3.body), code: codes[0] });
  assert.equal(reuse.status, 401, "同一恢复码不得二次使用");
  assert.equal(c3.jar.get("whl_session"), undefined);
});

test("超管未启用 MFA：登录后只能去 /mfa/setup，其他页面被中间件挡回", async () => {
  const c = new Client(H.BASE);
  const u = await H.register(c, { name: H.uniqueName("mfaroot") });
  await logout(c);
  H.sqlExec(
    `INSERT OR IGNORE INTO user_role (account_id, role_id, granted_by, granted_at)
     SELECT a.id, (SELECT id FROM role WHERE app_id IS NULL AND key = 'superadmin'), NULL, ${Q(new Date().toISOString())}
       FROM account a WHERE a.name = ${Q(u.name)};`,
  );

  const c2 = new Client(H.BASE);
  const login = await H.signIn(c2, u.name, PW);
  assert.equal(login.status, 303);
  assert.equal(login.location, "/mfa/setup", "超管登录后应直接进强制设置页");
  const home = await c2.get("/");
  assert.equal(home.status, 303);
  assert.equal(home.headers.get("location"), "/mfa/setup");
  assert.equal((await c2.get("/mfa/setup")).status, 200);
});
