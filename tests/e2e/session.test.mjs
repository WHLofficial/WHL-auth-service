// 会话与改密门禁的回归靶点：
//  F-D 服务端必须校验 session.expires_at（此前只查 revoked_at）
//  F-A must_change_pw=1 必须全局拦住页面与授权端点（此前只在登录后 303 到 /password，可绕过）
import { test } from "node:test";
import assert from "node:assert/strict";
import { Client } from "../lib/client.mjs";
import * as H from "../lib/harness.mjs";

const PW = "TestPass123";
const loc = (res) => new URL(res.headers.get("location"), H.BASE);

async function freshUser(prefix) {
  const client = new Client(H.BASE);
  const r = await H.register(client, { name: H.uniqueName(prefix) });
  assert.equal(r.status, 303, `注册应成功，实际 ${r.status}`);
  return { client, name: r.name };
}

test("F-D：D1 里 expires_at 已过期的会话不得再被接受（页面）", async () => {
  const u = await freshUser("exp");
  const token = H.sessionToken(u.client);
  assert.equal((await u.client.get("/")).status, 200, "改时间前应正常访问");

  H.sqlExec(`UPDATE session SET expires_at = '2000-01-01T00:00:00.000Z' WHERE token_hash = '${H.sha256Hex(token)}';`);
  assert.equal(H.sql(`SELECT expires_at FROM session WHERE token_hash = '${H.sha256Hex(token)}';`)[0].expires_at, "2000-01-01T00:00:00.000Z");

  const r = await u.client.get("/");
  assert.equal(r.status, 303, "过期会话访问 / 应跳登录（服务端必须校验 expires_at）");
  assert.equal(loc(r).pathname, "/login");

  const b = await u.client.get("/bind");
  assert.equal(b.status, 303, "过期会话访问 /bind 也应跳登录");
  assert.equal(loc(b).pathname, "/login");
});

test("F-D：过期会话不得再换取授权码（/authorize 与 /token 双闸）", async () => {
  const bc = await H.startBackchannel();
  try {
    H.setAppEndpoints({ origin: bc.origin });
    const u = await freshUser("expcode");
    const { verifier, challenge } = H.pkce();
    const redirectUri = `${bc.origin}/cb`;

    // 先拿一个未过期的授权码
    const a1 = await H.authorize(u.client, { clientId: H.TEST_APP, redirectUri, verifier, challenge });
    assert.equal(a1.status, 303, `authorize 应 303，实际 ${a1.status}`);
    assert.ok(a1.code, "应签发授权码");

    // 会话过期后：新的 authorize 必须跳登录，且不得签发授权码
    H.sqlExec(`UPDATE session SET expires_at = '2000-01-01T00:00:00.000Z' WHERE token_hash = '${H.sessionHashOf(u.client)}';`);
    const a2 = await H.authorize(u.client, { clientId: H.TEST_APP, redirectUri, verifier, challenge });
    assert.equal(a2.status, 303);
    assert.equal(a2.code, null, "过期会话不得签发授权码");
    assert.equal(loc(a2.res).pathname, "/login", "应跳登录页");

    // 过期会话之前签发的授权码，换 token 时也必须被拒（会话已死）
    const ex = await H.exchangeCode({ code: a1.code, redirectUri, verifier });
    assert.equal(ex.status, 400, "过期会话的授权码不应换到 token");
    assert.equal(ex.json.error, "invalid_grant");
    assert.match(ex.json.error_description || "", /会话|登录/, `描述应说明会话已结束：${ex.body}`);
  } finally {
    await bc.close();
  }
});

test("F-A：must_change_pw=1 时页面被全局拦到 /password，且保留回跳路径", async () => {
  const u = await freshUser("mustchg");
  H.sqlExec(`UPDATE account SET must_change_pw = 1 WHERE name = '${u.name}';`);
  assert.equal(H.sql(`SELECT must_change_pw FROM account WHERE name = '${u.name}';`)[0].must_change_pw, 1);

  for (const [path, expectedNext] of [["/", "/"], ["/bind", "/bind"]]) {
    const r = await u.client.get(path);
    assert.equal(r.status, 303, `${path} 应被改密门禁拦下`);
    const l = loc(r);
    assert.equal(l.pathname, "/password", `${path} 应跳 /password`);
    assert.equal(l.searchParams.get("next"), expectedNext, `应保留回跳路径 ${expectedNext}`);
  }

  // 授权端点同样被拦：不得签发授权码
  const bc = await H.startBackchannel();
  try {
    H.setAppEndpoints({ origin: bc.origin });
    const { verifier, challenge } = H.pkce();
    const redirectUri = `${bc.origin}/cb`;
    const a = await H.authorize(u.client, { clientId: H.TEST_APP, redirectUri, verifier, challenge });
    assert.equal(a.status, 303);
    assert.equal(a.code, null, "must_change_pw 未改密前不得签发授权码");
    assert.equal(loc(a.res).pathname, "/password", "应跳 /password");
    assert.match(loc(a.res).searchParams.get("next") || "", /^\/authorize\?/, "应带回原始 authorize 查询串");
  } finally {
    await bc.close();
  }
});

test("F-A：门禁期间白名单端点仍可用（避免自我锁死）", async () => {
  const u = await freshUser("mustexempt");
  H.sqlExec(`UPDATE account SET must_change_pw = 1 WHERE name = '${u.name}';`);

  assert.equal((await u.client.get("/healthz")).status, 200);
  assert.equal((await u.client.get("/jwks.json")).status, 200);
  assert.equal((await u.client.get("/.well-known/openid-configuration")).status, 200);
  const pw = await u.client.get("/password");
  assert.equal(pw.status, 200, "/password 必须可达，否则用户无法自救");
  const login = await u.client.get("/login");
  assert.equal(login.status, 303, "已登录访问 /login 仍应回跳（不应被门禁改写为 303 → /password 死循环）");
  assert.notEqual(loc(login).pathname, "/password", "不得形成 /login → /password → /login 死循环");
});

test("改密闭环：旧会话作废、must_change_pw 清零、旧密码失效、新密码可登录", async () => {
  const u = await freshUser("pwchange");
  H.sqlExec(`UPDATE account SET must_change_pw = 1 WHERE name = '${u.name}';`);
  await u.client.get("/"); // 触发一次门禁跳转，确认处于受控态
  const oldToken = H.sessionToken(u.client);

  const csrf = await u.client.csrf("/password");
  const oldPw = "TestPass123";
  const newPw = "NewPass456";
  const r = await u.client.postForm("/password", { csrf, oldPassword: oldPw, newPassword: newPw }, { retry: false });
  assert.equal(r.status, 303, `改密应成功，实际 ${r.status}`);
  assert.equal(loc(r).pathname, "/");
  assert.equal(loc(r).searchParams.get("notice"), "pw_changed");

  assert.equal(H.sql(`SELECT must_change_pw FROM account WHERE name = '${u.name}';`)[0].must_change_pw, 0, "改密后 must_change_pw 应清零");
  assert.equal((await u.client.get("/")).status, 200, "改密后应能正常访问 /");
  assert.notEqual(H.sessionToken(u.client), oldToken, "改密应轮换会话 token");

  // 旧 token 重放必须失效
  const replay = new Client(H.BASE, new Map([["whl_session", oldToken]]));
  assert.equal((await replay.get("/")).status, 303, "改密前的旧会话应作废");
  const oldSession = H.sql(`SELECT revoked_at FROM session WHERE token_hash = '${H.sha256Hex(oldToken)}';`);
  assert.ok(oldSession[0]?.revoked_at, "旧 session 行应被标记吊销");

  // 旧密码不可用、新密码可用
  const stale = new Client(H.BASE);
  assert.equal((await H.signIn(stale, u.name, oldPw)).status, 401, "旧密码应失效");
  const fresh = new Client(H.BASE);
  assert.equal((await H.signIn(fresh, u.name, newPw)).status, 303, "新密码应可登录");
});

test("改密的三类拒绝：缺 CSRF 403、新密码太弱 400、旧密码错 400", async () => {
  const u = await freshUser("pwreject");

  const csrf = await u.client.csrf("/password");
  const noCsrf = await u.client.postForm("/password", { oldPassword: PW, newPassword: "Good12345" }, { retry: false });
  assert.equal(noCsrf.status, 403, "缺 CSRF 应 403");

  const weak = await u.client.postForm("/password", { csrf, oldPassword: PW, newPassword: "short" }, { retry: false });
  assert.equal(weak.status, 400, "弱密码应 400");
  assert.match(await weak.text(), /至少 8 位/);

  const badOld = await u.client.postForm("/password", { csrf, oldPassword: "WrongOld999", newPassword: "Good12345" }, { retry: false });
  assert.equal(badOld.status, 400, "旧密码错应 400");
  assert.match(await badOld.text(), /旧密码不对/);

  // 失败后不应改变账号状态与会话
  assert.equal(H.sql(`SELECT must_change_pw FROM account WHERE name = '${u.name}';`)[0].must_change_pw, 0);
  const fresh = new Client(H.BASE);
  assert.equal((await H.signIn(fresh, u.name, PW)).status, 303, "原密码仍应有效");
});
