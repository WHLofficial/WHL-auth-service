// 登出与 back-channel 广播回归（F-I）：
// 旧实现只挑 `oidc_refresh.revoked_at IS NULL` 的 client，导致「RP 已自行吊销 refresh
// （RP 侧登出 / 授权码重放处置）」后再从 auth 登出时，该 RP 收不到登出通知，本地会话残留。
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

/** 走一次完整授权，拿到 { access_token, refresh_token, sid } */
async function issueTokensFor(client, redirectUri) {
  const { verifier, challenge } = H.pkce();
  const a = await H.authorize(client, { clientId: H.TEST_APP, redirectUri, verifier, challenge });
  assert.ok(a.code, "应签发授权码");
  const ex = await H.exchangeCode({ code: a.code, redirectUri, verifier });
  assert.equal(ex.status, 200, `换码应成功：${ex.body}`);
  return ex.json;
}

test("F-I：RP 先自行吊销 refresh 后再登出，back-channel 通知仍必须发出", async () => {
  const bc = await H.startBackchannel();
  try {
    H.setAppEndpoints({ origin: bc.origin });
    const u = await freshUser("bcrev");
    const redirectUri = `${bc.origin}/cb`;
    const tokens = await issueTokensFor(u.client, redirectUri);
    const sid = H.sessionHashOf(u.client);

    // RP 侧先行吊销（模拟 RP 自己登出 / 或它收到过 revoke）
    assert.equal((await H.revoke({ token: tokens.refresh_token })).status, 200);
    const row = H.sql(`SELECT revoked_at FROM oidc_refresh WHERE token_hash = '${H.sha256Hex(tokens.refresh_token)}';`);
    assert.equal(row.length, 1);
    assert.ok(row[0].revoked_at, "RP 侧吊销应写库");

    // 用户在 auth 侧登出
    const csrf = await u.client.csrf("/");
    const out = await u.client.postForm("/logout", { csrf }, { retry: false });
    assert.equal(out.status, 303);
    assert.equal(loc(out).pathname, "/login");

    const n = await H.waitFor(() => bc.received.length > 0 && bc.received[0]);
    assert.ok(n, "已吊销 refresh 的 client 也必须收到 back-channel 登出通知（F-I 回归点）");
    assert.equal(n.method, "POST");
    assert.match(n.contentType, /application\/x-www-form-urlencoded/);
    assert.ok(n.form.logout_token, "应带 logout_token");
    assert.equal(n.url, "/bc", "应打到 app.backchannel_logout_uri");

    const { payload } = await H.jwksVerify(n.form.logout_token, { audience: H.TEST_APP });
    assert.equal(payload.sid, sid, "logout_token.sid 应等于该登录会话指纹");
    assert.ok(payload.events["http://schemas.openid.net/event/backchannel-logout"] !== undefined, "应带 back-channel event 声明");
    assert.match(payload.sub, /^\d+$/);
  } finally {
    await bc.close();
  }
});

test("正常路径：登出广播一次、会话吊销、token 不可续期", async () => {
  const bc = await H.startBackchannel();
  try {
    H.setAppEndpoints({ origin: bc.origin });
    const u = await freshUser("bcnorm");
    const redirectUri = `${bc.origin}/cb`;
    const tokens = await issueTokensFor(u.client, redirectUri);
    const token = H.sessionToken(u.client);

    const csrf = await u.client.csrf("/");
    await u.client.postForm("/logout", { csrf }, { retry: false });

    const n = await H.waitFor(() => bc.received[0]);
    assert.ok(n, "应收到登出通知");
    assert.equal(bc.received.length, 1, "同一 RP 只应收到一条通知");

    const s = H.sql(`SELECT revoked_at FROM session WHERE token_hash = '${H.sha256Hex(token)}';`);
    assert.ok(s[0]?.revoked_at, "会话行应吊销");
    assert.ok(
      H.sql(`SELECT revoked_at FROM oidc_refresh WHERE session_hash = '${H.sha256Hex(token)}';`).every((r) => r.revoked_at),
      "该会话签发的 refresh 应全部吊销",
    );
    const r = await H.refreshToken({ token: tokens.refresh_token });
    assert.equal(r.status, 400, "登出后 refresh 不得再换 token");
    assert.equal(r.json.error, "invalid_grant");
  } finally {
    await bc.close();
  }
});

test("GET /logout（end_session）：无会话也安全，白名单外不跳转、白名单内回带 state", async () => {
  const bc = await H.startBackchannel();
  try {
    H.setAppEndpoints({ origin: bc.origin });
    const u = await freshUser("endsess");
    const redirectUri = `${bc.origin}/cb`;
    await issueTokensFor(u.client, redirectUri);
    const token = H.sessionToken(u.client);

    // 白名单外：只跳登录页
    const bad = await u.client.get(`/logout?post_logout_redirect_uri=${encodeURIComponent("http://evil.example/x")}`);
    assert.equal(bad.status, 303);
    assert.equal(loc(bad).pathname, "/login", "未注册的回跳地址不得跳转");
    assert.ok(!u.client.jar.has("whl_session"), "end_session 应清会话");

    // 会话已清，再用白名单内地址：仍安全不抛错
    const good = await u.client.get(
      `/logout?post_logout_redirect_uri=${encodeURIComponent(`${bc.origin}/done`)}&state=s1`,
    );
    assert.equal(good.status, 303);
    const t = loc(good);
    assert.equal(t.origin, bc.origin);
    assert.equal(t.pathname, "/done");
    assert.equal(t.searchParams.get("state"), "s1", "应回传 state");
    assert.ok(H.sql(`SELECT revoked_at FROM session WHERE token_hash = '${H.sha256Hex(token)}';`)[0]?.revoked_at);
  } finally {
    await bc.close();
  }
});

test("无任何 OIDC 授权的会话登出：不广播、不报错（clients 为空的路径）", async () => {
  const bc = await H.startBackchannel();
  try {
    H.setAppEndpoints({ origin: bc.origin });
    const u = await freshUser("bcnone");
    const csrf = await u.client.csrf("/");
    const out = await u.client.postForm("/logout", { csrf }, { retry: false });
    assert.equal(out.status, 303, "没有下游 client 时登出也必须成功");
    await new Promise((r) => setTimeout(r, 400));
    assert.equal(bc.received.length, 0, "没有绑定过 client，不应产生广播");
  } finally {
    await bc.close();
  }
});

test("登出 CSRF 无效：不改变登录态（不误登出）", async () => {
  const u = await freshUser("bccsrf");
  const token = H.sessionToken(u.client);
  const r = await u.client.postForm("/logout", { csrf: "forged" }, { retry: false });
  assert.equal(r.status, 303, "缺/错 CSRF 走同一 303 分支");
  assert.equal(H.sessionToken(u.client), token, "会话 cookie 不应被清");
  const s = H.sql(`SELECT revoked_at FROM session WHERE token_hash = '${H.sha256Hex(token)}';`);
  assert.equal(s[0]?.revoked_at, null, "会话不得被吊销");
  assert.equal((await u.client.get("/")).status, 200, "仍应处于登录态");
});

test("跨站 GET /logout 被拒（L-1）：cross-site 不碰会话；同站导航照常登出", async () => {
  const u = await freshUser("getlogout");
  const token = H.sessionToken(u.client);

  // 第三方页面发起顶层导航会带上 SameSite=Lax 的会话 cookie → 必须拒绝
  const x = await u.client.get("/logout", { headers: { "Sec-Fetch-Site": "cross-site" } });
  assert.equal(x.status, 303);
  assert.equal(loc(x).pathname, "/login", "跨站登出应静默跳登录页");
  assert.equal(H.sessionToken(u.client), token, "跨站请求不得清会话 cookie");
  assert.equal(
    H.sql(`SELECT revoked_at FROM session WHERE token_hash = '${H.sha256Hex(token)}';`)[0]?.revoked_at,
    null,
    "跨站请求不得吊销会话",
  );
  assert.equal((await u.client.get("/")).status, 200, "仍应处于登录态");

  // 三系统同属 *.whleague.win → Sec-Fetch-Site: same-site，必须照常登出
  const y = await u.client.get("/logout", { headers: { "Sec-Fetch-Site": "same-site" } });
  assert.equal(y.status, 303);
  assert.equal(loc(y).pathname, "/login");
  assert.equal(H.sessionToken(u.client), undefined, "同站 GET /logout 应正常清会话");
  assert.ok(
    H.sql(`SELECT revoked_at FROM session WHERE token_hash = '${H.sha256Hex(token)}';`)[0]?.revoked_at,
    "同站 GET /logout 应吊销会话",
  );
});
