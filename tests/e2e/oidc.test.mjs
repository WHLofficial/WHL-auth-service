// OIDC 授权服务回归：发现文档/JWKS、授权码全链路、PKCE 强制、白名单、一次性与重放、refresh 轮换与重用、userinfo、revoke。
import { test } from "node:test";
import assert from "node:assert/strict";
import { Client } from "../lib/client.mjs";
import * as H from "../lib/harness.mjs";

const PW = "TestPass123";
const ORIGIN = new URL(H.BASE).origin;
const loc = (res) => new URL(res.headers.get("location"), H.BASE);

async function freshUser(prefix) {
  const client = new Client(H.BASE);
  const r = await H.register(client, { name: H.uniqueName(prefix) });
  assert.equal(r.status, 303, `注册应成功，实际 ${r.status}`);
  return { client, name: r.name };
}

test("发现文档与 JWKS：元数据正确，公钥集不含任何私钥字段", async () => {
  const c = new Client(H.BASE);
  const doc = await (await c.get("/.well-known/openid-configuration")).json();
  assert.equal(doc.issuer, ORIGIN);
  assert.equal(doc.authorization_endpoint, `${ORIGIN}/authorize`);
  assert.equal(doc.token_endpoint, `${ORIGIN}/token`);
  assert.equal(doc.userinfo_endpoint, `${ORIGIN}/userinfo`);
  assert.equal(doc.jwks_uri, `${ORIGIN}/jwks.json`);
  assert.equal(doc.end_session_endpoint, `${ORIGIN}/logout`);
  assert.equal(doc.backchannel_logout_supported, true);
  assert.equal(doc.backchannel_logout_session_supported, true);
  assert.ok(doc.response_types_supported.includes("code"));
  assert.ok(doc.code_challenge_methods_supported.includes("S256"));

  const jwks = await (await c.get("/jwks.json")).json();
  assert.equal(jwks.keys.length, 1);
  const k = jwks.keys[0];
  assert.equal(k.kty, "RSA");
  assert.equal(k.use, "sig");
  assert.equal(k.alg, "RS256");
  for (const priv of ["d", "p", "q", "dp", "dq", "qi", "k"]) {
    assert.ok(!(priv in k), `JWKS 不得含私钥字段 ${priv}`);
  }
  assert.ok(k.kid && k.kid.length >= 32, "kid 应为密钥指纹");
});

test("授权码全链路：code → token → userinfo，id_token 验签与声明齐备", async () => {
  const bc = await H.startBackchannel();
  try {
    H.setAppEndpoints({ origin: bc.origin });
    const u = await freshUser("oidc");
    const { verifier, challenge } = H.pkce();
    const redirectUri = `${bc.origin}/cb`;

    const a = await H.authorize(u.client, { clientId: H.TEST_APP, redirectUri, verifier, challenge, state: "st-xyz", nonce: "nonce-1" });
    assert.equal(a.status, 303);
    assert.equal(loc(a.res).origin, bc.origin, "应跳回注册的回调地址");
    assert.ok(a.code, "应带 code");
    assert.equal(a.state, "st-xyz", "应回传 state");
    assert.equal(loc(a.res).searchParams.get("iss"), ORIGIN, "应带 RFC 9207 iss");

    const ex = await H.exchangeCode({ code: a.code, redirectUri, verifier });
    assert.equal(ex.status, 200, `换码应成功：${ex.body}`);
    assert.equal(ex.json.token_type, "Bearer");
    assert.equal(ex.json.expires_in, 1800);
    assert.ok(ex.json.access_token && ex.json.id_token && ex.json.refresh_token, "三件套齐全");

    const { payload } = await H.jwksVerify(ex.json.id_token, { audience: H.TEST_APP });
    assert.equal(payload.iss, ORIGIN);
    assert.equal(payload.aud, H.TEST_APP);
    assert.equal(payload.nonce, "nonce-1", "id_token 必须回带 nonce");
    assert.ok(payload.sid && payload.sid.length === 64, "sid 应为会话指纹（sha256 hex）");
    assert.match(payload.sub, /^\d+$/, "sub 必须是纯数字账号 id");
    assert.equal(payload.sid, H.sessionHashOf(u.client), "sid 应与当前登录会话一致");

    const ui = await H.userinfo(ex.json.access_token);
    assert.equal(ui.status, 200, `userinfo 应 200：${ui.body}`);
    assert.equal(ui.json.sub, payload.sub);
    assert.equal(ui.json.name, u.name, "profile scope 应带昵称");
    assert.equal(ui.json.locked, false);
    assert.equal(ui.json.must_change_pw, false);
    assert.ok(Array.isArray(ui.json.roles));
    // 跨系统隔离：test-rp 这个 aud 上没有任何角色，不得泄漏 tour/club 的角色
    assert.deepEqual(ui.json.roles, [], `test-rp 不应有角色，实际 ${JSON.stringify(ui.json.roles)}`);
    assert.deepEqual(ui.json.permissions, [], "test-rp 不应有权限点");
    assert.equal(ui.json.qq, null);
  } finally {
    await bc.close();
  }
});

test("授权码一次性：重放无效，且触发同码 refresh 全量吊销", async () => {
  const bc = await H.startBackchannel();
  try {
    H.setAppEndpoints({ origin: bc.origin });
    const u = await freshUser("replay");
    const { verifier, challenge } = H.pkce();
    const redirectUri = `${bc.origin}/cb`;
    const a = await H.authorize(u.client, { clientId: H.TEST_APP, redirectUri, verifier, challenge });
    const first = await H.exchangeCode({ code: a.code, redirectUri, verifier });
    assert.equal(first.status, 200);

    const again = await H.exchangeCode({ code: a.code, redirectUri, verifier });
    assert.equal(again.status, 400, "同一 code 二次换码必须失败");
    assert.equal(again.json.error, "invalid_grant");
    assert.match(again.json.error_description, /已使用|无效/);

    // 重放检测的处置：该 code 换出的 refresh 应已被吊销
    const rows = H.sql(`SELECT revoked_at FROM oidc_refresh WHERE code_hash = '${H.sha256Hex(a.code)}';`);
    assert.equal(rows.length, 1, "应有一条 refresh 记录");
    assert.ok(rows[0].revoked_at, "重放检测应吊销该 code 换出的 refresh");

    const r = await H.refreshToken({ token: first.json.refresh_token });
    assert.equal(r.status, 400, "被吊销的 refresh 不得再换 token");
    assert.equal(r.json.error, "invalid_grant");
  } finally {
    await bc.close();
  }
});

test("PKCE 强制：缺 challenge 不签码；错 verifier / 错 redirect_uri 换不到", async () => {
  const bc = await H.startBackchannel();
  try {
    H.setAppEndpoints({ origin: bc.origin });
    const u = await freshUser("pkce");
    const { verifier, challenge } = H.pkce();
    const redirectUri = `${bc.origin}/cb`;

    // 缺 code_challenge → 错误跳回（invalid_request），不签码
    const noCh = await H.authorize(u.client, { url: H.authorizeQuery({ clientId: H.TEST_APP, redirectUri, challenge: "" }) });
    assert.equal(noCh.status, 303);
    assert.equal(noCh.error, "invalid_request");
    assert.equal(noCh.code, null);

    // 错 method → 同样拒绝
    const badMethod = await H.authorize(u.client, {
      url: H.authorizeQuery({ clientId: H.TEST_APP, redirectUri, challenge, extra: { code_challenge_method: "plain" } }),
    });
    assert.equal(badMethod.error, "invalid_request");

    // 正确 challenge，但换码用错 verifier
    const a = await H.authorize(u.client, { clientId: H.TEST_APP, redirectUri, verifier, challenge });
    assert.ok(a.code);
    const bad = await H.exchangeCode({ code: a.code, redirectUri, verifier: H.pkce().verifier });
    assert.equal(bad.status, 400);
    assert.equal(bad.json.error, "invalid_grant");
    assert.match(bad.json.error_description, /PKCE/);

    // 换码 redirect_uri 与发码时不一致
    const a2 = await H.authorize(u.client, { clientId: H.TEST_APP, redirectUri, verifier, challenge });
    const mismatch = await H.exchangeCode({ code: a2.code, redirectUri: `${bc.origin}/other`, verifier });
    assert.equal(mismatch.status, 400);
    assert.match(mismatch.json.error_description, /不一致/);
  } finally {
    await bc.close();
  }
});

test("client_id / redirect_uri 白名单：不匹配一律 400 错误页，绝不跳转", async () => {
  const u = await freshUser("wl");
  const { challenge } = H.pkce();
  const bad = [
    { client_id: "no-such-client", redirect_uri: "http://127.0.0.1:1/cb" },
    { client_id: H.TEST_APP, redirect_uri: "http://evil.example/cb" },
    { client_id: H.TEST_APP, redirect_uri: "http://127.0.0.1:1/cb#frag" },
    { client_id: H.TEST_APP, redirect_uri: "" },
  ];
  for (const p of bad) {
    const r = await H.authorize(u.client, { url: H.authorizeQuery({ clientId: p.client_id, redirectUri: p.redirect_uri, challenge }) });
    assert.equal(r.status, 400, `client=${p.client_id} uri=${p.redirect_uri} 应 400，实际 ${r.status}`);
    assert.equal(r.res.status === 303, false, "不得 303 跳转到未验证的地址");
    assert.ok((await r.res.text()).includes("无法处理这个登录请求"), "应渲染中文错误页");
  }
  // 未带全参数也是 400
  assert.equal((await u.client.get("/authorize")).status, 400);
  assert.equal((await u.client.get(`/authorize?client_id=${H.TEST_APP}`)).status, 400);
});

test("response_type 与 scope 校验：错误以 303 跳回 RP 并带 error", async () => {
  const bc = await H.startBackchannel();
  try {
    H.setAppEndpoints({ origin: bc.origin });
    const u = await freshUser("param");
    const { challenge } = H.pkce();
    const redirectUri = `${bc.origin}/cb`;
    const cases = [
      [{ response_type: "token" }, "unsupported_response_type"],
      [{ scope: "profile openid" }, null],
      [{ scope: "profile" }, "invalid_scope"],
      [{ scope: "openid unknown_scope" }, "invalid_scope"],
    ];
    for (const [override, expected] of cases) {
      // 覆盖项必须走 extra：authorizeQuery 里固定字段写在 extra 之前，extra 才能逐字覆盖
      const r = await H.authorize(u.client, { url: H.authorizeQuery({ clientId: H.TEST_APP, redirectUri, challenge, extra: override }) });
      if (expected === null) {
        assert.equal(r.code !== null, true, "scope 含 openid 且顺序不同也应放行");
        continue;
      }
      assert.equal(r.status, 303);
      assert.equal(r.error, expected, `override=${JSON.stringify(override)} 应 ${expected}，实际 ${r.error}`);
      assert.equal(r.code, null);
      assert.equal(loc(r.res).origin, bc.origin, "错误也应跳回已注册回调");
    }
  } finally {
    await bc.close();
  }
});

test("refresh 轮换：旧 token 重用时吊销整个轮换族（家庭级失效）", async () => {
  const bc = await H.startBackchannel();
  try {
    H.setAppEndpoints({ origin: bc.origin });
    const u = await freshUser("rotate");
    const { verifier, challenge } = H.pkce();
    const redirectUri = `${bc.origin}/cb`;
    const a = await H.authorize(u.client, { clientId: H.TEST_APP, redirectUri, verifier, challenge });
    const t1 = await H.exchangeCode({ code: a.code, redirectUri, verifier });
    assert.equal(t1.status, 200);

    const t2 = await H.refreshToken({ token: t1.json.refresh_token });
    assert.equal(t2.status, 200, `第一次刷新应成功：${t2.body}`);
    assert.notEqual(t2.json.refresh_token, t1.json.refresh_token, "刷新必须轮换 refresh token");

    // 旧 refresh 再次使用 → 判定重用，吊销整族（含刚拿到的 t2）
    const reuse = await H.refreshToken({ token: t1.json.refresh_token });
    assert.equal(reuse.status, 400, "已轮换的 refresh 再用必须失败");
    assert.equal(reuse.json.error, "invalid_grant");
    assert.match(reuse.json.error_description, /已轮换|无效/);

    const after = await H.refreshToken({ token: t2.json.refresh_token });
    assert.equal(after.status, 400, "重用检测应连带吊销同族的新 refresh");
    assert.ok(
      H.sql(`SELECT revoked_at FROM oidc_refresh WHERE session_hash = '${H.sessionHashOf(u.client)}';`).every((r) => r.revoked_at),
      "同族 refresh 应全部标记吊销",
    );
  } finally {
    await bc.close();
  }
});

test("userinfo 鉴权：无 token / 垃圾 token / 非 Bearer 一律 401 且带 WWW-Authenticate", async () => {
  const c = new Client(H.BASE);
  for (const headers of [{}, { authorization: "Bearer not-a-jwt" }, { authorization: "Basic abc" }, { authorization: "Bearer" }]) {
    const res = await c.get("/userinfo", { headers });
    assert.equal(res.status, 401, `headers=${JSON.stringify(headers)} 应 401`);
    assert.match(res.headers.get("www-authenticate") || "", /Bearer/);
    assert.equal((await res.json()).error, "invalid_token");
  }
});

test("/revoke（RFC 7009）：未知 client 401、无效 token 也回 200、有效 refresh 被吊销", async () => {
  const bc = await H.startBackchannel();
  try {
    H.setAppEndpoints({ origin: bc.origin });
    const u = await freshUser("revoke");
    const { verifier, challenge } = H.pkce();
    const redirectUri = `${bc.origin}/cb`;

    assert.equal((await H.revoke({ clientId: "no-such-client", token: "x" })).status, 401, "未知 client 应 401 invalid_client");

    const junk = await H.revoke({ token: "not-a-token" });
    assert.equal(junk.status, 200, "无效 token 也不得暴露存在性（回 200 空 body）");
    assert.equal(junk.body, "");

    const a = await H.authorize(u.client, { clientId: H.TEST_APP, redirectUri, verifier, challenge });
    const ex = await H.exchangeCode({ code: a.code, redirectUri, verifier });
    assert.equal(ex.status, 200);

    const rv = await H.revoke({ token: ex.json.refresh_token });
    assert.equal(rv.status, 200);
    const after = await H.refreshToken({ token: ex.json.refresh_token });
    assert.equal(after.status, 400, "被吊销的 refresh 不得再换 token");
  } finally {
    await bc.close();
  }
});

test("静默 SSO：未登录访问 /authorize 保留完整查询串，登录后可直接取到授权码", async () => {
  const bc = await H.startBackchannel();
  try {
    H.setAppEndpoints({ origin: bc.origin });
    const u = await freshUser("sso");
    const { verifier, challenge } = H.pkce();
    const redirectUri = `${bc.origin}/cb`;
    const authorizeUrl = H.authorizeQuery({ clientId: H.TEST_APP, redirectUri, verifier, challenge, state: "st-sso" });

    const anon = new Client(H.BASE);
    const a = await anon.get(authorizeUrl);
    assert.equal(a.status, 303);
    const l = loc(a);
    assert.equal(l.pathname, "/login");
    assert.equal(l.searchParams.get("next"), authorizeUrl, "next 应原样保留 state/nonce/challenge");

    // 登录时带上 next → 内联发码直跳 client 回调（省掉重走 /authorize 整跳）
    const r = await H.signIn(anon, u.name, PW, authorizeUrl);
    assert.equal(r.status, 303);
    const target = loc(r.res);
    assert.equal(target.origin, bc.origin, "登录后应直跳回调地址");
    assert.ok(target.searchParams.get("code"), "应直接拿到授权码");
    assert.equal(target.searchParams.get("state"), "st-sso");
    assert.equal(target.searchParams.get("iss"), ORIGIN, "应带 RFC 9207 iss");
  } finally {
    await bc.close();
  }
});

test("内联发码回退：next 的 redirect_uri 非法时回退老链路，由 /authorize 出标准错误", async () => {
  const u = await freshUser("inlinefb");
  const { challenge } = H.pkce();
  const bad = H.authorizeQuery({ clientId: H.TEST_APP, redirectUri: "https://evil.example/cb", challenge });
  const anon = new Client(H.BASE);
  const r = await H.signIn(anon, u.name, PW, bad);
  assert.equal(r.status, 303);
  const back = loc(r.res);
  assert.equal(back.pathname, "/authorize", "校验不过应回退 /authorize，不得直跳任意地址");
  assert.equal(back.search, new URL(bad, H.BASE).search);
  const err = await anon.get(back.pathname + back.search);
  assert.equal(err.status, 400, "非法回调地址应由 /authorize 渲染标准错误页");
});

test("prompt=none 静默探测：未登录回 login_required，不弹登录页", async () => {
  const bc = await H.startBackchannel();
  try {
    H.setAppEndpoints({ origin: bc.origin });
    const { verifier, challenge } = H.pkce();
    const redirectUri = `${bc.origin}/cb`;
    const anon = new Client(H.BASE);
    const a = await H.authorize(anon, { clientId: H.TEST_APP, redirectUri, verifier, challenge, state: "st-silent", extra: { prompt: "none" } });
    assert.equal(a.status, 303);
    assert.equal(a.error, "login_required", "未登录应回 login_required");
    assert.equal(a.code, null, "不得签发授权码");
    assert.equal(loc(a.res).origin, bc.origin, "应跳回 RP 回调而不是登录页");
    assert.equal(a.state, "st-silent", "state 应原样回传");
    assert.equal(loc(a.res).pathname, "/cb", "绝不能落 auth 登录页");
  } finally {
    await bc.close();
  }
});

test("prompt=none 已登录：照常静默发码", async () => {
  const bc = await H.startBackchannel();
  try {
    H.setAppEndpoints({ origin: bc.origin });
    const u = await freshUser("silentok");
    const { verifier, challenge } = H.pkce();
    const redirectUri = `${bc.origin}/cb`;
    const a = await H.authorize(u.client, { clientId: H.TEST_APP, redirectUri, verifier, challenge, extra: { prompt: "none" } });
    assert.equal(a.status, 303);
    assert.ok(a.code, "已登录 prompt=none 应照常静默签发授权码");
    assert.equal(a.error, null);
  } finally {
    await bc.close();
  }
});

test("prompt=none + must_change_pw：回 interaction_required，保持静默", async () => {
  const bc = await H.startBackchannel();
  try {
    H.setAppEndpoints({ origin: bc.origin });
    const u = await freshUser("silentchg");
    H.sqlExec(`UPDATE account SET must_change_pw = 1 WHERE name = '${u.name}';`);
    const { verifier, challenge } = H.pkce();
    const redirectUri = `${bc.origin}/cb`;
    const a = await H.authorize(u.client, { clientId: H.TEST_APP, redirectUri, verifier, challenge, extra: { prompt: "none" } });
    assert.equal(a.status, 303);
    assert.equal(a.error, "interaction_required", "改密门禁在静默探测下应回 interaction_required");
    assert.equal(a.code, null, "不得签发授权码");
    assert.equal(loc(a.res).origin, bc.origin, "应跳回 RP 回调而不是改密页");
  } finally {
    await bc.close();
  }
});
