// 管理机器端点（增量 8，PRD P1-1）：把管理能力落到 auth，修 tour 管理台的 6 处死写。
// 覆盖：机器门（无签/伪签/跨路径签名 401）、目录、列表（q + keyset 翻页 + 不带会话）、详情、
//   角色增删与审计、权限点额外授予（含 userinfo 当场生效与跨系统隔离）、重置密码（连带会话全吊销 +
//   must_change_pw + 临时密码真能登录）、解锁、停用/启用（登录被拒 + userinfo 清空角色权限 + 踢下线）、
//   强制下线（单会话 / 整账号 / 不存在 404）、组织设置读写、注册码创建与列表（码必须真能注册）。
// 未配 BIND_SECRET 时整文件跳过（与 run.mjs 的读法一致：.dev.vars → 环境变量）。
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { Client } from "../lib/client.mjs";
import * as H from "../lib/harness.mjs";

const BIND_SECRET = process.env.BIND_SECRET || "";
const SKIP = BIND_SECRET ? false : "未配 BIND_SECRET，管理机器端点测试跳过";
const PW = "TestPass123";
const CODE_ALPHABET = /^[ABCDEFGHJKMNPQRSTUVWXYZ23456789]+$/;
// 测试 RP 的固定回调（不做真实回跳，只读 Location 里的 code）
const RP_BASE = "http://127.0.0.1:1";
const RP_CB = `${RP_BASE}/cb`;

const Q = (s) => `'${String(s).replace(/'/g, "''")}'`;
const nowIso = () => new Date().toISOString();
const countOf = (sql) => H.sql(sql)[0].n;

function sign(path, raw, ts) {
  return createHmac("sha256", BIND_SECRET).update(`POST|${path}|${ts}|${raw}`).digest("hex");
}

// raw 传字符串可构造非法 JSON；不传 body 走空串（签名对空串同样成立，读类端点允许无 body）
async function adminPost(c, path, body, { badSign = false, raw, signedPath } = {}) {
  const text = raw ?? (body === undefined ? "" : JSON.stringify(body));
  const ts = Math.floor(Date.now() / 1000);
  return c.raw(path, {
    method: "POST",
    retry: false,
    headers: {
      "content-type": "application/json",
      "x-timestamp": String(ts),
      "x-sign": badSign ? "deadbeef" : sign(signedPath ?? path, text, ts),
    },
    body: text,
  });
}

async function admin(c, path, body, opts) {
  const res = await adminPost(c, path, body, opts);
  let json = null;
  try {
    json = await res.json();
  } catch {
    /* 非 JSON */
  }
  return { res, status: res.status, json };
}

// 每个用例独立 Client（随机 IP）：机器桶 300/15min 互不干扰
const machineClient = () => new Client(H.BASE);

// 首个注册账号按设计会成为全局 superadmin（src/routes/pages.ts「首个用户 = superadmin」），
// 会让本文件第一个 freshUser 拿到超管身份、把后面所有「超管受保护」的断言搅乱。
// 先在库里放一个哑账号占住「首个」，此后所有注册用户就都是普通的 tour.coach + club.coach；
// 需要超管目标的用例直接用它（它没有 credential，登不进来，只作被操作对象）。
let rootCache;
function rootId() {
  if (rootCache === undefined) {    H.sqlExec(
      `INSERT OR IGNORE INTO account (name, email, locked, must_change_pw, created_at)
       VALUES ('e2e-root', NULL, 0, 0, ${Q(nowIso())});`,
    );
    H.sqlExec(
      `INSERT OR IGNORE INTO user_role (account_id, role_id, granted_by, granted_at)
       SELECT a.id, (SELECT id FROM role WHERE app_id IS NULL AND key = 'superadmin'), NULL, ${Q(nowIso())}
         FROM account a WHERE a.name = 'e2e-root';`,
    );
    rootCache = H.sql("SELECT id FROM account WHERE name = 'e2e-root';")[0].id;
  }
  return rootCache;
}

// 必须在任何注册发生之前执行：一旦第一个 freshUser 先注册成功，它就会成为 superadmin。
rootId();

function accountIdOf(name) {
  const rows = H.sql(`SELECT id FROM account WHERE name = ${Q(name)};`);
  assert.equal(rows.length, 1, `应能查到账号 ${name}`);
  return rows[0].id;
}

async function freshUser(prefix) {
  const client = new Client(H.BASE);
  const r = await H.register(client, { name: H.uniqueName(prefix) });
  assert.equal(r.status, 303, `注册应成功，实际 ${r.status}`);
  return { client, name: r.name, id: accountIdOf(r.name) };
}

// 注册即登录（POST /register 直接建会话），所以这里不能再走 H.signIn：
// 已登录的 client GET /login 会 303 回首页，页面里没有 csrf 隐藏域，H.signIn 会抛。
// 需要「全新客户端登录」的用例自己 new Client 再 H.signIn。
async function signedInUser(prefix) {
  const u = await freshUser(prefix);
  const sessionHash = H.sessionHashOf(u.client);
  assert.ok(sessionHash, "注册应已建立会话");
  return { ...u, sessionHash };
}

// 走一遍 OIDC 拿 access token（不依赖别的测试文件是否改过 test-rp 的回调地址）
function pinRpEndpoints() {
  H.setAppEndpoints({ origin: RP_BASE });
}

async function accessTokenOfAs(user, clientId) {
  const { verifier, challenge } = H.pkce();
  const a = await H.authorize(user.client, { clientId, redirectUri: RP_CB, verifier, challenge });
  assert.ok(a.code, `授权应回码，实际跳 ${a.location}`);
  const ex = await H.exchangeCode({ clientId, code: a.code, redirectUri: RP_CB, verifier });
  assert.equal(ex.status, 200, `换码应成功：${ex.body}`);
  return ex.json;
}

const accessTokenOf = (user) => accessTokenOfAs(user, H.TEST_APP);

/** 临时把某个真实 client（tour/guess/club）的回调地址指到本地假 RP，用完必须还原——别的测试文件依赖种子里的生产地址。 */
async function useRealAppEndpoints(clientId, body) {
  const row = H.sql(
    `SELECT redirect_uris, backchannel_logout_uri, post_logout_redirect_uris FROM app WHERE client_id = ${Q(clientId)};`,
  )[0];
  assert.ok(row, `种子应有 ${clientId} 应用`);
  const raw = (v) => (v === null || v === undefined ? "NULL" : Q(v));
  H.setAppEndpoints({ clientId, origin: RP_BASE });
  try {
    return await body();
  } finally {
    H.sqlExec(
      `UPDATE app SET redirect_uris = ${raw(row.redirect_uris)},
         backchannel_logout_uri = ${raw(row.backchannel_logout_uri)},
         post_logout_redirect_uris = ${raw(row.post_logout_redirect_uris)}
       WHERE client_id = ${Q(clientId)};`,
    );
  }
}

test("机器门：无签名 / 伪签名 / 跨路径签名一律 401，非法 JSON 400", { skip: SKIP }, async () => {
  const c = machineClient();
  const bare = await c.raw("/api/admin/catalog", { method: "POST", retry: false, body: "{}" });
  assert.equal(bare.status, 401, "无签名应 401");
  assert.equal((await bare.json()).error, "bad sign");

  const forged = await adminPost(c, "/api/admin/catalog", {}, { badSign: true });
  assert.equal(forged.status, 401, "伪签名应 401");

  // 把 A 端点的合法签名贴到 B 端点上：canonical 串含 path，必须验不过
  const crossed = await adminPost(c, "/api/admin/accounts/list", {}, { signedPath: "/api/admin/catalog" });
  assert.equal(crossed.status, 401, "跨路径签名应 401");

  const badJson = await admin(c, "/api/admin/catalog", undefined, { raw: "{不是 JSON" });
  assert.equal(badJson.status, 400, "非法 JSON 应 400");
  assert.equal(badJson.json.error, "bad body");
});

test("目录：3 个接入系统、7 个角色、16 个权限点（0010 删除死点 tour.team.bindcode.issue）", { skip: SKIP }, async () => {
  const { status, json } = await admin(machineClient(), "/api/admin/catalog", {});
  assert.equal(status, 200);
  const clients = json.apps.map((a) => a.client_id);
  for (const id of ["tour", "guess", "club"]) assert.ok(clients.includes(id), `目录应有 ${id}`);

  assert.equal(json.roles.length, 7, `角色应 7 个（1 全局 + tour/guess/club 各 2），实际 ${json.roles.length}`);
  assert.equal(json.permissions.length, 16, `权限点应 16 个，实际 ${json.permissions.length}`);
  assert.ok(
    !json.permissions.some((p) => p.key === "tour.team.bindcode.issue"),
    "死权限点 tour.team.bindcode.issue 应已被 0010 删除",
  );

  const superRole = json.roles.find((r) => r.app_id === null && r.key === "superadmin");
  assert.ok(superRole, "应有全局超管角色");
  assert.equal(superRole.name, "超级管理员", "角色应带中文展示名");
  assert.ok(
    json.permissions.every((p) => p.app_id && /^[a-z]+\./.test(p.key) && typeof p.description === "string"),
    "权限点应是「app 归属 + 全键名 + 中文说明」（key 本身已带前缀，界面直接用 key 当标识）",
  );

  // 角色→权限点映射：界面据它算「角色带来的权限」与「额外授予」的并集，不能为空
  const superPermIds = json.role_permissions.filter((rp) => rp.role_id === superRole.id);
  assert.equal(superPermIds.length, 16, "全局超管经 CROSS JOIN 应持全部 16 个权限点");
  assert.ok(
    json.role_permissions.some((rp) => rp.role_id !== superRole.id),
    "非全局角色也应有权限点映射（tour.recorder / club.admin 等）",
  );
});

test("账号列表：一次请求带出角色、q 过滤、keyset 翻页，且不含会话", { skip: SKIP }, async () => {
  const c = machineClient();
  const u = await freshUser("alist");
  const { json } = await admin(c, "/api/admin/accounts/list", { q: u.name });
  assert.equal(json.accounts.length, 1, `q 过滤应只剩目标账号：${JSON.stringify(json.accounts.map((a) => a.name))}`);
  const row = json.accounts[0];
  assert.equal(row.id, u.id);
  assert.equal(row.disabled, false);
  assert.equal(row.is_super, false);
  assert.deepEqual(row.roles.map((r) => r.key).sort(), ["club.coach", "tour.coach"], "角色键应带 app 前缀");
  assert.ok(row.roles.every((r) => typeof r.name === "string" && r.name.length), "角色应带中文名供界面直接渲染");
  assert.ok(!("sessions" in row), "列表不得携带会话（性能约定：只有详情才查会话）");
  assert.equal(row.team_id, null, "未绑队账号应回 null（球队随列表 LEFT JOIN 带出，便于 tour 管理台省一次全表扫）");
  assert.equal(row.team_name, null);

  // keyset 翻页：limit=1 时 next_after 指向本页最后一行，下一页必须换人
  const page1 = await admin(c, "/api/admin/accounts/list", { limit: 1 });
  assert.equal(page1.json.accounts.length, 1);
  assert.equal(page1.json.next_after, page1.json.accounts[0].id);
  const page2 = await admin(c, "/api/admin/accounts/list", { limit: 1, after: page1.json.next_after });
  assert.notEqual(page2.json.accounts[0].id, page1.json.accounts[0].id, "第二页应换人");
  assert.ok(page2.json.accounts[0].id > page1.json.accounts[0].id, "keyset 应严格递增");

  // 空请求体按 {} 处理（读类端点没有 body 也合法）
  const empty = await admin(c, "/api/admin/accounts/list");
  assert.equal(empty.status, 200, "空请求体应被接受");
});

test("账号详情：一次请求返回账号 / 角色 / 授予 / 活跃会话（带 IP）/ QQ", { skip: SKIP }, async () => {
  const c = machineClient();
  const u = await signedInUser("adet");
  const s = await admin(c, "/api/admin/accounts/detail", { account_id: u.id });
  assert.equal(s.status, 200, JSON.stringify(s.json));
  assert.equal(s.json.account.id, u.id);
  assert.equal(s.json.account.is_super, false);
  assert.equal(s.json.account.disabled, false);
  assert.equal(s.json.account.disabled_at, null);
  assert.deepEqual(s.json.roles.map((r) => r.key).sort(), ["club.coach", "tour.coach"]);
  assert.deepEqual(s.json.grants, [], "未额外授予时应为空数组");
  assert.equal(s.json.qq, null);

  const sess = s.json.sessions.find((x) => x.session_hash === u.sessionHash);
  assert.ok(sess, "详情应列出刚登录的活跃会话");
  assert.ok(sess.created_at && sess.expires_at, "会话应带创建/过期时间");
  assert.equal(sess.ip, u.client.ip, "createSession 应记下 CF-Connecting-IP");

  const missing = await admin(c, "/api/admin/accounts/detail", { account_id: 99999999 });
  assert.equal(missing.status, 404);
  assert.equal(missing.json.error, "account_not_found");
});

test("角色授权：差集写入 + role.grant/revoke 审计含操作者 + 幂等零写 + 超管角色拒改", { skip: SKIP }, async () => {
  const c = machineClient();
  const actor = await freshUser("arole-actor");
  const target = await freshUser("arole");

  const grants0 = countOf("SELECT COUNT(*) AS n FROM audit_log WHERE event = 'role.grant';");
  const first = await admin(c, "/api/admin/accounts/roles", {
    account_id: target.id,
    actor_id: actor.id,
    roles: ["tour.coach", "club.coach", "guess.admin"],
  });
  assert.equal(first.status, 200, JSON.stringify(first.json));
  assert.deepEqual(first.json.granted, ["guess.admin"], "已持有的角色不应重复授予");
  assert.deepEqual(first.json.revoked, []);
  assert.equal(countOf("SELECT COUNT(*) AS n FROM audit_log WHERE event = 'role.grant';"), grants0 + 1, "应写一条 role.grant");
  const detail = JSON.parse(
    H.sql("SELECT detail FROM audit_log WHERE event = 'role.grant' ORDER BY id DESC LIMIT 1;")[0].detail,
  );
  assert.equal(detail.actor_id, actor.id, "审计应记下操作者");
  assert.equal(detail.role, "guess.admin");

  // 传全集 = 幂等：重复保存同一状态零写入、零审计（界面可以放心地反复保存）
  const same = await admin(c, "/api/admin/accounts/roles", {
    account_id: target.id,
    actor_id: actor.id,
    roles: ["tour.coach", "club.coach", "guess.admin"],
  });
  assert.equal(same.json.changed, false);
  assert.equal(countOf("SELECT COUNT(*) AS n FROM audit_log WHERE event = 'role.grant';"), grants0 + 1);

  const revoke = await admin(c, "/api/admin/accounts/roles", {
    account_id: target.id,
    actor_id: actor.id,
    roles: ["club.coach", "guess.admin"],
  });
  assert.deepEqual(revoke.json.revoked, ["tour.coach"]);
  assert.equal(H.sql(`SELECT COUNT(*) AS n FROM user_role WHERE account_id = ${target.id};`)[0].n, 2);

  const unknown = await admin(c, "/api/admin/accounts/roles", { account_id: target.id, actor_id: actor.id, roles: ["nope.nope"] });
  assert.equal(unknown.status, 400);
  assert.equal(unknown.json.error, "bad_role");

  const asSuper = await admin(c, "/api/admin/accounts/roles", {
    account_id: target.id,
    actor_id: actor.id,
    roles: ["superadmin"],
  });
  assert.equal(asSuper.status, 403, "授予全局超管必须被拒");
  assert.equal(asSuper.json.error, "superadmin_locked");

  const stripSuper = await admin(c, "/api/admin/accounts/roles", { account_id: rootId(), actor_id: actor.id, roles: [] });
  assert.equal(stripSuper.status, 403, "回收全局超管同样必须被拒");
  assert.equal(stripSuper.json.error, "superadmin_locked");
});

test("权限点额外授予：只加不减、当场进 userinfo、且不跨系统泄漏", { skip: SKIP }, async () => {
  const c = machineClient();
  const actor = await freshUser("aperm-actor");
  const u = await signedInUser("aperm");

  // 角色/权限点按 token 的 aud 过滤，所以这里必须用真实 client「tour」取 token，
  // 而不是种子之外的 test-rp（aud=test-rp 下 tour 角色会被过滤掉，测不出东西）。
  await useRealAppEndpoints("tour", async () => {
    // 角色派生：tour.coach 应当带出 tour 的那几个权限点
    const before = await H.userinfo((await accessTokenOfAs(u, "tour")).access_token);
    assert.equal(before.status, 200);
    assert.deepEqual(before.json.roles, ["tour.coach"], "aud=tour 只应看到 tour 的 coach 角色");
    const roleDerived = [...before.json.permissions];
    assert.ok(roleDerived.length > 0, "tour.coach 应有角色派生权限点");

    // 额外授予两个：一个 tour 的（应生效）、一个 guess 的（aud=tour 下必须不可见）
    const grant = await admin(c, "/api/admin/accounts/grants", {
      account_id: u.id,
      actor_id: actor.id,
      permissions: ["tour.org.settings", "guess.recon.view"],
    });
    assert.equal(grant.status, 200, JSON.stringify(grant.json));
    assert.deepEqual(grant.json.granted.sort(), ["guess.recon.view", "tour.org.settings"]);
    assert.equal(H.sql(`SELECT COUNT(*) AS n FROM account_permission WHERE account_id = ${u.id};`)[0].n, 2);

    const after = await H.userinfo((await accessTokenOfAs(u, "tour")).access_token);
    assert.ok(after.json.permissions.includes("tour.org.settings"), `额外授予应立刻生效：${after.json.permissions}`);
    assert.ok(!after.json.permissions.includes("guess.recon.view"), "aud=tour 下不得泄漏 guess 的权限点");
    assert.deepEqual([...after.json.permissions].sort(), [...roleDerived, "tour.org.settings"].sort(), "只多不少");

    // 「只加不减」：取消勾选只删本表行——角色带来的权限点删不掉
    const revoke = await admin(c, "/api/admin/accounts/grants", { account_id: u.id, actor_id: actor.id, permissions: [] });
    assert.deepEqual(revoke.json.revoked.sort(), ["guess.recon.view", "tour.org.settings"]);
    const back = await H.userinfo((await accessTokenOfAs(u, "tour")).access_token);
    assert.deepEqual([...back.json.permissions].sort(), [...roleDerived].sort(), "角色派生权限点不受影响");
  });

  const nonExistent = await admin(c, "/api/admin/accounts/grants", {
    account_id: u.id,
    actor_id: actor.id,
    permissions: ["tour.not.a.perm"],
  });
  assert.equal(nonExistent.status, 400);
  assert.equal(nonExistent.json.error, "bad_permission");
});

test("重置密码：临时密码真能登录 + must_change_pw + 该账号全部会话当场失效", { skip: SKIP }, async () => {
  const c = machineClient();
  const actor = await freshUser("apw-actor");
  const u = await signedInUser("apw");

  const { status, json } = await admin(c, "/api/admin/accounts/password", { account_id: u.id, actor_id: actor.id });
  assert.equal(status, 200, JSON.stringify(json));
  assert.match(json.temp_password, /^[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{6}-[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{6}$/, "临时密码应用无歧义字母表");
  assert.equal(json.sessions_revoked, 1, "密码重置必须连带吊销全部会话");

  assert.ok(H.sql(`SELECT revoked_at FROM session WHERE token_hash = ${Q(u.sessionHash)};`)[0].revoked_at, "会话应被吊销");
  assert.equal(H.sql(`SELECT must_change_pw FROM account WHERE id = ${u.id};`)[0].must_change_pw, 1, "应置 must_change_pw");
  assert.equal((await u.client.get("/")).status, 303, "旧会话应立刻失去访问权");

  // 旧密码登不进；临时密码能登进，且被强制去改密
  const c2 = new Client(H.BASE);
  const old = await H.signIn(c2, u.name, PW);
  assert.equal(old.status, 401, "旧密码应失效");
  const temp = await H.signIn(c2, u.name, json.temp_password);
  assert.equal(temp.status, 303, "临时密码应能登录");
  assert.ok(String(temp.location).includes("/password"), `应被要求改密，实际跳 ${temp.location}`);

  const events = H.sql(`SELECT event FROM audit_log WHERE account_id = ${u.id} ORDER BY id;`).map((r) => r.event);
  assert.ok(events.includes("pw.reset"), `应有 pw.reset 审计：${events.join()}`);
  assert.ok(events.includes("session.revoke"), `应有 session.revoke 审计：${events.join()}`);

  const asSuper = await admin(c, "/api/admin/accounts/password", { account_id: rootId(), actor_id: actor.id });
  assert.equal(asSuper.status, 403, "超管密码不得在管理台重置");
  assert.equal(asSuper.json.error, "superadmin_locked");
});

test("解锁观众号：locked 1→0 记审计，重复调用零写入", { skip: SKIP }, async () => {
  const c = machineClient();
  const actor = await freshUser("aunlock-actor");
  const u = await freshUser("aunlock");
  H.sqlExec(`UPDATE account SET locked = 1 WHERE id = ${u.id};`);

  const first = await admin(c, "/api/admin/accounts/unlock", { account_id: u.id, actor_id: actor.id });
  assert.equal(first.json.changed, true);
  assert.equal(H.sql(`SELECT locked FROM account WHERE id = ${u.id};`)[0].locked, 0, "应解锁");

  const n = countOf("SELECT COUNT(*) AS n FROM audit_log WHERE event = 'account.unlock';");
  const again = await admin(c, "/api/admin/accounts/unlock", { account_id: u.id, actor_id: actor.id });
  assert.deepEqual(again.json, { ok: true, changed: false });
  assert.equal(countOf("SELECT COUNT(*) AS n FROM audit_log WHERE event = 'account.unlock';"), n, "无变化不写审计");
});

test("停用：踢下线 + 登录被拒 + userinfo 当场清空角色权限；启用后恢复", { skip: SKIP }, async () => {
  pinRpEndpoints();
  const c = machineClient();
  const actor = await freshUser("adisable-actor");
  const u = await signedInUser("adisable");
  const tokens = await accessTokenOf(u);

  const off = await admin(c, "/api/admin/accounts/disable", { account_id: u.id, actor_id: actor.id, disabled: true });
  assert.equal(off.status, 200, JSON.stringify(off.json));
  assert.ok(off.json.sessions_revoked >= 1, "停用应连带吊销全部会话");
  assert.ok(H.sql(`SELECT disabled_at FROM account WHERE id = ${u.id};`)[0].disabled_at, "应写 disabled_at");
  assert.equal(H.sql(`SELECT locked FROM account WHERE id = ${u.id};`)[0].locked, 0, "停用不得动 locked（观众号语义）");
  assert.equal((await u.client.get("/")).status, 303, "会话应立刻失效");

  // 密码正确也登不进；且不该泄漏「该昵称被停用」之外的信息
  const c2 = new Client(H.BASE);
  const denied = await H.signIn(c2, u.name, PW);
  assert.equal(denied.status, 401, "停用账号即使密码正确也必须拒登");

  // 停用前签发的 access token 还在有效期内：userinfo 必须当场降权
  const ui = await H.userinfo(tokens.access_token);
  assert.equal(ui.status, 200);
  assert.equal(ui.json.disabled, true);
  assert.deepEqual(ui.json.roles, [], "停用后不得再下发角色");
  assert.deepEqual(ui.json.permissions, [], "停用后不得再下发权限点");
  // refresh 也必须断（否则 RP 能靠刷新续命）
  const rf = await H.refreshToken({ token: tokens.refresh_token });
  assert.equal(rf.status, 400, `停用后 refresh 应失败：${rf.body}`);
  assert.equal(rf.json.error, "invalid_grant");

  const on = await admin(c, "/api/admin/accounts/disable", { account_id: u.id, actor_id: actor.id, disabled: false });
  assert.equal(on.json.changed, true);
  assert.equal(H.sql(`SELECT disabled_at FROM account WHERE id = ${u.id};`)[0].disabled_at, null, "应恢复");
  const c3 = new Client(H.BASE);
  assert.equal((await H.signIn(c3, u.name, PW)).status, 303, "启用后应能重新登录");

  const asSuper = await admin(c, "/api/admin/accounts/disable", { account_id: rootId(), actor_id: actor.id, disabled: true });
  assert.equal(asSuper.status, 403, "超管账号不得被停用");
  assert.equal(asSuper.json.error, "superadmin_locked");
});

test("强制下线：单会话定向吊销 / 整账号吊销 / 不存在的会话 404", { skip: SKIP }, async () => {
  const c = machineClient();
  const actor = await freshUser("akick-actor");
  const u = await signedInUser("akick");
  const u2 = new Client(H.BASE);
  assert.equal((await H.signIn(u2, u.name, PW)).status, 303, "第二处登录应成功");
  const secondHash = H.sessionHashOf(u2);
  assert.notEqual(secondHash, u.sessionHash);

  // 定向踢第二处：第一处必须活着
  const one = await admin(c, "/api/admin/sessions/revoke", { account_id: u.id, actor_id: actor.id, session_hash: secondHash });
  assert.equal(one.status, 200, JSON.stringify(one.json));
  assert.equal(one.json.revoked, 1);
  assert.equal((await u2.get("/")).status, 303, "被踢的会话应失效");
  assert.equal((await u.client.get("/")).status, 200, "未被踢的会话应照常可用");

  const ghost = await admin(c, "/api/admin/sessions/revoke", {
    account_id: u.id,
    actor_id: actor.id,
    session_hash: "0".repeat(64),
  });
  assert.equal(ghost.status, 404);
  assert.equal(ghost.json.error, "session_not_found");

  // 整账号：不给 session_hash
  const all = await admin(c, "/api/admin/sessions/revoke", { account_id: u.id, actor_id: actor.id });
  assert.equal(all.json.revoked, 1, "应吊销剩下那一处");
  assert.equal((await u.client.get("/")).status, 303, "整账号吊销后应全部失效");
  assert.ok(
    H.sql(`SELECT COUNT(*) AS n FROM audit_log WHERE event = 'session.revoke' AND account_id = ${u.id};`)[0].n >= 2,
    "两处吊销各应留一条 session.revoke 审计",
  );
});

test("开放注册开关：读 / 写 / 读回，写动作留 org.open_reg 审计", { skip: SKIP }, async () => {
  const c = machineClient();
  const initial = (await admin(c, "/api/admin/org-settings", {})).json;
  assert.equal(typeof initial.allow_open_reg, "boolean", "读应返回布尔");
  assert.equal((await admin(c, "/api/admin/org-settings")).json.allow_open_reg, initial.allow_open_reg, "无 body 也是读");

  const written = await admin(c, "/api/admin/org-settings", { allow_open_reg: !initial.allow_open_reg });
  assert.equal(written.status, 200);
  assert.equal(written.json.allow_open_reg, !initial.allow_open_reg);
  assert.equal((await admin(c, "/api/admin/org-settings", {})).json.allow_open_reg, !initial.allow_open_reg, "读回应一致");
  assert.ok(countOf("SELECT COUNT(*) AS n FROM audit_log WHERE event = 'org.open_reg';") >= 1, "应留审计");

  // 复位：register.test.mjs 会依赖开放注册的初始值
  await admin(c, "/api/admin/org-settings", { allow_open_reg: initial.allow_open_reg });
  assert.equal((await admin(c, "/api/admin/org-settings", {})).json.allow_open_reg, initial.allow_open_reg);
});

test("注册码：管理台生成的码必须真能注册（死写回归），列表只给不可逆指纹", { skip: SKIP }, async () => {
  const c = machineClient();
  const created = await admin(c, "/api/admin/signup-codes/create", { max_uses: 1, expires_in_hours: 24 });
  assert.equal(created.status, 201, JSON.stringify(created.json));
  const code = created.json.code;
  assert.match(code, CODE_ALPHABET, "明码应用无歧义字母表");
  assert.equal(code.length, 8);
  assert.equal(created.json.max_uses, 1);
  assert.ok(created.json.expires_at, "应带过期时间");

  // 真能注册（这条就是「tour 管理台生成的码一个都不可用」的回归）
  const client = new Client(H.BASE);
  const reg = await H.register(client, { code });
  assert.equal(reg.status, 303, `管理台生成的码应能注册，实际 ${reg.status}`);

  const list = await admin(c, "/api/admin/signup-codes/list", {});
  assert.equal(list.status, 200);
  const row = list.json.codes.find((x) => x.id === H.sha256Hex(code).slice(0, 12));
  assert.ok(row, `列表应回指纹行：${JSON.stringify(list.json.codes.slice(0, 3))}`);
  assert.equal(row.used_count, 1, "用过一次应计到一次");
  assert.equal(row.max_uses, 1);
  assert.ok(!JSON.stringify(list.json).includes(code), "列表绝不能回显明码");

  // 名额用尽即失效
  const again = await H.register(new Client(H.BASE), { code });
  assert.notEqual(again.status, 303, "max_uses=1 的码不应能二次使用");

  const audit = H.sql("SELECT detail FROM audit_log WHERE event = 'signup_code.create' ORDER BY id DESC LIMIT 1;")[0].detail;
  assert.ok(audit.includes(H.sha256Hex(code).slice(0, 12)), "审计应记指纹");
  assert.ok(!audit.includes(code), "审计绝不得记明码");
});

test("边界：不能对自己动手 / 缺参 400 / 未持有的角色键拒绝", { skip: SKIP }, async () => {
  const c = machineClient();
  const actor = await freshUser("aedge");
  const target = await freshUser("aedge-target");

  const self = await admin(c, "/api/admin/accounts/password", { account_id: actor.id, actor_id: actor.id });
  assert.equal(self.status, 403);
  assert.equal(self.json.error, "self_forbidden");

  const noId = await admin(c, "/api/admin/accounts/unlock", { actor_id: actor.id });
  assert.equal(noId.status, 400);
  assert.equal(noId.json.error, "bad body");

  const notArray = await admin(c, "/api/admin/accounts/roles", { account_id: target.id, actor_id: actor.id, roles: "tour.coach" });
  assert.equal(notArray.status, 400);
  assert.equal(notArray.json.error, "bad body");

  const missingAccount = await admin(c, "/api/admin/accounts/roles", { account_id: 99999999, actor_id: actor.id, roles: [] });
  assert.equal(missingAccount.status, 404);
  assert.equal(missingAccount.json.error, "account_not_found");
});

test("身份查询（增量 9B）：批量返回 qq 映射、未绑定不出现、去重；空名单/>100 拒 400；缺签 401", { skip: SKIP }, async () => {
  const c = machineClient();
  const u1 = await freshUser("lookup");
  const u2 = await freshUser("lookup");
  const u3 = await freshUser("lookup");
  const now = nowIso();
  H.sqlExec(
    `INSERT OR IGNORE INTO identity (account_id, provider, provider_uid, verified_at, bound_at)
     VALUES (${u1.id}, 'qq', 'qq-lookup-111', ${Q(now)}, ${Q(now)}), (${u2.id}, 'qq', 'qq-lookup-222', NULL, ${Q(now)});`,
  );

  const empty = await admin(c, "/api/admin/identity/lookup", { account_ids: [] });
  assert.equal(empty.status, 400);
  const many = await admin(c, "/api/admin/identity/lookup", { account_ids: Array.from({ length: 101 }, (_, i) => i + 1) });
  assert.equal(many.status, 400);

  const nosign = await c.raw("/api/admin/identity/lookup", {
    method: "POST",
    retry: false,
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ account_ids: [u1.id] }),
  });
  assert.equal(nosign.status, 401, "机器门先于业务逻辑（缺签 401）");

  // 重复 id 去重；不存在的账号（u3 / 999999999）静默不出现在结果里
  const ok = await admin(c, "/api/admin/identity/lookup", { account_ids: [u1.id, u2.id, u3.id, u3.id, 999999999] });
  assert.equal(ok.status, 200);
  assert.deepEqual(ok.json, {
    bindings: [
      { account_id: u1.id, qq_id: "qq-lookup-111", bound_at: now },
      { account_id: u2.id, qq_id: "qq-lookup-222", bound_at: now },
    ],
  });
});

test("审计查询（增量 10）：筛选 account/event/时间窗、id 倒序游标分页、limit 夹取、时间格式校验", { skip: SKIP }, async () => {
  const c = machineClient();
  const u = await freshUser("auditq");
  // 制造已知审计行：注册一条 + 登录失败两条（错密码），事件类型与账号都可预期
  const other = new Client(H.BASE);
  await H.signIn(other, u.name, "WrongPass999");
  await H.signIn(other, u.name, "WrongPass999");

  // 无筛选：id 倒序，最近的事件在最前。注意 login.fail 出于防账号枚举不带 account_id
  // （src/routes/pages.ts 验密失败路径只写 detail.name），account_id 筛选只会命中 register.ok
  const all = await admin(c, "/api/admin/audit/query", { account_id: u.id });
  assert.equal(all.status, 200);
  const events = all.json.events;
  assert.ok(events.length >= 1, "至少应有注册审计");
  assert.ok(events.every((e, i) => i === 0 || events[i - 1].id > e.id), "应按 id 倒序");
  assert.ok(events.some((e) => e.event === "register.ok"), "应含 register.ok");
  for (const e of events) assert.equal(e.account_id, u.id, "account_id 筛选应生效");

  // event 筛选：两条错密码的 login.fail 只能靠 detail.name 认领
  const fails = await admin(c, "/api/admin/audit/query", { event: "login.fail" });
  assert.ok(fails.json.events.length >= 2);
  assert.ok(fails.json.events.every((e) => e.event === "login.fail"), "event 筛选应生效");
  assert.equal(
    fails.json.events.filter((e) => e.detail?.name === u.name).length,
    2,
    "应恰 2 条本账号的 login.fail",
  );

  // 时间窗：since 取未来 1 小时 → 空；since 取过去 1 天 → 本账号 register.ok 命中
  const future = await admin(c, "/api/admin/audit/query", { account_id: u.id, since: new Date(Date.now() + 3600_000).toISOString() });
  assert.equal(future.json.events.length, 0, "未来时间窗应为空");
  const past = await admin(c, "/api/admin/audit/query", { account_id: u.id, since: new Date(Date.now() - 86_400_000).toISOString() });
  assert.ok(past.json.events.length >= 1, "过去 1 天时间窗应含注册审计");

  // 非法时间格式 400
  const badTime = await admin(c, "/api/admin/audit/query", { since: "不是时间" });
  assert.equal(badTime.status, 400);
  assert.equal(badTime.json.error, "bad_request");

  // 游标分页：limit=2，第二页用 next_cursor 续翻，直到取完（用全量账号不限定的流验证翻页语义）
  const p1 = await admin(c, "/api/admin/audit/query", { event: "login.fail", limit: 2 });
  assert.equal(p1.json.events.length, 2);
  assert.ok(p1.json.next_cursor, "还有更多应给 next_cursor");
  const p2 = await admin(c, "/api/admin/audit/query", { event: "login.fail", limit: 2, cursor: p1.json.next_cursor });
  assert.ok(p2.json.events.length >= 1);
  assert.ok(p2.json.events.every((e) => e.id < p1.json.next_cursor), "游标后的行应严格更旧");
  const allIds = [...p1.json.events, ...p2.json.events].map((e) => e.id);
  assert.equal(new Set(allIds).size, allIds.length, "翻页不应重复");

  // limit 夹取：>100 按 100、<1 按 1；不存在的 event 静默空集
  const big = await admin(c, "/api/admin/audit/query", { limit: 500 });
  assert.ok(big.json.events.length <= 100, "limit 应夹到 100");
  const tiny = await admin(c, "/api/admin/audit/query", { event: "login.fail", limit: 0 });
  assert.equal(tiny.json.events.length, 1, "limit=0 应夹到 1");
  const none = await admin(c, "/api/admin/audit/query", { event: "no.such.event" });
  assert.deepEqual(none.json.events, [], "不存在的 event 应空集");
  assert.equal(none.json.next_cursor, null, "空结果无下一页");
});
