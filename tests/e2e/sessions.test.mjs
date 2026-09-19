// 会话管理（增量 10，PRD P1-2）：自助列表、单个下线（含当前设备）、下线其他设备、
// 越权吊销拒绝、CSRF、审计同批入账、back-channel 联动在 RP 侧（本文件验 auth 侧行为）。
import { test } from "node:test";
import assert from "node:assert/strict";
import { Client } from "../lib/client.mjs";
import * as H from "../lib/harness.mjs";

const PW = "TestPass123";
const anon = () => new Client(H.BASE);
const loc = (res) => {
  const v = res.headers.get("location");
  assert.ok(v, "应当有 Location 头");
  return new URL(v, H.BASE);
};

/** 注册即登录的账号 + 独立 Client（新 IP 不污染限流桶） */
async function freshUser(prefix = "sess") {
  const client = new Client(H.BASE);
  const r = await H.register(client, { name: H.uniqueName(prefix) });
  assert.equal(r.status, 303, `注册应成功，实际 ${r.status}`);
  const accountId = H.sql(`SELECT id FROM account WHERE name = '${r.name}';`)[0].id;
  return { client, name: r.name, accountId };
}

const activeHashes = (accountId) => H.sql(`SELECT token_hash FROM session WHERE account_id = ${accountId} AND revoked_at IS NULL ORDER BY created_at;`).map((r) => r.token_hash);
const auditRows = (accountId) => H.sql(`SELECT event, detail FROM audit_log WHERE account_id = ${accountId} AND event = 'session.revoke';`);

test("匿名访问 /sessions 303 跳登录并带回跳路径", async () => {
  const r = await anon().get("/sessions");
  assert.equal(r.status, 303);
  assert.equal(loc(r).pathname, "/login");
  assert.equal(loc(r).searchParams.get("next"), "/sessions");
});

test("会话列表：注册即有 1 个当前会话；首页有会话管理入口", async () => {
  const u = await freshUser("list");
  const page = await u.client.text("/sessions");
  assert.equal(page.res.status, 200);
  assert.ok(page.body.includes("当前设备"), "应标记当前设备");
  assert.ok(page.body.includes("本机"), "当前设备显示「本机」");
  assert.ok(!page.body.includes("下线其他设备"), "只有 1 个会话时不应出现批量下线按钮");
  assert.ok(!page.body.includes("/sessions/revoke"), "当前设备不给下线按钮");

  const home = await u.client.text("/");
  assert.ok(home.body.includes('href="/sessions"'), "我的账号页应有会话管理入口");
});

test("多设备：第二台登录后列表出现两条，批量下线按钮出现", async () => {
  const u = await freshUser("multi");
  const second = new Client(H.BASE);
  await H.signIn(second, u.name, PW);
  const page = await u.client.text("/sessions");
  const ownHash = H.sessionHashOf(u.client);
  const active = activeHashes(u.accountId);
  assert.equal(active.length, 2, "应有 2 个活跃会话");
  // 当前设备没有下线按钮，其哈希不出现在页面；其他设备的吊销表单应逐个出现
  for (const h of active.filter((h) => h !== ownHash)) {
    assert.ok(page.body.includes(h), "列表应含其他设备的吊销标识");
  }
  assert.ok(!page.body.includes(ownHash), "当前会话哈希不应出现在页面");
  assert.ok(page.body.includes("下线其他设备"), "多会话时应出现批量下线按钮");
});

test("单个下线：吊销指定会话 + 审计 self:true + 被踢设备要求重登；越权吊销别人会话 404 且零写入", async () => {
  const u = await freshUser("kick");
  const victim = new Client(H.BASE);
  await H.signIn(victim, u.name, PW);
  const victimHash = H.sessionHashOf(victim);
  assert.ok(activeHashes(u.accountId).includes(victimHash));

  const csrf = await u.client.csrf("/sessions");
  const res = await u.client.postForm("/sessions/revoke", { csrf, session: victimHash }, { retry: false });
  assert.equal(res.status, 200);
  assert.ok((await res.text()).includes("该设备已下线"), "POST 响应应提示下线成功");
  assert.ok(!activeHashes(u.accountId).includes(victimHash), "目标会话应已吊销");

  // 被踢设备下一次带旧 cookie 的请求立即失效
  const kicked = await victim.get("/");
  assert.equal(kicked.status, 303, "被踢设备应被要求重新登录");
  assert.equal(loc(kicked).pathname, "/login");

  // 审计：吊销与审计同批（这里只验入账与内容）
  const audits = auditRows(u.accountId);
  const row = audits.find((r) => JSON.parse(r.detail ?? "{}").sid === victimHash.slice(0, 12));
  assert.ok(row, "应有 session.revoke 审计");
  const detail = JSON.parse(row.detail);
  assert.equal(detail.self, true, "自助下线应标记 self");
  assert.equal(detail.scope, "one");

  // 越权：吊销不属于自己账号的会话 → 404，目标会话不受影响，且不留审计
  const stranger = await freshUser("stranger");
  const strangerHash = H.sessionHashOf(stranger.client);
  const before = auditRows(u.accountId).length;
  const forged = await u.client.postForm("/sessions/revoke", { csrf, session: strangerHash }, { retry: false });
  assert.equal(forged.status, 404, "别人的会话不可吊销");
  assert.ok(activeHashes(stranger.accountId).includes(strangerHash), "目标会话不受影响");
  assert.equal(auditRows(u.accountId).length, before, "无效动作不入账");

  // 重复吊销已结束的会话：同样 404 不入账
  const repeat = await u.client.postForm("/sessions/revoke", { csrf, session: victimHash }, { retry: false });
  assert.equal(repeat.status, 404, "已吊销的会话再吊销应 404");
});

test("下线当前设备：303 送回登录页，cookie 失效", async () => {
  const u = await freshUser("self");
  // 页面只在「其他设备」的表单里带 csrf，先加一台设备才有表单可取
  const spare = new Client(H.BASE);
  await H.signIn(spare, u.name, PW);
  const ownHash = H.sessionHashOf(u.client);
  const csrf = await u.client.csrf("/sessions");
  const res = await u.client.postForm("/sessions/revoke", { csrf, session: ownHash }, { retry: false });
  assert.equal(res.status, 303, "下线当前设备应送回登录页");
  assert.equal(loc(res).pathname, "/login");
  assert.ok(!activeHashes(u.accountId).includes(ownHash), "当前会话应已吊销");
  const after = await u.client.get("/sessions");
  assert.equal(after.status, 303, "会话已失效，再访问应跳登录");
});

test("下线其他设备：保留本机、其余全灭，审计 scope=others 带数量", async () => {
  const u = await freshUser("others");
  const devices = [u.client];
  for (let i = 0; i < 2; i++) {
    const d = new Client(H.BASE);
    await H.signIn(d, u.name, PW);
    devices.push(d);
  }
  assert.equal(activeHashes(u.accountId).length, 3);

  const ownHash = H.sessionHashOf(u.client);
  const csrf = await u.client.csrf("/sessions");
  const res = await u.client.postForm("/sessions/revoke-others", { csrf }, { retry: false });
  assert.equal(res.status, 200);
  assert.ok((await res.text()).includes("已下线 2 台设备"), "POST 响应应提示下线数量");

  const active = activeHashes(u.accountId);
  assert.deepEqual(active, [ownHash], "只剩当前设备");
  const me = await u.client.get("/sessions");
  assert.equal(me.status, 200, "当前设备不受影响");
  for (const d of devices.slice(1)) {
    assert.equal((await d.get("/")).status, 303, "其他设备应被踢");
  }
  const detail = JSON.parse(auditRows(u.accountId).at(-1).detail);
  assert.equal(detail.scope, "others");
  assert.equal(detail.count, 2);
  assert.equal(detail.self, true);
});

test("CSRF 防护：缺/错 token 的吊销请求 403", async () => {
  const u = await freshUser("csrf");
  const victim = new Client(H.BASE);
  await H.signIn(victim, u.name, PW);
  const hash = H.sessionHashOf(victim);
  const bad = await u.client.postForm("/sessions/revoke", { csrf: "wrong", session: hash }, { retry: false });
  assert.equal(bad.status, 403);
  assert.ok(activeHashes(u.accountId).includes(hash), "CSRF 不过不得写入");
  const bad2 = await u.client.postForm("/sessions/revoke-others", { csrf: "wrong" }, { retry: false });
  assert.equal(bad2.status, 403);
});
