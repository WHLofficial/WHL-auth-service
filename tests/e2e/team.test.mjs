// 球队绑定机器端点（增量 7）：发码→烧码→一次性/一账号一队/审计 → unbind/rebind →
// 负例（伪签/坏参/过期码）→ 目录 register upsert 与 link 俱乐部关联（club_taken）。
// HMAC 契约与 QQ 绑定通道一致（X-Sign = HMAC-SHA256(secret, "POST|path|ts|raw")）；
// 未配 BIND_SECRET 时整文件跳过（与 run.mjs 的读法一致：.dev.vars → 环境变量）。
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { Client } from "../lib/client.mjs";
import * as H from "../lib/harness.mjs";

const BIND_SECRET = process.env.BIND_SECRET || "";
const SKIP = BIND_SECRET ? false : "未配 BIND_SECRET，机器端点测试跳过";

function sign(path, raw, ts) {
  return createHmac("sha256", BIND_SECRET).update(`POST|${path}|${ts}|${raw}`).digest("hex");
}

// 每个用例独立 Client（随机 IP）→ 机器桶 300/15min 互不干扰
function machineClient() {
  return new Client(H.BASE);
}

async function machinePost(c, path, body, { tsOffsetSec = 0, badSign = false } = {}) {
  const raw = JSON.stringify(body);
  const ts = Math.floor(Date.now() / 1000) + tsOffsetSec;
  return c.raw(path, {
    method: "POST",
    retry: false,
    headers: {
      "content-type": "application/json",
      "x-timestamp": String(ts),
      "x-sign": badSign ? "deadbeef" : sign(path, raw, ts),
    },
    body: raw,
  });
}

function seedTeam(tourTeamId, name, clubId = null) {
  H.sqlExec(
    `INSERT INTO team (tour_team_id, club_id, name, created_at)
     VALUES (${tourTeamId}, ${clubId === null ? "NULL" : clubId}, '${name}', '${new Date().toISOString()}');`,
  );
  return H.sql(`SELECT id FROM team WHERE tour_team_id = ${tourTeamId};`)[0].id;
}

function seedCode(teamId, code, expiresAt) {
  H.sqlExec(
    `INSERT INTO team_bind_code (team_id, code_hash, via, expires_at, created_at)
     VALUES (${teamId}, '${H.sha256Hex(code)}', 'tour', ${expiresAt ? `'${expiresAt}'` : "NULL"}, '${new Date().toISOString()}');`,
  );
}

test("发码→烧码→一次性→一账号一队→审计全链", { skip: SKIP }, async () => {
  const teamId = seedTeam(5601, "绑定测试一队");
  const c = machineClient();
  const issue = await (await machinePost(c, "/api/team/bindcode", { tour_team_id: 5601, via: "tour" })).json();
  assert.equal(issue.ok, true, "发码应成功");
  assert.match(issue.code, /^[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{8}$/, "明码应为 8 位无歧义字母数字");
  assert.ok(issue.expires_at, "应带过期时间");

  const bindRes = await machinePost(c, "/api/team/bind", { code: issue.code, account_id: 7001, via: "tour" });
  const bindBody = await bindRes.json();
  assert.equal(bindRes.status, 200, `烧码应成功：${JSON.stringify(bindBody)}`);
  assert.equal(bindBody.teamId, teamId);

  // 码一次性：复用报 invalid_code
  const reuse = await machinePost(c, "/api/team/bind", { code: issue.code, account_id: 7002, via: "tour" });
  assert.equal((await reuse.json()).error, "invalid_code");
  // 一账号一队：已绑账号用新码再烧被拒，且新码不被烧（前置检查先于核销）
  const code2 = "MMMM2222";
  seedCode(teamId, code2, null);
  const again = await machinePost(c, "/api/team/bind", { code: code2, account_id: 7001, via: "club" });
  assert.equal((await again.json()).error, "already_bound");
  const still = H.sql(`SELECT used_by FROM team_bind_code WHERE code_hash = '${H.sha256Hex(code2)}';`)[0];
  assert.equal(still.used_by, null, "already_bound 前置拒绝不应烧码");

  const rows = H.sql(
    `SELECT bound_via, bound_at FROM team_binding WHERE account_id = 7001 AND team_id = ${teamId};`,
  );
  assert.equal(rows.length, 1, "应恰有一行绑定");
  assert.equal(rows[0].bound_via, "tour");
  const audits = H.sql(
    `SELECT event FROM audit_log WHERE event LIKE 'team.%' ORDER BY id ASC;`,
  ).map((r) => r.event);
  assert.ok(audits.includes("team.bindcode") && audits.includes("team.bind"), `审计应有 bindcode/bind：${audits.join()}`);
});

test("同码并发竞速：码已被他人烧掉时第二路零写入（invalid_code 且不产生绑定）", { skip: SKIP }, async () => {
  seedTeam(5602, "绑定测试二队");
  const c = machineClient();
  const issue = await (await machinePost(c, "/api/team/bindcode", { tour_team_id: 5602, via: "tour" })).json();
  assert.equal(issue.ok, true);
  // 模拟并发竞速：另一账号已抢先烧掉该码
  H.sqlExec(
    `UPDATE team_bind_code SET used_by = 7101, used_at = '${new Date().toISOString()}' WHERE code_hash = '${H.sha256Hex(issue.code)}';`,
  );
  const late = await machinePost(c, "/api/team/bind", { code: issue.code, account_id: 7102, via: "tour" });
  assert.equal((await late.json()).error, "invalid_code", "输掉竞速应报 invalid_code");
  assert.equal(H.sql(`SELECT COUNT(*) AS n FROM team_binding WHERE account_id = 7102;`)[0].n, 0, "不应产生绑定行");
  assert.equal(H.sql(`SELECT used_by FROM team_bind_code WHERE code_hash = '${H.sha256Hex(issue.code)}';`)[0].used_by, 7101, "码保持被先到者占用");
  assert.equal(H.sql(`SELECT COUNT(*) AS n FROM audit_log WHERE event = 'team.bind' AND account_id = 7102;`)[0].n, 0, "失败请求不留审计");
});

test("解绑→not_bound→重绑（via=club 也落到同一张表）", { skip: SKIP }, async () => {
  const c = machineClient();
  const no = await machinePost(c, "/api/team/unbind", { account_id: 7003 });
  assert.equal((await no.json()).error, "not_bound");

  const un = await machinePost(c, "/api/team/unbind", { account_id: 7001 });
  const unBody = await un.json();
  assert.equal(unBody.ok, true, `解绑应成功：${JSON.stringify(unBody)}`);

  // 解绑后可凭新码重绑；club 入口烧码同样写 team_binding（双入口同真源）
  const teamId = H.sql(`SELECT id FROM team WHERE tour_team_id = 5601;`)[0].id;
  const code3 = "QQQQ3333";
  seedCode(teamId, code3, null);
  const re = await machinePost(c, "/api/team/bind", { code: code3, account_id: 7001, via: "club" });
  assert.equal((await re.json()).ok, true, "解绑后重绑应成功");
  assert.equal(H.sql(`SELECT bound_via FROM team_binding WHERE account_id = 7001;`)[0].bound_via, "club");
});

test("负例：伪签 401、坏参 400、过期码 invalid_code", { skip: SKIP }, async () => {
  const c = machineClient();
  const fake = await machinePost(c, "/api/team/bind", { code: "AAAAAAAA", account_id: 7004, via: "tour" }, { badSign: true });
  assert.equal(fake.status, 401, "伪签应 401");

  const staleTs = await machinePost(c, "/api/team/bind", { code: "AAAAAAAA", account_id: 7004, via: "tour" }, { tsOffsetSec: -400 });
  assert.equal(staleTs.status, 401, "超时钟窗应 401");

  // /api/team/bind 坏参：缺 via、code 短、account_id 非法
  for (const body of [
    { code: "AAAAAAAA", account_id: 7004 },
    { code: "AAAA", account_id: 7004, via: "tour" },
    { code: "AAAAAAAA", account_id: 0, via: "tour" },
  ]) {
    const r = await machinePost(c, "/api/team/bind", body);
    assert.equal(r.status, 400, `bind 负例应 400：${JSON.stringify(body)}`);
  }
  // /api/team/bindcode 坏参：ttl 超界、via 缺、键没给
  for (const body of [
    { tour_team_id: 5601, via: "tour", ttl_hours: 0 },
    { tour_team_id: 5601 },
    { via: "tour" },
  ]) {
    const r = await machinePost(c, "/api/team/bindcode", body);
    assert.equal(r.status, 400, `bindcode 负例应 400：${JSON.stringify(body)}`);
  }

  const teamId = H.sql(`SELECT id FROM team WHERE tour_team_id = 5601;`)[0].id;
  const past = new Date(Date.now() - 1000).toISOString();
  seedCode(teamId, "EXPI0001", past);
  const expired = await machinePost(c, "/api/team/bind", { code: "EXPI0001", account_id: 7004, via: "tour" });
  assert.equal((await expired.json()).error, "invalid_code", "过期码应 invalid_code");
});

test("目录 register upsert 与 link 关联（club_taken 冲突）", { skip: SKIP }, async () => {
  const c = machineClient();
  seedTeam(5701, "目录队甲");

  // upsert：同名重登不改 club_id（未传时保留），改名生效
  const r1 = await machinePost(c, "/api/team/register", { tour_team_id: 5701, name: "目录队改名" });
  assert.equal((await r1.json()).ok, true);
  assert.equal(H.sql(`SELECT name FROM team WHERE tour_team_id = 5701;`)[0].name, "目录队改名");

  // 带 club_id 的 upsert 关联；link 把同一俱乐部挂到另一队 → club_taken
  const r2 = await machinePost(c, "/api/team/register", { tour_team_id: 5701, name: "目录队改名", club_id: 6101 });
  assert.equal((await r2.json()).ok, true);
  seedTeam(5702, "目录二队");
  const r3 = await machinePost(c, "/api/team/link", { tour_team_id: 5702, club_id: 6101 });
  assert.equal(r3.status, 400);
  assert.equal((await r3.json()).error, "club_taken");

  // 未登记的队 link → team_not_found
  const r4 = await machinePost(c, "/api/team/link", { tour_team_id: 5799, club_id: 6102 });
  assert.equal((await r4.json()).error, "team_not_found");
  // 发码指向未关联俱乐部 → team_not_found
  const r5 = await machinePost(c, "/api/team/bindcode", { club_id: 6999, via: "club" });
  assert.equal((await r5.json()).error, "team_not_found");
});
