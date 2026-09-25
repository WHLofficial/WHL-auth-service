// QQ 绑定/解绑双向闭环（v3.2.0，PRD P1-4）：网页发起解绑 → 生成解绑确认码（bind_code
// kind='unbind'）→ 插件经 /api/identity/unbind/confirm 核销。覆盖：全链成功与审计 via、
// 码-QQ 不匹配、无效/过期码、两类码串用被拒、一号一码作废、网页侧防护（匿名/CSRF/限流）、
// QQ 群直接解绑老路（via=qq_direct）不回归。
// HMAC 契约与 team.test.mjs 一致；未配 BIND_SECRET 时机器端点用例整组跳过。
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { Client } from "../lib/client.mjs";
import * as H from "../lib/harness.mjs";

const BIND_SECRET = process.env.BIND_SECRET || "";
const SKIP_MACHINE = BIND_SECRET ? false : "未配 BIND_SECRET，机器端点测试跳过";

function sign(path, raw, ts) {
  return createHmac("sha256", BIND_SECRET).update(`POST|${path}|${ts}|${raw}`).digest("hex");
}

async function machinePost(path, body) {
  const c = new Client(H.BASE);
  const raw = JSON.stringify(body);
  const ts = Math.floor(Date.now() / 1000);
  return c.raw(path, {
    method: "POST",
    retry: false,
    headers: { "content-type": "application/json", "x-timestamp": String(ts), "x-sign": sign(path, raw, ts) },
    body: raw,
  });
}

const H_esc = (s) => String(s).replace(/'/g, "''");
const nowIso = () => new Date().toISOString();

// 注册并直接落一条 QQ 绑定（绑定码链路另有 P0-8 语义，这里只关心解绑）
async function boundUser(qq) {
  const c = new Client(H.BASE);
  const { name } = await H.register(c);
  const accountId = H.sql(`SELECT id FROM account WHERE name = '${H_esc(name)}';`)[0].id;
  H.sqlExec(
    `INSERT INTO identity (account_id, provider, provider_uid, verified_at, bound_at)
     VALUES (${accountId}, 'qq', '${H_esc(qq)}', '${nowIso()}', '${nowIso()}');`,
  );
  return { client: c, name, accountId, qq };
}

// 网页发起解绑，从响应体抠出确认码（<code class="kbd">解绑 123456</code>）
async function initiateUnbind(user) {
  const csrf = await user.client.csrf("/bind");
  const res = await user.client.postForm("/bind/unbind", { csrf }, { retry: false });
  const body = await res.text();
  const m = /解绑 (\d{6})<\/code>/.exec(body);
  return { res, body, status: res.status, code: m?.[1] ?? null };
}

test("网页发起解绑 → QQ 持码确认 → 解绑成功 + 审计 via=web_confirm", { skip: SKIP_MACHINE }, async () => {
  const qq = String(900000000 + Math.floor(Math.random() * 1000000));
  const u = await boundUser(qq);

  const page = await u.client.text("/bind");
  assert.match(page.body, /action="\/bind\/unbind"/, "已绑定态应出现解绑按钮");

  const init = await initiateUnbind(u);
  assert.equal(init.status, 200, "发起解绑应 200");
  assert.match(init.code, /^\d{6}$/, "页面应展示 6 位解绑码");
  const rows = H.sql(
    `SELECT account_id FROM bind_code WHERE code_hash = '${H.sha256Hex(init.code)}' AND kind = 'unbind' AND used_at IS NULL;`,
  );
  assert.equal(rows[0]?.account_id, u.accountId, "库里应有未用的解绑码且归属本账号");

  const res = await machinePost("/api/identity/unbind/confirm", { qq_id: qq, code: init.code });
  assert.equal(res.status, 200);
  const data = await res.json();
  assert.equal(data.ok, true);
  assert.equal(data.displayName, u.name, "核销应返回账号名");

  assert.equal(H.sql(`SELECT id FROM identity WHERE provider = 'qq' AND provider_uid = '${qq}';`).length, 0, "绑定应已删除");
  assert.ok(
    H.sql(`SELECT used_at FROM bind_code WHERE code_hash = '${H.sha256Hex(init.code)}';`)[0].used_at,
    "解绑码应置已用",
  );
  const audit = H.sql(
    `SELECT detail FROM audit_log WHERE account_id = ${u.accountId} AND event = 'bind.unbind' ORDER BY id DESC;`,
  )[0];
  assert.equal(JSON.parse(audit.detail).via, "web_confirm", "网页确认路审计应标 web_confirm");
  assert.equal(JSON.parse(audit.detail).qq, qq);
});

test("解绑码与 QQ 不匹配 → code_mismatch，双方绑定零写入", { skip: SKIP_MACHINE }, async () => {
  const qa = await boundUser(String(910000000 + Math.floor(Math.random() * 1000000)));
  const qb = await boundUser(String(920000000 + Math.floor(Math.random() * 1000000)));
  const init = await initiateUnbind(qa);
  assert.ok(init.code);

  const res = await machinePost("/api/identity/unbind/confirm", { qq_id: qb.qq, code: init.code });
  assert.equal(res.status, 400);
  assert.equal((await res.json()).error, "code_mismatch");
  for (const q of [qa.qq, qb.qq]) {
    assert.equal(H.sql(`SELECT id FROM identity WHERE provider_uid = '${q}';`).length, 1, `${q} 的绑定应原样保留`);
  }
  assert.ok(
    !H.sql(`SELECT used_at FROM bind_code WHERE code_hash = '${H.sha256Hex(init.code)}';`)[0].used_at,
    "无效动作不应核销解绑码",
  );
});

test("无效码 / 过期码 → invalid_code", { skip: SKIP_MACHINE }, async () => {
  const qq = String(930000000 + Math.floor(Math.random() * 1000000));
  const u = await boundUser(qq);

  const bad = await machinePost("/api/identity/unbind/confirm", { qq_id: qq, code: "000000" });
  assert.equal(bad.status, 400);
  assert.equal((await bad.json()).error, "invalid_code");

  const init = await initiateUnbind(u);
  H.sqlExec(`UPDATE bind_code SET expires_at = '${new Date(Date.now() - 1000).toISOString()}' WHERE code_hash = '${H.sha256Hex(init.code)}';`);
  const stale = await machinePost("/api/identity/unbind/confirm", { qq_id: qq, code: init.code });
  assert.equal(stale.status, 400);
  assert.equal((await stale.json()).error, "invalid_code", "过期解绑码应按无效处理");
  assert.equal(H.sql(`SELECT id FROM identity WHERE provider_uid = '${qq}';`).length, 1, "绑定应原样保留");
});

test("两类码串用被拒：绑定码当解绑码、解绑码当绑定码", { skip: SKIP_MACHINE }, async () => {
  // 解绑码 → /api/bind/claim 必须拒（claim 只认 kind='bind'）
  const qq = String(940000000 + Math.floor(Math.random() * 1000000));
  const u = await boundUser(qq);
  const init = await initiateUnbind(u);
  const claim = await machinePost("/api/bind/claim", { code: init.code, qq_id: String(949000000 + Math.floor(Math.random() * 100000)) });
  assert.equal(claim.status, 400);
  assert.equal((await claim.json()).error, "invalid_code", "解绑码不能当绑定码核销");

  // 绑定码 → confirm 必须拒（confirm 只认 kind='unbind'）
  const other = new Client(H.BASE);
  await H.register(other);
  const csrf = await other.csrf("/bind");
  const codeRes = await other.postForm("/bind/code", { csrf }, { retry: false });
  const bindCode = /绑定 (\d{6})<\/code>/.exec(await codeRes.text())?.[1];
  assert.ok(bindCode, "未绑定账号应能生成绑定码");
  const confirm = await machinePost("/api/identity/unbind/confirm", { qq_id: String(948000000 + Math.floor(Math.random() * 100000)), code: bindCode });
  assert.equal(confirm.status, 400);
  assert.equal((await confirm.json()).error, "invalid_code", "绑定码不能当解绑码核销");
});

test("一号一码：再次发起即作废旧解绑码", { skip: SKIP_MACHINE }, async () => {
  const qq = String(950000000 + Math.floor(Math.random() * 1000000));
  const u = await boundUser(qq);
  const first = await initiateUnbind(u);
  const second = await initiateUnbind(u);
  assert.ok(first.code && second.code && first.code !== second.code);

  const stale = await machinePost("/api/identity/unbind/confirm", { qq_id: qq, code: first.code });
  assert.equal(stale.status, 400, "旧码应已作废");
  const fresh = await machinePost("/api/identity/unbind/confirm", { qq_id: qq, code: second.code });
  assert.equal(fresh.status, 200, "新码应可核销");
});

test("网页侧防护：匿名 303、坏 CSRF 403、限流 429", async () => {
  const anon = await new Client(H.BASE).postForm("/bind/unbind", {}, { retry: false });
  assert.equal(anon.status, 303, "未登录发起解绑应重定向登录");
  assert.equal(anon.headers.get("location"), "/login");

  const u = await boundUser(String(960000000 + Math.floor(Math.random() * 1000000)));
  const badCsrf = await u.client.postForm("/bind/unbind", { csrf: "forged" }, { retry: false });
  assert.equal(badCsrf.status, 403, "坏 CSRF 应 403");

  for (let i = 0; i < 5; i++) {
    const csrf = await u.client.csrf("/bind");
    const r = await u.client.postForm("/bind/unbind", { csrf }, { retry: false });
    assert.equal(r.status, 200, `第 ${i + 1} 次应在配额内 200，实际 ${r.status}`);
  }
  const over = await u.client.postForm("/bind/unbind", { csrf: await u.client.csrf("/bind") }, { retry: false });
  assert.equal(over.status, 429, "超过 5 次/15min 应 429");
});

test("QQ 群直接解绑老路保留：仍成功，审计 via=qq_direct", { skip: SKIP_MACHINE }, async () => {
  const qq = String(970000000 + Math.floor(Math.random() * 1000000));
  const u = await boundUser(qq);
  const res = await machinePost("/api/identity/unbind", { qq_id: qq });
  assert.equal(res.status, 200);
  assert.equal((await res.json()).ok, true);
  assert.equal(H.sql(`SELECT id FROM identity WHERE provider_uid = '${qq}';`).length, 0, "绑定应已删除");
  const audit = H.sql(
    `SELECT detail FROM audit_log WHERE account_id = ${u.accountId} AND event = 'bind.unbind' ORDER BY id DESC;`,
  )[0];
  assert.equal(JSON.parse(audit.detail).via, "qq_direct", "直解路审计应标 qq_direct");
});
