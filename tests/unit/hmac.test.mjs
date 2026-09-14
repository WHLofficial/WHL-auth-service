// 机器端点签名（/api/bind/claim、/api/identity/unbind）：规范串、时间窗、常数时间比对。
// 注意 verifyBindSignature 是异步的，所有用例必须 await。
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { SIGN_WINDOW_SECONDS, verifyBindSignature } from "../../src/lib/hmac.ts";

const SECRET = "test-bind-secret";

function sign(secret, method, pathWithQuery, body, ts) {
  return createHmac("sha256", secret).update(`${method}|${pathWithQuery}|${ts}|${body}`).digest("hex");
}

const now = () => Math.floor(Date.now() / 1000);
const verify = (...args) => verifyBindSignature(...args);

test("签名窗口是 ±300s", () => {
  assert.equal(SIGN_WINDOW_SECONDS, 300);
});

test("正确签名通过；签名大小写不敏感", async () => {
  const ts = now();
  const body = JSON.stringify({ code: "abc123", qq_id: "10001" });
  const s = sign(SECRET, "POST", "/api/bind/claim", body, ts);
  assert.equal(await verify(SECRET, "POST", "/api/bind/claim", body, String(ts), s), true);
  assert.equal(await verify(SECRET, "POST", "/api/bind/claim", body, String(ts), s.toUpperCase()), true);
});

test("时间戳超出窗口或非整数时拒绝", async () => {
  const body = "{}";
  const path = "/api/bind/claim";
  const oldTs = now() - 301;
  assert.equal(await verify(SECRET, "POST", path, body, String(oldTs), sign(SECRET, "POST", path, body, oldTs)), false, "过期时间戳应拒绝");
  const futureTs = now() + 301;
  assert.equal(await verify(SECRET, "POST", path, body, String(futureTs), sign(SECRET, "POST", path, body, futureTs)), false, "未来时间戳应拒绝");
  const okTs = now() - 290;
  assert.equal(await verify(SECRET, "POST", path, body, String(okTs), sign(SECRET, "POST", path, body, okTs)), true, "窗口内应通过");
  assert.equal(await verify(SECRET, "POST", path, body, "abc", sign(SECRET, "POST", path, body, now())), false, "非数字时间戳应拒绝");
});

test("换密钥 / 换方法 / 换路径 / 改 body / 改时间戳都会拒绝", async () => {
  const ts = now();
  const body = JSON.stringify({ code: "abc123", qq_id: "10001" });
  const s = sign(SECRET, "POST", "/api/bind/claim", body, ts);
  assert.equal(await verify("other-secret", "POST", "/api/bind/claim", body, String(ts), s), false);
  assert.equal(await verify(SECRET, "GET", "/api/bind/claim", body, String(ts), s), false);
  assert.equal(await verify(SECRET, "POST", "/api/identity/unbind", body, String(ts), s), false);
  assert.equal(await verify(SECRET, "POST", "/api/bind/claim", body + " ", String(ts), s), false);
  assert.equal(await verify(SECRET, "POST", "/api/bind/claim", body, String(ts + 1), s), false);
});

test("查询串参与签名（含 query 的路径必须逐字一致）", async () => {
  const ts = now();
  const path = "/api/bind/claim?x=1";
  const s = sign(SECRET, "POST", path, "{}", ts);
  assert.equal(await verify(SECRET, "POST", path, "{}", String(ts), s), true);
  assert.equal(await verify(SECRET, "POST", "/api/bind/claim", "{}", String(ts), s), false);
});

test("缺少密钥 / 时间戳 / 签名时一律拒绝", async () => {
  const ts = now();
  const body = "{}";
  const s = sign(SECRET, "POST", "/api/bind/claim", body, ts);
  assert.equal(await verify("", "POST", "/api/bind/claim", body, String(ts), s), false);
  assert.equal(await verify(SECRET, "POST", "/api/bind/claim", body, "", s), false);
  assert.equal(await verify(SECRET, "POST", "/api/bind/claim", body, String(ts), ""), false);
  assert.equal(await verify(SECRET, "POST", "/api/bind/claim", body, "0", s), false);
});
