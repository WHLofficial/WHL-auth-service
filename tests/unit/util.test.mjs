// 客户端 IP 取值、JSON 容错解析、常数时间比对。
import { test } from "node:test";
import assert from "node:assert/strict";
import { clientIp, nowIso, parseUris, timingSafeEqual } from "../../src/lib/util.ts";

const fakeCtx = (headers) => ({
  req: { header: (name) => headers[String(name).toLowerCase()] ?? undefined },
});

test("clientIp 只认 CF-Connecting-IP，缺省回退 local", () => {
  assert.equal(clientIp(fakeCtx({ "cf-connecting-ip": "203.0.113.7" })), "203.0.113.7");
  assert.equal(clientIp(fakeCtx({})), "local");
});

test("clientIp 不读 X-Forwarded-For（伪造该头无法换 IP 桶）", () => {
  assert.equal(clientIp(fakeCtx({ "x-forwarded-for": "9.9.9.9" })), "local");
  assert.equal(clientIp(fakeCtx({ "cf-connecting-ip": "203.0.113.7", "x-forwarded-for": "9.9.9.9" })), "203.0.113.7");
});

test("nowIso 是 ISO 8601 UTC 且可解析", () => {
  const s = nowIso();
  assert.match(s, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
  assert.ok(Math.abs(Date.parse(s) - Date.now()) < 5000);
});

test("parseUris 容错：非 JSON / 非数组安全降级为空数组", () => {
  assert.deepEqual(parseUris('["https://a/cb"]'), ["https://a/cb"]);
  assert.deepEqual(parseUris("not json"), []);
  assert.deepEqual(parseUris(""), []);
  assert.deepEqual(parseUris("null"), []);
  assert.deepEqual(parseUris('{"a":1}'), [], "对象不是数组");
});

test("parseUris 逐元素过滤非字符串（避免把 123 当 URI 参与白名单比较）", () => {
  assert.deepEqual(parseUris('["ok",123]'), ["ok"]);
  assert.deepEqual(parseUris('[null,"ok",{"a":1},true]'), ["ok"]);
  assert.deepEqual(parseUris("[1,2,3]"), []);
  assert.deepEqual(parseUris('["http://a/cb","http://b/cb"]'), ["http://a/cb", "http://b/cb"]);
});

test("timingSafeEqual 等长比较正确、长度不等直接 false", () => {
  assert.equal(timingSafeEqual("abc", "abc"), true);
  assert.equal(timingSafeEqual("abc", "abd"), false);
  assert.equal(timingSafeEqual("abc", "abcd"), false);
  assert.equal(timingSafeEqual("", ""), true);
  assert.equal(timingSafeEqual("a", ""), false);
});
