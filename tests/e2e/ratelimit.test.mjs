// 限流配额回归（TEST_REPORT L-2）：/userinfo 与机器端点原本完全没有限流，现在都挂在 D1 固定窗口桶上。
// 两者配额都很宽（600/15min、300/15min），故这里必须真把配额打满才能断言 429 —— 每个用例一个全新
// Client，随机 CF-Connecting-IP 保证桶只属于自己，不会污染别的用例。
import { test } from "node:test";
import assert from "node:assert/strict";
import { Client } from "../lib/client.mjs";
import * as H from "../lib/harness.mjs";

test("/userinfo 限流：同一 IP 600 次配额内的 401，第 601 次 429", async () => {
  const c = new Client(H.BASE);
  for (let i = 1; i <= 600; i++) {
    const r = await c.get("/userinfo");
    assert.equal(r.status, 401, `第 ${i} 次无 token 的 /userinfo 应在配额内 401，实际 ${r.status}`);
  }
  const over = await c.get("/userinfo");
  assert.equal(over.status, 429, "超出 600/15min 配额应 429");
  assert.match(over.headers.get("content-type") ?? "", /application\/json/);
});

test("机器端点限流：先限流后验签，且 /api/bind/claim 与 /api/identity/unbind 共用一条桶", async () => {
  const c = new Client(H.BASE);
  // 限流在 HMAC 之前：配额内假签名得到的是 401 bad sign，而不是直接 429
  const probe = await c.postForm("/api/bind/claim", {}, { retry: false });
  assert.equal(probe.status, 401, "假签名应 401（限流不应抢在验签前误判）");

  for (let i = 2; i <= 300; i++) {
    const r = await c.postForm("/api/bind/claim", {}, { retry: false });
    assert.equal(r.status, 401, `第 ${i} 次应在配额内 401，实际 ${r.status}`);
  }
  const over = await c.postForm("/api/bind/claim", {}, { retry: false });
  assert.equal(over.status, 429, "超过 300/15min 应 429");
  assert.equal((await over.json()).error, "rate_limited");

  const other = await c.postForm("/api/identity/unbind", {}, { retry: false });
  assert.equal(other.status, 429, "两端点共用桶：claim 打满后 unbind 也应 429");
});
