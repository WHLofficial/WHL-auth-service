// 限流单测：计数落 D1 的 rate_limit 表（旧 KV 版为什么会漏计，见 TEST_REPORT F-E）。
// 这里用手写 fake D1，只模拟实现真正用到的那几条语句形状；真库的原子自增由 e2e 用例覆盖。
import { test } from "node:test";
import assert from "node:assert/strict";
import { rateLimit, resetRateLimit, clearExpiredLimits } from "../../src/lib/ratelimit.ts";

const id = (key, bucket) => `${key}\u0000${bucket}`;
const env = (db) => ({ DB: db });

/** 只认三件事：INSERT … ON CONFLICT … RETURNING count / DELETE 按 key / DELETE 按 expires_at。 */
function fakeDb(rows = new Map()) {
  const stmt = (sql, args) => ({
    bind: (...a) => stmt(sql, a),
    async all() {
      if (sql.startsWith("INSERT INTO rate_limit")) {
        const [key, bucket, expiresAt] = args;
        const k = id(key, bucket);
        const row = rows.get(k);
        if (row) row.count += 1;
        else rows.set(k, { key, bucket, count: 1, expires_at: expiresAt });
        return { results: [{ count: rows.get(k).count }] };
      }
      return { results: [] };
    },
    async run() {
      if (sql.includes("key = ?")) {
        for (const [k, r] of rows) if (r.key === args[0]) rows.delete(k);
      } else if (sql.includes("expires_at <= ?")) {
        for (const [k, r] of rows) if (r.expires_at <= args[0]) rows.delete(k);
      }
      return { success: true };
    },
  });
  return { rows, prepare: (sql) => stmt(sql, []) };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const onlyRow = (db) => {
  assert.equal(db.rows.size, 1, `应只有一行，实际 ${db.rows.size}`);
  return [...db.rows.values()][0];
};

test("键只作普通列值（不再是 rl:<key>:<bucket> 拼名），bucket 按窗口换算、expires_at 为窗口末端", async () => {
  const db = fakeDb();
  const before = Date.now();
  await rateLimit(env(db), "login-ip:1.2.3.4", 10, 900);
  const after = Date.now();
  const row = onlyRow(db);
  assert.equal(row.key, "login-ip:1.2.3.4", "key 列应原样存键名（F-B：超长键曾撑爆 KV 512 字节键名）");
  const buckets = [Math.floor(before / 1000 / 900), Math.floor(after / 1000 / 900)];
  assert.ok(buckets.includes(row.bucket), `bucket 应为 ${buckets} 之一，实际 ${row.bucket}`);
  assert.ok(
    Math.abs(new Date(row.expires_at).getTime() - (before + 900 * 1000)) < 5000,
    `expires_at 应落在窗口末端附近，实际 ${row.expires_at}`,
  );
});

test("固定窗口上限：limit=5 时前 5 次放行、之后一律拒绝", async () => {
  const db = fakeDb();
  const results = [];
  for (let i = 0; i < 12; i++) results.push(await rateLimit(env(db), "login-name:1.2.3.4:x", 5, 900));
  assert.deepEqual(results, [...Array(5).fill(true), ...Array(7).fill(false)], `实际 ${results}`);
});

test("同一窗口内计数单调递增", async () => {
  const db = fakeDb();
  await rateLimit(env(db), "k", 5, 900);
  await rateLimit(env(db), "k", 5, 900);
  await rateLimit(env(db), "k", 5, 900);
  assert.equal(onlyRow(db).count, 3);
});

test("不同键互不牵连", async () => {
  const db = fakeDb();
  for (let i = 0; i < 5; i++) await rateLimit(env(db), "login-name:1.1.1.1", 5, 900);
  assert.equal(await rateLimit(env(db), "login-name:1.1.1.1", 5, 900), false);
  assert.equal(await rateLimit(env(db), "login-name:2.2.2.2", 5, 900), true, "另一个 IP 的桶不应被牵连");
  assert.equal(await rateLimit(env(db), "login-ip:1.1.1.1", 5, 900), true, "同 IP 的另一个桶不应被牵连");
});

test("跨窗口重置：新窗口重新放行；过期行留着给 cron 扫，不在热路径删", async () => {
  const db = fakeDb();
  for (let i = 0; i < 5; i++) await rateLimit(env(db), "k", 5, 1);
  assert.equal(await rateLimit(env(db), "k", 5, 1), false, "同窗口第 6 次应拒绝");
  await sleep(1100);
  assert.equal(await rateLimit(env(db), "k", 5, 1), true, "新窗口应重新放行");
  assert.equal(db.rows.size, 2, "旧窗口的行不该被热路径删掉（清理交给 scheduled 全表扫）");
  const stale = [...db.rows.values()].filter((r) => r.expires_at <= new Date().toISOString());
  assert.equal(stale.length, 1, "旧窗口的行应已过期，供 cron 扫走");
});

test("超长键（600 字符）照常计数，不再有 512 字节键名上限", async () => {
  const db = fakeDb();
  const longKey = `login-name:${"x".repeat(590)}`;
  assert.equal(await rateLimit(env(db), longKey, 5, 900), true);
  assert.equal(onlyRow(db).key.length, longKey.length, "超长键应原样入库（F-B 的未认证 500 根因已消除）");
});

test("resetRateLimit 清零账号桶：受害者重新获得完整额度（F-C）", async () => {
  const db = fakeDb();
  for (let i = 0; i < 5; i++) await rateLimit(env(db), "login-acct:someone", 5, 900);
  assert.equal(await rateLimit(env(db), "login-acct:someone", 5, 900), false, "6 次应拒绝");
  await resetRateLimit(env(db), "login-acct:someone");
  assert.equal(db.rows.size, 0, "清零应删掉该键的全部行");
  assert.equal(await rateLimit(env(db), "login-acct:someone", 5, 900), true, "清零后应重新放行");
});

test("resetRateLimit 只动目标键，别的键保留", async () => {
  const db = fakeDb();
  await rateLimit(env(db), "login-acct:a", 5, 900);
  await rateLimit(env(db), "login-acct:b", 5, 900);
  await resetRateLimit(env(db), "login-acct:a");
  assert.deepEqual([...db.rows.values()].map((r) => r.key), ["login-acct:b"]);
});

test("clearExpiredLimits 只删过期行（scheduled cron 清理）", async () => {
  const db = fakeDb(
    new Map([
      [id("old", 1), { key: "old", bucket: 1, count: 3, expires_at: "2000-01-01T00:00:00.000Z" }],
      [id("fresh", 2), { key: "fresh", bucket: 2, count: 1, expires_at: new Date(Date.now() + 900_000).toISOString() }],
    ]),
  );
  await clearExpiredLimits(env(db));
  assert.deepEqual([...db.rows.values()].map((r) => r.key), ["fresh"], "未过期的窗口行必须留着");
});

test("拿不到计数时按超限处理（fail-closed）", async () => {
  const stmt = { bind: () => stmt, all: async () => ({ results: [] }), run: async () => ({}) };
  const broken = { prepare: () => stmt };
  assert.equal(await rateLimit({ DB: broken }, "k", 5, 900), false, "计数读不到就不放行");
});
