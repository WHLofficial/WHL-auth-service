// 固定窗口限流，计数落 D1 的 rate_limit 表（形态调整见 TEST_REPORT F-E）。
// 为什么不是 KV：KV 版是 get → 判上限 → put 的读改写，多 isolate 并发会漏计；D1 的单语句
// INSERT … ON CONFLICT … DO UPDATE SET count = count + 1 RETURNING count 是原子自增，
// 且键只作为普通列值，不再受 KV 512 字节键名限制（F-B 的未认证 500 就出在超长昵称进 KV 键名）。
export interface RateLimitEnv {
  DB: D1Database;
}

export async function rateLimit(
  env: RateLimitEnv,
  key: string,
  limit: number,
  windowSec: number,
): Promise<boolean> {
  const now = Date.now();
  const bucket = Math.floor(now / 1000 / windowSec);
  const res = await env.DB.prepare(
    `INSERT INTO rate_limit (key, bucket, count, expires_at) VALUES (?, ?, 1, ?)
       ON CONFLICT (key, bucket) DO UPDATE SET count = count + 1
     RETURNING count`,
  )
    .bind(key, bucket, new Date(now + windowSec * 1000).toISOString())
    .all<{ count: number }>();
  // 过期行交给 scheduled 的全表扫（clearExpiredLimits）。这里刻意不做「本键首次命中顺手清历史行」：
  // 那条 DELETE 只在键首触时执行，多一次 D1 往返不说，还让新键比已存在的键慢几毫秒（登录实测 6ms），
  // 反而是个方向反转的时序旁路；何况它清不掉「每次都是新键」的增长，真正的兜底是按 expires_at 索引全表扫。
  const count = res.results[0]?.count ?? limit + 1; // 拿不到计数就按超限处理（fail-closed）
  return count <= limit;
}

/** 清零一把键的计数。账号级桶在验密成功时调用：攻击者累计的失败不得把受害者锁在门外（F-C）。 */
export async function resetRateLimit(env: RateLimitEnv, key: string): Promise<void> {
  await env.DB.prepare("DELETE FROM rate_limit WHERE key = ?").bind(key).run();
}

/** 全表清过期行（wrangler.jsonc 的 triggers.crons → src/index.ts 的 scheduled 调用）。 */
export async function clearExpiredLimits(env: RateLimitEnv): Promise<void> {
  await env.DB.prepare("DELETE FROM rate_limit WHERE expires_at <= ?").bind(new Date().toISOString()).run();
}
