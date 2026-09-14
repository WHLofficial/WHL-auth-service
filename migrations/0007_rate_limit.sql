-- 限流计数落 D1（TEST_REPORT F-E）：原来的 KV 固定窗口是 get → 判上限 → put 的读改写，
-- 多 isolate 并发会漏计；这里改用单语句原子自增：
--   INSERT … ON CONFLICT (key, bucket) DO UPDATE SET count = count + 1 RETURNING count
-- 另一个收益：键存普通列而非 KV 键名，不再受 KV 512 字节键名上限约束（F-B 的未认证 500）。
-- key 保持调用方给的语义串（如 login-ip:1.2.3.4 / login-name:<ip>:<昵称>），bucket 单独一列。
CREATE TABLE IF NOT EXISTS rate_limit (
  key TEXT NOT NULL,
  bucket INTEGER NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  expires_at TEXT NOT NULL,
  PRIMARY KEY (key, bucket)
);

-- 过期行清理用（请求路径清自己那把键的历史行，scheduled 每日全表扫）
CREATE INDEX IF NOT EXISTS idx_rate_limit_expires ON rate_limit (expires_at);
