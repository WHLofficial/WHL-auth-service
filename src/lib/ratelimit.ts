// KV 固定窗口限流，与 tour 同款算法；用 auth 自有 KV（RL_KV），与共享会话 KV 物理隔离。
// KV 是最终一致，窗口边界少量超发对 ≤50 用户的朋友局场景可接受（TECH_DESIGN §8.4）。
export async function rateLimit(
  env: { RL_KV: KVNamespace },
  key: string,
  limit: number,
  windowSec: number,
): Promise<boolean> {
  const bucket = Math.floor(Date.now() / 1000 / windowSec);
  const k = `rl:${key}:${bucket}`;
  const cur = Number((await env.RL_KV.get(k)) ?? 0);
  if (cur >= limit) return false;
  await env.RL_KV.put(k, String(cur + 1), { expirationTtl: windowSec });
  return true;
}
