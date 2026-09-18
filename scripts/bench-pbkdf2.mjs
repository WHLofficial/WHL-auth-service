// PBKDF2 迭代数档位压测（增量 9，TECH_DESIGN §12 假设 5 的决策依据）。
// Node 与 workerd 的 WebCrypto PBKDF2 都是底层原生实现，本机数据作量级参考；
// 最终口径 = 本档位派生耗时相对 Free 档 10ms CPU 上限的余量 + 本地 wrangler dev 登录端到端增幅。
// 用法：node scripts/bench-pbkdf2.mjs [iterations ...]（缺省 25000 50000 100000，各 5 轮取中位数）
const enc = new TextEncoder();

async function derive(password, salt, iterations) {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  return crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, 256);
}

function median(xs) {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.floor(s.length / 2)];
}

const list = process.argv.slice(2).map(Number);
const rounds = 5;
console.log(`Node ${process.version}，每档 ${rounds} 轮取中位数（首轮预热不计入）`);
for (const n of (list.length ? list : [25_000, 50_000, 100_000])) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  await derive("warmup", salt, n);
  const times = [];
  for (let i = 0; i < rounds; i++) {
    const t0 = performance.now();
    await derive("whl-bench-password", salt, n);
    times.push(performance.now() - t0);
  }
  console.log(
    `pbkdf2-sha256 ${String(n).padStart(7)} iter: median ${median(times).toFixed(1)}ms` +
      `  min ${Math.min(...times).toFixed(1)}ms  max ${Math.max(...times).toFixed(1)}ms`,
  );
}
