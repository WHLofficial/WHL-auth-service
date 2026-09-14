// 本地测试环境工具：只操作 --local 的 D1/KV（绝不带 --remote）。
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { randomBytes, createHash } from "node:crypto";

const WRANGLER = fileURLToPath(new URL("../../node_modules/wrangler/bin/wrangler.js", import.meta.url));
const ROOT = fileURLToPath(new URL("../..", import.meta.url));

const sleepSync = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

// wrangler 在 Windows 上对同一 persist 目录偶发 "fetch failed" / libuv assertion
// （dev server 正在占用 .wrangler/state 时的瞬时冲突），退避重试即可，非数据问题。
function cli(args, opts = {}, { retries = 6, delayMs = 350 } = {}) {
  for (let i = 0; ; i++) {
    try {
      return execFileSync(process.execPath, [WRANGLER, ...args], {
        cwd: ROOT,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
        ...opts,
      });
    } catch (e) {
      const out = `${e.stdout ?? ""}${e.stderr ?? ""}`;
      const transient = /fetch failed|Assertion failed|ECONNRESET|EBUSY|SQLITE_BUSY|database is locked/i.test(out);
      if (!transient || i >= retries) throw e;
      sleepSync(delayMs * (i + 1));
    }
  }
}

function persist(args, opts) {
  return opts?.persistTo ? [...args, "--persist-to", opts.persistTo] : args;
}

export function d1Json(db, sql, opts) {
  const out = cli(persist(["d1", "execute", db, "--local", "--json", "--command", sql], opts));
  const start = out.indexOf("[");
  return JSON.parse(out.slice(start))[0].results;
}

export function d1Exec(db, sql, opts) {
  return cli(persist(["d1", "execute", db, "--local", "--command", sql], opts));
}

export function applyMigrations(db, opts) {
  return cli(persist(["d1", "migrations", "apply", db, "--local"], opts));
}

// 账号级 / IP 级限流清理：计数落在 D1 的 rate_limit 表（限流已从 KV 迁 D1，见 TEST_REPORT F-E）。
// 运行间清一次即可，避免 15 分钟固定窗口跨用例互相挤兑。
export function clearRateLimits(db = "whl-auth", opts) {
  return d1Exec(db, "DELETE FROM rate_limit;", opts);
}

export function randomIp() {
  // 10.x.x.x 私网段，模拟冒烟脚本的隔离手法（仅本地有效：CF 边缘会覆盖该头）
  return `10.${(Math.random() * 254 + 1) | 0}.${(Math.random() * 254 + 1) | 0}.${(Math.random() * 254 + 1) | 0}`;
}

export function rand(n = 6) {
  return randomBytes(16).toString("hex").slice(0, n);
}

export function sha256Hex(s) {
  return createHash("sha256").update(s).digest("hex");
}
