#!/usr/bin/env node
// 一键回归：起一个隔离实例（独立 persist 目录 + 独立端口）→ 本地迁移 → 播种测试数据
//    → 跑单元测试 + E2E 测试 → 收尾。
// 红线：全程只碰 --local 的本地 D1/KV，绝不 --remote、绝不 deploy。
// 用法：npm run test        （AUTH_TEST_PORT=xxxx 可固定端口；AUTH_TEST_KEEP=1 保留测试态目录）
import { spawn, spawnSync, execFileSync } from "node:child_process";
import { mkdirSync, openSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { createHash, randomBytes } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const WRANGLER = join(ROOT, "node_modules", "wrangler", "bin", "wrangler.js");
const STATE = join(ROOT, ".wrangler", "test-state");
const LOG = join(STATE, "dev.log");
const DB = "whl-auth";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const p = srv.address().port;
      srv.close(() => resolve(p));
    });
  });
}

// .dev.vars 只在本地读取并传给子进程（供 HMAC 绑定测试用），不打印、不落盘、不提交。
function readDevVars() {
  const out = {};
  try {
    for (const line of readFileSync(join(ROOT, ".dev.vars"), "utf8").split(/\r?\n/)) {
      const m = /^([A-Za-z0-9_]+)\s*=\s*(.*)$/.exec(line.trim());
      if (m) out[m[1]] = m[2].replace(/^["']|["']$/g, "");
    }
  } catch {
    /* 没有 .dev.vars 时绑定类测试会被跳过 */
  }
  return out;
}

function wrangler(args, opts = {}) {
  return execFileSync(process.execPath, [WRANGLER, ...args], { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], ...opts });
}

// 播种：一个测试用 RP（回调/back-channel 端口由各测试自己回填）+ 一张长期有效的注册码。
function seed(code) {
  const now = new Date().toISOString();
  const exp = new Date(Date.now() + 7 * 864e5).toISOString();
  const codeHash = createHash("sha256").update(code).digest("hex");
  wrangler(["d1", "execute", DB, "--local", "--persist-to", STATE, "--command",
    `INSERT OR REPLACE INTO app (client_id, name, redirect_uris, backchannel_logout_uri, created_at, post_logout_redirect_uris)
     VALUES ('test-rp', '回归测试 RP', '["http://127.0.0.1:1/cb"]', 'http://127.0.0.1:1/bc', '${now}', '["http://127.0.0.1:1/done"]');
     INSERT OR REPLACE INTO signup_code (code_hash, expires_at, max_uses, used_count, created_at)
     VALUES ('${codeHash}', '${exp}', 100000, 0, '${now}');`]);
}

function collect(dir) {
  try {
    return readdirSync(join(ROOT, "tests", dir))
      .filter((f) => f.endsWith(".test.mjs"))
      .sort()
      .map((f) => join("tests", dir, f));
  } catch {
    return [];
  }
}

function killTree(pid) {
  if (process.platform === "win32") {
    try {
      spawnSync("taskkill", ["/PID", String(pid), "/T", "/F"], { stdio: "ignore" });
    } catch {
      /* ignore */
    }
  } else {
    try {
      process.kill(-pid, "SIGKILL");
    } catch {
      /* ignore */
    }
  }
}

let dev = null;
let exitCode = 1;
let devDied = false; // 隔离实例在测试跑完之前自己退出（收尾杀进程不算）
let stopping = false; // 我们主动收尾时不再把退出当成异常

async function main(attempt = 0) {
  devDied = false;
  stopping = false;
  rmSync(STATE, { recursive: true, force: true });
  mkdirSync(STATE, { recursive: true });

  console.log("==> 迁移本地 D1（隔离目录 .wrangler/test-state，不碰开发实例的库）");
  wrangler(["d1", "migrations", "apply", DB, "--local", "--persist-to", STATE], { stdio: "inherit" });

  const port = Number(process.env.AUTH_TEST_PORT || 0) || (await freePort());
  const base = `http://127.0.0.1:${port}`;
  console.log(`==> 启动隔离实例 ${base}`);

  const fd = openSync(LOG, "a");
  dev = spawn(process.execPath, [WRANGLER, "dev", "--port", String(port), "--persist-to", STATE, "--log-level", "info"], {
    cwd: ROOT,
    stdio: ["ignore", fd, fd],
  });
  dev.on("exit", (code, signal) => {
    if (stopping) return;
    devDied = true;
    console.error(`==> 隔离实例提前退出（code=${code} signal=${signal}），日志尾部：`);
    console.error(readFileSync(LOG, "utf8").split(/\r?\n/).slice(-40).join("\n"));
  });

  let up = false;
  for (let i = 0; i < 300; i++) {
    try {
      const r = await fetch(`${base}/healthz`);
      if (r.ok) {
        up = true;
        break;
      }
    } catch {
      /* 还没起来 */
    }
    await sleep(300);
  }
  if (!up) {
    console.error("==> 隔离实例 90s 内未就绪，日志尾部：");
    console.error(readFileSync(LOG, "utf8").split(/\r?\n/).slice(-40).join("\n"));
    const retried = await retryOnce(attempt, "隔离实例未就绪");
    return retried ?? 1;
  }

  const signupCode = "REGR-" + randomBytes(8).toString("hex");
  seed(signupCode);

  const only = process.env.AUTH_TEST_ONLY; // 只跑匹配路径片段的用例，便于定位偶发问题
  const files = [...collect("unit"), ...collect("e2e")].filter((f) => !only || f.includes(only));
  if (!files.length) {
    console.error("==> 没找到任何测试文件");
    return 1;
  }
  console.log(`==> 跑 ${files.length} 个测试文件（unit + e2e）\n`);

  const env = {
    ...process.env,
    AUTH_BASE: base,
    AUTH_PERSIST: STATE,
    AUTH_DEV_LOG: LOG,
    AUTH_SIGNUP_CODE: signupCode,
    AUTH_TEST_APP: "test-rp",
    BIND_SECRET: readDevVars().BIND_SECRET || "",
  };
  const r = await runTests(
    ["--import", pathToFileURL(join(ROOT, "tests", "lib", "loader.mjs")).href, "--test", "--test-concurrency=1", "--test-reporter=spec", ...files],
    env,
  );
  const status = r.status;
  const died = devDied || dev.exitCode !== null;
  // 传输层抖动（Windows 上 undici 偶发 ECONNRESET / fetch failed）不是断言失败，整轮重试一次；
  // 断言失败（输出里没有连接错误标记）绝不重试，避免掩盖真实缺陷。
  const flake = /ECONNRESET|UND_ERR_SOCKET|ECONNREFUSED|socket hang up|fetch failed/i.test(r.output);
  if (status !== 0 && (died || flake)) {
    const retried = await retryOnce(attempt, died ? "隔离实例在测试过程中异常退出" : "出现传输层连接错误");
    return retried ?? status;
  }
  return status;
}

// 跑测试子进程：边流式转发输出边留一份全文，用于判定失败是不是连接抖动。
function runTests(args, env) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, args, { cwd: ROOT, env, stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    const onData = (chunk) => {
      const s = chunk.toString();
      output += s;
      process.stdout.write(s);
    };
    child.stdout.on("data", onData);
    child.stderr.on("data", onData);
    child.on("close", (code) => resolve({ status: code ?? 1, output }));
  });
}

// 实例没起来、实例中途死了、或跑测试途中撞上连接级抖动，都整轮重试一次；
// 实例状态全在 --persist-to 目录里，重建轮次与首轮等价。
async function retryOnce(attempt, reason) {
  if (attempt > 0) return null;
  console.error(`==> ${reason}：这不是用例失败，自动整轮重试一次`);
  stopping = true;
  if (dev?.pid) killTree(dev.pid);
  await sleep(1000);
  return await main(1);
}

try {
  exitCode = await main();
} catch (e) {
  console.error("==> 套件启动失败：", e?.message || e);
  try {
    console.error(readFileSync(LOG, "utf8").split(/\r?\n/).slice(-40).join("\n"));
  } catch {
    /* 无日志 */
  }
  exitCode = 1;
} finally {
  // 先标记"主动收尾"，否则这里杀实例会被 dev.on("exit") 误报成"提前退出"。
  stopping = true;
  if (dev?.pid) killTree(dev.pid);
  if (process.env.AUTH_TEST_KEEP !== "1") {
    // 等进程真正退出再删，否则 Windows 上删不掉被占用的 sqlite 文件。
    await sleep(500);
    rmSync(STATE, { recursive: true, force: true });
  } else {
    console.log(`==> 已保留测试态目录：${STATE}`);
  }
}

console.log(exitCode === 0 ? "\n==> 全部通过" : "\n==> 存在失败用例");
process.exit(exitCode);
