// OIDC Provider 全链路冒烟（本地 wrangler dev 8792）：
//   node scripts/smoke-oidc.mjs
// 前置：scripts/seed-local-users.mjs 播种过本地 whl 库（oidctest 系列账号，登录按账号分摊防限流自爆）；
//       scripts/seed-local-oidc.mjs 播种过本地 auth 库（smoke-rp 假 RP + club 本地回调）。
// 覆盖：discovery/jwks、登录跳转、authorize 发码、PKCE 正反例、code 烧毁与重放联动吊销、
//       refresh 轮换/并发双花/重用检测吊销整族、revoke、userinfo（含篡改负例）、
//       back-channel logout_token 推送、end_session 登出联动、must_change 用户的改密不断链、
//       兼容期共享 KV 会话键删除（P0-9，tour/guess/club 只读 KV 的登出可见性）、
//       权限点播种与按 aud 下发的行为等价（P0-10）。
import { createHash, createPublicKey, createVerify, randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { writeFileSync, unlinkSync } from "node:fs";
import { fileURLToPath } from "node:url";
import http from "node:http";

// —— 前置：清理上一轮冒烟留下的账号级限流键 ——
// login/pwd 限流按账号计数（IP 键已由随机 RUN_IP 隔离），连跑会被上一轮的尝试 429 卡死。
// 只动本地 miniflare KV 的 rl:login-name:* / rl:pwd:*；没有 --remote，生产 KV 无从触及。
// wrangler 命令清不动（如版本差异）就忽略，靠 15 分钟窗口自愈。
try {
  const wrangler = fileURLToPath(new URL("../node_modules/wrangler/bin/wrangler.js", import.meta.url));
  const list = execFileSync(process.execPath, [wrangler, "kv", "key", "list", "--binding", "RL_KV", "--local"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  });
  const keys = JSON.parse(list)
    .map((k) => k.name)
    .filter((n) => n.startsWith("rl:login-name:") || n.startsWith("rl:pwd:"));
  if (keys.length) {
    const file = fileURLToPath(new URL(".smoke-rl-keys.json", import.meta.url));
    writeFileSync(file, JSON.stringify(keys));
    execFileSync(process.execPath, [wrangler, "kv", "bulk", "delete", file, "--binding", "RL_KV", "--local", "--force"], {
      stdio: "ignore",
    });
    unlinkSync(file);
    console.log(`（已清理本地限流键 ${keys.length} 个）`);
  }
} catch {
  console.log("（限流键清理跳过：如遇 429 请等 15 分钟窗口过去再跑）");
}

// —— 前置：账号级授权播种（P0-10，幂等） ——
// 放在任何 HTTP 请求之前：本地 miniflare 的 D1 落盘会让 dev server 短暂重连，
// 运行中写库/查库会让在途请求（或 wrangler CLI 的 dev 代理握手）吃 ECONNRESET（曾实测）。
let grantSeedErr = "";
const grantsById = new Map(); // account_id → ["app.role", ...]，按实际账号核对（不硬编码 id）
try {
  const wrangler = fileURLToPath(new URL("../node_modules/wrangler/bin/wrangler.js", import.meta.url));
  const cli = (args) => execFileSync(process.execPath, [wrangler, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
  const seedSql = execFileSync(process.execPath, [fileURLToPath(new URL("./seed-grants.mjs", import.meta.url))], {
    encoding: "utf8",
  });
  cli(["d1", "execute", "whl-auth", "--local", "--command", seedSql]);
  // 回读全部授权行（§6.2 映射结果），失败重试两次
  for (let attempt = 1; ; attempt++) {
    try {
      const out = cli([
        "d1", "execute", "whl-auth", "--local", "--json", "--command",
        "SELECT ur.account_id AS id, COALESCE(r.app_id,'(global)') || '.' || r.key AS k FROM user_role ur JOIN role r ON r.id = ur.role_id ORDER BY ur.account_id, k",
      ]);
      for (const row of JSON.parse(out)[0].results) {
        grantsById.set(String(row.id), [...(grantsById.get(String(row.id)) ?? []), row.k]);
      }
      break;
    } catch (e) {
      if (attempt >= 3) throw e;
      await new Promise((r) => setTimeout(r, 800));
    }
  }
  console.log(`（已按 §6.2 播种账号级授权 ${grantsById.size} 个账号）`);
} catch (e) {
  grantSeedErr = String(e.message ?? e).split("\n")[0].slice(0, 160);
  console.log(`（授权播种失败：${grantSeedErr}）`);
}

const BASE = "http://127.0.0.1:8792";
const CLIENT = "club";
const REDIRECT_URI = "https://club.whleague.win/api/auth/callback";
// 每次运行用随机源 IP：本地 dev 不经过 CF 边缘，worker 直接透传此头（clientIp 的取值），
// 限流键（rl:*:{ip}）因此按运行隔离，连跑不互相挤兑 15 分钟固定窗口
const RUN_IP = `10.${randomBytes(1)[0]}.${randomBytes(1)[0]}.${(randomBytes(1)[0] % 250) + 1}`;

let passed = 0;
let failed = 0;
function ok(name, cond, extra = "") {
  if (cond) {
    passed++;
    console.log(`  ✓ ${name}`);
  } else {
    failed++;
    console.log(`  ✗ ${name}${extra ? `  (${extra})` : ""}`);
  }
}

// ---- 简易 cookie jar ----
const jar = new Map();
function absorb(res) {
  for (const sc of res.headers.getSetCookie?.() ?? []) {
    const [pair] = sc.split(";");
    const eq = pair.indexOf("=");
    if (eq > 0) jar.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
  }
}
function cookieHeader() {
  return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
}
async function req(method, path, { body, headers = {} } = {}) {
  // 本地 dev 的 miniflare 在 D1 落盘后会短暂重连，首次请求偶发 ECONNRESET：重试一次即可
  for (let attempt = 1; ; attempt++) {
    try {
      const res = await fetch(BASE + path, {
        method,
        redirect: "manual",
        headers: {
          cookie: cookieHeader(),
          "cf-connecting-ip": RUN_IP,
          ...(body ? { "Content-Type": "application/x-www-form-urlencoded" } : {}),
          ...headers,
        },
        body,
      });
      absorb(res);
      return res;
    } catch (e) {
      if (attempt >= 3 || !["ECONNRESET", "ECONNREFUSED", "UND_ERR_SOCKET"].includes(e.cause?.code ?? "")) throw e;
      await new Promise((r) => setTimeout(r, 500));
    }
  }
}
const location = (res) => res.headers.get("location") ?? "";
const qsOf = (u) => Object.fromEntries(new URL(u, BASE).searchParams);
const loggedIn = () => jar.has("whl_session");

// ---- PKCE / JWT 工具 ----
const b64url = (buf) => Buffer.from(buf).toString("base64url");
function pkce() {
  const verifier = b64url(randomBytes(32));
  return { verifier, challenge: b64url(createHash("sha256").update(verifier).digest()) };
}
function jwtDecode(t) {
  const [h, p] = t.split(".");
  return { header: JSON.parse(Buffer.from(h, "base64url")), payload: JSON.parse(Buffer.from(p, "base64url")) };
}
async function rs256Verify(jwt, pubkey) {
  const [h, p, s] = jwt.split(".");
  return createVerify("RSA-SHA256").update(`${h}.${p}`).verify(pubkey, Buffer.from(s, "base64url"));
}

// 发起 authorize（可指定已有 verifier 以测负例；client/redirectUri 可换身份，如本地冒烟 RP），
// 返回响应与发码 Location 参数
async function authorize({
  verifier: fixedVerifier,
  state = `st-${randomBytes(4).toString("hex")}`,
  nonce = `no-${randomBytes(4).toString("hex")}`,
  scope = "openid profile email",
  client = CLIENT,
  redirectUri = REDIRECT_URI,
} = {}) {
  const { verifier, challenge } = fixedVerifier ? { verifier: fixedVerifier, challenge: b64url(createHash("sha256").update(fixedVerifier).digest()) } : pkce();
  const u = new URL(`${BASE}/authorize`);
  u.searchParams.set("client_id", client);
  u.searchParams.set("redirect_uri", redirectUri);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("scope", scope);
  u.searchParams.set("state", state);
  u.searchParams.set("nonce", nonce);
  u.searchParams.set("code_challenge", challenge);
  u.searchParams.set("code_challenge_method", "S256");
  const res = await req("GET", u.pathname + u.search);
  const params = location(res) ? qsOf(location(res)) : {};
  return { res, params, verifier, state, nonce, authorizeUrl: u.pathname + u.search };
}

async function exchange(code, verifier, { client = CLIENT, redirectUri = REDIRECT_URI } = {}) {
  const body = new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: redirectUri, code_verifier: verifier, client_id: client });
  const res = await req("POST", "/token", { body: body.toString() });
  return { res, json: res.status === 200 ? await res.json() : await res.json().catch(() => ({})) };
}
const refresh = (token, client = CLIENT) =>
  req("POST", "/token", { body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: token, client_id: client }).toString() });

async function login(name, password, next) {
  const page = await req("GET", next ? `/login?next=${encodeURIComponent(next)}` : "/login");
  const csrf = /name="csrf" value="([^"]+)"/.exec(await page.text())?.[1];
  const body = new URLSearchParams({ name, password, csrf });
  if (next) body.set("next", next);
  return req("POST", "/login", { body: body.toString() });
}

const jwkPub = await (async () => {
  const res = await fetch(`${BASE}/jwks.json`);
  const { keys } = await res.json();
  return createPublicKey({ key: keys[0], format: "jwk" });
})();

console.log("== 基础端点 ==");
{
  const hz = await fetch(`${BASE}/healthz`);
  ok("healthz", hz.status === 200);
  const disc = await (await fetch(`${BASE}/.well-known/openid-configuration`)).json();
  ok(
    "discovery 字段",
    disc.issuer === BASE &&
      disc.authorization_endpoint === `${BASE}/authorize` &&
      disc.grant_types_supported.includes("refresh_token") &&
      disc.code_challenge_methods_supported.join() === "S256" &&
      disc.end_session_endpoint === `${BASE}/logout`,
  );
  const jwks = await (await fetch(`${BASE}/jwks.json`)).json();
  ok("jwks RSA + kid", jwks.keys?.[0]?.kty === "RSA" && /^[A-Za-z0-9\-_]{10,}$/.test(jwks.keys[0].kid));
}

console.log("== 登录页 CSP：form-action 必须放行 client 回调 origin ==");
{
  // 浏览器实测：Chromium 按 form-action 校验「表单提交触发的整条重定向链」，
  // POST /login → 303 /authorize → 303 <client>/api/auth/callback 最后一跳跨 origin，
  // 只写 'self' 就被静默拦下（页面停在登录页、输入值还在、无任何报错，表现即「登不上去」）。
  // curl 冒烟不执行 CSP，所以这里直接断言响应头，防止策略被改回只允许同源。
  const loginCsp = (await req("GET", "/login")).headers.get("content-security-policy") ?? "";
  const formAction = loginCsp.split("form-action ")[1]?.split(";")[0] ?? "";
  ok("登录页 form-action 仍含 'self'", formAction.includes("'self'"));
  ok("登录页 form-action 放行本地 client 回调 origin", formAction.includes("http://127.0.0.1:8795"));
  ok("登录页 form-action 放行生产 client origin", formAction.includes("https://club.whleague.win"));
  const jsonCsp = (await fetch(`${BASE}/jwks.json`)).headers.get("content-security-policy") ?? "";
  ok("机器接口（JSON）不派生 client origin", jsonCsp.includes("form-action 'self';") && !jsonCsp.includes("127.0.0.1:8795"));
}

console.log("== authorize：未登录跳登录 / 参数校验 ==");
{
  jar.clear();
  const a = await authorize();
  const loc = location(a.res);
  ok(
    "未登录 302 到登录页且带 next",
    a.res.status === 303 && loc.startsWith("/login?next=") && decodeURIComponent(loc).includes("/authorize?client_id=club"),
  );
  const badClient = await req("GET", `/authorize?client_id=nope&redirect_uri=${encodeURIComponent("https://evil.example/cb")}&response_type=code&scope=openid&code_challenge=${"A".repeat(43)}&code_challenge_method=S256`);
  ok("未知 client 渲染错误页（不跳转）", badClient.status === 400 && (await badClient.text()).includes("无法处理这个登录请求"));
  const badRedirect = await req("GET", `/authorize?client_id=club&redirect_uri=${encodeURIComponent("https://evil.example/cb")}&response_type=code&scope=openid&code_challenge=${"A".repeat(43)}&code_challenge_method=S256`);
  ok("redirect_uri 不在名单渲染错误页", badRedirect.status === 400);
  const noPkce = await req("GET", `/authorize?client_id=club&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=openid`);
  ok("缺 PKCE 跳错误到 client", noPkce.status === 303 && qsOf(location(noPkce)).error === "invalid_request");

  // 登录后重放 authorize（静默单点登录）
  const loginRes = await login("oidctest3", "TestPass123", a.authorizeUrl);
  ok("登录成功回到 authorize", loginRes.status === 303 && location(loginRes).startsWith("/authorize"));
  const back = await req("GET", location(loginRes));
  ok("authorize 发码 + state + iss", back.status === 303 && typeof qsOf(location(back)).code === "string" && qsOf(location(back)).iss === BASE);
}

console.log("== token：PKCE 正反例 / code 烧毁 / 重放联动 ==");
let tokensB;
{
  // A：错误 verifier → 400；同 code 换正确 verifier → 400（code 已烧毁，OAuth BCP 处置）
  const { verifier } = pkce();
  const a = await authorize({ verifier });
  const wrong = await exchange(a.params.code, "x".repeat(43));
  ok("错误 verifier 400", wrong.res.status === 400 && wrong.json.error === "invalid_grant");
  const burned = await exchange(a.params.code, verifier);
  ok("PKCE 失败后 code 已烧毁", burned.res.status === 400);

  // B：正常换取
  const b = await authorize();
  const good = await exchange(b.params.code, b.verifier);
  tokensB = good.json;
  ok("code 换取 200", good.res.status === 200 && tokensB.token_type === "Bearer" && tokensB.expires_in === 1800);
  ok("三 token 齐发", typeof tokensB.access_token === "string" && typeof tokensB.refresh_token === "string" && typeof tokensB.id_token === "string");
  const idh = jwtDecode(tokensB.id_token);
  const jwksNow = (await (await fetch(`${BASE}/jwks.json`)).json()).keys[0];
  ok("ID token RS256 + kid 对上 jwks", idh.header.alg === "RS256" && idh.header.kid === jwksNow.kid);
  ok("ID token claims", idh.payload.iss === BASE && idh.payload.aud === CLIENT && idh.payload.nonce === b.nonce && idh.payload.name === "oidctest3");
  ok("ID token 签名可验", await rs256Verify(tokensB.id_token, jwkPub));
  const at = jwtDecode(tokensB.access_token);
  ok("access token claims + 签名", at.payload.aud === CLIENT && at.payload.scope.includes("profile") && (await rs256Verify(tokensB.access_token, jwkPub)));

  // B 的 code 重放 → 400，且 B 族 refresh 被联动吊销
  const replay = await exchange(b.params.code, b.verifier);
  ok("code 重放 400", replay.res.status === 400);
  ok("重放后 B 族 refresh 被吊销", (await refresh(tokensB.refresh_token)).status === 400);
}

console.log("== userinfo ==");
let adminSub = ""; // 本段登录账号（admin）的 account id，供 P0-10 段核对授权行
{
  const ui = await req("GET", "/userinfo", { headers: { authorization: `Bearer ${tokensB.access_token}` } });
  const body = await ui.json();
  const idSub = jwtDecode(tokensB.id_token).payload.sub;
  adminSub = idSub;
  ok("userinfo 200 + sub 与 ID token 同源", ui.status === 200 && body.sub === idSub && /^\d+$/.test(body.sub), JSON.stringify(body));
  ok("aud 过滤角色（admin→club.admin，无 tour 角色）", body.roles.includes("club.admin") && !body.roles.includes("tour.recorder"));
  ok("权限点按角色下发", body.permissions.includes("club.clubs.manage") && body.permissions.includes("club.registrations.manage") && !body.permissions.includes("tour.match.manage"));
  ok("profile/email claims", body.name === "oidctest3" && body.email === "test3@example.com");
  ok("状态字段", body.locked === false && body.must_change_pw === false && body.qq === null);
  ok("无 token 401", (await req("GET", "/userinfo")).status === 401);
  const tampered = tokensB.access_token.slice(0, -3) + (tokensB.access_token.endsWith("aaa") ? "bbb" : "aaa");
  ok("篡改 token 401", (await req("GET", "/userinfo", { headers: { authorization: `Bearer ${tampered}` } })).status === 401);
  const stillOk = await req("GET", "/userinfo", { headers: { authorization: `Bearer ${tokensB.access_token}` } });
  ok("access token 与 refresh 生命周期独立", stillOk.status === 200);
}

console.log("== 权限点播种与下发等价（P0-10） ==");
{
  // §6.2 行为等价：tour user.role → user_role 授权（播种与回读都在脚本开头完成，读 grantsById）
  ok("授权播种脚本执行成功（幂等，可重复）", grantSeedErr === "", grantSeedErr);
  const adminRoles = grantsById.get(adminSub) ?? [];
  ok(
    `admin 账号（sub=${adminSub}）授权 = tour.recorder + guess.admin + club.admin`,
    adminRoles.join(",") === "club.admin,guess.admin,tour.recorder",
    adminRoles.join(","),
  );

  // 同一登录会话（oidctest3）分别向三个 client 取 token：§6.3 按 aud 过滤 + 精确权限集（不越界、不缺失）
  const cases = {
    tour: { client: "tour", redirectUri: "https://tour.whleague.win/api/auth/callback", roles: ["tour.recorder"], perms: ["tour.match.manage", "tour.team.bindcode.issue"] },
    guess: { client: "guess", redirectUri: "https://guess.whleague.win/api/auth/callback", roles: ["guess.admin"], perms: ["guess.event.manage", "guess.payout.reverse", "guess.recon.view", "guess.users.manage"] },
  };
  for (const [aud, e] of Object.entries(cases)) {
    const a = await authorize({ client: e.client, redirectUri: e.redirectUri });
    const t = (await exchange(a.params.code, a.verifier, { client: e.client, redirectUri: e.redirectUri })).json;
    const ui = await (await req("GET", "/userinfo", { headers: { authorization: `Bearer ${t.access_token}` } })).json();
    ok(`aud=${aud} 角色集精确`, JSON.stringify([...ui.roles].sort()) === JSON.stringify(e.roles), JSON.stringify(ui.roles));
    ok(`aud=${aud} 权限集精确等于映射表`, JSON.stringify([...ui.permissions].sort()) === JSON.stringify(e.perms), JSON.stringify(ui.permissions));
  }
}

console.log("== refresh 轮换与重用检测 ==");
{
  const c = await authorize();
  const t1 = (await exchange(c.params.code, c.verifier)).json;
  const r1 = await refresh(t1.refresh_token);
  const t2 = await r1.json();
  ok("轮换成功发新族员", r1.status === 200 && t2.refresh_token && t2.refresh_token !== t1.refresh_token);
  ok("轮换后 ID token 不带 nonce", jwtDecode(t2.id_token).payload.nonce === undefined);
  ok("重用旧 refresh 400", (await refresh(t1.refresh_token)).status === 400);
  ok("整族连坐 400", (await refresh(t2.refresh_token)).status === 400);

  // 并发双花：同一个未轮换 token 同时打两发，只有一发能成
  const d = await authorize();
  const t3 = (await exchange(d.params.code, d.verifier)).json;
  const [p1, p2] = await Promise.all([refresh(t3.refresh_token), refresh(t3.refresh_token)]);
  const winners = [p1.status, p2.status].filter((s) => s === 200).length;
  ok("并发双花只成功一次", winners === 1 && [p1.status, p2.status].includes(400), `p1=${p1.status} p2=${p2.status}`);
}

console.log("== revoke ==");
{
  const e = await authorize();
  const t = (await exchange(e.params.code, e.verifier)).json;
  ok("revoke 200", (await req("POST", "/revoke", { body: new URLSearchParams({ client_id: CLIENT, token: t.refresh_token }).toString() })).status === 200);
  ok("revoke 后 refresh 失效", (await refresh(t.refresh_token)).status === 400);
  ok("revoke 无效 token 也 200（RFC 7009）", (await req("POST", "/revoke", { body: new URLSearchParams({ client_id: CLIENT, token: "not-a-token" }).toString() })).status === 200);
}

console.log("== back-channel 登出通知（logout_token 推送） ==");
{
  // 本地假 RP = seed-local-oidc.mjs 播种的 smoke-rp，收端点 127.0.0.1:8793 由这里临时起服务
  const CLIENT_RP = "smoke-rp";
  const REDIRECT_RP = "http://127.0.0.1:8792/smoke-cb";
  const received = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (ch) => (body += ch));
    req.on("end", () => {
      received.push(new URLSearchParams(body).get("logout_token"));
      res.writeHead(200).end();
    });
  });
  await new Promise((resolve) => server.listen(8793, "127.0.0.1", resolve));
  try {
    // oidctest3：back-channel 小节专属（登录限流按账号计数，各小节分摊用户防自爆）
    jar.clear();
    const a = await authorize({ client: CLIENT_RP, redirectUri: REDIRECT_RP });
    const loginRes = await login("oidctest4", "TestPass123", a.authorizeUrl);
    ok("前置：登录成功", loggedIn());
    const back = await req("GET", location(loginRes));
    const t = (await exchange(qsOf(location(back)).code, a.verifier, { client: CLIENT_RP, redirectUri: REDIRECT_RP })).json;
    ok("smoke-rp 正常换取", typeof t.id_token === "string" && typeof t.refresh_token === "string");

    const idPayload = jwtDecode(t.id_token).payload;
    const idSid = idPayload.sid;
    const sessionToken = jar.get("whl_session") ?? "";
    ok(
      "ID token 带 sid = 登录会话指纹",
      typeof idSid === "string" && idSid === createHash("sha256").update(sessionToken).digest("hex"),
      `sid=${idSid}`,
    );

    await req("GET", "/logout");
    // 推送在 waitUntil 里跑，响应返回后才落地——轮询等它
    let logoutToken = null;
    for (let i = 0; i < 50 && !logoutToken; i++) {
      await new Promise((r) => setTimeout(r, 100));
      logoutToken = received.find(Boolean) ?? null;
    }
    ok("smoke-rp 收到 logout_token", typeof logoutToken === "string", `收到 ${received.length} 条`);
    const lp = jwtDecode(logoutToken).payload;
    ok("logout_token 签名可验", await rs256Verify(logoutToken, jwkPub));
    ok(
      "logout_token claims（iss/aud/sub/sid/jti/events，无 nonce）",
      lp.iss === BASE &&
        lp.aud === CLIENT_RP &&
        lp.sub === idPayload.sub &&
        lp.sid === idSid &&
        typeof lp.jti === "string" &&
        !!lp.events?.["http://schemas.openid.net/event/backchannel-logout"] &&
        lp.nonce === undefined,
      JSON.stringify(lp),
    );
    ok("登出后该 RP 的 refresh 全部吊销", (await refresh(t.refresh_token, CLIENT_RP)).status === 400);

    // 没换过 token 的会话登出：不该有第二封通知
    const before = received.length;
    jar.clear();
    await login("oidctest4", "TestPass123");
    ok("前置：纯兼容会话已登录", loggedIn());
    await req("GET", "/logout");
    await new Promise((r) => setTimeout(r, 1500));
    ok("纯兼容会话登出不推送", received.length === before, `收到 ${received.length - before} 条`);
  } finally {
    server.close();
  }
}

console.log("== end_session 登出联动 ==");
{
  // back-channel 小节已把会话登出，这里必须重新建立登录态（oidctest4：小节专属）
  jar.clear();
  await login("oidctest5", "TestPass123");
  ok("前置：登录成功", loggedIn());
  const f = await authorize();
  const t = (await exchange(f.params.code, f.verifier)).json;
  ok("前置：code 已换 token", typeof t.refresh_token === "string");
  const lo = await req("GET", `/logout?post_logout_redirect_uri=${encodeURIComponent("https://club.whleague.win/")}&state=bye`);
  ok("登出 303 回白名单域名 + state", lo.status === 303 && location(lo).startsWith("https://club.whleague.win/") && qsOf(location(lo)).state === "bye");
  const badLo = await req("GET", `/logout?post_logout_redirect_uri=${encodeURIComponent("https://evil.example/")}`);
  ok("非白名单跳回登录页", badLo.status === 303 && location(badLo) === "/login");
  ok("该会话签发的 refresh 全部吊销", (await refresh(t.refresh_token)).status === 400);
  const home = await req("GET", "/");
  ok("兼容会话已销毁", home.status === 303 && location(home) === "/login");
  const reAuth = await authorize();
  ok("登出后再 authorize 要重新登录", reAuth.res.status === 303 && location(reAuth.res).startsWith("/login"));
}

console.log("== compat 登出/改密联动吊销（与 GET /logout 同口径） ==");
{
  // oidctest5/6：compat 小节专属（3 次登录分摊两个账号，规避 login-name 5 次/15 分钟限流）
  jar.clear();
  await login("oidctest6", "TestPass123");
  ok("前置：登录成功", loggedIn());
  // P0-9 兼容期 KV 语义核对（TECH_DESIGN §8.7）：tour/guess/club 只读共享 KV、不查 D1，
  // 登出必须真的删掉 sess:{token} 键，三系统才能立刻回到未登录态（auth 自身还查 D1，
  // 单看 auth 页面测不出 KV 删除失败，所以这里直接查 KV 落盘）
  const rawToken = jar.get("whl_session");
  const wrangler = fileURLToPath(new URL("../node_modules/wrangler/bin/wrangler.js", import.meta.url));
  // 注意：wrangler kv key get 对不存在的键也可能退出码 0（只打印 "Value not found"），
  // 不能靠进程退出码判断存在性，必须看输出内容；值形状是 {"userId":N}
  const kvGet = (name) => {
    try {
      const out = execFileSync(process.execPath, [wrangler, "kv", "key", "get", name, "--binding", "SESSION_KV", "--local"], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      });
      return out.includes("Value not found") ? null : out;
    } catch {
      return null;
    }
  };
  ok("前置：拿到原始会话 token", typeof rawToken === "string" && rawToken.length > 0);
  let kvOk = false;
  try {
    kvOk = typeof JSON.parse(kvGet(`sess:${rawToken}`) ?? "").userId === "number";
  } catch {
    // 键不存在或值不是预期形状
  }
  ok("前置：兼容 KV 会话键在登出前存在", kvOk);
  const g = await authorize();
  const codeG = g.params.code;
  const home = await req("GET", "/");
  const csrf = /name="csrf" value="([^"]+)"/.exec(await home.text())?.[1];
  const lo = await req("POST", "/logout", { body: new URLSearchParams({ csrf }).toString() });
  ok("compat POST /logout 303", lo.status === 303);
  ok("compat 登出删除共享 KV 会话键", kvGet(`sess:${rawToken}`) === null, "键仍存在，三系统会保持登录态至 TTL");
  ok("compat 登出后未换的 code 作废", (await exchange(codeG, g.verifier)).res.status === 400);
  // refresh 吊销验证需要真实 token，重新走一遍：登录 → 换 token → POST /logout → refresh 应死
  jar.clear();
  await login("oidctest6", "TestPass123");
  ok("前置：登录成功", loggedIn());
  const g2 = await authorize();
  const t = (await exchange(g2.params.code, g2.verifier)).json;
  ok("前置：code 已换 token", typeof t.refresh_token === "string");
  const home2 = await req("GET", "/");
  const csrf2 = /name="csrf" value="([^"]+)"/.exec(await home2.text())?.[1];
  await req("POST", "/logout", { body: new URLSearchParams({ csrf: csrf2 }).toString() });
  ok("compat 登出吊销该会话 refresh", (await refresh(t.refresh_token)).status === 400);

  // 改密轮换联动吊销（改密会真的改掉密码，用池里的 oidctest6，seed 会重置回来）
  jar.clear();
  await login("oidctest5", "TestPass123");
  ok("前置：登录成功", loggedIn());
  const g3 = await authorize();
  const t3 = (await exchange(g3.params.code, g3.verifier)).json;
  ok("前置：code 已换 token", typeof t3.refresh_token === "string");
  const pwPage = await req("GET", "/password");
  const pcsrf = /name="csrf" value="([^"]+)"/.exec(await pwPage.text())?.[1];
  const pwRes = await req("POST", "/password", {
    body: new URLSearchParams({ csrf: pcsrf, oldPassword: "TestPass123", newPassword: "NewPass789" }).toString(),
  });
  ok("改密成功回首页", pwRes.status === 303 && location(pwRes) === "/?notice=pw_changed");
  ok("改密后旧 refresh 吊销", (await refresh(t3.refresh_token)).status === 400);
  const g4 = await authorize();
  ok("改密后新会话照常发码", g4.res.status === 303 && typeof g4.params.code === "string");
}

console.log("== must_change 用户：改密不断链 ==");
{
  jar.clear();
  const a = await authorize();
  const loginRes = await login("oidctest2", "OldPass999", a.authorizeUrl);
  ok("must_change 登录跳改密且带 next", loginRes.status === 303 && location(loginRes).startsWith("/password?next="));
  const pwPage = await req("GET", location(loginRes));
  const csrf = /name="csrf" value="([^"]+)"/.exec(await pwPage.text())?.[1];
  const next = qsOf(location(loginRes)).next;
  const pwRes = await req("POST", "/password", {
    body: new URLSearchParams({ csrf, oldPassword: "OldPass999", newPassword: "NewPass456", next }).toString(),
  });
  ok("改密后 303 直达 authorize", pwRes.status === 303 && location(pwRes).startsWith("/authorize"));
  const back = await req("GET", location(pwRes));
  ok("改密后直接发码（静默 SSO）", back.status === 303 && typeof qsOf(location(back)).code === "string");
  const g = await exchange(qsOf(location(back)).code, a.verifier);
  ok("改密链路换出的 code 能正常换 token", g.res.status === 200 && g.json.access_token);
  const ui = await req("GET", "/userinfo", { headers: { authorization: `Bearer ${g.json.access_token}` } });
  const coachBody = await ui.json();
  ok("userinfo 反映新用户（coach → club.coach）", ui.status === 200 && coachBody.roles.includes("club.coach"));
  const coachRoles = grantsById.get(coachBody.sub) ?? [];
  ok(`coach 账号（sub=${coachBody.sub}）授权 = tour.coach + club.coach`, coachRoles.join(",") === "club.coach,tour.coach", coachRoles.join(","));
}

console.log("== P0-10：superadmin 全局角色（§6.2 首行） ==");
{
  jar.clear();
  const a = await authorize();
  const loginRes = await login("oidctest7", "TestPass123", a.authorizeUrl);
  ok("前置：superadmin 登录成功", loggedIn());
  const back = await req("GET", location(loginRes));
  const t = (await exchange(qsOf(location(back)).code, a.verifier)).json;
  ok("前置：换到 access_token", typeof t.access_token === "string");
  const ui = await req("GET", "/userinfo", { headers: { authorization: `Bearer ${t.access_token}` } });
  const sb = await ui.json();
  ok(
    "superadmin 拿到全局角色 superadmin + club 视角的兼容换算角色",
    ui.status === 200 && [...sb.roles].sort().join(",") === "club.admin,superadmin",
    JSON.stringify(sb.roles),
  );
  ok(
    "superadmin 持全部权限点（含三系统各一个）",
    sb.permissions.length >= 17 && ["tour.match.manage", "guess.recon.view", "club.compliance.view"].every((k) => sb.permissions.includes(k)),
    `count=${sb.permissions.length}`,
  );
  ok(
    "superadmin 授权行来自全局角色（role.app_id IS NULL）",
    (grantsById.get(sb.sub) ?? []).join(",") === "(global).superadmin",
    (grantsById.get(sb.sub) ?? []).join(","),
  );
}

console.log(`\n结果：${passed} 过 / ${failed} 挂`);
process.exit(failed === 0 ? 0 : 1);
