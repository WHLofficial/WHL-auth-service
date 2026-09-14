// E2E 共享工具：SQL 直连（同一个隔离 persist 目录）、种子/账号辅助、RP 侧 back-channel 接收器、
// PKCE 与 OIDC 流程封装。只面向 tests/run.mjs 起的隔离实例。
import { createServer } from "node:http";
import { createHash, randomBytes } from "node:crypto";
import { d1Json, d1Exec } from "./env.mjs";
import { Client } from "./client.mjs";

export const BASE = process.env.AUTH_BASE || "http://127.0.0.1:8792";
export const PERSIST = process.env.AUTH_PERSIST;
export const SIGNUP_CODE = process.env.AUTH_SIGNUP_CODE || "";
export const TEST_APP = process.env.AUTH_TEST_APP || "test-rp";

const DB = "whl-auth";
const opts = PERSIST ? { persistTo: PERSIST } : undefined;

export const sql = (q) => d1Json(DB, q, opts);
export const sqlExec = (q) => d1Exec(DB, q, opts);

export const sha256Hex = (s) => createHash("sha256").update(s).digest("hex");
const sqlStr = (s) => `'${String(s).replace(/'/g, "''")}'`;

let seq = 0;
export function uniqueName(prefix = "t") {
  seq += 1;
  return `${prefix}${Date.now().toString(36)}${seq}${randomBytes(2).toString("hex")}`.slice(0, 32);
}

// 注册（默认带注册码，locked=0）。返回 { res, status, location, csrf, name }
export async function register(client, { name = uniqueName("u"), password = "TestPass123", email = "", code = SIGNUP_CODE } = {}) {
  const csrf = await client.csrf("/register");
  const fields = { csrf, name, password, email };
  if (code) fields.signupCode = code;
  const res = await client.postForm("/register", fields, { retry: false });
  return { res, status: res.status, location: res.headers.get("location"), csrf, name };
}

// 登录（复用已有 client 的 jar）。返回 { res, status, location, csrf }
export async function signIn(client, name, password = "TestPass123", next) {
  const csrf = await client.csrf("/login");
  const fields = { csrf, name, password };
  if (next !== undefined) fields.next = next;
  const res = await client.postForm("/login", fields);
  return { res, status: res.status, location: res.headers.get("location"), csrf };
}

export const sessionToken = (client) => client.jar.get("whl_session");
export const sessionHashOf = (client) => sha256Hex(sessionToken(client));

export function pkce() {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
}

// 更新测试 RP 的端点，指向本测试自己起的接收器。
export function setAppEndpoints({ clientId = TEST_APP, origin, redirectPath = "/cb", backchannelPath = "/bc", postLogoutPath = "/done" } = {}) {
  sqlExec(`UPDATE app SET redirect_uris = ${sqlStr(JSON.stringify([origin + redirectPath]))},
    backchannel_logout_uri = ${sqlStr(origin + backchannelPath)},
    post_logout_redirect_uris = ${sqlStr(JSON.stringify([origin + postLogoutPath]))}
    WHERE client_id = ${sqlStr(clientId)};`);
}

export function authorizeQuery({ clientId, redirectUri, verifier, challenge, state = "st1", nonce = "n1", scope = "openid profile offline_access", extra = {} } = {}) {
  const q = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope,
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: "S256",
    ...extra,
  });
  return "/authorize?" + q.toString();
}

// 走一次 /authorize，返回 { res, location, code, error, state }
export async function authorize(client, args) {
  const url = args.url || authorizeQuery(args);
  const res = await client.get(url, { retry: false });
  const location = res.headers.get("location");
  let code = null;
  let error = null;
  let state = null;
  if (location) {
    const u = new URL(location, BASE);
    code = u.searchParams.get("code");
    error = u.searchParams.get("error");
    state = u.searchParams.get("state");
  }
  return { res, status: res.status, location, code, error, state };
}

// 换 token（/token 是公开端点，用独立 Client 以隔离 IP 限流桶）
export async function exchangeToken(fields) {
  const c = new Client(BASE);
  const res = await c.postForm("/token", fields, { retry: false });
  const body = await res.text();
  let json = null;
  try {
    json = JSON.parse(body);
  } catch {
    /* 非 JSON */
  }
  return { res, status: res.status, body, json };
}

export function exchangeCode({ clientId = TEST_APP, code, redirectUri, verifier }) {
  return exchangeToken({ grant_type: "authorization_code", client_id: clientId, code, redirect_uri: redirectUri, code_verifier: verifier });
}

export function refreshToken({ clientId = TEST_APP, token }) {
  return exchangeToken({ grant_type: "refresh_token", client_id: clientId, refresh_token: token });
}

export async function revoke({ clientId = TEST_APP, token }) {
  const c = new Client(BASE);
  const res = await c.postForm("/revoke", { client_id: clientId, token });
  return { status: res.status, body: await res.text() };
}

export async function userinfo(accessToken) {
  const c = new Client(BASE);
  const res = await c.get("/userinfo", { headers: { authorization: `Bearer ${accessToken}` } });
  const body = await res.text();
  let json = null;
  try {
    json = JSON.parse(body);
  } catch {
    /* 非 JSON */
  }
  return { status: res.status, json, body };
}

// 收 back-channel 登出通知的本地 RP 端
export async function startBackchannel() {
  const received = [];
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      received.push({ method: req.method, url: req.url, contentType: req.headers["content-type"] || "", body, form: Object.fromEntries(new URLSearchParams(body)) });
      res.writeHead(200, { "content-type": "application/json" });
      res.end("{}");
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;
  return {
    port,
    origin: `http://127.0.0.1:${port}`,
    received,
    close: () => new Promise((r) => server.close(r)),
  };
}

export async function waitFor(predicate, { timeoutMs = 4000, stepMs = 150 } = {}) {
  const until = Date.now() + timeoutMs;
  for (;;) {
    const v = await predicate();
    if (v) return v;
    if (Date.now() > until) return null;
    await new Promise((r) => setTimeout(r, stepMs));
  }
}

// 用 auth 自己发布的 JWKS 校验 logout_token / id_token 的签名与声明
export async function jwksVerify(token, { issuer = BASE, audience } = {}) {
  const { jwtVerify, importJWK } = await import("jose");
  const jwks = await (await fetch(`${BASE}/jwks.json`)).json();
  const key = await importJWK(jwks.keys[0], "RS256");
  return jwtVerify(token, key, { issuer, ...(audience ? { audience } : {}) });
}

export { Client };
