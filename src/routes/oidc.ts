import { Hono } from "hono";
import { getCookie } from "hono/cookie";
import type { Context } from "hono";
import type { AppEnv } from "../env";
import { randomToken, sha256Hex } from "../lib/crypto";
import { signingKey, verifyPkce } from "../lib/oidc";
import { rateLimit } from "../lib/ratelimit";
import { SESSION_COOKIE } from "../lib/session";
import { clientIp } from "../lib/util";
import { oidcErrorPage } from "../web/pages";

const app = new Hono<AppEnv>();

// ---------- 共用小件 ----------

const ALLOWED_SCOPES = ["openid", "profile", "email", "offline_access"];

type AppRow = {
  client_id: string;
  redirect_uris: string;
  post_logout_redirect_uris: string;
};

function parseUris(json: string): string[] {
  try {
    const v: unknown = JSON.parse(json);
    return Array.isArray(v) ? v.filter((s): s is string => typeof s === "string") : [];
  } catch {
    return [];
  }
}

async function loadApp(c: Context<AppEnv>, clientId: string): Promise<AppRow | null> {
  return c.env.DB.prepare("SELECT client_id, redirect_uris, post_logout_redirect_uris FROM app WHERE client_id = ?")
    .bind(clientId)
    .first<AppRow>();
}

// 这些端点不读 cookie（公开 client 模式，token 靠 PKCE 与一次性 code 保护），允许任意源跨域访问
const CORS_PATHS = new Set(["/token", "/revoke", "/userinfo", "/jwks.json", "/.well-known/openid-configuration"]);

app.use(async (c, next) => {
  const corsable = CORS_PATHS.has(c.req.path);
  if (corsable && c.req.method === "OPTIONS") {
    return c.body(null, 204, {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Authorization, Content-Type",
      "Access-Control-Max-Age": "86400",
    });
  }
  await next();
  if (corsable) c.header("Access-Control-Allow-Origin", "*");
});

// ---------- 发现与验签公钥 ----------

app.get("/.well-known/openid-configuration", (c) => {
  const iss = new URL(c.req.url).origin;
  return c.json({
    issuer: iss,
    authorization_endpoint: `${iss}/authorize`,
    token_endpoint: `${iss}/token`,
    userinfo_endpoint: `${iss}/userinfo`,
    revocation_endpoint: `${iss}/revoke`,
    jwks_uri: `${iss}/jwks.json`,
    end_session_endpoint: `${iss}/logout`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    token_endpoint_auth_methods_supported: ["none"],
    scopes_supported: ALLOWED_SCOPES,
    code_challenge_methods_supported: ["S256"],
    claims_supported: [
      "sub",
      "name",
      "preferred_username",
      "email",
      "locked",
      "must_change_pw",
      "roles",
      "permissions",
      "qq",
    ],
    authorization_response_iss_parameter_supported: true,
  });
});

app.get("/jwks.json", async (c) => {
  try {
    const key = await signingKey(c.env);
    return c.json({ keys: [key.publicJwk] });
  } catch (err) {
    console.error(err);
    return c.json({ error: "server_error" }, 500);
  }
});

// ---------- 授权端点（authorization code + 强制 PKCE） ----------

/** 跳回 client 的错误响应（client/redirect_uri 已验证后才允许跳转） */
function oauthError(redirectUri: string, error: string, description: string, state?: string): string {
  const u = new URL(redirectUri);
  u.searchParams.set("error", error);
  u.searchParams.set("error_description", description);
  if (state !== undefined) u.searchParams.set("state", state);
  return u.toString();
}

app.get("/authorize", async (c) => {
  if (!(await rateLimit(c.env, `authz:${clientIp(c)}`, 60, 900))) {
    return c.html(oidcErrorPage("请求太频繁", "操作太密集，请 15 分钟后再试。"), 429);
  }
  const iss = new URL(c.req.url).origin;
  const clientId = c.req.query("client_id") ?? "";
  const redirectUri = c.req.query("redirect_uri") ?? "";
  const app_ = clientId && redirectUri ? await loadApp(c, clientId) : null;
  // client 与 redirect_uri 逐字精确匹配；匹配不上就渲染错误页而不是跳转——
  // 跳转目标本身还没被验证，开放跳转就是这么来的
  if (!app_ || redirectUri.includes("#") || !parseUris(app_.redirect_uris).includes(redirectUri)) {
    return c.html(
      oidcErrorPage("无法处理这个登录请求", "发起登录的应用不在接入名单里，或回调地址不对。请联系管理员。"),
      400,
    );
  }

  const state = c.req.query("state");
  const fail = (error: string, description: string) =>
    c.redirect(oauthError(redirectUri, error, description, state), 303);

  if (c.req.query("response_type") !== "code") return fail("unsupported_response_type", "只支持 code 流程");
  const scopes = (c.req.query("scope") ?? "").split(" ").filter(Boolean);
  if (!scopes.includes("openid")) return fail("invalid_scope", "scope 需要包含 openid");
  if (scopes.some((s) => !ALLOWED_SCOPES.includes(s))) return fail("invalid_scope", "scope 超出允许范围");
  const challenge = c.req.query("code_challenge") ?? "";
  // S256 的 challenge 恒为 43 位 base64url；PKCE 强制（TECH_DESIGN §8.3）
  if (!/^[A-Za-z0-9\-_]{43}$/.test(challenge) || c.req.query("code_challenge_method") !== "S256") {
    return fail("invalid_request", "必须携带 PKCE code_challenge（method=S256）");
  }

  const sessionToken = getCookie(c, SESSION_COOKIE);
  if (!sessionToken || !c.get("user")) {
    // 未登录：先登录，回来时原样重放本请求（state/nonce/challenge 全保留），实现静默单点登录
    const next = `/authorize${new URL(c.req.url).search}`;
    return c.redirect(`/login?next=${encodeURIComponent(next)}`, 303);
  }

  const code = randomToken(32);
  await c.env.DB.prepare(
    `INSERT INTO oidc_code
       (code_hash, account_id, client_id, redirect_uri, scope, nonce, code_challenge,
        code_challenge_method, session_hash, created_at, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, 'S256', ?, ?, ?)`,
  )
    .bind(
      await sha256Hex(code),
      c.get("user")!.id,
      clientId,
      redirectUri,
      scopes.join(" "),
      c.req.query("nonce") || null,
      challenge,
      await sha256Hex(sessionToken),
      new Date().toISOString(),
      new Date(Date.now() + 60_000).toISOString(),
    )
    .run();

  const target = new URL(redirectUri);
  target.searchParams.set("code", code);
  if (state !== undefined) target.searchParams.set("state", state);
  target.searchParams.set("iss", iss); // RFC 9207：client 可自查响应来自哪个授权服务，防混用
  return c.redirect(target.toString(), 303);
});

export default app;
