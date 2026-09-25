import { Hono } from "hono";
import { getCookie } from "hono/cookie";
import type { Context } from "hono";
import type { AppEnv } from "../env";
import { loadAccountUser, type AccountUser } from "../lib/accounts";
import { audit } from "../lib/audit";
import { randomToken, sha256Hex } from "../lib/crypto";
import { signRs256, signingKey, verifyAccessToken, verifyIdTokenHint, verifyPkce } from "../lib/oidc";
import { rateLimit } from "../lib/ratelimit";
import { SESSION_COOKIE, destroySession, revokeSessionAndNotify } from "../lib/session";
import { clientIp, nowIso, parseUris } from "../lib/util";
import { oidcErrorPage } from "../web/pages";

const app = new Hono<AppEnv>();

// ---------- 共用小件 ----------

const ALLOWED_SCOPES = ["openid", "profile", "email", "offline_access"];

type AppRow = {
  client_id: string;
  redirect_uris: string;
  post_logout_redirect_uris: string;
};

// app 表不做 isolate 缓存：测试与将来的运维脚本都可能直接改 app 行（redirect_uri 白名单），
// 缓存 60s 会让改白名单后 authorize 短暂全挂（本轮测试实测）；一次 D1 点查成本可接受。
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
      "sid",
      "locked",
      "must_change_pw",
      "disabled",
      "roles",
      "permissions",
      "qq",
    ],
    authorization_response_iss_parameter_supported: true,
    backchannel_logout_supported: true,
    backchannel_logout_session_supported: true,
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

/** parseAuthorize 的结果三分支：
 *  - invalid_client：client/redirect_uri 对不上，连跳转目标都没验证过，只能渲染错误页（防开放跳转）；
 *  - rp_error：参数问题，可安全跳回 client 带 error 参数；
 *  - ok：全部校验通过，可以发码。 */
type ParsedAuthorize =
  | { kind: "invalid_client" }
  | { kind: "rp_error"; redirectUri: string; error: string; description: string; state?: string }
  | {
      kind: "ok";
      clientId: string;
      redirectUri: string;
      state?: string;
      scopes: string[];
      challenge: string;
      nonce: string | null;
    };

/** 校验 /authorize 的全部请求参数（GET /authorize 与 POST /login 内联发码共用，口径一字不差）。
 *  url 传含 query 的完整 authorize 地址；query 直接取自该 URL。 */
export async function parseAuthorize(c: Context<AppEnv>, authorizeUrl: URL): Promise<ParsedAuthorize> {
  const clientId = authorizeUrl.searchParams.get("client_id") ?? "";
  const redirectUri = authorizeUrl.searchParams.get("redirect_uri") ?? "";
  const app_ = clientId && redirectUri ? await loadApp(c, clientId) : null;
  // client 与 redirect_uri 逐字精确匹配；匹配不上就渲染错误页而不是跳转——
  // 跳转目标本身还没被验证，开放跳转就是这么来的
  if (!app_ || redirectUri.includes("#") || !parseUris(app_.redirect_uris).includes(redirectUri)) {
    return { kind: "invalid_client" };
  }

  const state = authorizeUrl.searchParams.get("state") ?? undefined;
  const fail = (error: string, description: string) => ({
    kind: "rp_error" as const,
    redirectUri,
    error,
    description,
    state,
  });

  if (authorizeUrl.searchParams.get("response_type") !== "code") return fail("unsupported_response_type", "只支持 code 流程");
  const scopes = (authorizeUrl.searchParams.get("scope") ?? "").split(" ").filter(Boolean);
  if (!scopes.includes("openid")) return fail("invalid_scope", "scope 需要包含 openid");
  if (scopes.some((s) => !ALLOWED_SCOPES.includes(s))) return fail("invalid_scope", "scope 超出允许范围");
  const challenge = authorizeUrl.searchParams.get("code_challenge") ?? "";
  // S256 的 challenge 恒为 43 位 base64url；PKCE 强制（TECH_DESIGN §8.3）
  if (!/^[A-Za-z0-9\-_]{43}$/.test(challenge) || authorizeUrl.searchParams.get("code_challenge_method") !== "S256") {
    return fail("invalid_request", "必须携带 PKCE code_challenge（method=S256）");
  }
  return {
    kind: "ok",
    clientId,
    redirectUri,
    state,
    scopes,
    challenge,
    nonce: authorizeUrl.searchParams.get("nonce") || null,
  };
}

/** 发授权码：机会性清理过期码（后台）+ 写新码 + 构造回跳 client 的 URL（RFC 9207 带 iss）。
 *  sessionHash 由调用方提供（GET /authorize 用 cookie、POST /login 用刚建的令牌），同一套码表。 */
export async function issueCode(
  c: Context<AppEnv>,
  user: { id: number },
  parsed: Extract<ParsedAuthorize, { kind: "ok" }>,
  sessionHash: string,
): Promise<string> {
  const code = randomToken(32);
  const iss = new URL(c.req.url).origin;
  // 机会性清理过期授权码（行本体不自动消失，控制表体积；≤50 用户量级下成本可忽略）。
  // waitUntil 后台跑不挡发码；app.request 直调（测试）没有 executionCtx 时就地 await。
  const cleanup = c.env.DB.prepare("DELETE FROM oidc_code WHERE expires_at < ?")
    .bind(new Date().toISOString())
    .run();
  await c.env.DB.prepare(
    `INSERT INTO oidc_code
       (code_hash, account_id, client_id, redirect_uri, scope, nonce, code_challenge,
        code_challenge_method, session_hash, created_at, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, 'S256', ?, ?, ?)`,
  )
    .bind(
      await sha256Hex(code),
      user.id,
      parsed.clientId,
      parsed.redirectUri,
      parsed.scopes.join(" "),
      parsed.nonce,
      parsed.challenge,
      sessionHash,
      new Date().toISOString(),
      new Date(Date.now() + 60_000).toISOString(),
    )
    .run();
  // 过期码清理：生产 waitUntil 后台、测试就地等待（runDetached 返回值统一可 await）
  await runDetached(c, cleanup.catch((err) => console.error("过期授权码清理失败：", err)));

  const target = new URL(parsed.redirectUri);
  target.searchParams.set("code", code);
  if (parsed.state !== undefined) target.searchParams.set("state", parsed.state);
  target.searchParams.set("iss", iss); // RFC 9207：client 可自查响应来自哪个授权服务，防混用
  return target.toString();
}

/** 有 executionCtx 就 waitUntil 后台跑，没有（测试 app.request 直调）就地 await。
 *  登录/发码热路径的旁支写操作共用这个小件。 */
export function runDetached(c: Context<AppEnv>, job: Promise<unknown>): Promise<unknown> {
  try {
    c.executionCtx.waitUntil(job);
    return Promise.resolve(null);
  } catch {
    return job;
  }
}

app.get("/authorize", async (c) => {
  if (!(await rateLimit(c.env, `authz:${clientIp(c)}`, 60, 900))) {
    return c.html(oidcErrorPage("请求太频繁", "操作太密集，请 15 分钟后再试。"), 429);
  }
  const parsed = await parseAuthorize(c, new URL(c.req.url));
  if (parsed.kind === "invalid_client") {
    return c.html(
      oidcErrorPage("无法处理这个登录请求", "发起登录的应用不在接入名单里，或回调地址不对。请联系管理员。"),
      400,
    );
  }
  if (parsed.kind === "rp_error") {
    return c.redirect(oauthError(parsed.redirectUri, parsed.error, parsed.description, parsed.state), 303);
  }

  const sessionToken = getCookie(c, SESSION_COOKIE);
  if (!sessionToken || !c.get("user")) {
    // prompt=none（OIDC Core §3.1.2.1）：静默探测不许弹交互页——未登录按规范回 RP 错误，
    // 三系统的自动同步探测全靠这里兜住，绝不打扰未登录访客
    if (c.req.query("prompt") === "none") {
      return c.redirect(oauthError(parsed.redirectUri, "login_required", "需要登录", parsed.state), 303);
    }
    // 未登录：先登录，回来时原样重放本请求（state/nonce/challenge 全保留），实现静默单点登录
    const next = `/authorize${new URL(c.req.url).search}`;
    return c.redirect(`/login?next=${encodeURIComponent(next)}`, 303);
  }
  // must_change_pw 门禁（原在 index.ts 中间件，现移入此处——见 PW_EXEMPT_PATHS 注释）：
  // 普通请求跳改密页保 next 链路；prompt=none 探测按规范回 interaction_required，保持静默
  if (c.get("user")!.mustChangePassword) {
    const next = `/authorize${new URL(c.req.url).search}`;
    if (c.req.query("prompt") === "none") {
      return c.redirect(oauthError(parsed.redirectUri, "interaction_required", "需要先修改密码", parsed.state), 303);
    }
    return c.redirect(`/password?next=${encodeURIComponent(next)}`, 303);
  }

  // 发码 + 303 直跳 client（登录页内联发码走同一函数，见 pages.ts 的 POST /login）
  const target = await issueCode(c, c.get("user")!, parsed, await sha256Hex(sessionToken));
  return c.redirect(target, 303);
});

// ---------- token 端点（code 换取 + refresh 轮换） ----------

type OidcCodeRow = {
  code_hash: string;
  account_id: number;
  client_id: string;
  redirect_uri: string;
  scope: string;
  nonce: string | null;
  code_challenge: string;
  session_hash: string;
  consumed_at: string | null;
};

type OidcRefreshRow = {
  token_hash: string;
  account_id: number;
  client_id: string;
  scope: string;
  code_hash: string | null;
  family_id: string;
  session_hash: string;
  rotated_at: string | null;
  revoked_at: string | null;
};

const ACCESS_TTL = 1800; // 30 分钟（TECH_DESIGN §3）
const ID_TTL = 600; // 10 分钟
const REFRESH_TTL = 7 * 24 * 3600; // 对齐 auth 会话 7 天

/** OAuth 错误响应（token/revoke）；no-store 是规范要求（token 响应不得入缓存） */
function oauthJsonError(c: Context<AppEnv>, error: string, description: string, status: 400 | 401 | 429 = 400) {
  return c.json({ error, error_description: description }, status, {
    "Cache-Control": "no-store",
    Pragma: "no-cache",
  });
}

async function issueTokens(
  c: Context<AppEnv>,
  args: {
    accountId: number;
    clientId: string;
    scope: string;
    sessionHash: string;
    codeHash: string | null;
    familyId: string | null;
    nonce: string | null;
    user: AccountUser;
  },
): Promise<Record<string, unknown>> {
  const iss = new URL(c.req.url).origin;
  const scopes = args.scope.split(" ").filter(Boolean);
  const access = await signRs256(
    c.env,
    iss,
    { sub: String(args.accountId), aud: args.clientId, scope: args.scope, jti: randomToken(16) },
    ACCESS_TTL,
  );
  // ID token 保持最小集：身份信息走 userinfo（§6.3 按 aud 过滤，token 体积可控）；
  // sid = 登录会话指纹，RP 存下来即可被 back-channel 登出按会话精准命中
  const idClaims: Record<string, unknown> = { sub: String(args.accountId), aud: args.clientId, sid: args.sessionHash };
  if (args.nonce) idClaims.nonce = args.nonce;
  if (scopes.includes("profile")) idClaims.name = args.user.name;
  const idToken = await signRs256(c.env, iss, idClaims, ID_TTL);
  const refresh = randomToken(32);
  await c.env.DB.prepare(
    `INSERT INTO oidc_refresh
       (token_hash, account_id, client_id, scope, code_hash, family_id, session_hash, created_at, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      await sha256Hex(refresh),
      args.accountId,
      args.clientId,
      args.scope,
      args.codeHash,
      args.familyId ?? randomToken(16), // 新 code 换取开新轮换族，轮换沿用原族
      args.sessionHash,
      nowIso(),
      new Date(Date.now() + REFRESH_TTL * 1000).toISOString(),
    )
    .run();
  return {
    access_token: access,
    token_type: "Bearer",
    expires_in: ACCESS_TTL,
    refresh_token: refresh,
    scope: args.scope,
    id_token: idToken,
  };
}

/** 角色 = user_role 授权投影（账号收口后唯一来源，§6.2）；按 aud 过滤防跨系统信息泄漏（§6.3） */
async function rolesForAud(c: Context<AppEnv>, accountId: number, aud: string): Promise<string[]> {
  const rows = await c.env.DB.prepare(
    "SELECT r.app_id AS app_id, r.key AS role_key FROM user_role ur JOIN role r ON ur.role_id = r.id WHERE ur.account_id = ? AND (r.app_id = ? OR r.app_id IS NULL)",
  )
    .bind(accountId, aud)
    .all<{ app_id: string | null; role_key: string }>();
  // 角色键带 app 前缀（如 club.admin），全局角色裸键（superadmin）；
  // user_role 主键保证同一角色至多一行，无需去重
  return rows.results.map((r) => (r.app_id === null ? r.role_key : `${r.app_id}.${r.role_key}`));
}

/**
 * 权限点 = 角色派生 ∪ 账号级额外授予（v2.0.0「权限点额外授予」，migrations/0009_admin.sql）。
 * 一条 UNION SQL 直出：原实现是「全表拉 role_permission 再在 JS 里按角色集过滤」，
 * 每台实例每次 userinfo 都要把多系统的映射全读一遍；改成按 account_id 收窄后，
 * 读的行数只与本账号的授权数相关，且和账号级授予一次取齐（不新增往返）。
 *
 * 角色派生分支与改造前逐字等价：R.app_id ∈ {aud, NULL} 且账号持有 R。全局角色（app_id IS NULL）
 * 仍按原样下发其全部权限点（superadmin 即如此拿到全部）；新增的账号级授予则收紧到 p.app_id = aud，
 * 防止在某个 aud 下泄出别的系统的权限点。
 */
async function permissionsFor(c: Context<AppEnv>, aud: string, accountId: number): Promise<string[]> {
  const rows = await c.env.DB.prepare(
    `SELECT p.key AS perm_key
       FROM user_role ur
       JOIN role r ON r.id = ur.role_id
       JOIN role_permission rp ON rp.role_id = r.id
       JOIN permission p ON p.id = rp.permission_id
      WHERE ur.account_id = ? AND (r.app_id = ? OR r.app_id IS NULL)
     UNION
     SELECT p.key AS perm_key
       FROM account_permission ap
       JOIN permission p ON p.id = ap.permission_id
      WHERE ap.account_id = ? AND p.app_id = ?`,
  )
    .bind(accountId, aud, accountId, aud)
    .all<{ perm_key: string }>();
  return rows.results.map((r) => r.perm_key);
}

app.post("/token", async (c) => {
  if (!(await rateLimit(c.env, `token:${clientIp(c)}`, 30, 900))) {
    return oauthJsonError(c, "invalid_request", "请求太频繁，请 15 分钟后再试", 429);
  }
  const form = (await c.req.parseBody().catch(() => ({}))) as Record<string, unknown>;
  const val = (k: string) => (typeof form[k] === "string" ? (form[k] as string) : "");
  const clientId = val("client_id");
  const grantType = val("grant_type");
  if (!clientId) return oauthJsonError(c, "invalid_request", "需要 client_id");
  // 全部为公开 client（PKCE 强制，不设 client_secret），client 校验 = 存在于 app 表
  if (!(await loadApp(c, clientId))) return oauthJsonError(c, "invalid_client", "client_id 不存在", 401);

  if (grantType === "authorization_code") {
    const code = val("code");
    const redirectUri = val("redirect_uri");
    const verifier = val("code_verifier");
    if (!code || !redirectUri || !verifier) {
      return oauthJsonError(c, "invalid_request", "需要 code、redirect_uri、code_verifier");
    }
    const codeHash = await sha256Hex(code);
    const row = await c.env.DB.prepare("SELECT * FROM oidc_code WHERE code_hash = ?").bind(codeHash).first<OidcCodeRow>();
    // 原子消费 = 一次性（§8.2）；过期或已消费都改不动这一行
    const now = nowIso();
    const consume = await c.env.DB.prepare(
      "UPDATE oidc_code SET consumed_at = ? WHERE code_hash = ? AND consumed_at IS NULL AND expires_at > ?",
    )
      .bind(now, codeHash, now)
      .run();
    if (consume.meta.changes !== 1 || !row) {
      if (row?.consumed_at) {
        // 授权码重放：吊销这个 code 换出的所有 refresh（RFC 6749 §4.1.2 的处置）
        await c.env.DB.prepare("UPDATE oidc_refresh SET revoked_at = ? WHERE code_hash = ? AND revoked_at IS NULL")
          .bind(now, codeHash)
          .run();
        await audit(c, "oidc.code_replay", { accountId: row.account_id, detail: { client_id: row.client_id } });
      }
      return oauthJsonError(c, "invalid_grant", "授权码无效、已使用或已过期");
    }
    if (row.client_id !== clientId || row.redirect_uri !== redirectUri) {
      return oauthJsonError(c, "invalid_grant", "client 或 redirect_uri 与发码时不一致");
    }
    if (!(await verifyPkce(row.code_challenge, verifier))) {
      return oauthJsonError(c, "invalid_grant", "PKCE 校验失败");
    }
    // 会话吊销联动：发码用的登录会话若已登出，code 随之作废。
    // 兼容桥已停写（登录提速），会话只可能来自 auth 登录/注册，D1 必有行——查无行=非法 session_hash，
    // 按「登录会话已结束」拒绝（过渡期"无行按存活"的口径随 9-21 旧 KV 会话 TTL 归零后收紧）。
    const sess = await c.env.DB.prepare(
      "SELECT s.revoked_at, s.expires_at, a.disabled_at FROM session s JOIN account a ON a.id = s.account_id WHERE s.token_hash = ?",
    )
      .bind(row.session_hash)
      .first<{ revoked_at: string | null; expires_at: string; disabled_at: string | null }>();
    // 停用账号（v2.0.0）在换取 token 这一步也拦一道：停用时会批量吊销会话，但停用与吊销之间
    // 已在浏览器里发起的换码请求仍可能到达，这里花 0 次额外往返堵住它。
    if (!sess || sess.revoked_at || sess.expires_at <= nowIso() || sess.disabled_at)
      return oauthJsonError(c, "invalid_grant", "登录会话已结束，请重新登录");
    const user = await loadAccountUser(c, row.account_id);
    if (!user) return oauthJsonError(c, "invalid_grant", "账号不存在");
    const body = await issueTokens(c, {
      accountId: row.account_id,
      clientId,
      scope: row.scope,
      sessionHash: row.session_hash,
      codeHash,
      familyId: null,
      nonce: row.nonce,
      user,
    });
    return c.json(body, 200, { "Cache-Control": "no-store", Pragma: "no-cache" });
  }

  if (grantType === "refresh_token") {
    const token = val("refresh_token");
    if (!token) return oauthJsonError(c, "invalid_request", "需要 refresh_token");
    const tokenHash = await sha256Hex(token);
    const row = await c.env.DB.prepare("SELECT * FROM oidc_refresh WHERE token_hash = ?").bind(tokenHash).first<OidcRefreshRow>();
    if (!row || row.client_id !== clientId) return oauthJsonError(c, "invalid_grant", "refresh token 无效");
    const now = nowIso();
    // 原子轮换：同一 token 并发双花只有一个 UPDATE 成功，失败方一律按重用处理
    const rotate = await c.env.DB.prepare(
      "UPDATE oidc_refresh SET rotated_at = ?, revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ?",
    )
      .bind(now, now, tokenHash, now)
      .run();
    if (rotate.meta.changes !== 1) {
      if (row.rotated_at) {
        // 重用检测（§8.6）：轮换过的 token 再次出现，视同被盗，吊销整族
        await c.env.DB.prepare("UPDATE oidc_refresh SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL")
          .bind(now, row.family_id)
          .run();
        await audit(c, "oidc.refresh_reuse", {
          accountId: row.account_id,
          detail: { client_id: row.client_id, family_id: row.family_id },
        });
      }
      return oauthJsonError(c, "invalid_grant", "refresh token 无效、已轮换或已过期");
    }
    const user = await loadAccountUser(c, row.account_id);
    if (!user) return oauthJsonError(c, "invalid_grant", "账号不存在");
    if (user.disabledAt) return oauthJsonError(c, "invalid_grant", "账号已被停用");
    // 刷新请求的 scope 参数按原 scope 处理（不支持缩窄，避免接入方误传把权限越刷越小）；
    // 刷新签发的 ID token 不带 nonce（OIDC Core §12.2）；沿用原 scope 与轮换族
    const body = await issueTokens(c, {
      accountId: row.account_id,
      clientId,
      scope: row.scope,
      sessionHash: row.session_hash,
      codeHash: row.code_hash,
      familyId: row.family_id,
      nonce: null,
      user,
    });
    return c.json(body, 200, { "Cache-Control": "no-store", Pragma: "no-cache" });
  }

  return oauthJsonError(c, "unsupported_grant_type", "只支持 authorization_code 和 refresh_token");
});

// ---------- userinfo ----------

app.get("/userinfo", async (c) => {
  // 纵深防御（TEST_REPORT L-2）：Bearer 已把门，这里只挡无 token 的高速扫描
  if (!(await rateLimit(c.env, `userinfo:${clientIp(c)}`, 600, 900))) {
    return oauthJsonError(c, "invalid_request", "请求太频繁，请 15 分钟后再试", 429);
  }
  const m = /^Bearer\s+(.+)$/i.exec(c.req.header("Authorization") ?? "");
  const iss = new URL(c.req.url).origin;
  const at = m ? await verifyAccessToken(c.env, iss, m[1]) : null;
  if (!at) {
    return c.json({ error: "invalid_token" }, 401, { "WWW-Authenticate": 'Bearer error="invalid_token"' });
  }
  const accountId = Number(at.sub);
  const user = Number.isInteger(accountId) ? await loadAccountUser(c, accountId) : null;
  if (!user) {
    return c.json({ error: "invalid_token" }, 401, { "WWW-Authenticate": 'Bearer error="invalid_token"' });
  }
  // 停用账号（v2.0.0）：token 还在有效期内（access 30 分钟 / refresh 7 天）也必须立刻失去
  // 角色与权限点——RP 是拿 userinfo 的 roles/permissions 做鉴权的，置空等于当场降权。
  // 会话列表 / 单会话吊销也已把停用置为拒绝条件，这里是同一判定在 token 通道上的对应实现。
  const disabled = user.disabledAt !== null;
  // 角色/权限点按 access token 的 aud 过滤，防止跨系统信息泄漏（TECH_DESIGN §6.3）
  const roles = disabled ? [] : await rolesForAud(c, user.id, at.aud);
  const qq = await c.env.DB.prepare(
    "SELECT provider_uid FROM identity WHERE account_id = ? AND provider = 'qq' LIMIT 1",
  )
    .bind(user.id)
    .first<{ provider_uid: string }>();
  const out: Record<string, unknown> = {
    sub: String(user.id),
    locked: user.locked,
    must_change_pw: user.mustChangePassword,
    disabled,
    roles,
    permissions: disabled ? [] : await permissionsFor(c, at.aud, user.id),
    qq: qq?.provider_uid ?? null,
  };
  const scopes = at.scope.split(" ");
  if (scopes.includes("profile")) {
    out.name = user.name;
    out.preferred_username = user.name;
  }
  if (scopes.includes("email")) out.email = user.email; // 可能为 null（邮箱本就选填）
  return c.json(out);
});

// ---------- 吊销（RFC 7009） ----------

app.post("/revoke", async (c) => {
  if (!(await rateLimit(c.env, `revoke:${clientIp(c)}`, 30, 900))) {
    return oauthJsonError(c, "invalid_request", "请求太频繁，请 15 分钟后再试", 429);
  }
  const form = (await c.req.parseBody().catch(() => ({}))) as Record<string, unknown>;
  const val = (k: string) => (typeof form[k] === "string" ? (form[k] as string) : "");
  const clientId = val("client_id");
  const token = val("token");
  if (!clientId || !token) return oauthJsonError(c, "invalid_request", "需要 client_id 与 token");
  if (!(await loadApp(c, clientId))) return oauthJsonError(c, "invalid_client", "client_id 不存在", 401);
  // RFC 7009：无效 token 也回 200，不向调用方泄漏 token 存在性；只吊销属于自己的 refresh
  await c.env.DB.prepare(
    "UPDATE oidc_refresh SET revoked_at = ? WHERE token_hash = ? AND client_id = ? AND revoked_at IS NULL",
  )
    .bind(nowIso(), await sha256Hex(token), clientId)
    .run();
  // access token 是无状态 JWT，靠 30 分钟短 TTL 兜底，不做吊销黑名单（取舍：查询成本 > 收益）
  return c.body(null, 200);
});

// ---------- 登出（end_session_endpoint，RP 发起） ----------

app.get("/logout", async (c) => {
  // 跨站顶层导航同样会带上 SameSite=Lax 的会话 cookie，等于允许第三方页面强制登出本人（L-1）。
  // 生态三系统同属 *.whleague.win（Sec-Fetch-Site: same-site），只有真正 cross-site 才拦；
  // 不发这个头的旧浏览器按放行处理（fail-open），如实记在 TEST_REPORT L-1。
  if ((c.req.header("Sec-Fetch-Site") ?? "").toLowerCase() === "cross-site") {
    return c.redirect("/login", 303);
  }
  const iss = new URL(c.req.url).origin;
  const postLogout = c.req.query("post_logout_redirect_uri");
  const state = c.req.query("state");
  const hint = c.req.query("id_token_hint");
  if (hint) await verifyIdTokenHint(c.env, iss, hint); // 只作佐证，无效不阻断登出
  const sessionToken = getCookie(c, SESSION_COOKIE);
  const user = c.get("user");
  if (sessionToken) {
    // §3 登出语义：吊销 auth 会话 + 该会话签发的全部 token，并向各 client 发 back-channel 通知
    await revokeSessionAndNotify(c, await sha256Hex(sessionToken));
    await destroySession(c);
    if (user) await audit(c, "logout", { accountId: user.id, detail: { via: "end_session" } });
  }
  if (postLogout) {
    const apps = await c.env.DB.prepare("SELECT post_logout_redirect_uris FROM app").all<{
      post_logout_redirect_uris: string;
    }>();
    if (apps.results.some((r) => parseUris(r.post_logout_redirect_uris).includes(postLogout))) {
      const target = new URL(postLogout);
      if (state !== undefined) target.searchParams.set("state", state);
      return c.redirect(target.toString(), 303);
    }
  }
  return c.redirect("/login", 303);
});

export default app;
