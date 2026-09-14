// 令牌签发与校验：算法钉死、iss 校验、密钥强度下限、JWKS 只暴露公开参数、
// PKCE 校验、back-channel logout_token 的规范字段。
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, createPublicKey, generateKeyPairSync } from "node:crypto";
import { SignJWT, decodeJwt, decodeProtectedHeader, jwtVerify, importJWK } from "jose";
import { signLogoutToken, signRs256, signingKey, verifyAccessToken, verifyIdTokenHint, verifyPkce } from "../../src/lib/oidc.ts";

const ISS = "https://auth.test";

function makeKey(modulusLength = 2048) {
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength });
  return privateKey.export({ type: "pkcs8", format: "pem" }).toString();
}

const key2048 = makeKey(2048);
const env2048 = { AUTH_JWT_PRIVATE_KEY: key2048 };

test("signingKey 暴露的 JWK 只有公开参数（不得含 d/p/q 等私钥字段）", async () => {
  const { publicJwk, kid } = await signingKey(env2048);
  assert.deepEqual(Object.keys(publicJwk).sort(), ["alg", "e", "kid", "kty", "n", "use"]);
  for (const k of ["d", "p", "q", "dp", "dq", "qi"]) assert.equal(publicJwk[k], undefined, `不应导出 ${k}`);
  assert.equal(publicJwk.kty, "RSA");
  assert.equal(publicJwk.alg, "RS256");
  assert.equal(publicJwk.use, "sig");
  assert.equal(publicJwk.kid, kid);
  assert.ok(kid.length >= 32, `kid 应为 SHA-256 指纹（base64url），实际 ${kid}`);
});

test("同一密钥重复取用 kid 稳定（缓存命中，不改变 JWKS 指纹）", async () => {
  const a = await signingKey(env2048);
  const b = await signingKey(env2048);
  assert.equal(a.kid, b.kid);
});

test("小于 2048 位的 RSA 密钥被拒绝", async () => {
  await assert.rejects(() => signingKey({ AUTH_JWT_PRIVATE_KEY: makeKey(1024) }), /RSA 密钥强度不足|2048/);
});

test("未配置密钥时明确报错，而不是静默签空密钥", async () => {
  // 空串 / 缺失走显式报错分支
  await assert.rejects(() => signingKey({}), /AUTH_JWT_PRIVATE_KEY/);
  await assert.rejects(() => signingKey({ AUTH_JWT_PRIVATE_KEY: "" }), /AUTH_JWT_PRIVATE_KEY/);
  // 纯空白只被 trim 后判空才走同一分支；否则落到密钥解析失败——两种都不得放行
  await assert.rejects(() => signingKey({ AUTH_JWT_PRIVATE_KEY: "   " }), /AUTH_JWT_PRIVATE_KEY|Failed to read private key|Invalid keyData/);
});

test("单行 base64（去 PEM 头尾）与 PEM 等价，都能解析出同一 kid", async () => {
  const bare = key2048.replace(/-----[A-Z]+ PRIVATE KEY-----/g, "").replace(/\s+/g, "");
  const a = await signingKey(env2048);
  const b = await signingKey({ AUTH_JWT_PRIVATE_KEY: bare });
  assert.equal(a.kid, b.kid);
});

test("签发的 access token：RS256 + 指定 kid，exp-iat 等于 TTL，iss 正确", async () => {
  const ttl = 1800;
  const token = await signRs256(env2048, ISS, { sub: "42", aud: "tour", scope: "openid profile", jti: "j1" }, ttl);
  const header = decodeProtectedHeader(token);
  const { kid } = await signingKey(env2048);
  assert.equal(header.alg, "RS256");
  assert.equal(header.kid, kid);
  const payload = decodeJwt(token);
  assert.equal(payload.iss, ISS);
  assert.equal(payload.sub, "42");
  assert.equal(payload.aud, "tour");
  assert.equal(payload.exp - payload.iat, ttl);
});

test("verifyAccessToken 接受自己签发的 token 并回传关键声明", async () => {
  const token = await signRs256(env2048, ISS, { sub: "42", aud: "tour", scope: "openid", jti: "j1" }, 1800);
  const at = await verifyAccessToken(env2048, ISS, token);
  assert.ok(at);
  assert.equal(at.sub, "42");
  assert.equal(at.aud, "tour");
  assert.equal(at.scope, "openid");
  assert.equal(at.jti, "j1");
});

test("verifyAccessToken 拒绝：已过期 / iss 不符 / 算法替换 / 缺 jti / 缺 scope / 垃圾串", async () => {
  const expired = await signRs256(env2048, ISS, { sub: "42", aud: "tour", scope: "openid", jti: "j1" }, -10);
  assert.equal(await verifyAccessToken(env2048, ISS, expired), null, "过期应拒绝");

  const ok = await signRs256(env2048, ISS, { sub: "42", aud: "tour", scope: "openid", jti: "j1" }, 1800);
  assert.equal(await verifyAccessToken(env2048, "https://other.issuer", ok), null, "iss 不符应拒绝");

  const noJti = await signRs256(env2048, ISS, { sub: "42", aud: "tour", scope: "openid" }, 1800);
  assert.equal(await verifyAccessToken(env2048, ISS, noJti), null, "缺 jti 应拒绝");

  const noScope = await signRs256(env2048, ISS, { sub: "42", aud: "tour", jti: "j1" }, 1800);
  assert.equal(await verifyAccessToken(env2048, ISS, noScope), null, "缺 scope 应拒绝");

  assert.equal(await verifyAccessToken(env2048, ISS, "not.a.jwt"), null);
  assert.equal(await verifyAccessToken(env2048, ISS, ""), null);
});

test("算法混淆攻击被挡住：用公钥 PEM 当 HMAC 密钥签的 HS256 token 不被接受", async () => {
  // 攻击者拿得到 JWKS 里的公钥；这里等价地直接从私钥导出公钥 PEM 当 HMAC 密钥
  const publicPem = createPublicKey(key2048).export({ type: "spki", format: "pem" }).toString();
  const forged = await new SignJWT({ sub: "42", aud: "tour", scope: "openid", jti: "j1" })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer(ISS)
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(new TextEncoder().encode(publicPem));
  assert.equal(await verifyAccessToken(env2048, ISS, forged), null, "头部 alg 为 HS256，必须拒绝");
});

test("verifyAccessToken 拒绝用 id_token 冒充 access token（aud/sid 结构不同）", async () => {
  const idToken = await signRs256(env2048, ISS, { sub: "42", aud: "tour", sid: "sess1", name: "小明" }, 600);
  assert.equal(await verifyAccessToken(env2048, ISS, idToken), null, "缺 scope/jti，不得当 access token");
});

test("verifyIdTokenHint 只要求 sub 为字符串，且有意不校验 aud（登出提示容错）", async () => {
  const token = await signRs256(env2048, ISS, { sub: "42", aud: "some-other-client" }, 60);
  const hint = await verifyIdTokenHint(env2048, ISS, token);
  assert.ok(hint, "aud 不同也应接受（id_token_hint 仅作佐证）");
  assert.equal(hint.sub, "42");

  const noSub = await signRs256(env2048, ISS, { aud: "tour" }, 60);
  assert.equal(await verifyIdTokenHint(env2048, ISS, noSub), null);
  assert.equal(await verifyIdTokenHint(env2048, "https://other.issuer", token), null, "iss 仍须匹配");
});

test("logout_token：含 back-channel 事件、认 sid、不得带 nonce（规范要求）", async () => {
  const token = await signLogoutToken(env2048, ISS, { aud: "tour", sub: "42", sid: "sess-hash", jti: "lj1" });
  const payload = decodeJwt(token);
  assert.deepEqual(payload.events, { "http://schemas.openid.net/event/backchannel-logout": {} });
  assert.equal(payload.sid, "sess-hash");
  assert.equal(payload.aud, "tour");
  assert.equal(payload.sub, "42");
  assert.equal(payload.nonce, undefined, "logout_token 不得携带 nonce");
  assert.equal(payload.exp, undefined, "按实现不带 exp");
  const { publicJwk, kid } = await signingKey(env2048);
  assert.equal(decodeProtectedHeader(token).kid, kid, "RP 侧要能按 JWKS 的 kid 验签");
  const key = await importJWK(publicJwk, "RS256");
  const verified = await jwtVerify(token, key, { issuer: ISS, audience: "tour" });
  assert.equal(verified.payload.sid, "sess-hash");
});

test("verifyPkce 只接受 S256 结果，且 verifier 必须符合 43-128 位的 unreserved 字符集", async () => {
  const verifier = "A".repeat(43);
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  assert.equal(await verifyPkce(challenge, verifier), true);
  assert.equal(await verifyPkce(challenge, "A".repeat(42)), false, "42 位应拒绝");
  assert.equal(await verifyPkce(challenge, "A".repeat(129)), false, "129 位应拒绝");
  assert.equal(await verifyPkce(challenge, "A".repeat(42) + "!"), false, "非法字符应拒绝");
  assert.equal(await verifyPkce(challenge, "B".repeat(43)), false, "verifier 与 challenge 不匹配应拒绝");
  const plain = createHash("sha256").update(verifier).digest("hex");
  assert.equal(await verifyPkce(plain, verifier), false, "非 base64url 的 challenge 不应通过");
});
