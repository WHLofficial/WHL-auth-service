// 密码与随机原语：哈希格式、常数时间验密、随机 token / 邀请码字符集。
import { test } from "node:test";
import assert from "node:assert/strict";
import { PBKDF2_ITERATIONS, generateCode, hashIterations, hashPassword, randomToken, sha256Hex, verifyPassword } from "../../src/lib/crypto.ts";

test("PBKDF2 迭代数固定在 25000（TECH_DESIGN 口径）", () => {
  assert.equal(PBKDF2_ITERATIONS, 25_000);
});

test("sha256Hex 输出与标准向量一致（异步 API）", async () => {
  assert.equal(await sha256Hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  assert.equal(await sha256Hex(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
});

test("hashPassword 格式为 pbkdf2$iterations$salt$hash，且不含明文", async () => {
  const pw = "TestPass123";
  const stored = await hashPassword(pw);
  assert.match(stored, /^pbkdf2\$25000\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$/);
  assert.ok(!stored.includes(pw), "存档中不应出现明文密码");
  const [, , saltB64, hashB64] = stored.split("$");
  assert.equal(atob(saltB64).length, 16, "盐应为 16 字节");
  assert.equal(atob(hashB64).length, 32, "PBKDF2-SHA256 输出应为 32 字节");
});

test("同密码两次哈希因随机盐而不同（防彩虹表）", async () => {
  const [a, b] = await Promise.all([hashPassword("TestPass123"), hashPassword("TestPass123")]);
  assert.notEqual(a, b);
  assert.equal(await verifyPassword("TestPass123", a), true);
  assert.equal(await verifyPassword("TestPass123", b), true);
});

test("verifyPassword 拒绝错误密码与畸形存档", async () => {
  const stored = await hashPassword("TestPass123");
  assert.equal(await verifyPassword("TestPass124", stored), false);
  assert.equal(await verifyPassword("", stored), false);
  assert.equal(await verifyPassword("testpass123", stored), false);
  assert.equal(await verifyPassword("TestPass123", "pbkdf2$25000$abcd"), false, "字段数不足应拒绝");
  assert.equal(await verifyPassword("TestPass123", "bcrypt$25000$abcd$efgh"), false, "算法标识不符应拒绝");
  assert.equal(await verifyPassword("TestPass123", "pbkdf2$0$YWJjZGVmZ2hpamtsbW5vcA==$YWJjZA=="), false, "非法迭代数应拒绝");
  assert.equal(await verifyPassword("TestPass123", ""), false);
});

test("hashIterations 解析存档迭代数，畸形格式返回 null（透明重哈希判档依据）", () => {
  assert.equal(hashIterations("pbkdf2$25000$AAA$BBB"), 25_000);
  assert.equal(hashIterations("pbkdf2$1000$AAA$BBB"), 1000);
  assert.equal(hashIterations("pbkdf2$0$AAA$BBB"), null, "迭代数非法应返回 null");
  assert.equal(hashIterations("pbkdf2$x$AAA$BBB"), null);
  assert.equal(hashIterations("bcrypt$25000$AAA$BBB"), null, "算法标识不符应返回 null");
  assert.equal(hashIterations("pbkdf2$25000$AAA"), null, "字段数不足应返回 null");
  assert.equal(hashIterations(""), null);
});

test("randomToken 默认 32 字节 → base64url，无 padding 与 +/", () => {
  const t = randomToken();
  assert.match(t, /^[A-Za-z0-9\-_]{43}$/);
  assert.equal(randomToken(16).length, 22);
  const seen = new Set(Array.from({ length: 200 }, () => randomToken()));
  assert.equal(seen.size, 200, "随机 token 不应重复");
});

test("generateCode 只用无歧义字符集（无 I/L/O/0/1）", () => {
  assert.match(generateCode(6), /^[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{6}$/);
  assert.equal(generateCode().length, 8, "默认长度 8");
  for (let i = 0; i < 500; i++) {
    const c = generateCode(6);
    assert.equal(c.length, 6);
    assert.ok(!/[ILO01]/.test(c), `不应出现易混字符：${c}`);
  }
});
