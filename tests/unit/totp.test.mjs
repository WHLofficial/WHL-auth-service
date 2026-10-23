// TOTP（RFC 6238）单元测试：标准向量 + 时间窗/重放语义 + base32 边界。
import { test } from "node:test";
import assert from "node:assert/strict";
import { base32Decode, base32Encode, currentTotpStep, totpCode, verifyTotp } from "../../src/lib/totp.ts";

// RFC 4226 附录 D 的 ASCII secret "12345678901234567890" 的 base32
const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

test("base32 编解码往返", () => {
  const bytes = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
  const round = base32Decode(base32Encode(bytes));
  assert.deepEqual([...round], [...bytes]);
});

test("RFC 6238 SHA-1 标准向量（截取 6 位）", async () => {
  const vectors = [
    [59, "287082"],
    [1111111109, "081804"],
    [1111111111, "050471"],
    [1234567890, "005924"],
    [2000000000, "279037"],
    [20000000000, "353130"],
  ];
  for (const [t, expected] of vectors) {
    assert.equal(await totpCode(RFC_SECRET, Math.floor(t / 30)), expected, `T=${t}`);
  }
});

test("verifyTotp 接受窗口内验证码，拒绝已用过的 step 与格式错误", async () => {
  const step = currentTotpStep();
  const code = await totpCode(RFC_SECRET, step);
  assert.equal(await verifyTotp(RFC_SECRET, code, 0), step);
  assert.equal(await verifyTotp(RFC_SECRET, code, step), null, "同一 step 不得重放");
  assert.equal(await verifyTotp(RFC_SECRET, code, step - 1), step);
  assert.equal(await verifyTotp(RFC_SECRET, "12345"), null);
  assert.equal(await verifyTotp(RFC_SECRET, "abcdef"), null);
  assert.equal(await verifyTotp(RFC_SECRET, ` ${code} `, 0), step, "允许空格");
});
