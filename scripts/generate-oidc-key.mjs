// 生成本地开发的 RS256 签名密钥：node scripts/generate-oidc-key.mjs
// 输出 AUTH_JWT_PRIVATE_KEY=（PKCS8 DER 的单行 base64，dotenv 友好）。
// 生产环境不用本脚本落文件：生成后直接 npx wrangler secret put AUTH_JWT_PRIVATE_KEY。
// 轮换 = 换一把新密钥（kid 取公钥 JWK 指纹，自动变化）；旧 access/ID token 最长 30/10 分钟后自然失效。
import { generateKeyPairSync } from "node:crypto";

const { privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const der = privateKey.export({ type: "pkcs8", format: "der" });
const b64 = der.toString("base64");

console.log(`AUTH_JWT_PRIVATE_KEY=${b64}`);
