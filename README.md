# WHL-auth-service

WHL 生态统一认证中心（auth.whleague.win）。方案见 [PRD.md](./PRD.md) 与 [TECH_DESIGN.md](./TECH_DESIGN.md)。

## 现状

- **迁移步骤①（已实现）**：登录/注册/改密页，按 tour 旧格式双写共享 KV + auth D1，三系统零改动接入。
- **迁移步骤②（P0-4 已实现，待接入）**：OIDC Provider 全套端点，club 试点接入的依赖。

## OIDC 端点速览

| 端点 | 说明 |
|------|------|
| `GET /authorize` | 授权码 + 强制 PKCE（S256）；已登录静默发码，未登录出登录页 |
| `POST /token` | `authorization_code` / `refresh_token` 两种 grant；刷新令牌一次性轮换，重用即吊销整族 |
| `GET /userinfo` | Bearer access token → `sub/name/locked/must_change_pw/roles/permissions/qq`，角色按 `aud` 过滤 |
| `POST /revoke` | 吊销 refresh token（RFC 7009，无效 token 也回 200） |
| `GET /logout` | end_session：吊销会话 + 该会话签发的全部 token，白名单跳转 |
| `GET /.well-known/openid-configuration` `/jwks.json` | 发现文档与验签公钥（RS256，kid 自动派生） |

token 契约：ID token 10 分钟 / access token 30 分钟 / refresh token 7 天（对齐 auth 会话）。
client 全部为公开类型（PKCE 强制，无 client_secret），`redirect_uri` 逐字精确匹配。
角色返回格式：app 内角色带前缀（`club.admin`），全局角色裸键（`superadmin`）；过渡期按 tour 角色现场换算（§6.2 行为等价），`user_role` 播种后自动并轨。

## 本地开发

```sh
npm install
npm run db:migrate:local                      # 建 auth 库表
node scripts/generate-oidc-key.mjs > .dev.vars  # RS256 签名密钥（gitignored）
SQL=$(node scripts/seed-local-users.mjs) && npx wrangler d1 execute whl --local --command "$SQL"
npm run dev                                   # http://127.0.0.1:8792
node scripts/smoke-oidc.mjs                   # 全链路冒烟（51 项断言）
```

注意：本地 whl（tour）库需要先有表和用户；seed 脚本会幂等重置 `oidctest` / `oidctest2` 两个冒烟专用账号。

## 部署前置（未执行，等用户确认）

1. `npx wrangler d1 create whl-auth` → 替换 wrangler.jsonc 里 `DB` 的占位 id
2. `npx wrangler kv namespace create RL_KV` → 替换 `RL_KV` 的占位 id
3. `npx wrangler secret put COOKIE_DOMAIN`（`.whleague.win`）、`npx wrangler secret put AUTH_JWT_PRIVATE_KEY`
4. DNS：auth.whleague.win Worker 自定义域；auth 域名不启 Browser 挑战
