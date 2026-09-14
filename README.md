# WHL-auth-service

WHL 生态统一认证中心（auth.whleague.win）。方案见 [PRD.md](./PRD.md) 与 [TECH_DESIGN.md](./TECH_DESIGN.md)。

## 现状

- **迁移步骤①（已实现）**：登录/注册/改密页，按 tour 旧格式双写共享 KV + auth D1，三系统零改动接入。
- **迁移步骤②（P0-4 已实现）**：OIDC Provider 全套端点，club 试点接入的依赖。
- **迁移步骤③（P0-11 已实现，2026-09-14 上线）**：auth 切读自身 `account`/`credential`，tour `user` 表转只读；tour / guess / club 三站生产已切 OIDC 客户端。

## OIDC 端点速览

| 端点 | 说明 |
|------|------|
| `GET /authorize` | 授权码 + 强制 PKCE（S256）；已登录静默发码，未登录出登录页 |
| `POST /token` | `authorization_code` / `refresh_token` 两种 grant；刷新令牌一次性轮换，重用即吊销整族 |
| `GET /userinfo` | Bearer access token → `sub/name/locked/must_change_pw/roles/permissions/qq`，角色按 `aud` 过滤 |
| `POST /revoke` | 吊销 refresh token（RFC 7009，无效 token 也回 200） |
| `GET /logout` | end_session：吊销会话 + 该会话签发的全部 token，并向各 client 的 `backchannel_logout_uri` 推送 logout_token（back-channel 登出），白名单跳转 |
| `GET /.well-known/openid-configuration` `/jwks.json` | 发现文档与验签公钥（RS256，kid 自动派生） |

token 契约：ID token 10 分钟（带 `sid` = 登录会话指纹，back-channel 登出按它精准吊销）/ access token 30 分钟 / refresh token 7 天（对齐 auth 会话）。
client 全部为公开类型（PKCE 强制，无 client_secret），`redirect_uri` 逐字精确匹配。
角色返回格式：app 内角色带前缀（`club.admin`），全局角色裸键（`superadmin`）；过渡期按 tour 角色现场换算（§6.2 行为等价），`user_role` 播种后自动并轨。

## 本地开发

```sh
npm install
npm run db:migrate:local                      # 建 auth 库表
node scripts/generate-oidc-key.mjs > .dev.vars  # RS256 签名密钥（gitignored）
SQL=$(node scripts/seed-local-users.mjs) && npx wrangler d1 execute whl --local --command "$SQL"
SQL=$(node scripts/seed-local-oidc.mjs) && npx wrangler d1 execute whl-auth --local --command "$SQL"
npm run dev                                   # http://127.0.0.1:8792
node scripts/smoke-oidc.mjs                   # 全链路冒烟（92 项断言，含 back-channel 推送）
```

注意：本地 whl（tour）库需要先有表和用户；seed 脚本会幂等重置 `oidctest` 系列冒烟专用账号（改密用例会真改密码，重跑冒烟前先重新 seed）。

## 生产部署（2026-09-14 已执行）

生产资源：

| 项 | 值 |
|----|----|
| Worker | `whl-auth`，当前 Version `464dcf69-0d5e-4755-a7e1-23aa2ed7d4e5` |
| 自定义域 | `auth.whleague.win`（`routes` 里 `custom_domain`，证书自动签发） |
| D1 | `whl-auth` = `b76d1129-77ae-4844-931c-1c7b00a9b048`（APAC，与其余库同区） |
| Secret | `AUTH_JWT_PRIVATE_KEY`（RS256 私钥）、`BIND_SECRET`（QQ 绑定 HMAC）、`COOKIE_DOMAIN=.whleague.win` |
| Cron | `23 4 * * *` 清 `rate_limit` 表过期窗口行（`src/index.ts` 的 `scheduled`） |

部署步骤（已跑过一遍）：

```sh
npx wrangler d1 create whl-auth --location apac          # 产物 id 填进 wrangler.jsonc 的 DB
npx wrangler d1 migrations apply whl-auth --remote       # 0001/0002/0003/0004/0006/0007（无 0005）
npx wrangler secret put AUTH_JWT_PRIVATE_KEY             # 以下三选一，值勿入库、勿贴群
npx wrangler secret put BIND_SECRET                      # 与 AstrBot 插件 bind_secret 必须一致
npx wrangler secret put COOKIE_DOMAIN                    # .whleague.win
npx wrangler deploy
```

账号数据迁移与闸门（在 tour 仓库侧读生产 tour 库造 SQL，只读 tour、只写 auth）：

```sh
node scripts/migrate-accounts.mjs --remote
node scripts/seed-grants.mjs --remote --guess-db whl-guess
node scripts/verify-accounts.mjs --tour-db whl --auth-db whl-auth --remote   # 必须 exit 0
```

已上线的三个 RP（各自仓库 `wrangler.jsonc` 的 `vars` 配 `OIDC_ISSUER` / `OIDC_CLIENT_ID`）：
tour `cce46620-a68b-40c6-9ee9-8de426f58072`、guess `4ac1e83e-d4ce-46ac-aeb1-0277179a75f9`、club `1fa9173f-aee7-4c83-a509-42e8fbe2eb38`。

回滚：撤掉 RP 的 `vars` 重部署即回兼容模式（旧 Cookie 会话仍有效）；auth 侧轮换 `AUTH_JWT_PRIVATE_KEY` 会让已签发 token 全部失效，用户需重登。

仍需人工的两步：
1. AstrBot 插件 `bind_claim_url` 指向 `https://auth.whleague.win`，`bind_secret` 换成生产值并重启插件。
2. 生产 auth 域名不启 Browser 挑战（Worker 自定义域默认关闭）。
