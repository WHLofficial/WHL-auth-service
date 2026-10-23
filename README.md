# WHL-auth-service

WHL 生态统一认证中心（auth.whleague.win）。方案见 [PRD.md](./PRD.md) 与 [TECH_DESIGN.md](./TECH_DESIGN.md)。

## 现状

- **迁移步骤①（已实现）**：登录/注册/改密页，按 tour 旧格式双写共享 KV + auth D1，三系统零改动接入。
- **迁移步骤②（P0-4 已实现）**：OIDC Provider 全套端点，club 试点接入的依赖。
- **迁移步骤③（P0-11 已实现，2026-09-14 上线）**：auth 切读自身 `account`/`credential`，tour `user` 表转只读；tour / guess / club 三站生产已切 OIDC 客户端。
- **v1.0.0（已实现）**：球队绑定真源上收 auth（0008 三表 + 五条 HMAC 机器端点），tour/club 双入口发码烧码写同一张中央表。
- **v2.0.0（已实现）**：账号管理能力落到 auth（0009 + 12 条 HMAC 管理机器端点 `/api/admin/*`），tour 管理台改为转发调用，原先 6 处写自己 `user` 表的死写全部改道。**管理界面仍在 tour 侧，auth 只出能力**。
- **v4.0.0（已实现）**：管理端双因子（`ADMIN_SECRET` + `X-Nonce` + 管理员 access token）、超管强制 TOTP、注册接口不再产生超管。

## 管理能力端点速览（v2.0.0，v4.0.0 起双因子鉴权）

全部 **POST + 服务签名 + 管理员身份**：

1. 服务签名：`X-Sign = hex(HMAC-SHA256(ADMIN_SECRET, "POST|path含query|ts|X-Nonce|rawBody"))`，`X-Timestamp` 为秒级 Unix 时间，窗口 ±300s；`X-Nonce` 必须每次唯一（16-128 位 `[A-Za-z0-9_-]`），auth 落库去重，同一 nonce 第二次直接 401。**管理通道不再使用 `BIND_SECRET`**，两者必须分开配置。
2. 管理员身份：`X-Actor-Token: Bearer <access token>`（或 `Authorization: Bearer ...`）。token 必须由本服务签发且 `aud = ADMIN_AUDIENCE`（默认 `tour`）；auth 侧按 token 的 `sub` 重新查账号与权限点（`tour.accounts.manage` / `tour.org.settings`），不再信任 body 里的 `actor_id`。
3. 超管必须已启用 TOTP，否则管理接口返回 `mfa_required`。

调用方是 tour 管理台（`worker/lib/authAdmin.ts`）；它需要同时持有 `ADMIN_SECRET` 和当前管理员的 access token。操作结果由 auth 记审计（`actor_id` 来自 token），tour 另记一份本地审计。

| 端点 | 说明 |
|------|------|
| `/api/admin/accounts/list` | 账号列表（含绑定球队，LEFT JOIN 零额外往返；keyset 分页） |
| `/api/admin/accounts/detail` | 账号 + 角色 + 额外授予 + 存活会话（含 IP/登录时间/最后活跃）+ QQ，一个 batch 五条语句 |
| `/api/admin/catalog` | 角色 / 权限点 / app / 角色→权限点映射（isolate 缓存 60s） |
| `/api/admin/accounts/roles` `/grants` | 角色全集替换（幂等差集）/ 账号级额外授予；超管改动一律 403 |
| `/api/admin/accounts/password` | 临时密码 + `must_change_pw` + 吊销该账号全部会话 |
| `/api/admin/accounts/unlock` `/disable` | 解锁观众号 / 停用（`disabled_at`，`locked` 语义不动） |
| `/api/admin/sessions/revoke` | 单个会话强制下线或整账号吊销 |
| `/api/admin/org-settings` | 开放注册开关（不带参数 = 读） |
| `/api/admin/signup-codes/create` `/list` | 发注册码（明码只回一次）/ 列表（只给哈希指纹） |

只读的 `/api/admin/identity/lookup`（guess 批量查 QQ）仍走 `BIND_SECRET` 服务通道：不写库、不返回管理数据，不需要用户 token。

## 两步验证与超管初始化（v4.0.0）

- 任何账号都可以在首页 →「两步验证」启用 TOTP；启用时生成 8 个一次性恢复码（只显示一次）。
- **超管强制**：未启用 TOTP 的 superadmin 登录后只能访问 `/mfa/setup`、改密与登出；`/authorize` 对 `prompt=none` 返回 `interaction_required`，普通请求跳设置页；`/token` 的 code/refresh 也会拒绝。
- 登录流程变为「密码 → /mfa 验证码/恢复码 → 建会话」。恢复码用一次即失效；同一 TOTP 时间窗不能重放。
- **注册接口不再产生超管**：新账号固定为 `tour.coach + club.coach`。空库/新环境用带外脚本创建唯一超管：

```sh
node scripts/bootstrap-superadmin.mjs --name root > bootstrap.sql
npx wrangler d1 execute whl-auth --local --file bootstrap.sql   # 生产换 --remote
```

脚本只在「库中不存在任何全局 superadmin」时插入，密码随机生成且只打印一次；昵称已存在时不会把旧账号静默提权。

若超管丢失 TOTP 设备且恢复码也用尽，只能由运维在受信设备上手工重置该账号的 MFA（先确认账号身份；执行后立即用新设备重新绑定）：

```sql
-- 把 :id 换成目标超管账号 id；同时踢掉其全部会话与 refresh token
UPDATE account SET totp_secret=NULL, totp_enabled_at=NULL, totp_last_step=NULL,
                   totp_pending_secret=NULL, totp_pending_at=NULL WHERE id = :id;
DELETE FROM mfa_recovery_code WHERE account_id = :id;
DELETE FROM session WHERE account_id = :id;
UPDATE oidc_refresh SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE account_id = :id AND revoked_at IS NULL;
```

> 首次绑定 TOTP 之前，密码仍是超管的唯一因子：上线后应第一时间用受信设备打开 `/mfa/setup` 完成绑定，再轮换密码。

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
| Secret | `AUTH_JWT_PRIVATE_KEY`（RS256 私钥）、`BIND_SECRET`（QQ 绑定 HMAC）、`ADMIN_SECRET`（管理通道 HMAC，必须与 BIND_SECRET 不同）、`MFA_ENC_KEY`（TOTP secret 静态加密，32 字节 base64 或高熵字符串）、`COOKIE_DOMAIN=.whleague.win` |
| Cron | `23 4 * * *` 清 `rate_limit` / `hmac_nonce` / `mfa_challenge` 过期行（`src/index.ts` 的 `scheduled`） |

部署步骤：

```sh
npx wrangler d1 create whl-auth --location apac          # 产物 id 填进 wrangler.jsonc 的 DB
npx wrangler d1 migrations apply whl-auth --remote       # 含 0012_p0_security（0005 不存在）
npx wrangler secret put AUTH_JWT_PRIVATE_KEY             # 以下值勿入库、勿贴群
npx wrangler secret put BIND_SECRET                      # 与 AstrBot 插件 bind_secret 必须一致
npx wrangler secret put ADMIN_SECRET                     # tour 管理台专用，与 BIND_SECRET 分开并各自轮换
npx wrangler secret put MFA_ENC_KEY                      # 32 字节随机值；生成：node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
npx wrangler secret put COOKIE_DOMAIN                    # .whleague.win
npx wrangler deploy
```

> `ADMIN_AUDIENCE` 默认就是 `tour`，不配置即可。若管理端 token 的 `aud` 不是 `tour`，在 `wrangler.jsonc` 加 `"vars": { "ADMIN_AUDIENCE": "<实际 aud>" }` 后再 deploy；Wrangler 没有 `wrangler vars` 子命令。

> **部署前先查远端迁移账本**：本地开发库出现过「表都在、`d1_migrations` 为空」的历史遗留（此时 `d1 migrations apply` 会以 `table account already exists` 失败）。跑 `npx wrangler d1 execute whl-auth --remote --json --command "SELECT name FROM d1_migrations ORDER BY name"` 确认 0008/0009 是否已记入，未记入的表不要重复 apply（0009 含 `ALTER TABLE`，重复执行会报列已存在）。

> **两个密钥的轮换约束**：`MFA_ENC_KEY` 上线后不要随意更换——现有 TOTP secret 是用旧 key 加密的，换 key 会让超管无法通过验证；确需轮换，先让超管在旧 key 下重绑或清除 MFA。`ADMIN_SECRET` 轮换要同时改 auth 与 tour，两边不一致时管理接口全部 401。

> **上线后第一件事**：用现有超管登录，浏览器打开 `/mfa/setup` 绑定 TOTP 并保存恢复码；在完成绑定前，密码仍是该账号的唯一因子。部署前先确认库里只有一个超管：`SELECT COUNT(*) FROM user_role ur JOIN role r ON r.id=ur.role_id WHERE r.app_id IS NULL AND r.key='superadmin'`；大于 1 说明历史竞态已产生多个，需要人工逐个核对后再移除多余账号的超管角色。

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
