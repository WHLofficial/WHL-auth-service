# WHL-auth-service 网络安全深度审计

- 审计对象：`WHL-auth-service` v3.2.1（Cloudflare Workers + Hono + D1 的 OIDC 账号中枢）
- 审计方式：静态代码审计 + 配置/迁移/脚本检查 + 依赖审计 + 本地测试复核
- 审计范围：`src/` 20 个 TS 文件、`migrations/` 11 个迁移、`scripts/`、`tests/`、`wrangler.jsonc`、`.dev.vars.example`、README/TECH_DESIGN/PRD
- 限制：未接触生产 D1 数据、Cloudflare 控制台与真实 Secret；未做生产环境动态渗透/压测。严重度按“代码可达性 + 前置条件”评估。

## 0. 结论（先看这段）

**没有发现可直接未授权利用的 RCE、SQL 注入或 XSS。** 代码在参数化查询、输出转义、CSRF、PKCE、令牌哈希、限流等方面整体扎实，128 条测试全部通过。

**主要风险不在单点漏洞，而在信任边界：**

1. **管理 API 与 QQ 绑定通道共用同一个 `BIND_SECRET`，且 auth 侧对管理请求零授权**——只验 HMAC，权限判断完全交给 tour，操作者 `actor_id` 由请求体自带。任何拿到 `BIND_SECRET` 的一方（包括 AstrBot QQ 插件宿主机）都能重置除超管外任意账号的密码并拿到临时密码，进而接管账号；还能改角色/权限、停用账号、读取 QQ/邮箱等 PII、打开开放注册。这是本次审计的最高风险。
2. **会话 Cookie 挂在 `.whleague.win` 父域**——`tour/guess/club` 及任何同级子域都会收到 `whl_session`。任一子域被攻破、日志泄漏或存在恶意子域，都能窃取/覆盖会话；Cookie 也没有 `__Host-` 前缀。
3. **口令存储只有 25,000 轮 PBKDF2**（OWASP 2023 对 PBKDF2-HMAC-SHA256 的建议是 600,000 轮），且密码策略仅“8 位 + 字母 + 数字”，无泄露口令检查；一旦 D1 凭证表泄漏，离线破解成本明显偏低。
4. **超管没有 MFA**，仅密码登录；超管虽不能被管理 API 重置密码，但可被钓鱼/撞库。
5. **“首个注册者成为超管”存在竞态与空库重置风险**：`COUNT(*)` 与插入不在同一原子判断里，空库时首个注册者自动获得全局 superadmin。

如果只能先做五件事：**拆分管理密钥并加 nonce→给管理 API 加服务端授权→给超管上 MFA→修首个注册者竞态→把 PBKDF2 提到当前算力允许的上限**。

## 1. 风险总览

| 级别 | 编号 | 问题 | 位置 |
| --- | --- | --- | --- |
| 高（设计级） | H-1 | 管理 API 共用 `BIND_SECRET`、零授权、`actor_id` 可伪造、HMAC 可重放 | `src/lib/machineGate.ts:21-29`、`src/routes/admin.ts:122-131` |
| 高 | H-2 | 会话 Cookie 跨父域共享，任一子域可接收/覆盖 | `src/lib/session.ts:15-17,42-48` |
| 中高 | H-3 | PBKDF2 仅 25,000 轮 + 弱密码策略 | `src/lib/crypto.ts:3`、`src/routes/pages.ts:241-243,352-355` |
| 中高 | H-4 | 超管无 MFA | `src/routes/pages.ts:120-190`、`src/routes/admin.ts:451` |
| 中 | H-5 | 首个注册者超管：竞态 + 空库即 root | `src/routes/pages.ts:247-248,287-301` |
| 中 | M-1 | `prompt=login` / `max_age` 被忽略，旧会话可满足 RP 的“重新认证”要求 | `src/routes/oidc.ts:240-262` |
| 中 | M-2 | `/logout` 顶层 GET 可被跨站强制登出；`post_logout_redirect_uri` 按全部 client 并集校验；hint 结果被忽略 | `src/routes/oidc.ts:587-615` |
| 中 | M-3 | refresh 换取不复查会话存活；会话自然过期后 refresh 仍可能有效 | `src/routes/oidc.ts:469-510` |
| 中 | M-4 | `/userinfo` 无视 scope 返回 QQ 号 | `src/routes/oidc.ts:548-552` |
| 中 | M-5 | 审计 `actor_id` 可伪造；审计/PII 无保留期 | `src/routes/admin.ts:384-385`、`src/lib/audit.ts` |
| 中 | M-6 | 会话 7 天、无空闲超时；访问令牌 30 分钟内无法撤销 | `src/lib/session.ts:10`、`src/routes/oidc.ts:290-292` |
| 中低 | M-7 | 每请求 D1 查询（带 Cookie 时 2 次）可被伪造 Cookie 放大 | `src/index.ts:15-18`、`src/lib/session.ts:55-86` |
| 中低 | M-8 | 依赖公告：Hono 4.13.7 中危；wrangler/miniflare/undici/sharp 高危（开发链） | `package-lock.json` |
| 低 | L-1 | 授权码先消费后校验 client/redirect/PKCE，可被“烧码”DoS | `src/routes/oidc.ts:418-439` |
| 低 | L-2 | 全局角色的权限点跨 aud 下发（当前仅 superadmin，未来新增全局角色会外溢） | `src/routes/oidc.ts:379-398` |
| 低 | L-3 | `machineGate` 先读 body 再验签，无体积上限 | `src/lib/machineGate.ts:23` |
| 低 | L-4 | back-channel HTTP 无超时/私网限制（依赖 app 表可信） | `src/lib/session.ts:145-190` |
| 低 | L-5 | CORS `*` 覆盖 `/token`、`/userinfo`、`/revoke` 等 | `src/routes/oidc.ts:41-48` |
| 低 | L-6 | HSTS 无 `includeSubDomains/preload` | `src/index.ts:45` |
| 低 | L-7 | `int(null)=0` 等宽松数字转换 | `src/lib/machineGate.ts:44-47` |
| 低 | L-8 | 注册昵称可枚举；无账号删除/数据导出；过期 session/refresh/audit 无清理 | `src/routes/pages.ts:273`、`src/index.ts:68-70` |
| 低 | L-9 | 仓库跟踪了生产迁移 SQL/报告（含账号 ID、球队绑定，无密钥） | `migrate-sql-prod.sql`、`migrate-report-prod.md` |

## 2. 详细发现

### H-1（高，设计级）管理 API：一个共享密钥就是账号系统的 root

**证据链**

- `src/lib/machineGate.ts:21-29`：所有机器端点统一从 `c.env.BIND_SECRET` 取密钥，验 `X-Sign = HMAC-SHA256(secret, "POST|path|ts|raw")`，没有第二套管理密钥。
- `src/routes/admin.ts:122-131`：
  ```ts
  const gate = await machineGate(c);
  ...
  return { body, actorId: int(body.actor_id) ?? undefined };
  ```
  `actor_id` 来自请求体，只用于审计和“不能操作自己”的判断，不是可信身份。
- `src/routes/admin.ts` 的 14 个 `/api/admin/*` 端点全部只经过 `machineBody`，没有任何 `actor_id` 权限查询、角色校验或调用方白名单。README 也明确写了：“鉴权由调用方的权限点负责”。
- 同一 `BIND_SECRET` 同时是 QQ 绑定通道的密钥（README:15、67；`src/lib/machineGate.ts` 注释“绑定专用密钥”）。AstrBot 插件必须持有它，才能调 `/api/bind/claim`、`/api/identity/unbind` 等。

**可造成的后果（拿到密钥即可）**

- `POST /api/admin/accounts/password`：重置**任意非超管**账号密码，响应直接返回 `temp_password`（`src/routes/admin.ts:445-481`）；`must_change_pw=1` 只限制登录后的页面，攻击者拿到临时密码后可先登录再改密。
- `POST /api/admin/accounts/roles` / `grants`：给任意账号授予 `tour.admin`、`club.admin` 等角色或权限点（超管角色本身被锁，但应用级管理员可拿）。
- `POST /api/admin/accounts/disable` / `unlock`：停用或解锁账号。
- `POST /api/admin/identity/lookup`：按 account_id 批量读取 QQ 号（PII）。
- `POST /api/admin/accounts/list` / `detail` / `audit/query`：枚举账号、邮箱、IP、审计详情。
- `POST /api/admin/org-settings`：打开开放注册。
- `POST /api/admin/signup-codes/create`：批量生成注册码。
- `POST /api/admin/sessions/revoke`：踢掉任意会话。

**重放放大**：`src/lib/hmac.ts:32` 只校验时间戳 ±300 秒，没有 nonce/jti 缓存。任何被代理、日志、抓包记录下来的管理请求，在 5 分钟内可以原样重放；重放密码重置会生成新的临时密码并再次返回，等于“抓到一次请求就能接管账号”。

**为什么是高危而不是严重**：利用需要先拿到 `BIND_SECRET`。但该密钥的持有者至少包括 tour 管理后端和 AstrBot 插件宿主机；插件宿主机通常不是按“账号系统 root”标准加固的。这是典型的“信任边界画错”，而不是单点代码 bug。

**建议**

1. 立即拆分密钥：`ADMIN_SECRET` 与 `BIND_SECRET` 分离，分别只授予 tour 管理端与 QQ 插件；两者都轮换一次。
2. 管理端点不要只验 HMAC：要么要求 tour 用 OIDC access token（含 `tour.accounts.manage` / `tour.org.settings`）调用，auth 侧自行校验权限点；要么用 Cloudflare Access / mTLS / 服务令牌，并把调用方身份写进签名（而不是 body 里的 `actor_id`）。
3. 给 HMAC 加 nonce 或 `jti`，在 D1/KV 缓存 5 分钟内已用签名；或把窗口缩到 60 秒并加请求 ID 去重。
4. 管理端点加独立限流与告警（密码重置、角色变更、开放注册开关），失败验签也记录/告警。
5. 在完成 1-3 前，至少把 `BIND_SECRET` 当作 root 密钥管理：不落盘、不进日志、不放在 QQ 插件可读的普通配置里。

### H-2（高）父域会话 Cookie：任一子域都能收到 `whl_session`

**证据**

- `src/lib/session.ts:15-17`：
  ```ts
  function cookieDomain(c: Context<AppEnv>): { domain?: string } {
    return c.env.COOKIE_DOMAIN ? { domain: c.env.COOKIE_DOMAIN } : {};
  }
  ```
- `src/lib/session.ts:42-48`：`httpOnly: true`、`sameSite: "Lax"`、`path: "/"`、`secure` 按请求协议、`...cookieDomain(c)`。
- 生产 `COOKIE_DOMAIN=.whleague.win`（README:67）。

**影响**

- 浏览器会把 `whl_session` 发送给 `auth.whleague.win` 的**所有同级子域**（tour、guess、club、以及任何未来/遗忘的子域）。子域的服务端、访问日志、WAF、错误追踪、被攻破的容器都能拿到完整会话令牌，直接冒充用户访问 auth。
- 同级子域还可以设置 `Domain=.whleague.win` 的同名 Cookie，造成 Cookie 覆盖/污染（cookie tossing），导致会话固定或“登出后仍有登录态”等歧义。
- `httpOnly` 只挡 JS 读取，不挡“子域服务器收到 Cookie”。
- 没有 `__Host-` 前缀（因为设置了 Domain，本来也不能用）。

**说明**：这是“同主域 SSO”的固有代价，不是实现失误；但需要按“所有子域都等同于 auth 的信任级别”来治理。

**建议**

- 首选：auth 使用 host-only `__Host-whl_session`（不设 Domain），各子域通过 OIDC 各自维持本地会话；跨站登录用授权码跳转，而不是共享 Cookie。
- 若必须共享：至少确保所有 `*.whleague.win` 子域都在同一安全等级（HSTS、无废弃子域、无第三方托管、无通配 DNS 接管），并加子域清单/监控；Cookie 名加固定前缀并处理同名冲突。
- 会话 TTL 从 7 天缩短，并加空闲超时；高敏感动作要求重新认证。

### H-3（中高）PBKDF2 25,000 轮 + 弱密码策略

**证据**

- `src/lib/crypto.ts:3`：`export const PBKDF2_ITERATIONS = 25_000;`，注释说明是 Workers 免费档 CPU 预算内取值。
- `src/routes/pages.ts:241-243`、`:352-355`：密码至少 8 位且同时含字母和数字；没有长度上限、没有泄露口令检查、没有密码历史。
- `src/routes/pages.ts` 的透明重哈希只会在“存量迭代数 < 25,000”时升到 25,000，不会提高当前档。

**影响**：D1 凭证表一旦泄漏（备份、注入、云账号失守），25,000 轮 PBKDF2-HMAC-SHA256 的离线破解速度约为 600,000 轮的 24 倍；配合“8 位字母+数字”的策略，弱口令很快被还原。限流只能挡在线爆破，挡不住离线。

**建议**

- 在 CPU 预算允许的前提下把迭代数提到 OWASP 当前建议（PBKDF2-HMAC-SHA256 600,000）；Workers 付费档/更高 CPU 限额下可做到。若免费档限制无法提高，改用 WebAssembly 实现的 Argon2id/scrypt（内存硬）或把登录验证移到有更高 CPU 预算的服务。
- 增加泄露口令检查（HIBP k-anonymity 或本地弱口令库）、最小长度 12（或 passphrase）、禁止常见口令。
- 保留透明重哈希机制，并在登录时按当前档升级；不要把 25,000 写死为“设计口径”。

### H-4（中高）超管无 MFA

**证据**：登录只有昵称+密码（`src/routes/pages.ts:120-190`）；没有 TOTP/WebAuthn；超管只是被管理 API 保护（`src/routes/admin.ts:451` 拒绝重置超管密码），但登录本身没有第二因素。

**影响**：超管是全局角色，能跨 tour/guess/club 下发权限；钓鱼、撞库、密码复用都会直接导致全生态失守。

**建议**：给 superadmin 强制 WebAuthn/TOTP；至少给所有能调用管理 API 的账号加 MFA；敏感管理动作（重置密码、改角色、开放注册）做 step-up 认证。

### H-5（中）首个注册者成为超管：竞态与空库风险

**证据**

- `src/routes/pages.ts:247-248`：`SELECT COUNT(*) AS n FROM account`，`isFirst = (count?.n ?? 0) === 0`。
- `src/routes/pages.ts:250-266`：`isFirst` 时跳过注册码/开放注册校验。
- `src/routes/pages.ts:287-301`：`isFirst` 时插入全局 `superadmin` 角色。
- 计数与插入不在同一个原子事务/唯一约束里。

**影响**

- 空库时两个并发注册都可能读到 `count=0`，都成为 superadmin。
- 数据库被清空/恢复到空库后，第一个访问 `/register` 的人自动获得 root；如果同时打开了开放注册，任何人都可以抢。
- 这是一条“部署/恢复流程”级别的后门，不是日常攻击面，但后果极大。

**建议**：superadmin 由迁移/部署脚本在带外创建（固定账号或一次性 bootstrap token），注册接口永远不产生 superadmin；用唯一约束/事务保证“全局超管至多一个”；空库时禁用注册，直到初始化完成。

### M-1（中）`prompt=login` / `max_age` 被忽略

**证据**：`src/routes/oidc.ts:240-262` 只处理 `prompt=none` 和 `must_change_pw`；没有读取 `max_age`，也没有 `auth_time` claim。带 `prompt=login` 的请求会被当作普通请求，已有会话直接发码。

**影响**：RP 若在敏感操作前要求“重新认证”，auth 会静默复用旧会话；`prompt=none&max_age=0` 按规范应返回 `login_required`，这里可能直接发码。对依赖 `max_age` 的 RP 是安全语义缺口。

**建议**：解析 `max_age`，在会话 `auth_time` 超过阈值时强制登录；实现 `prompt=login`；在 ID token 中加 `auth_time`（以及可选的 `amr`）。

### M-2（中）`/logout` 的 CSRF、跨 client 跳转与 hint 忽略

**证据**

- `src/routes/oidc.ts:589-592`：只有 `Sec-Fetch-Site: cross-site` 才拦；缺头按放行（fail-open）。`SameSite=Lax` 的 Cookie 会随顶层 GET 发送，任何第三方页面用 `<a>`/`window.location` 就能强制登出。
- `src/routes/oidc.ts:595-615`：`post_logout_redirect_uri` 在所有 app 的 `post_logout_redirect_uris` 并集里匹配，不绑定 `id_token_hint` 的 `aud`/client。
- `src/routes/oidc.ts:598`：`verifyIdTokenHint` 的返回值被丢弃；hint 只作“佐证”，无效也继续登出。

**影响**：强制登出（可用性/骚扰）；一个已注册 client 的登出地址可被另一个 client 的登出请求使用（仍在白名单内，风险有限）；hint 不参与 client 绑定，不符合最小权限。

**建议**：登出改 POST（或要求 `Sec-Fetch-Site` 缺失时拒绝）；按 client 绑定 `post_logout_redirect_uri`；用 hint 的 `aud` 校验并只允许对应 client 的地址；对 `state` 做完整性保护。

### M-3（中）refresh 不复查会话存活

**证据**：`src/routes/oidc.ts:469-510` 的 refresh 分支只查 `oidc_refresh` 行、原子轮换、`loadAccountUser` 和 `disabledAt`；没有 join `session` 检查 `revoked_at/expires_at`。授权码换取分支反而做了会话检查（`:441-456`）。

**影响**：正常吊销会同时撤销 refresh 行（`src/lib/session.ts:215-225`），所以主要缺口是“会话自然过期但 refresh 尚未到期”的窗口，以及未来漏吊销时的兜底缺失。属于纵深防御缺口，不是当前可直接利用的越权。

**建议**：refresh 时 join session，检查 `revoked_at IS NULL AND expires_at > now`；refresh TTL 不超过会话 TTL；密码重置/停用后继续保证 refresh 全撤。

### M-4（中）`/userinfo` 无视 scope 返回 QQ 号

**证据**：`src/routes/oidc.ts:548-552`：
```ts
const qq = await c.env.DB.prepare(
  "SELECT provider_uid FROM identity WHERE account_id = ? AND provider = 'qq' LIMIT 1",
).bind(user.id).first<{ provider_uid: string }>();
```
`qq` 被无条件放进响应；`name`/`email` 分别受 `profile`/`email` scope 控制。

**影响**：只申请 `openid` 的 client 也能拿到 QQ 号（PII），违反最小权限；如果某个 client 被攻破，QQ 号暴露面比预期大。

**建议**：把 `qq` 放到 `profile` 或自定义 scope（如 `qq`）下；在 userinfo 文档中明确字段与 scope 的对应关系。

### M-5（中）审计：actor 可伪造、无保留期

**证据**：`src/routes/admin.ts:384-385` 等把 `m.actorId` 写进 `detail.actor_id`；`m.actorId` 来自 body（`:131`）。审计写库见 `src/lib/audit.ts`，没有清理任务。

**影响**：任何 HMAC 持有者可以填任意 `actor_id`，把操作栽赃给别的管理员；审计不是不可否认证据。`audit_log` 里的 IP、昵称、QQ、操作详情无保留期，长期增长且涉及隐私。

**建议**：操作者身份由服务端从认证凭据推导（OIDC sub/服务身份），不要信 body；审计写外部不可变存储/SIEM；定义保留期（如 180 天）与脱敏策略；对高危事件实时告警。

### M-6（中）会话 7 天、无空闲超时；访问令牌撤销延迟

**证据**：`src/lib/session.ts:10` `TTL_SECONDS = 7 * 24 * 3600`；Cookie `maxAge` 同值（`:47`）。`src/routes/oidc.ts:290-292`：access 30 分钟、ID 10 分钟、refresh 7 天。

**影响**：被复制的会话令牌最多可用 7 天；停用/改密后，已签发的 access token 在 30 分钟内仍可能被本地验签的 RP 接受（userinfo 会置空权限，但 RP 若只验 JWT 就看不到）。

**建议**：加空闲超时（如 12-24 小时）与绝对上限；高敏感动作重新认证；access TTL 缩到 5-10 分钟；提供 introspection/revocation 机制或在 RP 侧强制查 userinfo；文档明确 RP 不得只依赖 JWT 本地验签做高敏授权。

### M-7（中低）每请求 D1 查询可被伪造 Cookie 放大

**证据**

- `src/index.ts:15-18`：全局中间件对**每个请求**调用 `getSessionUser`。
- `src/lib/session.ts:55-86`：有 `whl_session` Cookie 时先查 `session JOIN account`，再查 `user_role`（2 次 D1）；`touchSession` 每 5 分钟写一次。
- `/healthz`、`/jwks.json`、`/.well-known/*`、`/` 等没有针对“伪造 Cookie”的限流。

**影响**：攻击者带一个随机 `whl_session` 请求任意路径，每次都会触发一次 D1 读；认证用户触发两次。可被用于放大 D1 读/费用与延迟（Cloudflare 会吸收部分流量，但成本仍在）。

**建议**：对无状态端点（healthz、jwks、well-known、token、userinfo、machine/admin）跳过会话查询；只对页面路由挂 `getSessionUser`；对公共端点加 IP 级限流；对不存在的会话做短 TTL 负缓存（KV/内存）。

### M-8（中低）依赖公告

`npm audit --registry=https://registry.npmjs.org` 结果：

- `hono@4.13.7`：**moderate**，GHSA-5r4p-p66f-jhc7（`serveStatic` 二次解码导致静态路径中间件绕过，修复版本 ≥4.13.11）。本项目 `grep` 未使用 `serveStatic`，当前不可达；仍建议升级。
- `wrangler@4.131.1`、`miniflare`、`undici`、`sharp`：**high**，均在开发/构建链，不进入 Worker 运行时；升级 wrangler 即可连带修复。
- `jose@6.2.12` 无公告。

**建议**：升级 `hono` 到 ≥4.13.11、`wrangler` 到 ≥4.148.1；加 CI 的 `npm audit` 与 Dependabot/Renovate。

### L-1（低）授权码先消费后校验

`src/routes/oidc.ts:418-439` 先原子 `UPDATE oidc_code SET consumed_at`，再校验 `client_id`、`redirect_uri`、PKCE。知道 code 但没有 verifier 的人可以把 code 烧掉，造成合法登录失败（DoS），但无法换取 token（PKCE 仍在）。建议先校验 client/redirect/PKCE，再原子消费；或消费失败时回滚。

### L-2（低）全局角色权限跨 aud 下发

`src/routes/oidc.ts:379-398` 的 `permissionsFor` 对 `r.app_id IS NULL` 的角色下发其全部权限点，不按 aud 过滤。当前只有 `superadmin` 是全局角色，注释也说明是刻意为之；但未来若新增“support/auditor”等全局角色，其权限会泄漏到所有 client。建议把“全局角色跨 aud”限制为 superadmin 专属，其他全局角色显式声明适用 aud。

### L-3（低）`machineGate` 先读 body 再验签，无体积上限

`src/lib/machineGate.ts:23` `const raw = await c.req.text();` 在验签前读完整 body；未认证请求在 300/15min/IP 的额度内可以发送大 body，消耗内存/CPU。建议先检查 `Content-Length` 上限（如 64KB）再读；超限直接 413。

### L-4（低）back-channel 通知的 SSRF/超时

`src/lib/session.ts:145-190` 用 `fetch(uri)` 向 `app.backchannel_logout_uri` 发 POST，无超时、无 `redirect: "manual"`、无 http(s)/私网校验。`app` 表目前只由迁移/播种修改，风险低；一旦有了改 app 表的管理入口，就会变成 SSRF。建议校验 http(s)、禁止私网/元数据地址、加超时和手动重定向。

### L-5（低）CORS `*`

`src/routes/oidc.ts:41-48` 对 `/token`、`/userinfo`、`/revoke`、`/jwks.json`、`/.well-known/*` 返回 `Access-Control-Allow-Origin: *`。公开 client + PKCE 的常规做法；但 `/userinfo` 会返回 PII，若未来支持多租户/第三方 client，建议改为按注册 origin 白名单。

### L-6（低）HSTS 无 `includeSubDomains/preload`

`src/index.ts:45` 仅 `max-age=31536000`。父域 Cookie 场景下，同级子域的 HSTS 需要各自配置；建议全生态统一 HSTS，评估 `includeSubDomains` 与 preload。

### L-7（低）宽松数字转换

`src/lib/machineGate.ts:44-47`：
```ts
const n = Number(v);
return Number.isInteger(n) ? n : null;
```
`Number(null)=0`、`Number("")=0`、`Number(true)=1`。在机器端点里，`account_id: null` 会变成 0；当前有 HMAC 与存在性检查兜底，不构成越权，但容易在未来引入“0 号账号/球队”类逻辑错误。建议显式只接受 number/数字字符串，并拒绝 null/boolean/空串。

### L-8（低）隐私与数据生命周期

- 注册重复昵称返回 409（`src/routes/pages.ts:273`），可枚举昵称；风险低（昵称本身半公开）。
- 没有账号删除/数据导出；`identity` 的 QQ、`account` 的邮箱、`audit_log` 的 IP/昵称长期保留。
- `session`/`oidc_refresh` 的过期行不清理，`audit_log` 无保留期；`src/index.ts:68-70` 的 cron 只清 `rate_limit`。
- 建议：定义保留期（session/refresh 过期即删，audit 180 天），提供删除/导出流程，审计里对 QQ/邮箱脱敏。

### L-9（低）仓库中的生产迁移产物

`migrate-sql-prod.sql`、`migrate-report-prod.md` 已被 git 跟踪，内容包含生产账号 ID 与球队绑定（无密码/密钥/姓名）。属于运维产物入库的卫生问题，建议移到私有运维仓库或加访问说明；同时确认 `.dev.vars`、`.wrangler`、`migrate-prod.log` 继续保持忽略（当前已忽略）。

## 3. 已验证的安全能力（做得好的部分）

- **SQL 注入**：全量参数化；唯一动态拼接是 `src/routes/machine.ts:175-176` 的三选一列名（来自固定分支，不是用户输入）；`IN (...)` 占位符按数组长度生成；`LIKE` 搜索值绑定；`LIMIT` 有上限。
- **XSS**：`src/web/layout.ts:4-11` 的 `esc()` 覆盖 `& < > " '`；页面所有动态插值都过 `esc()`；无内联脚本；CSP `default-src 'self'`、`frame-ancestors 'none'`、`base-uri 'none'`。
- **CSRF**：`src/lib/csrf.ts` 双提交，Cookie `httpOnly`、host-only、`SameSite=Lax`、7 天；所有页面 POST 都校验；机器/管理端点用 HMAC，不依赖 Cookie。
- **OIDC**：强制 PKCE S256（43 位 base64url）；`redirect_uri` 逐字精确匹配且拒绝 `#`；授权码一次性 + 重放检测；refresh 轮换 + 重用检测（吊销整族）；RS256 固定算法；RSA ≥2048；`kid` 用 JWK thumbprint；JWKS 只暴露公开参数。
- **令牌存储**：session/refresh/auth code 全部 SHA-256 哈希后入库；HMAC/CSRF/PKCE 比较用常数时间函数。
- **会话**：服务端校验 `revoked_at`/`expires_at`/`disabled_at`；改密轮换会话并撤销旧 token；停用/重置密码批内撤销 session + refresh，并异步 back-channel 通知各 client。
- **限流**：D1 原子自增，fail-closed；登录有 IP/昵称/账号三层桶；token/authorize/userinfo/machine/register 均有独立桶；拿不到计数按超限处理。
- **响应头**：`nosniff`、`X-Frame-Options: DENY`、`Referrer-Policy: no-referrer`、`Cache-Control: no-store`、HSTS、CSP。
- **密钥卫生**：git 历史未发现私钥/`BIND_SECRET` 值；`.dev.vars` 未跟踪且被忽略；`.dev.vars.example` 无真实值；密钥生成脚本只打印到 stdout，README 明确“值勿入库、勿贴群”。
- **测试**：`npm test` 128/128 通过，覆盖算法混淆、HMAC 负例、CSRF、PKCE、限流、并发烧码等；`tsc --noEmit` 通过。

## 4. 修复路线图

### P0（本周内）

1. 拆分 `ADMIN_SECRET` / `BIND_SECRET`，轮换两者；管理端点加独立限流与告警。
2. 给管理 API 加服务端授权：OIDC 权限点校验，或 Cloudflare Access/mTLS；`actor_id` 不再作为身份来源。
3. HMAC 加 nonce/jti 去重（5 分钟缓存），或把窗口缩到 60 秒。
4. 给 superadmin 上 WebAuthn/TOTP；至少给管理调用方上 MFA。
5. 修首个注册者竞态：superadmin 带外创建，注册接口不产生 superadmin，空库禁用注册。

### P0 修复状态（v4.0.0）

- 1、2、3 已落地：`/api/admin/*` 改用 `ADMIN_SECRET` + `X-Nonce`（落 `hmac_nonce` 去重），并强制 `X-Actor-Token`（`aud = ADMIN_AUDIENCE`）；auth 侧按 token `sub` 重查权限点，`body.actor_id` 不再参与鉴权。
- 4 已落地：TOTP + 8 个一次性恢复码；superadmin 未启用 TOTP 时被全站门禁（仅 `/mfa/setup`/登出），`/authorize` 与 code/refresh 均拒绝。
- 5 已落地：注册固定 `tour.coach + club.coach`，超管只能由 `scripts/bootstrap-superadmin.mjs` 带外创建。
- 验证：`npm run typecheck` 通过；完整套件 **134 例**（含 MFA e2e 3 例、TOTP 单测 3 例）全部通过。
- **未在本轮修复（P1）**：H-2 父域 Cookie、H-3 PBKDF2 25k/弱口令策略、M-4 `/userinfo` 无视 scope、M-6 会话 7 天无空闲超时、M-8 依赖公告。

### P1（2-4 周）

6. 评估并实施会话 Cookie 去父域化（host-only `__Host-` + OIDC SSO），或完成全子域安全治理清单。
7. PBKDF2 升档（600k 或等价 Argon2id/scrypt）+ 泄露口令检查 + 最小长度 12。
8. 实现 `max_age`/`auth_time`/`prompt=login`；登出改 POST、按 client 绑定 redirect、使用 hint 的 aud。
9. refresh 复查 session；`/userinfo` 的 QQ 按 scope 下发。
10. 审计 actor 服务端化 + 保留期/脱敏 + 高危动作告警。
11. 缩短 access TTL（5-10 分钟），明确 RP 的撤销/内省义务。

### P2（持续）

12. 升级 hono ≥4.13.11、wrangler ≥4.148.1；加 CI 的 audit/secret scan。
13. 无状态端点跳过 session 查询；公共端点限流/负缓存。
14. 清理过期 session/refresh；audit 保留期；账号删除/导出。
15. 机器端点 body 上限；back-channel 超时/私网限制；CORS 白名单；HSTS 全生态。
16. 迁移产物移出仓库；建立子域清单与变更评审。

## 5. 验证记录

- `npm run typecheck`：通过（`tsc --noEmit`）。
- `npm test`：**128 pass / 0 fail / 0 skipped**，耗时约 667 秒；包含 e2e + unit（审计基线）。
- P0 修复后 `npm test`：**134 pass / 0 fail**（新增 MFA e2e 3、TOTP 单测 3），`tsc --noEmit` 通过。
- `npm audit --registry=https://registry.npmjs.org`：5 个漏洞（1 moderate：hono；4 high：wrangler/miniflare/undici/sharp，均开发链）。
- `git log -S "BEGIN RSA PRIVATE KEY"`、`git log -S "BEGIN PRIVATE KEY"`、`git log -S "BIND_SECRET="`：无命中。
- `.dev.vars`：未跟踪、已忽略；`.wrangler` 已忽略；`scratch/` 为空。
- 未执行：生产环境动态扫描、D1 生产数据核查、Cloudflare Access/WAF 配置核查、社会工程/钓鱼演练、压力测试。

## 6. 一句话总结

这套 OIDC 服务的“协议实现”比“信任边界”更成熟：PKCE、令牌哈希、限流、转义都做得不错；真正需要优先处理的是**管理 API 的共享密钥与零授权**、**父域 Cookie**、**口令强度与超管 MFA**、**首个注册者超管**这四件事。前两件一旦被突破，后面的细节防护都挡不住账号接管。
