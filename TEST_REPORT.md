# WHL-auth-service 严格测试报告

- 被测对象：`C:\Users\bhdjb\whlProgram\WHL-auth-service`（Hono + jose + D1 + KV，Cloudflare Workers）
- 基线：本地 `wrangler dev --port 8792`，D1 `whl-auth`（本地隔离库），KV `SESSION_KV`（本地）。限流计数已从 `RL_KV` 迁到 D1 的 `rate_limit` 表（见 F-E），`RL_KV` 绑定与建 KV 步骤已删除
- 代码基线：`44e2154`（测试与修复均未提交，见 §8）
- 日期：2026-09-14
- 依赖：仅 `hono ^4.6.0` + `jose ^6.2.12`（未新增任何运行时依赖；测试只用 Node 内置 `node:test` / `node:http`）
- 两轮记录：第一轮「发现缺陷 + 修高危」；第二轮（用户确认后）「中低危一并修掉」。本文档是第二轮结束后的最终版，每条发现都标注了当前状态

---

## 0. 结论（先行）

1. **交付达成：`npm run test` 一键回归全绿** —— **87 个用例（42 单测 + 45 e2e）、87 pass / 0 fail / exit 0**，耗时 269s；从零起一个隔离实例（独立 `--persist-to` 目录、全新库）跑完，不碰开发实例的库、数据与限流桶。
2. **高危缺陷 3 类（涉 4 处代码）全部已修复，并已固化为永久回归用例**：
   - **F-A [高]** `must_change_pw` 完全没生效 —— 拿临时密码可正常访问业务页，还能走 `/authorize` 换授权码进三系统。
   - **F-D [高]** 会话过期只在浏览器侧（cookie `Max-Age`）生效，**服务端不校验 `expires_at`** —— 被复制/被改期的会话 token 永不过期（页面与换码两条路径都漏）。
   - **F-I [高]** 登出时 back-channel 广播**漏发**给"refresh 已被吊销"的 client（最常见的一种），实际效果是三系统仍有本地登录态，违反 PRD P0-9。
3. **中低危 11 条：8 条已修复、3 条保留不改（文档化）**：
   - 已修复：**F-B**（超长昵称触发未认证 500）、**F-C**（账号桶与 IP 无关，任意 IP 可锁死他人账号）、**F-E**（限流计数读改写非原子）、**F-F**（注册码名额在建号失败时白耗）、**L-1**（`GET /logout` 可跨站强制登出）、**L-2**（`/userinfo` 与机器端点无独立限流）、**L-3**（"账号不存在"与"密码错"的登录时序差）。
   - 保留不改：**L-4**（`/register` 重名 409 明文枚举昵称）、**I-1**（空库首账号免码注册即 superadmin）、**I-3**（改密允许新旧密码相同）—— 分别是文档化机制、社群场景固有面、无安全后果的取舍，见 §4。
4. **六项安全底线逐项结论（修复后）**：密码哈希 ✅、会话固定 ✅、CSRF ✅、token 过期刷新 ✅（修完 F-D 才达标）、**防爆破 ✅**（第一轮是 ⚠️，修完 F-B/F-C/F-E 才达标）、QQ 绑定防冒充 ✅。详见 §6。
5. **没有发现**可以由外部未知凭据方利用的越权、认证绕过、开放重定向、XSS、SQL 注入、JWT 算法混淆等问题 —— 这些方向都做了针对性攻击并**被挡住**（证伪记录见 §5）。
6. 三系统 SSO 做了真联调（auth@8792 ↔ tour@8797 真起进程、真走 OIDC），29 项断言全过；`scripts/smoke-oidc.mjs`（92 断言）、`scripts/smoke-bind.mjs`（18 断言）在修复后复跑仍全绿。
7. **两处需要用户知道的偏差**（详见 §9）：限流实现从 KV 固定窗口改成 D1 原子自增（偏离 `TECH_DESIGN.md:359`，换来严格上限与键长免疫）；登录链路因此每请求多 1 次 D1 写，端到端从 ~23/43ms 升到 ~68ms。

---

## 1. 测试范围与方法

| 维度 | 做法 |
| --- | --- |
| 功能闭环 | 注册（注册码/开放注册/首个用户）→ 登录 → 改密 → 登出；OIDC 授权码全链路（`/authorize` → `/token` → `/userinfo` → refresh 轮换 → `/revoke` → `/logout`）|
| 反例与边界 | 参数缺失/越界、错误签名、过期/重放凭据、弱密码、超长输入、错误 method、错误白名单 |
| 安全专项 | 六项底线 + 开放重定向、CSRF、会话固定、XSS/头注入、JWT 篡改/算法混淆、限流绕过、并发竞态（双花/双换码/复用检测）|
| 联调 | auth 与 tour 起真进程走真 OIDC；back-channel 通知用本地 `node:http` 接收器实收 JWT 验签 |
| 定向修复复测 | 每个修复都做"修前复现 → 修后定向验证 → 证明修复的断言进回归套件" |
| 证据形态 | 每条结论都落到 `文件:行号` 或完整请求/响应；探针脚本用后即删，复现步骤写进本报告（§2、§3、§4）|

**红线遵守情况**：全程只跑 `npm run db:migrate:local` 与 `wrangler dev`；未执行 `db:migrate:remote`、`wrangler deploy`、未触碰线上 D1/KV、未 `git push`、未提交；`.dev.vars` 未外传、未写入任何新增文件；未往兄弟仓库（tour/guess/club）写任何文件（联调用 `--var` 传参）。

---

## 2. 高危缺陷（已修复 + 已复测）

### F-A [高] `must_change_pw` 没有任何强制力

- **文档依据**：`PRD.md:50` P0-2「locked / must_change_pw 拦截语义全盘继承……must_change_pw 强制改密」；`TECH_DESIGN.md:415` 登录时序要求做 `locked / must_change_pw 检查`；`TECH_DESIGN.md:356` 管理员重置密码流程依赖"临时密码 + must_change_pw"。
- **实测（修复前）**：`account.id=4`（`oidctest2`，`must_change_pw=1`，密码 `OldPass999`）登录后仅得到 `303 /password`，但：
  - `GET /` → **200**（正常登录态首页）
  - `GET /bind` → **200**（可直接去绑 QQ）
  - `GET /authorize?...`（client=tour，带合法 PKCE）→ **303 到回调并带 `code`** —— 即临时密码可以换到授权码、直接进入三个业务系统，`must_change_pw` 形同虚设。
- **根因**：`src/routes/pages.ts` 的 `POST /login` 只在响应里做 `303 /password` 的重定向提示，没有任何全局守卫；`src/index.ts` 的会话中间件只挂 `user`，不检查 `mustChangePassword`。
- **修复**：`src/index.ts:20-33` 新增全局门禁中间件。
  ```
  const PW_EXEMPT_PATHS = new Set(["/healthz","/login","/password","/logout","/jwks.json","/userinfo","/token","/revoke"]);
  function pwExempt(path) { return PW_EXEMPT_PATHS.has(path) || path.startsWith("/.well-known/") || path.startsWith("/api/"); }
  app.use(async (c, next) => {
    if (!c.get("user")?.mustChangePassword) return next();
    const path = c.req.path;
    if (pwExempt(path)) return next();
    const search = new URL(c.req.url).search;
    return c.redirect(`/password?next=${encodeURIComponent(path + search)}`, 303);
  });
  ```
  放行的只有"改密/登出/登录自身 + 静态契约（healthz/.well-known/jwks）+ 不依赖会话的机器端点（/userinfo /token /revoke）与 `/api/*`"——保证不会把自己锁死在改密页里，且改密完成后能靠 `next` 原样回跳到原请求（含 `/authorize` 的**完整查询串**，state/nonce/challenge 不会丢）。
- **复测**：`tests/e2e/session.test.mjs` 的两条用例（`must_change_pw=1` 时 `/`、`/bind` 303 到 `/password?next=…`；`/authorize` 被拦且**不签码**；白名单端点仍可用）。测试结束时把种子账号复原为 `must_change_pw=1` 的原始状态。

### F-D [高] 会话过期服务端不校验（两个入口都漏）

- **实测（修复前）**：`UPDATE session SET expires_at='2000-01-01T00:00:00.000Z' WHERE token_hash=<sha256(当前 cookie)>` 后，用**同一个 cookie**：
  - `GET /` → **200**（应视为未登录）
  - `GET /authorize?...` → 仍能拿到授权码；`POST /token` 换码也照过。
  - 也就是说 `expires_at` 在库里有值、有用途，但从未被读来判断，cookie 的 `Max-Age` 只是浏览器侧约束，**拷贝 token 出来用就不受任何过期约束**。
- **根因**：`src/lib/session.ts` 的 `getSessionUser` 原 SQL 只 `SELECT account_id, revoked_at`；`src/routes/oidc.ts` 换码时查会话同样只查 `revoked_at`。
- **修复**（两处）：
  - `src/lib/session.ts:57-63`：
    ```
    const sess = await c.env.DB.prepare("SELECT account_id, revoked_at, expires_at FROM session WHERE token_hash = ?")...
    if (!sess || sess.revoked_at || sess.expires_at <= nowIso()) return null;
    ```
  - `src/routes/oidc.ts:340-344`：
    ```
    const sess = await c.env.DB.prepare("SELECT revoked_at, expires_at FROM session WHERE token_hash = ?")...
    if (sess && (sess.revoked_at || sess.expires_at <= nowIso()))
      return oauthJsonError(c, "invalid_grant", "登录会话已结束，请重新登录");
    ```
    这里保留"auth 库无会话行则按存活处理"的既有口径（tour 兼容期旧会话无 D1 行），只在**有行**且已过期/已吊销时拒绝。
- **复测**：`tests/e2e/session.test.mjs` 两条用例 —— 过期会话访问 `/`、`/bind` 一律 303 跳登录；过期会话签发授权码被拒，且**过期前已经签发**的 code 去 `/token` 换也会被拒（描述含「会话」）。测试后 `expires_at` 复原。

### F-I [高] 登出 back-channel 广播漏发给"refresh 已被吊销"的 client

- **文档依据**：`PRD.md:57` P0-9「任一系统登出后，三系统 + auth 全部回到未登录态」。
- **实测（修复前）**：`src/lib/session.ts` 的 `revokeSessionAndNotify` 原本这样挑广播对象：
  ```
  SELECT DISTINCT client_id, account_id FROM oidc_refresh WHERE session_hash = ? AND revoked_at IS NULL
  ```
  `revoked_at IS NULL` 把**已经吊销过 refresh 的 client 全部排除**，而这些恰恰是最需要通知的：授权码重放检测会吊销同码 refresh、RP 自己调过 `/revoke`、refresh 轮换后旧 token 被标记吊销 —— 任一情况下该 client 收不到登出通知，`clients.length === 0` 直接 `return`，RP 侧本地登录态继续存活（最多靠 7 天 refresh TTL 兜底）。
- **修复**：`src/lib/session.ts:96-105` 去掉该过滤条件（`WHERE session_hash = ?`）。`oidc_refresh.session_hash` 是**随机会话 token 的 sha256**，不可能误伤其它会话，所以按会话维度取全集是安全的。同一函数被 `POST /logout`、`GET /logout`（end_session）、`POST /password`（改密触发的传播）三个入口共用，一处修复三处受益。
- **复测**（真收真验，不是看日志）：
  - `tests/e2e/logout.test.mjs` 的回归点：先让 RP 自己调 `/revoke` 把 refresh 吊销，**再**登出 —— 断言仍收到 back-channel 通知，且 `sid` 等于会话 sha256 的 hex、`events` 为 back-channel-logout URI、`aud` 为该 client。
  - 正常登出路径：恰好收到 **1 条**通知、`session.revoked_at` 写入、该会话的全部 refresh 被吊销、旧 refresh 不可再续期。
  - 端到端（真三系统）：auth@8792 + tour@8797，登出后 tour 收到通知并按 `auth_sid` 吊销本地会话，`tour /api/auth/me` 返回 `user:null`；DB 级确认 tour `oidc_session.revoked_at` 有写入（修复前该调用根本没有发生，日志计数 +0）。

---

## 3. 中危缺陷（用户确认后已全部修复 + 已复测）

### F-B [中] 超长昵称触发未认证 500（KV 键长上限）

- **现象（修复前）**：`POST /login` 的账号级限流键是 `rl:login-name:${name}:${bucket}`，昵称直接进 KV 键名；KV 键上限 512 字节，越界即抛异常 → 未捕获 → **500**。
- **证据（修复前实测）**：昵称 600 字符 → `HTTP 500`；dev 日志 `KV GET failed: 414 UTF-8 encoded length of 522 exceeds key length limit of 512.`，抛出点 `src/lib/ratelimit.ts:11`，调用点 `src/routes/pages.ts:84`。逐点实测阈值：490 字符 → 键长 512 → 401（正常失败语义）；**491 字符 → 键长 513 → 500**。与密码对错、账号是否存在无关，未认证可达。
- **修复（两层，都保留了）**：
  1. **根因消除**：限流计数迁到 D1（见 F-E），键只作为普通列值，不再有 512 字节上限 —— `src/lib/ratelimit.ts:17-26`。
  2. **输入守卫**：`src/routes/pages.ts:96-100` 在进任何账号级桶之前挡长度：
     ```
     if (name.length > 64) {
       await audit(c, "login.fail", { detail: { name: name.slice(0, 64) } });
       return fail(401, "昵称或密码不正确");
     }
     ```
     注册侧本来就限 1–32 字符，64 已属宽放；守卫的作用是"脏输入不进限流键 + 不泄漏账号是否存在"，返回统一失败语义（401）而非 400/500。
- **复测**：`tests/e2e/auth.test.mjs`「超长昵称不得 500（F-B）：65 / 490 / 491 / 600 字符一律按失败语义 401」；`tests/unit/ratelimit.test.mjs`「600 字符超长键照常计数」（键长维度）。两条都在 `npm run test` 里。

### F-C [中] 账号名限流桶与 IP 无关 → 任意 IP 可锁死他人账号（DoS）

- **现象（修复前）**：`src/routes/pages.ts:84` 的键是 `login-name:${name}`，**不含 IP**，且在校验密码**之前**就 429。任何 IP 对某昵称连发 5 次错密码，该昵称 15 分钟内即使密码正确也登不进去。
- **证据（修复前实测）**：攻击者 IP `10.91.2.1` 对受害者连发 5 次错密码 → `[401×5]`；受害者换 IP `10.91.2.2` 用**正确密码** → **429**（应 303）。
- **修复**：改成三重桶（语义与 tour `POST /api/auth/login` 对齐）：
  - `login-ip:${ip}` **10/900** —— 单 IP 总闸（`src/routes/pages.ts:83`）
  - `login-name:${ip}:${name}` **5/900** —— 只锁攻击者自己这条路（`src/routes/pages.ts:101-105`）
  - `login-acct:${name}` **50/900** —— 跨 IP 的账号慢速爆破闸，**只在验密失败路径计数**（`src/routes/pages.ts:120-124`）
  - 验密成功立即清零账号桶：`await resetRateLimit(c.env, \`login-acct:${name}\`)`（`src/routes/pages.ts:127`）—— 所以攻击者累计的失败**锁不住**知道密码的受害者，而 50 次阈值仍然挡住分布式慢速爆破。
- **复测**：`tests/e2e/auth.test.mjs`「账号桶不锁受害者（F-C）：攻击者 IP 连失 6 次被 429，受害者换 IP 用正确密码照常登录」（攻击者前 5 次 401、第 6 次 429；受害者新 Client 正确密码 → 303 且 jar 里有 `whl_session`）。

### F-E [中] 限流计数"读-判-写"非原子 → 根修：计数落 D1 原子自增

- **现象（修复前）**：`src/lib/ratelimit.ts` 是 `get()` → 判 `cur >= limit` → `put(cur+1)`，KV 上没有 CAS/原子自增；另外键里拼了 bucket，键名长度也连带出 F-B。
- **修复**：
  - 新增迁移 `migrations/0007_rate_limit.sql`：`rate_limit(key TEXT, bucket INTEGER, count INTEGER, expires_at TEXT, PRIMARY KEY (key, bucket))` + `idx_rate_limit_expires` 索引（已用 `npm run db:migrate:local` 应用到本地库）。
  - `src/lib/ratelimit.ts` 全文重写（40 行）：
    ```
    INSERT INTO rate_limit (key, bucket, count, expires_at) VALUES (?, ?, 1, ?)
      ON CONFLICT (key, bucket) DO UPDATE SET count = count + 1
    RETURNING count
    ```
    `const count = res.results[0]?.count ?? limit + 1;`（拿不到计数按超限处理，**fail-closed**）→ `return count <= limit`。新增 `resetRateLimit(env, key)`（`DELETE … WHERE key = ?`）与 `clearExpiredLimits(env)`（`DELETE … WHERE expires_at <= ?`）。
  - 清理过期行：不再放热路径（见下），改由 cron 全表扫 —— `wrangler.jsonc` 加 `"triggers": { "crons": ["23 4 * * *"] }`，`src/index.ts:56` 导出 `export default { fetch: app.fetch, scheduled: async (_event, env) => { await clearExpiredLimits(env); } }`。
  - `RL_KV` 绑定与其建 KV 步骤随之删除（`src/env.ts:8-9` 注释、`wrangler.jsonc`、`README.md`、`scripts/smoke-oidc.mjs` 的清理块、`tests/lib/env.mjs` 的辅助函数均同步）。
- **本地前置验证**：D1（workerd/miniflare）**支持** `INSERT … ON CONFLICT … DO UPDATE … RETURNING`（CLI 实测连续两次返回 `{"count":1}` / `{"count":2}`）。
- **一处刻意的简化（复测中发现的）**：初版在"本键首次命中"时顺手 `DELETE` 本键的过期行，消 F-B 时序探针时发现它让**新键比已存在的键慢约 6ms**（多一次 D1 往返），方向反转成新的时序旁路，而且它只清自己、收敛不了"每次都是新键"的增长。已删除该分支，改由 cron 全表扫 + `expires_at` 索引兜底（`src/lib/ratelimit.ts:28-31` 注释记录了原因）。
- **复测**：`tests/unit/ratelimit.test.mjs` 10 用例（键作列值、bucket 换算、前 N 次放行、计数递增、桶隔离、跨窗口重置且过期行留给 cron、超长键、`resetRateLimit` 只清目标键、`clearExpiredLimits` 只删过期行、**fail-closed**）+ `tests/e2e/ratelimit.test.mjs` 2 用例（真机 401→429 边界）。
- **残留**：热路径每请求 1 次 D1 写（性能影响见 §9）。

### F-F [低] 注册码预扣名额在"建号失败"时被白耗 —— 已用补偿式修复

- **代码事实**：`src/routes/pages.ts` 的顺序是「查重名 → 原子核销 `UPDATE signup_code SET used_count = used_count + 1 WHERE … AND used_count < max_uses` → `hashPassword`（PBKDF2，昂贵）→ `DB.batch(建 account + credential + user_role)`」。核销在 batch **之外**。
- **为什么当初不建议简单挪进 batch**：把核销挪进 `DB.batch` 会让批次内的 `INSERT/UPDATE` 无条件执行 —— D1 batch 能整体回滚，但**不能按中间语句的 `changes` 中止**，于是 `max_uses=1` 的双花保护会倒退。
- **修复（保留顺序 + 失败退还）**：
  - `src/routes/pages.ts:64-69` 新增 `refundSignupCode(c, code)`：`UPDATE signup_code SET used_count = used_count - 1 WHERE code_hash = ? AND used_count > 0`（`code_hash` 用 `sha256Hex(code)`）。
  - `src/routes/pages.ts:250-256` 建号 batch 抛错时退款：
    ```
    } catch {
      if (!isFirst && code) await refundSignupCode(c, code);
      return renderError("这个昵称已被占用", 409);
    }
    ```
    批是整体事务、抛错即"没有账号"，所以退还名额是正确的方向；核销仍是配额的唯一闸门（`WHERE used_count < max_uses` 的原子 UPDATE），"每个码实际建号数 ≤ max_uses"的不变式不变。
- **复测**：`tests/e2e/auth.test.mjs`「注册码名额：同名并发注册只消耗成功那一次（F-F）」—— 记 `used_count` 前后值，两个新 Client 并发提交同名注册，断言恰 1 个 303 且 `after - before === 1`。
- **残留（如实记录）**：极端并发下，失败方的退还若发生在成功方核销之后，期间到达的同码注册可能瞬时看到"名额耗尽"而拿到 400（重试即可，不会多建账号）。

---

## 4. 低危与 INFO

| ID | 级别 | 状态 | 内容与处理 |
| --- | --- | --- | --- |
| L-1 | 低 | **已修复** | `GET /logout` 可被跨站强制登出（`SameSite=Lax` 允许顶层导航带 cookie）。修复：`src/routes/oidc.ts:472-478` 读到 `Sec-Fetch-Site: cross-site` 时直接 `303 /login`，**不碰会话**；生态三系统（`*.whleague.win`，同站导航）不受影响。复测：`tests/e2e/logout.test.mjs`「跨站 GET /logout 被拒（L-1）」（cross-site 后 `session.revoked_at` 仍为 null、`GET /` 仍 200；再以 `same-site` 请求则正常登出）。**残留**：不发 `Sec-Fetch-Site` 的旧浏览器按放行处理（fail-open），是刻意的兼容取舍。 |
| L-2 | 低 | **已修复** | `/userinfo`、`/api/bind/claim`、`/api/identity/unbind` 原先没有独立限流。修复：`/userinfo` 加 `userinfo:${ip}` **600/900**（`src/routes/oidc.ts:409-412`）；机器端点加 `machineAllowed(c)` = `machine:${ip}` **300/900**，两端点**共用一条桶**，且在 HMAC 验签**之前**判上限（`src/routes/machine.ts:24-27, 33, 92`）。配额宽松是有意的（`scripts/smoke-bind.mjs` 连跑多轮不该被自己卡住）。复测：`tests/e2e/ratelimit.test.mjs` 2 用例（第 601 次 429；机器端点"配额内假签名 401、第 301 次 429、另一端点是同一桶"）。 |
| L-3 | 低 | **已修复** | 登录"账号不存在"与"密码错"有可测量时序差（修复前实测 ≈23ms vs ≈43ms，账号不存在**更快**，可用于枚举昵称）。修复：`src/routes/pages.ts:70-75` 模块级缓存一个 dummy 哈希（`hashPassword("whl-dummy-password")`，同算法同迭代次数、盐格式与真实凭证一致），不存在账号也跑一次 `verifyPassword`（`src/routes/pages.ts:114-118`：`row?.password_hash ?? (await dummyPasswordHash())`）。**复测（交错采样 14 轮取中位数）**：不存在 68.4ms vs 密码错 68.1ms，**差 0.3ms（噪声级）**；PBKDF2 短路已被消除。 |
| L-4 | 低 | 保留不改 | `/register` 重名返回 409 明文枚举昵称。社群场景昵称本就公开（名单/排行榜），文档也未要求保密注册；若要收紧需改成"提交后静默发码"的异步流程，成本与收益不成比例。**已知面，记录在案**。 |
| I-1 | INFO | 保留不改 | 空库 `isFirst` 免码注册即 `superadmin`：`TECH_DESIGN.md:28` 明写"首个用户 = superadmin"，是**文档化的引导机制**。加固建议（运维侧）：引导完成后把 `allow_open_reg` 锁 0 并立即轮换首账号密码。 |
| I-2 | INFO | 保留不改 | `superadmin` 全局权限会跨 `aud` 全量下发（`scripts/seed-grants.mjs` 有意为之），`/userinfo` 仍按 `at.aud` 过滤。无实际越权。 |
| I-3 | INFO | 保留不改 | 改密只校验旧密码，不校验新密码 ≠ 旧密码（允许"新旧同一个密码"）。无安全后果；若要加，属产品策略变更。 |

**非缺陷（澄清后关闭）**：`locked` 账号可以正常登录 —— 这是生态既有语义（guess/club/tour 都把 `locked` 当作"未解锁绑队的观众号"，不是封禁；`TECH_DESIGN.md:319` 明确"locked 不进授权，client 保留 locked→viewer 映射"）。曾按"封禁语义"怀疑过一次，核对文档后判定不是缺陷。

---

## 5. 证伪记录（曾被怀疑、实测不成立，勿重复怀疑）

这些方向都做了针对性攻击，结论是**被正确挡住**：

- **CSRF 完整**：`POST /login`、`/register`、`/password`、`/bind/code` 在缺/错 `csrf` 时一律 403；`POST /logout` 校验失败时不改变登录态。双提交 cookie + `SameSite=Lax`，无 token 泄露面。
- **Cookie 属性正确**：`whl_session` / `whl_csrf` 均 `HttpOnly; SameSite=Lax; Path=/`，host-only（未配 `COOKIE_DOMAIN`，无 `Domain` 属性），HTTP 下不带 `Secure`（本地预期）。
- **会话固定防御正确**：每次登录签发**全新** 256 位随机 token + 新 `family_id`，改密后旧 token 立即作废并重发新 token（不是沿用）。
- **开放重定向全挡**：`next` 的 `//evil.com`、`http://evil.com`、`/\evil.com`、`javascript:`、CRLF 注入等 6 类 payload 一律回落 `/`；`safeNext` 只认站内相对路径。`/authorize` 的 `redirect_uri` 走**精确白名单**，不匹配直接 400 错误页且**绝不跳转**（`#` 也被显式拒绝）。
- **XSS / 头注入全挡**：`?next` 的 `<script>` 回显被 `esc()` 转义；`/authorize` 的 `state` 里 CRLF 被 `URLSearchParams` 编码，无响应头注入。
- **JWT 正确**：JWKS 只含 `kty/n/e/kid/use/alg`（无私钥字段）；`verifyAccessToken` 钉死 RS256 + `iss`，并要求 `sub/aud/scope/jti` 齐全 —— **算法混淆攻击（用公钥当 HMAC 密钥签 HS256）被拒**，**用 `id_token` 冒充 access token 被拒**（缺 scope/jti）；`verifyPkce` 只认 S256 且 verifier 落在 43–128 位 unreserved 字符集。
- **OIDC 全链路正确**：授权码一次性（重放即拒并吊销同码 refresh）、refresh 轮换 + 重用检测**吊销整个 family**、`/revoke` 不误伤其它 client、`/logout` 的 `post_logout_redirect_uri` 需在所有 app 的白名单里精确匹配。
- **QQ 绑定 HMAC 契约全对**：±300s 窗口、重放/篡改/换密钥全拒、`qq_id` 正则校验、`(provider, provider_uid)` 双向唯一、核销原子。
- **注册矩阵正确**：重名 + 有效码 → 409 **且不烧码**；`allow_open_reg=1` 无码 → `locked=1` 观众号；`=0` → 400；伪造/过期/用尽三种码各有可区分文案；**同一 `max_uses=1` 的码 3 并发注册 → 恰好 1 个成功、恰好 1 个账号**。
- **并发竞态无穿透**：同一 `code` 6 并发换 token → 恰好 1 个 200；同一 `refresh` 6 并发 → 恰好 1 个 200。
- **`CF-Connecting-IP` 伪造没用**：`clientIp` 只读 `CF-Connecting-IP`（不读 `X-Forwarded-For`）；生产该头由 CF 边缘注入、外部不可伪造，所以"只信它"是正确设计。实测：固定 `CF-Connecting-IP` + 变造 `X-Forwarded-For` 连发 8 次注册 → `[303×5, 429×3]`，只创建 5 个账号，绕过失败。

---

## 6. 六项安全底线逐项结论（修复后）

| # | 底线 | 结论 | 依据 |
| --- | --- | --- | --- |
| 1 | 密码哈希 | ✅ 达标 | PBKDF2-SHA256 **25000** 迭代（`PBKDF2_ITERATIONS`，与 `TECH_DESIGN.md:356` 一致）、每账号 16 字节随机盐、存档 `pbkdf2$25000$<salt>$<hash>` 不含明文；同密码两次哈希不同；`verifyPassword` 对错误密码/畸形存档（字段数不足、算法标识不符、迭代数 0、空串）一律 false；比较走常数时间。`tests/unit/crypto.test.mjs` 7 用例锁定。 |
| 2 | 会话固定 | ✅ 达标 | 登录/改密都重新签发全新随机 token 与新 family；旧 token 立即失效（旧 cookie 重放换不到任何页面）。实测：两次登录 token 不同（256 位随机）。 |
| 3 | CSRF | ✅ 达标 | 所有状态变更端点（登录/注册/改密/绑码/登出）校验双提交 token，缺/错一律 403 或不做变更；`SameSite=Lax`。 |
| 4 | token 过期与刷新 | ✅ 达标（**修完 F-D 才达标**） | 修复前**不合格**：会话 `expires_at` 服务端不校验，被复制的会话 token 永不过期。修复后页面与换码两侧都校验；access token `ACCESS_TTL=1800` / id_token `600` / refresh `7 天`，refresh 轮换 + 重用检测吊销整族，access token 无黑名单（按 30 分钟 TTL 自然过期，`/revoke` 只对 refresh 生效，符合 RFC 7009 的宽松实现）。 |
| 5 | 防爆破 | ✅ 达标（**修完 F-B/F-C/F-E 才达标**） | 机制与实现都合格：单 IP 总闸 `login-ip:${ip}` 10/900、同 IP 同账号 `login-name:${ip}:${name}` 5/900、跨 IP 账号闸 `login-acct:${name}` 50/900（**只在失败计数、成功即清零**，故攻击者锁不住受害者）；注册 5/3600、改密 `pwd:${id}` 5/900、绑码 `bind-code:${id}` 5/900、`/authorize` 60/900、`/token` 30/900、`/revoke` 30/900、`/userinfo` 600/900、机器端点 300/900（按 IP 分桶）。计数由 D1 单语句原子自增（不存在读改写竞态，多 isolate 不穿透），键只作列值（超长输入不再能造 500）。实测：单 IP 第 11 次 429、机器端点第 301 次 429、`/userinfo` 第 601 次 429。 |
| 6 | QQ 绑定防冒充 | ✅ 达标 | 绑定走 `BIND_SECRET` 的 HMAC-SHA256 签名（canonical `${method}|${pathWithQuery}|${ts}|${rawBody}`，hex 小写），±300s 窗口、时间戳必须为整数、签名大小写不敏感；重放（同 ts 同 body 二次提交）、篡改（换方法/路径/body/时间戳）、换密钥全部拒绝；`qq_id` 有正则约束；`(provider, provider_uid)` 全局唯一且同一账号同一 provider 唯一（`idx_identity_acct_provider`），核销原子。`tests/unit/hmac.test.mjs` 6 用例锁定契约。 |

---

## 7. 回归套件（`npm run test`）

**用法**：`npm run test`（`package.json` scripts → `node tests/run.mjs`）。可选 `AUTH_TEST_PORT` 指定端口、`AUTH_TEST_KEEP=1` 保留临时目录与 dev 日志（默认删）、`AUTH_TEST_ONLY=<片段>` 只跑匹配的测试文件（定位偶发问题用）。

**最终结果**：**87 tests / 87 pass / 0 fail / exit 0**，耗时 **269s**（日志 `C:/Users/bhdjb/AppData/Local/Temp/auth-final-run.log`）。加固后的历史运行另含完整跑 2 次 79/79（修复前的基线，162s / 170s）与多次定向跑全绿。
> 本节数字是**增量 6 的基线**。此后增量 7 追加 `tests/e2e/team.test.mjs`（5 例）、增量 8 追加 `tests/e2e/admin.test.mjs`（13 例），当前总数为 **110 tests / 110 pass**（详见 §10.4）。

**它做了什么**：删除并重建 `.wrangler/test-state` → 在**该隔离目录**上跑 `d1 migrations apply`（不碰开发实例的库）→ 找一个空闲端口起 `wrangler dev --persist-to <隔离目录>` → 轮询 `/healthz` → 播种测试数据（`test-rp` 这个 app 行 + 一枚 `REGR-<hex>` 注册码，`max_uses` 100000）→ 用 `node --test` 跑 unit + e2e（11 个文件）。因为每次都是全新库，不需要清理限流桶或测试账号。

**对测试期间连接抖动的处理**：踩到过两次 78/79（都是同一个用例 `tests/e2e/logout.test.mjs` 的「正常路径：登出广播一次、会话吊销、token 不可续期」，在 `tests/lib/harness.mjs` 的 `exchangeToken` 处报 `TypeError: fetch failed / ECONNRESET`；原样重跑即 79/79）。起初判为「实例在测试途中静默崩溃」，**复查后这个归因是错的**：同一次运行里，失败的用例之后还有约 60 个用例全部通过（实例一直活着），日志里的 `==> 隔离实例提前退出` 是套件收尾自己 `taskkill` 触发的误报（收尾路径没先置 `stopping` 标志）。真实原因是**连接级抖动**：本地这套环境里 undici 的 keep-alive 池会复用已被服务端关掉的空闲 socket 并抛 `ECONNRESET`（`tests/lib/client.mjs` 里早先就留着同一现象的注释，属历史记录；用 `/healthz` 做「请求→空闲→复用」的定向探针没能稳定复现，说明是概率性竞态而非必现）。加固全部在测试侧（产品代码未动）：`tests/lib/client.mjs` 对所有测试请求加 `connection: close`，不复用连接；`tests/run.mjs` 边流式转发输出边留全文，只有失败输出里出现 `ECONNRESET / UND_ERR_SOCKET / ECONNREFUSED / socket hang up / fetch failed` 才整轮重试一次（**断言失败绝不重试**，不会掩盖缺陷），并在收尾前置 `stopping`，不再把正常关闭误报成「提前退出」。

**文件与覆盖（用例数为实测值）**：

| 文件 | 用例数 | 覆盖 |
| --- | --- | --- |
| `tests/unit/crypto.test.mjs` | 7 | PBKDF2 迭代数/格式/随机盐/畸形存档拒绝、`randomToken` 位宽与字符集、`generateCode` 无歧义字符集 |
| `tests/unit/hmac.test.mjs` | 6 | 绑定签名契约（窗口、大小写、query 参与、换密钥/方法/路径/body/ts 全拒、缺件全拒） |
| `tests/unit/oidc.test.mjs` | 13 | JWKS 无私钥字段、kid 指纹稳定、<2048 位拒绝、未配置密钥明确报错、PEM 与单行 base64 等价、access/id token 声明与 TTL、**HS256 算法混淆被拒**、id_token 冒充被拒、logout_token 形态（含 sid、无 nonce）、`verifyIdTokenHint` 的容错口径、PKCE 字符集与长度 |
| `tests/unit/ratelimit.test.mjs` | 10 | 键作列值 + bucket 换算、前 N 次放行、计数递增、桶隔离、跨窗口重置（过期行留给 cron）、**超长键照常计数（F-B）**、`resetRateLimit` 只清目标键、`clearExpiredLimits` 只删过期行、**fail-closed** |
| `tests/unit/util.test.mjs` | 6 | `clientIp` 只认 `CF-Connecting-IP`（不读 XFF）、`nowIso` 格式、`parseUris` 容错与逐元素过滤、`timingSafeEqual` |
| `tests/e2e/auth.test.mjs` | 12 | 匿名守卫与回跳、cookie 属性、会话固定、登录失败 401 与 CSRF 403、IP 桶 10/900、**F-B 超长昵称**、**F-C 不锁受害者**、6 类开放跳转 payload、反射转义、登出 + 旧 token 失效、匿名探针端点、**F-F 注册码名额** |
| `tests/e2e/session.test.mjs` | 6 | **F-D**（页面 / 换码双闸）、**F-A**（全局门禁 + 白名单不自锁）、改密闭环（旧会话作废 + `must_change_pw` 清零 + 旧密码失效 + 新密码可登录）、改密三类拒绝 |
| `tests/e2e/oidc.test.mjs` | 10 | discovery/JWKS、授权码全链路（验签 / iss / aud / nonce / sid / sub 纯数字 / RFC 9207 `iss`）、一次性与重放吊销、PKCE 强制、client/redirect 白名单绝不跳转、`response_type`/`scope` 校验、refresh 轮换与重用吊销整族、userinfo 鉴权、`/revoke` 语义、静默 SSO 保留完整查询串 |
| `tests/e2e/ratelimit.test.mjs` | 2 | **L-2**：`/userinfo` 600/900（第 601 次 429）；机器端点 300/900 且"先限流后验签"，两端点共用一条桶 |
| `tests/e2e/logout.test.mjs` | 6 | **F-I**（RP 先自吊销 refresh 后仍须收到通知）、正常登出（恰 1 条通知 + 会话吊销 + refresh 全吊销）、`GET /logout` 白名单内外、无授权时不广播不报错、CSRF 无效不误登出、**L-1 跨站被拒** |
| `tests/e2e/register.test.mjs` | 9 | 有效码、开放注册开关两态、重名不烧码、无效码三态文案、**并发双花**（3 并发 → 恰 1 个账号）、密码/昵称规则 6 例（含 33 字符昵称必须 400 而非 500）、CSRF、注册 IP 桶 5/3600、已登录回跳 |

| `tests/e2e/team.test.mjs`（增量 7） | 5 | 球队目录登记/发码/烧码（含并发竞速输家整批零写回 `invalid_code`）/一账号一队/解绑与派生读 |
| `tests/e2e/admin.test.mjs`（增量 8） | 13 | 见 §10.2（管理机器端点全量 + 审计 + 停用语义 + 跨服务实联另见 tour 侧） |

**支撑库**：`tests/lib/client.mjs`（cookie jar + 表单 + CSRF 提取，**每个 Client 默认注入独立随机 `CF-Connecting-IP`**，否则本地共享 `local` 桶会互相打死；所有请求带 `connection: close`，不复用连接以规避 keep-alive 陈旧 socket 抖动）、`tests/lib/env.mjs`（wrangler CLI 封装，对 Windows 上 `ECONNRESET/EBUSY/SQLITE_BUSY` 做退避重试）、`tests/lib/harness.mjs`（注册/登录/授权码/换码/刷新/吊销/back-channel 接收器/JWKS 验签）、`tests/lib/loader.mjs`（**必需**：Node 24 原生 TS 剥离不会给 `src` 内部省略扩展名的相对导入补 `.ts`，此 loader 用 `module.registerHooks` 补上，否则 `hmac`/`oidc`/`csrf`/`session` 等模块无法在单测里导入 —— 产品代码一行未改）。

---

## 8. 变更清单（未提交、未 push）

```
 M README.md                # 删「建 RL_KV」步骤（限流迁 D1）；冒烟断言数 67→92
 M package.json             # 新增 "test": "node tests/run.mjs"
 M scripts/smoke-oidc.mjs   # 限流清理从 KV 改成 D1（DELETE FROM rate_limit）
 M src/env.ts               # 去掉 RL_KV 绑定
 M src/index.ts             # F-A 门禁中间件 + scheduled 清理过期限流行
 M src/lib/ratelimit.ts     # F-E 根修：D1 原子自增；新增 resetRateLimit / clearExpiredLimits
 M src/lib/session.ts       # F-D 会话过期校验；F-I 广播对象去掉 revoked_at 过滤
 M src/routes/machine.ts    # L-2 机器端点限流（两端点共一条桶，验签前判）
 M src/routes/oidc.ts       # F-D 换码校验会话；L-2 /userinfo 限流；L-1 cross-site 登出拦截
 M src/routes/pages.ts      # F-B 长度守卫；F-C 三重桶 + 成功清零；L-3 dummy 哈希；F-F 名额退还
 M wrangler.jsonc           # 删 RL_KV 绑定；加 triggers.crons ["23 4 * * *"]
?? migrations/0007_rate_limit.sql   # rate_limit 表 + expires_at 索引
?? tests/                           # 回归套件（run.mjs + lib×4 + unit×5 + e2e×6）
?? TEST_REPORT.md                   # 本文档
?? auth-test-brief.md               # 本次任务书（用户提供）
```

`git diff --stat` = **11 files changed, 150 insertions(+), 60 deletions(-)**（不含未跟踪的 `tests/`、`migrations/0007_rate_limit.sql` 与本文档）。**未新增任何运行时依赖**；`npm run typecheck`（`tsc --noEmit`）在每轮改动后均 exit 0。

---

## 9. 假设、偏差与未覆盖

**假设（文档未覆盖处）**

- `allow_open_reg` 的真源是 `organization` 表 `id=1` 那一行（`src/routes/pages.ts:43-47`），无其它开关入口。
- `locked` = "未解锁绑队的观众号"，不是封禁（`TECH_DESIGN.md:319`）；据此把"locked 可登录"判为非缺陷。
- **F-F 的补偿前提**：D1 `batch` 抛错即"批次整体回滚、没有写入"。若某次失败是"已提交但响应丢失"，退还就会与既存账号并存（等同少扣一次名额），属极端边界，未做故障注入验证。
- **cron 需要重新部署才生效**：`triggers.crons` 是部署期配置，本地 `wrangler dev` 不触发 `scheduled`；本地过期行靠下一次 `DELETE FROM rate_limit`（冒烟脚本/手工）清理。

**偏差（偏离既有设计文档）**

- **限流实现从 KV 换成 D1**：`TECH_DESIGN.md:359` 写的是"沿用 KV 固定窗口"。改成 D1 `rate_limit` 表是为了根除 F-E（读改写非原子）与 F-B（键长上限）。代价：热路径每请求多 1 次 D1 写，实测登录端到端从修复前的 **≈23ms（账号不存在）/ ≈43ms（密码错）** 变为 **≈68ms**（交错采样中位数），注册与 OIDC 端点同理多一次写。对"≤50 人的朋友局"规模可接受；若日后要压回来，可考虑 Durable Object 计数器或"KV + 定期校准"，但两者都比现在复杂，且都不解决"键长进键名"的输入面。**此偏差需要你认可后才算定案。**
- L-1 的 `Sec-Fetch-Site` 判定是 **fail-open**（不带头就放行），为兼容旧浏览器保留；要彻底关闭需改 POST-only 登出端点，会与生态现有"退出登录"链接不兼容。

**未覆盖 / 未验证**

1. **生产（Cloudflare 边缘）行为**：本地 wrangler dev 单 isolate、强一致 KV、无 CF 边缘注入逻辑；F-E 修复后已不依赖 isolate 数，但"D1 写配额/延迟在生产下的表现"未测。
2. **真实浏览器交互**：`SameSite`、`Secure`、cookie 分区、`Sec-Fetch-Site` 只在 HTTP/本地语义下验证过，未做真浏览器（HTTPS）验证。
3. 邮件验证、真实 QQ 网关、R2 回滚路径、P0-13 停写 KV 的迁移态、`COOKIE_DOMAIN` 生产配置下的跨子域行为。
4. 压力与性能（Free 档 10ms CPU 限制下 PBKDF2 25k 迭代余量、D1 写放大）未压测。

**测试环境的已知坑（供后续复用）**：本地 wrangler dev **不注入 `CF-Connecting-IP`**，`clientIp` 回退 `"local"`，所以测试客户端必须自己注入随机 IP；账号级限流桶跨用例污染 → 每个用例注册自己的账号（新 Client = 新 IP）；已登录后 `GET /login` 直接 303 拿不到 csrf 表单，需复用先前取到的 token；本地 Windows 上 undici 的 keep-alive 池偶发复用陈旧 socket（`ECONNRESET`）→ 测试客户端已改为 `connection: close`，套件另对连接级失败整轮重试一次（见 §7）；`node --import tests/lib/loader.mjs` 是单测跑产品源码的必要条件。

---

## 10. 增量 8：账号管理能力落到 auth（2026-09-18）

**背景（要修的缺陷）**：账号真源 2026-09-14 已收口到 auth（`account`/`credential`/`user_role`），但 tour 管理台的写操作仍打自己已归档的 `user` 表，**6 处死写且无一处有 OIDC 门控**：改角色（`worker/routes/admin/accounts.ts:61`）、解锁观众号（`:72`）、重置密码（`:87-88`，发出的临时密码登不进去）、开放注册开关（`worker/routes/admin.ts:50`）、注册码生成（`:57-73`，生成的码一个都用不掉）、注册码列表（`:76-96`，列出的永远是用不掉的码）。管理员日常入口批量失效，且当时 auth 侧**没有任何账号管理端点**（`src/routes/machine.ts` 只有球队绑定五条 + 绑定两条），线上无可用入口做「重置密码 / 解锁 / 改角色」。

**做法**：界面继续留在 tour，auth 只出能力——新增 12 条 POST + HMAC 管理机器端点，tour 管理台改为转发调用。四题决策见 `PRD.md` §3 决策 11–14。

### 10.1 新增能力清单

| 端点（全 POST，`machineGate` 限流 + 验签） | 说明 |
| --- | --- |
| `/api/admin/accounts/list` | 账号列表：一次查询 LEFT JOIN 绑定球队（`team_id`/`team_name`），角色第二次查询按 `IN (...)` 合并——**禁止 N+1**；keyset 分页（`after`/`limit`，上限 500），会话不进列表 |
| `/api/admin/accounts/detail` | 账号 + 角色 + 账号级授予 + 存活会话（含 IP/登录时间/最后活跃/过期，LIMIT 50）+ QQ，**一个 `DB.batch` 五条语句一次往返** |
| `/api/admin/catalog` | 角色 / 权限点 / app / 角色→权限点映射；isolate 内存缓存 60s（照 `src/lib/csp.ts` 先例，TTL 60s、失败不缓存） |
| `/api/admin/accounts/roles` | 传「应有角色全集」，auth 算差集增删（幂等）；涉及全局超管一律 403 `superadmin_locked` |
| `/api/admin/accounts/grants` | 账号级「额外授予」权限点（只加不减由界面保证，接口传全集）；未知键 400 `bad_permission` |
| `/api/admin/accounts/password` | 生成临时密码 + `must_change_pw=1` + **吊销该账号全部会话** + back-channel 通知；超管 403 |
| `/api/admin/accounts/unlock` | 解锁观众号；已是解锁态返回 `changed:false` 且**不写审计** |
| `/api/admin/accounts/disable` | 停用/启用（`disabled_at`），停用同时吊销全部会话；超管 403 |
| `/api/admin/sessions/revoke` | 单个会话强制下线（带 `session_hash`）或整账号吊销；幽灵 hash 404 `session_not_found` |
| `/api/admin/org-settings` | 不带 `allow_open_reg` = 读，带 = 写（真源 `organization` 表） |
| `/api/admin/signup-codes/create` | 发注册码，**明码只在响应里出现这一次**（库里存 `code_hash`） |
| `/api/admin/signup-codes/list` | 注册码列表，`id` 是 `code_hash` 前 12 位指纹（auth 的 `signup_code` 无自增 id，明码不可回查） |

**数据层（`migrations/0009_admin.sql`）**：新增 `account_permission`（账号级额外授予）、`account.disabled_at`（停用；`locked` 语义完全不动）、`session.ip`。`session.last_seen_at` 是既有列，本轮开始写入（**热路径节流 5 分钟**）。

**审计**：`AuditEvent` 扩 11 项（`role.grant`/`role.revoke`/`perm.grant`/`perm.revoke`/`session.revoke`/`pw.reset`/`account.disable`/`account.enable`/`account.unlock`/`signup_code.create`/`org.open_reg`），补齐了 TECH_DESIGN §8.8 要求但一直缺入口的 `role.grant`/`role.revoke`/`session.revoke`。新增 `auditStatement()` 供 `DB.batch` 使用——**业务写入与审计同一次批**（原先 `audit()` 只能单独 `.run()`，无法进批）。tour 侧对同一动作另记一份本地审计（`target_type='account'`，带 `actor_user_id`），双写沿用增量 7 球队绑定的先例。

**权限下发改造**：`oidc.ts permissionsFor` 从「全表拉 role_permission 再在 JS 过滤」改为一条 UNION SQL（角色派生 ∪ 账号级授予，后者按 `p.app_id = aud` 收紧），**调用点不变、往返数不变**。userinfo/id_token claims 新增 `disabled`；被停用账号 `/userinfo` 下发空 roles/permissions，`/token` 换码与刷新回 `invalid_grant`，会话中间件把 `disabled_at` 与吊销/过期并列为一道闸。

### 10.2 新增测试

| 文件 | 用例数 | 覆盖 |
| --- | --- | --- |
| `tests/e2e/admin.test.mjs` | 13 | 机器门（无签/伪签/跨路径签名 401、非法 JSON 400）；目录（3 app / 7 角色 / 17 权限点 / 角色权限映射 / 超管持全部）；列表（q 过滤、角色带 app 前缀、不含 sessions、`limit=1` keyset 翻页、未绑队 `team_id=null`）；详情（含 IP 与会话、不存在 404）；角色授权（差集 + `role.grant` 审计含 actor_id + 传全集幂等零审计 + 未知键 400 + 超管 403）；额外授予（当场进 userinfo、不跨 app 泄漏、只加不减）；重置密码（临时密码格式、会话全吊销、旧会话失效、旧密码 401、临时密码跳改密页、超管 403）；解锁（`changed` 两态 + 已解锁不写审计）；停用（会话吊销 + 登录 401 + userinfo `disabled` 且 roles/permissions 清空 + refresh `invalid_grant` + 启用恢复 + 超管 403）；强制下线（单会话只踢一个 + 幽灵 hash 404 + 整账号吊销）；org-settings 读写回环；注册码（创建 → 真能注册 → 列表按指纹找回 → 二次使用被拒 → 审计不含明码）；边界（`self_forbidden`、缺参 400、roles 非数组 400、账号不存在 404） |
| `WHL-tournament-management-system/tests/admin.live.test.ts` | 6 | **跨服务实联冒烟**（不替换 fetch，用真实 HMAC 打真实跑着的 auth Worker，未设 `AUTH_LIVE_URL`/`AUTH_LIVE_SECRET` 则整文件 skip）：目录 3 系统/7 角色/17 权限点；列表 camelCase 字段类型；不存在账号抛 `AuthApiError.code === "account_not_found"`（证明 body 解析正常而非 `bad body`）；org-settings 读布尔；注册码列表指纹格式；**注册码写入回环**——经 tour 发的码用 `sha256(code).slice(0,12)` 能在列表里找回（死写回归的跨服务版本） |
| `WHL-tournament-management-system/tests/oidc.test.ts` | +1（共 13） | 账号管理台路由层：管理端点转发认证中心 + snake_case → camelCase 映射 + 无 `tour.accounts.manage` 的教练 403（含路由路径与前端调用路径一致性的回归） |

### 10.3 D1 读写基线（静态语句计数，非运行时测量）

口径：数的是代码里的 D1 语句条数（`prepare().run()`/`batch()` 内每句算一条），**不含** PBKDF2 计算与 KV 操作。`getSessionUser` 是每请求中间件（`src/index.ts:14-17`），有会话 cookie 时固定 2 读（session JOIN account、user_role），无 cookie 时 0（早退）。

| 场景 | 读 | 写 | 说明 |
| --- | --- | --- | --- |
| 登录一次（`POST /login`，无会话 cookie） | 1 | 5 | 读 = 账号+凭证查询；写 = IP 限流、账号限流、INSERT session、后台清账号限流、后台 audit login.ok（后两条 `waitUntil` 不挡响应 → **阻塞往返 3 次**） |
| 鉴权一次（带会话访问任意页） | 2 | 0（每 5 分钟 1） | 2 读来自 `getSessionUser`；`last_seen_at` 埋点节流 5 分钟才写 1 次 |
| 管理列表一次（`/api/admin/accounts/list`） | 2 | 1 | 读 = 账号页 + 角色 `IN`；写 = 机器端点限流。**无 N+1**：绑定球队随账号页 LEFT JOIN 一起取回 |
| 管理详情一次（`/api/admin/accounts/detail`） | 5 | 1 | 5 条语句在**一个 `DB.batch`** 里（账号/角色/授予/会话/QQ），对 D1 是**一次往返**；写 = 机器端点限流 |

对比改造前：tour 列表读自己 `user` 表 + `teamOfAccounts` 全表扫 `team_binding`/`team`（每次全表），现在改为 auth 侧一条 LEFT JOIN。管理端点全部 POST 单次往返，写操作「业务 + 审计」同批。

### 10.4 回归结果（本轮实测）

- auth：`npm run typecheck`（`tsc --noEmit`）干净；`npm test`（`node tests/run.mjs`）**110 tests / 110 pass**（§7 的 87 为增量 6 基线，增量 7 加 `team.test.mjs` 5 例、增量 8 加 `admin.test.mjs` 13 例）。
- tour：`npm run typecheck`（`tsc --noEmit && tsc -p tsconfig.worker.json --noEmit`）干净；`npm test`（`vitest run`）**96 passed / 6 skipped**（skip 的是需真机 auth 的实联用例）；`npm run build`（vite）成功。
- 跨服务实联：auth `npm run dev`（8792）+ tour `AUTH_LIVE_URL=http://127.0.0.1:8792 npx vitest run tests/admin.live.test.ts` → **6/6 通过**。

### 10.5 偏差与未覆盖（增量 8）

**偏差**

- **管理台界面留在 tour，auth 只有能力层**（PRD 决策 11）：admin 端点只验 HMAC 不认人，鉴权由调用方权限点（`tour.accounts.manage` / `tour.org.settings`）负责，操作者身份靠 tour 会话决定后作 `actor_id` 传入。这是刻意的取舍——把管理台依赖 client 的问题留到下一次全面重构。
- **注册码明文不可回显**：`signup_code` 主键是 `code_hash`（`migrations/0001_init.sql:91-98`），列表只能给 12 位指纹。界面文案已相应改为「码只显示一次」。
- **权限点「额外授予」只加不减**（界面层保证），且对全局超管冗余（超管经 `CROSS JOIN permission` 已持全部权限点，界面禁用其授予区）。

**未覆盖 / 未验证**

1. **`last_seen_at` 埋点撞全站热路径的实际影响未压测**（节流 5 分钟后最坏每 5 分钟 1 次写）。退路：不展示「最后活跃」列，只显示 IP/登录时间/过期时间。
2. **生产 CF 边缘行为与真实 HTTPS cookie 语义**仍未验证（沿用 §9 的口径）。
3. **生产库 `d1_migrations` 账本一致性未查**：本地开发库存在「表都在、账本为空」的历史遗留（`npm run db:migrate:local` 会以 `table account already exists` 失败，测试用隔离目录不受影响）。部署 `0009_admin.sql` 前须先查远端账本，否则会重复建表失败。
4. 管理动作的**并发**未专门压测（角色差集与「传全集」幂等设计使重复提交无副作用，但两个管理员同时改同一账号的后写覆盖前写未测）。

