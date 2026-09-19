# 权限点对照表（增量 10，PRD P1-3 前置盘点）

权限真源在本库（`permission` / `role` / `role_permission` / `account_permission`），登录 claims 的
`permissions` 按 aud 过滤下发（`src/routes/oidc.ts` 的 `permissionsFor`：角色派生 UNION 账号级授予，
账号级授予收紧到 `p.app_id = aud` 防跨系统泄漏）。本文对照「auth 定义」与「三仓实际检查」，行号以
增量 10 时点为准，会漂移；以 grep 权限点键名为准。

## 语义判定入口（三仓）

| 仓 | 入口 | OIDC 判定 | 兼容模式回落 |
| --- | --- | --- | --- |
| tour | `worker/middleware/auth.ts` `requirePermission(perm, compatLevel)` | `claims.permissions.includes(perm)` | compatLevel 角色名 |
| guess | `src/_lib/auth.ts` `requireManager` / `requireAdminPerm` | 同上 | `role === 'admin'` |
| club | `src/lib/session.ts` `requireAdmin(perm?)` / `requireCoach(perm?)` | 同上 | `role === 'admin'` |

角色投影（claims.roles → 本地角色）：tour `superadmin→superadmin / tour.recorder→admin / 其余→coach`；
guess `guess.admin|superadmin→admin`；club `superadmin|club.admin→admin / club.coach→coach`。

## 权限点 × 检查点（现役 16 点）

| 权限点 | 种子角色 | tour | guess | club |
| --- | --- | --- | --- | --- |
| tour.match.manage | recorder, superadmin | `routes/admin.ts` 管理台通配、`admin/scoring.ts`、`admin/schedule.ts` | — | — |
| tour.accounts.manage | superadmin | `admin/accounts.ts` | — | — |
| tour.org.settings | superadmin | `routes/admin.ts` org-settings PUT | — | — |
| tour.team.bind | coach, superadmin | `routes/coach.ts` 绑队 | — | — |
| guess.event.manage | guess.admin, guess.initiator, superadmin | — | `requireManager`（多处） | — |
| guess.users.manage | guess.admin, superadmin | — | `api.ts` 用户列表/发起人设置 | — |
| guess.payout.reverse | guess.admin, superadmin | — | `api.ts` 发奖冲正 | — |
| guess.recon.view | guess.admin, superadmin | — | `api.ts` 对账 | — |
| club.clubs.manage | club.admin, superadmin | — | — | `routes/admin.ts` 建队/球队 |
| club.bindings.unbind | club.admin, superadmin | — | — | 解绑球员/球队 |
| club.players.import | club.admin, superadmin | — | — | 球员导入 |
| club.ledger.manage | club.admin, superadmin | — | — | 账本/期初 |
| club.registrations.manage | club.admin, superadmin | — | — | 报名审核 |
| club.compliance.view | club.admin, superadmin | — | — | 合规查看 |
| club.squad.manage | club.coach, superadmin | — | — | `market/transfers/negotiations` 排阵 |
| club.registrations.submit | club.coach, superadmin | — | — | `routes/registration.ts` 提交报名 |

## 已删除死点

- **`tour.team.bindcode.issue`**（0010 删除）：签发球队认证码在增量 7 收进 auth 机器端点
  `/api/team/bindcode`（按绑定关系校验，不经权限点），tour 全仓从未检查过它——目录里有、claims
  下发、零消费。删除后 recorder 的 claims 少一个无效点。

## 有意设计（注明，不改行为）

1. **tour 扣分端点保留 superadmin 角色直判**（`routes/admin/tournaments.ts` 扣分）：增量 8 既定
   决策——目录外保留角色判定，避免为单一端点扩权限点。
2. **club 教练资格走「球队绑定」旁路**（`club/session.ts` `requireCoach`）：auth 对所有新账号自动发
   `club.coach`，权限点无区分度，实际闸门是 `hasTeamBinding()`；权限点仅作管理组旁路。
3. **guess 发起人走本地 `initiators` 表兜底**（`requireManager`）：`guess.initiator` 角色由 auth 播种
   同一权限点 `guess.event.manage`，本地名单兼容历史数据；本地库是 guess 自己的账，不回 auth。
4. **同一个人「三仓管理员」不等价是特性**：tour 管理员 = `tour.recorder`（+superadmin），guess = 
   `guess.admin`，club = `club.admin` 六点并集；seed-grants 只是对历史 admin 账号**同时播三个角色**
   维持迁移前等价。账号级单点授予（account_permission）只在本系统生效（aud 过滤），本就如此。

## 管理端点（增量 8/10）

`/api/admin/*`（machineGate HMAC，界面在 tour，P1-1 既定）：`catalog`、`identity/lookup`（9B）、
`accounts/list|detail|roles|grants|password|unlock|disable`、`sessions/revoke`、`org-settings`、
`signup-codes/create|list`、`audit/query`（10 新增，P1-3）。
