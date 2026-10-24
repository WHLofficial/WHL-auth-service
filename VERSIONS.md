# 版本口径与历史版本（whl-auth）

> 2026-09-25 起本仓采用**自己的语义化版本**。此前全生态共用一个「增量 N」序列，那个序列的台账不在本仓
> （在俱乐部平台 `ROADMAP.md`），本仓只零散标注过其中部分 wave。**本表是本仓版本历史的唯一真源**：
> 历史文档/注释里的「增量 N」一律按本表换算为 `vX.Y.Z`。

## 判级口径

- **major**（`vX.0.0`）：① 对外/跨仓契约或 URL 不兼容；② 生产数据真源或口径重定义、需重导；③ 写入口下线或必须多仓同轮。
- **minor**（`vX.Y.0`）：新增用户可见能力（新页面 / 新端点 / 新规则），向后兼容。
- **patch**（`vX.Y.Z`）：无新增能力——缺陷修补、性能与读量治理、文档、内部重构、纯展示微调。
- 起点：本仓地基（无生产数据）= `v0.1.0`。**纯他仓的 wave 不占本仓版本号。**

## 历史版本

| 原增量 | 版本 | 主题 | 判级依据 |
| --- | --- | --- | --- |
| 6 | `v0.1.0` | 服务初建 + P0 全量落地 + 严格测试加固 | 地基（无生产数据） |
| 7 | `v1.0.0` | 球队绑定真源上收 auth | major：跨仓契约（五条 HMAC 机器端点）+ 绑定真源迁移 + 存量生产迁移 |
| 8 | `v2.0.0` | 账号管理能力落到 auth | major：跨仓契约（12 条 `/api/admin/*`）+ tour 侧 6 处写入口改道下线 |
| 9 | `v3.0.0` | P0 契约对齐与残留清理 | major：`AUTH_MODE` 三仓同轮显式化 + 兼容直写死码删除（写入口下线） |
| 10 | `v3.1.0` | 自助会话 + 审计查询 + 权限点对照表 | minor：新增用户可见能力（`/sessions` 页、`/api/admin/audit/query`） |
| 11 | `v3.2.0` | 换绑 UX 双向闭环 | minor：新增用户可见能力（解绑确认码流程），向后兼容 |
| —（非编号增量，事故响应） | `v3.2.1` | club 入口正式开放 + `hidden` 机制修复 | patch：展示口径订正（删 club 的 `hidden`）+ 缺陷修补（作者样式 `a.jump` 的 `display` 压过 `[hidden]` ⇒ 2026-09-14 起的 hidden 从未生效），无新增能力 |
| —（安全审计 P0） | `v4.0.0` | 管理端双因子 + TOTP MFA + 超管初始化 | major：`/api/admin/*` 契约不兼容（`BIND_SECRET` → `ADMIN_SECRET` + `X-Nonce` + `X-Actor-Token`，`actor_id` 不再走 body）+ 注册不再产生超管、空库必须带外 bootstrap（写入口/初始化流程变更，需 tour 同轮改造） |
| —（MFA 绑定修复） | `v4.0.1` | `/mfa/setup` 刷新不再更换待确认密钥 | patch：设置页 GET 复用 10 分钟内仍有效的 pending secret，避免用户录入上一页密钥后刷新导致验证码必然失效；新增 e2e 回归断言 |
| —（MFA 限流放宽） | `v4.0.2` | MFA 绑定限流 5 → 30 次/15 分钟 | patch：绑定页是交互式调试场景，5 次上限把超管自己卡住；保留上限防「已登录会话 + 密码爆破」，当前生产 `mfa-setup:1` 计数已清零 |
| —（全站字体） | `v4.0.3` | 正文 Inter + 验证码等宽（自托管，Workers Assets） | patch：纯展示微调；新增 `assets` 目录只承载 `/fonts/*`，路由与 CSP 仍由 Worker 出。2026-10-23 上线：push `7a9dbd2..affeed4`，手动 `wrangler deploy` 出包 Version `86130b7f-cea5-4566-a6e9-d7311551a1a9`；生产 `/login` 只请求 `inter-latin.woff2`（48,444 B），body/h1/input/button 均为 Inter，1440/375 无横滚 |
| —（字体共享源） | `v4.0.4` | 字体源切平台共享源 + CSP 放行 font-src | patch：纯展示微调——4 条 `@font-face` 与 inter-latin preload 改指 `https://fonts.whleague.win/v1/`（本地 `/fonts/` 保留为回滚垫），CSP 新增 `font-src` 仅放行该源（`data:` 与其他外部源仍拦）；**待上线**（未 push 未部署） |

**当前版本：`v4.0.4`**

## 落地位置

- 版本号单一真源 = `package.json` 的 `version` → `src/version.ts` 用 JSON import 引入（wrangler 打包时内联；
  本仓无构建步骤）→ 页面统一由 `src/web/layout.ts` 的 `page()` 渲染页脚 `WHL 统一登录 · vX.Y.Z`。
  `errorPage` / `oidcErrorPage` 也走 `page()`，因此 404/500 页同样带版本。
- 迁移文件名不随版本改：`migrations/0010_increment10.sql`、`0011_increment11.sql` 等**保留原文件名**
  （已 apply 的迁移历史不能改），只回填文件内容里的「增量 N」。
- 本仓 wave 的子步骤标签（9A / 9B / 9C / 9D、10C 等）属旧共享序列词汇，回填时收敛为所属版本号。

## 已知缺口（不可考）

- 增量 6 无一手主题记录：仅 `TEST_REPORT.md` 以「增量 6 基线」引用（87 例 = 42 单测 + 45 e2e，
  代码基线 `44e2154`），主题按 2026-09-12~09-14 的提交时序推断。
