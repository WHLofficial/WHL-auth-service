# 球队绑定迁移报告（增量 7）

- 源：tour whl（team 20 / team_member 10）+ club whl-club（clubs 0 / club_bindings 0）
- 产出：目录行 20、绑定 INSERT 10（SQL 见脚本 stdout，执行到 whl-auth）

## 目录匹配（按队名精确相等）

| tour team | club | 状态 |
| --- | --- | --- |
| 1 巴黎圣日耳曼 | — | 未匹配（club_id NULL，可后补 /api/team/link） |
| 2 里昂 | — | 未匹配（club_id NULL，可后补 /api/team/link） |
| 3 利物浦 | — | 未匹配（club_id NULL，可后补 /api/team/link） |
| 4 曼联 | — | 未匹配（club_id NULL，可后补 /api/team/link） |
| 5 慕尼黑1860 | — | 未匹配（club_id NULL，可后补 /api/team/link） |
| 6 巴塞罗那(CPU) | — | 未匹配（club_id NULL，可后补 /api/team/link） |
| 7 纽卡斯尔联 | — | 未匹配（club_id NULL，可后补 /api/team/link） |
| 8 尤文图斯 | — | 未匹配（club_id NULL，可后补 /api/team/link） |
| 9 佛罗伦萨 | — | 未匹配（club_id NULL，可后补 /api/team/link） |
| 10 切尔西 | — | 未匹配（club_id NULL，可后补 /api/team/link） |
| 12 皇家贝蒂斯 | — | 未匹配（club_id NULL，可后补 /api/team/link） |
| 13 阿斯顿维拉 | — | 未匹配（club_id NULL，可后补 /api/team/link） |
| 14 拜仁慕尼黑 | — | 未匹配（club_id NULL，可后补 /api/team/link） |
| 15 阿森纳 | — | 未匹配（club_id NULL，可后补 /api/team/link） |
| 16 曼城(CPU) | — | 未匹配（club_id NULL，可后补 /api/team/link） |
| 17 奥林匹亚科斯 | — | 未匹配（club_id NULL，可后补 /api/team/link） |
| 18 诺丁汉森林 | — | 未匹配（club_id NULL，可后补 /api/team/link） |
| 19 RB莱比锡(CPU) | — | 未匹配（club_id NULL，可后补 /api/team/link） |
| 20 皇家马德里 | — | 未匹配（club_id NULL，可后补 /api/team/link） |
| 21 AC米兰(CPU) | — | 未匹配（club_id NULL，可后补 /api/team/link） |

## 绑定迁移（tour team_member → auth team_binding，via=tour）

| 账号 | 球队 | 动作 |
| --- | --- | --- |
| 1 | 里昂（tour team 2） | 迁移 |
| 2 | 里昂（tour team 2） | 迁移 |
| 3 | 尤文图斯（tour team 8） | 迁移 |
| 5 | 曼联（tour team 4） | 迁移 |
| 6 | 阿森纳（tour team 15） | 迁移 |
| 8 | 皇家马德里（tour team 20） | 迁移 |
| 9 | 奥林匹亚科斯（tour team 17） | 迁移 |
| 10 | 皇家贝蒂斯（tour team 12） | 迁移 |
| 11 | 切尔西（tour team 10） | 迁移 |
| 12 | 纽卡斯尔联（tour team 7） | 迁移 |

## club_bindings 校对：确认一致（0）

| 账号 | 球队 | club | 结论 |
| --- | --- | --- | --- |
| — | — | — | — |

## 冲突（须人工裁决：0）

- 无

## 单边：只有 club 绑定、无赛事系统入队记录（0）

| 账号 | 姓名 | club | 绑定时间 |
| --- | --- | --- | --- |
| — | — | — | — |

## 单边：未匹配俱乐部的赛事球队（20） / 未匹配赛事球队的俱乐部（0）

- tour team 1「巴黎圣日耳曼」未匹配到同名俱乐部
- tour team 2「里昂」未匹配到同名俱乐部
- tour team 3「利物浦」未匹配到同名俱乐部
- tour team 4「曼联」未匹配到同名俱乐部
- tour team 5「慕尼黑1860」未匹配到同名俱乐部
- tour team 6「巴塞罗那(CPU)」未匹配到同名俱乐部
- tour team 7「纽卡斯尔联」未匹配到同名俱乐部
- tour team 8「尤文图斯」未匹配到同名俱乐部
- tour team 9「佛罗伦萨」未匹配到同名俱乐部
- tour team 10「切尔西」未匹配到同名俱乐部
- tour team 12「皇家贝蒂斯」未匹配到同名俱乐部
- tour team 13「阿斯顿维拉」未匹配到同名俱乐部
- tour team 14「拜仁慕尼黑」未匹配到同名俱乐部
- tour team 15「阿森纳」未匹配到同名俱乐部
- tour team 16「曼城(CPU)」未匹配到同名俱乐部
- tour team 17「奥林匹亚科斯」未匹配到同名俱乐部
- tour team 18「诺丁汉森林」未匹配到同名俱乐部
- tour team 19「RB莱比锡(CPU)」未匹配到同名俱乐部
- tour team 20「皇家马德里」未匹配到同名俱乐部
- tour team 21「AC米兰(CPU)」未匹配到同名俱乐部

## 执行说明

1. 前置：migrate-accounts.mjs（account 行）与 seed-grants.mjs（user_role）已执行。
2. `SQL=$(node scripts/migrate-team-bindings.mjs --remote)` → 人工核对本报告 → `npx wrangler d1 execute whl-auth --remote --command "$SQL"`。
3. 执行后抽查：`SELECT b.account_id, t.name, t.club_id FROM team_binding b JOIN team t ON t.id=b.team_id ORDER BY b.account_id;`
4. 冲突/单边项裁决后：目录补关联用 club 侧管理端发码（自愈 register）或 /api/team/link；单边 club 绑定按裁决手写 INSERT（bound_via 按裁决入口取 tour/club）。
