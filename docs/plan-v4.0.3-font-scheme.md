# v4.0.3 · 全站字体（auth）

- **状态**：已上线（2026-10-23）。push `7a9dbd2..affeed4`；手动 `wrangler deploy`，Version `86130b7f-cea5-4566-a6e9-d7311551a1a9`。
- **判级**：patch（纯展示微调，无新增能力；`VERSIONS.md` 口径）。
- **版本**：`4.0.2` → `4.0.3`（`package.json` 是唯一真源，`src/version.ts` 直接读它）。

## 目标

给统一登录页一个确定的西文字体与数字字体，消除「Windows 上是 Segoe UI、Mac 上是 SF、表单控件落 Arial」的三套观感；中文继续走系统黑体，不下载任何 CJK 字体。

## 现状（改造前）

- `src/web/layout.ts` 的 `STYLE` 整段内联在 HTML 里，body 是 `system-ui, -apple-system, "Segoe UI", …`。
- `input` / `button` 只设了 `font-size`，**没有** `font-family` ⇒ Chrome 落到 Arial，与正文不同族。
- `.kbd`（绑定码 / 解绑码）用 `ui-monospace`。
- `wrangler.jsonc` 没有 `assets`，Worker 不提供任何静态文件。
- CSP 是 `default-src 'self'; style-src 'unsafe-inline'; form-action 'self'`（`src/lib/csp.ts`），**没有** `font-src` ⇒ 同源字体由 `default-src 'self'` 放行；`data:` 字体被拦（已实测）。

## 裁决

- **F1 不上衬线标题。** 登录页 h1 是 18px（「欢迎回到 WHL 足球联赛」），A/B（18px 宋体 600 vs 现有黑体 700）显示衬线更轻、标题层级反而被削弱，20px 仍偏轻；按「衬线 ≥22px」的阈值不引入 CJK 字体，省掉 ~170KB 子集与一套再生成脚本。
- **F2 正文 Inter**（variable 100–900，latin + latin-ext 双 `unicode-range`）：中文逐字回落系统黑体，与四个站统一。
- **F3 等宽只给 `.kbd`**（绑定码/解绑码，20px + 字距 2px）。表格与其余数字继续用正文的比例字 + `tabular-nums`（本仓没有表格）。
- **F4 表单控件显式继承**：`input, button { font-family: inherit }`，否则「Inter 正文 + Arial 输入框」会更明显。
- **F5 只 preload `inter-latin.woff2`**（48,444 B）：每页都用得到拉丁；latin-ext 只在生僻字符出现时按 `unicode-range` 懒加载；等宽只在验证码页用到，不 preload。
- **F6 CSP 不改**：同源 `/fonts/*` 由 `default-src 'self'` 放行；不新增 `font-src`，也不放行 `data:` 与外部源。
- **F7 用 Workers Assets 只承载字体**：`assets.directory = "./public"`，目录里只有 `fonts/`（无 `index.html`），`not_found_handling = "none"` ⇒ 未命中的路径照旧进 Worker，路由与 CSP 仍由 `src/index.ts` 出。

## 改动清单

| 文件 | 改动 |
| --- | --- |
| `public/fonts/` | 4 个 woff2（Inter latin/latin-ext、JetBrains Mono latin/latin-ext）+ 2 份 OFL + README |
| `wrangler.jsonc` | 新增 `assets`（`./public`、`not_found_handling: "none"`） |
| `src/web/layout.ts` | 4 条 `@font-face`（全 `swap`）、`:root` 字体令牌、body 走 `--font-sans`、`input,button` 继承、`.kbd` 走 `--font-mono`、head 加 preload |
| `tests/e2e/fonts.test.mjs` | 4 条：页面引用与 preload、字体 200 + 字节数、CSP 边界、未知字体 404 |
| `package.json` / `VERSIONS.md` | 4.0.3 + 台账行 |

## 验收

- `npm run typecheck` 0 error；`npm test` 全绿（基线 52 文件 / 628 例，含 7 跳过；本次新增 1 文件 4 例）。
- 本地 `/login`、`/register`：只请求 `inter-latin.woff2`（48,444 B），computed 字体 body / h1 / input / button 全是 `Inter`；1440 与 375 均无横向溢出。
- `GET /fonts/inter-latin.woff2` → 200、`font/woff2`、48,444 B；`/fonts/nope.woff2` → 404。
- CSP 头仍无外部 `font-src`、无 `data:`。

## 风险与已知后果

- Workers Assets 的响应不经过 Worker，因此 `/fonts/*` 没有本仓的 CSP 头——字体本身不需要 CSP，可接受。
- 字体文件名不含内容 hash：将来换字体文件要同步改名或接受边缘/浏览器缓存按 ETag 重验。
- 若哪天登录页 h1 涨到 ≥22px，可以回到「衬线标题」选项（F1 的否决条件只在当前 18px 成立）。

## 待办

- 已发布（2026-10-23）。生产实测：`/login` 只拉 `inter-latin.woff2` 48,444 B；body/h1/input/button computed 首族 Inter；1440/375 无横滚；页脚 v4.0.3。
- 若登录页 h1 将来涨到 ≥22px，再回来评估衬线标题（见 F1）。
