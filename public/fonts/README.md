# 自托管字体（whl-auth）

v4.0.3 起，登录页正文用 Inter、绑定码用 JetBrains Mono。中文不下载字体，逐字回落到系统黑体（PingFang / 雅黑 / Noto Sans）。

| 文件 | 字节 | 用途 |
| --- | --- | --- |
| `inter-latin.woff2` | 48,444 | 正文拉丁（variable 100–900） |
| `inter-latin-ext.woff2` | 74,328 | 生僻拉丁（Š / Đ / Ł 等），按 unicode-range 懒加载 |
| `jbmono-latin.woff2` | 40,404 | `.kbd` 绑定码 / 解绑码（variable 100–800） |
| `jbmono-latin-ext.woff2` | 15,196 | 等宽的生僻拉丁 |

- 来源：`@fontsource-variable/inter@5.2.5`、`@fontsource-variable/jetbrains-mono@5.2.5`（npm/jsDelivr 分发）。
- 许可：SIL Open Font License 1.1，见 `OFL-Inter.txt` / `OFL-JetBrainsMono.txt`。

## 为什么没有 CJK 字体

登录页标题 18px，衬线在此字号会削弱层级（A/B 见 `docs/plan-v4.0.3-font-scheme.md` F1），而且整站中文只出现在系统已装的字体里。为 18px 标题背一个 ~170KB 的宋体子集不划算。

## 硬约束

1. `@font-face` 一律 `font-display: swap`，且不写 `local()`——避免命中系统里同名但版本不同的字体。
2. 只 preload `inter-latin.woff2`；其余按需加载。
3. 字体经 Workers Assets（`wrangler.jsonc` 的 `assets`）提供，同源加载由 CSP 的 `default-src 'self'` 放行；不要改成 `data:` 或外部 CDN。
4. 换字体文件时同步改文件名（无内容 hash），否则缓存需按 ETag 重验。
