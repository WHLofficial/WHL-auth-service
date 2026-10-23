// 字体落地（v4.0.3）：自托管 Inter / JetBrains Mono 的静态资产、页面引用与 CSP 边界。
// 关键前提：字体走 Workers Assets 的 /fonts/*，同源加载由 CSP 的 default-src 'self' 放行；
// 若哪天把 assets 撤掉，这里的前三条会先红。
import { test } from "node:test";
import assert from "node:assert/strict";
import * as H from "../lib/harness.mjs";

const SIZES = new Map([
  ["inter-latin.woff2", 48_444],
  ["jbmono-latin.woff2", 40_404],
]);

test("登录页引用本地字体：@font-face、preload 与正文栈", async () => {
  const res = await fetch(`${H.BASE}/login`);
  assert.equal(res.status, 200);
  const html = await res.text();
  assert.match(html, /@font-face/, "内联样式应含 @font-face");
  assert.match(html, /url\('\/fonts\/inter-latin\.woff2'\)/, "Inter 应从 /fonts 加载");
  assert.match(html, /font-family: var\(--font-sans\)/, "body 应走字体令牌");
  assert.match(html, /<link rel="preload" href="\/fonts\/inter-latin\.woff2" as="font" type="font\/woff2" crossorigin>/,
    "head 应 preload Inter latin");
  assert.doesNotMatch(html, /Noto Serif/, "auth 不引入宋体（18px 标题撑不住衬线）");
});

test("字体资产由边缘直出：200、字节数、woff2 类型", async () => {
  for (const [name, size] of SIZES) {
    const res = await fetch(`${H.BASE}/fonts/${name}`);
    assert.equal(res.status, 200, `${name} 应 200`);
    assert.match(res.headers.get("content-type") ?? "", /font\/woff2|application\/octet-stream/, `${name} 内容类型`);
    assert.equal((await res.arrayBuffer()).byteLength, size, `${name} 字节数应与提交一致`);
  }
});

test("CSP 未拦同源字体，也未放行外部字体源", async () => {
  const res = await fetch(`${H.BASE}/login`);
  const csp = res.headers.get("content-security-policy") ?? "";
  assert.match(csp, /default-src 'self'/, "应保留 default-src 'self'");
  const fontSrc = csp.match(/(?:^|;)\s*font-src([^;]*)/);
  if (fontSrc) assert.doesNotMatch(fontSrc[1], /https?:|data:/, "不应放行外部或 data: 字体源");
});

test("不存在的字体回落 404（assets 不接管未知路径）", async () => {
  const res = await fetch(`${H.BASE}/fonts/nope.woff2`);
  assert.equal(res.status, 404);
});
