// 字体共享源切换（v4.0.4）：@font-face 与 preload 全部指向平台共享源 https://fonts.whleague.win/v1/，
// CSP 显式新增 font-src 放行该源（default-src 'self' 不覆盖跨源字体）。
// 红线：fonts.whleague.win 尚未建域，本文件任何断言都不得访问它（本地不可解析是预期）——
// 只锁 /login HTML 与 CSP 响应头里的引用口径；本地 /fonts/* 保留为回滚垫，仍应 200。
import { test } from "node:test";
import assert from "node:assert/strict";
import * as H from "../lib/harness.mjs";

const FONT_BASE = "https://fonts.whleague.win/v1/";
const SIZES = new Map([
  ["inter-latin.woff2", 48_444],
  ["jbmono-latin.woff2", 40_404],
]);

test("登录页引用共享源字体：@font-face、preload 与正文栈", async () => {
  const res = await fetch(`${H.BASE}/login`);
  assert.equal(res.status, 200);
  const html = await res.text();
  // @font-face 的 src 全部命中共享源 v1 基址，且四条版本一致
  const srcs = [...html.matchAll(/url\('(https:\/\/fonts\.whleague\.win\/[^']+)'\)/g)].map((m) => m[1]);
  assert.equal(srcs.length, 4, "应有 4 条 @font-face src");
  for (const src of srcs) {
    assert.ok(src.startsWith(FONT_BASE), `src 必须命中共享源 v1 基址：${src}`);
  }
  const bases = new Set(srcs.map((s) => s.replace(/[^/]+$/, "")));
  assert.equal(bases.size, 1, "四条 src 的版本基址应一致");
  assert.ok(bases.has(FONT_BASE), "版本基址应为 v1");
  assert.doesNotMatch(html, /url\('\/fonts\//, "不应再引用本地 /fonts/ 相对路径");
  // 声明原样保留：四条 swap、无 local()
  assert.equal((html.match(/font-display: swap/g) ?? []).length, 4, "四条 @font-face 都应 font-display: swap");
  assert.doesNotMatch(html, /local\(/, "不应使用 local()");
  // preload：共享源绝对 URL + crossorigin，且只 preload inter-latin
  assert.ok(
    html.includes('<link rel="preload" href="https://fonts.whleague.win/v1/inter-latin.woff2" as="font" type="font/woff2" crossorigin>'),
    "head 应 preload 共享源 Inter latin 且带 crossorigin",
  );
  assert.doesNotMatch(html, /rel="preload"[^>]*(latin-ext|jbmono)/, "只 preload inter-latin，不预载其余三件");
  assert.match(html, /font-family: var\(--font-sans\)/, "body 应走字体令牌");
  assert.doesNotMatch(html, /Noto Serif/, "auth 不引入宋体（18px 标题撑不住衬线）");
});

test("本地 /fonts/ 回滚垫仍在场：200、字节数、woff2 类型", async () => {
  for (const [name, size] of SIZES) {
    const res = await fetch(`${H.BASE}/fonts/${name}`);
    assert.equal(res.status, 200, `${name} 应 200`);
    assert.match(res.headers.get("content-type") ?? "", /font\/woff2|application\/octet-stream/, `${name} 内容类型`);
    assert.equal((await res.arrayBuffer()).byteLength, size, `${name} 字节数应与提交一致`);
  }
});

test("CSP 放行共享源字体，且不放行 data: 或其他外部字体源", async () => {
  const res = await fetch(`${H.BASE}/login`);
  const csp = res.headers.get("content-security-policy") ?? "";
  assert.match(csp, /default-src 'self'/, "应保留 default-src 'self'");
  const fontSrc = csp.match(/(?:^|;)\s*font-src([^;]*)/);
  assert.ok(fontSrc, "CSP 应显式声明 font-src");
  assert.match(fontSrc[1], /https:\/\/fonts\.whleague\.win/, "font-src 应放行共享源");
  assert.doesNotMatch(fontSrc[1], /data:/, "font-src 不应放行 data:");
  const others = (fontSrc[1].match(/https?:\/\/[^;\s]+/g) ?? []).filter((s) => !s.startsWith("https://fonts.whleague.win"));
  assert.deepEqual(others, [], "font-src 不应放行共享源之外的任何外部源");
});

test("不存在的字体回落 404（assets 不接管未知路径）", async () => {
  const res = await fetch(`${H.BASE}/fonts/nope.woff2`);
  assert.equal(res.status, 404);
});
