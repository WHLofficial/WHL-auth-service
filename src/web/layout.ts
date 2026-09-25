import { APP_VERSION } from "../version";

/** HTML 转义：所有动态插值进模板前必须过 esc */
export function esc(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const STYLE = `
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
  background: #f4f5f7; color: #1c1e21;
  font-family: system-ui, -apple-system, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif; }
.card { width: 100%; max-width: 360px; margin: 16px; padding: 28px;
  background: #fff; border: 1px solid #e3e5e8; border-radius: 12px; }
h1 { font-size: 18px; margin: 0 0 4px; }
.sub { color: #6a7280; font-size: 13px; margin: 0 0 20px; }
label { display: block; font-size: 13px; margin: 14px 0 6px; }
input { width: 100%; padding: 10px 12px; font-size: 15px;
  border: 1px solid #cdd2d9; border-radius: 8px; background: #fff; }
input:focus { outline: 2px solid #2563eb; outline-offset: -1px; border-color: #2563eb; }
button { width: 100%; margin-top: 20px; padding: 10px 12px; font-size: 15px;
  border: 0; border-radius: 8px; background: #2563eb; color: #fff; cursor: pointer; }
button:hover { background: #1d4ed8; }
button.btn2 { background: #eef0f3; color: #1c1e21; }
button.btn2:hover { background: #e2e5ea; }
.foot { margin-top: 16px; font-size: 13px; color: #6a7280; text-align: center; }
.foot a { color: #2563eb; text-decoration: none; }
.ver { margin-top: 18px; font-size: 12px; color: #9aa1ab; text-align: center; letter-spacing: .4px; }
.msg { background: #fef2f2; border: 1px solid #fecaca; color: #b91c1c;
  font-size: 13px; padding: 10px 12px; border-radius: 8px; margin: 0 0 4px; }
.notice { background: #eff6ff; border: 1px solid #bfdbfe; color: #1d4ed8;
  font-size: 13px; padding: 10px 12px; border-radius: 8px; margin: 0 0 4px; }
.notice a { color: inherit; }
.hint { color: #6a7280; font-size: 12px; margin: 6px 0 0; }
dl { margin: 8px 0 0; }
.kv { display: flex; justify-content: space-between; gap: 12px; padding: 10px 0;
  border-bottom: 1px solid #eef0f2; font-size: 14px; }
.kv dt { color: #6a7280; margin: 0; }
.kv dd { margin: 0; text-align: right; }
.kv dd a { color: #2563eb; text-decoration: none; }
.center { text-align: center; margin: 12px 0 0; }
.kbd { display: inline-block; padding: 10px 16px; font-size: 20px; letter-spacing: 2px;
  background: #eef0f3; border: 1px solid #cdd2d9; border-radius: 8px;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
a.btn2 { display: block; margin-top: 20px; padding: 10px 12px; font-size: 15px;
  border-radius: 8px; background: #eef0f3; color: #1c1e21; text-align: center; text-decoration: none; }
a.btn2:hover { background: #e2e5ea; }
/* 三系统跳转按钮配色对齐生态内既有跳转入口：赛事=guess 顶栏去赛事平台的草坪绿条纹，
   竞猜=tour 顶栏去竞猜站的冷青，俱乐部=鎏金徽牌（club 门厅的 --gold 徽章金系：
   金属渐变节律 + 金环 + 金光晕，光晕即金属反光）；
   发光本为深色顶栏设计，按白卡片调弱一档 */
a.jump { display: block; margin-top: 8px; padding: 10px 12px; font-size: 15px;
  border-radius: 8px; text-align: center; text-decoration: none; }
a.jump-tour { border: 1px solid #0a3d24; color: #fff;
  background: repeating-linear-gradient(90deg, rgba(255,255,255,.06) 0 9px, rgba(255,255,255,0) 9px 18px),
    linear-gradient(180deg, #0e7a46, #0b6a3d 55%, #0a3d24);
  box-shadow: inset 0 1px 0 rgba(255,255,255,.22), 0 0 10px rgba(40,190,110,.45), 0 0 22px rgba(40,190,110,.25); }
a.jump-tour:hover { filter: brightness(1.07); }
a.jump-guess { border: 1px solid #35a8c9; color: #06303d;
  background: linear-gradient(180deg, #8fe6f7, #35a8c9);
  box-shadow: 0 0 10px rgba(80,205,235,.45), 0 0 22px rgba(80,205,235,.22); }
a.jump-guess:hover { filter: brightness(1.07); }
a.jump-club { border: 1px solid #8f6a1e; color: #fff;
  background: linear-gradient(180deg, #c99b3f, #b5773a 35%, #a4612c 60%, #8e5426);
  box-shadow: inset 0 1px 0 rgba(255,244,220,.4), inset 0 0 0 2px rgba(201,155,63,.25),
    0 0 12px rgba(201,155,63,.6), 0 0 26px rgba(201,155,63,.35); }
a.jump-club:hover { filter: brightness(1.07); }
`;

export function page(title: string, body: string, heading = "WHL 统一登录"): string {
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} · WHL 统一登录</title>
<style>${STYLE}</style>
</head>
<body>
<main class="card">
<h1>${esc(heading)}</h1>
${body}
<p class="ver">WHL 统一登录 · v${APP_VERSION}</p>
</main>
</body>
</html>`;
}
