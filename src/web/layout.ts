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
</main>
</body>
</html>`;
}
