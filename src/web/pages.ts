import type { SessionUser } from "../env";
import { esc, page } from "./layout";

export function loginPage(opts: { csrf: string; next?: string; error?: string }): string {
  return page(
    "登录",
    `<p class="sub">赛事、竞猜、俱乐部共用这个账号。登录一次，三个系统都能进。</p>
${opts.error ? `<p class="msg">${esc(opts.error)}</p>` : ""}
<form method="post" action="/login">
<input type="hidden" name="csrf" value="${esc(opts.csrf)}">
${opts.next ? `<input type="hidden" name="next" value="${esc(opts.next)}">` : ""}
<label for="name">昵称</label>
<input id="name" name="name" autocomplete="username" maxlength="32" required autofocus>
<label for="password">密码</label>
<input id="password" name="password" type="password" autocomplete="current-password" required>
<button type="submit">登录</button>
</form>
<p class="foot">没有账号？<a href="/register">注册</a></p>`,
    "欢迎回到 WHL 足球联赛",
  );
}

export function registerPage(opts: {
  csrf: string;
  openReg: boolean;
  name?: string;
  email?: string;
  error?: string;
}): string {
  const codeLabel = opts.openReg ? "注册码（选填）" : "注册码";
  const codeHint = opts.openReg
    ? "没有注册码也能注册，账号会先受限（观众号），解锁前不能绑队。"
    : "注册码向管理员要。";
  return page(
    "注册",
    `<p class="sub">注册后可登录赛事、竞猜、俱乐部。</p>
${opts.error ? `<p class="msg">${esc(opts.error)}</p>` : ""}
<form method="post" action="/register">
<input type="hidden" name="csrf" value="${esc(opts.csrf)}">
<label for="name">昵称</label>
<input id="name" name="name" maxlength="32" required value="${esc(opts.name ?? "")}">
<label for="password">密码</label>
<input id="password" name="password" type="password" autocomplete="new-password" required>
<p class="hint">至少 8 位，要包含字母和数字。</p>
<label for="email">邮箱（选填）</label>
<input id="email" name="email" type="email" value="${esc(opts.email ?? "")}">
<label for="signupCode">${codeLabel}</label>
<input id="signupCode" name="signupCode" ${opts.openReg ? "" : "required"}>
<p class="hint">${codeHint}</p>
<button type="submit">注册</button>
</form>
<p class="foot">已有账号？<a href="/login">登录</a></p>`,
    "欢迎来到 WHL 足球联赛",
  );
}

export function passwordPage(opts: { csrf: string; next?: string; error?: string }): string {
  return page(
    "修改密码",
    `<p class="sub">改完当前登录不受影响。</p>
${opts.error ? `<p class="msg">${esc(opts.error)}</p>` : ""}
<form method="post" action="/password">
<input type="hidden" name="csrf" value="${esc(opts.csrf)}">
${opts.next ? `<input type="hidden" name="next" value="${esc(opts.next)}">` : ""}
<label for="oldPassword">当前密码</label>
<input id="oldPassword" name="oldPassword" type="password" autocomplete="current-password" required>
<label for="newPassword">新密码</label>
<input id="newPassword" name="newPassword" type="password" autocomplete="new-password" required>
<p class="hint">至少 8 位，要包含字母和数字。</p>
<button type="submit">修改密码</button>
</form>`,
  );
}

export function homePage(opts: {
  csrf: string;
  user: SessionUser;
  qq: string | null;
  notice?: string;
}): string {
  const u = opts.user;
  const roleLabel = u.role === "superadmin" ? "超级管理员" : u.role === "admin" ? "管理员" : "教练";
  const qqCell = opts.qq
    ? esc(opts.qq)
    : `<a href="/bind">去绑定</a>`;
  return page(
    "我的账号",
    `<p class="sub">你好，${esc(u.name)}。</p>
${opts.notice ? `<p class="notice">${esc(opts.notice)}</p>` : ""}
${u.mustChangePassword ? `<p class="notice">密码刚被重置，请先<a href="/password">设置新密码</a>。</p>` : ""}
<dl>
<div class="kv"><dt>昵称</dt><dd>${esc(u.name)}</dd></div>
<div class="kv"><dt>角色</dt><dd>${roleLabel}</dd></div>
<div class="kv"><dt>QQ 绑定</dt><dd>${qqCell}</dd></div>
${u.locked ? `<div class="kv"><dt>账号状态</dt><dd>受限（观众号），解锁前不能绑队</dd></div>` : ""}
</dl>
<form method="post" action="/logout">
<input type="hidden" name="csrf" value="${esc(opts.csrf)}">
<button type="submit" class="btn2">登出</button>
</form>`,
  );
}

/** QQ 绑定页（P0-8）：生成一次性码 → QQ 群「绑定 <码>」由插件核销；解绑在 QQ 群发「解绑」 */
export function bindPage(opts: {
  csrf: string;
  qq: string | null;
  boundAt: string | null;
  code?: string;
  error?: string;
}): string {
  const boundBox = opts.qq
    ? `<dl>
<div class="kv"><dt>已绑定 QQ</dt><dd>${esc(opts.qq)}</dd></div>
${opts.boundAt ? `<div class="kv"><dt>绑定时间</dt><dd>${esc(opts.boundAt)}</dd></div>` : ""}
</dl>
<p class="hint">解绑请在本 QQ 的群聊里发送「解绑」；换绑 = 解绑后重新生成绑定码。解绑、换绑不影响积分余额。</p>
<form method="post" action="/bind/code">
<input type="hidden" name="csrf" value="${esc(opts.csrf)}">
<button type="submit" class="btn2">重新生成绑定码</button>
</form>`
    : opts.code
      ? `<p class="sub">在 QQ 群里发送下面这条消息：</p>
<p class="center"><code class="kbd">绑定 ${esc(opts.code)}</code></p>
<p class="hint">10 分钟内有效，一次一用；机器人回复确认即绑定成功。</p>`
      : `<p class="sub">绑定后，各系统积分才能自动发到你的 QQ 上。</p>
<form method="post" action="/bind/code">
<input type="hidden" name="csrf" value="${esc(opts.csrf)}">
<button type="submit">生成绑定码</button>
</form>
<p class="hint">生成后按提示在 QQ 群发送「绑定 码」完成绑定。</p>`;
  return page(
    "QQ 绑定",
    `${opts.error ? `<p class="msg">${esc(opts.error)}</p>` : ""}
${boundBox}
<p class="foot"><a href="/">返回我的账号</a></p>`,
  );
}

export function errorPage(status: 404 | 500): string {
  const text =
    status === 404
      ? "这个地址没有对应页面。"
      : "服务器出了点问题，请稍后再试。";
  return page(
    status === 404 ? "页面不存在" : "出错了",
    `<p class="sub">${text}</p><p class="foot"><a href="/">返回首页</a></p>`,
  );
}

/** OIDC 端点上给浏览器看的错误页（只用于 client/redirect 本身不可信、不能跳转的场景） */
export function oidcErrorPage(title: string, detail: string): string {
  return page(title, `<p class="sub">${esc(detail)}</p><p class="foot"><a href="/login">去登录</a></p>`);
}
