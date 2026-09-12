import type { SessionUser } from "../env";
import { esc, page } from "./layout";

export function loginPage(opts: { csrf: string; next?: string; error?: string }): string {
  return page(
    "登录",
    `<p class="sub">赛事、竞猜、俱乐部共用这个账号。</p>
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
  );
}

export function passwordPage(opts: { csrf: string; error?: string }): string {
  return page(
    "修改密码",
    `<p class="sub">改完当前登录不受影响。</p>
<form method="post" action="/password">
<input type="hidden" name="csrf" value="${esc(opts.csrf)}">
<label for="oldPassword">当前密码</label>
<input id="oldPassword" name="oldPassword" type="password" autocomplete="current-password" required>
<label for="newPassword">新密码</label>
<input id="newPassword" name="newPassword" type="password" autocomplete="new-password" required>
<p class="hint">至少 8 位，要包含字母和数字。</p>
<button type="submit">修改密码</button>
</form>`,
  );
}

export function homePage(opts: { csrf: string; user: SessionUser; notice?: string }): string {
  const u = opts.user;
  const roleLabel = u.role === "superadmin" ? "超级管理员" : u.role === "admin" ? "管理员" : "教练";
  return page(
    "我的账号",
    `<p class="sub">你好，${esc(u.name)}。</p>
${opts.notice ? `<p class="notice">${esc(opts.notice)}</p>` : ""}
${u.mustChangePassword ? `<p class="notice">密码刚被重置，请先<a href="/password">设置新密码</a>。</p>` : ""}
<dl>
<div class="kv"><dt>昵称</dt><dd>${esc(u.name)}</dd></div>
<div class="kv"><dt>角色</dt><dd>${roleLabel}</dd></div>
${u.locked ? `<div class="kv"><dt>账号状态</dt><dd>受限（观众号），解锁前不能绑队</dd></div>` : ""}
</dl>
<form method="post" action="/logout">
<input type="hidden" name="csrf" value="${esc(opts.csrf)}">
<button type="submit" class="btn2">登出</button>
</form>`,
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
