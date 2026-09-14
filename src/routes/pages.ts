import { Hono } from "hono";
import { getCookie } from "hono/cookie";
import type { Context } from "hono";
import type { AppEnv } from "../env";
import { audit } from "../lib/audit";
import { csrfValid, ensureCsrfToken } from "../lib/csrf";
import { PBKDF2_ITERATIONS, hashPassword, sha256Hex, verifyPassword } from "../lib/crypto";
import { rateLimit, resetRateLimit } from "../lib/ratelimit";
import { SESSION_COOKIE, createSession, destroySession, revokeSessionAndNotify } from "../lib/session";
import { clientIp } from "../lib/util";
import { bindPage, homePage, loginPage, passwordPage, registerPage } from "../web/pages";

const app = new Hono<AppEnv>();

type Form = Record<string, unknown>;

function formValue(form: Form, key: string): string {
  const v = form[key];
  return typeof v === "string" ? v : "";
}

/** 当前账号的 QQ 绑定（identity 表，P0-8 起启用；没有则 null） */
async function qqBindingOf(c: Context<AppEnv>, accountId: number): Promise<{ provider_uid: string; bound_at: string } | null> {
  return c.env.DB.prepare("SELECT provider_uid, bound_at FROM identity WHERE account_id = ? AND provider = 'qq'")
    .bind(accountId)
    .first<{ provider_uid: string; bound_at: string }>();
}

/** 6 位数字绑定码（2^32 取模的微量偏移对 10 分钟一次性码无影响） */
function sixDigitCode(): string {
  return String(crypto.getRandomValues(new Uint32Array(1))[0] % 1_000_000).padStart(6, "0");
}

/** 只接受站内相对路径，防开放跳转与头部注入（登录/注册/改密后的 ?next）。
 *  上限放宽到 1024：OIDC 回跳的 /authorize URL 带 state/challenge，512 不够 */
function safeNext(v: unknown): string {
  if (typeof v !== "string") return "/";
  if (!v.startsWith("/") || v.startsWith("//") || v.includes("\\") || /[\r\n\t]/.test(v)) return "/";
  return v.slice(0, 1024);
}

async function openRegAllowed(c: Context<AppEnv>): Promise<boolean> {
  // 账号收口（P0-11）：组织级注册开关随账号真源迁入 auth（初值由迁移脚本从 tour 库复制）
  const org = await c.env.DB.prepare("SELECT allow_open_reg FROM organization WHERE id = 1")
    .first<{ allow_open_reg: number }>();
  return (org?.allow_open_reg ?? 0) === 1;
}

const CSRF_EXPIRED = "页面已过期，请重新提交";

app.get("/", async (c) => {
  const user = c.get("user");
  if (!user) return c.redirect("/login", 303);
  const csrf = await ensureCsrfToken(c);
  const notice = c.req.query("notice") === "pw_changed" ? "密码已更新" : undefined;
  const binding = await qqBindingOf(c, user.id);
  return c.html(homePage({ csrf, user, qq: binding?.provider_uid ?? null, notice }));
});

app.get("/login", async (c) => {
  if (c.get("user")) return c.redirect(safeNext(c.req.query("next")), 303);
  const csrf = await ensureCsrfToken(c);
  return c.html(loginPage({ csrf, next: c.req.query("next") }));
});

// 账号不存在时也跑一次等价的 PBKDF2（同算法同迭代次数），免得「账号存在与否」被登录耗时区分出来（L-3）。
// 盐由 hashPassword 现场生成，格式与真实凭证一致；模块级缓存一次，isolate 内复用。
let dummyHashPromise: Promise<string> | null = null;
function dummyPasswordHash(): Promise<string> {
  return (dummyHashPromise ??= hashPassword("whl-dummy-password"));
}

/** 退还预扣的注册码名额：只在「已核销但建号失败」的补偿路径上调用（F-F）。 */
async function refundSignupCode(c: Context<AppEnv>, code: string): Promise<void> {
  await c.env.DB.prepare("UPDATE signup_code SET used_count = used_count - 1 WHERE code_hash = ? AND used_count > 0")
    .bind(await sha256Hex(code))
    .run();
}

// 语义与 tour POST /api/auth/login 一致：IP 10/900s + 同 IP 同账号 5/900s + 跨 IP 账号 50/900s 三重限流
app.post("/login", async (c) => {
  const ip = clientIp(c);
  if (!(await rateLimit(c.env, `login-ip:${ip}`, 10, 900))) {
    await audit(c, "login.rate_limited", { detail: { scope: "ip" } });
    return c.html(loginPage({ csrf: await ensureCsrfToken(c), error: "尝试太频繁，请 15 分钟后再来" }), 429);
  }
  const form = (await c.req.parseBody().catch(() => ({}))) as Form;
  if (!csrfValid(c, form.csrf)) {
    return c.html(
      loginPage({ csrf: await ensureCsrfToken(c), error: CSRF_EXPIRED, next: formValue(form, "next") }),
      403,
    );
  }
  const name = formValue(form, "name").trim();
  if (!name) {
    return c.html(loginPage({ csrf: await ensureCsrfToken(c), error: "请输入昵称", next: formValue(form, "next") }), 400);
  }
  const fail = async (status: 401 | 429, error: string) =>
    c.html(loginPage({ csrf: await ensureCsrfToken(c), error, next: formValue(form, "next") }), status);
  // 昵称先挡长度：注册侧限 1-32 字符，明显超长的输入直接按统一失败语义回（F-B：超长昵称
  // 曾进 KV 键名把键撑爆成未认证 500；迁 D1 后已无此上限，守卫留着防脏数据进限流键）
  if (name.length > 64) {
    await audit(c, "login.fail", { detail: { name: name.slice(0, 64) } });
    return fail(401, "昵称或密码不正确");
  }
  // 同 IP 同账号 5/900：只锁攻击者自己这条路，受害者换 IP 用正确密码不受影响（F-C）
  if (!(await rateLimit(c.env, `login-name:${ip}:${name}`, 5, 900))) {
    await audit(c, "login.rate_limited", { detail: { scope: "ip+name", name } });
    return fail(429, "这个账号尝试太频繁，请 15 分钟后再来");
  }
  // 账号收口（P0-11）：账号/凭证真源 = auth 库 account/credential（TECH_DESIGN §5.3 终态）
  const row = await c.env.DB.prepare(
    `SELECT a.id, a.locked, a.must_change_pw, cr.hash AS password_hash
       FROM account a JOIN credential cr ON cr.account_id = a.id AND cr.type = 'password'
      WHERE a.name = ?`,
  )
    .bind(name)
    .first<{ id: number; locked: number; must_change_pw: number; password_hash: string }>();
  const passwordOk = await verifyPassword(formValue(form, "password"), row?.password_hash ?? (await dummyPasswordHash()));
  if (!row || !passwordOk) {
    await audit(c, "login.fail", { detail: { name } });
    // 跨 IP 的账号桶只在失败路径计数（阈值高于单 IP 桶，兜分布式慢速爆破）；密码正确时
    // 下面直接清零，所以攻击者累计失败也锁不住受害者（F-C）
    if (!(await rateLimit(c.env, `login-acct:${name}`, 50, 900))) {
      await audit(c, "login.rate_limited", { detail: { scope: "acct", name } });
      return fail(429, "这个账号尝试太频繁，请 15 分钟后再来");
    }
    return fail(401, "昵称或密码不正确");
  }
  await resetRateLimit(c.env, `login-acct:${name}`);
  await audit(c, "login.ok", { accountId: row.id });
  await createSession(c, row.id);
  if (row.must_change_pw === 1) {
    // 带 next 进来的（如 OIDC authorize 跳转）把链路保住：改完密码直接回原目标
    const nx = safeNext(form.next);
    return c.redirect(nx === "/" ? "/password" : `/password?next=${encodeURIComponent(nx)}`, 303);
  }
  return c.redirect(safeNext(form.next), 303);
});

app.get("/register", async (c) => {
  if (c.get("user")) return c.redirect("/", 303);
  const csrf = await ensureCsrfToken(c);
  return c.html(registerPage({ csrf, openReg: await openRegAllowed(c) }));
});

// 语义与 tour POST /api/auth/register 一致：邀请码 / 开放注册（locked 观众号）/ 首个用户 = superadmin
app.post("/register", async (c) => {
  const ip = clientIp(c);
  const openReg = await openRegAllowed(c);
  if (!(await rateLimit(c.env, `reg:${ip}`, 5, 3600))) {
    await audit(c, "register.rate_limited");
    return c.html(registerPage({ csrf: await ensureCsrfToken(c), openReg, error: "注册太频繁，请一小时后再试" }), 429);
  }
  const form = (await c.req.parseBody().catch(() => ({}))) as Form;
  const renderError = async (message: string, status: 400 | 409) =>
    c.html(
      registerPage({
        csrf: await ensureCsrfToken(c),
        openReg: await openRegAllowed(c),
        name: formValue(form, "name"),
        email: formValue(form, "email"),
        error: message,
      }),
      status,
    );
  if (!csrfValid(c, form.csrf)) {
    return c.html(
      registerPage({
        csrf: await ensureCsrfToken(c),
        openReg: await openRegAllowed(c),
        name: formValue(form, "name"),
        email: formValue(form, "email"),
        error: CSRF_EXPIRED,
      }),
      403,
    );
  }
  const name = formValue(form, "name").trim();
  const password = formValue(form, "password");
  if (name.length < 1 || name.length > 32) return renderError("昵称需要 1-32 个字符", 400);
  if (password.length < 8 || !/[A-Za-z]/.test(password) || !/\d/.test(password))
    return renderError("密码至少 8 位，且要同时包含字母和数字", 400);
  const email = formValue(form, "email").trim() || null;
  if (email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return renderError("邮箱格式不对", 400);

  const count = await c.env.DB.prepare("SELECT COUNT(*) AS n FROM account").first<{ n: number }>();
  const isFirst = (count?.n ?? 0) === 0;
  const code = formValue(form, "signupCode").trim();
  // 观众号：无注册码注册（需组织开关放开），锁定绑队直到超管解锁
  let locked = 0;

  if (!isFirst) {
    if (code) {
      const codeHash = await sha256Hex(code);
      const sc = await c.env.DB.prepare(
        "SELECT expires_at, max_uses, used_count FROM signup_code WHERE code_hash = ?",
      )
        .bind(codeHash)
        .first<{ expires_at: string | null; max_uses: number | null; used_count: number }>();
      if (!sc) return renderError("注册码无效", 400);
      if (sc.expires_at && sc.expires_at < new Date().toISOString())
        return renderError("注册码已过期", 400);
      if (sc.max_uses !== null && sc.used_count >= sc.max_uses)
        return renderError("注册码已用完", 400);
    } else {
      if (!openReg) return renderError("需要注册码", 400);
      locked = 1;
    }
  }

  const dup = await c.env.DB.prepare("SELECT id FROM account WHERE name = ?").bind(name).first();
  if (dup) return renderError("这个昵称已被占用", 409);

  if (!isFirst && code) {
    const codeHash = await sha256Hex(code);
    const upd = await c.env.DB.prepare(
      "UPDATE signup_code SET used_count = used_count + 1 WHERE code_hash = ? AND (max_uses IS NULL OR used_count < max_uses) AND (expires_at IS NULL OR expires_at > ?)",
    )
      .bind(codeHash, new Date().toISOString())
      .run();
    if (upd.meta.changes !== 1) return renderError("注册码无效或已用完", 400);
  }

  // 账号收口（P0-11）：account + credential + user_role 一个 D1 batch（隐式事务），
  // 不出现「有账号无凭证/无授权」的半截账号。role 不再是账号列：新账号按 §6.2 投影播种
  // user_role——首个账号 = 全局 superadmin，其余 = coach（tour.coach + club.coach，等价旧投影）。
  const now = new Date().toISOString();
  const pwHash = await hashPassword(password);
  const stmts = [
    c.env.DB.prepare("INSERT INTO account (name, email, locked, created_at) VALUES (?, ?, ?, ?)").bind(
      name,
      email,
      locked,
      now,
    ),
    c.env.DB.prepare(
      "INSERT INTO credential (account_id, type, hash, iterations, updated_at) VALUES ((SELECT id FROM account WHERE name = ?), 'password', ?, ?, ?)",
    ).bind(name, pwHash, PBKDF2_ITERATIONS, now),
  ];
  for (const [appId, key] of isFirst ? [[null, "superadmin"]] : [["tour", "coach"], ["club", "coach"]]) {
    stmts.push(
      c.env.DB.prepare(
        "INSERT INTO user_role (account_id, role_id, granted_at) SELECT (SELECT id FROM account WHERE name = ?), id, ? FROM role WHERE app_id IS ? AND key = ?",
      ).bind(name, now, appId, key),
    );
  }
  let userId: number;
  try {
    await c.env.DB.batch(stmts);
  } catch {
    // 建号失败（并发同名撞 UNIQUE）就把上面预扣的名额还回去：核销在 batch 之外、batch 是
    // 整体事务，失败即「没有账号」，退还不至于被白耗一个名额（F-F）
    if (!isFirst && code) await refundSignupCode(c, code);
    return renderError("这个昵称已被占用", 409);
  }
  userId = (await c.env.DB.prepare("SELECT id FROM account WHERE name = ?").bind(name).first<{ id: number }>())!.id;
  // 审计先于会话签发：与登录一致，审计失败时不发会话（fail-closed），不会出现「已注册已登录但无审计」
  await audit(c, "register.ok", { accountId: userId, detail: { name, locked: locked === 1, invited: code !== "" } });
  await createSession(c, userId);
  return c.redirect("/", 303);
});

app.get("/password", async (c) => {
  const user = c.get("user");
  if (!user) return c.redirect("/login", 303);
  const csrf = await ensureCsrfToken(c);
  const next = safeNext(c.req.query("next"));
  return c.html(passwordPage({ csrf, next: next === "/" ? undefined : next }));
});

// 语义与 tour POST /api/auth/password 一致：验旧密码、改 auth 库凭证、清 must_change_pw；
// 差异点：改密后轮换会话（旧 token 全端失效，本浏览器拿到新 cookie，体感仍为已登录）
app.post("/password", async (c) => {
  const user = c.get("user");
  if (!user) return c.redirect("/login", 303);
  // 先解析表单：next 走隐藏字段回传，所有错误重渲染都带上它，二次提交后仍能回 OIDC 目标
  const form = (await c.req.parseBody().catch(() => ({}))) as Form;
  const next = () => safeNext(form.next);
  if (!(await rateLimit(c.env, `pwd:${user.id}`, 5, 900))) {
    return c.html(
      passwordPage({ csrf: await ensureCsrfToken(c), next: next(), error: "尝试太频繁，请 15 分钟后再来" }),
      429,
    );
  }
  if (!csrfValid(c, form.csrf)) {
    return c.html(
      passwordPage({ csrf: await ensureCsrfToken(c), next: next(), error: CSRF_EXPIRED }),
      403,
    );
  }
  const newPassword = formValue(form, "newPassword");
  if (newPassword.length < 8 || !/[A-Za-z]/.test(newPassword) || !/\d/.test(newPassword))
    return c.html(
      passwordPage({
        csrf: await ensureCsrfToken(c),
        next: next(),
        error: "新密码至少 8 位，且要同时包含字母和数字",
      }),
      400,
    );
  const row = await c.env.DB.prepare(
    "SELECT cr.hash AS password_hash FROM credential cr WHERE cr.account_id = ? AND cr.type = 'password'",
  )
    .bind(user.id)
    .first<{ password_hash: string }>();
  if (!row || !(await verifyPassword(formValue(form, "oldPassword"), row.password_hash))) {
    return c.html(
      passwordPage({ csrf: await ensureCsrfToken(c), next: next(), error: "旧密码不对" }),
      400,
    );
  }
  // 账号收口（P0-11）：凭证与 must_change_pw 同批写 auth 库（隐式事务）
  await c.env.DB.batch([
    c.env.DB.prepare(
      "UPDATE credential SET hash = ?, iterations = ?, updated_at = ? WHERE account_id = ? AND type = 'password'",
    ).bind(await hashPassword(newPassword), PBKDF2_ITERATIONS, new Date().toISOString(), user.id),
    c.env.DB.prepare("UPDATE account SET must_change_pw = 0 WHERE id = ?").bind(user.id),
  ]);
  // 会话轮换：旧会话签发的 OIDC token 一并吊销（改密可能是泄露后的处置动作），client 同步收到登出通知
  const oldToken = getCookie(c, SESSION_COOKIE);
  if (oldToken) await revokeSessionAndNotify(c, await sha256Hex(oldToken));
  await destroySession(c);
  await createSession(c, user.id);
  await audit(c, "pw.change", { accountId: user.id });
  const nx = safeNext(form.next);
  return c.redirect(nx === "/" ? "/?notice=pw_changed" : nx, 303);
});

// ---------- QQ 绑定（P0-8，TECH_DESIGN §7） ----------
// 码只出现在已登录的绑定页（防冒充四重校验之一）；「绑定 <码>」由插件 HMAC 调
// /api/bind/claim 核销（routes/machine.ts）；解绑在 QQ 群发「解绑」走 /api/identity/unbind。

app.get("/bind", async (c) => {
  const user = c.get("user");
  if (!user) return c.redirect(`/login?next=${encodeURIComponent("/bind")}`, 303);
  const csrf = await ensureCsrfToken(c);
  const binding = await qqBindingOf(c, user.id);
  return c.html(bindPage({ csrf, qq: binding?.provider_uid ?? null, boundAt: binding?.bound_at ?? null }));
});

// 生成一次性绑定码：10 分钟、一次一用；新码发出即作废同账号旧码
app.post("/bind/code", async (c) => {
  const user = c.get("user");
  if (!user) return c.redirect("/login", 303);
  const form = (await c.req.parseBody().catch(() => ({}))) as Form;
  // 重渲染带上实时绑定态：已绑定用户看到的是绑定卡片 + 错误提示，而不是未绑定的生成表单
  const render = async (opts: { code?: string; error?: string }, status: 200 | 400 | 403 | 429 = 200) => {
    const binding = await qqBindingOf(c, user.id);
    return c.html(
      bindPage({ csrf: await ensureCsrfToken(c), qq: binding?.provider_uid ?? null, boundAt: binding?.bound_at ?? null, ...opts }),
      status,
    );
  };
  if (!csrfValid(c, form.csrf)) return render({ error: CSRF_EXPIRED }, 403);
  if (!(await rateLimit(c.env, `bind-code:${user.id}`, 5, 900))) {
    return render({ error: "生成太频繁，请 15 分钟后再来" }, 429);
  }
  const binding = await qqBindingOf(c, user.id);
  if (binding) return render({ error: "该账号已绑定过 QQ，请先解绑再重新生成" }, 400);
  const now = new Date();
  await c.env.DB.prepare("DELETE FROM bind_code WHERE account_id = ? AND used_at IS NULL").bind(user.id).run();
  const code = sixDigitCode();
  await c.env.DB.prepare(
    "INSERT INTO bind_code (code_hash, account_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
  )
    .bind(await sha256Hex(code), user.id, now.toISOString(), new Date(now.getTime() + 600_000).toISOString())
    .run();
  return render({ code });
});

app.post("/logout", async (c) => {
  const form = (await c.req.parseBody().catch(() => ({}))) as Form;
  // 登出属低风险操作，CSRF 校验不过回首页重试即可，不渲染错误页
  if (!csrfValid(c, form.csrf)) return c.redirect("/", 303);
  const user = c.get("user");
  // 与 OIDC GET /logout 同口径：吊销本会话签发的全部 refresh + back-channel 通知各 client
  const token = getCookie(c, SESSION_COOKIE);
  if (token) await revokeSessionAndNotify(c, await sha256Hex(token));
  await destroySession(c);
  if (user) await audit(c, "logout", { accountId: user.id });
  return c.redirect("/login", 303);
});

export default app;
