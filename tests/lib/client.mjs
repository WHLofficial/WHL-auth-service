// 轻量 HTTP 测试客户端：cookie jar + 表单提交 + CSRF 自动提取。
// 只面向本地 wrangler dev（默认 http://127.0.0.1:8792），不做任何远程请求。

export const BASE = process.env.AUTH_BASE || "http://127.0.0.1:8792";

export class Client {
  constructor(base = BASE, jar = new Map(), ip) {
    this.base = base;
    this.jar = jar; // name -> value，手动管理，方便断言 Set-Cookie 行为
    // 每个 Client 默认独立随机 IP：本地 wrangler dev 不注入 CF-Connecting-IP，
    // 不隔离会让所有请求共享 "local" 桶，10 次/15 分钟的 IP 限流会互相打死测试。
    this.ip = ip || `10.${(Math.random() * 254 + 1) | 0}.${(Math.random() * 254 + 1) | 0}.${(Math.random() * 254 + 1) | 0}`;
  }

  cookieHeader() {
    if (!this.jar.size) return "";
    return [...this.jar].map(([k, v]) => `${k}=${v}`).join("; ");
  }

  storeCookies(res) {
    const list = typeof res.headers.getSetCookie === "function" ? res.headers.getSetCookie() : [];
    for (const sc of list) {
      const [pair] = sc.split(";");
      const idx = pair.indexOf("=");
      const name = pair.slice(0, idx).trim();
      const value = pair.slice(idx + 1).trim();
      if (value === "" || /Max-Age=0/i.test(sc) || /Expires=Thu, 01 Jan 1970/i.test(sc)) this.jar.delete(name);
      else this.jar.set(name, value);
    }
  }

  // init.retry=false 关掉重试：消费一次性凭据（OIDC code、注册码等）的请求重放会产生幽灵状态。
  async raw(path, init = {}) {
    const { retry = true, ...rest } = init;
    const headers = new Headers(rest.headers || {});
    if (!headers.has("CF-Connecting-IP") && this.ip) headers.set("CF-Connecting-IP", this.ip);
    const ch = this.cookieHeader();
    if (ch) headers.set("cookie", ch);
    // 强制短连接：undici 的 keep-alive 池会复用已被服务端关掉的空闲 socket，表现为偶发 ECONNRESET。
    // 不能重放的请求（POST /token 换码、refresh 轮换）一旦撞上就直接用例失败，故这里干脆放弃连接复用。
    if (!headers.has("connection")) headers.set("connection", "close");
    // 兜底：即便如此仍可能遇到连接级抖动，幂等请求再重试一次。
    for (let attempt = 0; ; attempt++) {
      try {
        const res = await fetch(this.base + path, { ...rest, headers, redirect: "manual" });
        this.storeCookies(res);
        return res;
      } catch (e) {
        const isReset = e.cause?.code === "ECONNRESET" || e.cause?.code === "UND_ERR_SOCKET" || e.cause?.code === "ECONNREFUSED";
        if (!isReset || !retry || attempt >= 2) throw e;
        await new Promise((r) => setTimeout(r, 150 * (attempt + 1)));
      }
    }
  }

  get(path, init) {
    return this.raw(path, { ...init, method: "GET" });
  }

  async postForm(path, fields, init = {}) {
    const body = new URLSearchParams(fields).toString();
    return this.raw(path, {
      ...init,
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", ...(init?.headers || {}) },
      body,
    });
  }

  async text(path, init) {
    const res = await this.get(path, init);
    return { res, body: await res.text() };
  }

  // 取页面里的 csrf 隐藏域（顺带建立 whl_csrf cookie）
  async csrf(path = "/login") {
    const { body } = await this.text(path);
    const m = /name="csrf" value="([^"]+)"/.exec(body);
    if (!m) throw new Error(`页面 ${path} 未找到 csrf 隐藏域`);
    return m[1];
  }

  async loginWithCsrf(name, password, next) {
    const csrf = await this.csrf("/login");
    const fields = { csrf, name, password };
    if (next !== undefined) fields.next = next;
    const res = await this.postForm("/login", fields);
    return { res, csrf, body: await res.text() };
  }
}

// 一次登录：返回 { res, client, body }
export async function login(name, password, { next, base = BASE, ip } = {}) {
  const c = new Client(base, new Map(), ip);
  const csrf = await c.csrf("/login");
  const fields = { csrf, name, password };
  if (next !== undefined) fields.next = next;
  const res = await c.postForm("/login", fields);
  const body = await res.text();
  return { client: c, res, body, status: res.status, location: res.headers.get("location") };
}

export function assert(cond, msg) {
  if (!cond) throw new Error(msg || "assertion failed");
}

export function assertEq(actual, expected, msg) {
  if (actual !== expected) throw new Error(`${msg || "assertEq"}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}
