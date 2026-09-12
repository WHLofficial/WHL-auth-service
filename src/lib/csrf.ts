import { getCookie, setCookie } from "hono/cookie";
import type { Context } from "hono";
import type { AppEnv } from "../env";
import { randomToken } from "./crypto";
import { timingSafeEqual } from "./util";

const CSRF_COOKIE = "whl_csrf";
const CSRF_TTL_SECONDS = 7 * 24 * 3600;

/**
 * 双提交 CSRF（TECH_DESIGN §8.3）：GET 渲染表单时种随机 cookie 并写入隐藏字段，POST 比对两者。
 * cookie 不带 Domain（host-only），同主域兄弟子域无法替用户植入；httpOnly 使页面脚本不可读。
 */
export async function ensureCsrfToken(c: Context<AppEnv>): Promise<string> {
  const existing = getCookie(c, CSRF_COOKIE);
  if (existing) return existing;
  const token = randomToken(16);
  setCookie(c, CSRF_COOKIE, token, {
    httpOnly: true,
    sameSite: "Lax",
    path: "/",
    secure: new URL(c.req.url).protocol === "https:",
    maxAge: CSRF_TTL_SECONDS,
  });
  return token;
}

export function csrfValid(c: Context<AppEnv>, submitted: unknown): boolean {
  if (typeof submitted !== "string" || !submitted) return false;
  const cookieToken = getCookie(c, CSRF_COOKIE);
  if (!cookieToken) return false;
  return timingSafeEqual(cookieToken, submitted);
}
