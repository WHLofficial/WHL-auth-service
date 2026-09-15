import { Hono } from "hono";
import type { AppEnv } from "./env";
import { contentSecurityPolicy } from "./lib/csp";
import { clearExpiredLimits } from "./lib/ratelimit";
import { getSessionUser } from "./lib/session";
import routes from "./routes/pages";
import oidcRoutes from "./routes/oidc";
import machineRoutes from "./routes/machine";
import { errorPage } from "./web/pages";

const app = new Hono<AppEnv>();

// 所有页面共用：读会话挂 user（未登录为 null）
app.use(async (c, next) => {
  c.set("user", await getSessionUser(c));
  await next();
});

// 强制改密门禁（PRD P0-2「must_change_pw 强制改密」）：管理员重置出来的临时密码只够进改密页，
// 在改密完成前不得访问业务页、也不得走 /authorize 换授权码进三系统（改密链路靠 next 原样回跳）。
// 放行的只有改密/登出/登录自身、静态契约（healthz/.well-known/jwks）与不依赖会话的机器端点。
const PW_EXEMPT_PATHS = new Set(["/healthz", "/login", "/password", "/logout", "/jwks.json", "/userinfo", "/token", "/revoke"]);
function pwExempt(path: string): boolean {
  return PW_EXEMPT_PATHS.has(path) || path.startsWith("/.well-known/") || path.startsWith("/api/");
}
app.use(async (c, next) => {
  if (!c.get("user")?.mustChangePassword) return next();
  const path = c.req.path;
  if (pwExempt(path)) return next();
  const search = new URL(c.req.url).search;
  return c.redirect(`/password?next=${encodeURIComponent(path + search)}`, 303);
});

// 基础安全响应头：页面不允许被嵌入、不允许缓存；无脚本，CSP 只放行内联样式与同源表单
app.use(async (c, next) => {
  await next();
  c.header("X-Content-Type-Options", "nosniff");
  c.header("X-Frame-Options", "DENY");
  c.header("Referrer-Policy", "no-referrer");
  c.header("Cache-Control", "no-store");
  // 全站经 CF 边缘走 HTTPS；HSTS 由 Worker 兜底（HTTP 响应按规范忽略此头）
  c.header("Strict-Transport-Security", "max-age=31536000");
  c.header("Content-Security-Policy", await contentSecurityPolicy(c));
});

app.get("/healthz", (c) => c.json({ ok: true }));

app.route("/", routes);
app.route("/", oidcRoutes);
app.route("/", machineRoutes);

app.notFound((c) => c.html(errorPage(404), 404));

app.onError((err, c) => {
  console.error(err);
  return c.html(errorPage(500), 500);
});

// 除了 fetch 还要 scheduled：每日扫掉限流计数表里过期的窗口行（cron 见 wrangler.jsonc triggers）。
// 请求路径只清自己那把键的历史行，跨键的堆积由这里兜底（见 lib/ratelimit.ts）。
export default {
  fetch: app.fetch,
  scheduled: async (_event: unknown, env: AppEnv["Bindings"]) => {
    await clearExpiredLimits(env);
  },
};
