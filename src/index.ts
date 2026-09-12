import { Hono } from "hono";
import type { AppEnv } from "./env";
import { getSessionUser } from "./lib/session";
import routes from "./routes/pages";
import { errorPage } from "./web/pages";

const app = new Hono<AppEnv>();

// 所有页面共用：读兼容会话挂 user（未登录为 null）
app.use(async (c, next) => {
  c.set("user", await getSessionUser(c));
  await next();
});

// 基础安全响应头：页面不允许被嵌入、不允许缓存；无脚本，CSP 只放行内联样式与同源表单
app.use(async (c, next) => {
  await next();
  c.header("X-Content-Type-Options", "nosniff");
  c.header("X-Frame-Options", "DENY");
  c.header("Referrer-Policy", "no-referrer");
  c.header("Cache-Control", "no-store");
  c.header(
    "Content-Security-Policy",
    "default-src 'self'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  );
});

app.get("/healthz", (c) => c.json({ ok: true }));

app.route("/", routes);

app.notFound((c) => c.html(errorPage(404), 404));

app.onError((err, c) => {
  console.error(err);
  return c.html(errorPage(500), 500);
});

export default app;
