import { Hono } from "hono";
import type { AppEnv } from "./env";

const app = new Hono<AppEnv>();

app.get("/healthz", (c) => c.json({ ok: true }));

app.notFound((c) => c.text("404 Not Found", 404));

app.onError((err, c) => {
  console.error(err);
  return c.text("Internal Server Error", 500);
});

export default app;
