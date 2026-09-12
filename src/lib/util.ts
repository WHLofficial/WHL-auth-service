export function clientIp(c: { req: { header(name: string): string | undefined } }): string {
  return c.req.header("CF-Connecting-IP") ?? "local";
}

export function nowIso(): string {
  return new Date().toISOString();
}
