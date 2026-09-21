import { Hono } from "hono";

const app = new Hono();
app.get("/api/health", (c) => c.json({ ok: true }));

const port = Number(process.env.PORT ?? 8787);
const host = process.argv.includes("--host") ? "0.0.0.0" : "127.0.0.1";

console.log(`hbs-dashboard listening on http://${host}:${port}`);

export default {
  port,
  hostname: host,
  fetch: app.fetch,
};
