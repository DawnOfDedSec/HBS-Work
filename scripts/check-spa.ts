// Smoke test: the dashboard server serves the built SPA at `/` (with deep-link
// fallback) and still returns proper API responses.
// Run: cd dashboard && bun run ../scripts/check-spa.ts

import { resolve } from "node:path";

const dashboardDir = resolve(import.meta.dir, "..", "dashboard");
const port = 20000 + Math.floor(Math.random() * 20000);
const base = `http://127.0.0.1:${port}`;

const server = Bun.spawn(["bun", "server/index.ts"], {
  cwd: dashboardDir,
  env: { ...process.env, HOST: "127.0.0.1", PORT: String(port), HBS_DB_PATH: ":memory:" },
  stdout: "ignore",
  stderr: "ignore",
});

async function wait(): Promise<boolean> {
  for (let i = 0; i < 40; i += 1) {
    try {
      if ((await fetch(`${base}/api/health`)).ok) return true;
    } catch {
      // not up
    }
    await Bun.sleep(250);
  }
  return false;
}

let failures = 0;
function check(condition: unknown, label: string): void {
  console.log(`${condition ? "ok  " : "FAIL"} - ${label}`);
  if (!condition) failures += 1;
}

try {
  check(await wait(), `server up on ${base}`);
  const root = await fetch(`${base}/`);
  const html = await root.text();
  check(root.status === 200 && html.includes('id="root"'), "GET / serves the SPA shell");

  const deep = await fetch(`${base}/campaigns`);
  check(deep.status === 200 && (await deep.text()).includes('id="root"'), "deep link falls back to the SPA");

  const asset = /\/assets\/([^"]+\.js)/.exec(html)?.[1];
  check(!!asset, "SPA references a built asset");
  if (asset) {
    const res = await fetch(`${base}/assets/${asset}`);
    check(res.status === 200 && (res.headers.get("content-type") ?? "").includes("javascript"), "asset served with JS content-type");
  }

  const health = await fetch(`${base}/api/health`);
  check(health.status === 200, "GET /api/health still works");
  const missing = await fetch(`${base}/api/does-not-exist`);
  check(missing.status === 404 || missing.status === 401, "unknown /api/* is not served the SPA (401/404)");
} finally {
  server.kill();
  await server.exited.catch(() => {});
}

if (failures > 0) {
  console.error(`\n${failures} failure(s)`);
  process.exit(1);
}
console.log("\nSPA SERVING PASS");
process.exit(0);
