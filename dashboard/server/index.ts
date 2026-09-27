import { X509Certificate } from "node:crypto";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { Hono } from "hono";
import { serveStatic } from "hono/bun";
import { openDb, runMigrations } from "./db";
import { createAuthRoutes, requireAuth, requireRole } from "./auth";
import { createCampaignRoutes, type CampaignAuth } from "./campaigns";
import { registerLocationRoutes } from "./locations";
import { registerIssuanceRoutes } from "./issuances";
import { registerDownloadRoutes } from "./downloads";
import { createUserRoutes } from "./users";
import { MAX_BATCH_FILES, configureIngest, ingestBatch, validateAndIngestEnvelope } from "./ingest";
import { registerReportRoutes } from "./reports";
import { registerRemediationRoutes } from "./remediation";
import { registerAdminRoutes } from "./admin";
import { registerNetworkRoutes } from "./network/routes";
import { registerExportRoutes } from "./exports/xlsx";
import { reportEvents } from "./sse";
import { streamSSE } from "hono/streaming";

import { networkInterfaces } from "node:os";
import { USAGE, isExposed, parseServerOptions } from "./options";

const parsed = parseServerOptions(process.argv, process.env);
if (!parsed.ok) {
  console.error(`hbs-dashboard: ${parsed.error}\n\n${USAGE}`);
  process.exit(2);
}
if ("help" in parsed) {
  console.log(parsed.help);
  process.exit(0);
}
const { host, port, dbPath, tlsCert: tlsCertPath, tlsKey: tlsKeyPath } = parsed.options;
if (dbPath !== ":memory:") mkdirSync(dirname(dbPath), { recursive: true });

export const db = openDb(dbPath);
const version = runMigrations(db);
console.log(`hbs-dashboard database schema version ${version}`);

// First-run bootstrap: create and print the initial super_admin. Only when the
// server is the entrypoint (not when the module is imported by tests).
if (import.meta.main && process.env.HBS_BOOTSTRAP_ADMIN !== "false") {
  const { ensureBootstrapAdmin } = await import("./bootstrap");
  const created = await ensureBootstrapAdmin(db);
  if (created) {
    const rule = "=".repeat(72);
    console.log(rule);
    console.log("  HBS dashboard - first-run superuser created");
    console.log(`  username: ${created.username}`);
    console.log(`  password: ${created.password}`);
    console.log("  Store these credentials securely and change the password after sign-in.");
    console.log("  (Set HBS_BOOTSTRAP_ADMIN=false to skip this; HBS_ADMIN_USERNAME /");
    console.log("   HBS_ADMIN_PASSWORD override the generated values.)");
    console.log(rule);
  }
}

const app = new Hono();
const MAX_RAW_BODY = 64 * 1024 * 1024;
configureIngest({ db, dataRoot: process.env.HBS_DATA_ROOT });

function bearer(header: string | undefined): string {
  const value = header ?? "";
  return value.toLowerCase().startsWith("bearer ") ? value.slice(7).trim() : value.trim();
}

// --- public routes (no session required) ---
app.get("/api/health", (c) => c.json({ ok: true }));
app.route("/", createAuthRoutes(db));
// Download is authenticated by session OR a campaign download token, so it is
// registered before the session gate.
registerDownloadRoutes(app, db);

// Extractor push: authenticated by the campaign push token, not a session.
app.post("/api/ingest", async (c) => {
  const declared = Number(c.req.header("content-length") ?? "0");
  if (Number.isFinite(declared) && declared > MAX_RAW_BODY) {
    return c.json({ error: "payload too large", code: "BODY_TOO_LARGE" }, 413);
  }
  const bytes = new Uint8Array(await c.req.arrayBuffer());
  if (bytes.length > MAX_RAW_BODY) {
    return c.json({ error: "payload too large", code: "BODY_TOO_LARGE" }, 413);
  }
  const result = await validateAndIngestEnvelope(bytes, "push", {
    kind: "push",
    token: bearer(c.req.header("authorization")),
  });
  return c.json(result, result.ok ? 200 : 400);
});

// --- session-gated API ---
const campaignAuth: CampaignAuth = {
  requireRole: (...roles) => requireRole(...(roles as Parameters<typeof requireRole>)) as never,
};
app.use("/api/*", requireAuth(db));
app.route("/", createUserRoutes(db));

// Multipart batch upload: each file is ingested independently.
app.post("/api/reports/upload", requireRole("super_admin", "auditor"), async (c) => {
  const declared = Number(c.req.header("content-length") ?? "0");
  if (Number.isFinite(declared) && declared > MAX_RAW_BODY) {
    return c.json({ error: "payload too large", code: "BODY_TOO_LARGE" }, 413);
  }
  const form = await c.req.formData().catch(() => null);
  if (!form) return c.json({ error: "expected multipart form data" }, 400);
  const files: { name: string; bytes: Uint8Array }[] = [];
  for (const value of form.values()) {
    if (typeof value === "string") continue;
    const file = value as unknown as { name?: string; arrayBuffer(): Promise<ArrayBuffer> };
    files.push({ name: file.name || "report.hbs", bytes: new Uint8Array(await file.arrayBuffer()) });
  }
  if (files.length === 0) return c.json({ error: "no files provided" }, 400);
  if (files.length > MAX_BATCH_FILES) {
    return c.json({ error: `at most ${MAX_BATCH_FILES} files per batch`, code: "BATCH_TOO_LARGE" }, 413);
  }
  const user = c.get("user");
  const results = await ingestBatch(files, { kind: "session", user });
  return c.json({ results });
});

// Live refresh stream: emits report-arrived (IDs/links only) after a commit.
app.get("/api/events", (c) =>
  streamSSE(c, async (stream) => {
    const unsubscribe = reportEvents.subscribe((event) => {
      void stream.writeSSE({ event: event.event, data: JSON.stringify(event.data) });
    });
    stream.onAbort(() => unsubscribe());
    for (;;) {
      await stream.sleep(15_000);
      await stream.writeSSE({ event: "heartbeat", data: String(Date.now()) });
    }
  }),
);

const campaignApp = createCampaignRoutes(db, campaignAuth);
registerLocationRoutes(campaignApp, db, campaignAuth);
registerIssuanceRoutes(campaignApp, db, campaignAuth, {
  dataRoot: process.env.HBS_DATA_ROOT,
});
app.route("/", campaignApp);

// Scoped report/findings/summary/diff/telemetry/standards/treatment, saved
// views, and the super-admin diagnostic bundle.
registerReportRoutes(app, db, campaignAuth);
registerRemediationRoutes(app, db, campaignAuth);
// Network device / firewall configuration review (upload → parse → review).
registerNetworkRoutes(app, db, campaignAuth);
registerAdminRoutes(app, db, campaignAuth, {
  databasePath: dbPath === ":memory:" ? undefined : dbPath,
  dataRoot: process.env.HBS_DATA_ROOT,
});
registerExportRoutes(app, db, campaignAuth);

// --- built SPA (production) -------------------------------------------------
// `bun run build` emits dashboard/dist; serve it at `/` with an SPA fallback
// so deep links work, while leaving /api/* to the API (and its 404s) alone.
const distDir = resolve(import.meta.dir, "..", "dist");
const indexHtml = join(distDir, "index.html");
if (existsSync(indexHtml)) {
  app.use("/assets/*", serveStatic({ root: distDir }));
  // Self-hosted fonts live in public/fonts, so Vite emits them to
  // dist/fonts. Serving only /assets/* meant every font request fell
  // through to the SPA fallback below, got the HTML shell back, and the
  // browser quietly used the OS default face - in production only, since
  // `bun run dev` lets Vite serve public/ itself. Guarded by
  // server/static.test.ts.
  app.use("/fonts/*", serveStatic({ root: distDir }));
  app.get("*", (c, next) => {
    if (c.req.path.startsWith("/api/")) return next();
    return serveStatic({ path: indexHtml })(c, next);
  });
} else {
  app.get("/", (c) =>
    c.text("HBS dashboard: the SPA is not built yet. Run `bun run build` in dashboard/, or use `bun run dev` (Vite) for development."),
  );
}

const tls = tlsCertPath && tlsKeyPath
  ? { cert: readFileSync(tlsCertPath), key: readFileSync(tlsKeyPath) }
  : undefined;
if (tls && tlsCertPath) {
  const fingerprint = new X509Certificate(readFileSync(tlsCertPath)).fingerprint256;
  console.log(`hbs-dashboard TLS certificate SHA-256 ${fingerprint}`);
}

const scheme = tls ? "https" : "http";
if (isExposed(host)) {
  const urls = new Set<string>();
  if (host === "0.0.0.0" || host === "::") {
    for (const entries of Object.values(networkInterfaces())) {
      for (const entry of entries ?? []) {
        if (entry.family === "IPv4" && !entry.internal) urls.add(`${scheme}://${entry.address}:${port}`);
      }
    }
    if (urls.size === 0) urls.add(`${scheme}://localhost:${port}`);
  } else {
    urls.add(`${scheme}://${host}:${port}`);
  }
  console.log(`hbs-dashboard is exposed on the network (${host}):`);
  for (const url of urls) console.log(`  ${url}`);
  if (!tls) {
    console.log("  WARNING: TLS is not configured - dashboard traffic and session cookies are unencrypted. Use --tls-cert/--tls-key on untrusted networks.");
  }
} else {
  console.log(`hbs-dashboard listening on ${scheme}://${host}:${port} (localhost only; pass --host to expose it)`);
}

export { app };
export default {
  port,
  hostname: host,
  fetch: app.fetch,
  ...(tls ? { tls } : {}),
};
