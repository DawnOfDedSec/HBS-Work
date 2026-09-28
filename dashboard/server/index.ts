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
import { embeddedFile, embeddedIndexHtml, hasEmbeddedDist } from "./embedded-dist";
import {
  configPath,
  effectiveFromEnv,
  loadHostingSettings,
  saveHostingSettings,
  settingsFingerprint,
  settingsToEnv,
} from "./config-store";

// --- headless config CLI (the desktop shell's settings editor) --------------
// Runs before any database or network setup and exits. The desktop app has no
// session cookie, so it edits the sealed config through this path instead of
// duplicating the AEAD format in Rust. Output is one JSON object on stdout.
function runConfigCli(argv: string[], env: NodeJS.ProcessEnv): { code: number; out: unknown } | null {
  const applyIndex = argv.indexOf("--apply-config");
  const print = argv.includes("--print-config");
  if (applyIndex < 0 && !print) return null;
  if (applyIndex >= 0) {
    const file = argv[applyIndex + 1];
    if (!file || file.startsWith("--")) {
      return { code: 2, out: { ok: false, error: "--apply-config needs a JSON file path" } };
    }
    let body: unknown;
    try {
      body = JSON.parse(readFileSync(file, "utf8"));
    } catch {
      return { code: 1, out: { ok: false, error: `could not read a JSON config from ${file}` } };
    }
    const result = saveHostingSettings(body, env, "desktop");
    if (!result.ok) return { code: 1, out: result };
    // The caller's environment still describes the running binding, so a
    // difference means the engine must restart before the change applies.
    const effective = effectiveFromEnv(env);
    return {
      code: 0,
      out: { ...result, restartRequired: settingsFingerprint(result.settings) !== settingsFingerprint(effective) },
    };
  }
  const loaded = loadHostingSettings(env);
  const settings = loaded.status === "ok" ? loaded.settings : effectiveFromEnv(env);
  const storage: Record<string, unknown> = { path: configPath(env), encrypted: true };
  if (loaded.status === "tampered" || loaded.status === "error") storage.error = loaded.error;
  return { code: 0, out: { status: loaded.status, settings, storage } };
}

const configCli = runConfigCli(process.argv, process.env);
if (configCli) {
  console.log(JSON.stringify(configCli.out));
  process.exit(configCli.code);
}

// The sealed config is authoritative; hbs.env is the installer's bootstrap and
// a mirror the supervisors read. Precedence stays CLI flag > sealed config >
// environment > default, so `--port` still wins for one-off dev runs.
const stored = loadHostingSettings(process.env);
if (stored.status === "tampered" || stored.status === "error") {
  console.error(`hbs-dashboard: stored settings ignored - ${stored.error}`);
}
const storedEnv = stored.status === "ok" ? settingsToEnv(stored.settings) : {};
const parsed = parseServerOptions(process.argv, { ...process.env, ...storedEnv });
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

// First-run administrator. By default nothing is created here: the console
// shows its setup wizard (POST /api/auth/setup) so the operator picks their own
// username and password. Unattended installs opt in with
// HBS_BOOTSTRAP_ADMIN=true (+ HBS_ADMIN_USERNAME / HBS_ADMIN_PASSWORD), which
// prints the generated credentials once. Only when the server is the entrypoint
// (not when the module is imported by tests).
const bootstrapMode = process.env.HBS_BOOTSTRAP_ADMIN?.trim();
const bootstrapRequested =
  bootstrapMode === "true" || (bootstrapMode !== "false" && !!process.env.HBS_ADMIN_PASSWORD?.trim());
if (import.meta.main && bootstrapRequested) {
  const { ensureBootstrapAdmin } = await import("./bootstrap");
  const created = await ensureBootstrapAdmin(db);
  if (created) {
    const rule = "=".repeat(72);
    console.log(rule);
    console.log("  HBS dashboard - superuser created (HBS_BOOTSTRAP_ADMIN)");
    console.log(`  username: ${created.username}`);
    console.log(`  password: ${created.password}`);
    console.log("  Store these credentials securely and change the password after sign-in.");
    console.log("  To use the in-console setup wizard instead, unset HBS_BOOTSTRAP_ADMIN.");
    console.log(rule);
  }
} else if (import.meta.main) {
  const users = (db.query("SELECT COUNT(*) AS count FROM users").get() as { count: number }).count;
  if (users === 0) {
    console.log("HBS dashboard: no administrator yet - open the console to run the setup wizard.");
  }
}

const app = new Hono();
const MAX_RAW_BODY = 64 * 1024 * 1024;

// --- hardening: headers, no-store on the API, cross-origin writes ------------
// HBS is a local/LAN console with cookie sessions, so these close the cheap
// attack classes (clickjacking, MIME sniffing, referrer leaks, XSS payload
// hosting) without a proxy in front. HBS_DISABLE_SECURITY_HEADERS=true turns
// them off for an exotic deployment, HBS_DISABLE_ORIGIN_CHECK=true for a proxy
// that rewrites Origin.
const distDir = resolve(import.meta.dir, "..", "dist");

const UNSAFE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
// Same-machine origins are trusted: Vite's dev proxy and local reverse proxies
// keep the browser's Origin while talking to the API on another port.
const LOCAL_ORIGIN = /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/;

/** The built shell carries one inline theme-guard script; allow exactly it. */
function contentSecurityPolicy(): string {
  const hashes: string[] = [];
  try {
    // Standalone binaries carry the shell embedded; repo checkouts read dist/.
    const html = embeddedIndexHtml() ?? readFileSync(join(distDir, "index.html"), "utf8");
    for (const match of html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi)) {
      const body = match[1];
      if (body.trim()) {
        hashes.push(`'sha256-${new Bun.CryptoHasher("sha256").update(body).digest("base64")}'`);
      }
    }
  } catch {
    // No build output (dev server or API-only run): keep scripts same-origin.
  }
  const scriptSrc = hashes.length > 0 ? `'self' ${hashes.join(" ")}` : "'self' 'unsafe-inline'";
  return (
    "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; " +
    `object-src 'none'; script-src ${scriptSrc}; style-src 'self' 'unsafe-inline'; ` +
    "img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; worker-src 'self' blob:"
  );
}

app.use("*", async (c, next) => {
  await next();
  if (process.env.HBS_DISABLE_SECURITY_HEADERS?.trim() === "true") return;
  c.res.headers.set("content-security-policy", contentSecurityPolicy());
  c.res.headers.set("x-content-type-options", "nosniff");
  c.res.headers.set("x-frame-options", "DENY");
  c.res.headers.set("referrer-policy", "no-referrer");
  c.res.headers.set("cross-origin-opener-policy", "same-origin");
  c.res.headers.set("cross-origin-resource-policy", "same-origin");
  c.res.headers.set("permissions-policy", "camera=(), microphone=(), geolocation=(), usb=(), payment=()");
  // Authenticated payloads must never sit in a shared/browser cache.
  if (c.req.path.startsWith("/api/")) c.res.headers.set("cache-control", "no-store");
  const forwarded = c.req.header("x-forwarded-proto")?.split(",", 1)[0]?.trim();
  if (c.req.url.startsWith("https://") || forwarded === "https") {
    c.res.headers.set("strict-transport-security", "max-age=31536000");
  }
});

app.use("*", async (c, next) => {
  if (UNSAFE_METHODS.has(c.req.method) && process.env.HBS_DISABLE_ORIGIN_CHECK?.trim() !== "true") {
    const origin = c.req.header("origin");
    if (origin && !LOCAL_ORIGIN.test(origin)) {
      let originHost: string | null = null;
      try {
        originHost = new URL(origin).host;
      } catch {
        originHost = null;
      }
      const allowed = [c.req.header("host"), c.req.header("x-forwarded-host")].filter(
        (value): value is string => !!value,
      );
      if (!originHost || !allowed.includes(originHost)) {
        return c.json({ error: "cross-origin request rejected" }, 403);
      }
    }
  }
  await next();
});
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
  env: process.env,
  effective: {
    host,
    port,
    tls: !!tlsCertPath,
    tlsCert: tlsCertPath,
    tlsKey: tlsKeyPath,
    exposed: isExposed(host),
  },
});
registerExportRoutes(app, db, campaignAuth);

// --- built SPA (production) -------------------------------------------------
// Two sources, preferred in this order: assets embedded in a standalone
// server binary (`bun build --compile`, see tools/embed-dist.ts) or
// dashboard/dist on disk (repo checkouts). Both keep /api/* with the API (and
// its 404s); both fall back to the SPA shell so deep links work.
const indexHtml = join(distDir, "index.html");
if (hasEmbeddedDist()) {
  const serveFromBundle = (path: string): Response | null => {
    const file = embeddedFile(path);
    if (!file) return null;
    return new Response(file.body, { headers: { "content-type": file.contentType } });
  };
  app.on("GET", ["/assets/*", "/fonts/*"], (c) => {
    // Self-hosted fonts live in public/fonts, so Vite emits them to
    // dist/fonts. Serving only /assets/* meant every font request fell
    // through to the SPA fallback, got the HTML shell back, and the browser
    // quietly used the OS default face - in production only, since `bun run
    // dev` lets Vite serve public/ itself. Guarded by server/static.test.ts.
    return serveFromBundle(c.req.path.slice(1)) ?? c.notFound();
  });
  app.get("*", (c, next) => {
    if (c.req.path.startsWith("/api/")) return next();
    return (
      serveFromBundle(c.req.path.slice(1)) ??
      serveFromBundle("index.html") ??
      c.notFound()
    );
  });
} else if (existsSync(indexHtml)) {
  app.use("/assets/*", serveStatic({ root: distDir }));
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
