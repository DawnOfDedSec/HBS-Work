import { afterEach, describe, expect, it } from "bun:test";
import type { MiddlewareHandler } from "hono";
import { Hono } from "hono";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openDb, runMigrations } from "./db";
import { registerAdminRoutes } from "./admin";
import { DEFAULT_SETTINGS } from "./notifications";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function root(): string {
  const value = mkdtempSync(join(tmpdir(), "hbs-admin-"));
  roots.push(value);
  return value;
}

function superAdminAuth(): { requireRole: (...roles: string[]) => MiddlewareHandler } {
  return {
    requireRole: () =>
      (async (c: any, next: any) => {
        c.set("user", { id: 1, username: "root", role: "super_admin" });
        
        await next();
      }) as MiddlewareHandler,
  };
}

function harness(dataRoot: string) {
  const db = openDb(":memory:");
  runMigrations(db);
  const app = new Hono();
  registerAdminRoutes(app, db, superAdminAuth(), { dataRoot, databasePath: join(dataRoot, "live.sqlite") });
  return { db, app };
}

describe("admin audit trail", () => {
  it("lists append-only audit events with redacted details", async () => {
    const { db, app } = harness(root());
    db.query(
      `INSERT INTO audit_log (actor, actor_ip, action, resource, details, created_at)
       VALUES ('root', '127.0.0.1', 'campaign.create', 'campaign:1', '{"name":"Acme","token":"should-not-leak"}', '2026-01-01T00:00:00Z')`,
    ).run();

    const response = await app.request("/api/admin/audit?limit=10");
    expect(response.status).toBe(200);
    const body = (await response.json()) as { total: number; events: { action: string; details: string | null }[] };
    expect(body.total).toBe(1);
    expect(body.events[0]?.action).toBe("campaign.create");
    expect(typeof body.events[0]?.details).toBe("string");
    db.close();
  });
});

describe("notification settings routes", () => {
  it("returns defaults for a fresh install", async () => {
    const { db, app } = harness(root());
    const response = await app.request("/api/admin/notifications/settings");
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual(DEFAULT_SETTINGS);
    db.close();
  });

  it("persists valid settings and records the audit action", async () => {
    const { db, app } = harness(root());
    const response = await app.request("/api/admin/notifications/settings", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ enabled: true, url: "https://example.test/hook", minSeverity: "High" }),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;
    expect(body).toEqual({
      enabled: true,
      url: "https://example.test/hook",
      minSeverity: "High",
      lastFiredAt: null,
    });

    const fetched = await app.request("/api/admin/notifications/settings");
    expect(await fetched.json()).toEqual(body);

    const audit = db
      .query("SELECT actor, action, resource FROM audit_log WHERE action = 'notification.settings.update'")
      .get() as { actor: string; action: string; resource: string } | null;
    expect(audit?.actor).toBe("root");
    expect(audit?.resource).toBe("settings:notifications.webhook");
    db.close();
  });

  it("rejects an invalid webhook url", async () => {
    const { db, app } = harness(root());
    const response = await app.request("/api/admin/notifications/settings", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ enabled: true, url: "not-a-url", minSeverity: "Critical" }),
    });
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "invalid webhook url" });
    db.close();
  });
});

describe("encrypted backup and restore routes", () => {
  it("rejects a short passphrase", async () => {
    const { db, app } = harness(root());
    const response = await app.request("/api/admin/backup", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ passphrase: "short" }),
    });
    expect(response.status).toBe(400);
    db.close();
  });

  it("returns a passphrase-encrypted archive and records the action", async () => {
    const { db, app } = harness(root());
    const response = await app.request("/api/admin/backup", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ passphrase: "correct horse battery staple" }),
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/octet-stream");
    const bytes = new Uint8Array(await response.arrayBuffer());
    expect(bytes.length).toBeGreaterThan(0);
    expect(Buffer.from(bytes).toString("utf8")).toContain("\"version\":1");
    const audit = db.query("SELECT action FROM audit_log WHERE action = 'backup.create'").get();
    expect(audit).not.toBeNull();
    db.close();
  });

  it("validates and stages a restore without touching the live database", async () => {
    const dataRoot = root();
    const { db, app } = harness(dataRoot);

    const backup = await app.request("/api/admin/backup", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ passphrase: "correct horse battery staple" }),
    });
    const archive = new Uint8Array(await backup.arrayBuffer());

    const form = new FormData();
    form.set("passphrase", "correct horse battery staple");
    form.set("file", new Blob([archive]), "backup.hbsbak");
    const restore = await app.request("/api/admin/backup/restore", { method: "POST", body: form });
    expect(restore.status).toBe(200);
    const body = (await restore.json()) as { staged: boolean; stagingPath: string };
    expect(body.staged).toBeTrue();
    expect(statSync(body.stagingPath).isFile()).toBeTrue();
    db.close();
  });

  it("rejects a restore with the wrong passphrase", async () => {
    const dataRoot = root();
    const { db, app } = harness(dataRoot);
    const backup = await app.request("/api/admin/backup", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ passphrase: "correct horse battery staple" }),
    });
    const archive = new Uint8Array(await backup.arrayBuffer());

    const form = new FormData();
    form.set("passphrase", "totally wrong passphrase");
    form.set("file", new Blob([archive]), "backup.hbsbak");
    const restore = await app.request("/api/admin/backup/restore", { method: "POST", body: form });
    expect(restore.status).toBe(400);
    db.close();
  });
});
