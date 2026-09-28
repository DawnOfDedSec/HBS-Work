// Per-campaign access scoping: user restriction storage, campaign gates,
// and the findings/query fence for restricted accounts.

import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { Database } from "bun:sqlite";
import { Hono } from "hono";
import { openDb, runMigrations } from "./db";
import { createAuthRoutes, requireAuth, requireRole, type UserRole } from "./auth";
import { createUserRoutes } from "./users";
import { createCampaignRoutes } from "./campaigns";
import { registerReportRoutes } from "./reports";
import { registerNetworkRoutes } from "./network/routes";

let db: Database;

function makeApp() {
  const app = new Hono();
  app.route("/", createAuthRoutes(db));
  app.use("/api/*", requireAuth(db));
  app.route("/", createUserRoutes(db));
  app.route("/", createCampaignRoutes(db, {
    requireRole: (...roles: string[]) => requireRole(...(roles as UserRole[])) as any,
  }));
  registerReportRoutes(app, db, {
    requireRole: (...roles: string[]) => requireRole(...(roles as UserRole[])) as any,
  });
  registerNetworkRoutes(app, db, {
    requireRole: (...roles: string[]) => requireRole(...(roles as UserRole[])) as any,
  });
  return app;
}

function sessionCookie(response: Response): string {
  const header = response.headers.get("set-cookie") ?? "";
  const cookie = header.split(";")[0];
  if (!cookie.startsWith("hbs_session=")) throw new Error("no session cookie");
  return cookie;
}

async function setupAdmin(app: Hono): Promise<string> {
  const response = await app.request("/api/auth/setup", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username: "admin", password: "correct-horse-battery-42" }),
  });
  expect(response.status).toBe(201);
  return sessionCookie(response);
}

async function login(app: Hono, username: string, password: string): Promise<string> {
  const response = await app.request("/api/auth/login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  expect(response.status).toBe(200);
  return sessionCookie(response);
}

let campaignSeq = 0;
function seedCampaign(name: string): number {
  campaignSeq += 1;
  const timestamp = new Date().toISOString();
  const inserted = db
    .query(
      `INSERT INTO campaigns (name, client, scope, status, tags, created_at, updated_at)
       VALUES (?, NULL, NULL, 'active', '[]', ?, ?)`,
    )
    .run(`${name} ${campaignSeq}`, timestamp, timestamp);
  db.query(
    `INSERT INTO locations (campaign_id, name, tags, created_at, updated_at) VALUES (?, 'HQ', '[]', ?, ?)`,
  ).run(Number(inserted.lastInsertRowid), timestamp, timestamp);
  return Number(inserted.lastInsertRowid);
}

function seedNetworkReport(campaignId: number, locationId: number, hostname: string): number {
  const now = new Date().toISOString();
  const device = db
    .query(
      `INSERT INTO network_devices (device_key, hostname, vendor, device_type, first_seen_at, last_seen_at)
       VALUES (?, ?, 'cisco-ios', 'switch', ?, ?)`,
    )
    .run(`host:${hostname}`, hostname, now, now);
  const findings = [
    {
      checkId: "NET-MGMT-001",
      title: "Telnet management service enabled",
      severity: "High",
      status: "NonCompliant",
      category: "Management",
      description: "",
      evidence: [],
      recommendation: "",
      references: [],
    },
  ];
  const inserted = db
    .query(
      `INSERT INTO network_reports
         (device_id, location_id, campaign_id, config_name, config_sha256, config_size,
          config_text, parsed_json, findings_json, score, received_at, uploaded_by)
       VALUES (?, ?, ?, 'cfg', ?, 64, 'x', '{}', ?, 50, ?, 'admin')`,
    )
    .run(Number(device.lastInsertRowid), locationId, campaignId, `sha-${campaignId}-${hostname}`, JSON.stringify(findings), now);
  return Number(inserted.lastInsertRowid);
}

function locationIdFor(campaignId: number): number {
  const row = db.query("SELECT id FROM locations WHERE campaign_id = ? ORDER BY id LIMIT 1").get(campaignId) as { id: number };
  return row.id;
}

beforeEach(() => {
  db = openDb(":memory:");
  runMigrations(db);
});

afterEach(() => {
  db.close();
});

describe("campaign access scoping", () => {
  it("stores and returns campaign restrictions on users", async () => {
    const app = makeApp();
    const adminCookie = await setupAdmin(app);

    const created = await app.request("/api/users", {
      method: "POST",
      headers: { "content-type": "application/json", cookie: adminCookie },
      body: JSON.stringify({ username: "scoped", password: "quarterly-review-2026", role: "auditor", allowedCampaigns: [1, 3] }),
    });
    expect(created.status).toBe(201);
    expect(((await created.json()) as any).user.allowedCampaigns).toEqual([1, 3]);

    const listed = await app.request("/api/users", { headers: { cookie: adminCookie } });
    const users = ((await listed.json()) as any).users as Array<{ username: string; allowedCampaigns: number[] | null }>;
    expect(users.find((entry) => entry.username === "scoped")?.allowedCampaigns).toEqual([1, 3]);

    const invalid = await app.request("/api/users", {
      method: "POST",
      headers: { "content-type": "application/json", cookie: adminCookie },
      body: JSON.stringify({ username: "bad", password: "another-passphrase-123", allowedCampaigns: ["nope"] }),
    });
    expect(invalid.status).toBe(400);
  });

  it("demotes a restricted account from super_admin", async () => {
    const app = makeApp();
    const adminCookie = await setupAdmin(app);
    const created = await app.request("/api/users", {
      method: "POST",
      headers: { "content-type": "application/json", cookie: adminCookie },
      body: JSON.stringify({ username: "bossy", password: "quarterly-review-2026", role: "super_admin" }),
    });
    const id = ((await created.json()) as any).user.id as number;
    const patched = await app.request(`/api/users/${id}`, {
      method: "PATCH",
      headers: { "content-type": "application/json", cookie: adminCookie },
      body: JSON.stringify({ allowedCampaigns: [2] }),
    });
    expect(patched.status).toBe(200);
    expect(((await patched.json()) as any).user.role).toBe("auditor");
  });

  it("hides unlisted campaigns and gates campaign routes", async () => {
    const app = makeApp();
    const adminCookie = await setupAdmin(app);
    await app.request("/api/users", {
      method: "POST",
      headers: { "content-type": "application/json", cookie: adminCookie },
      body: JSON.stringify({ username: "scoped", password: "quarterly-review-2026", role: "auditor", allowedCampaigns: [] }),
    });
    const allowed = seedCampaign("Allowed");
    const other = seedCampaign("Other");

    // Restrict after the campaigns exist.
    const userId = ((await (
      await app.request("/api/users", { headers: { cookie: adminCookie } })
    ).json()) as any).users.find((entry: any) => entry.username === "scoped").id as number;
    await app.request(`/api/users/${userId}`, {
      method: "PATCH",
      headers: { "content-type": "application/json", cookie: adminCookie },
      body: JSON.stringify({ allowedCampaigns: [allowed] }),
    });

    const scopedCookie = await login(app, "scoped", "quarterly-review-2026");
    const listed = await app.request("/api/campaigns", { headers: { cookie: scopedCookie } });
    const campaigns = (await listed.json()) as Array<{ id: number }>;
    expect(campaigns.some((entry) => entry.id === allowed)).toBe(true);
    expect(campaigns.some((entry) => entry.id === other)).toBe(false);

    const denied = await app.request(`/api/campaigns/${other}`, { headers: { cookie: scopedCookie } });
    expect(denied.status).toBe(403);
    const permitted = await app.request(`/api/campaigns/${allowed}`, { headers: { cookie: scopedCookie } });
    expect(permitted.status).toBe(200);
  });

  it("fences global findings to the allowed campaigns", async () => {
    const app = makeApp();
    const adminCookie = await setupAdmin(app);
    const allowed = seedCampaign("Allowed");
    const other = seedCampaign("Other");
    seedNetworkReport(allowed, locationIdFor(allowed), "fw-allowed");
    seedNetworkReport(other, locationIdFor(other), "fw-other");

    await app.request("/api/users", {
      method: "POST",
      headers: { "content-type": "application/json", cookie: adminCookie },
      body: JSON.stringify({ username: "scoped", password: "quarterly-review-2026", role: "auditor", allowedCampaigns: [allowed] }),
    });
    const scopedCookie = await login(app, "scoped", "quarterly-review-2026");

    const scoped = await app.request("/api/findings?source=network", { headers: { cookie: scopedCookie } });
    expect(scoped.status).toBe(200);
    const body = (await scoped.json()) as { total: number; results: Array<{ hostname: string; campaignId: number }> };
    expect(body.total).toBe(1);
    expect(body.results[0].campaignId).toBe(allowed);

    const everything = await app.request("/api/findings?source=network", { headers: { cookie: adminCookie } });
    expect(((await everything.json()) as any).total).toBe(2);
  });
});
