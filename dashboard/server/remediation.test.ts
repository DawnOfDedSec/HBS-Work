// Remediation Center aggregation tests.
//
// The fixtures mirror the report JSON the extractor emits, inserted directly so
// the canonical query layer can be exercised without the crypto envelope path.

import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import type { Database } from "bun:sqlite";
import { Hono } from "hono";
import { openDb, runMigrations } from "./db";
import { requireRole, type UserRole } from "./auth";
import { registerRemediationRoutes } from "./remediation";

type TestUser = { id: number; username: string; role: string };

const VIEWER: TestUser = { id: 1, username: "viewer1", role: "viewer" };

let db: Database;
let reportSeq = 0;

function makeApp(user: TestUser | null) {
  const app = new Hono();
  app.use("*", async (c, next) => {
    if (user) (c as any).set("user", user);
    await next();
  });
  registerRemediationRoutes(app, db, {
    requireRole: (...roles: string[]) => requireRole(...(roles as UserRole[])) as never,
  });
  return app;
}

async function request(user: TestUser | null, path: string) {
  const response = await makeApp(user).request(path);
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : null };
}

function check(input: {
  id: string;
  status: string;
  severity: string;
  category: string;
  title: string;
  recommendation?: string;
  impact?: string;
  repro?: string;
  location?: string;
  references?: string[];
}): Record<string, unknown> {
  return {
    id: input.id,
    title: input.title,
    status: input.status,
    severity: input.severity,
    category: input.category,
    description: `${input.title} description`,
    impact: input.impact ?? "impact text",
    recommendation: input.recommendation ?? "recommendation text",
    references: input.references ?? [],
    evidence: "EVIDENCE_SENTINEL",
    location: input.location ?? "/etc/example.conf",
    repro: input.repro ?? "cat /etc/example.conf",
    degradedReason: null,
    fallbackLog: [],
    evidenceBlocks: [],
    runContext: { user: "root", uid: 0, elevated: false },
    durationMs: 3,
  };
}

function insertReport(input: {
  hostId: number;
  locationId: number;
  campaignId: number;
  extractorId: string;
  receivedAt: string;
  results: Record<string, unknown>[];
}): number {
  reportSeq += 1;
  const machineId = `machine-${input.hostId}`;
  const document = {
    schemaVersion: 1,
    scan: {
      extractorVersion: "0.1.0",
      machineId,
      hostname: `host-${input.hostId}`,
      platform: "Linux",
      privilege: "degraded",
      evidenceDepth: "AuthoritativePrimary",
    },
    metadata: {},
    results: input.results,
    summary: { compliant: 0, nonCompliant: 0, notApplicable: 0, error: 0, degraded: 0, informational: 0 },
    selfAudit: { commands: [], filesRead: [] },
  };
  const result = db
    .query(
      `INSERT INTO reports
         (issuance_id, host_id, location_id, campaign_id, extractor_id, scan_id, report_json,
          score, coverage, summary_json, scan_timestamp, received_at, via, total_duration_ms,
          bytes, peak_rss_bytes, privilege_level, evidence_depth)
       VALUES ('iss-1', ?, ?, ?, ?, ?, ?, 0, 0, '{}', ?, ?, 'upload', 1, 1, 1, 'degraded', 'AuthoritativePrimary')`,
    )
    .run(
      input.hostId,
      input.locationId,
      input.campaignId,
      input.extractorId,
      `scan-${reportSeq}`,
      JSON.stringify(document),
      input.receivedAt,
      input.receivedAt,
    );
  return Number(result.lastInsertRowid);
}

function setTreatment(reportId: number, checkId: string, state: string, assignee: string | null, dueDate: string | null): void {
  db.query(
    `INSERT INTO finding_states (report_id, check_id, state, assignee, due_date, updated_at)
     VALUES (?, ?, ?, ?, ?, '2026-03-01T00:00:00.000Z')`,
  ).run(reportId, checkId, state, assignee, dueDate);
}

function seed(): { r1: number; r2: number } {
  reportSeq = 0;
  db.query(
    "INSERT INTO users (id, username, password_hash, role, active, created_at, updated_at) VALUES (1, 'viewer1', 'x', 'viewer', 1, '2026-01-01', '2026-01-01')",
  ).run();
  db.query(
    "INSERT INTO campaigns (id, name, client, scope, status, tags, created_at, updated_at) VALUES (1, 'Alpha', 'Acme', 'HQ network', 'active', '[]', '2026-01-01', '2026-01-01')",
  ).run();
  db.query(
    "INSERT INTO locations (id, campaign_id, name, tags, created_at, updated_at) VALUES (1, 1, 'HQ', '[]', '2026-01-01', '2026-01-01')",
  ).run();
  db.query(
    "INSERT INTO issuances (id, extractor_id, campaign_id, location_id, key_id, created_at) VALUES ('iss-1', 'extractor-1', 1, 1, '1', '2026-01-01')",
  ).run();
  for (const id of [1, 2]) {
    db.query(
      `INSERT INTO hosts (id, machine_id, hostname, platform, os, arch, first_seen_at, last_seen_at)
       VALUES (?, ?, ?, 'Linux', 'Ubuntu', 'x86_64', '2026-01-01', '2026-03-01')`,
    ).run(id, `machine-${id}`, `host-${id}`);
    db.query(
      "INSERT INTO host_locations (host_id, location_id, first_seen_at, last_seen_at) VALUES (?, 1, '2026-01-01', '2026-03-01')",
    ).run(id);
  }

  const r1 = insertReport({
    hostId: 1,
    locationId: 1,
    campaignId: 1,
    extractorId: "extractor-1",
    receivedAt: "2026-02-01T00:00:00.000Z",
    results: [
      check({ id: "CHK-A", status: "NonCompliant", severity: "Critical", category: "Auth", title: "Password policy", references: ["CIS-1.1", "NIST-IA-5"] }),
      check({ id: "CHK-B", status: "NonCompliant", severity: "High", category: "Network", title: "Exposed ports", repro: "ss -tulpn", location: "/etc/ssh/sshd_config", references: ["CIS-2.1"] }),
      check({ id: "CHK-C", status: "Compliant", severity: "Low", category: "Auth", title: "Audit logging" }),
    ],
  });
  const r2 = insertReport({
    hostId: 2,
    locationId: 1,
    campaignId: 1,
    extractorId: "extractor-1",
    receivedAt: "2026-02-02T00:00:00.000Z",
    results: [
      check({ id: "CHK-A", status: "NonCompliant", severity: "Critical", category: "Auth", title: "Password policy", references: ["CIS-1.1"] }),
      check({ id: "CHK-B", status: "Compliant", severity: "High", category: "Network", title: "Exposed ports" }),
      check({ id: "CHK-D", status: "Error", severity: "Medium", category: "Logging", title: "Log rotation", location: "/var/log" }),
    ],
  });

  setTreatment(r1, "CHK-A", "accepted_risk", "alice", "2026-04-01T00:00:00.000Z");
  return { r1, r2 };
}

beforeEach(() => {
  db = openDb(":memory:");
  runMigrations(db);
});

afterEach(() => {
  db.close();
});

describe("remediation aggregation", () => {
  it("groups failing checks and counts distinct failing hosts", async () => {
    seed();
    const { status, body } = await request(VIEWER, "/api/remediation");
    expect(status).toBe(200);
    const byId = Object.fromEntries(body.items.map((item: { checkId: string }) => [item.checkId, item]));
    expect(body.total).toBe(3); // CHK-A, CHK-B, CHK-D (CHK-C is compliant)
    expect(byId["CHK-A"].failingHosts).toBe(2);
    expect(byId["CHK-A"].hostCount).toBe(2);
    expect(byId["CHK-B"].failingHosts).toBe(1);
    // CHK-B reported on two hosts (one compliant) -> hostCount 2, failingHosts 1
    expect(byId["CHK-B"].hostCount).toBe(2);
  });

  it("excludes compliant checks but still counts their hosts", async () => {
    seed();
    const { body } = await request(VIEWER, "/api/remediation");
    const ids = body.items.map((item: { checkId: string }) => item.checkId);
    expect(ids).not.toContain("CHK-C");
  });

  it("rolls up treatment owners, due dates, references, and the repro command", async () => {
    seed();
    const { body } = await request(VIEWER, "/api/remediation");
    const item = body.items.find((entry: { checkId: string }) => entry.checkId === "CHK-A");
    expect(item.treatmentSummary.accepted_risk).toBe(1);
    expect(item.treatmentSummary.open).toBe(1);
    expect(item.treatmentSummary.assignees).toEqual(["alice"]);
    expect(item.treatmentSummary.nextDueDate).toBe("2026-04-01T00:00:00.000Z");
    expect(item.references).toEqual(["CIS-1.1", "NIST-IA-5"]);
    expect(item.recommendation).toBe("recommendation text");
    expect(item.exampleLocation).toBe("/etc/example.conf");

    const network = body.items.find((entry: { checkId: string }) => entry.checkId === "CHK-B");
    expect(network.repro).toBe("ss -tulpn");
    expect(network.exampleLocation).toBe("/etc/ssh/sshd_config");
  });

  it("sorts by severity weight then failing-host count", async () => {
    seed();
    const { body } = await request(VIEWER, "/api/remediation");
    expect(body.items.map((item: { checkId: string }) => item.checkId)).toEqual(["CHK-A", "CHK-B", "CHK-D"]);
  });

  it("applies canonical filters and rejects invalid values", async () => {
    seed();
    const filtered = await request(VIEWER, "/api/remediation?severity=Critical");
    expect(filtered.status).toBe(200);
    expect(filtered.body.items.map((item: { checkId: string }) => item.checkId)).toEqual(["CHK-A"]);

    const invalid = await request(VIEWER, "/api/remediation?severity=Catastrophic");
    expect(invalid.status).toBe(400);
    expect(invalid.body.code).toBe("INVALID_FILTER");
  });

  it("is role-gated to authenticated viewers", async () => {
    seed();
    const anonymous = await request(null, "/api/remediation");
    expect(anonymous.status).toBe(403);
  });
});
