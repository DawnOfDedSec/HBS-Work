// Task 49 scoped query / report API tests.
//
// The database is seeded directly with realistic report JSON (the same shape
// the extractor emits and `ingest.test.ts` builds) so the query layer can be
// exercised deterministically without re-running the crypto envelope pipeline.

import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { Database } from "bun:sqlite";
import { Hono } from "hono";
import { openDb, runMigrations } from "./db";
import { requireRole, type UserRole } from "./auth";
import { computeCoverage, computeRiskScore, computeSummary } from "./metrics";
import {
  buildReportWhere,
  parseQuery,
  serializeQuery,
  whereText,
  type NormalizedQuery,
} from "./query";
import {
  reconcileTreatment,
  registerReportRoutes,
  recomputeCampaignMetrics,
  recomputeReportMetrics,
} from "./reports";
import { registerNetworkRoutes } from "./network/routes";

// ---------------------------------------------------------------------------
// Seed fixtures
// ---------------------------------------------------------------------------

type TestUser = { id: number; username: string; role: string };

const VIEWER: TestUser = { id: 1, username: "viewer1", role: "viewer" };
const AUDITOR: TestUser = { id: 2, username: "auditor1", role: "auditor" };
const AUDITOR2: TestUser = { id: 3, username: "auditor2", role: "auditor" };
const ADMIN: TestUser = { id: 4, username: "admin1", role: "super_admin" };

let db: Database;
let reportSeq = 0;

function makeApp(user: TestUser) {
  const app = new Hono();
  app.use("*", async (c, next) => {
    (c as any).set("user", user);
    await next();
  });
  registerReportRoutes(app, db, {
    requireRole: (...roles: string[]) => requireRole(...(roles as UserRole[])) as any,
  });
  registerNetworkRoutes(app, db, {
    requireRole: (...roles: string[]) => requireRole(...(roles as UserRole[])) as any,
  });
  return app;
}

async function request(user: TestUser, path: string, init?: RequestInit) {
  const response = await makeApp(user).request(path, init);
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : null };
}

function postJson(user: TestUser, path: string, body: unknown) {
  return request(user, path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

// --- seed helpers ----------------------------------------------------------

function insertCampaign(id: number, name: string): void {
  db.query(
    "INSERT INTO campaigns (id, name, status, tags, created_at, updated_at) VALUES (?, ?, 'active', '[]', '2026-01-01', '2026-01-01')",
  ).run(id, name);
}

function insertLocation(id: number, campaignId: number, name: string): void {
  db.query(
    "INSERT INTO locations (id, campaign_id, name, tags, created_at, updated_at) VALUES (?, ?, ?, '[]', '2026-01-01', '2026-01-01')",
  ).run(id, campaignId, name);
}

function insertIssuance(id: string, campaignId: number, locationId: number, extractorId: string): void {
  db.query(
    `INSERT INTO issuances (id, extractor_id, campaign_id, location_id, key_id, created_at)
     VALUES (?, ?, ?, ?, '1', '2026-01-01')`,
  ).run(id, extractorId, campaignId, locationId);
}

function insertHost(id: number, machineId: string, hostname: string, platform: string, os: string, arch: string): void {
  db.query(
    `INSERT INTO hosts (id, machine_id, hostname, platform, os, arch, first_seen_at, last_seen_at)
     VALUES (?, ?, ?, ?, ?, ?, '2026-01-01', '2026-03-01')`,
  ).run(id, machineId, hostname, platform, os, arch);
}

function insertHostLocation(hostId: number, locationId: number): void {
  db.query(
    `INSERT INTO host_locations (host_id, location_id, first_seen_at, last_seen_at)
     VALUES (?, ?, '2026-01-01', '2026-03-01')`,
  ).run(hostId, locationId);
}

type CheckInput = {
  id: string;
  status: string;
  severity: string;
  category: string;
  title: string;
  references?: string[];
  evidence?: string;
};

function check(input: CheckInput): Record<string, unknown> {
  return {
    id: input.id,
    title: input.title,
    status: input.status,
    severity: input.severity,
    category: input.category,
    description: `${input.title} description`,
    impact: "impact",
    recommendation: "recommendation",
    references: input.references ?? [],
    evidence: input.evidence ?? "EVIDENCE_SENTINEL",
    location: "/etc/example.conf",
    repro: "cat /etc/example.conf",
    degradedReason: null,
    fallbackLog: [{ source: "/etc/example.conf", outcome: "read" }],
    evidenceBlocks: [],
    runContext: { user: "root", uid: 0, elevated: false },
    durationMs: 3,
  };
}

type ReportInput = {
  issuanceId: string;
  hostId: number;
  locationId: number;
  campaignId: number;
  extractorId: string;
  machineId: string;
  hostname: string;
  platform: string;
  os: string;
  arch: string;
  extractorVersion: string;
  privilegeLevel: string;
  evidenceDepth: string;
  via: string;
  receivedAt: string;
  totalDurationMs: number;
  bytes: number;
  peakRssBytes: number;
  results: Record<string, unknown>[];
  scanExtra?: Record<string, unknown>;
};

function insertReport(input: ReportInput): number {
  reportSeq += 1;
  const document = {
    schemaVersion: 1,
    scan: {
      extractorVersion: input.extractorVersion,
      platform: input.platform,
      osName: input.os,
      arch: input.arch,
      machineId: input.machineId,
      hostname: input.hostname,
      privilege: input.privilegeLevel,
      evidenceDepth: input.evidenceDepth,
      catalogFingerprint: "fingerprint-abc",
      startedUnix: Math.floor(Date.parse(input.receivedAt) / 1000),
      durationMs: input.totalDurationMs,
      peakRssKb: Math.round(input.peakRssBytes / 1024),
      ...input.scanExtra,
    },
    metadata: { hostname: input.hostname, machine_id: input.machineId, os_name: input.os, arch: input.arch },
    results: input.results,
    summary: { compliant: 999, nonCompliant: 999, notApplicable: 0, error: 0, degraded: 0, informational: 0 },
    selfAudit: { commands: ["uname -a", "ss -tulpn"], filesRead: ["/etc/hostname"] },
  };
  const summary = computeSummary(input.results as any);
  const score = computeRiskScore(input.results as any);
  const coverage = computeCoverage(input.results as any);
  const result = db
    .query(
      `INSERT INTO reports
         (issuance_id, host_id, location_id, campaign_id, extractor_id, scan_id, report_json,
          score, coverage, summary_json, scan_timestamp, received_at, via, total_duration_ms,
          bytes, peak_rss_bytes, privilege_level, evidence_depth)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(
      input.issuanceId,
      input.hostId,
      input.locationId,
      input.campaignId,
      input.extractorId,
      `scan-${reportSeq}`,
      JSON.stringify(document),
      score,
      coverage,
      JSON.stringify(summary),
      input.receivedAt,
      input.receivedAt,
      input.via,
      input.totalDurationMs,
      input.bytes,
      input.peakRssBytes,
      input.privilegeLevel,
      input.evidenceDepth,
    );
  return Number(result.lastInsertRowid);
}

function insertIngestEvent(reportId: number | null, durationMs: number, accepted: boolean, reasonCode: string | null, receivedAt: string): void {
  db.query(
    `INSERT INTO ingest_events (received_at, via, envelope_bytes, duration_ms, accepted, reason_code, report_id, issuance_id)
     VALUES (?, 'upload', 4096, ?, ?, ?, ?, ?)`,
  ).run(receivedAt, durationMs, accepted ? 1 : 0, reasonCode, reportId, reportId === null ? null : "iss-1");
}

let reports: Record<string, number> = {};

function seed(): void {
  reportSeq = 0;
  reports = {};

  for (const user of [VIEWER, AUDITOR, AUDITOR2, ADMIN]) {
    db.query(
      "INSERT INTO users (id, username, password_hash, role, active, created_at, updated_at) VALUES (?, ?, 'x', ?, 1, '2026-01-01', '2026-01-01')",
    ).run(user.id, user.username, user.role);
  }

  insertCampaign(1, "Alpha");
  insertCampaign(2, "Beta");
  insertLocation(1, 1, "HQ");
  insertLocation(2, 1, "Branch");
  insertLocation(3, 2, "DC");
  insertIssuance("iss-1", 1, 1, "extractor-1");
  insertIssuance("iss-2", 1, 2, "extractor-2");
  insertIssuance("iss-3", 2, 3, "extractor-3");

  insertHost(1, "machine-aaaa1111", "web-01", "Linux", "Ubuntu", "x86_64");
  insertHost(2, "machine-bbbb2222", "db-01", "Linux", "Debian", "x86_64");
  insertHost(3, "machine-cccc3333", "win-01", "Windows", "Server 2022", "x86_64");
  insertHostLocation(1, 1);
  insertHostLocation(2, 2);
  insertHostLocation(3, 3);

  const base = (receivedAt: string) => ({
    extractorVersion: "0.1.0",
    privilegeLevel: "degraded",
    evidenceDepth: "AuthoritativePrimary",
    via: "upload",
    receivedAt,
    peakRssBytes: 2 * 1024 * 1024,
  });

  reports.r1 = insertReport({
    ...base("2026-01-01T00:00:00.000Z"),
    issuanceId: "iss-1",
    hostId: 1,
    locationId: 1,
    campaignId: 1,
    extractorId: "extractor-1",
    machineId: "machine-aaaa1111",
    hostname: "web-01",
    platform: "Linux",
    os: "Ubuntu",
    arch: "x86_64",
    totalDurationMs: 100,
    bytes: 1000,
    results: [
      check({ id: "LIN-A", status: "NonCompliant", severity: "Critical", category: "Auth", title: "Authentication: password policy", references: ["CIS-1.1"] }),
      check({ id: "LIN-B", status: "Compliant", severity: "High", category: "Auth", title: "Authentication: MFA required", references: ["CIS-1.2", "NIST-CM-6"] }),
      check({ id: "LIN-C", status: "NonCompliant", severity: "Medium", category: "Network", title: "Network: exposed ports", references: ["CIS-2.1"] }),
    ],
  });

  reports.r2 = insertReport({
    ...base("2026-02-01T00:00:00.000Z"),
    issuanceId: "iss-1",
    hostId: 1,
    locationId: 1,
    campaignId: 1,
    extractorId: "extractor-1",
    machineId: "machine-aaaa1111",
    hostname: "web-01",
    platform: "Linux",
    os: "Ubuntu",
    arch: "x86_64",
    totalDurationMs: 200,
    bytes: 2000,
    results: [
      check({ id: "LIN-A", status: "Compliant", severity: "Critical", category: "Auth", title: "Authentication: password policy", references: ["CIS-1.1"] }),
      check({ id: "LIN-B", status: "NonCompliant", severity: "High", category: "Auth", title: "Authentication: MFA required", references: ["CIS-1.2", "NIST-CM-6"] }),
      check({ id: "LIN-C", status: "NonCompliant", severity: "Medium", category: "Network", title: "Network: exposed ports", references: ["CIS-2.1"] }),
    ],
    scanExtra: { apiToken: "SECRET_TOKEN_XYZ" },
  });

  reports.r3 = insertReport({
    ...base("2026-02-01T00:00:00.000Z"),
    issuanceId: "iss-2",
    hostId: 2,
    locationId: 2,
    campaignId: 1,
    extractorId: "extractor-2",
    machineId: "machine-bbbb2222",
    hostname: "db-01",
    platform: "Linux",
    os: "Debian",
    arch: "x86_64",
    totalDurationMs: 300,
    bytes: 3000,
    results: [
      check({ id: "LIN-A", status: "Compliant", severity: "Critical", category: "Auth", title: "Authentication: password policy", references: ["CIS-1.1"] }),
      check({ id: "LIN-B", status: "NonCompliant", severity: "High", category: "Auth", title: "Authentication: MFA required", references: ["CIS-1.2", "NIST-CM-6"] }),
    ],
  });

  reports.r4 = insertReport({
    ...base("2026-02-02T00:00:00.000Z"),
    issuanceId: "iss-3",
    hostId: 3,
    locationId: 3,
    campaignId: 2,
    extractorId: "extractor-3",
    machineId: "machine-cccc3333",
    hostname: "win-01",
    platform: "Windows",
    os: "Server 2022",
    arch: "x86_64",
    totalDurationMs: 400,
    bytes: 4000,
    results: [
      check({ id: "WIN-A", status: "NonCompliant", severity: "High", category: "OS", title: "Audit: logon events", references: ["NIST-CM-6"] }),
      check({ id: "WIN-B", status: "Compliant", severity: "Low", category: "OS", title: "Windows: SMB signing", references: ["CIS-1.1"] }),
      check({ id: "WIN-C", status: "Compliant", severity: "Informational", category: "OS", title: "Inventory: software" }),
    ],
  });

  reports.r5 = insertReport({
    ...base("2026-03-01T00:00:00.000Z"),
    issuanceId: "iss-2",
    hostId: 2,
    locationId: 2,
    campaignId: 1,
    extractorId: "extractor-2",
    machineId: "machine-bbbb2222",
    hostname: "db-01",
    platform: "Linux",
    os: "Debian",
    arch: "x86_64",
    totalDurationMs: 500,
    bytes: 5000,
    results: [
      check({ id: "LIN-A", status: "NonCompliant", severity: "Critical", category: "Auth", title: "Authentication: password policy", references: ["CIS-1.1"] }),
      check({ id: "LIN-B", status: "Compliant", severity: "High", category: "Auth", title: "Authentication: MFA required", references: ["CIS-1.2", "NIST-CM-6"] }),
    ],
  });

  insertIngestEvent(reports.r1, 10, true, null, "2026-01-01T01:00:00.000Z");
  insertIngestEvent(reports.r2, 20, true, null, "2026-02-01T01:00:00.000Z");
  insertIngestEvent(reports.r3, 30, true, null, "2026-02-01T02:00:00.000Z");
  insertIngestEvent(reports.r4, 40, true, null, "2026-02-02T01:00:00.000Z");
  insertIngestEvent(null, 55, false, "bad token=SECRET_TOKEN_XYZ", "2026-02-15T00:00:00.000Z");
}

beforeEach(() => {
  db = openDb(":memory:");
  runMigrations(db);
  seed();
});

afterEach(() => {
  db.close();
});

// ---------------------------------------------------------------------------
// Query parser
// ---------------------------------------------------------------------------

describe("scoped query parser", () => {
  it("parses every canonical parameter and repeated multi-values", () => {
    const parsed = parseQuery(
      "?severity=Critical&severity=High&category=Auth&status=NonCompliant&treatment=open" +
        "&locationId=1&hostId=2&checkId=LIN-A&reportId=3&standard=CIS" +
        "&via=upload&privilege=degraded&extractorVersion=0.1.0" +
        "&platform=Linux&evidenceDepth=AuthoritativePrimary&q=auth",
    );
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const f = parsed.query.filters;
    expect(f.severity).toEqual(["Critical", "High"]);
    expect(f.category).toEqual(["Auth"]);
    expect(f.status).toEqual(["NonCompliant"]);
    expect(f.treatment).toEqual(["open"]);
    expect(f.locationId).toEqual([1]);
    expect(f.hostId).toEqual([2]);
    expect(f.checkId).toEqual(["LIN-A"]);
    expect(f.reportId).toEqual([3]);
    expect(f.standard).toEqual(["CIS"]);
    expect(f.via).toEqual(["upload"]);
    expect(f.privilege).toEqual(["degraded"]);
    expect(f.extractorVersion).toEqual(["0.1.0"]);
    expect(f.platform).toEqual(["Linux"]);
    expect(f.evidenceDepth).toEqual(["AuthoritativePrimary"]);
    expect(f.q).toBe("auth");
    expect(parsed.query.scope).toBe("report");

    const range = parseQuery("?from=2026-01-01T00:00:00.000Z&to=2026-02-01T00:00:00.000Z");
    expect(range.ok).toBe(true);
    if (range.ok) {
      expect(range.query.filters.from).toBe("2026-01-01T00:00:00.000Z");
      expect(range.query.filters.to).toBe("2026-02-01T00:00:00.000Z");
      expect(range.query.scope).toBe("range");
    }
  });

  it("returns a deeply frozen normalized object", () => {
    const parsed = parseQuery("?severity=Critical&hostId=1");
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(Object.isFrozen(parsed.query)).toBe(true);
    expect(Object.isFrozen(parsed.query.filters)).toBe(true);
    expect(Object.isFrozen(parsed.query.filters.severity)).toBe(true);
    expect(Object.isFrozen(parsed.query.pagination)).toBe(true);
  });

  it("ignores unknown keys", () => {
    const parsed = parseQuery("?severity=High&nonsense=1&other=x");
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.query.filters.severity).toEqual(["High"]);
    expect(parsed.query.ignored).toContain("nonsense");
    expect(parsed.query.ignored).toContain("other");
  });

  it("rejects invalid enums, ids, ranges, and over-long q with stable codes", () => {
    expect(parseQuery("?severity=Banana")).toMatchObject({ ok: false, code: "INVALID_FILTER" });
    expect(parseQuery("?status=Nope")).toMatchObject({ ok: false, code: "INVALID_FILTER" });
    expect(parseQuery("?reportId=0")).toMatchObject({ ok: false, code: "INVALID_ID" });
    expect(parseQuery("?hostId=abc")).toMatchObject({ ok: false, code: "INVALID_ID" });
    expect(parseQuery("?from=not-a-date")).toMatchObject({ ok: false, code: "INVALID_FILTER" });
    expect(parseQuery("?from=2026-02-01&to=2026-01-01")).toMatchObject({ ok: false, code: "INVALID_RANGE" });
    expect(parseQuery(`?q=${"a".repeat(201)}`)).toMatchObject({ ok: false, code: "QUERY_TOO_LONG" });
  });

  it("infers scope and rejects invalid scope combinations", () => {
    const latest = parseQuery("?");
    expect(latest.ok).toBe(true);
    if (latest.ok) expect(latest.query.scope).toBe("latest");
    expect(parseQuery("?reportId=1")).toMatchObject({ ok: true });
    const reportScope = parseQuery("?reportId=1");
    if (reportScope.ok) expect(reportScope.query.scope).toBe("report");
    const rangeScope = parseQuery("?from=2026-01-01T00:00:00.000Z");
    if (rangeScope.ok) expect(rangeScope.query.scope).toBe("range");

    expect(parseQuery("?scope=report")).toMatchObject({ ok: false, code: "SCOPE_REQUIRES_REPORT" });
    expect(parseQuery("?scope=range")).toMatchObject({ ok: false, code: "SCOPE_REQUIRES_RANGE" });
    expect(parseQuery("?scope=latest&reportId=1")).toMatchObject({ ok: false, code: "SCOPE_CONFLICT" });
    expect(parseQuery("?reportId=1&from=2026-01-01")).toMatchObject({ ok: false, code: "SCOPE_CONFLICT" });
  });

  it("keeps the SQL builder fully parameterized and never interpolates values", () => {
    const parsed = parseQuery("?platform=Linux&via=push&hostId=3&from=2026-01-01T00:00:00.000Z");
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    const built = buildReportWhere(parsed.query);
    const text = whereText(built);
    expect(text).toContain("?");
    expect(text).not.toContain("Linux");
    expect(text).not.toContain("push");
    expect(text).not.toContain("3");
    expect(built.params).toContain("Linux");
    expect(built.params).toContain("push");
    expect(built.params).toContain(3);
  });

  it("treats SQL-injection-ish q as an inert literal and keeps the table intact", async () => {
    const evil = "'; DROP TABLE reports;--";
    const parsed = parseQuery(`?q=${encodeURIComponent(evil)}`);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.query.filters.q).toBe(evil);

    const response = await request(VIEWER, `/api/findings?q=${encodeURIComponent(evil)}`);
    expect(response.status).toBe(200);
    expect(response.body.total).toBe(0);
    const remaining = (db.query("SELECT COUNT(*) AS count FROM reports").get() as { count: number }).count;
    expect(remaining).toBe(5);
  });

  it("serializes back to a canonical, sorted query string", () => {
    const parsed = parseQuery("?severity=High&severity=Critical&hostId=2");
    if (!parsed.ok) throw new Error("expected parse");
    const serialized = serializeQuery(parsed.query);
    expect(serialized).toBe("severity=Critical&severity=High&hostId=2");
  });
});

// ---------------------------------------------------------------------------
// Scopes, filters, pagination
// ---------------------------------------------------------------------------

describe("findings explorer", () => {
  it("applies the latest scope by default (one latest report per host)", async () => {
    const response = await request(VIEWER, "/api/findings");
    expect(response.status).toBe(200);
    expect(response.body.scope.kind).toBe("latest");
    expect(response.body.total).toBe(8);
  });

  it("scopes to a single report", async () => {
    const response = await request(VIEWER, `/api/findings?reportId=${reports.r1}`);
    expect(response.status).toBe(200);
    expect(response.body.scope.kind).toBe("report");
    expect(response.body.total).toBe(3);
  });

  it("scopes to an inclusive date range", async () => {
    const response = await request(
      VIEWER,
      "/api/findings?scope=range&from=2026-02-01T00:00:00.000Z&to=2026-02-01T23:59:59.999Z",
    );
    expect(response.status).toBe(200);
    expect(response.body.scope.kind).toBe("range");
    expect(response.body.total).toBe(5); // r2 (3 results) + r3 (2 results)
  });

  it("returns 400 for invalid scope combinations", async () => {
    expect((await request(VIEWER, "/api/findings?scope=report")).status).toBe(400);
    expect((await request(VIEWER, "/api/findings?scope=range")).status).toBe(400);
    expect((await request(VIEWER, "/api/findings?scope=latest&reportId=1")).status).toBe(400);
  });

  it("filters by severity, status, host, check, standard, and q", async () => {
    expect((await request(VIEWER, "/api/findings?severity=Critical")).body.total).toBe(2);
    expect((await request(VIEWER, "/api/findings?status=NonCompliant")).body.total).toBe(4);
    expect((await request(VIEWER, "/api/findings?hostId=1")).body.total).toBe(3);
    expect((await request(VIEWER, "/api/findings?checkId=LIN-A")).body.total).toBe(2);
    expect((await request(VIEWER, "/api/findings?standard=CIS")).body.total).toBe(6);
    expect((await request(VIEWER, "/api/findings?standard=NIST")).body.total).toBe(3);
    expect((await request(VIEWER, "/api/findings?q=authentication")).body.total).toBe(4);
    expect((await request(VIEWER, "/api/findings?q=network")).body.total).toBe(1);
  });

  it("paginates with deterministic severity/host ordering", async () => {
    const page1 = await request(VIEWER, "/api/findings?pageSize=3&page=1");
    expect(page1.body.results).toHaveLength(3);
    expect(page1.body.total).toBe(8);
    expect(page1.body.results[0].severity).toBe("Critical");
    expect(page1.body.results[0].hostname).toBe("db-01");

    const page3 = await request(VIEWER, "/api/findings?pageSize=3&page=3");
    expect(page3.body.results).toHaveLength(2);

    const again = await request(VIEWER, "/api/findings?pageSize=3&page=1");
    expect(again.body.results.map((row: any) => row.checkId)).toEqual(
      page1.body.results.map((row: any) => row.checkId),
    );
  });

  it("keeps chart and table endpoints in agreement under the same query", async () => {
    const metrics = await request(VIEWER, "/api/metrics/severity");
    expect(metrics.status).toBe(200);
    for (const [severity, count] of Object.entries(metrics.body.severity as Record<string, number>)) {
      const table = await request(VIEWER, `/api/findings?severity=${severity}`);
      expect(table.body.total).toBe(count);
    }

    const riskChart = await request(VIEWER, "/api/metrics/risk");
    const overview = await request(VIEWER, "/api/overview");
    expect(riskChart.body.riskTrend).toEqual(overview.body.riskTrend);
    expect(riskChart.body.weightedRiskScore).toBe(overview.body.kpis.weightedRiskScore);
  });
});

// ---------------------------------------------------------------------------
// Network findings in the global explorer
// ---------------------------------------------------------------------------

describe("network findings in the global explorer", () => {
  function seedNetworkReport(): number {
    const now = "2026-03-01T00:00:00.000Z";
    const device = db
      .query(
        `INSERT INTO network_devices (device_key, hostname, vendor, device_type, first_seen_at, last_seen_at)
         VALUES ('host:fw-edge', 'fw-edge', 'cisco-asa', 'firewall', ?, ?)`,
      )
      .run(now, now);
    const findings = [
      {
        checkId: "NET-MGMT-001",
        title: "Telnet management service enabled",
        severity: "Critical",
        status: "NonCompliant",
        category: "Management",
        description: "Telnet transmits credentials in cleartext.",
        evidence: [],
        recommendation: "Use SSHv2 exclusively.",
        references: ["CIS Benchmarks (Network Devices)"],
      },
      {
        checkId: "NET-MGMT-010",
        title: "Legal warning banner not configured",
        severity: "Low",
        status: "NonCompliant",
        category: "Management",
        description: "No login banner present.",
        evidence: [],
        recommendation: "Configure a legal warning banner.",
        references: [],
      },
      {
        checkId: "NET-MGMT-011",
        title: "Minimum password length policy set",
        severity: "Low",
        status: "Compliant",
        category: "Authentication",
        description: "Minimum length configured.",
        evidence: [],
        recommendation: "Keep enforcing the policy.",
        references: [],
      },
    ];
    const inserted = db
      .query(
        `INSERT INTO network_reports
           (device_id, location_id, campaign_id, config_name, config_sha256, config_size,
            config_text, parsed_json, findings_json, score, received_at, uploaded_by)
         VALUES (?, 1, 1, 'fw.cfg', 'netsha0000000001', 128, 'hostname fw-edge', '{}', ?, 62.5, ?, 'admin')`,
      )
      .run(Number(device.lastInsertRowid), JSON.stringify(findings), now);
    return Number(inserted.lastInsertRowid);
  }

  it("merges network findings and honors the source filter", async () => {
    const reportId = seedNetworkReport();

    const merged = await request(VIEWER, "/api/findings");
    expect(merged.body.total).toBe(8 + 3);

    const hostOnly = await request(VIEWER, "/api/findings?source=host");
    expect(hostOnly.body.total).toBe(8);

    const networkOnly = await request(VIEWER, "/api/findings?source=network");
    expect(networkOnly.body.total).toBe(3);
    for (const row of networkOnly.body.results as Array<Record<string, unknown>>) {
      expect(row.source).toBe("network");
      expect(row.hostId).toBe(0);
    }

    const critical = await request(VIEWER, "/api/findings?source=network&severity=Critical");
    expect(critical.body.total).toBe(1);
    expect(critical.body.results[0].checkId).toBe("NET-MGMT-001");

    // Location scoping applies to network findings too.
    const scoped = await request(VIEWER, "/api/findings?source=network&locationId=2");
    expect(scoped.body.total).toBe(0);

    void reportId;
  });

  it("reflects network treatments in the global treatment board", async () => {
    const reportId = seedNetworkReport();
    const applied = await request(ADMIN, `/api/network/reports/${reportId}/findings/NET-MGMT-001/treatment`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ state: "accepted_risk", justification: "Telnet restricted to jump host." }),
    });
    expect(applied.status).toBe(200);

    const board = await request(VIEWER, "/api/findings?source=network&treatment=accepted_risk");
    expect(board.body.total).toBe(1);
    expect(board.body.results[0].checkId).toBe("NET-MGMT-001");
  });
});

// ---------------------------------------------------------------------------
// Overview, summary, standards
// ---------------------------------------------------------------------------

describe("overview and campaign summary", () => {
  it("computes global KPIs and risk trend server-side", async () => {
    const response = await request(VIEWER, "/api/overview");
    expect(response.status).toBe(200);
    const kpis = response.body.kpis;
    expect(kpis.campaignCount).toBe(2);
    expect(kpis.activeLocations).toBe(3);
    expect(kpis.scannedHosts).toBe(3);
    expect(kpis.openCriticals).toBe(1); // r5 LIN-A only (r2 LIN-A is compliant)
    // applicable weight 42, failed weight 25
    expect(kpis.weightedRiskScore).toBeCloseTo(100 * (1 - 25 / 42), 2);
    expect(kpis.coverage).toBe(100);
    expect(response.body.riskTrend.map((point: any) => point.date)).toEqual([
      "2026-01-01",
      "2026-02-01",
      "2026-02-02",
      "2026-03-01",
    ]);
  });

  it("returns a campaign summary with severity, category, and top failing checks", async () => {
    const response = await request(VIEWER, "/api/campaigns/1/summary");
    expect(response.status).toBe(200);
    expect(response.body.severityBreakdown).toEqual({
      Critical: 2,
      High: 2,
      Medium: 1,
      Low: 0,
      Informational: 0,
    });
    const auth = response.body.categoryCompliance.find((row: any) => row.category === "Auth");
    expect(auth).toMatchObject({ total: 4, compliant: 2, nonCompliant: 2, complianceRate: 50 });
    expect(response.body.topFailingChecks[0].checkId).toBe("LIN-A");
    expect(response.body.topFailingChecks[0].severity).toBe("Critical");
  });

  it("maps standards/references coverage from stored results", async () => {
    const response = await request(VIEWER, "/api/standards");
    expect(response.status).toBe(200);
    const cis = response.body.standards.find((row: any) => row.standard === "CIS");
    expect(cis.total).toBe(6);
    const nist = response.body.standards.find((row: any) => row.standard === "NIST");
    expect(nist.total).toBe(3);
    expect(response.body.references.some((row: any) => row.reference === "CIS-1.1")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Reports, hosts, checks, diff
// ---------------------------------------------------------------------------

describe("reports, hosts, checks, diff", () => {
  it("lists reports and returns report detail with per-result rows", async () => {
    const list = await request(VIEWER, "/api/reports");
    expect(list.status).toBe(200);
    expect(list.body.total).toBe(5);
    expect(list.body.reports[0].id).toBe(reports.r5);

    const detail = await request(VIEWER, `/api/reports/${reports.r1}`);
    expect(detail.status).toBe(200);
    expect(detail.body.id).toBe(reports.r1);
    expect(detail.body.results).toHaveLength(3);
    expect(detail.body.results[0].treatment.state).toBe("open");

    expect((await request(VIEWER, "/api/reports/99999")).status).toBe(404);
  });

  it("hand-computes report risk/coverage and exposes them through the API", async () => {
    const detail = await request(VIEWER, `/api/reports/${reports.r1}`);
    const results = JSON.parse(
      (db.query("SELECT report_json FROM reports WHERE id = ?").get(reports.r1) as any).report_json,
    ).results;
    expect(detail.body.score).toBeCloseTo(computeRiskScore(results), 6);
    expect(detail.body.coverage).toBeCloseTo(computeCoverage(results), 6);
  });

  it("lists hosts and returns host detail with locations and reports", async () => {
    const list = await request(VIEWER, "/api/hosts");
    expect(list.status).toBe(200);
    expect(list.body.total).toBe(3);
    expect(list.body.hosts.map((host: any) => host.hostname).sort()).toEqual([
      "db-01",
      "web-01",
      "win-01",
    ]);

    const detail = await request(VIEWER, "/api/hosts/1");
    expect(detail.status).toBe(200);
    expect(detail.body.host.id).toBe(1);
    expect(detail.body.host.machineId).toBe("machine-aaaa1111");
    expect(detail.body.reports).toHaveLength(2);
    expect(detail.body.locations[0].id).toBe(1);
    expect((await request(VIEWER, "/api/hosts/99999")).status).toBe(404);
  });

  it("pivots By Check across hosts in scope", async () => {
    const response = await request(VIEWER, "/api/checks/LIN-A");
    expect(response.status).toBe(200);
    expect(response.body.checkId).toBe("LIN-A");
    expect(response.body.total).toBe(2);
    expect(response.body.hosts.map((row: any) => row.hostname).sort()).toEqual(["db-01", "web-01"]);
    expect((await request(VIEWER, "/api/checks/LIN$A")).status).toBe(400);
  });

  it("diffs two scans of the same host into fixed/regressed/unchanged", async () => {
    const response = await request(VIEWER, `/api/reports/${reports.r3}/diff/${reports.r5}`);
    expect(response.status).toBe(200);
    expect(response.body.summary.fixed).toBe(1);
    expect(response.body.summary.regressed).toBe(1);
    expect(response.body.fixed[0].checkId).toBe("LIN-B");
    expect(response.body.regressed[0].checkId).toBe("LIN-A");

    const mismatch = await request(VIEWER, `/api/reports/${reports.r1}/diff/${reports.r4}`);
    expect(mismatch.status).toBe(400);
    expect(mismatch.body.code).toBe("REPORT_HOST_MISMATCH");
  });
});

// ---------------------------------------------------------------------------
// Telemetry
// ---------------------------------------------------------------------------

describe("telemetry", () => {
  it("recomputes scan/ingest p50/p95 from stored data", async () => {
    const response = await request(VIEWER, "/api/telemetry");
    expect(response.status).toBe(200);
    expect(response.body.scanDurationMs).toMatchObject({ count: 5, p50: 300, p95: 500, min: 100, max: 500 });
    expect(response.body.ingestDurationMs).toMatchObject({ count: 4, p50: 20, p95: 40 });
    expect(response.body.freshness.slaHours).toBe(24);
    expect(response.body.platform.Linux).toBe(4);
    expect(response.body.platform.Windows).toBe(1);
    expect(response.body.extractorVersion["0.1.0"]).toBe(5);
    expect(response.body.commands).toBe(10);
    expect(response.body.files).toBe(5);
  });

  it("reports accepted/rejected ingest reasons for a range scope", async () => {
    const response = await request(
      VIEWER,
      "/api/telemetry?scope=range&from=2026-01-01T00:00:00.000Z&to=2026-02-28T00:00:00.000Z",
    );
    expect(response.status).toBe(200);
    expect(response.body.ingest.accepted).toBe(4);
    expect(response.body.ingest.rejected).toBe(1);
    expect(response.body.ingest.reasons.INVALID_PUSH_TOKEN ?? response.body.ingest.reasons).toBeDefined();
    expect(Object.keys(response.body.ingest.reasons)).toContain("bad token=SECRET_TOKEN_XYZ");
  });
});

// ---------------------------------------------------------------------------
// Treatment
// ---------------------------------------------------------------------------

describe("treatment", () => {
  it("requires justification for accepted_risk and false_positive", async () => {
    const response = await postJson(AUDITOR, `/api/reports/${reports.r2}/findings/LIN-B/treatment`, {
      state: "accepted_risk",
    });
    expect(response.status).toBe(400);
    expect(response.body.code).toBe("JUSTIFICATION_REQUIRED");
    expect((await postJson(AUDITOR, `/api/reports/${reports.r2}/findings/LIN-B/treatment`, { state: "bogus" })).status).toBe(400);
    expect((await request(VIEWER, `/api/reports/${reports.r2}/findings/LIN-B/treatment`, { method: "POST" })).status).toBe(403);
  });

  it("appends history and recomputes report + campaign score/coverage", async () => {
    const before = (db.query("SELECT score FROM reports WHERE id = ?").get(reports.r2) as { score: number }).score;

    const response = await postJson(AUDITOR, `/api/reports/${reports.r2}/findings/LIN-B/treatment`, {
      state: "accepted_risk",
      justification: "Compensating control in place",
      assignee: "auditor1",
    });
    expect(response.status).toBe(200);
    expect(response.body.state).toBe("accepted_risk");

    const state = db
      .query("SELECT * FROM finding_states WHERE report_id = ? AND check_id = 'LIN-B'")
      .get(reports.r2) as any;
    expect(state.state).toBe("accepted_risk");

    const history = db
      .query("SELECT * FROM finding_state_history WHERE finding_state_id = ? ORDER BY id")
      .all(state.id) as any[];
    const explicit = history.find((row) => row.actor === "auditor1");
    expect(explicit).toBeDefined();
    expect(explicit!.justification).toBe("Compensating control in place");
    expect(explicit!.to_state).toBe("accepted_risk");

    // r2 failed weight drops from 9 to 3; denominator stays 19.
    const after = (db.query("SELECT score FROM reports WHERE id = ?").get(reports.r2) as any).score;
    expect(after).not.toBe(before);
    expect(after).toBeCloseTo(100 * (1 - 3 / 19), 6);

    const campaign = db.query("SELECT * FROM campaign_metrics WHERE campaign_id = 1").get() as any;
    expect(campaign).toBeDefined();
    // host1 r2 (failed 3 of 19) + host2 r5 (failed 10 of 16): 13/35
    expect(campaign.score).toBeCloseTo(100 * (1 - 13 / 35), 6);
    expect(campaign.coverage).toBe(100);
  });

  it("auto-resolves a stale treatment when a later scan fixes the check", async () => {
    // r3 is host2's older report; r5 (latest) has LIN-B compliant.
    await postJson(AUDITOR, `/api/reports/${reports.r3}/findings/LIN-B/treatment`, {
      state: "accepted_risk",
      justification: "temporary",
    });
    const projection = db
      .query("SELECT * FROM finding_states WHERE report_id = ? AND check_id = 'LIN-B'")
      .get(reports.r3) as any;
    expect(projection.state).toBe("accepted_risk");

    const resolved = reconcileTreatment(db, { campaignId: 1 });
    expect(resolved).toBeGreaterThanOrEqual(1);
    const updated = db
      .query("SELECT state FROM finding_states WHERE id = ?")
      .get(projection.id) as { state: string };
    expect(updated.state).toBe("remediated");

    const systemRow = db
      .query("SELECT * FROM finding_state_history WHERE finding_state_id = ? AND actor = 'system'")
      .get(projection.id) as any;
    expect(systemRow).toBeDefined();
    expect(systemRow.to_state).toBe("remediated");

    const board = await request(VIEWER, "/api/treatment");
    expect(board.status).toBe(200);
    expect(board.body.counts.remediated).toBeGreaterThanOrEqual(0);
  });

  it("forbids viewers from changing treatment", async () => {
    const response = await postJson(VIEWER, `/api/reports/${reports.r2}/findings/LIN-B/treatment`, {
      state: "open",
    });
    expect(response.status).toBe(403);
  });

  it("exposes direct recompute helpers for report and campaign metrics", () => {
    const report = recomputeReportMetrics(db, reports.r1);
    expect(report.score).toBeCloseTo(
      computeRiskScore(JSON.parse((db.query("SELECT report_json FROM reports WHERE id = ?").get(reports.r1) as any).report_json).results),
      6,
    );
    const campaign = recomputeCampaignMetrics(db, 1);
    expect(campaign.reportCount).toBe(4);
    expect(campaign.hostCount).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// Saved views
// ---------------------------------------------------------------------------

describe("saved views", () => {
  it("enforces personal/team visibility and owner/super-admin mutation", async () => {
    const personal = await postJson(AUDITOR, "/api/saved-views", {
      name: "My criticals",
      query: "severity=Critical",
      visibility: "personal",
    });
    expect(personal.status).toBe(201);
    const personalId = personal.body.view.id;

    const team = await postJson(AUDITOR, "/api/saved-views", {
      name: "Team audit",
      query: "status=NonCompliant",
      visibility: "team",
    });
    expect(team.status).toBe(201);

    const viewerList = await request(VIEWER, "/api/saved-views");
    expect(viewerList.body.views.map((view: any) => view.name)).toEqual(["Team audit"]);

    const otherAuditorList = await request(AUDITOR2, "/api/saved-views");
    expect(otherAuditorList.body.views.map((view: any) => view.name)).toEqual(["Team audit"]);

    const ownerList = await request(AUDITOR, "/api/saved-views");
    expect(ownerList.body.views.map((view: any) => view.name)).toEqual(["My criticals", "Team audit"]);

    // Viewer cannot create.
    expect((await postJson(VIEWER, "/api/saved-views", { name: "x", query: "" })).status).toBe(403);

    // Non-owner auditor cannot mutate.
    const forbidden = await request(AUDITOR2, `/api/saved-views/${personalId}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: "hijack" }),
    });
    expect(forbidden.status).toBe(403);

    // Owner can, and stores a canonical query.
    const patched = await request(AUDITOR, `/api/saved-views/${personalId}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ query: "severity=High&severity=Critical" }),
    });
    expect(patched.status).toBe(200);
    expect(patched.body.view.query).toBe("severity=Critical&severity=High");

    // Super admin can delete someone else's view.
    expect((await request(ADMIN, `/api/saved-views/${personalId}`, { method: "DELETE" })).status).toBe(204);
    expect((await request(AUDITOR, `/api/saved-views/${personalId}`, { method: "DELETE" })).status).toBe(404);
  });

  it("rejects an invalid saved-view query", async () => {
    const response = await postJson(AUDITOR, "/api/saved-views", {
      name: "bad",
      query: "severity=Banana",
    });
    expect(response.status).toBe(400);
    expect(response.body.code).toBe("INVALID_FILTER");
  });
});

// ---------------------------------------------------------------------------
// Diagnostic
// ---------------------------------------------------------------------------

describe("diagnostic bundle", () => {
  it("is super_admin only", async () => {
    expect((await request(VIEWER, "/api/diagnostic")).status).toBe(403);
    expect((await request(AUDITOR, "/api/diagnostic")).status).toBe(403);
    expect((await request(ADMIN, "/api/diagnostic")).status).toBe(200);
  });

  it("never leaks evidence text, report evidence, or secrets", async () => {
    const response = await request(ADMIN, "/api/diagnostic");
    expect(response.status).toBe(200);
    const text = JSON.stringify(response.body);
    expect(text).not.toContain("EVIDENCE_SENTINEL");
    expect(text).not.toContain("SECRET_TOKEN_XYZ");
    expect(text).toContain("[redacted]");
    expect(response.body.diagnostic.selfAudit.length).toBeGreaterThan(0);
    expect(response.body.diagnostic.telemetry).toBeDefined();
    expect(response.body.diagnostic.errors).toBeDefined();

    // A range scope pulls the rejected event (and its reason code) into the
    // bundle; it must still be redacted there.
    const ranged = await request(
      ADMIN,
      "/api/diagnostic?scope=range&from=2026-01-01T00:00:00.000Z&to=2026-02-28T00:00:00.000Z",
    );
    expect(ranged.status).toBe(200);
    const rangedText = JSON.stringify(ranged.body);
    expect(rangedText).not.toContain("SECRET_TOKEN_XYZ");
    expect(rangedText).not.toContain("EVIDENCE_SENTINEL");
    expect(ranged.body.diagnostic.ingestEvents.some((event: any) => event.accepted === false)).toBe(true);
    expect(rangedText).toContain("[redacted]");
  });
});

// ---------------------------------------------------------------------------
// Role gating
// ---------------------------------------------------------------------------

describe("role gating", () => {
  it("allows viewers to read every report endpoint", async () => {
    for (const path of [
      "/api/overview",
      "/api/findings",
      "/api/reports",
      "/api/hosts",
      "/api/telemetry",
      "/api/standards",
      "/api/treatment",
      "/api/metrics/severity",
      "/api/metrics/category",
      "/api/metrics/risk",
    ]) {
      expect((await request(VIEWER, path)).status).toBe(200);
    }
  });
});
