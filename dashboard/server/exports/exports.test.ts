// Task 57 + 58 export tests.
//
// A database is seeded directly with realistic `report_json` (the same shape
// the extractor emits and `reports.test.ts` builds) so every generator is
// exercised against real evidence blocks, fallback logs, treatment state, and a
// secret sentinel that must never survive redaction.

import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { Database } from "bun:sqlite";
import ExcelJS from "exceljs";
import { Hono } from "hono";
import JSZip from "jszip";
import { requireRole, type UserRole } from "../auth";
import { openDb, runMigrations } from "../db";
import { computeCoverage, computeRiskScore } from "../metrics";
import { parseQuery } from "../query";
import { csvCell, renderCsv, toCsv } from "./csv";
import { buildDiagnosticExport, renderDiagnosticCsv, renderDiagnosticJson } from "./diagnostic";
import { renderDocx } from "./docx";
import { renderPdf } from "./pdf";
import { buildExportViewModel } from "./viewmodel";
import { registerExportRoutes, renderXlsx } from "./xlsx";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

type TestUser = { id: number; username: string; role: string };
const VIEWER: TestUser = { id: 1, username: "viewer1", role: "viewer" };
const ADMIN: TestUser = { id: 2, username: "admin1", role: "super_admin" };

const EVIDENCE_SENTINEL = "EVIDENCE_SENTINEL_ABC";
const SECRET_PASSWORD = "SECRET_PASSWORD_123";
const SECRET_TOKEN = "SECRET_TOKEN_XYZ";

let db: Database;
let reportSeq = 0;
let reportIds: Record<string, number> = {};

function makeApp(user: TestUser): Hono {
  const app = new Hono();
  app.use("*", async (c, next) => {
    (c as any).set("user", user);
    await next();
  });
  registerExportRoutes(app, db, {
    requireRole: (...roles: string[]) => requireRole(...(roles as UserRole[])) as any,
  });
  return app;
}

function get(user: TestUser, path: string) {
  return makeApp(user).request(path);
}

type CheckInput = {
  id: string;
  status: string;
  severity: string;
  category: string;
  title: string;
  references?: string[];
  evidence?: string;
  recommendation?: string;
  evidenceBlocks?: Record<string, unknown>[];
  fallbackLog?: { source: string; outcome: string }[];
};

function check(input: CheckInput): Record<string, unknown> {
  return {
    id: input.id,
    title: input.title,
    status: input.status,
    severity: input.severity,
    category: input.category,
    description: `${input.title} description`,
    impact: `${input.title} impact`,
    recommendation: input.recommendation ?? `${input.title} remediation`,
    references: input.references ?? [],
    evidence: input.evidence ?? EVIDENCE_SENTINEL,
    location: "/etc/ssh/sshd_config",
    repro: "cat /etc/ssh/sshd_config",
    degradedReason: null,
    fallbackLog: input.fallbackLog ?? [{ source: "/etc/ssh/sshd_config", outcome: "read" }],
    evidenceBlocks: input.evidenceBlocks ?? [],
    runContext: { user: "root", uid: 0, elevated: false },
    durationMs: 3,
  };
}

function evidenceBlock(): Record<string, unknown> {
  return {
    path: "/etc/ssh/sshd_config",
    line: 42,
    col: 1,
    context: [
      "# Port 22",
      "# AddressFamily any",
      "PermitRootLogin yes",
      "AuthorizedKeysFile .ssh/authorized_keys",
      "PasswordAuthentication yes",
    ],
    targetIndex: 2,
    fileMode: 420,
    fileUid: 0,
    fileGid: 0,
  };
}

function insertReport(input: {
  hostId: number;
  hostname: string;
  machineId: string;
  receivedAt: string;
  results: Record<string, unknown>[];
  scanExtra?: Record<string, unknown>;
}): number {
  reportSeq += 1;
  const document = {
    schemaVersion: 1,
    scan: {
      extractorVersion: "0.1.0",
      platform: "Linux",
      osName: "Ubuntu",
      arch: "x86_64",
      machineId: input.machineId,
      hostname: input.hostname,
      privilege: "degraded",
      evidenceDepth: "AuthoritativePrimary",
      catalogFingerprint: "fingerprint-abc",
      ...input.scanExtra,
    },
    metadata: { hostname: input.hostname, machine_id: input.machineId },
    results: input.results,
    summary: { compliant: 0, nonCompliant: 0, notApplicable: 0, error: 0, degraded: 0, informational: 0 },
    selfAudit: { commands: ["uname -a"], filesRead: ["/etc/hostname"] },
  };
  const score = computeRiskScore(input.results as any);
  const coverage = computeCoverage(input.results as any);
  const result = db
    .query(
      `INSERT INTO reports
         (issuance_id, host_id, location_id, campaign_id, extractor_id, scan_id, report_json,
          score, coverage, summary_json, scan_timestamp, received_at, via, total_duration_ms,
          bytes, peak_rss_bytes, privilege_level, evidence_depth)
       VALUES (?, ?, 1, 1, 'extractor-1', ?, ?, ?, ?, '{}', ?, ?, 'upload', 100, 1000, 2048, 'degraded', 'AuthoritativePrimary')`,
    )
    .run(
      "iss-1",
      input.hostId,
      `scan-${reportSeq}`,
      JSON.stringify(document),
      score,
      coverage,
      input.receivedAt,
      input.receivedAt,
    );
  return Number(result.lastInsertRowid);
}

function seed(): void {
  reportSeq = 0;
  reportIds = {};
  for (const user of [VIEWER, ADMIN]) {
    db.query(
      "INSERT INTO users (id, username, password_hash, role, active, created_at, updated_at) VALUES (?, ?, 'x', ?, 1, '2026-01-01', '2026-01-01')",
    ).run(user.id, user.username, user.role);
  }
  db.query(
    "INSERT INTO campaigns (id, name, status, tags, created_at, updated_at) VALUES (1, 'Alpha', 'active', '[]', '2026-01-01', '2026-01-01')",
  ).run();
  db.query(
    "INSERT INTO locations (id, campaign_id, name, tags, created_at, updated_at) VALUES (1, 1, 'HQ', '[]', '2026-01-01', '2026-01-01')",
  ).run();
  db.query(
    "INSERT INTO issuances (id, extractor_id, campaign_id, location_id, key_id, created_at) VALUES ('iss-1', 'extractor-1', 1, 1, '1', '2026-01-01')",
  ).run();
  db.query(
    "INSERT INTO hosts (id, machine_id, hostname, platform, os, arch, first_seen_at, last_seen_at) VALUES (1, 'machine-aaaa1111', 'web-01', 'Linux', 'Ubuntu', 'x86_64', '2026-01-01', '2026-02-01')",
  ).run();
  db.query(
    "INSERT INTO hosts (id, machine_id, hostname, platform, os, arch, first_seen_at, last_seen_at) VALUES (2, 'machine-bbbb2222', 'db-01', 'Linux', 'Debian', 'x86_64', '2026-01-01', '2026-02-01')",
  ).run();
  db.query("INSERT INTO host_locations (host_id, location_id, first_seen_at, last_seen_at) VALUES (1, 1, '2026-01-01', '2026-02-01')").run();
  db.query("INSERT INTO host_locations (host_id, location_id, first_seen_at, last_seen_at) VALUES (2, 1, '2026-01-01', '2026-02-01')").run();

  reportIds.r1 = insertReport({
    hostId: 1,
    hostname: "web-01",
    machineId: "machine-aaaa1111",
    receivedAt: "2026-01-01T00:00:00.000Z",
    scanExtra: { apiToken: SECRET_TOKEN },
    results: [
      check({
        id: "LIN-A",
        status: "NonCompliant",
        severity: "Critical",
        category: "Auth",
        title: "Authentication: password policy",
        references: ["CIS-1.1", "NIST-CM-6"],
        evidence: `${EVIDENCE_SENTINEL} password=${SECRET_PASSWORD}`,
        recommendation: "Set PermitRootLogin no",
        evidenceBlocks: [evidenceBlock()],
        fallbackLog: [
          { source: "/etc/ssh/sshd_config", outcome: "read" },
          { source: "sshd -T", outcome: "denied" },
        ],
      }),
      check({ id: "LIN-B", status: "Compliant", severity: "High", category: "Auth", title: "Authentication: MFA required", references: ["CIS-1.2"] }),
      check({
        id: "LIN-EVIL",
        status: "NonCompliant",
        severity: "Low",
        category: "Misc",
        title: '=HYPERLINK("http://evil.example","x")',
        evidence: "=1+1",
      }),
    ],
  });

  reportIds.r2 = insertReport({
    hostId: 2,
    hostname: "db-01",
    machineId: "machine-bbbb2222",
    receivedAt: "2026-01-02T00:00:00.000Z",
    results: [
      check({ id: "WIN-A", status: "NonCompliant", severity: "High", category: "OS", title: "Audit: logon events", references: ["NIST-CM-6"] }),
      check({ id: "WIN-B", status: "Compliant", severity: "Informational", category: "OS", title: "Inventory: software" }),
    ],
  });

  // Treatment: accepted_risk removes WIN-A's failed weight from the numerator.
  db.query(
    `INSERT INTO finding_states (report_id, check_id, state, assignee, due_date, updated_at)
     VALUES (?, 'WIN-A', 'accepted_risk', 'auditor1', NULL, '2026-02-01T00:00:00.000Z')`,
  ).run(reportIds.r2);

  db.query(
    `INSERT INTO ingest_events (received_at, via, envelope_bytes, duration_ms, accepted, reason_code, report_id, issuance_id)
     VALUES ('2026-01-01T01:00:00.000Z', 'push', 4096, 12, 1, NULL, ?, 'iss-1')`,
  ).run(reportIds.r1);
  db.query(
    `INSERT INTO ingest_events (received_at, via, envelope_bytes, duration_ms, accepted, reason_code, report_id, issuance_id)
     VALUES ('2026-01-01T02:00:00.000Z', 'push', 4096, 9, 0, 'bad token=${SECRET_TOKEN}', NULL, NULL)`,
  ).run();
}

function viewModel() {
  const parsed = parseQuery("?");
  if (!parsed.ok) throw new Error("query parse failed");
  return buildExportViewModel(db, parsed.query);
}

function parseCsv(text: string): string[][] {
  const src = text.startsWith("\uFEFF") ? text.slice(1) : text;
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let quoted = false;
  for (let index = 0; index < src.length; index += 1) {
    const char = src[index];
    if (quoted) {
      if (char === '"') {
        if (src[index + 1] === '"') {
          field += '"';
          index += 1;
        } else quoted = false;
      } else field += char;
      continue;
    }
    if (char === '"') quoted = true;
    else if (char === ",") {
      row.push(field);
      field = "";
    } else if (char === "\r") {
      if (src[index + 1] === "\n") index += 1;
      row.push(field);
      field = "";
      rows.push(row);
      row = [];
    } else if (char === "\n") {
      row.push(field);
      field = "";
      rows.push(row);
      row = [];
    } else field += char;
  }
  if (field !== "" || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows;
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
// View model
// ---------------------------------------------------------------------------

describe("export view model", () => {
  it("builds KPIs, ordering, sections, and redacted evidence from the scoped query", () => {
    const vm = viewModel();
    expect(vm.kpis.totalFindings).toBe(5);
    expect(vm.kpis.hostCount).toBe(2);
    expect(vm.kpis.totalReports).toBe(2);
    expect(vm.kpis.severity).toEqual({ Critical: 1, High: 2, Medium: 0, Low: 1, Informational: 1 });
    expect(vm.kpis.failingSeverity).toEqual({ Critical: 1, High: 1, Medium: 0, Low: 1, Informational: 0 });
    expect(vm.kpis.status.NonCompliant).toBe(3);
    expect(vm.kpis.treatment).toEqual({ open: 4, accepted_risk: 1, false_positive: 0, remediated: 0 });
    expect(vm.kpis.openFindings).toBe(2);
    expect(vm.kpis.openCriticals).toBe(1);
    expect(vm.kpis.coverage).toBe(100);

    // risk = 100 * (1 - (10 + 1) / (10 + 6 + 6 + 1))
    expect(vm.kpis.riskScore).toBeCloseTo(100 * (1 - 11 / 23), 2);

    // Severity descending, then check id.
    expect(vm.findings.map((finding) => finding.checkId)).toEqual([
      "LIN-A",
      "LIN-B",
      "WIN-A",
      "LIN-EVIL",
      "WIN-B",
    ]);

    expect(vm.hosts.map((host) => host.hostname)).toEqual(["db-01", "web-01"]);
    expect(vm.checks).toHaveLength(5);
    expect(vm.references.map((reference) => reference.reference)).toEqual(["CIS-1.1", "CIS-1.2", "NIST-CM-6"]);
    const nist = vm.references.find((reference) => reference.reference === "NIST-CM-6");
    expect(nist).toMatchObject({ standard: "NIST", count: 2, nonCompliant: 2, hosts: 2 });

    expect(vm.summary.length).toBeGreaterThanOrEqual(4);
    expect(vm.summary.every((sentence) => sentence.length > 0)).toBe(true);
    expect(vm.summary.some((sentence) => sentence.includes("open Critical"))).toBe(true);
  });

  it("exposes evidence ±3 context with absolute line numbers and the offending line", () => {
    const vm = viewModel();
    const finding = vm.findings.find((entry) => entry.checkId === "LIN-A")!;
    expect(finding.evidenceBlocks).toHaveLength(1);
    const block = finding.evidenceBlocks[0];
    expect(block.path).toBe("/etc/ssh/sshd_config");
    expect(block.lines.map((line) => line.lineNumber)).toEqual([40, 41, 42, 43, 44]);
    const offending = block.lines.filter((line) => line.offending);
    expect(offending).toHaveLength(1);
    expect(offending[0].text).toBe("PermitRootLogin yes");
    expect(block.fileMode).toBe("0644");
    expect(finding.fallbackLog).toEqual([
      { source: "/etc/ssh/sshd_config", outcome: "read" },
      { source: "sshd -T", outcome: "denied" },
    ]);
  });

  it("runs the shared redactor over evidence before it reaches the model", () => {
    const vm = viewModel();
    const finding = vm.findings.find((entry) => entry.checkId === "LIN-A")!;
    expect(finding.evidence).toContain(EVIDENCE_SENTINEL);
    expect(finding.evidence).toContain("password=[redacted]");
    expect(finding.evidence).not.toContain(SECRET_PASSWORD);
  });

  it("computes the same risk/coverage as the metrics layer", () => {
    const vm = viewModel();
    const results = db
      .query("SELECT report_json FROM reports ORDER BY id")
      .all() as { report_json: string }[];
    const all = results.flatMap((row) => JSON.parse(row.report_json).results);
    const treatment = new Map<string, string>([["WIN-A", "accepted_risk"]]);
    const lookup = (id: string) => treatment.get(id) as any;
    expect(vm.kpis.coverage).toBeCloseTo(computeCoverage(all), 2);
    expect(vm.kpis.riskScore).toBeCloseTo(computeRiskScore(all, lookup), 2);
  });
});

// ---------------------------------------------------------------------------
// XLSX
// ---------------------------------------------------------------------------

describe("xlsx export", () => {
  it("produces a valid workbook with the two required sheets", async () => {
    const vm = viewModel();
    const buffer = await renderXlsx(vm);
    expect(buffer.subarray(0, 2).toString()).toBe("PK");

    const workbook = new ExcelJS.Workbook();
    await workbook.xlsx.load(buffer as any);
    expect(workbook.worksheets.map((sheet) => sheet.name)).toEqual(["Executive Summary", "Findings"]);
  });

  it("freezes the header, sets an autofilter, and colour-codes severity", async () => {
    const vm = viewModel();
    const buffer = await renderXlsx(vm);
    const workbook = new ExcelJS.Workbook();
    await workbook.xlsx.load(buffer as any);
    const sheet = workbook.getWorksheet("Findings")!;
    expect(sheet.rowCount).toBe(vm.findings.length + 1);
    expect(sheet.views[0]).toMatchObject({ state: "frozen", ySplit: 1 });
    expect(sheet.autoFilter).toBeTruthy();

    const header = sheet.getRow(1);
    expect(header.getCell(1).value).toBe("Host");
    expect(header.getCell(6).value).toBe("Severity");

    const criticalRow = sheet.getCell(2, 6); // first finding is Critical
    expect((criticalRow.fill as any).fgColor.argb).toBe("FFC00000");
    const lowRow = sheet.getCell(5, 6); // LIN-EVIL
    expect((lowRow.fill as any).fgColor.argb).toBe("FF70AD47");
  });

  it("renders executive KPIs from the same view model", async () => {
    const vm = viewModel();
    const buffer = await renderXlsx(vm);
    const workbook = new ExcelJS.Workbook();
    await workbook.xlsx.load(buffer as any);
    const sheet = workbook.getWorksheet("Executive Summary")!;

    let riskScore: unknown;
    let coverage: unknown;
    sheet.eachRow((row) => {
      if (row.getCell(1).value === "Weighted Risk Score (0-100)") riskScore = row.getCell(2).value;
      if (row.getCell(1).value === "Evidence Coverage (%)") coverage = row.getCell(2).value;
    });
    expect(riskScore).toBe(vm.kpis.riskScore);
    expect(coverage).toBe(vm.kpis.coverage);
  });
});

// ---------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------

describe("csv export", () => {
  it("escapes quotes, commas, and newlines per RFC 4180", () => {
    expect(csvCell("plain")).toBe("plain");
    expect(csvCell('a,b')).toBe('"a,b"');
    expect(csvCell('a"b')).toBe('"a""b"');
    expect(csvCell("a\nb")).toBe('"a\nb"');
    expect(toCsv([["a", 'b,c'], ["d", 'e"f']])).toBe('a,"b,c"\r\nd,"e""f"');
  });

  it("neutralizes spreadsheet formula injection", () => {
    expect(csvCell("=1+1")).toBe("'=1+1");
    expect(csvCell("+SUM(A1)")).toBe("'+SUM(A1)");
    expect(csvCell("-2+3")).toBe("'-2+3");
    expect(csvCell("@cmd")).toBe("'@cmd");
  });

  it("emits a BOM-prefixed flat table that round-trips through a parser", () => {
    const vm = viewModel();
    const csv = renderCsv(vm);
    expect(csv.startsWith("\uFEFF")).toBe(true);
    const rows = parseCsv(csv);
    expect(rows).toHaveLength(vm.findings.length + 1);
    expect(rows[0][3]).toBe("Check ID");

    // The malicious title survives only as an inert, single-quoted cell.
    const evilRow = rows.find((row) => row[3] === "LIN-EVIL")!;
    expect(evilRow[4]).toBe('\'=HYPERLINK("http://evil.example","x")');

    // Severity tally from the CSV agrees with the view model.
    const severityIndex = rows[0].indexOf("Severity");
    const tally: Record<string, number> = {};
    for (const row of rows.slice(1)) tally[row[severityIndex]] = (tally[row[severityIndex]] ?? 0) + 1;
    for (const [severity, count] of Object.entries(vm.kpis.severity)) {
      expect(tally[severity] ?? 0).toBe(count);
    }
    expect(Object.values(tally).reduce((sum, count) => sum + count, 0)).toBe(vm.findings.length);

    expect(csv).not.toContain(SECRET_PASSWORD);
  });
});

// ---------------------------------------------------------------------------
// PDF
// ---------------------------------------------------------------------------

describe("pdf export", () => {
  it("renders both templates to distinct, parseable PDFs", async () => {
    const vm = viewModel();
    const executive = await renderPdf(vm, "executive");
    const technical = await renderPdf(vm, "technical");

    for (const buffer of [executive, technical]) {
      const text = buffer.toString("latin1");
      expect(text.startsWith("%PDF-")).toBe(true);
      expect(text.includes("%%EOF")).toBe(true);
      expect(buffer.length).toBeGreaterThan(1000);
      expect((text.match(/\/Type \/Page(?![a-zA-Z])/g) ?? []).length).toBeGreaterThanOrEqual(1);
    }

    const executiveText = executive.toString("latin1");
    const technicalText = technical.toString("latin1");
    expect(executiveText).toContain("HBS-EXPORT-MARKER-executive");
    expect(technicalText).toContain("HBS-EXPORT-MARKER-technical");
    expect(executiveText).not.toContain("HBS-EXPORT-MARKER-technical");
    expect(technicalText).not.toContain("HBS-EXPORT-MARKER-executive");
    expect(executive.equals(technical)).toBe(false);
  });

  it("technical template paginates hosts and never leaks a raw secret", async () => {
    const vm = viewModel();
    const technical = await renderPdf(vm, "technical");
    const text = technical.toString("latin1");
    expect((text.match(/\/Type \/Page(?![a-zA-Z])/g) ?? []).length).toBeGreaterThanOrEqual(3);
    expect(text).not.toContain(SECRET_PASSWORD);
    expect(text).not.toContain(SECRET_TOKEN);
  });
});

// ---------------------------------------------------------------------------
// DOCX
// ---------------------------------------------------------------------------

describe("docx export", () => {
  it("produces a valid, editable document mirroring the technical PDF", async () => {
    const vm = viewModel();
    const buffer = await renderDocx(vm);
    expect(buffer.subarray(0, 2).toString()).toBe("PK");

    const zip = await JSZip.loadAsync(buffer);
    const xml = await zip.file("word/document.xml")!.async("string");
    expect(xml).toContain("Technical Audit Report");
    expect(xml).toContain("Findings by Host");
    expect(xml).toContain("web-01");
    expect(xml).toContain("PermitRootLogin yes");
    expect(xml).toContain("Standard References");
    expect(xml).toContain("CIS-1.1");
    expect(xml).not.toContain(SECRET_PASSWORD);
    expect(xml).not.toContain(SECRET_TOKEN);
  });
});

// ---------------------------------------------------------------------------
// Diagnostic
// ---------------------------------------------------------------------------

describe("diagnostic export", () => {
  it("contains telemetry but never evidence, report_json, or secrets", () => {
    const parsed = parseQuery("?");
    if (!parsed.ok) throw new Error("parse failed");
    const bundle = buildDiagnosticExport(db, parsed.query);
    const json = renderDiagnosticJson(bundle);
    const csv = renderDiagnosticCsv(bundle);

    expect(json).toContain("telemetry");
    expect(json).toContain("ingestEvents");
    for (const sentinel of [EVIDENCE_SENTINEL, SECRET_PASSWORD, SECRET_TOKEN]) {
      expect(json).not.toContain(sentinel);
      expect(csv).not.toContain(sentinel);
    }
    expect(json).not.toContain("report_json");
    expect(json).not.toContain("reportJson");
    expect(json).not.toContain("evidenceBlocks");
    expect(csv.startsWith("\uFEFF")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Routes + role restrictions
// ---------------------------------------------------------------------------

describe("export routes", () => {
  it("serves viewer-scoped report and campaign exports", async () => {
    const csv = await get(VIEWER, `/api/export/report/${reportIds.r1}?format=csv`);
    expect(csv.status).toBe(200);
    expect(csv.headers.get("content-type")).toContain("text/csv");
    const csvBytes = new Uint8Array(await csv.arrayBuffer());
    // Fetch `text()` strips a leading BOM, so assert on the wire bytes.
    expect([csvBytes[0], csvBytes[1], csvBytes[2]]).toEqual([0xef, 0xbb, 0xbf]);
    expect(new TextDecoder().decode(csvBytes)).toContain("LIN-A");

    const xlsx = await get(VIEWER, `/api/export/report/${reportIds.r1}?format=xlsx`);
    expect(xlsx.status).toBe(200);
    expect(xlsx.headers.get("content-type")).toContain("spreadsheetml");
    expect((await xlsx.arrayBuffer()).byteLength).toBeGreaterThan(1000);

    const campaign = await get(VIEWER, `/api/export/campaign/1?format=csv`);
    expect(campaign.status).toBe(200);
    const campaignText = await campaign.text();
    expect(campaignText).toContain("web-01");
    expect(campaignText).toContain("db-01");

    const alias = await get(VIEWER, `/api/export/${reportIds.r1}?format=csv`);
    expect(alias.status).toBe(200);

    const pdf = await get(VIEWER, `/api/export/report/${reportIds.r1}?format=pdf&template=executive`);
    expect(pdf.status).toBe(200);
    expect(pdf.headers.get("content-type")).toContain("application/pdf");

    const docx = await get(VIEWER, `/api/export/report/${reportIds.r1}?format=docx`);
    expect(docx.status).toBe(200);
    expect(docx.headers.get("content-type")).toContain("wordprocessingml");
  });

  it("rejects bad formats, templates, ids, and unknown reports", async () => {
    expect((await get(VIEWER, `/api/export/report/${reportIds.r1}?format=exe`)).status).toBe(400);
    expect((await get(VIEWER, `/api/export/report/${reportIds.r1}?format=pdf&template=evil`)).status).toBe(400);
    expect((await get(VIEWER, "/api/export/report/abc?format=csv")).status).toBe(400);
    expect((await get(VIEWER, "/api/export/report/99999?format=csv")).status).toBe(404);
    expect((await get(VIEWER, "/api/export/campaign/99999?format=csv")).status).toBe(404);
  });

  it("restricts the diagnostic bundle to super_admin", async () => {
    const forbidden = await get(VIEWER, "/api/export/diagnostic");
    expect(forbidden.status).toBe(403);

    const allowed = await get(ADMIN, "/api/export/diagnostic?format=json");
    expect(allowed.status).toBe(200);
    expect(allowed.headers.get("content-type")).toContain("application/json");
    const body = await allowed.text();
    expect(body).toContain("telemetry");
    expect(body).not.toContain(SECRET_TOKEN);
    expect(body).not.toContain(EVIDENCE_SENTINEL);

    const csv = await get(ADMIN, "/api/export/diagnostic?format=csv");
    expect(csv.status).toBe(200);
    expect(csv.headers.get("content-type")).toContain("text/csv");
    const csvBytes = new Uint8Array(await csv.arrayBuffer());
    expect([csvBytes[0], csvBytes[1], csvBytes[2]]).toEqual([0xef, 0xbb, 0xbf]);

    expect((await get(ADMIN, "/api/export/diagnostic?format=xml")).status).toBe(400);
  });
});
