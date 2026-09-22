// Task 57 + 58 export tests.
//
// A database is seeded directly with realistic `report_json` (the same shape
// the extractor emits and `reports.test.ts` builds) so every generator is
// exercised against real evidence blocks, fallback logs, treatment state, and a
// secret sentinel that must never survive redaction.
//
// Every format is driven from the SAME `buildExportViewModel` output, so the
// metric-agreement assertions below are the guard against KPI drift.

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
import {
  buildExportViewModel,
  CONFIDENTIALITY_NOTE,
  SEVERITY_ARGB,
  SEVERITY_HEX,
  SEVERITY_ORDER,
  type ExportViewModel,
} from "./viewmodel";
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
    "INSERT INTO campaigns (id, name, client, status, tags, created_at, updated_at) VALUES (1, 'Alpha', 'Acme Industries', 'active', '[]', '2026-01-01', '2026-01-01')",
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

function viewModel(): ExportViewModel {
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

/** Locate the header row (the one starting with "Host") in a parsed CSV. */
function csvHeaderIndex(rows: readonly string[][]): number {
  const index = rows.findIndex((row) => row[0] === "Host" && row.includes("Check ID"));
  if (index < 0) throw new Error("findings header row not found");
  return index;
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

  it("exposes branding metadata (client, subtitle, confidentiality) from the campaign", () => {
    const vm = viewModel();
    expect(vm.subtitle).toBe("Technical Audit Report");
    expect(vm.client).toBe("Acme Industries");
    expect(vm.scope.campaignName).toBe("Alpha");
    expect(vm.scope.campaignClient).toBe("Acme Industries");
    expect(vm.confidentiality).toBe(CONFIDENTIALITY_NOTE);
    expect(vm.generator.length).toBeGreaterThan(0);
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
  async function load(buffer: Buffer): Promise<ExcelJS.Workbook> {
    const workbook = new ExcelJS.Workbook();
    await workbook.xlsx.load(buffer as any);
    return workbook;
  }

  it("produces a branded workbook with cover, executive, findings, and rollup sheets", async () => {
    const vm = viewModel();
    const buffer = await renderXlsx(vm);
    expect(buffer.subarray(0, 2).toString()).toBe("PK");

    const workbook = await load(buffer);
    expect(workbook.worksheets.map((sheet) => sheet.name)).toEqual([
      "Cover",
      "Executive Summary",
      "Findings",
      "By Host",
      "By Check",
    ]);

    const cover = workbook.getWorksheet("Cover")!;
    const values: string[] = [];
    cover.eachRow((row) => {
      for (let column = 1; column <= 6; column += 1) {
        const value = row.getCell(column).value;
        if (typeof value === "string") values.push(value);
      }
    });
    expect(values).toContain(vm.title);
    expect(values.some((value) => value.includes("Acme Industries"))).toBe(true);
    expect(values).toContain(vm.confidentiality);
    expect(values.some((value) => value.startsWith("Generated"))).toBe(true);
  });

  it("draws KPI cards as merged, coloured cells and a severity distribution block", async () => {
    const vm = viewModel();
    const workbook = await load(await renderXlsx(vm));
    const sheet = workbook.getWorksheet("Executive Summary")!;

    const labels = new Set<string>();
    sheet.eachRow((row) => {
      for (let column = 1; column <= 6; column += 1) {
        const value = row.getCell(column).value;
        if (typeof value === "string") labels.add(value);
      }
    });
    expect(labels.has("Weighted Risk Score (0-100)")).toBe(true);
    expect(labels.has("Evidence Coverage (%)")).toBe(true);
    expect(labels.has("Open Critical Findings")).toBe(true);

    // KPI values are written into merged card cells.
    const merges = (sheet as any).model?.merges as string[] | undefined;
    expect(Array.isArray(merges) && merges.length > 0).toBe(true);

    let riskCard: ExcelJS.Cell | null = null;
    let criticalCard: ExcelJS.Cell | null = null;
    sheet.eachRow((row) => {
      for (let column = 1; column <= 6; column += 1) {
        const cell = row.getCell(column);
        if (cell.value === "Weighted Risk Score (0-100)") riskCard = sheet.getCell(row.number + 1, column);
        if (cell.value === "Open Critical Findings") criticalCard = sheet.getCell(row.number + 1, column);
      }
    });
    expect(riskCard).not.toBeNull();
    expect((riskCard as unknown as ExcelJS.Cell).value).toBe(vm.kpis.riskScore);
    // Risk card is tinted by the score band (52.17 -> orange "EA580C").
    expect(((riskCard as unknown as ExcelJS.Cell).fill as any).fgColor.argb).toBe("FFEA580C");
    expect(criticalCard).not.toBeNull();
    expect((criticalCard as unknown as ExcelJS.Cell).value).toBe(vm.kpis.openCriticals);
    // The open-critical card uses the Critical severity red.
    expect(((criticalCard as unknown as ExcelJS.Cell).fill as any).fgColor.argb).toBe("FFE11D48");
  });

  it("freezes the findings header, sets an autofilter, and colour-codes severity", async () => {
    const vm = viewModel();
    const workbook = await load(await renderXlsx(vm));
    const sheet = workbook.getWorksheet("Findings")!;
    expect(sheet.rowCount).toBe(vm.findings.length + 1);
    expect(sheet.views[0]).toMatchObject({ state: "frozen", ySplit: 1 });
    expect(sheet.autoFilter).toBeTruthy();

    const header = sheet.getRow(1);
    expect(header.getCell(1).value).toBe("Host");
    expect(header.getCell(2).value).toBe("Display ID");
    expect(header.getCell(4).value).toBe("Check ID");
    expect(header.getCell(5).value).toBe("Title");
    expect(header.getCell(6).value).toBe("Severity");
    expect(header.getCell(7).value).toBe("Status");
    expect(header.getCell(8).value).toBe("Treatment");
    expect(header.getCell(9).value).toBe("Evidence Depth");
    expect(header.getCell(10).value).toBe("Category");
    expect(header.getCell(11).value).toBe("References");
    expect(header.getCell(12).value).toBe("Repro");

    // Severity fill matches the UI palette for every row.
    for (let index = 0; index < vm.findings.length; index += 1) {
      const finding = vm.findings[index];
      const cell = sheet.getCell(index + 2, 6);
      expect((cell.fill as any).fgColor.argb).toBe(SEVERITY_ARGB[finding.severity]);
    }
    expect((sheet.getCell(2, 6).fill as any).fgColor.argb).toBe("FFE11D48"); // Critical
  });

  it("renders by-host and by-check rollups that agree with the view model", async () => {
    const vm = viewModel();
    const workbook = await load(await renderXlsx(vm));

    const hostSheet = workbook.getWorksheet("By Host")!;
    expect(hostSheet.rowCount).toBe(vm.hosts.length + 1);
    expect(hostSheet.getRow(1).getCell(1).value).toBe("Host");

    const checkSheet = workbook.getWorksheet("By Check")!;
    expect(checkSheet.rowCount).toBe(vm.checks.length + 1);
    expect(checkSheet.getRow(1).getCell(1).value).toBe("Check ID");

    // Total severity column across hosts equals the workbook severity tally.
    const totals: Record<string, number> = { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 };
    const columns: Record<string, number> = { Critical: 9, High: 10, Medium: 11, Low: 12, Informational: 13 };
    for (let index = 0; index < vm.hosts.length; index += 1) {
      for (const severity of SEVERITY_ORDER) {
        totals[severity] += Number(hostSheet.getCell(index + 2, columns[severity]).value ?? 0);
      }
    }
    for (const severity of SEVERITY_ORDER) {
      expect(totals[severity]).toBe(vm.kpis.severity[severity]);
    }
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

  it("neutralizes spreadsheet formula injection, including leading tab and CR", () => {
    expect(csvCell("=1+1")).toBe("'=1+1");
    expect(csvCell("+SUM(A1)")).toBe("'+SUM(A1)");
    expect(csvCell("-2+3")).toBe("'-2+3");
    expect(csvCell("@cmd")).toBe("'@cmd");
    expect(csvCell("\tcmd")).toBe("'\tcmd");
    expect(csvCell("\rcmd")).toBe('"\'\rcmd"');
    // A formula that also contains a comma is quoted AND neutralized.
    expect(csvCell("=cmd|' /C calc',A0")).toBe('"\'=cmd|\' /C calc\',A0"');
  });

  it("emits a BOM-prefixed header block followed by the flat findings table", () => {
    const vm = viewModel();
    const csv = renderCsv(vm);
    expect(csv.startsWith("\uFEFF")).toBe(true);
    const rows = parseCsv(csv);
    const headerIndex = csvHeaderIndex(rows);

    // Provenance block names the client, campaign, and confidentiality notice.
    const block = rows.slice(0, headerIndex).flat();
    expect(block.some((cell) => cell.includes(vm.title))).toBe(true);
    expect(block.some((cell) => cell.includes("Acme Industries"))).toBe(true);
    expect(block.some((cell) => cell.includes(vm.confidentiality))).toBe(true);

    const dataRows = rows.slice(headerIndex + 1).filter((row) => row.some((cell) => cell !== ""));
    expect(dataRows).toHaveLength(vm.findings.length);
    expect(rows[headerIndex][3]).toBe("Check ID");

    // The malicious title survives only as an inert, single-quoted cell.
    const evilRow = dataRows.find((row) => row[3] === "LIN-EVIL")!;
    expect(evilRow[4]).toBe('\'=HYPERLINK("http://evil.example","x")');

    // Severity tally from the CSV agrees with the view model.
    const severityIndex = rows[headerIndex].indexOf("Severity");
    const tally: Record<string, number> = {};
    for (const row of dataRows) tally[row[severityIndex]] = (tally[row[severityIndex]] ?? 0) + 1;
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

/**
 * PDFKit writes text as hex-encoded `<...>` TJ runs with WinAnsi bytes and puts
 * the ASCII metadata dictionary in plain parens. Decode both so assertions can
 * look for real rendered strings (e.g. "Key Performance Indicators").
 */
/**
 * Decode a PDF back to a normalized, human-meaningful text stream.
 *
 * PDFKit splits a line into several TJ segments and writes them as `<hex>` runs
 * and WinAnsi `(literal)` strings. We decode both, join with a single space, and
 * collapse whitespace so multi-segment headings ("Key Performance " +
 * "Indicators") match as one phrase. The ASCII metadata dictionary is appended
 * verbatim afterwards because it is not hex-encoded.
 */
function pdfText(buffer: Buffer): string {
  const raw = buffer.toString("latin1");
  const decoded = raw.replace(
    /<([0-9A-Fa-f]+)>|\(((?:\\.|[^\\()])*)\)/g,
    (_match, hex: string, literal: string) => {
      if (typeof hex === "string" && hex.length > 0) {
        const bytes: number[] = [];
        for (let index = 0; index + 1 < hex.length; index += 2) {
          bytes.push(parseInt(hex.slice(index, index + 2), 16));
        }
        return `\u0001${latin1(bytes)}\u0001`;
      }
      const unescaped = (literal ?? "")
        .replace(/\\([nrtbf()\\])/g, "$1")
        .replace(/\\([0-7]{1,3})/g, (_m, oct: string) => String.fromCharCode(parseInt(oct, 8)));
      return `\u0001${unescaped}\u0001`;
    },
  );
  // Between two text segments PDFKit emits kerning / TJ positioning numbers
  // (e.g. `[<4b> 15 <65>]`) which must be dropped so adjacent segments rejoin
  // into one phrase. The \u0001 sentinels mark the true segment boundaries so
  // numbers *inside* a segment (a score like "52.17") survive.
  // Drop every kerning / TJ positioning number that sits between two segments;
  // kerning hints convey no characters, so the segments must be concatenated.
  // `g`-flagged replace skips overlapping matches, so iterate to a fixed point.
  let joined = decoded;
  let previous = "";
  while (joined !== previous) {
    previous = joined;
    joined = joined.replace(/\u0001\s*[\d.-]+\s*\u0001/g, "");
  }
  joined = joined.split("\u0001").join("");
  return `${raw}\n${normalizeWinAnsi(joined).replace(/\s+/g, " ")}`;
}

/** Map the WinAnsi-only punctuation PDFKit writes back onto Unicode. */
function normalizeWinAnsi(value: string): string {
  return value
    .replace(/\u0097/g, "\u2014") // em dash
    .replace(/\u0096/g, "\u2013") // en dash
    .replace(/\u0092/g, "\u2019") // right single quote
    .replace(/\u0093/g, "\u201c")
    .replace(/\u0094/g, "\u201d")
    .replace(/\u2022/g, "\u00b7");
}

/** Decode WinAnsi bytes to a JS string without buffering through latin1 escapes. */
function latin1(bytes: readonly number[]): string {
  let out = "";
  for (const byte of bytes) out += String.fromCharCode(byte);
  return out;
}

function pageCount(text: string): number {
  return (text.match(/\/Type \/Page(?![a-zA-Z])/g) ?? []).length;
}

describe("pdf export", () => {
  it("renders both templates to distinct, parseable PDFs with cover + footer markers", async () => {
    const vm = viewModel();
    const executive = await renderPdf(vm, "executive");
    const technical = await renderPdf(vm, "technical");

    for (const buffer of [executive, technical]) {
      const text = pdfText(buffer);
      expect(text.startsWith("%PDF-")).toBe(true);
      expect(text.includes("%%EOF")).toBe(true);
      expect(buffer.length).toBeGreaterThan(1000);
      expect(pageCount(text)).toBeGreaterThanOrEqual(1);
      // Cover page + running footer markers present in both templates.
      expect(text).toContain("HBS-COVER-PAGE");
      expect(text).toContain("HBS-PAGE-FOOTER");
      expect(text).toContain(vm.title);
      expect(text).toContain(vm.confidentiality);
      // Cover labels and values are separate table cells, so assert both.
      expect(text).toContain("Campaign");
      expect(text).toContain(vm.scope.campaignName!);
      expect(text).toContain(vm.generator);
      expect(text).toContain("Page 1 of");
    }

    const executiveText = pdfText(executive);
    const technicalText = pdfText(technical);
    expect(executiveText).toContain("HBS-EXPORT-MARKER-executive");
    expect(technicalText).toContain("HBS-EXPORT-MARKER-technical");
    expect(executiveText).not.toContain("HBS-EXPORT-MARKER-technical");
    expect(technicalText).not.toContain("HBS-EXPORT-MARKER-executive");
    expect(executive.equals(technical)).toBe(false);
  });

  it("executive template is a KPI-first summary with a gauge and no evidence dump", async () => {
    const vm = viewModel();
    const text = pdfText(await renderPdf(vm, "executive"));
    expect(text).toContain("Executive Summary");
    expect(text).toContain("Key Performance Indicators");
    expect(text).toContain("Severity Breakdown");
    expect(text).toContain("Top 10 Findings");
    expect(text).toContain("Plain-Language Summary");
    expect(text).toContain("weighted risk score");
    expect(text).toContain(vm.kpis.riskScore.toFixed(1));
    expect(text).not.toContain("Findings by Host");
    expect(text).not.toContain(SECRET_PASSWORD);
    expect(text).not.toContain(SECRET_TOKEN);
  });

  it("technical template paginates hosts, highlights offending evidence, and never leaks a raw secret", async () => {
    const vm = viewModel();
    const technical = await renderPdf(vm, "technical");
    const text = pdfText(technical);
    expect(pageCount(text)).toBeGreaterThanOrEqual(3);
    expect(text).toContain("Technical Audit Report");
    expect(text).toContain("Findings by Host");
    expect(text).toContain("Findings by Check");
    expect(text).toContain("Reproduce (read-only)");
    expect(text).toContain("Remediation:");
    expect(text).toContain("Standard References");
    expect(text).toContain("PermitRootLogin yes");
    // Highlight fill drawn behind the offending evidence line (#FEE2E2).
    expect(text).toMatch(/0\.996078431372549 0\.8862745098039215 0\.8862745098039215/);
    expect(text).not.toContain(SECRET_PASSWORD);
    expect(text).not.toContain(SECRET_TOKEN);
  });

  it("agrees with the view model on the headline metrics", async () => {
    const vm = viewModel();
    for (const template of ["executive", "technical"] as const) {
      const text = pdfText(await renderPdf(vm, template));
      expect(text).toContain(`risk=${vm.kpis.riskScore}`);
      expect(text).toContain(`coverage=${vm.kpis.coverage}`);
      expect(text).toContain(`findings=${vm.kpis.totalFindings}`);
    }
  });
});

// ---------------------------------------------------------------------------
// DOCX
// ---------------------------------------------------------------------------

describe("docx export", () => {
  it("produces a valid, editable document with cover and TOC markers", async () => {
    const vm = viewModel();
    const buffer = await renderDocx(vm);
    expect(buffer.subarray(0, 2).toString()).toBe("PK");

    const zip = await JSZip.loadAsync(buffer);
    const xml = await zip.file("word/document.xml")!.async("string");
    expect(xml).toContain("Table of Contents");
    expect(xml).toContain("TOC");
    expect(xml).toContain(vm.title);
    expect(xml).toContain(vm.confidentiality);
    expect(xml).toContain("Technical Audit Report");
    expect(xml).toContain("Findings by Host");
    expect(xml).toContain("Findings by Check");
    expect(xml).toContain("Key Performance Indicators");
    expect(xml).toContain("web-01");
    expect(xml).toContain("PermitRootLogin yes");
    expect(xml).toContain("Standard References");
    expect(xml).toContain("CIS-1.1");
    expect(xml).not.toContain(SECRET_PASSWORD);
    expect(xml).not.toContain(SECRET_TOKEN);

    // Page-number footer field.
    const footerFile = Object.keys(zip.files).find((name) => /word\/footer\d*\.xml$/.test(name));
    expect(footerFile).toBeDefined();
    const footerXml = await zip.file(footerFile!)!.async("string");
    expect(footerXml).toContain("PAGE");
  });
});

// ---------------------------------------------------------------------------
// Metric agreement across every format
// ---------------------------------------------------------------------------

describe("cross-format metric agreement", () => {
  it("every format renders the identical KPI values from one view model", async () => {
    const vm = viewModel();

    // XLSX executive KPI cards.
    const workbook = new ExcelJS.Workbook();
    await workbook.xlsx.load((await renderXlsx(vm)) as any);
    const sheet = workbook.getWorksheet("Executive Summary")!;
    const cards = new Map<string, unknown>();
    sheet.eachRow((row) => {
      for (let column = 1; column <= 6; column += 1) {
        const cell = row.getCell(column);
        if (typeof cell.value === "string" && cell.value.endsWith(")")) {
          const value = sheet.getCell(row.number + 1, column).value;
          if (typeof value === "number") cards.set(cell.value, value);
        }
        if (cell.value === "Total Findings") cards.set("Total Findings", sheet.getCell(row.number + 1, column).value);
      }
    });
    expect(cards.get("Weighted Risk Score (0-100)")).toBe(vm.kpis.riskScore);
    expect(cards.get("Evidence Coverage (%)")).toBe(vm.kpis.coverage);
    expect(cards.get("Total Findings")).toBe(vm.kpis.totalFindings);

    // CSV header block.
    const rows = parseCsv(renderCsv(vm));
    const meta = new Map<string, string>();
    for (const row of rows) {
      if (row[0]?.startsWith("# ")) meta.set(row[0].slice(2), row[1] ?? "");
    }
    expect(Number(meta.get("Risk Score"))).toBe(vm.kpis.riskScore);
    expect(Number(meta.get("Coverage (%)"))).toBe(vm.kpis.coverage);
    expect(Number(meta.get("Total Findings"))).toBe(vm.kpis.totalFindings);

    // Both PDF templates.
    for (const template of ["executive", "technical"] as const) {
      const text = pdfText(await renderPdf(vm, template));
      expect(text).toContain(`risk=${vm.kpis.riskScore}`);
      expect(text).toContain(`coverage=${vm.kpis.coverage}`);
      expect(text).toContain(`findings=${vm.kpis.totalFindings}`);
    }

    // Severity palette shared by XLSX and the view model.
    for (const severity of SEVERITY_ORDER) {
      expect(SEVERITY_ARGB[severity]).toBe(`FF${SEVERITY_HEX[severity].slice(1)}`);
    }
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
