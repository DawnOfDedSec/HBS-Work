// Flat CSV export (Task 57, spec §6.6).
//
// Pure serializer over the shared export view model. The document is a
// metadata header block (title, client, campaign, scope, generated date, and
// the headline metrics) followed by the flat findings table. Every cell is
// escaped per RFC 4180 and guarded against spreadsheet formula injection: a
// cell whose text begins with `=`, `+`, `-`, `@`, tab, or CR is prefixed with a
// single quote so Excel / Sheets / LibreOffice treat it as inert text rather
// than a formula. Output carries a UTF-8 BOM so Excel detects the encoding.

import { campaignLabel, describeScopeText, type ExportFinding, type ExportViewModel } from "./viewmodel";

export const UTF8_BOM = "\uFEFF";

/** Characters that can start a spreadsheet formula / dangerous cell. */
const FORMULA_PREFIX = /^[=+\-@\t\r]/;

/**
 * Escape one CSV cell. Formula-looking text is prefixed with `'` BEFORE quoting
 * so the quote lands inside the quoted field and survives the round-trip.
 */
export function csvCell(value: unknown): string {
  const text = value === null || value === undefined ? "" : String(value);
  const guarded = FORMULA_PREFIX.test(text) ? `'${text}` : text;
  if (/[",\r\n]/.test(guarded)) return `"${guarded.replace(/"/g, '""')}"`;
  return guarded;
}

/** Serialize a matrix of cells into CRLF-delimited CSV records. */
export function toCsv(rows: readonly (readonly unknown[])[]): string {
  return rows.map((row) => row.map(csvCell).join(",")).join("\r\n");
}

const FINDING_COLUMNS = [
  "Host",
  "Display ID",
  "Machine ID",
  "Check ID",
  "Title",
  "Severity",
  "Status",
  "Treatment",
  "Evidence Depth",
  "Category",
  "References",
  "Repro",
  "Assignee",
  "Due Date",
  "Platform",
  "OS",
  "Arch",
  "Location",
  "Evidence",
  "Evidence Excerpt",
  "Fallback Log",
  "Received At",
  "Report ID",
  "Risk Score",
  "Coverage",
] as const;

export const CSV_FINDING_COLUMNS: readonly string[] = FINDING_COLUMNS;

/** Column index (1-based) of the "Severity" column in the findings table. */
export const CSV_SEVERITY_COLUMN = FINDING_COLUMNS.indexOf("Severity") + 1;

function firstOffending(finding: ExportFinding): string {
  for (const block of finding.evidenceBlocks) {
    const line = block.lines.find((entry) => entry.offending);
    if (line) return line.text;
  }
  return "";
}

function fallbackSummary(finding: ExportFinding): string {
  return finding.fallbackLog
    .map((entry) => `${entry.source}=${entry.outcome}`)
    .filter((entry) => entry !== "=")
    .join("; ");
}

function findingRow(finding: ExportFinding): (string | number | null)[] {
  return [
    finding.hostname,
    finding.displayId,
    finding.machineId,
    finding.checkId,
    finding.title,
    finding.severity,
    finding.status,
    finding.treatment,
    finding.evidenceDepth,
    finding.category,
    finding.references.join("; "),
    finding.repro,
    finding.treatmentAssignee,
    finding.treatmentDueDate,
    finding.platform,
    finding.os,
    finding.arch,
    finding.location,
    finding.evidence,
    firstOffending(finding),
    fallbackSummary(finding),
    finding.receivedAt,
    finding.reportId,
    finding.reportScore,
    finding.reportCoverage,
  ];
}

/**
 * Metadata rows that precede the findings table. Kept as `key,value` CSV
 * records so a strict parser still sees a well-formed document; the leading
 * `#` marks them as provenance rather than findings.
 */
export function csvHeaderBlock(viewModel: ExportViewModel): (string | number)[][] {
  const kpis = viewModel.kpis;
  return [
    ["# HBS Security Review Export", ""],
    ["# Title", viewModel.title],
    ["# Deliverable", viewModel.subtitle],
    ["# Client", viewModel.client ?? ""],
    ["# Campaign", campaignLabel(viewModel.scope)],
    ["# Scope", describeScopeText(viewModel.scope)],
    ["# Generated", viewModel.generatedAt],
    ["# Risk Score", kpis.riskScore],
    ["# Coverage (%)", kpis.coverage],
    ["# Total Findings", kpis.totalFindings],
    ["# Failing Findings", kpis.failingFindings],
    ["# Open Findings", kpis.openFindings],
    ["# Open Critical Findings", kpis.openCriticals],
    ["# Hosts", kpis.hostCount],
    ["# Scan Reports", kpis.totalReports],
    ["# Standard References", kpis.referenceCount],
    ["# Confidentiality", viewModel.confidentiality],
  ];
}

/** Render the header block + flat findings table. */
export function renderCsv(viewModel: ExportViewModel): string {
  const rows: (string | number | null)[][] = [
    ...csvHeaderBlock(viewModel),
    [],
    [...FINDING_COLUMNS],
    ...viewModel.findings.map(findingRow),
  ];
  return UTF8_BOM + toCsv(rows) + "\r\n";
}
