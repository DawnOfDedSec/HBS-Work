// Flat CSV export (Task 57, spec §6.6).
//
// Pure serializer over the shared export view model. Every cell is escaped per
// RFC 4180 and guarded against spreadsheet formula injection: a cell whose text
// begins with `=`, `+`, `-`, or `@` is prefixed with a single quote so Excel /
// Sheets / LibreOffice treat it as inert text rather than a formula. Output
// carries a UTF-8 BOM so Excel detects the encoding on double-click.

import type { ExportFinding, ExportViewModel } from "./viewmodel";

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
  "Category",
  "Treatment",
  "Assignee",
  "Due Date",
  "Platform",
  "OS",
  "Arch",
  "Evidence Depth",
  "Location",
  "References",
  "Repro",
  "Evidence",
  "Evidence Excerpt",
  "Fallback Log",
  "Received At",
  "Report ID",
  "Risk Score",
  "Coverage",
] as const;

export const CSV_FINDING_COLUMNS: readonly string[] = FINDING_COLUMNS;

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
    finding.category,
    finding.treatment,
    finding.treatmentAssignee,
    finding.treatmentDueDate,
    finding.platform,
    finding.os,
    finding.arch,
    finding.evidenceDepth,
    finding.location,
    finding.references.join("; "),
    finding.repro,
    finding.evidence,
    firstOffending(finding),
    fallbackSummary(finding),
    finding.receivedAt,
    finding.reportId,
    finding.reportScore,
    finding.reportCoverage,
  ];
}

/** Render the flat findings table (header + one row per finding). */
export function renderCsv(viewModel: ExportViewModel): string {
  const rows: (string | number | null)[][] = [
    [...FINDING_COLUMNS],
    ...viewModel.findings.map(findingRow),
  ];
  return UTF8_BOM + toCsv(rows) + "\r\n";
}
