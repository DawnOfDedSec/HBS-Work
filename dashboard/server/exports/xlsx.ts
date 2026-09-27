// Excel workbook export + the shared export route hub (Task 57, spec §6.6).
//
// `renderXlsx` is a pure serializer over the normalized export view model and
// produces a branded, client-ready workbook:
//   * "Cover"             - title banner, campaign/client/scope, date, and the
//                           confidentiality note.
//   * "Executive Summary" - KPI cards drawn as merged/coloured cells, a
//                           severity distribution block, and the plain-language
//                           summary.
//   * "Findings"          - one row per finding with severity colour coding, a
//                           frozen header row, and an autofilter.
//   * "By Host"           - per-host rollup with severity counts.
//   * "By Check"          - per-check rollup with status counts and references.
//
// `registerExportRoutes` is the single mount point for the export feature. It
// wires the canonical scoped routes (report + campaign, `?format=`) plus the
// super-admin diagnostic bundle. It never renders: it resolves the scope,
// builds ONE view model, and hands it to the format renderer.

import type { Database } from "bun:sqlite";
import ExcelJS from "exceljs";
import { Hono, type MiddlewareHandler } from "hono";
import { parseQuery } from "../query";
import { registerDiagnosticExportRoutes } from "./diagnostic";
import { renderCsv } from "./csv";
import { renderDocx } from "./docx";
import { renderPdf } from "./pdf";
import {
  buildExportViewModel,
  campaignLabel,
  describeScopeText,
  EXPORT_FORMATS,
  EXPORT_TEMPLATES,
  scopeToCampaign,
  scopeToReport,
  scoreHex,
  SEVERITY_ARGB,
  SEVERITY_ORDER,
  SEVERITY_TEXT_ARGB,
  type ExportFormat,
  type ExportTemplate,
  type ExportViewModel,
} from "./viewmodel";
import type { ReportOptions } from "../reports";

// ---------------------------------------------------------------------------
// Shared styling helpers
// ---------------------------------------------------------------------------

const INK = "FF0F172A";
const MUTED = "FF475569";
const RULE = "FFE2E8F0";
const CARD_BG = "FFF1F5F9";
const BANNER = "FF0F172A";

const THIN_BORDER: Partial<ExcelJS.Borders> = {
  top: { style: "thin", color: { argb: RULE } },
  left: { style: "thin", color: { argb: RULE } },
  bottom: { style: "thin", color: { argb: RULE } },
  right: { style: "thin", color: { argb: RULE } },
};

function solidFill(argb: string): ExcelJS.Fill {
  return { type: "pattern", pattern: "solid", fgColor: { argb } };
}

function severityFill(argb: string): ExcelJS.Fill {
  return solidFill(argb);
}

function hexArgb(hex: string): string {
  return `FF${hex.replace("#", "").toUpperCase()}`;
}

function styleTitleRow(ws: ExcelJS.Worksheet, rowNumber: number, text: string, size: number): void {
  const row = ws.getRow(rowNumber);
  row.getCell(1).value = text;
  row.getCell(1).font = { bold: true, size };
}

function styleSectionRow(ws: ExcelJS.Worksheet, rowNumber: number, text: string): void {
  const row = ws.getRow(rowNumber);
  row.getCell(1).value = text;
  row.getCell(1).font = { bold: true, size: 12, color: { argb: INK } };
}

type TableColumn = { header: string; width: number };

/** Write a header + rows table with a frozen header and an autofilter. */
function writeTable(
  ws: ExcelJS.Worksheet,
  columns: readonly TableColumn[],
  rows: readonly (string | number | null)[][],
): void {
  ws.columns = columns.map((column) => ({
    header: column.header,
    key: column.header,
    width: column.width,
  }));
  for (const row of rows) ws.addRow(row);
  const header = ws.getRow(1);
  header.font = { bold: true, color: { argb: "FFFFFFFF" } };
  header.fill = solidFill(INK);
  header.alignment = { vertical: "middle" };
  header.height = 20;
  ws.views = [{ state: "frozen", ySplit: 1 }];
  ws.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: columns.length } };
}

// ---------------------------------------------------------------------------
// Cover sheet
// ---------------------------------------------------------------------------

function buildCoverSheet(ws: ExcelJS.Worksheet, viewModel: ExportViewModel): void {
  ws.getColumn(1).width = 26;
  ws.getColumn(2).width = 52;
  for (let index = 3; index <= 6; index += 1) ws.getColumn(index).width = 16;

  ws.mergeCells("A1:F2");
  const banner = ws.getCell("A1");
  banner.value = viewModel.title;
  banner.font = { bold: true, size: 22, color: { argb: "FFFFFFFF" } };
  banner.fill = solidFill(BANNER);
  banner.alignment = { vertical: "middle", horizontal: "left", indent: 1, wrapText: true };
  ws.getRow(1).height = 26;
  ws.getRow(2).height = 26;

  const metadata: [string, string | number][] = [
    ["Deliverable", viewModel.subtitle],
    ["Client", viewModel.client ?? "-"],
    ["Campaign", campaignLabel(viewModel.scope)],
    ["Scope", describeScopeText(viewModel.scope)],
    ["Generated", viewModel.generatedAt],
    ["Weighted Risk Score", `${viewModel.kpis.riskScore.toFixed(1)} / 100`],
    ["Evidence Coverage", `${viewModel.kpis.coverage.toFixed(1)}%`],
    ["Findings in scope", viewModel.kpis.totalFindings],
    ["Hosts in scope", viewModel.kpis.hostCount],
  ];

  let row = 4;
  for (const [label, value] of metadata) {
    const metaRow = ws.getRow(row++);
    metaRow.getCell(1).value = label;
    metaRow.getCell(1).font = { bold: true, color: { argb: MUTED } };
    metaRow.getCell(2).value = value;
    metaRow.getCell(2).font = { bold: label === "Weighted Risk Score" };
  }

  row += 1;
  ws.mergeCells(`A${row}:F${row}`);
  const notice = ws.getCell(`A${row}`);
  notice.value = viewModel.confidentiality;
  notice.font = { italic: true, color: { argb: "FF9A3412" }, size: 10 };
  notice.fill = solidFill("FFFFF7ED");
  notice.alignment = { wrapText: true, vertical: "middle", indent: 1 };
  ws.getRow(row).height = 30;
  row += 2;

  styleSectionRow(ws, row++, "Contents");
  for (const name of ["Executive Summary", "Findings", "By Host", "By Check"]) {
    const contentsRow = ws.getRow(row++);
    contentsRow.getCell(1).value = name;
    contentsRow.getCell(1).font = { color: { argb: INK } };
  }

  row += 1;
  const attribution = ws.getRow(row);
  attribution.getCell(1).value = `Generated by ${viewModel.generator}`;
  attribution.getCell(1).font = { size: 9, color: { argb: MUTED } };
}

// ---------------------------------------------------------------------------
// Executive Summary sheet (KPI cards + severity distribution)
// ---------------------------------------------------------------------------

type KpiCard = { label: string; value: string | number; fill: string; text: string };

function kpiCards(viewModel: ExportViewModel): KpiCard[] {
  const kpis = viewModel.kpis;
  const neutral = { fill: CARD_BG, text: INK };
  return [
    { label: "Weighted Risk Score (0-100)", value: kpis.riskScore, ...neutral, fill: hexArgb(scoreHex(kpis.riskScore)), text: "FFFFFFFF" },
    { label: "Evidence Coverage (%)", value: kpis.coverage, ...neutral },
    { label: "Total Findings", value: kpis.totalFindings, ...neutral },
    { label: "Failing / Degraded", value: kpis.failingFindings, ...neutral },
    {
      label: "Open Findings",
      value: kpis.openFindings,
      fill: kpis.openFindings > 0 ? hexArgb("#FEF3C7") : CARD_BG,
      text: INK,
    },
    {
      label: "Open Critical Findings",
      value: kpis.openCriticals,
      fill: kpis.openCriticals > 0 ? hexArgb("#E11D48") : CARD_BG,
      text: kpis.openCriticals > 0 ? "FFFFFFFF" : INK,
    },
    { label: "Hosts", value: kpis.hostCount, ...neutral },
    { label: "Scan Reports", value: kpis.totalReports, ...neutral },
    { label: "Standard References", value: kpis.referenceCount, ...neutral },
  ];
}

function buildExecutiveSheet(ws: ExcelJS.Worksheet, viewModel: ExportViewModel): void {
  for (let index = 1; index <= 6; index += 1) ws.getColumn(index).width = 18;

  ws.mergeCells("A1:F1");
  const title = ws.getCell("A1");
  title.value = `${viewModel.title} - Executive Summary`;
  title.font = { bold: true, size: 15, color: { argb: INK } };
  title.alignment = { vertical: "middle" };
  ws.getRow(1).height = 24;

  ws.mergeCells("A2:F2");
  const subtitle = ws.getCell("A2");
  subtitle.value = `${campaignLabel(viewModel.scope)} · ${describeScopeText(viewModel.scope)} · Generated ${viewModel.generatedAt}`;
  subtitle.font = { size: 9, color: { argb: MUTED } };

  let row = 4;

  // --- KPI cards: 3 per row, each card spans two columns and two rows. -----
  styleSectionRow(ws, row++, "Key Performance Indicators");
  const cards = kpiCards(viewModel);
  const cardColumns = [1, 3, 5]; // A-B, C-D, E-F
  for (let index = 0; index < cards.length; index += cardColumns.length) {
    const slice = cards.slice(index, index + cardColumns.length);
    const labelRow = row;
    const valueRow = row + 1;
    slice.forEach((card, cardIndex) => {
      const col = cardColumns[cardIndex];
      ws.mergeCells(labelRow, col, labelRow, col + 1);
      ws.mergeCells(valueRow, col, valueRow, col + 1);

      const labelCell = ws.getCell(labelRow, col);
      labelCell.value = card.label;
      labelCell.font = { bold: true, size: 9, color: { argb: MUTED } };
      labelCell.fill = solidFill(CARD_BG);
      labelCell.alignment = { vertical: "middle", horizontal: "left", indent: 1, wrapText: true };
      labelCell.border = THIN_BORDER;

      const valueCell = ws.getCell(valueRow, col);
      valueCell.value = card.value;
      valueCell.font = { bold: true, size: 16, color: { argb: card.text } };
      valueCell.fill = solidFill(card.fill);
      valueCell.alignment = { vertical: "middle", horizontal: "left", indent: 1 };
      valueCell.border = THIN_BORDER;
    });
    ws.getRow(labelRow).height = 18;
    ws.getRow(valueRow).height = 26;
    row += 2;
  }

  row += 1;

  // --- Severity distribution block. ---------------------------------------
  styleSectionRow(ws, row++, "Severity Distribution");
  const distHeader = ws.getRow(row++);
  distHeader.getCell(1).value = "Severity";
  distHeader.getCell(2).value = "Total";
  distHeader.getCell(3).value = "Failing";
  distHeader.getCell(4).value = "Distribution";
  distHeader.font = { bold: true, color: { argb: MUTED } };

  const maxSeverity = Math.max(1, ...SEVERITY_ORDER.map((severity) => viewModel.kpis.severity[severity] ?? 0));
  for (const severity of SEVERITY_ORDER) {
    const total = viewModel.kpis.severity[severity] ?? 0;
    const failing = viewModel.kpis.failingSeverity[severity] ?? 0;
    const severityRow = ws.getRow(row++);
    severityRow.getCell(1).value = severity;
    severityRow.getCell(1).fill = severityFill(SEVERITY_ARGB[severity] ?? "FF64748B");
    severityRow.getCell(1).font = { bold: true, color: { argb: SEVERITY_TEXT_ARGB[severity] ?? "FFFFFFFF" } };
    severityRow.getCell(2).value = total;
    severityRow.getCell(3).value = failing;
    const bars = total > 0 ? Math.max(1, Math.round((total / maxSeverity) * 24)) : 0;
    severityRow.getCell(4).value = "█".repeat(bars);
    severityRow.getCell(4).font = { color: { argb: SEVERITY_ARGB[severity] ?? "FF64748B" } };
  }

  row += 1;

  // --- Status / treatment snapshot. ---------------------------------------
  styleSectionRow(ws, row++, "Treatment State");
  for (const [state, count] of Object.entries(viewModel.kpis.treatment)) {
    const treatmentRow = ws.getRow(row++);
    treatmentRow.getCell(1).value = state;
    treatmentRow.getCell(2).value = count;
    treatmentRow.getCell(2).font = { bold: true };
  }

  row += 1;
  styleSectionRow(ws, row++, "Plain-Language Summary");
  for (const sentence of viewModel.summary) {
    ws.mergeCells(`A${row}:F${row}`);
    const sentenceRow = ws.getRow(row++);
    sentenceRow.getCell(1).value = sentence;
    sentenceRow.getCell(1).alignment = { wrapText: true, vertical: "top" };
    sentenceRow.height = 28;
  }
}

// ---------------------------------------------------------------------------
// Findings sheet
// ---------------------------------------------------------------------------

const COLUMN_DEFS: readonly TableColumn[] = [
  { header: "Host", width: 18 },
  { header: "Display ID", width: 26 },
  { header: "Machine ID", width: 22 },
  { header: "Check ID", width: 16 },
  { header: "Title", width: 46 },
  { header: "Severity", width: 14 },
  { header: "Status", width: 16 },
  { header: "Treatment", width: 16 },
  { header: "Evidence Depth", width: 20 },
  { header: "Category", width: 16 },
  { header: "References", width: 26 },
  { header: "Repro", width: 40 },
  { header: "Assignee", width: 16 },
  { header: "Due Date", width: 14 },
  { header: "Platform", width: 12 },
  { header: "OS", width: 16 },
  { header: "Arch", width: 10 },
  { header: "Location", width: 34 },
  { header: "Evidence", width: 50 },
  { header: "Fallback Log", width: 40 },
  { header: "Received At", width: 22 },
  { header: "Report ID", width: 10 },
  { header: "Risk Score", width: 12 },
  { header: "Coverage", width: 12 },
];

const SEVERITY_COLUMN = 6;

function findingValues(finding: ExportViewModel["findings"][number]): (string | number | null)[] {
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
    finding.fallbackLog.map((entry) => `${entry.source}=${entry.outcome}`).join("; "),
    finding.receivedAt,
    finding.reportId,
    finding.reportScore,
    finding.reportCoverage,
  ];
}

function buildFindingsSheet(ws: ExcelJS.Worksheet, viewModel: ExportViewModel): void {
  writeTable(
    ws,
    COLUMN_DEFS,
    viewModel.findings.map(findingValues),
  );
  for (let index = 0; index < viewModel.findings.length; index += 1) {
    const finding = viewModel.findings[index];
    const cell = ws.getCell(index + 2, SEVERITY_COLUMN);
    cell.fill = severityFill(SEVERITY_ARGB[finding.severity] ?? "FF64748B");
    cell.font = { bold: true, color: { argb: SEVERITY_TEXT_ARGB[finding.severity] ?? "FFFFFFFF" } };
  }
}

// ---------------------------------------------------------------------------
// By Host / By Check sheets
// ---------------------------------------------------------------------------

const HOST_COLUMNS: readonly TableColumn[] = [
  { header: "Host", width: 20 },
  { header: "Display ID", width: 26 },
  { header: "Machine ID", width: 22 },
  { header: "Platform", width: 12 },
  { header: "OS", width: 16 },
  { header: "Reports", width: 10 },
  { header: "Risk Score", width: 12 },
  { header: "Coverage (%)", width: 14 },
  { header: "Critical", width: 10 },
  { header: "High", width: 10 },
  { header: "Medium", width: 10 },
  { header: "Low", width: 10 },
  { header: "Informational", width: 14 },
  { header: "Total", width: 10 },
  { header: "Open", width: 10 },
  { header: "Remediated", width: 12 },
];

function buildByHostSheet(ws: ExcelJS.Worksheet, viewModel: ExportViewModel): void {
  const rows = viewModel.hosts.map((host) => [
    host.hostname,
    host.displayId,
    host.machineId,
    host.platform,
    host.os,
    host.reportCount,
    host.riskScore,
    host.coverage,
    host.severity.Critical ?? 0,
    host.severity.High ?? 0,
    host.severity.Medium ?? 0,
    host.severity.Low ?? 0,
    host.severity.Informational ?? 0,
    host.findings.length,
    host.treatment.open ?? 0,
    host.treatment.remediated ?? 0,
  ]);
  writeTable(ws, HOST_COLUMNS, rows);
}

const CHECK_COLUMNS: readonly TableColumn[] = [
  { header: "Check ID", width: 18 },
  { header: "Title", width: 46 },
  { header: "Severity", width: 14 },
  { header: "Category", width: 16 },
  { header: "Findings", width: 10 },
  { header: "Hosts", width: 10 },
  { header: "NonCompliant", width: 14 },
  { header: "Compliant", width: 12 },
  { header: "References", width: 30 },
];

const CHECK_SEVERITY_COLUMN = 3;

function buildByCheckSheet(ws: ExcelJS.Worksheet, viewModel: ExportViewModel): void {
  const rows = viewModel.checks.map((check) => [
    check.checkId,
    check.title,
    check.severity,
    check.category,
    check.findingCount,
    check.hostCount,
    check.status.NonCompliant ?? 0,
    check.status.Compliant ?? 0,
    check.references.join("; "),
  ]);
  writeTable(ws, CHECK_COLUMNS, rows);
  for (let index = 0; index < viewModel.checks.length; index += 1) {
    const check = viewModel.checks[index];
    const cell = ws.getCell(index + 2, CHECK_SEVERITY_COLUMN);
    cell.fill = severityFill(SEVERITY_ARGB[check.severity] ?? "FF64748B");
    cell.font = { bold: true, color: { argb: SEVERITY_TEXT_ARGB[check.severity] ?? "FFFFFFFF" } };
  }
}

/** Render the branded multi-sheet workbook. Pure: no I/O beyond returned bytes. */
export async function renderXlsx(viewModel: ExportViewModel): Promise<Buffer> {
  const workbook = new ExcelJS.Workbook();
  workbook.creator = viewModel.generator;
  workbook.title = viewModel.title;
  workbook.created = new Date(viewModel.generatedAt);
  workbook.modified = new Date(viewModel.generatedAt);

  buildCoverSheet(workbook.addWorksheet("Cover"), viewModel);
  buildExecutiveSheet(workbook.addWorksheet("Executive Summary"), viewModel);
  buildFindingsSheet(workbook.addWorksheet("Findings"), viewModel);
  buildByHostSheet(workbook.addWorksheet("By Host"), viewModel);
  buildByCheckSheet(workbook.addWorksheet("By Check"), viewModel);

  const buffer = await workbook.xlsx.writeBuffer();
  return Buffer.from(buffer as ArrayBuffer);
}

// ---------------------------------------------------------------------------
// Route hub
// ---------------------------------------------------------------------------

export type ExportAuth = { requireRole: (...roles: string[]) => MiddlewareHandler };
export type ExportRouteDeps = ReportOptions;

const READ_ROLES = ["super_admin", "auditor", "viewer"];

const CONTENT_TYPES: Record<ExportFormat, string> = {
  xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  csv: "text/csv; charset=utf-8",
  pdf: "application/pdf",
  docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
};

const EXTENSIONS: Record<ExportFormat, string> = {
  xlsx: "xlsx",
  csv: "csv",
  pdf: "pdf",
  docx: "docx",
};

function positiveInt(value: unknown): number | null {
  if (typeof value !== "string" || !/^[0-9]+$/.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
}

function parseFormat(raw: string | undefined): ExportFormat | null {
  if (raw === undefined || raw === "") return "xlsx";
  return (EXPORT_FORMATS as readonly string[]).includes(raw) ? (raw as ExportFormat) : null;
}

function resolveTemplate(raw: string | undefined, kind: "report" | "campaign"): ExportTemplate | null {
  if (raw === undefined || raw === "") return kind === "campaign" ? "executive" : "technical";
  return (EXPORT_TEMPLATES as readonly string[]).includes(raw) ? (raw as ExportTemplate) : null;
}

function slugify(value: string): string {
  const slug = value
    .normalize("NFKD")
    .replace(/[^A-Za-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .toLowerCase();
  return slug || "hbs-export";
}

async function renderFormat(
  db: Database,
  query: Parameters<typeof buildExportViewModel>[1],
  format: ExportFormat,
  template: ExportTemplate,
  deps: ExportRouteDeps,
): Promise<{ bytes: Buffer; viewModel: ExportViewModel }> {
  const viewModel = buildExportViewModel(db, query, deps);
  switch (format) {
    case "xlsx":
      return { bytes: await renderXlsx(viewModel), viewModel };
    case "csv":
      return { bytes: Buffer.from(renderCsv(viewModel), "utf8"), viewModel };
    case "pdf":
      return { bytes: await renderPdf(viewModel, template), viewModel };
    case "docx":
      return { bytes: await renderDocx(viewModel), viewModel };
  }
}

export function registerExportRoutes(
  app: Hono<any>,
  db: Database,
  auth: ExportAuth,
  deps: ExportRouteDeps = {},
): void {
  // Super-admin only, registered before the parameterised alias below.
  registerDiagnosticExportRoutes(app, db, auth, deps);

  const scopedHandler = (kind: "report" | "campaign") => async (c: any) => {
    const id = positiveInt(c.req.param("id"));
    if (!id) return c.json({ error: "invalid id", code: "INVALID_ID" }, 400);

    const exists =
      kind === "report"
        ? db.query("SELECT 1 FROM reports WHERE id = ?").get(id)
        : db.query("SELECT 1 FROM campaigns WHERE id = ?").get(id);
    if (!exists) return c.json({ error: `${kind} not found`, code: "NOT_FOUND" }, 404);

    const parsed = parseQuery(new URL(c.req.url).search);
    if (!parsed.ok) return c.json({ error: parsed.message, code: parsed.code }, 400);

    const format = parseFormat(c.req.query("format"));
    if (!format) {
      return c.json({ error: "format must be one of xlsx, csv, pdf, docx", code: "INVALID_FORMAT" }, 400);
    }
    const template = resolveTemplate(c.req.query("template"), kind);
    if (!template) {
      return c.json({ error: "template must be one of executive, technical", code: "INVALID_TEMPLATE" }, 400);
    }

    const query = kind === "report" ? scopeToReport(parsed.query, id) : scopeToCampaign(db, parsed.query, id);
    const { bytes, viewModel } = await renderFormat(db, query, format, template, deps);
    const filename = `${slugify(viewModel.title)}-${kind}-${id}.${EXTENSIONS[format]}`;
    return c.body(new Uint8Array(bytes), 200, {
      "content-type": CONTENT_TYPES[format],
      "content-disposition": `attachment; filename="${filename}"`,
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    });
  };

  app.get("/api/export/report/:id", auth.requireRole(...READ_ROLES), scopedHandler("report"));
  app.get("/api/export/campaign/:id", auth.requireRole(...READ_ROLES), scopedHandler("campaign"));
  // Plan §Task 57 shorthand: `/api/export/:reportId?format=` scopes to a report.
  app.get("/api/export/:id", auth.requireRole(...READ_ROLES), scopedHandler("report"));
}
