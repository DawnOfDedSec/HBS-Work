// Excel workbook export + the shared export route hub (Task 57, spec §6.6).
//
// `renderXlsx` is a pure serializer over the normalized export view model:
//   * "Executive Summary" sheet — KPI cards, severity breakdown, treatment
//     state, and the plain-language summary sentences.
//   * "Findings" sheet — one row per finding with severity colour coding,
//     a frozen header row, and an autofilter.
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
  EXPORT_FORMATS,
  EXPORT_TEMPLATES,
  scopeToCampaign,
  scopeToReport,
  SEVERITY_ARGB,
  SEVERITY_ORDER,
  SEVERITY_TEXT_ARGB,
  type ExportFormat,
  type ExportScope,
  type ExportTemplate,
  type ExportViewModel,
} from "./viewmodel";
import type { ReportOptions } from "../reports";

// ---------------------------------------------------------------------------
// Findings sheet layout
// ---------------------------------------------------------------------------

type ColumnDef = { header: string; width: number };

const COLUMN_DEFS: readonly ColumnDef[] = [
  { header: "Host", width: 18 },
  { header: "Display ID", width: 26 },
  { header: "Machine ID", width: 22 },
  { header: "Check ID", width: 16 },
  { header: "Title", width: 46 },
  { header: "Severity", width: 14 },
  { header: "Status", width: 16 },
  { header: "Category", width: 16 },
  { header: "Treatment", width: 16 },
  { header: "Assignee", width: 16 },
  { header: "Due Date", width: 14 },
  { header: "Platform", width: 12 },
  { header: "OS", width: 16 },
  { header: "Arch", width: 10 },
  { header: "Evidence Depth", width: 20 },
  { header: "Location", width: 34 },
  { header: "References", width: 26 },
  { header: "Repro", width: 40 },
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
    finding.fallbackLog.map((entry) => `${entry.source}=${entry.outcome}`).join("; "),
    finding.receivedAt,
    finding.reportId,
    finding.reportScore,
    finding.reportCoverage,
  ];
}

function scopeText(scope: ExportScope): string {
  const parts = [`scope=${scope.kind}`];
  if (scope.campaignName) parts.push(`campaign=${scope.campaignName}`);
  else if (scope.campaignId) parts.push(`campaign=#${scope.campaignId}`);
  if (scope.reportId) parts.push(`report=#${scope.reportId}`);
  if (scope.from) parts.push(`from=${scope.from}`);
  if (scope.to) parts.push(`to=${scope.to}`);
  return parts.join(", ");
}

function styleTitleRow(ws: ExcelJS.Worksheet, rowNumber: number, text: string, size: number): void {
  const row = ws.getRow(rowNumber);
  row.getCell(1).value = text;
  row.getCell(1).font = { bold: true, size };
}

function styleSectionRow(ws: ExcelJS.Worksheet, rowNumber: number, text: string): void {
  const row = ws.getRow(rowNumber);
  row.getCell(1).value = text;
  row.getCell(1).font = { bold: true, size: 12, color: { argb: "FF1F2937" } };
}

function severityFill(argb: string): ExcelJS.Fill {
  return { type: "pattern", pattern: "solid", fgColor: { argb } };
}

function buildExecutiveSheet(ws: ExcelJS.Worksheet, viewModel: ExportViewModel): void {
  ws.getColumn(1).width = 34;
  ws.getColumn(2).width = 16;
  ws.getColumn(3).width = 16;
  ws.getColumn(4).width = 16;

  let row = 1;
  styleTitleRow(ws, row++, viewModel.title, 16);
  ws.getRow(row).getCell(1).value = `Generated ${viewModel.generatedAt}`;
  row += 1;
  ws.getRow(row).getCell(1).value = scopeText(viewModel.scope);
  row += 2;

  styleSectionRow(ws, row++, "Key Performance Indicators");
  const kpis: [string, string | number][] = [
    ["Weighted Risk Score (0-100)", viewModel.kpis.riskScore],
    ["Evidence Coverage (%)", viewModel.kpis.coverage],
    ["Total Findings", viewModel.kpis.totalFindings],
    ["Failing / Degraded Findings", viewModel.kpis.failingFindings],
    ["Open Findings", viewModel.kpis.openFindings],
    ["Open Critical Findings", viewModel.kpis.openCriticals],
    ["Hosts", viewModel.kpis.hostCount],
    ["Scan Reports", viewModel.kpis.totalReports],
    ["Standard References", viewModel.kpis.referenceCount],
  ];
  for (const [label, value] of kpis) {
    const kpiRow = ws.getRow(row++);
    kpiRow.getCell(1).value = label;
    kpiRow.getCell(2).value = value;
    kpiRow.getCell(2).font = { bold: true };
  }
  row += 1;

  styleSectionRow(ws, row++, "Severity Breakdown");
  const severityHeader = ws.getRow(row++);
  severityHeader.getCell(1).value = "Severity";
  severityHeader.getCell(2).value = "Total";
  severityHeader.getCell(3).value = "Failing";
  severityHeader.font = { bold: true };
  for (const severity of SEVERITY_ORDER) {
    const severityRow = ws.getRow(row++);
    severityRow.getCell(1).value = severity;
    severityRow.getCell(1).fill = severityFill(SEVERITY_ARGB[severity] ?? "FF7F7F7F");
    severityRow.getCell(1).font = { bold: true, color: { argb: SEVERITY_TEXT_ARGB[severity] ?? "FFFFFFFF" } };
    severityRow.getCell(2).value = viewModel.kpis.severity[severity] ?? 0;
    severityRow.getCell(3).value = viewModel.kpis.failingSeverity[severity] ?? 0;
  }
  row += 1;

  styleSectionRow(ws, row++, "Treatment State");
  for (const [state, count] of Object.entries(viewModel.kpis.treatment)) {
    const treatmentRow = ws.getRow(row++);
    treatmentRow.getCell(1).value = state;
    treatmentRow.getCell(2).value = count;
  }
  row += 1;

  styleSectionRow(ws, row++, "Executive Summary");
  for (const sentence of viewModel.summary) {
    const sentenceRow = ws.getRow(row++);
    sentenceRow.getCell(1).value = sentence;
    sentenceRow.getCell(1).alignment = { wrapText: true, vertical: "top" };
  }
}

function buildFindingsSheet(ws: ExcelJS.Worksheet, viewModel: ExportViewModel): void {
  ws.columns = COLUMN_DEFS.map((column) => ({
    header: column.header,
    key: column.header,
    width: column.width,
  }));
  for (const finding of viewModel.findings) ws.addRow(findingValues(finding));

  const header = ws.getRow(1);
  header.font = { bold: true, color: { argb: "FFFFFFFF" } };
  header.fill = severityFill("FF1F2937");
  header.alignment = { vertical: "middle" };

  ws.views = [{ state: "frozen", ySplit: 1 }];
  ws.autoFilter = {
    from: { row: 1, column: 1 },
    to: { row: 1, column: COLUMN_DEFS.length },
  };

  for (let index = 0; index < viewModel.findings.length; index += 1) {
    const finding = viewModel.findings[index];
    const cell = ws.getCell(index + 2, SEVERITY_COLUMN);
    cell.fill = severityFill(SEVERITY_ARGB[finding.severity] ?? "FF7F7F7F");
    cell.font = { bold: true, color: { argb: SEVERITY_TEXT_ARGB[finding.severity] ?? "FFFFFFFF" } };
  }
}

/** Render the two-sheet workbook. Pure: no I/O beyond the returned bytes. */
export async function renderXlsx(viewModel: ExportViewModel): Promise<Buffer> {
  const workbook = new ExcelJS.Workbook();
  workbook.creator = "HBS Dashboard";
  workbook.created = new Date(viewModel.generatedAt);
  workbook.modified = new Date(viewModel.generatedAt);

  buildExecutiveSheet(workbook.addWorksheet("Executive Summary"), viewModel);
  buildFindingsSheet(workbook.addWorksheet("Findings"), viewModel);

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
