// Network review exports: one workbook per report or device (xlsx/csv).
// Self-contained by design — the host export pipeline models sealed host
// reports, while network findings live in network_reports JSON documents.

import type { Database } from "bun:sqlite";
import ExcelJS from "exceljs";
import type { Context, Hono, MiddlewareHandler } from "hono";
import type { NetworkFinding } from "./review";

const READ_ROLES = ["super_admin", "auditor", "viewer"];
const EXPORT_FORMATS = ["xlsx", "csv"] as const;
type ExportFormat = (typeof EXPORT_FORMATS)[number];

const CONTENT_TYPES: Record<ExportFormat, string> = {
  xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  csv: "text/csv; charset=utf-8",
};

const EXTENSIONS: Record<ExportFormat, string> = { xlsx: "xlsx", csv: "csv" };

type ExportAuth = { requireRole: (...roles: string[]) => MiddlewareHandler };

function positiveInt(value: unknown): number | null {
  const parsed = typeof value === "number" ? value : Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
}

function parseFormat(raw: string | undefined): ExportFormat | null {
  if (raw === undefined || raw === "") return "xlsx";
  return (EXPORT_FORMATS as readonly string[]).includes(raw) ? (raw as ExportFormat) : null;
}

function slugify(value: string): string {
  const slug = value
    .normalize("NFKD")
    .replace(/[^A-Za-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .toLowerCase();
  return slug || "network-export";
}

function csvCell(value: string | number | null): string {
  const text = value === null ? "" : String(value);
  if (/[",\r\n]/.test(text)) return `"${text.replace(/"/g, '""')}"`;
  return text;
}

function csvRows(header: string[], rows: Array<Array<string | number | null>>): string {
  const lines = [header, ...rows].map((row) => row.map(csvCell).join(","));
  return `\uFEFF${lines.join("\r\n")}\r\n`;
}

type DeviceMeta = {
  id: number;
  hostname: string | null;
  vendor: string;
  device_type: string | null;
  model: string | null;
  os_version: string | null;
  serial: string | null;
};

function loadDevice(db: Database, deviceId: number): DeviceMeta | null {
  return (db.query("SELECT * FROM network_devices WHERE id = ?").get(deviceId) as DeviceMeta | null) ?? null;
}

type ReportRow = {
  id: number;
  device_id: number;
  location_id: number;
  config_name: string;
  config_sha256: string;
  score: number | null;
  received_at: string;
  uploaded_by: string | null;
  findings_json: string;
  states_json?: never;
};

function loadFindings(db: Database, reportId: number): NetworkFinding[] {
  const row = db.query("SELECT findings_json FROM network_reports WHERE id = ?").get(reportId) as {
    findings_json: string;
  } | null;
  if (!row) return [];
  try {
    return JSON.parse(row.findings_json) as NetworkFinding[];
  } catch {
    return [];
  }
}

function treatmentMapFor(db: Database, reportId: number): Map<string, string> {
  const rows = db
    .query("SELECT check_id, state FROM network_finding_states WHERE report_id = ?")
    .all(reportId) as Array<{ check_id: string; state: string }>;
  return new Map(rows.map((row) => [row.check_id, row.state]));
}

const HEADER = ["Check", "Title", "Severity", "Status", "Category", "Treatment", "References", "Recommendation", "Evidence (redacted)"];

function findingRow(finding: NetworkFinding, treatment: string): Array<string | number | null> {
  return [
    finding.checkId,
    finding.title,
    finding.severity,
    finding.status,
    finding.category,
    treatment,
    finding.references.join("; "),
    finding.recommendation,
    finding.evidence.join("\n"),
  ];
}

async function renderWorkbook(
  title: string,
  meta: string[],
  groups: Array<{ sheetName: string; caption: string; rows: Array<Array<string | number | null>> }>,
): Promise<Buffer> {
  const workbook = new ExcelJS.Workbook();
  workbook.creator = "HBS Console";
  workbook.created = new Date();

  const cover = workbook.addWorksheet("Overview");
  cover.columns = [{ width: 28 }, { width: 90 }];
  const titleCell = cover.getCell("A1", title);
  titleCell.font = { bold: true, size: 14 };
  cover.mergeCells("A1:B1");
  meta.forEach((entry, index) => {
    cover.getCell(`A${index + 3}`, entry.split(":")[0]).font = { bold: true };
    cover.getCell(`B${index + 3}`, entry.slice(entry.indexOf(":") + 1).trim());
  });

  for (const group of groups) {
    const sheet = workbook.addWorksheet(group.sheetName);
    sheet.addRow(HEADER);
    sheet.getRow(1).font = { bold: true };
    sheet.columns = [
      { width: 16 },
      { width: 44 },
      { width: 12 },
      { width: 14 },
      { width: 16 },
      { width: 16 },
      { width: 34 },
      { width: 60 },
      { width: 60 },
    ];
    for (const row of group.rows) sheet.addRow(row);
    sheet.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: HEADER.length } };
    void group.caption;
  }

  const buffer = await workbook.xlsx.writeBuffer();
  return Buffer.from(buffer);
}

function send(c: Context, bytes: Buffer, format: ExportFormat, filename: string) {
  return c.body(new Uint8Array(bytes), 200, {
    "content-type": CONTENT_TYPES[format],
    "content-disposition": `attachment; filename="${filename}"`,
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
}

function metaLines(device: DeviceMeta, extra: string[]): string[] {
  return [
    `Hostname: ${device.hostname ?? "(unnamed)"}`,
    `Vendor: ${device.vendor}`,
    `Type: ${device.device_type ?? "unknown"}`,
    `Model: ${device.model ?? "—"}`,
    `OS version: ${device.os_version ?? "—"}`,
    `Serial: ${device.serial ?? "—"}`,
    ...extra,
  ];
}

export function registerNetworkExportRoutes(app: Hono<any>, db: Database, auth: ExportAuth): void {
  // Single report export.
  app.get("/api/network/reports/:id/export", auth.requireRole(...READ_ROLES), async (c) => {
    const reportId = positiveInt(c.req.param("id"));
    if (!reportId) return c.json({ error: "invalid report id", code: "INVALID_ID" }, 400);
    const format = parseFormat(c.req.query("format"));
    if (!format) return c.json({ error: "format must be one of xlsx, csv", code: "INVALID_FORMAT" }, 400);

    const report = db
      .query(
        `SELECT r.id, r.device_id, r.location_id, r.config_name, r.config_sha256, r.score, r.received_at, r.uploaded_by,
                d.hostname, d.vendor, d.device_type, d.model, d.os_version, d.serial
           FROM network_reports r
           JOIN network_devices d ON d.id = r.device_id
          WHERE r.id = ?`,
      )
      .get(reportId) as (ReportRow & DeviceMeta) | null;
    if (!report) return c.json({ error: "report not found", code: "NOT_FOUND" }, 404);

    const device: DeviceMeta = {
      id: report.device_id,
      hostname: report.hostname,
      vendor: report.vendor,
      device_type: report.device_type,
      model: report.model,
      os_version: report.os_version,
      serial: report.serial,
    };
    const treatment = treatmentMapFor(db, reportId);
    const findings = loadFindings(db, reportId).sort(
      (a, b) => (a.status === "NonCompliant" ? 0 : 1) - (b.status === "NonCompliant" ? 0 : 1),
    );
    const rows = findings.map((finding) => findingRow(finding, treatment.get(finding.checkId) ?? "open"));

    if (format === "csv") {
      const csv = csvRows(HEADER, rows);
      return send(c, Buffer.from(csv, "utf8"), format, `${slugify(device.hostname ?? "device")}-report-${reportId}.csv`);
    }
    const bytes = await renderWorkbook(
      "Network configuration review",
      metaLines(device, [
        `Report: #${reportId} (${report.config_name})`,
        `Score: ${report.score === null ? "—" : report.score.toFixed(1)}`,
        `Received: ${report.received_at}`,
        `Uploaded by: ${report.uploaded_by ?? "—"}`,
        `Config sha256: ${report.config_sha256}`,
      ]),
      [{ sheetName: "Findings", caption: "Review findings", rows }],
    );
    return send(c, bytes, format, `${slugify(device.hostname ?? "device")}-report-${reportId}.xlsx`);
  });

  // Whole-device export: latest report per sheet is not needed — one findings
  // sheet containing every report's rows with a Report column.
  app.get("/api/network/devices/:id/export", auth.requireRole(...READ_ROLES), async (c) => {
    const deviceId = positiveInt(c.req.param("id"));
    if (!deviceId) return c.json({ error: "invalid device id", code: "INVALID_ID" }, 400);
    const format = parseFormat(c.req.query("format"));
    if (!format) return c.json({ error: "format must be one of xlsx, csv", code: "INVALID_FORMAT" }, 400);
    const device = loadDevice(db, deviceId);
    if (!device) return c.json({ error: "device not found", code: "NOT_FOUND" }, 404);

    const reports = db
      .query(
        `SELECT id, device_id, location_id, config_name, config_sha256, score, received_at, uploaded_by
           FROM network_reports
          WHERE device_id = ?
          ORDER BY received_at DESC, id DESC`,
      )
      .all(deviceId) as ReportRow[];

    const header = ["Report", "Received", ...HEADER];
    const rows: Array<Array<string | number | null>> = [];
    for (const report of reports) {
      const treatment = treatmentMapFor(db, report.id);
      const prefix: Array<string | number | null> = [`#${report.id}`, report.received_at];
      for (const finding of loadFindings(db, report.id)) {
        rows.push([...prefix, ...findingRow(finding, treatment.get(finding.checkId) ?? "open")]);
      }
    }

    if (format === "csv") {
      const csv = csvRows(header, rows);
      return send(c, Buffer.from(csv, "utf8"), format, `${slugify(device.hostname ?? "device")}-${deviceId}.csv`);
    }
    const bytes = await renderWorkbook(
      "Network review history",
      metaLines(device, [`Reports: ${reports.length}`, `Exported: ${new Date().toISOString()}`]),
      [{ sheetName: "Findings", caption: "All findings across reports", rows }],
    );
    return send(c, bytes, format, `${slugify(device.hostname ?? "device")}-${deviceId}.xlsx`);
  });
}
