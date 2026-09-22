// Super-admin diagnostic download (Task 57, spec §6.6).
//
// Reuses `reports.ts` `buildDiagnosticBundle` — IDs, counts, timings, enum
// values, and redacted rejection reasons only. It NEVER contains `report_json`,
// `envelope`, evidence blocks, evidence strings, justifications, or secrets.
// On top of the shared builder we run a recursive sanitizer that strips any
// evidence/report payload key and re-redacts every string, so even a future
// change to the builder cannot leak a secret through this export.

import type { Database } from "bun:sqlite";
import { Hono, type MiddlewareHandler } from "hono";
import { parseQuery } from "../query";
import { buildDiagnosticBundle, redactDiagnosticText, type ReportOptions } from "../reports";
import { toCsv, UTF8_BOM } from "./csv";

export type DiagnosticExport = ReturnType<typeof buildDiagnosticBundle>;

const FORBIDDEN_KEYS = new Set([
  "evidence",
  "evidenceblocks",
  "evidence_blocks",
  "report_json",
  "reportjson",
  "envelope",
  "justification",
  "raw",
  "body",
]);

const SECRET_KEY = /(secret|token|password|passwd|api_?key|private_?key|credential)/i;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function sanitize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map((entry) => sanitize(entry));
  if (isRecord(value)) {
    const out: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value)) {
      if (FORBIDDEN_KEYS.has(key.toLowerCase()) || SECRET_KEY.test(key)) {
        out[key] = "[redacted]";
        continue;
      }
      out[key] = sanitize(entry);
    }
    return out;
  }
  if (typeof value === "string") return redactDiagnosticText(value, 512);
  return value;
}

/** Build the redacted, sanitized diagnostic bundle for export. */
export function buildDiagnosticExport(
  db: Database,
  query: Parameters<typeof buildDiagnosticBundle>[1],
  options: ReportOptions = {},
): DiagnosticExport {
  const bundle = buildDiagnosticBundle(db, query, options);
  return sanitize(bundle) as DiagnosticExport;
}

/** Pretty JSON serialization (default diagnostic format). */
export function renderDiagnosticJson(bundle: DiagnosticExport): string {
  return JSON.stringify(bundle, null, 2);
}

function flatten(value: unknown, prefix: string, rows: (string | number | null)[][]): void {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => flatten(entry, `${prefix}[${index}]`, rows));
    return;
  }
  if (isRecord(value)) {
    for (const [key, entry] of Object.entries(value)) {
      flatten(entry, prefix ? `${prefix}.${key}` : key, rows);
    }
    return;
  }
  rows.push([prefix, value === null || value === undefined ? "" : String(value)]);
}

/** Flat two-column CSV (`path,value`) of the whole sanitized bundle. */
export function renderDiagnosticCsv(bundle: DiagnosticExport): string {
  const rows: (string | number | null)[][] = [["path", "value"]];
  flatten(bundle, "", rows);
  return UTF8_BOM + toCsv(rows) + "\r\n";
}

export type DiagnosticExportAuth = { requireRole: (...roles: string[]) => MiddlewareHandler };

/**
 * Mount `GET /api/export/diagnostic?format=json|csv` (super-admin only).
 * `registerExportRoutes` calls this; it can also be mounted standalone.
 */
export function registerDiagnosticExportRoutes(
  app: Hono<any>,
  db: Database,
  auth: DiagnosticExportAuth,
  deps: ReportOptions = {},
): void {
  app.get("/api/export/diagnostic", auth.requireRole("super_admin"), (c) => {
    const parsed = parseQuery(new URL(c.req.url).search);
    if (!parsed.ok) return c.json({ error: parsed.message, code: parsed.code }, 400);

    const format = c.req.query("format") ?? "json";
    if (format !== "json" && format !== "csv") {
      return c.json({ error: "format must be json or csv", code: "INVALID_FORMAT" }, 400);
    }

    const bundle = buildDiagnosticExport(db, parsed.query, deps);
    const body =
      format === "csv"
        ? { bytes: Buffer.from(renderDiagnosticCsv(bundle), "utf8"), type: "text/csv; charset=utf-8", ext: "csv" }
        : { bytes: Buffer.from(renderDiagnosticJson(bundle), "utf8"), type: "application/json; charset=utf-8", ext: "json" };

    return c.body(new Uint8Array(body.bytes), 200, {
      "content-type": body.type,
      "content-disposition": `attachment; filename="hbs-diagnostic.${body.ext}"`,
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    });
  });
}
