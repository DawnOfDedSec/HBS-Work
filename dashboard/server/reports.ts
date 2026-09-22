// Scoped report / findings / summary / pivot / telemetry API (Task 49).
//
// Every endpoint here funnels through `query.ts` so the scope selector (latest
// campaign state, one report, or an inclusive from/to range) and the canonical
// filters are applied identically. Metrics are always recomputed server-side
// from the stored report JSON; nothing trusts client-supplied aggregates.
//
// Treatment lives in `finding_states` (current projection) plus the
// append-only `finding_state_history`. Changing treatment recomputes and
// persists the affected report and campaign score/coverage per SDD ruling 6:
// `accepted_risk`/`false_positive` remove failed weight from the numerator but
// keep applicable weight in the denominator.

import type { Database } from "bun:sqlite";
import { Hono, type MiddlewareHandler } from "hono";
import { computeCoverage, computeRiskScore, computeSummary, type TreatmentState } from "./metrics";
import {
  ALLOWED_TREATMENT,
  buildReportWhere,
  parseQuery,
  whereText,
  type NormalizedQuery,
  type QueryParseError,
  type SqlValue,
} from "./query";
import { registerSavedViewRoutes } from "./saved_views";
import { registerDiagnosticRoutes } from "./diagnostic";
import { percentile } from "./telemetry";

export type ReportAuth = {
  requireRole: (...roles: string[]) => MiddlewareHandler;
};

export type ReportRouteDeps = {
  /** Overrides the settings-backed freshness SLA (tests). */
  freshnessSlaHours?: number;
};

// ---------------------------------------------------------------------------
// Row types
// ---------------------------------------------------------------------------

type ReportRow = {
  id: number;
  issuance_id: string;
  host_id: number;
  location_id: number;
  campaign_id: number;
  extractor_id: string;
  scan_id: string;
  schema_fingerprint: string | null;
  catalog_fingerprint: string | null;
  report_json: string | null;
  score: number | null;
  coverage: number | null;
  summary_json: string | null;
  scan_timestamp: string | null;
  received_at: string;
  via: string | null;
  total_duration_ms: number | null;
  collect_duration_ms: number | null;
  bytes: number | null;
  peak_rss_bytes: number | null;
  privilege_level: string | null;
  evidence_depth: string | null;
  host_hostname: string | null;
  host_machine_id: string | null;
  host_platform: string | null;
  host_os: string | null;
  host_arch: string | null;
};

type TreatmentRow = {
  id: number;
  report_id: number;
  check_id: string;
  state: string;
  assignee: string | null;
  due_date: string | null;
  updated_at: string;
};

type HostRow = {
  id: number;
  machine_id: string;
  hostname: string | null;
  platform: string | null;
  os: string | null;
  arch: string | null;
  first_seen_at: string;
  last_seen_at: string;
};

type Finding = {
  reportId: number;
  campaignId: number;
  locationId: number;
  hostId: number;
  hostname: string;
  displayId: string;
  checkId: string;
  title: string;
  severity: string;
  status: string;
  category: string;
  references: string[];
  treatment: string;
  treatmentAssignee: string | null;
  treatmentDueDate: string | null;
  treatmentUpdatedAt: string | null;
  extractorVersion: string | null;
  platform: string | null;
  os: string | null;
  arch: string | null;
  via: string | null;
  evidenceDepth: string | null;
  receivedAt: string;
  scanTimestamp: string | null;
  reportScore: number | null;
  reportCoverage: number | null;
  links: Record<string, string>;
  result: Record<string, unknown>;
};

export type ReportDoc = {
  schemaVersion?: unknown;
  scan?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  results?: unknown;
  summary?: unknown;
  selfAudit?: { commands?: unknown; filesRead?: unknown };
  [key: string]: unknown;
};

type ScopeData = {
  query: NormalizedQuery;
  selectedReports: ReportRow[];
  allReports: ReportRow[];
  findings: Finding[];
};

type SqlExtra = { clauses?: readonly string[]; params?: readonly SqlValue[] };

type Actor = { id: number; username: string; role: string };

// ---------------------------------------------------------------------------
// Constants + small helpers
// ---------------------------------------------------------------------------

const READ_ROLES = ["super_admin", "auditor", "viewer"];
const WRITE_ROLES = ["super_admin", "auditor"];

const SEVERITY_RANK: Record<string, number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
  Informational: 4,
};

const STATUS_RANK: Record<string, number> = {
  NonCompliant: 0,
  DegradedPartial: 1,
  Error: 2,
  Compliant: 3,
  NotApplicable: 4,
};

const EXCLUDED_FROM_NUMERATOR = new Set(["accepted_risk", "false_positive"]);
const BROKEN_STATUSES = new Set(["NonCompliant", "DegradedPartial", "Error"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

function positiveInt(value: unknown): number | null {
  const parsed = typeof value === "number" ? value : Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
}

function nowIso(): string {
  return new Date().toISOString();
}

function actorOf(c: any): Actor {
  const user = c.get("user") as Actor | undefined;
  return user ?? { id: 0, username: "unknown", role: "viewer" };
}

function displayId(hostname: string, machineId: string | null): string {
  return `${hostname}:${(machineId ?? "unknown").slice(0, 8)}`;
}

function makeLinks(
  campaignId: number,
  locationId: number,
  hostId: number,
  reportId: number,
): Record<string, string> {
  return {
    campaign: `/api/campaigns/${campaignId}`,
    location: `/api/campaigns/${campaignId}/locations/${locationId}`,
    host: `/api/hosts/${hostId}`,
    report: `/api/reports/${reportId}`,
  };
}

export function parseReportDoc(reportJson: string | null): ReportDoc {
  if (!reportJson) return {};
  try {
    const parsed = JSON.parse(reportJson);
    return isRecord(parsed) ? (parsed as ReportDoc) : {};
  } catch {
    return {};
  }
}

function docResults(doc: ReportDoc): Record<string, unknown>[] {
  return Array.isArray(doc.results) ? doc.results.filter(isRecord) : [];
}

function resultReferences(result: Record<string, unknown>): string[] {
  const refs = result.references;
  return Array.isArray(refs) ? refs.filter((value): value is string => typeof value === "string") : [];
}

function stripAndTrim(value: string, maxLength: number): string | null {
  const cleaned = value.replace(/[\u0000-\u001f\u007f-\u009f]/g, " ").trim();
  return cleaned ? cleaned.slice(0, maxLength) : null;
}

function parseSummary(summaryJson: string | null): unknown {
  if (!summaryJson) return null;
  try {
    return JSON.parse(summaryJson);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Schema support tables
// ---------------------------------------------------------------------------

export function prepareReportTables(db: Database): void {
  db.run(`CREATE TABLE IF NOT EXISTS campaign_metrics (
    campaign_id INTEGER PRIMARY KEY REFERENCES campaigns(id),
    score REAL,
    coverage REAL,
    report_count INTEGER NOT NULL DEFAULT 0,
    host_count INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
  )`);
}

// ---------------------------------------------------------------------------
// Query parsing helper
// ---------------------------------------------------------------------------

export type ParsedOrError =
  | { ok: true; query: NormalizedQuery }
  | { ok: false; response: Response };

export function parseRequestQuery(
  c: any,
  options: { campaignId?: number | null } = {},
): ParsedOrError {
  const parsed = parseQuery(new URL(c.req.url).search, options);
  if (!parsed.ok) return { ok: false, response: errorResponse(c, parsed) };
  return { ok: true, query: parsed.query };
}

function errorResponse(c: any, parsed: QueryParseError): Response {
  return c.json({ error: parsed.message, code: parsed.code }, 400);
}

function describeScope(query: NormalizedQuery): Record<string, unknown> {
  return {
    kind: query.scope,
    campaignId: query.campaignId,
    reportId: query.filters.reportId[0] ?? null,
    from: query.filters.from,
    to: query.filters.to,
  };
}

// ---------------------------------------------------------------------------
// Scope + findings collection
// ---------------------------------------------------------------------------

function selectReportRows(db: Database, query: NormalizedQuery, extra?: SqlExtra): ReportRow[] {
  const filter = buildReportWhere(
    query,
    extra ? { extra: { clauses: extra.clauses ?? [], params: extra.params ?? [] } } : {},
  );
  const sql = `SELECT r.*, h.hostname AS host_hostname, h.machine_id AS host_machine_id,
      h.platform AS host_platform, h.os AS host_os, h.arch AS host_arch
    FROM reports r
    LEFT JOIN hosts h ON h.id = r.host_id
    ${whereText(filter)}
    ORDER BY r.received_at DESC, r.id DESC`;
  return db.query(sql).all(...filter.params) as ReportRow[];
}

function latestPerHost(rows: readonly ReportRow[]): ReportRow[] {
  const seen = new Set<number>();
  const out: ReportRow[] = [];
  for (const row of rows) {
    if (seen.has(row.host_id)) continue;
    seen.add(row.host_id);
    out.push(row);
  }
  return out;
}

function treatmentMap(db: Database, reportIds: readonly number[]): Map<string, TreatmentRow> {
  const map = new Map<string, TreatmentRow>();
  if (reportIds.length === 0) return map;
  const placeholders = reportIds.map(() => "?").join(", ");
  const rows = db
    .query(`SELECT * FROM finding_states WHERE report_id IN (${placeholders})`)
    .all(...reportIds) as TreatmentRow[];
  for (const row of rows) map.set(`${row.report_id}:${row.check_id}`, row);
  return map;
}

function matchesResult(
  result: Record<string, unknown>,
  query: NormalizedQuery,
  extractorVersion: string | null,
): boolean {
  const filters = query.filters;
  if (filters.severity.length > 0 && !filters.severity.includes(String(result.severity ?? ""))) return false;
  if (filters.status.length > 0 && !filters.status.includes(String(result.status ?? ""))) return false;
  if (filters.category.length > 0 && !filters.category.includes(String(result.category ?? ""))) return false;
  if (filters.checkId.length > 0 && !filters.checkId.includes(String(result.id ?? ""))) return false;
  if (filters.extractorVersion.length > 0 && !filters.extractorVersion.includes(extractorVersion ?? "")) return false;
  if (filters.standard.length > 0) {
    const refs = resultReferences(result);
    const matched = filters.standard.some((standard) =>
      refs.some(
        (ref) =>
          ref === standard || ref.startsWith(`${standard}.`) || ref.startsWith(`${standard}-`),
      ),
    );
    if (!matched) return false;
  }
  if (filters.q !== null) {
    const haystack = [
      result.id,
      result.title,
      result.description,
      result.category,
      result.impact,
      result.recommendation,
      ...resultReferences(result),
    ]
      .filter((value): value is string => typeof value === "string")
      .join("\n")
      .toLowerCase();
    if (!haystack.includes(filters.q.toLowerCase())) return false;
  }
  return true;
}

function collectScopeWithExtra(db: Database, query: NormalizedQuery, extra?: SqlExtra): ScopeData {
  const allReports = selectReportRows(db, query, extra);
  const selectedReports = query.scope === "latest" ? latestPerHost(allReports) : allReports;
  const treatments = treatmentMap(db, selectedReports.map((report) => report.id));
  const findings: Finding[] = [];

  for (const report of selectedReports) {
    const doc = parseReportDoc(report.report_json);
    const scan = isRecord(doc.scan) ? doc.scan : {};
    const extractorVersion = asString(scan.extractorVersion);
    const hostname = report.host_hostname ?? "";
    for (const result of docResults(doc)) {
      if (!matchesResult(result, query, extractorVersion)) continue;
      const checkId = String(result.id ?? "");
      if (!checkId) continue;
      const treatment = treatments.get(`${report.id}:${checkId}`);
      const state = treatment?.state ?? "open";
      if (query.filters.treatment.length > 0 && !query.filters.treatment.includes(state)) continue;
      findings.push({
        reportId: report.id,
        campaignId: report.campaign_id,
        locationId: report.location_id,
        hostId: report.host_id,
        hostname,
        displayId: displayId(hostname, report.host_machine_id),
        checkId,
        title: String(result.title ?? ""),
        severity: String(result.severity ?? ""),
        status: String(result.status ?? ""),
        category: String(result.category ?? ""),
        references: resultReferences(result),
        treatment: state,
        treatmentAssignee: treatment?.assignee ?? null,
        treatmentDueDate: treatment?.due_date ?? null,
        treatmentUpdatedAt: treatment?.updated_at ?? null,
        extractorVersion,
        platform: report.host_platform,
        os: report.host_os,
        arch: report.host_arch,
        via: report.via,
        evidenceDepth: report.evidence_depth,
        receivedAt: report.received_at,
        scanTimestamp: report.scan_timestamp,
        reportScore: report.score,
        reportCoverage: report.coverage,
        links: makeLinks(report.campaign_id, report.location_id, report.host_id, report.id),
        result,
      });
    }
  }

  findings.sort(compareFindings);
  return { query, selectedReports, allReports, findings };
}

export function collectScope(db: Database, query: NormalizedQuery): ScopeData {
  return collectScopeWithExtra(db, query);
}

function compareFindings(a: Finding, b: Finding): number {
  const severity = (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9);
  if (severity !== 0) return severity;
  const status = (STATUS_RANK[a.status] ?? 9) - (STATUS_RANK[b.status] ?? 9);
  if (status !== 0) return status;
  const host = a.hostname.localeCompare(b.hostname);
  if (host !== 0) return host;
  const check = a.checkId.localeCompare(b.checkId);
  if (check !== 0) return check;
  return a.reportId - b.reportId;
}

function findingResults(findings: readonly Finding[]) {
  return findings.map((finding) => ({
    id: `${finding.reportId}:${finding.checkId}`,
    status: finding.status,
    severity: finding.severity,
  }));
}

function riskFromFindings(findings: readonly Finding[]): number {
  const lookup = new Map(
    findings.map((finding) => [`${finding.reportId}:${finding.checkId}`, finding.treatment]),
  );
  return computeRiskScore(findingResults(findings), (id) => lookup.get(id) as TreatmentState | undefined);
}

function coverageFromFindings(findings: readonly Finding[]): number {
  return computeCoverage(findingResults(findings));
}

function severityBreakdown(findings: readonly Finding[]): Record<string, number> {
  const out: Record<string, number> = { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 };
  for (const finding of findings) {
    out[finding.severity] = (out[finding.severity] ?? 0) + 1;
  }
  return out;
}

function riskTrend(reports: readonly ReportRow[]) {
  const trendMap = new Map<string, { total: number; count: number }>();
  for (const report of reports) {
    const day = report.received_at.slice(0, 10);
    const bucket = trendMap.get(day) ?? { total: 0, count: 0 };
    bucket.total += report.score ?? 0;
    bucket.count += 1;
    trendMap.set(day, bucket);
  }
  return [...trendMap.entries()]
    .map(([date, bucket]) => ({
      date,
      score: bucket.count > 0 ? Math.round((bucket.total / bucket.count) * 100) / 100 : 0,
      reports: bucket.count,
    }))
    .sort((a, b) => a.date.localeCompare(b.date));
}

function tallyTreatments(findings: readonly Finding[]): Record<string, number> {
  const out: Record<string, number> = { open: 0, accepted_risk: 0, false_positive: 0, remediated: 0 };
  for (const finding of findings) out[finding.treatment] = (out[finding.treatment] ?? 0) + 1;
  return out;
}

// ---------------------------------------------------------------------------
// Score recomputation (SDD ruling 6)
// ---------------------------------------------------------------------------

function treatmentLookup(
  db: Database,
  reportId: number,
): (checkId: string) => TreatmentState | undefined {
  const map = new Map<string, string>();
  const rows = db
    .query("SELECT check_id, state FROM finding_states WHERE report_id = ?")
    .all(reportId) as { check_id: string; state: string }[];
  for (const row of rows) map.set(row.check_id, row.state);
  return (checkId: string) => map.get(checkId) as TreatmentState | undefined;
}

/** Recompute + persist one report's score/coverage from its raw results. */
export function recomputeReportMetrics(
  db: Database,
  reportId: number,
): { score: number; coverage: number } {
  const report = db
    .query("SELECT report_json FROM reports WHERE id = ?")
    .get(reportId) as { report_json: string | null } | null;
  if (!report) return { score: 100, coverage: 100 };
  const results = docResults(parseReportDoc(report.report_json));
  const score = computeRiskScore(results, treatmentLookup(db, reportId));
  const coverage = computeCoverage(results);
  db.query("UPDATE reports SET score = ?, coverage = ? WHERE id = ?").run(score, coverage, reportId);
  return { score, coverage };
}

/** Recompute + persist campaign score/coverage over the latest report per host. */
export function recomputeCampaignMetrics(
  db: Database,
  campaignId: number,
): { score: number; coverage: number; reportCount: number; hostCount: number } {
  prepareReportTables(db);
  const rows = db
    .query(
      `SELECT r.* FROM reports r WHERE r.campaign_id = ?
       ORDER BY r.received_at DESC, r.id DESC`,
    )
    .all(campaignId) as ReportRow[];
  const latest = latestPerHost(rows);
  const results: { id: string; status: unknown; severity: unknown }[] = [];
  const lookup = new Map<string, string>();
  for (const report of latest) {
    const treatments = treatmentMap(db, [report.id]);
    for (const result of docResults(parseReportDoc(report.report_json))) {
      const key = `${report.id}:${String(result.id ?? "")}`;
      results.push({ id: key, status: result.status, severity: result.severity });
      const state = treatments.get(key)?.state;
      if (state) lookup.set(key, state);
    }
  }
  const score = computeRiskScore(results, (id) => lookup.get(id) as TreatmentState | undefined);
  const coverage = computeCoverage(results);
  db.query(
    `INSERT INTO campaign_metrics (campaign_id, score, coverage, report_count, host_count, updated_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(campaign_id) DO UPDATE SET
       score = excluded.score,
       coverage = excluded.coverage,
       report_count = excluded.report_count,
       host_count = excluded.host_count,
       updated_at = excluded.updated_at`,
  ).run(campaignId, score, coverage, rows.length, latest.length, nowIso());
  return { score, coverage, reportCount: rows.length, hostCount: latest.length };
}

/**
 * Auto-resolve stale treatments: when a host's latest report no longer reports
 * the treated check as failing, move the projection to `remediated` and append
 * an explicit `system` history row. Idempotent.
 */
export function reconcileTreatment(
  db: Database,
  options: { campaignId?: number | null } = {},
): number {
  const campaignId = options.campaignId ?? null;
  const reports = db
    .query(
      `SELECT r.id, r.host_id, r.received_at FROM reports r
       ${campaignId ? "WHERE r.campaign_id = ?" : ""}
       ORDER BY r.received_at DESC, r.id DESC`,
    )
    .all(...(campaignId ? [campaignId] : [])) as {
    id: number;
    host_id: number;
    received_at: string;
  }[];
  const latestByHost = new Map<number, number>();
  for (const report of reports) {
    if (!latestByHost.has(report.host_id)) latestByHost.set(report.host_id, report.id);
  }

  const states = db
    .query(
      `SELECT fs.*, r.host_id FROM finding_states fs
       JOIN reports r ON r.id = fs.report_id
       ${campaignId ? "WHERE r.campaign_id = ?" : ""}
       ORDER BY fs.id`,
    )
    .all(...(campaignId ? [campaignId] : [])) as (TreatmentRow & { host_id: number })[];

  let resolved = 0;
  const affectedCampaigns = new Set<number>();
  for (const state of states) {
    if (state.state === "remediated") continue;
    const latestReportId = latestByHost.get(state.host_id);
    if (!latestReportId || latestReportId === state.report_id) continue;
    const latestDoc = db
      .query("SELECT report_json FROM reports WHERE id = ?")
      .get(latestReportId) as { report_json: string | null } | null;
    const latestResult = docResults(parseReportDoc(latestDoc?.report_json ?? null)).find(
      (result) => String(result.id ?? "") === state.check_id,
    );
    const status = latestResult ? String(latestResult.status) : undefined;
    if (status === "NonCompliant" || status === "DegradedPartial" || status === "Error") continue;

    const timestamp = nowIso();
    db.query("UPDATE finding_states SET state = 'remediated', updated_at = ? WHERE id = ?").run(
      timestamp,
      state.id,
    );
    db.query(
      `INSERT INTO finding_state_history
         (finding_state_id, actor, changed_at, from_state, to_state, justification, assignee, due_date)
       VALUES (?, 'system', ?, ?, 'remediated', ?, ?, ?)`,
    ).run(
      state.id,
      timestamp,
      state.state,
      "auto-resolved: fixed or absent in a later scan",
      state.assignee,
      state.due_date,
    );
    affectedCampaigns.add(
      (db.query("SELECT campaign_id FROM reports WHERE id = ?").get(state.report_id) as {
        campaign_id: number;
      }).campaign_id,
    );
    resolved += 1;
  }

  for (const id of affectedCampaigns) recomputeCampaignMetrics(db, id);
  return resolved;
}

// ---------------------------------------------------------------------------
// Telemetry
// ---------------------------------------------------------------------------

type IngestEventRow = {
  duration_ms: number | null;
  envelope_bytes: number | null;
  accepted: number;
  reason_code: string | null;
  via: string | null;
};

function durationStats(values: readonly number[]) {
  const sorted = [...values].sort((a, b) => a - b);
  const sum = sorted.reduce((acc, value) => acc + value, 0);
  return {
    count: sorted.length,
    min: sorted[0] ?? null,
    max: sorted[sorted.length - 1] ?? null,
    avg: sorted.length > 0 ? Math.round((sum / sorted.length) * 1000) / 1000 : null,
    p50: percentile(sorted, 50),
    p95: percentile(sorted, 95),
  };
}

function tally(values: readonly (string | null)[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const value of values) {
    const key = value ?? "unknown";
    out[key] = (out[key] ?? 0) + 1;
  }
  return out;
}

function freshnessSla(db: Database, override?: number): number {
  if (override !== undefined) return override;
  const row = db
    .query("SELECT value FROM settings WHERE key = 'freshness_sla_hours'")
    .get() as { value: string } | null;
  const parsed = row ? Number(row.value) : NaN;
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 24;
}

export type ReportOptions = { freshnessSlaHours?: number };

export function buildTelemetry(db: Database, scoped: ScopeData, options: ReportOptions = {}) {
  const { query, allReports, selectedReports, findings } = scoped;

  const durationValues = allReports
    .map((report) => report.total_duration_ms)
    .filter((value): value is number => typeof value === "number" && Number.isFinite(value));

  const reportIds = allReports.map((report) => report.id);
  let ingestRows: IngestEventRow[];
  if (query.scope === "range") {
    ingestRows = db
      .query(
        `SELECT duration_ms, envelope_bytes, accepted, reason_code, via FROM ingest_events
         WHERE received_at >= ? AND received_at <= ?`,
      )
      .all(query.filters.from ?? "0000", query.filters.to ?? "9999") as IngestEventRow[];
  } else if (reportIds.length > 0) {
    const placeholders = reportIds.map(() => "?").join(", ");
    ingestRows = db
      .query(
        `SELECT duration_ms, envelope_bytes, accepted, reason_code, via FROM ingest_events
         WHERE report_id IN (${placeholders})`,
      )
      .all(...reportIds) as IngestEventRow[];
  } else {
    ingestRows = [];
  }

  let commandCount = 0;
  let fileCount = 0;
  for (const report of allReports) {
    const doc = parseReportDoc(report.report_json);
    const audit = isRecord(doc.selfAudit) ? doc.selfAudit : {};
    if (Array.isArray(audit.commands)) commandCount += audit.commands.length;
    if (Array.isArray(audit.filesRead)) fileCount += audit.filesRead.length;
  }

  const summary = computeSummary(
    findings.map((finding) => ({ status: finding.status, severity: finding.severity })),
  );
  const seenHosts = new Set(selectedReports.map((report) => report.host_id));
  const latestReceivedAt =
    selectedReports
      .map((report) => report.received_at)
      .sort()
      .at(-1) ?? null;
  const slaHours = freshnessSla(db, options.freshnessSlaHours);
  const ageHours = latestReceivedAt
    ? Math.round(((Date.now() - Date.parse(latestReceivedAt)) / 3_600_000) * 100) / 100
    : null;
  const staleCutoff = new Date(Date.now() - slaHours * 3_600_000).toISOString();
  const staleHosts = selectedReports.filter((report) => report.received_at < staleCutoff).length;

  const acceptedEvents = ingestRows.filter((row) => row.accepted === 1);
  const rejectedEvents = ingestRows.filter((row) => row.accepted === 0);
  const reasons: Record<string, number> = {};
  for (const row of rejectedEvents) {
    const key = row.reason_code ?? "UNKNOWN";
    reasons[key] = (reasons[key] ?? 0) + 1;
  }

  const totalBytes = allReports.reduce((acc, report) => acc + (report.bytes ?? 0), 0);
  const rssValues = allReports
    .map((report) => report.peak_rss_bytes)
    .filter((value): value is number => typeof value === "number");

  return {
    scope: describeScope(query),
    reportCount: allReports.length,
    hostCount: seenHosts.size,
    scanDurationMs: durationStats(durationValues),
    ingestDurationMs: durationStats(
      ingestRows.map((row) => row.duration_ms).filter((value): value is number => typeof value === "number"),
    ),
    bytes: {
      total: totalBytes,
      avg: allReports.length > 0 ? Math.round((totalBytes / allReports.length) * 100) / 100 : 0,
      ingestTotal: ingestRows.reduce((acc, row) => acc + (row.envelope_bytes ?? 0), 0),
    },
    rssBytes: {
      avg: rssValues.length > 0 ? Math.round(rssValues.reduce((a, b) => a + b, 0) / rssValues.length) : null,
      max: rssValues.length > 0 ? Math.max(...rssValues) : null,
    },
    coverage: coverageFromFindings(findings),
    decided: summary.compliant + summary.nonCompliant,
    compliant: summary.compliant,
    nonCompliant: summary.nonCompliant,
    degraded: summary.degraded,
    error: summary.error,
    notApplicable: summary.notApplicable,
    informational: summary.informational,
    commands: commandCount,
    files: fileCount,
    privilege: tally(allReports.map((report) => report.privilege_level)),
    evidenceDepth: tally(allReports.map((report) => report.evidence_depth)),
    platform: tally(allReports.map((report) => report.host_platform)),
    arch: tally(allReports.map((report) => report.host_arch)),
    os: tally(allReports.map((report) => report.host_os)),
    location: tally(allReports.map((report) => String(report.location_id))),
    extractorVersion: tally(
      allReports.map((report) => asString(parseReportDoc(report.report_json).scan?.extractorVersion)),
    ),
    via: tally(allReports.map((report) => report.via)),
    freshness: {
      latestReceivedAt,
      ageHours,
      slaHours,
      stale: ageHours !== null && ageHours > slaHours,
      staleHosts,
    },
    ingest: {
      accepted: acceptedEvents.length,
      rejected: rejectedEvents.length,
      reasons,
    },
  };
}

// ---------------------------------------------------------------------------
// Standards / references coverage
// ---------------------------------------------------------------------------

export function buildStandards(findings: readonly Finding[]) {
  const references = new Map<string, { total: number; compliant: number; nonCompliant: number }>();
  const standards = new Map<string, { total: number; compliant: number; nonCompliant: number }>();
  for (const finding of findings) {
    const standardGroups = new Set<string>();
    for (const reference of finding.references) {
      const detail = references.get(reference) ?? { total: 0, compliant: 0, nonCompliant: 0 };
      detail.total += 1;
      if (finding.status === "Compliant") detail.compliant += 1;
      if (finding.status === "NonCompliant") detail.nonCompliant += 1;
      references.set(reference, detail);
      standardGroups.add(reference.split(/[.\-_]/)[0] || reference);
    }
    for (const standard of standardGroups) {
      const group = standards.get(standard) ?? { total: 0, compliant: 0, nonCompliant: 0 };
      group.total += 1;
      if (finding.status === "Compliant") group.compliant += 1;
      if (finding.status === "NonCompliant") group.nonCompliant += 1;
      standards.set(standard, group);
    }
  }
  return {
    standards: [...standards.entries()]
      .map(([standard, value]) => ({
        standard,
        ...value,
        decided: value.compliant + value.nonCompliant,
        coverage:
          value.total > 0
            ? Math.round(((value.compliant + value.nonCompliant) / value.total) * 10000) / 100
            : 0,
      }))
      .sort((a, b) => a.standard.localeCompare(b.standard)),
    references: [...references.entries()]
      .map(([reference, value]) => ({ reference, ...value }))
      .sort((a, b) => a.reference.localeCompare(b.reference)),
    total: findings.length,
  };
}

// ---------------------------------------------------------------------------
// Diagnostic bundle (redacted)
// ---------------------------------------------------------------------------

/**
 * Redact a string defensively: strip control chars and mask secret-looking
 * `key=value` pairs. Used on any string that leaves the diagnostic endpoint.
 */
export function redactDiagnosticText(value: string, maxLength = 200): string {
  const withoutControls = value.replace(/[\u0000-\u001f\u007f-\u009f]/g, " ");
  const masked = withoutControls.replace(
    /([A-Za-z0-9_]*(?:token|password|secret|apikey|api_key|private_key)[A-Za-z0-9_]*\s*[=:]\s*)\S+/gi,
    "$1[redacted]",
  );
  return masked.slice(0, maxLength);
}

export function buildDiagnosticBundle(
  db: Database,
  query: NormalizedQuery,
  options: ReportOptions = {},
) {
  const scoped = collectScope(db, query);
  const events = db
    .query(
      `SELECT received_at, via, envelope_bytes, duration_ms, accepted, reason_code, report_id, issuance_id
       FROM ingest_events ORDER BY id DESC LIMIT 500`,
    )
    .all() as {
    received_at: string;
    via: string | null;
    envelope_bytes: number | null;
    duration_ms: number | null;
    accepted: number;
    reason_code: string | null;
    report_id: number | null;
    issuance_id: string | null;
  }[];

  const selfAudit = scoped.allReports.slice(0, 500).map((report) => {
    const doc = parseReportDoc(report.report_json);
    const audit = isRecord(doc.selfAudit) ? doc.selfAudit : {};
    return {
      reportId: report.id,
      campaignId: report.campaign_id,
      hostId: report.host_id,
      commandCount: Array.isArray(audit.commands) ? audit.commands.length : 0,
      fileCount: Array.isArray(audit.filesRead) ? audit.filesRead.length : 0,
      peakRssBytes: report.peak_rss_bytes,
      durationMs: report.total_duration_ms,
      evidenceDepth: report.evidence_depth,
    };
  });

  const errorFindings = scoped.findings
    .filter((finding) => finding.status === "Error")
    .slice(0, 200)
    .map((finding) => ({
      reportId: finding.reportId,
      campaignId: finding.campaignId,
      hostId: finding.hostId,
      checkId: finding.checkId,
      severity: finding.severity,
      category: finding.category,
    }));

  const telemetry = buildTelemetry(db, scoped, options);
  const safeTelemetry = {
    ...telemetry,
    ingest: {
      ...telemetry.ingest,
      reasons: Object.fromEntries(
        Object.entries(telemetry.ingest.reasons).map(([reason, count]) => [
          redactDiagnosticText(reason, 64),
          count,
        ]),
      ),
    },
  };

  return {
    generatedAt: nowIso(),
    scope: describeScope(query),
    ingestEvents: events.map((event) => ({
      receivedAt: event.received_at,
      via: event.via,
      envelopeBytes: event.envelope_bytes,
      durationMs: event.duration_ms,
      accepted: event.accepted === 1,
      reasonCode: event.reason_code ? redactDiagnosticText(event.reason_code, 64) : null,
      reportId: event.report_id,
      issuanceId: event.issuance_id,
    })),
    selfAudit,
    telemetry: safeTelemetry,
    errors: {
      ingestRejections: events
        .filter((event) => event.accepted === 0)
        .map((event) => ({
          receivedAt: event.received_at,
          via: event.via,
          reasonCode: event.reason_code ? redactDiagnosticText(event.reason_code, 64) : null,
        })),
      reportErrors: errorFindings,
    },
  };
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

function serializeFinding(finding: Finding): Record<string, unknown> {
  return {
    reportId: finding.reportId,
    campaignId: finding.campaignId,
    locationId: finding.locationId,
    hostId: finding.hostId,
    hostname: finding.hostname,
    displayId: finding.displayId,
    checkId: finding.checkId,
    title: finding.title,
    severity: finding.severity,
    status: finding.status,
    category: finding.category,
    references: finding.references,
    treatment: finding.treatment,
    treatmentAssignee: finding.treatmentAssignee,
    treatmentDueDate: finding.treatmentDueDate,
    treatmentUpdatedAt: finding.treatmentUpdatedAt,
    extractorVersion: finding.extractorVersion,
    platform: finding.platform,
    os: finding.os,
    arch: finding.arch,
    via: finding.via,
    evidenceDepth: finding.evidenceDepth,
    receivedAt: finding.receivedAt,
    scanTimestamp: finding.scanTimestamp,
    reportScore: finding.reportScore,
    reportCoverage: finding.reportCoverage,
    links: finding.links,
  };
}

function serializeReportRow(report: ReportRow): Record<string, unknown> {
  const doc = parseReportDoc(report.report_json);
  const scan = isRecord(doc.scan) ? doc.scan : {};
  return {
    id: report.id,
    campaignId: report.campaign_id,
    locationId: report.location_id,
    hostId: report.host_id,
    hostname: report.host_hostname,
    scanId: report.scan_id,
    extractorId: report.extractor_id,
    extractorVersion: asString(scan.extractorVersion),
    scanTimestamp: report.scan_timestamp,
    receivedAt: report.received_at,
    via: report.via,
    score: report.score,
    coverage: report.coverage,
    summary: parseSummary(report.summary_json),
    privilegeLevel: report.privilege_level,
    evidenceDepth: report.evidence_depth,
    bytes: report.bytes,
    totalDurationMs: report.total_duration_ms,
    peakRssBytes: report.peak_rss_bytes,
    links: makeLinks(report.campaign_id, report.location_id, report.host_id, report.id),
  };
}

function getReportRow(db: Database, reportId: number): ReportRow | null {
  return db
    .query(
      `SELECT r.*, h.hostname AS host_hostname, h.machine_id AS host_machine_id,
              h.platform AS host_platform, h.os AS host_os, h.arch AS host_arch
       FROM reports r LEFT JOIN hosts h ON h.id = r.host_id WHERE r.id = ?`,
    )
    .get(reportId) as ReportRow | null;
}

function serializeHost(host: HostRow | null, scoped: ScopeData): Record<string, unknown> {
  if (!host) return {};
  const latest = scoped.selectedReports.find((report) => report.host_id === host.id);
  return {
    id: host.id,
    machineId: host.machine_id,
    hostname: host.hostname,
    displayId: displayId(host.hostname ?? "", host.machine_id),
    platform: host.platform,
    os: host.os,
    arch: host.arch,
    firstSeenAt: host.first_seen_at,
    lastSeenAt: host.last_seen_at,
    latestReportId: latest?.id ?? null,
    latestReceivedAt: latest?.received_at ?? null,
    riskScore: latest?.score ?? null,
    coverage: latest?.coverage ?? null,
  };
}

function groupByHost(scoped: ScopeData, db: Database) {
  const groups = new Map<number, Finding[]>();
  for (const finding of scoped.findings) {
    const bucket = groups.get(finding.hostId) ?? [];
    bucket.push(finding);
    groups.set(finding.hostId, bucket);
  }
  const reportsByHost = new Map<number, ReportRow[]>();
  for (const report of scoped.allReports) {
    const bucket = reportsByHost.get(report.host_id) ?? [];
    bucket.push(report);
    reportsByHost.set(report.host_id, bucket);
  }
  return [...groups.entries()]
    .map(([hostId, findings]) => {
      const host = db.query("SELECT * FROM hosts WHERE id = ?").get(hostId) as HostRow | null;
      const reports = reportsByHost.get(hostId) ?? [];
      const base = serializeHost(host, scoped);
      return {
        ...base,
        id: hostId,
        hostname: host?.hostname ?? null,
        reportCount: reports.length,
        latestReportId: reports[0]?.id ?? null,
        latestReceivedAt: reports[0]?.received_at ?? null,
        severity: severityBreakdown(findings),
        treatment: tallyTreatments(findings),
        links: { host: `/api/hosts/${hostId}` },
      };
    })
    .sort(
      (a, b) =>
        String(a.hostname ?? "").localeCompare(String(b.hostname ?? "")) ||
        Number(a.id) - Number(b.id),
    );
}

function withCheckId(query: NormalizedQuery, checkId: string): NormalizedQuery {
  return Object.freeze({
    ...query,
    filters: Object.freeze({ ...query.filters, checkId: Object.freeze([checkId]) }),
  });
}

function buildDiff(base: ReportRow, target: ReportRow) {
  const baseResults = new Map(
    docResults(parseReportDoc(base.report_json)).map((result) => [String(result.id ?? ""), result]),
  );
  const targetResults = new Map(
    docResults(parseReportDoc(target.report_json)).map((result) => [String(result.id ?? ""), result]),
  );
  const fixed: Record<string, unknown>[] = [];
  const regressed: Record<string, unknown>[] = [];
  const unchanged: Record<string, unknown>[] = [];
  const added: Record<string, unknown>[] = [];
  const removed: Record<string, unknown>[] = [];

  const allIds = new Set([...baseResults.keys(), ...targetResults.keys()]);
  for (const checkId of [...allIds].sort()) {
    const before = baseResults.get(checkId);
    const after = targetResults.get(checkId);
    const meta = (result: Record<string, unknown> | undefined) => ({
      checkId,
      title: String(result?.title ?? ""),
      severity: String(result?.severity ?? ""),
      category: String(result?.category ?? ""),
    });
    if (before && !after) {
      removed.push({ ...meta(before), from: String(before.status), to: null });
      continue;
    }
    if (!before && after) {
      added.push({ ...meta(after), from: null, to: String(after.status) });
      continue;
    }
    if (!before || !after) continue;
    const from = String(before.status);
    const to = String(after.status);
    const record = { ...meta(after), from, to };
    if (BROKEN_STATUSES.has(from) && to === "Compliant") fixed.push(record);
    else if (from === "Compliant" && BROKEN_STATUSES.has(to)) regressed.push(record);
    else unchanged.push(record);
  }

  return {
    hostId: base.host_id,
    baseReportId: base.id,
    targetReportId: target.id,
    summary: {
      fixed: fixed.length,
      regressed: regressed.length,
      unchanged: unchanged.length,
      added: added.length,
      removed: removed.length,
    },
    fixed,
    regressed,
    unchanged,
    added,
    removed,
  };
}

// `percentile` re-exported so callers/tests can compute p50/p95 directly.
export { percentile };

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

export function registerReportRoutes(
  app: Hono<any>,
  db: Database,
  auth: ReportAuth,
  deps: ReportRouteDeps = {},
): void {
  prepareReportTables(db);
  registerSavedViewRoutes(app, db, auth);
  registerDiagnosticRoutes(app, db, auth, {
    buildBundle: (database, query) => buildDiagnosticBundle(database, query, deps),
  });

  // ---- global overview -----------------------------------------------------
  app.get("/api/overview", auth.requireRole(...READ_ROLES), (c) => {
    const parsed = parseRequestQuery(c);
    if (!parsed.ok) return parsed.response;
    const scoped = collectScope(db, parsed.query);
    const campaignFilter = parsed.query.campaignId;
    const campaignCount = (
      db
        .query(`SELECT COUNT(*) AS count FROM campaigns ${campaignFilter ? "WHERE id = ?" : ""}`)
        .get(...(campaignFilter ? [campaignFilter] : [])) as { count: number }
    ).count;
    const activeLocations = (
      db
        .query(
          `SELECT COUNT(*) AS count FROM locations l JOIN campaigns c ON c.id = l.campaign_id
           WHERE l.retired_at IS NULL AND c.status = 'active' ${campaignFilter ? "AND l.campaign_id = ?" : ""}`,
        )
        .get(...(campaignFilter ? [campaignFilter] : [])) as { count: number }
    ).count;
    const scannedHosts = new Set(scoped.allReports.map((report) => report.host_id)).size;

    const openCriticals = scoped.findings.filter(
      (finding) =>
        finding.status === "NonCompliant" &&
        finding.severity === "Critical" &&
        !EXCLUDED_FROM_NUMERATOR.has(finding.treatment),
    ).length;

    const riskTrendData = riskTrend(scoped.allReports);

    return c.json({
      scope: describeScope(parsed.query),
      kpis: {
        campaignCount,
        activeLocations,
        scannedHosts,
        openCriticals,
        weightedRiskScore: Math.round(riskFromFindings(scoped.findings) * 100) / 100,
        coverage: Math.round(coverageFromFindings(scoped.findings) * 100) / 100,
        totalFindings: scoped.findings.length,
      },
      riskTrend: riskTrendData,
    });
  });

  // ---- campaign summary ----------------------------------------------------
  app.get("/api/campaigns/:id/summary", auth.requireRole(...READ_ROLES), (c) => {
    const campaignId = positiveInt(c.req.param("id"));
    const campaign = campaignId
      ? (db.query("SELECT id, name FROM campaigns WHERE id = ?").get(campaignId) as {
          id: number;
          name: string;
        } | null)
      : null;
    if (!campaign) return c.json({ error: "campaign not found", code: "NOT_FOUND" }, 404);
    const parsed = parseRequestQuery(c, { campaignId });
    if (!parsed.ok) return parsed.response;
    const scoped = collectScopeWithExtra(db, parsed.query, {
      clauses: ["r.campaign_id = ?"],
      params: [campaign.id],
    });

    const categories = new Map<
      string,
      { total: number; compliant: number; nonCompliant: number; notApplicable: number }
    >();
    for (const finding of scoped.findings) {
      const bucket = categories.get(finding.category) ?? {
        total: 0,
        compliant: 0,
        nonCompliant: 0,
        notApplicable: 0,
      };
      bucket.total += 1;
      if (finding.status === "Compliant") bucket.compliant += 1;
      else if (finding.status === "NonCompliant") bucket.nonCompliant += 1;
      else if (finding.status === "NotApplicable") bucket.notApplicable += 1;
      categories.set(finding.category, bucket);
    }
    const categoryCompliance = [...categories.entries()]
      .map(([category, value]) => {
        const applicable = value.total - value.notApplicable;
        return {
          category,
          ...value,
          applicable,
          complianceRate:
            applicable > 0 ? Math.round((value.compliant / applicable) * 10000) / 100 : 100,
        };
      })
      .sort((a, b) => a.category.localeCompare(b.category));

    const failing = new Map<
      string,
      { checkId: string; title: string; severity: string; count: number; hosts: Set<number> }
    >();
    for (const finding of scoped.findings) {
      if (finding.status !== "NonCompliant") continue;
      const bucket = failing.get(finding.checkId) ?? {
        checkId: finding.checkId,
        title: finding.title,
        severity: finding.severity,
        count: 0,
        hosts: new Set<number>(),
      };
      bucket.count += 1;
      bucket.hosts.add(finding.hostId);
      failing.set(finding.checkId, bucket);
    }
    const topFailingChecks = [...failing.values()]
      .map((value) => ({
        checkId: value.checkId,
        title: value.title,
        severity: value.severity,
        count: value.count,
        hosts: value.hosts.size,
      }))
      .sort(
        (a, b) =>
          b.count - a.count ||
          (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9) ||
          a.checkId.localeCompare(b.checkId),
      )
      .slice(0, 10);

    return c.json({
      campaign,
      scope: describeScope(parsed.query),
      kpis: {
        weightedRiskScore: Math.round(riskFromFindings(scoped.findings) * 100) / 100,
        coverage: Math.round(coverageFromFindings(scoped.findings) * 100) / 100,
        totalFindings: scoped.findings.length,
        hosts: new Set(scoped.findings.map((finding) => finding.hostId)).size,
      },
      severityBreakdown: severityBreakdown(scoped.findings),
      categoryCompliance,
      topFailingChecks,
    });
  });

  // ---- findings explorer ---------------------------------------------------
  app.get("/api/findings", auth.requireRole(...READ_ROLES), (c) => {
    const parsed = parseRequestQuery(c);
    if (!parsed.ok) return parsed.response;
    const scoped = collectScope(db, parsed.query);
    const { page, pageSize, offset } = parsed.query.pagination;
    return c.json({
      scope: describeScope(parsed.query),
      results: scoped.findings.slice(offset, offset + pageSize).map(serializeFinding),
      total: scoped.findings.length,
      page,
      pageSize,
    });
  });

  // ---- metric (chart) endpoints -------------------------------------------
  app.get("/api/metrics/severity", auth.requireRole(...READ_ROLES), (c) => {
    const parsed = parseRequestQuery(c);
    if (!parsed.ok) return parsed.response;
    const scoped = collectScope(db, parsed.query);
    return c.json({
      scope: describeScope(parsed.query),
      severity: severityBreakdown(scoped.findings),
      total: scoped.findings.length,
    });
  });

  app.get("/api/metrics/category", auth.requireRole(...READ_ROLES), (c) => {
    const parsed = parseRequestQuery(c);
    if (!parsed.ok) return parsed.response;
    const scoped = collectScope(db, parsed.query);
    const categories = new Map<string, { total: number; compliant: number; nonCompliant: number }>();
    for (const finding of scoped.findings) {
      const bucket = categories.get(finding.category) ?? { total: 0, compliant: 0, nonCompliant: 0 };
      bucket.total += 1;
      if (finding.status === "Compliant") bucket.compliant += 1;
      if (finding.status === "NonCompliant") bucket.nonCompliant += 1;
      categories.set(finding.category, bucket);
    }
    return c.json({
      scope: describeScope(parsed.query),
      categories: [...categories.entries()]
        .map(([category, value]) => ({ category, ...value }))
        .sort((a, b) => a.category.localeCompare(b.category)),
      total: scoped.findings.length,
    });
  });

  app.get("/api/metrics/risk", auth.requireRole(...READ_ROLES), (c) => {
    const parsed = parseRequestQuery(c);
    if (!parsed.ok) return parsed.response;
    const scoped = collectScope(db, parsed.query);
    return c.json({
      scope: describeScope(parsed.query),
      weightedRiskScore: Math.round(riskFromFindings(scoped.findings) * 100) / 100,
      coverage: Math.round(coverageFromFindings(scoped.findings) * 100) / 100,
      riskTrend: riskTrend(scoped.allReports),
    });
  });

  // ---- reports -------------------------------------------------------------
  app.get("/api/reports", auth.requireRole(...READ_ROLES), (c) => {
    const parsed = parseRequestQuery(c);
    if (!parsed.ok) return parsed.response;
    const scoped = collectScope(db, parsed.query);
    const { page, pageSize, offset } = parsed.query.pagination;
    return c.json({
      scope: describeScope(parsed.query),
      reports: scoped.allReports.slice(offset, offset + pageSize).map(serializeReportRow),
      total: scoped.allReports.length,
      page,
      pageSize,
    });
  });

  app.get("/api/reports/:id", auth.requireRole(...READ_ROLES), (c) => {
    const parsed = parseRequestQuery(c);
    if (!parsed.ok) return parsed.response;
    const reportId = positiveInt(c.req.param("id"));
    const report = reportId ? getReportRow(db, reportId) : null;
    if (!report) return c.json({ error: "report not found", code: "NOT_FOUND" }, 404);
    const doc = parseReportDoc(report.report_json);
    const extractorVersion = asString(isRecord(doc.scan) ? doc.scan.extractorVersion : null);
    const treatments = treatmentMap(db, [report.id]);
    const results = docResults(doc)
      .filter((result) => matchesResult(result, parsed.query, extractorVersion))
      .map((result) => {
        const checkId = String(result.id ?? "");
        const treatment = treatments.get(`${report.id}:${checkId}`);
        return {
          ...result,
          treatment: {
            state: treatment?.state ?? "open",
            assignee: treatment?.assignee ?? null,
            dueDate: treatment?.due_date ?? null,
            updatedAt: treatment?.updated_at ?? null,
          },
        };
      });

    return c.json({
      ...doc,
      id: report.id,
      campaignId: report.campaign_id,
      locationId: report.location_id,
      hostId: report.host_id,
      hostname: report.host_hostname,
      receivedAt: report.received_at,
      scanTimestamp: report.scan_timestamp,
      via: report.via,
      score: report.score,
      coverage: report.coverage,
      evidenceDepth: report.evidence_depth,
      links: makeLinks(report.campaign_id, report.location_id, report.host_id, report.id),
      results,
    });
  });

  // ---- diff ----------------------------------------------------------------
  app.get("/api/reports/:id/diff/:otherId", auth.requireRole(...READ_ROLES), (c) => {
    const parsed = parseRequestQuery(c);
    if (!parsed.ok) return parsed.response;
    const baseId = positiveInt(c.req.param("id"));
    const targetId = positiveInt(c.req.param("otherId"));
    const base = baseId ? getReportRow(db, baseId) : null;
    const target = targetId ? getReportRow(db, targetId) : null;
    if (!base || !target) return c.json({ error: "report not found", code: "NOT_FOUND" }, 404);
    if (base.host_id !== target.host_id) {
      return c.json({ error: "reports are from different hosts", code: "REPORT_HOST_MISMATCH" }, 400);
    }
    return c.json(buildDiff(base, target));
  });

  // ---- hosts ---------------------------------------------------------------
  app.get("/api/hosts", auth.requireRole(...READ_ROLES), (c) => {
    const parsed = parseRequestQuery(c);
    if (!parsed.ok) return parsed.response;
    const scoped = collectScope(db, parsed.query);
    const hosts = groupByHost(scoped, db);
    const { page, pageSize, offset } = parsed.query.pagination;
    return c.json({
      scope: describeScope(parsed.query),
      hosts: hosts.slice(offset, offset + pageSize),
      total: hosts.length,
      page,
      pageSize,
    });
  });

  app.get("/api/hosts/:id", auth.requireRole(...READ_ROLES), (c) => {
    const parsed = parseRequestQuery(c);
    if (!parsed.ok) return parsed.response;
    const hostId = positiveInt(c.req.param("id"));
    const host = hostId
      ? (db.query("SELECT * FROM hosts WHERE id = ?").get(hostId) as HostRow | null)
      : null;
    if (!host) return c.json({ error: "host not found", code: "NOT_FOUND" }, 404);
    const scoped = collectScopeWithExtra(db, parsed.query, {
      clauses: ["r.host_id = ?"],
      params: [host.id],
    });
    const locations = db
      .query(
        `SELECT l.id, l.name, l.campaign_id, hl.first_seen_at, hl.last_seen_at
         FROM host_locations hl JOIN locations l ON l.id = hl.location_id
         WHERE hl.host_id = ? ORDER BY hl.last_seen_at DESC, l.id`,
      )
      .all(host.id) as {
      id: number;
      name: string;
      campaign_id: number;
      first_seen_at: string;
      last_seen_at: string;
    }[];
    const reports = db
      .query(
        `SELECT r.*, h.hostname AS host_hostname, h.machine_id AS host_machine_id,
                h.platform AS host_platform, h.os AS host_os, h.arch AS host_arch
         FROM reports r LEFT JOIN hosts h ON h.id = r.host_id
         WHERE r.host_id = ? ORDER BY r.received_at DESC, r.id DESC LIMIT 100`,
      )
      .all(host.id) as ReportRow[];
    return c.json({
      host: serializeHost(host, scoped),
      locations: locations.map((row) => ({
        id: row.id,
        name: row.name,
        campaignId: row.campaign_id,
        firstSeenAt: row.first_seen_at,
        lastSeenAt: row.last_seen_at,
        links: { location: `/api/campaigns/${row.campaign_id}/locations/${row.id}` },
      })),
      reports: reports.map(serializeReportRow),
      findings: scoped.findings.map(serializeFinding),
      summary: {
        severity: severityBreakdown(scoped.findings),
        treatment: tallyTreatments(scoped.findings),
      },
    });
  });

  // ---- By Check pivot ------------------------------------------------------
  app.get("/api/checks/:checkId", auth.requireRole(...READ_ROLES), (c) => {
    const checkId = String(c.req.param("checkId") ?? "");
    if (!/^[A-Za-z0-9_-]+$/.test(checkId)) {
      return c.json({ error: "invalid check id", code: "INVALID_FILTER" }, 400);
    }
    const parsed = parseRequestQuery(c);
    if (!parsed.ok) return parsed.response;
    const narrowed = withCheckId(parsed.query, checkId);
    const scoped = collectScope(db, narrowed);
    return c.json({
      checkId,
      scope: describeScope(narrowed),
      total: scoped.findings.length,
      statusCounts: tallyTreatments(scoped.findings),
      hosts: scoped.findings.map((finding) => ({
        hostId: finding.hostId,
        hostname: finding.hostname,
        displayId: finding.displayId,
        status: finding.status,
        severity: finding.severity,
        category: finding.category,
        reportId: finding.reportId,
        receivedAt: finding.receivedAt,
        treatment: finding.treatment,
        links: finding.links,
      })),
    });
  });

  // ---- telemetry -----------------------------------------------------------
  app.get("/api/telemetry", auth.requireRole(...READ_ROLES), (c) => {
    const parsed = parseRequestQuery(c);
    if (!parsed.ok) return parsed.response;
    const scoped = collectScope(db, parsed.query);
    return c.json(buildTelemetry(db, scoped, deps));
  });

  // ---- standards -----------------------------------------------------------
  app.get("/api/standards", auth.requireRole(...READ_ROLES), (c) => {
    const parsed = parseRequestQuery(c);
    if (!parsed.ok) return parsed.response;
    const scoped = collectScope(db, parsed.query);
    return c.json({ scope: describeScope(parsed.query), ...buildStandards(scoped.findings) });
  });

  // ---- treatment board -----------------------------------------------------
  app.get("/api/treatment", auth.requireRole(...READ_ROLES), (c) => {
    const parsed = parseRequestQuery(c);
    if (!parsed.ok) return parsed.response;
    // Idempotent reconciliation: a newer scan can auto-resolve stale states.
    const autoResolved = reconcileTreatment(db, { campaignId: parsed.query.campaignId });
    const scoped = collectScope(db, parsed.query);
    return c.json({
      scope: describeScope(parsed.query),
      autoResolved,
      counts: tallyTreatments(scoped.findings),
      findings: scoped.findings.map(serializeFinding),
      total: scoped.findings.length,
    });
  });

  app.post("/api/reports/:id/findings/:checkId/treatment", auth.requireRole(...WRITE_ROLES), async (c) => {
    const reportId = positiveInt(c.req.param("id"));
    const checkId = String(c.req.param("checkId") ?? "");
    if (!reportId || !/^[A-Za-z0-9_-]+$/.test(checkId)) {
      return c.json({ error: "invalid report or check id", code: "INVALID_FILTER" }, 400);
    }
    const report = db
      .query("SELECT id, campaign_id, report_json FROM reports WHERE id = ?")
      .get(reportId) as { id: number; campaign_id: number; report_json: string | null } | null;
    if (!report) return c.json({ error: "report not found", code: "NOT_FOUND" }, 404);
    if (!docResults(parseReportDoc(report.report_json)).some((entry) => String(entry.id ?? "") === checkId)) {
      return c.json({ error: "finding not found in report", code: "NOT_FOUND" }, 404);
    }

    let body: Record<string, unknown> | null = null;
    try {
      const parsed = await c.req.json();
      body = isRecord(parsed) ? parsed : null;
    } catch {
      return c.json({ error: "invalid JSON", code: "INVALID_BODY" }, 400);
    }
    if (!body) return c.json({ error: "invalid JSON", code: "INVALID_BODY" }, 400);

    const state = typeof body.state === "string" ? body.state : "";
    if (!ALLOWED_TREATMENT.includes(state)) {
      return c.json({ error: "invalid treatment state", code: "INVALID_TREATMENT_STATE" }, 400);
    }
    const justification =
      typeof body.justification === "string" ? stripAndTrim(body.justification, 2048) : null;
    if ((state === "accepted_risk" || state === "false_positive") && !justification) {
      return c.json(
        {
          error: "justification is required for accepted_risk and false_positive",
          code: "JUSTIFICATION_REQUIRED",
        },
        400,
      );
    }
    const assignee = typeof body.assignee === "string" ? stripAndTrim(body.assignee, 128) : null;
    let dueDate: string | null = null;
    if (typeof body.dueDate === "string" && body.dueDate.trim()) {
      const millis = Date.parse(body.dueDate);
      if (!Number.isFinite(millis)) {
        return c.json({ error: "dueDate must be an ISO timestamp", code: "INVALID_DUE_DATE" }, 400);
      }
      dueDate = new Date(millis).toISOString();
    }
    const actor = actorOf(c);
    const timestamp = nowIso();

    const outcome = db.transaction(() => {
      const previous = db
        .query("SELECT * FROM finding_states WHERE report_id = ? AND check_id = ?")
        .get(reportId, checkId) as TreatmentRow | null;
      db.query(
        `INSERT INTO finding_states (report_id, check_id, state, assignee, due_date, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(report_id, check_id) DO UPDATE SET
           state = excluded.state,
           assignee = excluded.assignee,
           due_date = excluded.due_date,
           updated_at = excluded.updated_at`,
      ).run(reportId, checkId, state, assignee, dueDate, timestamp);
      const projection = db
        .query("SELECT id FROM finding_states WHERE report_id = ? AND check_id = ?")
        .get(reportId, checkId) as { id: number };
      const history = db
        .query(
          `INSERT INTO finding_state_history
             (finding_state_id, actor, changed_at, from_state, to_state, justification, assignee, due_date)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          projection.id,
          actor.username,
          timestamp,
          previous?.state ?? null,
          state,
          justification,
          assignee,
          dueDate,
        );
      const metrics = recomputeReportMetrics(db, reportId);
      const campaignMetrics = recomputeCampaignMetrics(db, report.campaign_id);
      db.query(
        `INSERT INTO audit_log (actor, actor_ip, action, resource, details, created_at)
         VALUES (?, ?, 'treatment.update', ?, ?, ?)`,
      ).run(
        actor.username,
        c.req.header("x-forwarded-for") ?? null,
        `report:${reportId}:finding:${checkId}`,
        JSON.stringify({ state, from: previous?.state ?? null }),
        timestamp,
      );
      return { historyId: Number(history.lastInsertRowid), metrics, campaignMetrics };
    })();

    return c.json({
      reportId,
      checkId,
      state,
      justification,
      assignee,
      dueDate,
      updatedAt: timestamp,
      historyId: outcome.historyId,
      reportMetrics: outcome.metrics,
      campaignMetrics: outcome.campaignMetrics,
    });
  });
}
