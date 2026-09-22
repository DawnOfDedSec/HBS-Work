// Normalized export view model (Tasks 57 + 58, spec §6.6).
//
// Every export format (XLSX, CSV, PDF, DOCX) renders from this ONE value so
// KPIs, severity breakdowns, treatment state, ordering, and evidence never
// drift between deliverables. The model is assembled exclusively from the
// canonical scoped query layer (`reports.ts` `collectScope` + `buildTelemetry`)
// plus the pure metric functions in `metrics.ts`; nothing is trusted from the
// client and no aggregate is recomputed differently per format.
//
// Evidence and free-text fields pass through the shared `redactDiagnosticText`
// redactor before they enter the model, so nothing downstream can re-introduce
// a secret that the platform already masks.

import type { Database } from "bun:sqlite";
import { computeCoverage, computeRiskScore, roundMetric, type TreatmentState } from "../metrics";
import {
  buildTelemetry,
  collectScope,
  redactDiagnosticText,
  type ReportOptions,
} from "../reports";
import type { NormalizedQuery } from "../query";

export type ExportFormat = "xlsx" | "csv" | "pdf" | "docx";
export type ExportTemplate = "executive" | "technical";

export const EXPORT_FORMATS: readonly ExportFormat[] = ["xlsx", "csv", "pdf", "docx"];
export const EXPORT_TEMPLATES: readonly ExportTemplate[] = ["executive", "technical"];

/** Canonical severity ordering (most severe first). */
export const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"] as const;

/** ARGB fills shared by the XLSX sheet and reused by the badge colours. */
export const SEVERITY_ARGB: Record<string, string> = {
  Critical: "FFC00000",
  High: "FFE8590C",
  Medium: "FFFFC000",
  Low: "FF70AD47",
  Informational: "FF7F7F7F",
};

/** Readable foreground for a severity badge fill. */
export const SEVERITY_TEXT_ARGB: Record<string, string> = {
  Critical: "FFFFFFFF",
  High: "FFFFFFFF",
  Medium: "FF1F2937",
  Low: "FF1F2937",
  Informational: "FFFFFFFF",
};
/** Canonical status ordering (worst first). */
export const STATUS_ORDER = ["NonCompliant", "DegradedPartial", "Error", "Compliant", "NotApplicable"] as const;
/** Canonical treatment ordering. */
export const TREATMENT_ORDER = ["open", "accepted_risk", "false_positive", "remediated"] as const;

const SEVERITY_RANK: Record<string, number> = Object.fromEntries(
  SEVERITY_ORDER.map((severity, index) => [severity, index]),
);
const BROKEN_STATUSES = new Set(["NonCompliant", "DegradedPartial", "Error"]);
const EXCLUDED_TREATMENTS = new Set(["accepted_risk", "false_positive"]);

type Scoped = ReturnType<typeof collectScope>;
type Finding = Scoped["findings"][number];
type Telemetry = ReturnType<typeof buildTelemetry>;

export type ExportScope = {
  kind: string;
  campaignId: number | null;
  campaignName: string | null;
  reportId: number | null;
  from: string | null;
  to: string | null;
};

export type ExportEvidenceLine = {
  lineNumber: number | null;
  text: string;
  /** True for the exact offending line at `targetIndex`. */
  offending: boolean;
};

export type ExportEvidenceBlock = {
  path: string;
  line: number | null;
  col: number | null;
  /** `target ±3` context window, redacted, with computed absolute line numbers. */
  lines: ExportEvidenceLine[];
  fileMode: string | null;
  fileUid: number | null;
  fileGid: number | null;
};

export type ExportFallbackEntry = { source: string; outcome: string };

export type ExportFinding = {
  reportId: number;
  campaignId: number;
  locationId: number;
  hostId: number;
  hostname: string;
  machineId: string | null;
  displayId: string;
  checkId: string;
  title: string;
  severity: string;
  severityRank: number;
  status: string;
  category: string;
  description: string;
  impact: string;
  recommendation: string;
  location: string;
  repro: string;
  degradedReason: string;
  evidence: string;
  evidenceBlocks: ExportEvidenceBlock[];
  fallbackLog: ExportFallbackEntry[];
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
};

export type ExportHostSection = {
  hostId: number;
  hostname: string;
  machineId: string | null;
  displayId: string;
  platform: string | null;
  os: string | null;
  arch: string | null;
  reportCount: number;
  latestReportId: number | null;
  latestReceivedAt: string | null;
  riskScore: number | null;
  coverage: number | null;
  severity: Record<string, number>;
  treatment: Record<string, number>;
  findings: ExportFinding[];
};

export type ExportCheckSection = {
  checkId: string;
  title: string;
  severity: string;
  severityRank: number;
  category: string;
  references: string[];
  findingCount: number;
  hostCount: number;
  status: Record<string, number>;
  treatment: Record<string, number>;
  findings: ExportFinding[];
};

export type ExportReference = {
  reference: string;
  standard: string;
  count: number;
  hosts: number;
  nonCompliant: number;
};

export type ExportKpis = {
  riskScore: number;
  coverage: number;
  totalFindings: number;
  failingFindings: number;
  openFindings: number;
  openCriticals: number;
  totalReports: number;
  hostCount: number;
  referenceCount: number;
  severity: Record<string, number>;
  failingSeverity: Record<string, number>;
  status: Record<string, number>;
  treatment: Record<string, number>;
  evidenceDepth: Record<string, number>;
  freshness: Telemetry["freshness"];
};

export type ExportViewModel = {
  formatVersion: 1;
  title: string;
  generatedAt: string;
  scope: ExportScope;
  kpis: ExportKpis;
  summary: string[];
  findings: ExportFinding[];
  hosts: ExportHostSection[];
  checks: ExportCheckSection[];
  references: ExportReference[];
};

// ---------------------------------------------------------------------------
// Scoping helpers (path-scoped routes merge into the canonical filter set)
// ---------------------------------------------------------------------------

function freezeQuery(query: NormalizedQuery, patch: Partial<NormalizedQuery>): NormalizedQuery {
  return Object.freeze({
    ...query,
    ...patch,
    filters: Object.freeze({ ...query.filters, ...(patch.filters ?? {}) }),
  });
}

/** Force a query to a single report, preserving any caller-supplied filters. */
export function scopeToReport(query: NormalizedQuery, reportId: number): NormalizedQuery {
  return freezeQuery(query, {
    scope: "report",
    filters: { ...query.filters, reportId: Object.freeze([reportId]), from: null, to: null },
  });
}

/**
 * Restrict a query to one campaign's locations. Locations belong to exactly
 * one campaign, so this is an exact campaign scope that still flows through the
 * shared parameterized `buildReportWhere` path (and avoids materializing every
 * report id into an `IN (...)` list).
 */
export function scopeToCampaign(
  db: Database,
  query: NormalizedQuery,
  campaignId: number,
): NormalizedQuery {
  const rows = db
    .query("SELECT id FROM locations WHERE campaign_id = ?")
    .all(campaignId) as { id: number }[];
  let locationIds = rows.map((row) => row.id);
  if (query.filters.locationId.length > 0) {
    const requested = new Set(query.filters.locationId);
    locationIds = locationIds.filter((id) => requested.has(id));
  }
  // `0` is never a valid location id, so an empty campaign yields zero rows
  // instead of silently widening the scope.
  if (locationIds.length === 0) locationIds = [0];
  return freezeQuery(query, {
    campaignId,
    filters: { ...query.filters, locationId: Object.freeze(locationIds) },
  });
}

// ---------------------------------------------------------------------------
// Redaction + coercion helpers
// ---------------------------------------------------------------------------

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Run the platform secret redactor over any free text before it is rendered. */
export function redactText(value: unknown, maxLength = 8192): string {
  return typeof value === "string" ? redactDiagnosticText(value, maxLength) : "";
}

function resultString(result: Record<string, unknown>, key: string, maxLength = 4096): string {
  return redactText(result[key], maxLength);
}

function resultReferences(result: Record<string, unknown>): string[] {
  const raw = result.references;
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  for (const value of raw) {
    const cleaned = redactText(value, 256).trim();
    if (cleaned && !out.includes(cleaned)) out.push(cleaned);
  }
  return out;
}

function resultFallbackLog(result: Record<string, unknown>): ExportFallbackEntry[] {
  const raw = result.fallbackLog;
  if (!Array.isArray(raw)) return [];
  const out: ExportFallbackEntry[] = [];
  for (const entry of raw) {
    if (!isRecord(entry)) continue;
    const source = redactText(entry.source, 512).trim();
    const outcome = redactText(entry.outcome, 512).trim();
    if (source || outcome) out.push({ source, outcome });
  }
  return out;
}

function resultEvidenceBlocks(result: Record<string, unknown>): ExportEvidenceBlock[] {
  const raw = result.evidenceBlocks;
  if (!Array.isArray(raw)) return [];
  const blocks: ExportEvidenceBlock[] = [];
  for (const entry of raw) {
    if (!isRecord(entry)) continue;
    const context = Array.isArray(entry.context)
      ? entry.context.filter((line): line is string => typeof line === "string")
      : [];
    const line = typeof entry.line === "number" && Number.isFinite(entry.line) ? entry.line : null;
    const col = typeof entry.col === "number" && Number.isFinite(entry.col) ? entry.col : null;
    const targetIndex =
      typeof entry.targetIndex === "number" && Number.isInteger(entry.targetIndex)
        ? entry.targetIndex
        : -1;
    // `line` is the absolute line of the offending value; walk back to the
    // first context line so every rendered line carries its real number.
    const firstLine = line !== null && targetIndex >= 0 ? line - targetIndex : null;
    const lines: ExportEvidenceLine[] = context.map((text, index) => ({
      lineNumber: firstLine !== null ? firstLine + index : null,
      text: redactText(text, 2048),
      offending: index === targetIndex,
    }));
    blocks.push({
      path: redactText(entry.path, 1024),
      line,
      col,
      lines,
      fileMode: typeof entry.fileMode === "number" ? `0${entry.fileMode.toString(8)}` : null,
      fileUid: typeof entry.fileUid === "number" ? entry.fileUid : null,
      fileGid: typeof entry.fileGid === "number" ? entry.fileGid : null,
    });
  }
  return blocks;
}

function tally<T>(values: readonly T[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const value of values) {
    const key = String(value);
    out[key] = (out[key] ?? 0) + 1;
  }
  return out;
}

function orderedTally(values: readonly string[], order: readonly string[]): Record<string, number> {
  const raw = tally(values);
  const out: Record<string, number> = {};
  for (const key of order) out[key] = raw[key] ?? 0;
  for (const [key, count] of Object.entries(raw)) if (!(key in out)) out[key] = count;
  return out;
}

const SEVERITY_COUNT_TEMPLATE: Record<string, number> = Object.fromEntries(
  SEVERITY_ORDER.map((severity) => [severity, 0]),
);

function severityTally(findings: readonly ExportFinding[], failingOnly: boolean): Record<string, number> {
  const out = { ...SEVERITY_COUNT_TEMPLATE };
  for (const finding of findings) {
    if (failingOnly && !BROKEN_STATUSES.has(finding.status)) continue;
    out[finding.severity] = (out[finding.severity] ?? 0) + 1;
  }
  return out;
}

function standardOf(reference: string): string {
  return reference.split(/[.\-_]/)[0] || reference;
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

function toExportFinding(finding: Finding, machineId: string | null): ExportFinding {
  const result = finding.result;
  return {
    reportId: finding.reportId,
    campaignId: finding.campaignId,
    locationId: finding.locationId,
    hostId: finding.hostId,
    hostname: finding.hostname,
    machineId,
    displayId: finding.displayId,
    checkId: finding.checkId,
    title: redactText(finding.title, 512),
    severity: finding.severity || "Informational",
    severityRank: SEVERITY_RANK[finding.severity] ?? SEVERITY_ORDER.length,
    status: finding.status,
    category: redactText(finding.category, 256),
    description: resultString(result, "description"),
    impact: resultString(result, "impact"),
    recommendation: resultString(result, "recommendation"),
    location: resultString(result, "location", 1024),
    repro: resultString(result, "repro", 2048),
    degradedReason: resultString(result, "degradedReason", 1024),
    evidence: resultString(result, "evidence", 8192),
    evidenceBlocks: resultEvidenceBlocks(result),
    fallbackLog: resultFallbackLog(result),
    references: resultReferences(result),
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

/** Severity descending (most severe first), then check id, then host. */
export function compareExportFindings(a: ExportFinding, b: ExportFinding): number {
  if (a.severityRank !== b.severityRank) return a.severityRank - b.severityRank;
  const check = a.checkId.localeCompare(b.checkId);
  if (check !== 0) return check;
  const host = a.hostname.localeCompare(b.hostname);
  if (host !== 0) return host;
  return a.reportId - b.reportId;
}

// ---------------------------------------------------------------------------
// Sections
// ---------------------------------------------------------------------------

function buildHostSections(scoped: Scoped, findings: ExportFinding[]): ExportHostSection[] {
  const byHost = new Map<number, ExportFinding[]>();
  for (const finding of findings) {
    const bucket = byHost.get(finding.hostId) ?? [];
    bucket.push(finding);
    byHost.set(finding.hostId, bucket);
  }

  const latestReport = new Map<number, Scoped["selectedReports"][number]>();
  const reportCounts = new Map<number, number>();
  for (const report of scoped.allReports) {
    reportCounts.set(report.host_id, (reportCounts.get(report.host_id) ?? 0) + 1);
    const current = latestReport.get(report.host_id);
    if (!current || report.received_at > current.received_at) latestReport.set(report.host_id, report);
  }

  return [...byHost.entries()]
    .map(([hostId, hostFindings]) => {
      const sample = hostFindings[0];
      const report = latestReport.get(hostId) ?? scoped.selectedReports.find((row) => row.host_id === hostId);
      return {
        hostId,
        hostname: sample.hostname,
        machineId: sample.machineId,
        displayId: sample.displayId,
        platform: sample.platform,
        os: sample.os,
        arch: sample.arch,
        reportCount: reportCounts.get(hostId) ?? (report ? 1 : 0),
        latestReportId: report?.id ?? null,
        latestReceivedAt: report?.received_at ?? null,
        riskScore: report?.score ?? null,
        coverage: report?.coverage ?? null,
        severity: severityTally(hostFindings, false),
        treatment: tally(hostFindings.map((finding) => finding.treatment)),
        findings: [...hostFindings].sort(compareExportFindings),
      };
    })
    .sort((a, b) => a.hostname.localeCompare(b.hostname) || a.hostId - b.hostId);
}

function buildCheckSections(findings: ExportFinding[]): ExportCheckSection[] {
  const byCheck = new Map<string, ExportFinding[]>();
  for (const finding of findings) {
    const bucket = byCheck.get(finding.checkId) ?? [];
    bucket.push(finding);
    byCheck.set(finding.checkId, bucket);
  }
  return [...byCheck.entries()]
    .map(([checkId, checkFindings]) => {
      const sample = checkFindings[0];
      const references: string[] = [];
      for (const finding of checkFindings) {
        for (const reference of finding.references) {
          if (!references.includes(reference)) references.push(reference);
        }
      }
      return {
        checkId,
        title: sample.title,
        severity: sample.severity,
        severityRank: sample.severityRank,
        category: sample.category,
        references,
        findingCount: checkFindings.length,
        hostCount: new Set(checkFindings.map((finding) => finding.hostId)).size,
        status: tally(checkFindings.map((finding) => finding.status)),
        treatment: tally(checkFindings.map((finding) => finding.treatment)),
        findings: [...checkFindings].sort(compareExportFindings),
      };
    })
    .sort((a, b) => a.severityRank - b.severityRank || a.checkId.localeCompare(b.checkId));
}

function buildReferences(findings: ExportFinding[]): ExportReference[] {
  const map = new Map<
    string,
    { reference: string; standard: string; count: number; hosts: Set<number>; nonCompliant: number }
  >();
  for (const finding of findings) {
    for (const reference of finding.references) {
      const entry = map.get(reference) ?? {
        reference,
        standard: standardOf(reference),
        count: 0,
        hosts: new Set<number>(),
        nonCompliant: 0,
      };
      entry.count += 1;
      entry.hosts.add(finding.hostId);
      if (finding.status === "NonCompliant") entry.nonCompliant += 1;
      map.set(reference, entry);
    }
  }
  return [...map.values()]
    .map((entry) => ({
      reference: entry.reference,
      standard: entry.standard,
      count: entry.count,
      hosts: entry.hosts.size,
      nonCompliant: entry.nonCompliant,
    }))
    .sort((a, b) => a.reference.localeCompare(b.reference));
}

// ---------------------------------------------------------------------------
// Plain-language summary
// ---------------------------------------------------------------------------

export function buildSummarySentences(kpis: ExportKpis, scope?: ExportScope): string[] {
  const sentences: string[] = [];
  const scopeText = scope ? ` (scope: ${scope.kind}).` : ".";
  sentences.push(
    `This export covers ${kpis.hostCount} host(s) and ${kpis.totalReports} scan report(s)${scopeText}`,
  );
  sentences.push(
    `The weighted risk score is ${kpis.riskScore.toFixed(1)} out of 100 (higher is safer) with ${kpis.coverage.toFixed(1)}% authoritative evidence coverage.`,
  );
  sentences.push(
    `Findings in scope: ${kpis.totalFindings} total, of which ${kpis.failingFindings} are failing or degraded ` +
      `(${kpis.severity.Critical ?? 0} Critical, ${kpis.severity.High ?? 0} High, ${kpis.severity.Medium ?? 0} Medium, ${kpis.severity.Low ?? 0} Low, ${kpis.severity.Informational ?? 0} Informational).`,
  );
  if (kpis.openCriticals > 0) {
    sentences.push(
      `${kpis.openCriticals} open Critical finding(s) require immediate remediation; ${kpis.openFindings} finding(s) are still open in total.`,
    );
  } else if (kpis.openFindings > 0) {
    sentences.push(`${kpis.openFindings} finding(s) remain open and should be triaged.`);
  } else if (kpis.totalFindings === 0) {
    sentences.push("No testcase results were found in this scope.");
  } else {
    sentences.push("No open findings remain; all findings in scope have a recorded treatment decision.");
  }
  sentences.push(
    `Treatment: ${kpis.treatment.open ?? 0} open, ${kpis.treatment.remediated ?? 0} remediated, ` +
      `${kpis.treatment.accepted_risk ?? 0} accepted risk, ${kpis.treatment.false_positive ?? 0} false positive.`,
  );
  if (kpis.referenceCount > 0) {
    sentences.push(
      `Findings map to ${kpis.referenceCount} distinct standard reference(s), available in the references section of this deliverable.`,
    );
  }
  return sentences;
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

function scopeDescriptor(query: NormalizedQuery, campaignName: string | null): ExportScope {
  return {
    kind: query.scope,
    campaignId: query.campaignId,
    campaignName,
    reportId: query.filters.reportId[0] ?? null,
    from: query.filters.from,
    to: query.filters.to,
  };
}

function exportTitle(scope: ExportScope): string {
  if (scope.campaignName) return `Security Audit — ${scope.campaignName}`;
  if (scope.campaignId) return `Security Audit — Campaign #${scope.campaignId}`;
  if (scope.reportId) return `Security Audit — Report #${scope.reportId}`;
  return "Security Audit";
}

/**
 * Build the single normalized export view model. Pure with respect to the
 * database (read-only) and deterministic given the same stored reports.
 */
export function buildExportViewModel(
  db: Database,
  query: NormalizedQuery,
  options: ReportOptions = {},
): ExportViewModel {
  const scoped = collectScope(db, query);
  const telemetry = buildTelemetry(db, scoped, options);
  const now = new Date().toISOString();

  // Machine IDs are not part of the finding row; resolve them once.
  const hostIds = new Set<number>();
  for (const finding of scoped.findings) hostIds.add(finding.hostId);
  for (const report of scoped.selectedReports) hostIds.add(report.host_id);
  const machineIds = new Map<number, string>();
  const hostNames = new Map<number, string>();
  if (hostIds.size > 0) {
    const placeholders = [...hostIds].map(() => "?").join(", ");
    const rows = db
      .query(`SELECT id, machine_id, hostname FROM hosts WHERE id IN (${placeholders})`)
      .all(...hostIds) as { id: number; machine_id: string; hostname: string | null }[];
    for (const row of rows) {
      machineIds.set(row.id, row.machine_id);
      hostNames.set(row.id, row.hostname ?? "");
    }
  }

  const findings = scoped.findings
    .map((finding) => toExportFinding(finding, machineIds.get(finding.hostId) ?? null))
    .sort(compareExportFindings);

  // Risk/coverage from the same finding projections the export renders, so the
  // workbook and documents cannot disagree with each other.
  const treatmentById = new Map(
    findings.map((finding) => [`${finding.reportId}:${finding.checkId}`, finding.treatment]),
  );
  const metricInputs = findings.map((finding) => ({
    id: `${finding.reportId}:${finding.checkId}`,
    status: finding.status,
    severity: finding.severity,
  }));
  const riskScore = roundMetric(
    computeRiskScore(metricInputs, (id) => treatmentById.get(id) as TreatmentState | undefined),
  );
  const coverage = roundMetric(
    typeof telemetry.coverage === "number" ? telemetry.coverage : computeCoverage(metricInputs),
  );

  const campaignName = query.campaignId
    ? ((db.query("SELECT name FROM campaigns WHERE id = ?").get(query.campaignId) as {
        name: string;
      } | null)?.name ?? null)
    : null;
  const scope = scopeDescriptor(query, campaignName);

  const references = buildReferences(findings);
  const failingFindings = findings.filter((finding) => BROKEN_STATUSES.has(finding.status));
  const openFindings = failingFindings.filter((finding) => finding.treatment === "open");
  const kpis: ExportKpis = {
    riskScore,
    coverage,
    totalFindings: findings.length,
    failingFindings: failingFindings.length,
    openFindings: openFindings.length,
    openCriticals: openFindings.filter((finding) => finding.severity === "Critical").length,
    totalReports: scoped.allReports.length,
    hostCount: new Set(findings.map((finding) => finding.hostId)).size || telemetry.hostCount,
    referenceCount: references.length,
    severity: severityTally(findings, false),
    failingSeverity: severityTally(findings, true),
    status: orderedTally(findings.map((finding) => finding.status), STATUS_ORDER),
    treatment: orderedTally(findings.map((finding) => finding.treatment), TREATMENT_ORDER),
    evidenceDepth: orderedTally(
      scoped.selectedReports.map((report) => report.evidence_depth ?? "unknown"),
      [],
    ),
    freshness: telemetry.freshness,
  };

  return {
    formatVersion: 1,
    title: exportTitle(scope),
    generatedAt: now,
    scope,
    kpis,
    summary: buildSummarySentences(kpis, scope),
    findings,
    hosts: buildHostSections(scoped, findings),
    checks: buildCheckSections(findings),
    references,
  };
}

export { EXCLUDED_TREATMENTS as EXPORT_EXCLUDED_TREATMENTS };
