// Server-authoritative report metrics (Task 48, spec §6.4).
//
// Everything here is a pure function over the validated result list so the
// dashboard never trusts aggregates supplied inside a sealed report. The
// extractor may emit `summary`, but ingest always recomputes it from the raw
// results and stores the recomputed value.
//
// Binding formula (Global Constraints / spec §6.4):
//   risk   = 100 * (1 - Σ(w_i * failed_i) / Σ(w_i * applicable_i))
//   weights: Critical=10, High=6, Medium=3, Low=1, Info=0
//   `accepted_risk` and `false_positive` remove failed weight from the
//   numerator but retain applicable weight in the denominator.
//   coverage = authoritative decided applicable / applicable.

export const SEVERITY_WEIGHTS = {
  Critical: 10,
  High: 6,
  Medium: 3,
  Low: 1,
  Informational: 0,
} as const;

export type SeverityName = keyof typeof SEVERITY_WEIGHTS;

/** Rust `Severity` serializes variant names verbatim (no rename_all). */
export function severityWeight(severity: unknown): number {
  if (typeof severity !== "string") return 0;
  const weight = (SEVERITY_WEIGHTS as Record<string, number>)[severity];
  return typeof weight === "number" ? weight : 0;
}

/** Rust `Status` serializes variant names verbatim (no rename_all). */
export const STATUS = {
  Compliant: "Compliant",
  NonCompliant: "NonCompliant",
  NotApplicable: "NotApplicable",
  Error: "Error",
  DegradedPartial: "DegradedPartial",
} as const;

export type StatusName = (typeof STATUS)[keyof typeof STATUS];

const VALID_STATUSES = new Set<string>(Object.values(STATUS));

export function isValidStatus(status: unknown): status is StatusName {
  return typeof status === "string" && VALID_STATUSES.has(status);
}

export function isValidSeverity(severity: unknown): severity is SeverityName {
  return typeof severity === "string" && severity in SEVERITY_WEIGHTS;
}

/** Applicable = the check could run at all (NotApplicable excluded). */
export function isApplicable(status: unknown): boolean {
  return status !== STATUS.NotApplicable;
}

/** Decided = authoritative evidence resolved the check (Compliant/NonCompliant). */
export function isDecided(status: unknown): boolean {
  return status === STATUS.Compliant || status === STATUS.NonCompliant;
}

export type ResultLike = {
  id?: unknown;
  status?: unknown;
  severity?: unknown;
};

export type SummaryCounts = {
  compliant: number;
  nonCompliant: number;
  notApplicable: number;
  error: number;
  degraded: number;
  informational: number;
};

/** Mirrors the Rust `engine::summarize` projection exactly. */
export function computeSummary(results: readonly ResultLike[]): SummaryCounts {
  const summary: SummaryCounts = {
    compliant: 0,
    nonCompliant: 0,
    notApplicable: 0,
    error: 0,
    degraded: 0,
    informational: 0,
  };
  for (const result of results) {
    switch (result.status) {
      case STATUS.Compliant:
        summary.compliant += 1;
        break;
      case STATUS.NonCompliant:
        summary.nonCompliant += 1;
        break;
      case STATUS.NotApplicable:
        summary.notApplicable += 1;
        break;
      case STATUS.Error:
        summary.error += 1;
        break;
      case STATUS.DegradedPartial:
        summary.degraded += 1;
        break;
      default:
        break;
    }
    if (result.severity === "Informational") summary.informational += 1;
  }
  return summary;
}

export type TreatmentState =
  | "open"
  | "in_progress"
  | "mitigated"
  | "accepted_risk"
  | "false_positive"
  | "resolved";

export type TreatmentLookup = (checkId: string) => TreatmentState | undefined;

const EXCLUDED_FROM_NUMERATOR = new Set<TreatmentState>(["accepted_risk", "false_positive"]);

/**
 * Weighted risk score in [0, 100], higher = safer. Returns 100 when nothing
 * applicable is weighted (empty scope), never NaN.
 */
export function computeRiskScore(
  results: readonly ResultLike[],
  treatmentFor?: TreatmentLookup,
): number {
  let failedWeight = 0;
  let applicableWeight = 0;
  for (const result of results) {
    if (!isApplicable(result.status)) continue;
    const weight = severityWeight(result.severity);
    if (weight <= 0) continue;
    applicableWeight += weight;
    if (result.status !== STATUS.NonCompliant) continue;
    const checkId = typeof result.id === "string" ? result.id : "";
    const treatment = treatmentFor?.(checkId);
    if (treatment && EXCLUDED_FROM_NUMERATOR.has(treatment)) continue;
    failedWeight += weight;
  }
  if (applicableWeight <= 0) return 100;
  return 100 * (1 - failedWeight / applicableWeight);
}

/** Percentage of applicable checks with authoritative decided evidence. */
export function computeCoverage(results: readonly ResultLike[]): number {
  let applicable = 0;
  let decided = 0;
  for (const result of results) {
    if (!isApplicable(result.status)) continue;
    applicable += 1;
    if (isDecided(result.status)) decided += 1;
  }
  if (applicable <= 0) return 100;
  return (decided / applicable) * 100;
}

/** Round helper used when persisting/displaying a metric. */
export function roundMetric(value: number, decimals = 2): number {
  const factor = 10 ** decimals;
  return Math.round(value * factor) / factor;
}
