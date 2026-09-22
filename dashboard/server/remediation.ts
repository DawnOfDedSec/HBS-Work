// Remediation Center API (Task 60).
//
// Sysadmin-facing aggregation: every *failing* check in the current scope is
// collapsed into one actionable unit with the exact repro/remediation command,
// the affected hosts, references, and the current treatment roll-up.
//
// Scoping is delegated to the canonical query layer in `reports.ts` — this
// module never re-implements the filter parser or the report scoping. All
// aggregation happens in JS over the scoped findings (already read from the
// stored report JSON), so no user value ever reaches SQL as text.

import type { Database } from "bun:sqlite";
import { Hono, type MiddlewareHandler } from "hono";
import { collectScope, describeScope, parseRequestQuery } from "./reports";

export type RemediationAuth = {
  requireRole: (...roles: string[]) => MiddlewareHandler;
};

const READ_ROLES = ["super_admin", "auditor", "viewer"];

/** Statuses that represent a check an operator must act on. */
const FAILING_STATUSES = new Set(["NonCompliant", "DegradedPartial", "Error"]);

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

const MAX_REFERENCES = 50;
const MAX_HOSTS = 200;

/** Structural subset of the scoped finding that remediation needs. */
type ScopedFinding = {
  checkId: string;
  title: string;
  severity: string;
  status: string;
  category: string;
  references: string[];
  treatment: string;
  treatmentAssignee: string | null;
  treatmentDueDate: string | null;
  hostId: number;
  hostname: string;
  displayId: string;
  reportId: number;
  result: Record<string, unknown>;
};

export type RemediationHost = {
  hostId: number;
  hostname: string;
  displayId: string;
  reportId: number;
  status: string;
};

export type RemediationTreatmentSummary = {
  open: number;
  accepted_risk: number;
  false_positive: number;
  remediated: number;
  /** Distinct non-empty owners referenced by any failing finding. */
  assignees: string[];
  /** Earliest non-empty due date across the failing findings. */
  nextDueDate: string | null;
};

export type RemediationItem = {
  checkId: string;
  title: string;
  severity: string;
  category: string;
  /** Worst status observed for the check (NonCompliant before Error). */
  status: string;
  /** Number of distinct hosts currently failing this check. */
  failingHosts: number;
  /** Number of distinct hosts that reported this check in scope (incl. compliant). */
  hostCount: number;
  /** Affected hosts, worst status first. */
  hosts: RemediationHost[];
  recommendation: string;
  impact: string;
  references: string[];
  /** Exact command that reproduces/drives the remediation. */
  repro: string;
  /** Representative evidence path/location for the check. */
  exampleLocation: string;
  treatmentSummary: RemediationTreatmentSummary;
};

type Group = {
  checkId: string;
  title: string;
  severity: string;
  category: string;
  status: string;
  references: string[];
  recommendation: string;
  impact: string;
  repro: string;
  exampleLocation: string;
  hosts: Map<number, RemediationHost>;
  treatment: { open: number; accepted_risk: number; false_positive: number; remediated: number };
  assignees: Set<string>;
  dueDates: string[];
};

function text(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function worstStatus(current: string, next: string): string {
  return (STATUS_RANK[next] ?? 9) < (STATUS_RANK[current] ?? 9) ? next : current;
}

function compareItems(a: RemediationItem, b: RemediationItem): number {
  const severity = (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9);
  if (severity !== 0) return severity;
  if (a.failingHosts !== b.failingHosts) return b.failingHosts - a.failingHosts;
  return a.checkId.localeCompare(b.checkId);
}

/**
 * Group scoped findings into remediation units. Failing checks are emitted
 * once; compliant/not-applicable rows only contribute to `hostCount`.
 */
export function aggregateRemediation(findings: readonly ScopedFinding[]): RemediationItem[] {
  const reportedHosts = new Map<string, Set<number>>();
  for (const finding of findings) {
    const bucket = reportedHosts.get(finding.checkId) ?? new Set<number>();
    bucket.add(finding.hostId);
    reportedHosts.set(finding.checkId, bucket);
  }

  const groups = new Map<string, Group>();
  for (const finding of findings) {
    if (!FAILING_STATUSES.has(finding.status)) continue;
    const group =
      groups.get(finding.checkId) ??
      {
        checkId: finding.checkId,
        title: finding.title,
        severity: finding.severity,
        category: finding.category,
        status: finding.status,
        references: [],
        recommendation: "",
        impact: "",
        repro: "",
        exampleLocation: "",
        hosts: new Map<number, RemediationHost>(),
        treatment: { open: 0, accepted_risk: 0, false_positive: 0, remediated: 0 },
        assignees: new Set<string>(),
        dueDates: [],
      };

    group.status = worstStatus(group.status, finding.status);
    // Prefer the first non-empty descriptive fields (they are identical across
    // hosts for the same check id, but defensive against partial reports).
    if (!group.recommendation) group.recommendation = text(finding.result.recommendation);
    if (!group.impact) group.impact = text(finding.result.impact);
    if (!group.repro) group.repro = text(finding.result.repro);
    if (!group.exampleLocation) group.exampleLocation = text(finding.result.location);
    if (!group.title) group.title = finding.title;
    for (const reference of finding.references) {
      if (group.references.length >= MAX_REFERENCES) break;
      if (!group.references.includes(reference)) group.references.push(reference);
    }

    const existingHost = group.hosts.get(finding.hostId);
    group.hosts.set(finding.hostId, {
      hostId: finding.hostId,
      hostname: finding.hostname,
      displayId: finding.displayId,
      reportId: finding.reportId,
      status: existingHost ? worstStatus(existingHost.status, finding.status) : finding.status,
    });

    if (finding.treatment in group.treatment) {
      group.treatment[finding.treatment as keyof Group["treatment"]] += 1;
    }
    if (finding.treatmentAssignee) group.assignees.add(finding.treatmentAssignee);
    if (finding.treatmentDueDate) group.dueDates.push(finding.treatmentDueDate);

    groups.set(finding.checkId, group);
  }

  const items: RemediationItem[] = [];
  for (const group of groups.values()) {
    const hosts = [...group.hosts.values()]
      .sort(
        (a, b) =>
          (STATUS_RANK[a.status] ?? 9) - (STATUS_RANK[b.status] ?? 9) ||
          a.displayId.localeCompare(b.displayId),
      )
      .slice(0, MAX_HOSTS);
    const dueDates = [...group.dueDates].sort();
    items.push({
      checkId: group.checkId,
      title: group.title,
      severity: group.severity,
      category: group.category,
      status: group.status,
      failingHosts: group.hosts.size,
      hostCount: reportedHosts.get(group.checkId)?.size ?? group.hosts.size,
      hosts,
      recommendation: group.recommendation,
      impact: group.impact,
      references: [...group.references].sort((a, b) => a.localeCompare(b)),
      repro: group.repro,
      exampleLocation: group.exampleLocation,
      treatmentSummary: {
        ...group.treatment,
        assignees: [...group.assignees].sort((a, b) => a.localeCompare(b)),
        nextDueDate: dueDates[0] ?? null,
      },
    });
  }

  items.sort(compareItems);
  return items;
}

export function registerRemediationRoutes(
  app: Hono<any>,
  db: Database,
  auth: RemediationAuth,
): void {
  app.get("/api/remediation", auth.requireRole(...READ_ROLES), (c) => {
    const parsed = parseRequestQuery(c);
    if (!parsed.ok) return parsed.response;
    const scoped = collectScope(db, parsed.query);
    const items = aggregateRemediation(scoped.findings);
    return c.json({
      scope: describeScope(parsed.query),
      total: items.length,
      items,
    });
  });
}
