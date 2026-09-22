// Wire types for the sealed report and dashboard API. These mirror the
// actual serialized shapes produced by the Rust extractor
// (`extractor/src/model.rs`, serde `rename_all = "camelCase"`) and the
// dashboard route responses. Keep in lock-step with those — do not invent
// aliases.

export type Severity = "Critical" | "High" | "Medium" | "Low" | "Informational";
export type Status = "Compliant" | "NonCompliant" | "NotApplicable" | "Error" | "DegradedPartial";
export type EvidenceDepth = "AuthoritativePrimary" | "AuthoritativeFallback" | "DegradedPartial";
export type TreatmentState =
  | "open"
  | "accepted_risk"
  | "false_positive"
  | "remediated";

export type FallbackAttempt = { source: string; outcome: string };

/**
 * Pinpoint evidence block as emitted today: path header, 1-based line/col,
 * a context window (`context`) with the offending line at `targetIndex`,
 * and optional Unix file metadata. The UI derives contextBefore /
 * offendingValue / contextAfter from these three fields.
 */
export type EvidenceBlock = {
  path: string;
  line: number;
  col: number;
  context: string[];
  targetIndex: number;
  fileMode?: number | null;
  fileUid?: number | null;
  fileGid?: number | null;
};

export type RunContext = { user: string; uid?: number | null; elevated: boolean };

export type CheckResult = {
  id: string;
  title: string;
  status: Status;
  severity: Severity;
  category: string;
  description: string;
  impact: string;
  recommendation: string;
  references: string[];
  evidence: string;
  location: string;
  repro: string;
  degradedReason?: string | null;
  fallbackLog: FallbackAttempt[];
  evidenceBlocks: EvidenceBlock[];
  runContext: RunContext;
  durationMs: number;
};

export type Summary = {
  compliant: number;
  nonCompliant: number;
  notApplicable: number;
  error: number;
  degraded: number;
  informational: number;
};

export type SelfAudit = { commands: string[]; filesRead: string[] };

export type ScanMeta = {
  schemaVersion: number;
  extractorVersion: string;
  extractorId: string;
  campaignId: string;
  keyId: number;
  machineId: string;
  hostname: string;
  platform: string;
  osName?: string | null;
  osVersion?: string | null;
  arch: string;
  privileged: boolean;
  privilege?: string;
  peakRssKb?: number;
  startedUnix?: number;
  durationMs?: number;
  elevationStatus?: string;
  privilegeRequested?: boolean;
  privilegeGranted?: boolean;
  privilegeRefused?: boolean;
  catalogFingerprint?: string;
};

export type Report = {
  schemaVersion: number;
  scan: ScanMeta;
  metadata: Record<string, unknown>;
  results: CheckResult[];
  summary: Summary;
  selfAudit: SelfAudit;
};

export type AuthUser = { id: number; username: string; role: "super_admin" | "auditor" | "viewer" };

export type Campaign = {
  id: number;
  name: string;
  client?: string | null;
  scope?: string | null;
  status: "active" | "completed" | "archived";
  tags: string[];
  createdAt: string;
  updatedAt: string;
};

export type Location = {
  id: number;
  campaignId: number;
  name: string;
  tags: string[];
  retiredAt: string | null;
};

export type Issuance = {
  id: string;
  extractorId: string;
  platform: string;
  artifactSha256: string;
  downloadCount: number;
  expiresAt: string | null;
  revokedAt?: string | null;
};

export type IngestLink = { campaign: string; location: string; host: string; report: string };

export type RiskTrendPoint = { date: string; score: number; reports: number };

/** Global overview response (`GET /api/overview`). */
export type OverviewMetrics = {
  scope?: { kind?: string; [key: string]: unknown };
  kpis: {
    campaignCount: number;
    activeLocations: number;
    scannedHosts: number;
    openCriticals: number;
    weightedRiskScore: number;
    coverage: number;
    totalFindings: number;
  };
  riskTrend: RiskTrendPoint[];
};

export type IngestResult =
  | { ok: true; duplicate: boolean; reportId: number; campaignId: number; locationId: number; hostId: number; links: IngestLink }
  | { ok: false; code: string };
