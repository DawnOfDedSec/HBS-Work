import { useEffect, useState, type ReactNode } from "react";
import {
  AlertTriangle,
  ArrowLeft,
  ClipboardList,
  Cpu,
  FileText,
  Gauge,
  RefreshCw,
  ShieldCheck,
} from "lucide-react";
import { api, ApiError } from "../api";
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  SectionHeader,
  Skeleton,
  Stat,
  Table,
  type TableColumn,
  useToast,
} from "../components/ui";
import { EvidenceDepthBadge, SeverityBadge, StatusBadge, TreatmentBadge } from "../components/badges";
import { EvidenceDrawer, sanitizeText, type EvidenceFinding } from "../components/EvidenceDrawer";
import type { CheckResult } from "../types";

/** `GET /api/reports/:id` returns the report document plus routing fields. */
type ReportResult = CheckResult & {
  treatment?: { state: string; assignee: string | null; dueDate: string | null; updatedAt: string | null };
};

type ReportDetailResponse = {
  id: number;
  campaignId: number;
  locationId: number;
  hostId: number;
  hostname: string | null;
  receivedAt: string;
  scanTimestamp: string | null;
  via: string | null;
  score: number | null;
  coverage: number | null;
  evidenceDepth: string | null;
  links?: Record<string, string> | null;
  scan?: {
    extractorVersion?: string;
    extractorId?: string;
    hostname?: string;
    machineId?: string;
    platform?: string;
    osName?: string | null;
    osVersion?: string | null;
    arch?: string;
    privileged?: boolean;
    privilege?: string;
    peakRssKb?: number;
    startedUnix?: number;
    durationMs?: number;
    catalogFingerprint?: string;
  } | null;
  summary?: {
    compliant: number;
    nonCompliant: number;
    notApplicable: number;
    error: number;
    degraded: number;
    informational: number;
  } | null;
  selfAudit?: { commands?: string[]; filesRead?: string[] } | null;
  results?: ReportResult[] | null;
};

export type ReportDetailProps = {
  reportId: number;
  onBack?: () => void;
  onOpenCheck?: (checkId: string) => void;
};

function asText(value: unknown): string {
  return sanitizeText(value) || "-";
}

function formatDuration(ms: number | undefined): string {
  if (typeof ms !== "number" || !Number.isFinite(ms)) return "-";
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(2)} s`;
}

function formatBytes(kb: number | undefined): string {
  if (typeof kb !== "number" || !Number.isFinite(kb)) return "-";
  if (kb < 1024) return `${kb} KiB`;
  return `${(kb / 1024).toFixed(1)} MiB`;
}

function DetailItem({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">{label}</dt>
      <dd className="mt-0.5 truncate text-sm text-ink">{value}</dd>
    </div>
  );
}

function toEvidence(result: ReportResult): EvidenceFinding {
  return {
    checkId: result.id,
    title: result.title,
    severity: result.severity,
    status: result.status,
    category: result.category,
    impact: result.impact,
    recommendation: result.recommendation,
    references: Array.isArray(result.references) ? result.references : [],
    repro: result.repro,
    evidence: result.evidence,
    degradedReason: result.degradedReason ?? null,
    fallbackLog: Array.isArray(result.fallbackLog) ? result.fallbackLog : [],
    evidenceBlocks: Array.isArray(result.evidenceBlocks) ? result.evidenceBlocks : [],
    runContext: result.runContext,
  };
}

export function ReportDetail({ reportId, onBack, onOpenCheck }: ReportDetailProps) {
  const [report, setReport] = useState<ReportDetailResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [evidence, setEvidence] = useState<EvidenceFinding | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(null);
    api
      .raw<ReportDetailResponse>("GET", `/api/reports/${reportId}`)
      .then((value) => {
        if (alive) setReport(value);
      })
      .catch((err) => {
        if (alive) setError(err instanceof ApiError ? err.message : "Request failed. Please retry.");
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [reportId, reloadKey]);

  const results = Array.isArray(report?.results) ? report.results : [];
  const summary = report?.summary;

  const columns: Array<TableColumn<ReportResult>> = [
    {
      key: "id",
      header: "Check",
      render: (row) => (
        <button
          type="button"
          onClick={() => onOpenCheck?.(row.id)}
          disabled={!onOpenCheck}
          className="rounded font-mono text-xs text-accent underline decoration-dotted underline-offset-2 hover:text-accent-strong disabled:text-ink-muted disabled:no-underline"
        >
          {sanitizeText(row.id)}
        </button>
      ),
    },
    { key: "title", header: "Title", render: (row) => sanitizeText(row.title) },
    { key: "severity", header: "Severity", render: (row) => <SeverityBadge severity={row.severity} /> },
    { key: "status", header: "Status", render: (row) => <StatusBadge status={row.status} /> },
    {
      key: "treatment",
      header: "Treatment",
      render: (row) => <TreatmentBadge state={row.treatment?.state ?? "open"} />,
    },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      align: "right",
      render: (row) => (
        <Button size="sm" variant="secondary" onClick={() => setEvidence(toEvidence(row))}>
          View
        </Button>
      ),
    },
  ];

  return (
    <section aria-label={`Report ${reportId}`} className="mx-auto flex max-w-7xl flex-col gap-5">
      <SectionHeader
        eyebrow="Report"
        title={
          report ? (
            <span>
              Report #{report.id} <span className="text-ink-muted">· {asText(report.hostname)}</span>
            </span>
          ) : (
            `Report #${reportId}`
          )
        }
        description="Server-recomputed seal: score, coverage, summary, and every check result."
        icon={FileText}
        actions={
          <>
            {report?.via ? <Badge tone="neutral">via {sanitizeText(report.via)}</Badge> : null}
            {report?.evidenceDepth ? <EvidenceDepthBadge depth={report.evidenceDepth} /> : null}
            {onBack ? (
              <Button variant="ghost" icon={ArrowLeft} onClick={onBack}>
                Back
              </Button>
            ) : null}
            <Button variant="secondary" icon={RefreshCw} loading={loading} onClick={() => setReloadKey((key) => key + 1)}>
              Refresh
            </Button>
          </>
        }
      />

      {error && !report ? (
        <EmptyState
          icon={AlertTriangle}
          title="Could not load report"
          detail={error}
          action={
            <Button variant="secondary" icon={RefreshCw} onClick={() => setReloadKey((key) => key + 1)}>
              Try again
            </Button>
          }
        />
      ) : loading && !report ? (
        <Card>
          <Skeleton width="30%" />
          <Skeleton className="mt-3" width="60%" height={28} />
          <Skeleton className="mt-3" width="100%" />
        </Card>
      ) : !report ? (
        <EmptyState title="Report not available" />
      ) : (
        <>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <Stat
              label="Risk score"
              value={report.score === null ? "-" : report.score.toFixed(1)}
              icon={Gauge}
              tone={report.score === null ? "default" : report.score >= 80 ? "ok" : report.score >= 50 ? "default" : "high"}
              hint="Server-authoritative"
            />
            <Stat
              label="Coverage"
              value={report.coverage === null ? "-" : `${report.coverage.toFixed(1)}%`}
              icon={ShieldCheck}
              hint="Decided / applicable"
            />
            <Stat label="Results" value={results.length} icon={ClipboardList} hint="Checks in this seal" />
            <Stat
              label="Received"
              value={<span className="text-base">{asText(report.receivedAt)}</span>}
              icon={FileText}
              hint={report.scanTimestamp ? `Scanned ${asText(report.scanTimestamp)}` : "Scan time unavailable"}
            />
          </div>

          {report.scan ? (
            <Card>
              <CardHeader icon={Cpu} title="Scan context" description="Extractor, platform, and privilege metadata." />
              <CardBody>
                <dl className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-4">
                  <DetailItem label="Extractor" value={asText(report.scan.extractorVersion)} />
                  <DetailItem
                    label="Platform"
                    value={sanitizeText([report.scan.platform, report.scan.arch].filter(Boolean).join(" · ")) || "-"}
                  />
                  <DetailItem
                    label="OS"
                    value={sanitizeText([report.scan.osName, report.scan.osVersion].filter(Boolean).join(" ")) || "-"}
                  />
                  <DetailItem
                    label="Privilege"
                    value={asText(report.scan.privilege ?? (report.scan.privileged ? "elevated" : "not-needed"))}
                  />
                  <DetailItem label="Duration" value={formatDuration(report.scan.durationMs)} />
                  <DetailItem label="Peak RSS" value={formatBytes(report.scan.peakRssKb)} />
                  <DetailItem label="Machine ID" value={<span className="font-mono text-xs">{asText(report.scan.machineId).slice(0, 24)}</span>} />
                  <DetailItem label="Catalog" value={<span className="font-mono text-xs">{asText(report.scan.catalogFingerprint).slice(0, 16)}</span>} />
                </dl>
              </CardBody>
            </Card>
          ) : null}

          {summary ? (
            <Card>
              <CardHeader icon={ClipboardList} title="Summary" description="Status counts recomputed at ingest." />
              <CardBody className="flex flex-wrap gap-2">
                <Badge tone="compliant">{summary.compliant} compliant</Badge>
                <Badge tone={summary.nonCompliant > 0 ? "noncompliant" : "na"}>{summary.nonCompliant} non-compliant</Badge>
                <Badge tone={summary.degraded > 0 ? "degraded" : "na"}>{summary.degraded} degraded</Badge>
                <Badge tone={summary.error > 0 ? "error" : "na"}>{summary.error} error</Badge>
                <Badge tone="na">{summary.notApplicable} n/a</Badge>
                <Badge tone="info">{summary.informational} informational</Badge>
              </CardBody>
            </Card>
          ) : null}

          <Card flush className="overflow-hidden">
            <div className="p-4">
              <CardHeader
                title={`Results (${results.length})`}
                description="Select a check for its cross-host pivot or open its pinned evidence."
                icon={ClipboardList}
              />
            </div>
            {results.length === 0 ? (
              <div className="p-4">
                <EmptyState title="No check results match the current filters" />
              </div>
            ) : (
              <Table
                label="Check results in this report"
                columns={columns}
                rows={results}
                rowKey={(row) => row.id}
                stickyHeader
              />
            )}
          </Card>

          {report.selfAudit ? (
            <Card>
              <CardHeader icon={ShieldCheck} title="Self-audit" description="Commands attempted and files read on the scanned host." />
              <CardBody>
                <p className="text-sm text-ink-muted">
                  <span className="tabular-nums text-ink">{report.selfAudit.commands?.length ?? 0}</span> command attempts ·{" "}
                  <span className="tabular-nums text-ink">{report.selfAudit.filesRead?.length ?? 0}</span> file reads recorded on the
                  scanned host.
                </p>
                {(report.selfAudit.commands?.length ?? 0) > 0 || (report.selfAudit.filesRead?.length ?? 0) > 0 ? (
                  <details className="mt-2">
                    <summary className="cursor-pointer text-xs text-ink-muted">Show redacted audit entries</summary>
                    <ul className="hbs-scroll mt-2 max-h-56 space-y-1 overflow-y-auto font-mono text-xs text-ink-muted">
                      {(report.selfAudit.commands ?? []).map((entry, index) => (
                        <li key={`cmd-${index}`}>cmd: {sanitizeText(entry)}</li>
                      ))}
                      {(report.selfAudit.filesRead ?? []).map((entry, index) => (
                        <li key={`file-${index}`}>file: {sanitizeText(entry)}</li>
                      ))}
                    </ul>
                  </details>
                ) : null}
              </CardBody>
            </Card>
          ) : null}
        </>
      )}

      <EvidenceDrawer
        open={evidence !== null}
        finding={evidence}
        reportId={report?.id ?? reportId}
        hostname={report?.hostname ?? null}
        onClose={() => setEvidence(null)}
      />
    </section>
  );
}
