import { useEffect, useState } from "react";
import { api, ApiError } from "../api";
import { EmptyState } from "../components/EmptyState";
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
  return sanitizeText(value) || "—";
}

function formatDuration(ms: number | undefined): string {
  if (typeof ms !== "number" || !Number.isFinite(ms)) return "—";
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(2)} s`;
}

function formatBytes(kb: number | undefined): string {
  if (typeof kb !== "number" || !Number.isFinite(kb)) return "—";
  if (kb < 1024) return `${kb} KiB`;
  return `${(kb / 1024).toFixed(1)} MiB`;
}

export function ReportDetail({ reportId, onBack, onOpenCheck }: ReportDetailProps) {
  const [report, setReport] = useState<ReportDetailResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [evidence, setEvidence] = useState<EvidenceFinding | null>(null);

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
  }, [reportId]);

  if (error) return <EmptyState title="Could not load report" detail={error} />;
  if (loading && !report) return <p role="status">Loading report…</p>;
  if (!report) return <EmptyState title="Report not available" />;

  const results = Array.isArray(report.results) ? report.results : [];
  const summary = report.summary;

  return (
    <section aria-label={`Report ${reportId}`} className="space-y-5">
      <div className="flex flex-wrap items-center gap-3">
        {onBack ? (
          <button
            type="button"
            onClick={onBack}
            className="rounded border border-slate-700 px-2 py-1 text-sm hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
          >
            ← Back
          </button>
        ) : null}
        <h2 className="text-lg font-semibold">
          Report #{report.id} · {asText(report.hostname)}
        </h2>
        {report.via ? (
          <span className="rounded border border-slate-700 px-2 py-0.5 text-xs text-slate-300">
            via {sanitizeText(report.via)}
          </span>
        ) : null}
        {report.evidenceDepth ? (
          <span className="rounded border border-slate-700 px-2 py-0.5 text-xs text-slate-300">
            {sanitizeText(report.evidenceDepth)}
          </span>
        ) : null}
      </div>

      <dl className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4">
        <Metric label="Score" value={report.score === null ? "—" : report.score.toFixed(1)} />
        <Metric label="Coverage" value={report.coverage === null ? "—" : `${report.coverage.toFixed(1)}%`} />
        <Metric label="Received" value={asText(report.receivedAt)} />
        <Metric label="Scan timestamp" value={asText(report.scanTimestamp)} />
      </dl>

      {report.scan ? (
        <section aria-labelledby="report-scan" className="rounded-lg border border-slate-800 p-3">
          <h3 id="report-scan" className="text-xs font-semibold uppercase tracking-wide text-slate-400">
            Scan context
          </h3>
          <dl className="mt-2 grid grid-cols-2 gap-3 text-xs sm:grid-cols-3 lg:grid-cols-4">
            <Metric label="Extractor" value={asText(report.scan.extractorVersion)} />
            <Metric
              label="Platform"
              value={sanitizeText([report.scan.platform, report.scan.arch].filter(Boolean).join(" · ")) || "—"}
            />
            <Metric
              label="OS"
              value={
                sanitizeText([report.scan.osName, report.scan.osVersion].filter(Boolean).join(" ")) || "—"
              }
            />
            <Metric label="Privilege" value={asText(report.scan.privilege ?? (report.scan.privileged ? "elevated" : "not-needed"))} />
            <Metric label="Duration" value={formatDuration(report.scan.durationMs)} />
            <Metric label="Peak RSS" value={formatBytes(report.scan.peakRssKb)} />
            <Metric label="Machine ID" value={asText(report.scan.machineId).slice(0, 24)} />
            <Metric label="Catalog" value={asText(report.scan.catalogFingerprint).slice(0, 16)} />
          </dl>
        </section>
      ) : null}

      {summary ? (
        <section aria-labelledby="report-summary" className="rounded-lg border border-slate-800 p-3">
          <h3 id="report-summary" className="text-xs font-semibold uppercase tracking-wide text-slate-400">
            Summary
          </h3>
          <dl className="mt-2 grid grid-cols-3 gap-3 text-xs sm:grid-cols-6">
            <Metric label="Compliant" value={summary.compliant} />
            <Metric label="Non-compliant" value={summary.nonCompliant} />
            <Metric label="N/A" value={summary.notApplicable} />
            <Metric label="Degraded" value={summary.degraded} />
            <Metric label="Error" value={summary.error} />
            <Metric label="Informational" value={summary.informational} />
          </dl>
        </section>
      ) : null}

      <section aria-labelledby="report-results">
        <h3 id="report-results" className="mb-2 text-sm font-semibold">
          Results ({results.length})
        </h3>
        {results.length === 0 ? (
          <EmptyState title="No check results match the current filters" />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-sm">
              <caption className="sr-only">Check results in this report</caption>
              <thead>
                <tr className="text-left text-slate-400">
                  <th scope="col" className="border-b border-slate-800 py-2 pr-3">Check</th>
                  <th scope="col" className="border-b border-slate-800 py-2 pr-3">Title</th>
                  <th scope="col" className="border-b border-slate-800 py-2 pr-3">Severity</th>
                  <th scope="col" className="border-b border-slate-800 py-2 pr-3">Status</th>
                  <th scope="col" className="border-b border-slate-800 py-2 pr-3">Treatment</th>
                  <th scope="col" className="border-b border-slate-800 py-2">Evidence</th>
                </tr>
              </thead>
              <tbody>
                {results.map((result) => (
                  <tr key={result.id} className="align-top">
                    <td className="border-b border-slate-900 py-2 pr-3">
                      <button
                        type="button"
                        onClick={() => onOpenCheck?.(result.id)}
                        disabled={!onOpenCheck}
                        className="font-mono text-sky-300 underline underline-offset-2 disabled:text-slate-300 disabled:no-underline focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
                      >
                        {sanitizeText(result.id)}
                      </button>
                    </td>
                    <td className="border-b border-slate-900 py-2 pr-3">{sanitizeText(result.title)}</td>
                    <td className="border-b border-slate-900 py-2 pr-3">{sanitizeText(result.severity)}</td>
                    <td className="border-b border-slate-900 py-2 pr-3">{sanitizeText(result.status)}</td>
                    <td className="border-b border-slate-900 py-2 pr-3">
                      {sanitizeText(result.treatment?.state ?? "open")}
                    </td>
                    <td className="border-b border-slate-900 py-2">
                      <button
                        type="button"
                        onClick={() =>
                          setEvidence({
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
                          })
                        }
                        className="rounded border border-slate-700 px-2 py-0.5 text-xs hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
                      >
                        View
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {report.selfAudit ? (
        <section aria-labelledby="report-audit" className="rounded-lg border border-slate-800 p-3 text-sm">
          <h3 id="report-audit" className="text-xs font-semibold uppercase tracking-wide text-slate-400">
            Self-audit
          </h3>
          <p className="mt-1 text-slate-300">
            {report.selfAudit.commands?.length ?? 0} command attempts ·{" "}
            {report.selfAudit.filesRead?.length ?? 0} file reads recorded on the scanned host.
          </p>
          {(report.selfAudit.commands?.length ?? 0) > 0 || (report.selfAudit.filesRead?.length ?? 0) > 0 ? (
            <details className="mt-2">
              <summary className="cursor-pointer text-xs text-slate-400">Show redacted audit entries</summary>
              <ul className="mt-2 space-y-1 font-mono text-xs text-slate-300">
                {(report.selfAudit.commands ?? []).map((entry, index) => (
                  <li key={`cmd-${index}`}>cmd: {sanitizeText(entry)}</li>
                ))}
                {(report.selfAudit.filesRead ?? []).map((entry, index) => (
                  <li key={`file-${index}`}>file: {sanitizeText(entry)}</li>
                ))}
              </ul>
            </details>
          ) : null}
        </section>
      ) : null}

      <EvidenceDrawer
        open={evidence !== null}
        finding={evidence}
        reportId={report.id}
        hostname={report.hostname}
        onClose={() => setEvidence(null)}
      />
    </section>
  );
}

function Metric({ label, value }: { label: string; value: string | number }) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-wide text-slate-500">{label}</dt>
      <dd className="mt-0.5 font-medium tabular-nums text-slate-100">{value}</dd>
    </div>
  );
}
