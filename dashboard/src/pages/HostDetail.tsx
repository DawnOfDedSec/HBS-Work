import { useEffect, useState } from "react";
import { ArrowLeft, Clock, Server } from "lucide-react";
import { api, ApiError } from "../api";
import { EmptyState } from "../components/EmptyState";
import { SEVERITY_ORDER, StatusLabel, severityColor } from "../components/charts/TableTwin";

export type HostIdentity = {
  id: number;
  machineId: string;
  hostname: string | null;
  displayId: string;
  platform: string | null;
  os: string | null;
  arch: string | null;
  firstSeenAt: string;
  lastSeenAt: string;
  latestReportId: number | null;
  latestReceivedAt: string | null;
  riskScore: number | null;
  coverage: number | null;
};

export type HostLocation = {
  id: number;
  name: string;
  campaignId: number;
  firstSeenAt: string;
  lastSeenAt: string;
  links: { location: string };
};

export type HostReportRow = {
  id: number;
  campaignId: number;
  locationId: number;
  hostId: number;
  hostname: string | null;
  extractorVersion: string | null;
  scanTimestamp: string | null;
  receivedAt: string;
  via: string | null;
  score: number | null;
  coverage: number | null;
  privilegeLevel: string | null;
  evidenceDepth: string | null;
  bytes: number | null;
  links: Record<string, string>;
};

export type HostFindingRow = {
  checkId: string;
  title: string;
  status: string;
  severity: string;
  category: string;
};

export type HostDetailResponse = {
  host: HostIdentity;
  locations: HostLocation[];
  reports: HostReportRow[];
  findings: HostFindingRow[];
  summary: {
    severity: Record<string, number>;
    treatment: Record<string, number>;
  };
};

/** Check statuses in descending severity of concern. */
const STATUS_ORDER = ["NonCompliant", "DegradedPartial", "Error", "Compliant", "NotApplicable"];

export type HostDetailProps = {
  hostId: number;
  onBack?: () => void;
};

function formatTimestamp(value: string | null): string {
  if (!value) return "—";
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? new Date(parsed).toLocaleString() : value;
}

/** Host identity, every location it was seen in, and its report timeline. */
export function HostDetail({ hostId, onBack }: HostDetailProps) {
  const [data, setData] = useState<HostDetailResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(null);
    api
      .raw<HostDetailResponse>("GET", `/api/hosts/${hostId}`)
      .then((response) => {
        if (alive) setData(response);
      })
      .catch((err) => {
        if (alive) setError(err instanceof ApiError ? err.message : "failed to load host");
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [hostId]);

  if (error) return <EmptyState title="Could not load host" detail={error} />;
  if (loading && !data) return <p role="status">Loading host…</p>;
  if (!data) return <EmptyState title="No host available" />;

  const { host, locations, reports, findings, summary } = data;

  const statusCounts = new Map<string, number>();
  for (const finding of findings) {
    statusCounts.set(finding.status, (statusCounts.get(finding.status) ?? 0) + 1);
  }
  const statusRows = STATUS_ORDER.filter((status) => (statusCounts.get(status) ?? 0) > 0).map(
    (status) => ({ status, count: statusCounts.get(status) ?? 0 }),
  );

  return (
    <section aria-label={`Host ${host.displayId}`} className="space-y-5">
      <div className="flex items-center gap-3">
        {onBack ? (
          <button
            type="button"
            onClick={onBack}
            className="inline-flex items-center gap-1 rounded border border-slate-700 px-2 py-1 text-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
          >
            <ArrowLeft size={14} aria-hidden /> Back
          </button>
        ) : null}
        <h2 className="text-lg font-semibold">{host.displayId}</h2>
      </div>

      <div className="grid gap-3 rounded-lg border border-slate-800 bg-slate-900/50 p-4 sm:grid-cols-2 lg:grid-cols-4">
        <div>
          <div className="text-xs uppercase tracking-wide text-slate-400">Hostname</div>
          <div className="mt-0.5 inline-flex items-center gap-1">
            <Server size={14} aria-hidden /> {host.hostname ?? "—"}
          </div>
        </div>
        <div>
          <div className="text-xs uppercase tracking-wide text-slate-400">Machine ID</div>
          <div className="mt-0.5 break-all font-mono text-xs">{host.machineId}</div>
        </div>
        <div>
          <div className="text-xs uppercase tracking-wide text-slate-400">Platform</div>
          <div className="mt-0.5">
            {host.platform ?? "—"} {host.arch ? `· ${host.arch}` : ""}
          </div>
        </div>
        <div>
          <div className="text-xs uppercase tracking-wide text-slate-400">OS</div>
          <div className="mt-0.5">{host.os ?? "—"}</div>
        </div>
        <div>
          <div className="text-xs uppercase tracking-wide text-slate-400">First seen</div>
          <div className="mt-0.5">{formatTimestamp(host.firstSeenAt)}</div>
        </div>
        <div>
          <div className="text-xs uppercase tracking-wide text-slate-400">Last seen</div>
          <div className="mt-0.5">{formatTimestamp(host.lastSeenAt)}</div>
        </div>
        <div>
          <div className="text-xs uppercase tracking-wide text-slate-400">Risk score</div>
          <div className="mt-0.5 tabular-nums">{host.riskScore === null ? "—" : host.riskScore.toFixed(1)}</div>
        </div>
        <div>
          <div className="text-xs uppercase tracking-wide text-slate-400">Coverage</div>
          <div className="mt-0.5 tabular-nums">{host.coverage === null ? "—" : `${host.coverage.toFixed(1)}%`}</div>
        </div>
      </div>

      <section aria-label="Severity summary" className="rounded-lg border border-slate-800 p-4">
        <h3 className="text-sm font-medium">Findings by severity</h3>
        <ul className="mt-2 flex flex-wrap gap-2">
          {SEVERITY_ORDER.map((severity) => (
            <li
              key={severity}
              className="inline-flex items-center gap-1 rounded border border-slate-700 px-2 py-0.5 text-xs"
            >
              <span
                aria-hidden
                className="inline-block h-2 w-2 rounded-full"
                style={{ backgroundColor: severityColor(severity) }}
              />
              {severity}: <span className="tabular-nums">{summary.severity[severity] ?? 0}</span>
            </li>
          ))}
        </ul>
      </section>

      <section aria-label="Check status summary" className="rounded-lg border border-slate-800 p-4">
        <h3 className="text-sm font-medium">Checks by status</h3>
        {statusRows.length === 0 ? (
          <p className="mt-1 text-sm text-slate-400">No check results in this scope.</p>
        ) : (
          <ul className="mt-2 flex flex-wrap gap-3">
            {statusRows.map((row) => (
              <li key={row.status} className="inline-flex items-center gap-1">
                <StatusLabel status={row.status} />
                <span className="tabular-nums text-xs text-slate-300">{row.count}</span>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section aria-label="Locations" className="space-y-2">
        <h3 className="text-sm font-medium">Locations</h3>
        {locations.length === 0 ? (
          <EmptyState title="No location history" />
        ) : (
          <ul className="grid gap-2 sm:grid-cols-2">
            {locations.map((location) => (
              <li key={`${location.campaignId}-${location.id}`} className="rounded border border-slate-800 p-3 text-sm">
                <a
                  href={location.links.location}
                  className="font-medium text-sky-300 underline focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
                >
                  {location.name}
                </a>
                <div className="mt-1 text-xs text-slate-400">
                  Campaign #{location.campaignId} · last seen {formatTimestamp(location.lastSeenAt)}
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section aria-label="Report timeline" className="space-y-2">
        <h3 className="text-sm font-medium">Report timeline</h3>
        {reports.length === 0 ? (
          <EmptyState title="No reports for this host" />
        ) : (
          <ol className="space-y-2">
            {reports.map((report) => (
              <li key={report.id} className="rounded border border-slate-800 bg-slate-900/40 p-3 text-sm">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <a
                    href={report.links.report}
                    className="font-medium text-sky-300 underline focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
                  >
                    Report #{report.id}
                  </a>
                  <span className="inline-flex items-center gap-1 text-xs text-slate-400">
                    <Clock size={12} aria-hidden /> {formatTimestamp(report.receivedAt)}
                  </span>
                </div>
                <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-400">
                  <span>via {report.via ?? "—"}</span>
                  <span>extractor {report.extractorVersion ?? "—"}</span>
                  <span>scan {formatTimestamp(report.scanTimestamp)}</span>
                  <span>score {report.score === null ? "—" : report.score.toFixed(1)}</span>
                  <span>coverage {report.coverage === null ? "—" : `${report.coverage.toFixed(1)}%`}</span>
                  <span>privilege {report.privilegeLevel ?? "—"}</span>
                  <span>evidence {report.evidenceDepth ?? "—"}</span>
                </div>
              </li>
            ))}
          </ol>
        )}
      </section>
    </section>
  );
}
