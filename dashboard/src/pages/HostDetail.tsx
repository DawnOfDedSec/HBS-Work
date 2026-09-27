import { useEffect, useState } from "react";
import {
  AlertTriangle,
  ArrowLeft,
  Clock,
  Cpu,
  MapPin,
  RefreshCw,
  Server,
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
  useToast,
} from "../components/ui";
import { PlatformBadge } from "../components/badges";
import { SEVERITY_ORDER, StatusLabel, severityColor } from "../components/charts/TableTwin";
import { sanitizeText } from "../components/EvidenceDrawer";

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
  if (!value) return "-";
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? new Date(parsed).toLocaleString() : sanitizeText(value);
}

function formatBytes(value: number | null): string {
  if (value === null || !Number.isFinite(value)) return "-";
  if (value < 1024) return `${value} B`;
  const units = ["KiB", "MiB", "GiB"];
  let size = value / 1024;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(1)} ${units[unit]}`;
}

/** Host identity, every location it was seen in, and its report timeline. */
export function HostDetail({ hostId, onBack }: HostDetailProps) {
  const [data, setData] = useState<HostDetailResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [reloadKey, setReloadKey] = useState(0);
  const toast = useToast();

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
        if (!alive) return;
        const message = err instanceof ApiError ? err.message : "failed to load host";
        setError(message);
        toast.error("Could not load host", { description: message });
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [hostId, reloadKey, toast]);

  const host = data?.host;
  const locations = data?.locations ?? [];
  const reports = data?.reports ?? [];
  const findings = data?.findings ?? [];
  const summary = data?.summary;

  const statusCounts = new Map<string, number>();
  for (const finding of findings) {
    statusCounts.set(finding.status, (statusCounts.get(finding.status) ?? 0) + 1);
  }
  const statusRows = STATUS_ORDER.filter((status) => (statusCounts.get(status) ?? 0) > 0).map((status) => ({
    status,
    count: statusCounts.get(status) ?? 0,
  }));

  return (
    <section aria-label={host ? `Host ${host.displayId}` : `Host ${hostId}`} className="mx-auto flex max-w-7xl flex-col gap-5">
      <SectionHeader
        eyebrow="Host"
        title={host ? sanitizeText(host.displayId) : `Host #${hostId}`}
        description="Identity, location history, and the full report timeline."
        icon={Server}
        actions={
          <>
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

      {error && !data ? (
        <EmptyState
          icon={AlertTriangle}
          title="Could not load host"
          detail={error}
          action={
            <Button variant="secondary" icon={RefreshCw} onClick={() => setReloadKey((key) => key + 1)}>
              Try again
            </Button>
          }
        />
      ) : loading && !data ? (
        <Card>
          <Skeleton width="30%" />
          <Skeleton className="mt-3" width="100%" />
        </Card>
      ) : !host ? (
        <EmptyState title="No host available" />
      ) : (
        <>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <Stat
              label="Risk score"
              value={host.riskScore === null ? "-" : host.riskScore.toFixed(1)}
              tone={host.riskScore === null ? "default" : host.riskScore >= 80 ? "ok" : host.riskScore >= 50 ? "default" : "high"}
              hint="Latest report"
            />
            <Stat
              label="Coverage"
              value={host.coverage === null ? "-" : `${host.coverage.toFixed(1)}%`}
              tone={host.coverage !== null && host.coverage >= 90 ? "ok" : "default"}
              hint="Authoritative decided"
            />
            <Stat label="Reports" value={reports.length} icon={Clock} hint={formatTimestamp(host.lastSeenAt)} />
            <Stat label="Findings" value={findings.length} icon={Server} hint={`${locations.length} location(s)`} />
          </div>

          <Card>
            <CardHeader icon={Server} title="Identity" description="Stable machine identity and platform metadata." />
            <CardBody>
              <dl className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-4">
                <div className="min-w-0">
                  <dt className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">Hostname</dt>
                  <dd className="mt-0.5 truncate text-sm text-ink">{sanitizeText(host.hostname) || "-"}</dd>
                </div>
                <div className="min-w-0">
                  <dt className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">Machine ID</dt>
                  <dd className="mt-0.5 truncate font-mono text-xs text-ink-muted">{sanitizeText(host.machineId)}</dd>
                </div>
                <div>
                  <dt className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">Platform</dt>
                  <dd className="mt-0.5 flex items-center gap-2">
                    <PlatformBadge platform={host.platform} />
                    {host.arch ? <span className="text-xs text-ink-muted">{sanitizeText(host.arch)}</span> : null}
                  </dd>
                </div>
                <div className="min-w-0">
                  <dt className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">OS</dt>
                  <dd className="mt-0.5 truncate text-sm text-ink">{sanitizeText(host.os) || "-"}</dd>
                </div>
                <div>
                  <dt className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">First seen</dt>
                  <dd className="mt-0.5 text-sm text-ink">{formatTimestamp(host.firstSeenAt)}</dd>
                </div>
                <div>
                  <dt className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">Last seen</dt>
                  <dd className="mt-0.5 text-sm text-ink">{formatTimestamp(host.lastSeenAt)}</dd>
                </div>
                <div>
                  <dt className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">Latest report</dt>
                  <dd className="mt-0.5 text-sm text-ink">
                    {host.latestReportId === null ? "-" : `#${host.latestReportId}`}
                    {host.latestReceivedAt ? ` · ${formatTimestamp(host.latestReceivedAt)}` : ""}
                  </dd>
                </div>
                <div>
                  <dt className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">Campaign</dt>
                  <dd className="mt-0.5 text-sm text-ink">{reports[0] ? `#${reports[0].campaignId}` : "-"}</dd>
                </div>
              </dl>
            </CardBody>
          </Card>

          <div className="grid gap-4 lg:grid-cols-2">
            <Card>
              <CardHeader icon={AlertTriangle} title="Findings by severity" description="Across the latest report per location." />
              <CardBody>
                <ul className="flex flex-wrap gap-2">
                  {SEVERITY_ORDER.map((severity) => (
                    <li key={severity}>
                      <span className="inline-flex items-center gap-1.5 rounded-full border border-hairline bg-surface-raised px-2.5 py-1 text-xs text-ink-muted">
                        <span
                          aria-hidden
                          className="inline-block h-2 w-2 rounded-full"
                          style={{ backgroundColor: severityColor(severity) }}
                        />
                        {severity}: <span className="tabular-nums text-ink">{summary?.severity[severity] ?? 0}</span>
                      </span>
                    </li>
                  ))}
                </ul>
              </CardBody>
            </Card>

            <Card>
              <CardHeader icon={Cpu} title="Checks by status" description="Authoritative status distribution." />
              <CardBody>
                {statusRows.length === 0 ? (
                  <p className="text-sm text-ink-muted">No check results in this scope.</p>
                ) : (
                  <ul className="flex flex-wrap gap-3">
                    {statusRows.map((row) => (
                      <li key={row.status} className="inline-flex items-center gap-1.5">
                        <StatusLabel status={row.status} />
                        <span className="tabular-nums text-xs text-ink">{row.count}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </CardBody>
            </Card>
          </div>

          <Card>
            <CardHeader
              icon={MapPin}
              title="Locations"
              description="Every campaign/location this machine has been seen in."
            />
            <CardBody>
              {locations.length === 0 ? (
                <EmptyState title="No location history" />
              ) : (
                <ul className="grid gap-2 sm:grid-cols-2">
                  {locations.map((location) => (
                    <li key={`${location.campaignId}-${location.id}`} className="hbs-inset flex flex-col gap-1 p-3">
                      <a href={location.links.location} className="text-sm font-medium text-accent underline decoration-dotted underline-offset-2">
                        {sanitizeText(location.name)}
                      </a>
                      <span className="text-2xs text-ink-subtle">
                        Campaign #{location.campaignId} · last seen {formatTimestamp(location.lastSeenAt)}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </CardBody>
          </Card>

          <Card flush className="overflow-hidden">
            <div className="p-4">
              <CardHeader
                icon={Clock}
                title="Report timeline"
                description="Newest first. Select a report to open its sealed detail."
                actions={<Badge tone="accent">{reports.length} reports</Badge>}
              />
            </div>
            {reports.length === 0 ? (
              <div className="p-4">
                <EmptyState title="No reports for this host" />
              </div>
            ) : (
              <ol className="flex flex-col">
                {reports.map((report) => (
                  <li key={report.id} className="flex flex-col gap-2 border-b border-hairline-soft p-4 last:border-b-0">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <a
                        href={report.links.report}
                        className="inline-flex items-center gap-2 text-sm font-medium text-accent underline decoration-dotted underline-offset-2"
                      >
                        <Clock size={14} aria-hidden /> Report #{report.id}
                      </a>
                      <div className="flex flex-wrap items-center gap-2">
                        {report.score !== null ? <Badge tone="accent">risk {report.score.toFixed(1)}</Badge> : null}
                        {report.coverage !== null ? <Badge tone="neutral">coverage {report.coverage.toFixed(1)}%</Badge> : null}
                        <span className="text-2xs text-ink-subtle">{formatTimestamp(report.receivedAt)}</span>
                      </div>
                    </div>
                    <div className="flex flex-wrap gap-x-4 gap-y-1 text-2xs text-ink-subtle">
                      <span>via {sanitizeText(report.via) || "-"}</span>
                      <span>extractor {sanitizeText(report.extractorVersion) || "-"}</span>
                      <span>scan {formatTimestamp(report.scanTimestamp)}</span>
                      <span>privilege {sanitizeText(report.privilegeLevel) || "-"}</span>
                      <span>evidence {sanitizeText(report.evidenceDepth) || "-"}</span>
                      <span>size {formatBytes(report.bytes)}</span>
                    </div>
                  </li>
                ))}
              </ol>
            )}
          </Card>
        </>
      )}
    </section>
  );
}
