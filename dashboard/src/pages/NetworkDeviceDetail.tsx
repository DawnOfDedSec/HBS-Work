// Network device detail: identity, review score, findings with treatment,
// and the configuration report timeline. Mirrors HostDetail's structure.

import { useEffect, useState } from "react";
import {
  AlertTriangle,
  ArrowDownRight,
  ArrowLeft,
  ArrowUpRight,
  Clock,
  Download,
  GitCompareArrows,
  Network,
  RefreshCw,
  Server,
  Trash2,
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
import { NetworkFindingsTable, scoreTone } from "../components/NetworkFindings";
import { SEVERITY_ORDER, severityColor } from "../components/charts/TableTwin";
import { sanitizeText } from "../components/EvidenceDrawer";
import type { NetworkDeviceDetail as NetworkDeviceData, NetworkDiffResponse } from "../network-types";

export type NetworkDeviceDetailProps = {
  deviceId: number;
  canEdit: boolean;
  canDelete?: boolean;
  onBack?: () => void;
  onOpenReport?: (reportId: number) => void;
  onDeleted?: () => void;
};

function formatTimestamp(value: string | null | undefined): string {
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

function download(url: string): void {
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.rel = "noopener";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
}

/** Configuration drift between the two most recent review runs. */
function DiffCard({ deviceId, onOpenReport }: { deviceId: number; onOpenReport?: (reportId: number) => void }) {
  const [diff, setDiff] = useState<NetworkDiffResponse>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(false);
    api
      .getNetworkDiff(deviceId)
      .then((response) => alive && setDiff(response))
      .catch(() => alive && setError(true))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [deviceId]);

  if (loading) {
    return (
      <Card>
        <Skeleton width="40%" />
        <Skeleton className="mt-3" width="100%" />
      </Card>
    );
  }
  if (error || !diff) return null;
  const scoreDelta = (diff.to.score ?? 0) - (diff.from.score ?? 0);

  return (
    <Card>
      <CardHeader
        icon={GitCompareArrows}
        title="Configuration drift"
        description={`Report #${diff.from.reportId} → #${diff.to.reportId} · ${formatTimestamp(diff.to.receivedAt)}`}
        actions={
          <span className="inline-flex items-center gap-2">
            <Badge tone={scoreDelta > 0 ? "compliant" : scoreDelta < 0 ? "critical" : "neutral"}>
              {scoreDelta > 0 ? "+" : ""}
              {scoreDelta.toFixed(1)} score
            </Badge>
            <Badge tone="neutral">{diff.unchangedCount} unchanged</Badge>
          </span>
        }
      />
      <CardBody>
        <div className="grid gap-4 md:grid-cols-3">
          <div className="hbs-inset rounded-control p-3">
            <h4 className="flex items-center gap-1.5 text-2xs font-semibold uppercase tracking-wide text-ink-subtle">
              <ArrowUpRight size={12} aria-hidden /> Fixed ({diff.fixed.length})
            </h4>
            <ul className="mt-2 flex flex-col gap-1">
              {diff.fixed.slice(0, 6).map((entry) => (
                <li key={entry.checkId} className="text-2xs text-ink-muted">
                  <span className="font-mono">{entry.checkId}</span> {sanitizeText(entry.title)}
                </li>
              ))}
              {diff.fixed.length === 0 ? <li className="text-2xs text-ink-subtle">None</li> : null}
            </ul>
          </div>
          <div className="hbs-inset rounded-control p-3">
            <h4 className="flex items-center gap-1.5 text-2xs font-semibold uppercase tracking-wide text-ink-subtle">
              <ArrowDownRight size={12} aria-hidden /> Regressed ({diff.regressed.length})
            </h4>
            <ul className="mt-2 flex flex-col gap-1">
              {diff.regressed.slice(0, 6).map((entry) => (
                <li key={entry.checkId} className="text-2xs text-ink-muted">
                  <span className="font-mono">{entry.checkId}</span> {sanitizeText(entry.title)}
                </li>
              ))}
              {diff.regressed.length === 0 ? <li className="text-2xs text-ink-subtle">None</li> : null}
            </ul>
          </div>
          <div className="hbs-inset rounded-control p-3">
            <h4 className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">Changed ({diff.changed.length})</h4>
            <ul className="mt-2 flex flex-col gap-1">
              {diff.changed.slice(0, 6).map((entry) => (
                <li key={entry.checkId} className="text-2xs text-ink-muted">
                  <span className="font-mono">{entry.checkId}</span> {sanitizeText(entry.from)} → {sanitizeText(entry.to)}
                </li>
              ))}
              {diff.changed.length === 0 ? <li className="text-2xs text-ink-subtle">None</li> : null}
            </ul>
          </div>
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          <Button size="sm" variant="ghost" onClick={() => onOpenReport?.(diff.from.reportId)}>
            Open older report
          </Button>
          <Button size="sm" variant="ghost" onClick={() => onOpenReport?.(diff.to.reportId)}>
            Open newer report
          </Button>
        </div>
      </CardBody>
    </Card>
  );
}

/** One reviewed network device alongside the hosts of its location. */
export function NetworkDeviceDetail({ deviceId, canEdit, canDelete = false, onBack, onOpenReport, onDeleted }: NetworkDeviceDetailProps) {
  const [data, setData] = useState<NetworkDeviceData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [reloadKey, setReloadKey] = useState(0);
  const [deleting, setDeleting] = useState(false);
  const toast = useToast();

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(null);
    api
      .getNetworkDevice(deviceId)
      .then((response) => alive && setData(response))
      .catch((err) => {
        if (!alive) return;
        const message = err instanceof ApiError ? err.message : "failed to load device";
        setError(message);
        toast.error("Could not load device", { description: message });
      })
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [deviceId, reloadKey, toast]);

  const device = data?.device;
  const latest = data?.latest ?? null;
  const reports = data?.reports ?? [];
  const severity = latest?.severity ?? data?.summary.severity;

  async function removeDevice() {
    if (!device) return;
    setDeleting(true);
    try {
      await api.deleteNetworkDevice(device.id);
      toast.info("Device deleted", { description: sanitizeText(device.hostname) || `#${device.id}` });
      onDeleted?.();
      onBack?.();
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "could not delete device";
      toast.error("Could not delete device", { description: message });
    } finally {
      setDeleting(false);
    }
  }

  return (
    <section aria-label={device ? `Device ${device.hostname ?? device.id}` : `Device ${deviceId}`} className="mx-auto flex max-w-7xl flex-col gap-5">
      <SectionHeader
        eyebrow="Network device"
        title={device ? sanitizeText(device.hostname) || `Device #${device.id}` : `Device #${deviceId}`}
        description="Configuration review findings, treatment state, and upload history."
        icon={Network}
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
            <Button variant="secondary" icon={Download} onClick={() => download(api.networkExportUrl("device", deviceId, "xlsx"))}>
              Export
            </Button>
            {canDelete && device ? (
              <Button variant="danger" icon={Trash2} loading={deleting} onClick={() => void removeDevice()}>
                Delete
              </Button>
            ) : null}
          </>
        }
      />

      {error && !data ? (
        <EmptyState
          icon={AlertTriangle}
          title="Could not load device"
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
      ) : !device ? (
        <EmptyState title="No device available" />
      ) : (
        <>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <Stat
              label="Review score"
              value={latest?.score === null || latest?.score === undefined ? "-" : latest.score.toFixed(1)}
              tone={latest?.score === null || latest?.score === undefined ? "default" : latest.score >= 90 ? "ok" : latest.score >= 70 ? "default" : "high"}
              hint="Latest configuration"
            />
            <Stat
              label="Crit / High"
              value={(severity?.critical ?? 0) + (severity?.high ?? 0)}
              tone={(severity?.critical ?? 0) + (severity?.high ?? 0) > 0 ? "critical" : "ok"}
              icon={AlertTriangle}
              hint="Open findings, latest report"
            />
            <Stat label="Reports" value={reports.length} icon={Clock} hint={formatTimestamp(device.lastSeenAt)} />
            <Stat label="Locations" value={data?.locations.length ?? 0} icon={Server} hint="Sites seen" />
          </div>

          <Card>
            <CardHeader icon={Network} title="Identity" description="Parsed from the uploaded configuration." />
            <CardBody>
              <dl className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-4">
                <div className="min-w-0">
                  <dt className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">Hostname</dt>
                  <dd className="mt-0.5 truncate text-sm text-ink">{sanitizeText(device.hostname) || "-"}</dd>
                </div>
                <div>
                  <dt className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">Vendor</dt>
                  <dd className="mt-0.5 text-sm text-ink">
                    <Badge tone="info">{sanitizeText(device.vendorLabel)}</Badge>
                  </dd>
                </div>
                <div>
                  <dt className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">Type</dt>
                  <dd className="mt-0.5 text-sm text-ink">{sanitizeText(device.deviceType)}</dd>
                </div>
                <div className="min-w-0">
                  <dt className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">Model</dt>
                  <dd className="mt-0.5 truncate text-sm text-ink">{sanitizeText(device.model) || "-"}</dd>
                </div>
                <div className="min-w-0">
                  <dt className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">OS version</dt>
                  <dd className="mt-0.5 truncate text-sm text-ink">{sanitizeText(device.osVersion) || "-"}</dd>
                </div>
                <div className="min-w-0">
                  <dt className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">Serial</dt>
                  <dd className="mt-0.5 truncate font-mono text-xs text-ink-muted">{sanitizeText(device.serial) || "-"}</dd>
                </div>
                <div>
                  <dt className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">First seen</dt>
                  <dd className="mt-0.5 text-sm text-ink">{formatTimestamp(device.firstSeenAt)}</dd>
                </div>
                <div>
                  <dt className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">Last seen</dt>
                  <dd className="mt-0.5 text-sm text-ink">{formatTimestamp(device.lastSeenAt)}</dd>
                </div>
              </dl>
            </CardBody>
          </Card>

          {reports.length >= 2 ? <DiffCard deviceId={device.id} onOpenReport={onOpenReport} /> : null}

          {severity && latest ? (
            <Card>
              <CardHeader
                icon={AlertTriangle}
                title="Latest review findings"
                description={`Report #${latest.reportId} · received ${formatTimestamp(latest.receivedAt)}`}
                actions={
                  <span className="inline-flex items-center gap-2">
                    {SEVERITY_ORDER.filter((entry) => (severity[entry.toLowerCase() as "critical"] ?? 0) > 0).map((entry) => (
                      <span key={entry} className="inline-flex items-center gap-1 text-2xs text-ink-muted">
                        <span aria-hidden className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: severityColor(entry) }} />
                        {entry} {severity[entry.toLowerCase() as "critical"]}
                      </span>
                    ))}
                    <Badge tone={scoreTone(latest.score)}>score {latest.score === null ? "-" : latest.score.toFixed(0)}</Badge>
                  </span>
                }
              />
              <CardBody>
                <NetworkFindingsTable
                  findings={latest.findings}
                  reportId={latest.reportId}
                  canEdit={canEdit}
                  onChanged={() => setReloadKey((key) => key + 1)}
                />
              </CardBody>
            </Card>
          ) : null}

          <Card flush className="overflow-hidden">
            <div className="p-4">
              <CardHeader
                icon={Clock}
                title="Configuration timeline"
                description="Newest first. Select a report for the parsed config and redacted source."
                actions={<Badge tone="accent">{reports.length} reports</Badge>}
              />
            </div>
            {reports.length === 0 ? (
              <div className="p-4">
                <EmptyState title="No reports for this device" />
              </div>
            ) : (
              <ol className="flex flex-col">
                {reports.map((report) => (
                  <li key={report.id} className="flex flex-col gap-2 border-b border-hairline-soft p-4 last:border-b-0">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <button
                        type="button"
                        onClick={() => onOpenReport?.(report.id)}
                        className="inline-flex items-center gap-2 text-sm font-medium text-accent underline decoration-dotted underline-offset-2"
                      >
                        <Clock size={14} aria-hidden /> Report #{report.id}
                      </button>
                      <div className="flex flex-wrap items-center gap-2">
                        {report.score !== null ? <Badge tone={scoreTone(report.score)}>score {report.score.toFixed(0)}</Badge> : null}
                        <span className="text-2xs text-ink-subtle">{formatTimestamp(report.receivedAt)}</span>
                      </div>
                    </div>
                    <div className="flex flex-wrap gap-x-4 gap-y-1 text-2xs text-ink-subtle">
                      <span className="font-mono">{sanitizeText(report.configName)}</span>
                      <span>sha256 {sanitizeText(report.configSha256.slice(0, 16))}…</span>
                      <span>size {formatBytes(report.configSize)}</span>
                      <span>by {sanitizeText(report.uploadedBy) || "-"}</span>
                      <span>location #{report.locationId}</span>
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
