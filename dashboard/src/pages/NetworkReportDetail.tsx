// Network configuration report detail: parsed config inventory, review
// findings with treatment, and the redacted raw configuration.

import { useEffect, useState } from "react";
import { AlertTriangle, ArrowLeft, Download, FileCode2, RefreshCw } from "lucide-react";
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
import { sanitizeText } from "../components/EvidenceDrawer";
import type { NetworkReportDetail } from "../network-types";

export type NetworkReportDetailProps = {
  reportId: number;
  canEdit: boolean;
  onBack?: () => void;
  onOpenDevice?: (deviceId: number) => void;
};

function formatTimestamp(value: string | null | undefined): string {
  if (!value) return "—";
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? new Date(parsed).toLocaleString() : sanitizeText(value);
}

function Meta({ label, value }: { label: string; value: string | number | null | undefined }) {
  return (
    <div className="min-w-0">
      <dt className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">{label}</dt>
      <dd className="mt-0.5 truncate text-sm text-ink">{typeof value === "number" ? value : sanitizeText(value) || "—"}</dd>
    </div>
  );
}

/** One reviewed configuration: what was parsed, what failed, and the source. */
export function NetworkReportDetail({ reportId, canEdit, onBack, onOpenDevice }: NetworkReportDetailProps) {
  const [data, setData] = useState<NetworkReportDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [reloadKey, setReloadKey] = useState(0);
  const [showConfig, setShowConfig] = useState(false);
  const toast = useToast();

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(null);
    api
      .getNetworkReport(reportId)
      .then((response) => alive && setData(response))
      .catch((err) => {
        if (!alive) return;
        const message = err instanceof ApiError ? err.message : "failed to load report";
        setError(message);
        toast.error("Could not load report", { description: message });
      })
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [reportId, reloadKey, toast]);

  const report = data?.report;
  const device = data?.device;
  const parsed = data?.parsed ?? null;
  const failing = (data?.findings ?? []).filter((finding) => finding.status === "NonCompliant");

  return (
    <section aria-label={report ? `Network report ${report.id}` : `Network report ${reportId}`} className="mx-auto flex max-w-7xl flex-col gap-5">
      <SectionHeader
        eyebrow="Network review"
        title={device ? `${sanitizeText(device.hostname) || `Device #${device.id}`} · report #${reportId}` : `Network report #${reportId}`}
        description={report ? `${sanitizeText(report.configName)} · received ${formatTimestamp(report.receivedAt)}` : undefined}
        icon={FileCode2}
        actions={
          <>
            {onBack ? (
              <Button variant="ghost" icon={ArrowLeft} onClick={onBack}>
                Back
              </Button>
            ) : null}
            {device && onOpenDevice ? (
              <Button variant="secondary" onClick={() => onOpenDevice(device.id)}>
                Open device
              </Button>
            ) : null}
            <Button
              variant="secondary"
              icon={Download}
              onClick={() => {
                const anchor = document.createElement("a");
                anchor.href = api.networkExportUrl("report", reportId, "xlsx");
                anchor.rel = "noopener";
                document.body.appendChild(anchor);
                anchor.click();
                anchor.remove();
              }}
            >
              Export
            </Button>
            <Button variant="secondary" icon={RefreshCw} loading={loading} onClick={() => setReloadKey((key) => key + 1)}>
              Refresh
            </Button>
          </>
        }
      />

      {error && !data ? (
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
      ) : loading && !data ? (
        <Card>
          <Skeleton width="30%" />
          <Skeleton className="mt-3" width="100%" />
        </Card>
      ) : !report || !device ? (
        <EmptyState title="No report available" />
      ) : (
        <>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <Stat
              label="Review score"
              value={report.score === null ? "—" : report.score.toFixed(1)}
              tone={report.score === null ? "default" : report.score >= 90 ? "ok" : report.score >= 70 ? "default" : "high"}
              hint="CIS/NIST weighted"
            />
            <Stat label="Failing checks" value={failing.length} tone={failing.length > 0 ? "critical" : "ok"} icon={AlertTriangle} hint="Non-compliant" />
            <Stat label="Config size" value={`${(report.configSize / 1024).toFixed(1)} KiB`} hint={`${parsed?.configLines ?? 0} lines`} />
            <Stat label="Interfaces" value={parsed?.interfaces.length ?? 0} hint={`${parsed?.users.length ?? 0} local user(s)`} />
          </div>

          <Card>
            <CardHeader
              icon={FileCode2}
              title="Parsed configuration"
              description="Inventory extracted from the uploaded file (secrets are never stored)."
              actions={
                <span className="inline-flex items-center gap-2">
                  <Badge tone="info">{sanitizeText(device.vendorLabel)}</Badge>
                  <Badge tone={scoreTone(report.score)}>score {report.score === null ? "—" : report.score.toFixed(0)}</Badge>
                </span>
              }
            />
            <CardBody>
              <dl className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-4">
                <Meta label="Hostname" value={device.hostname} />
                <Meta label="Device type" value={device.deviceType} />
                <Meta label="Model" value={device.model} />
                <Meta label="OS version" value={device.osVersion} />
                <Meta label="Serial" value={device.serial} />
                <Meta label="Interfaces" value={parsed?.interfaces.length ?? 0} />
                <Meta label="Firewall rules" value={parsed?.firewallRules.length ?? 0} />
                <Meta label="VPN proposals" value={parsed?.vpns.length ?? 0} />
                <Meta label="Wireless LANs" value={parsed?.wirelessLans.length ?? 0} />
                <Meta label="SNMP communities" value={parsed?.snmp.communities.length ?? 0} />
                <Meta label="SNMPv3" value={parsed?.snmp.v3Configured ? "configured" : parsed?.snmp.v3Configured === false ? "no" : "unknown"} />
                <Meta label="Telnet" value={parsed?.management.telnetEnabled === true ? "enabled" : parsed?.management.telnetEnabled === false ? "disabled" : "unknown"} />
                <Meta label="HTTP mgmt" value={parsed?.management.httpEnabled === true ? "enabled" : parsed?.management.httpEnabled === false ? "disabled" : "unknown"} />
                <Meta label="SSH version" value={parsed?.management.sshVersion ?? "unknown"} />
                <Meta label="AAA" value={parsed?.aaa.newModel ? `tacacs ${parsed.aaa.tacacsHosts.length} · radius ${parsed.aaa.radiusHosts.length}` : "unknown"} />
                <Meta label="NTP servers" value={parsed?.ntp.servers.length ?? 0} />
                <Meta label="Syslog hosts" value={parsed?.logging.hosts.length ?? 0} />
                <Meta label="Log timestamps" value={parsed?.logging.timestamps ? "datetime" : "unknown"} />
              </dl>
            </CardBody>
          </Card>

          <Card>
            <CardHeader
              icon={AlertTriangle}
              title="Review findings"
              description="Every benchmark check with its decision, evidence, and treatment."
            />
            <CardBody>
              <NetworkFindingsTable
                findings={data.findings}
                reportId={report.id}
                canEdit={canEdit}
                onChanged={() => setReloadKey((key) => key + 1)}
              />
            </CardBody>
          </Card>

          <Card flush className="overflow-hidden">
            <div className="flex flex-wrap items-center justify-between gap-2 p-4">
              <CardHeader
                icon={FileCode2}
                title="Configuration source (redacted)"
                description="Secrets are masked; structure and line numbers are preserved."
              />
              <div className="pr-4">
                <Button variant="secondary" size="sm" onClick={() => setShowConfig((value) => !value)}>
                  {showConfig ? "Hide source" : "Show source"}
                </Button>
              </div>
            </div>
            {showConfig ? (
              <div className="border-t border-hairline-soft p-4">
                <pre className="hbs-inset hbs-scroll max-h-[28rem] overflow-auto rounded-control p-3 font-mono text-2xs leading-relaxed text-ink-muted">
                  {data.configText}
                </pre>
              </div>
            ) : null}
          </Card>
        </>
      )}
    </section>
  );
}
