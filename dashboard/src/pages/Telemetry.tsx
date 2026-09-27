import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Clock,
  Gauge,
  HardDrive,
  RefreshCw,
  Server,
  ShieldCheck,
  Signal,
  Timer,
  UploadCloud,
} from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Line,
  LineChart,
  Tooltip,
  XAxis,
  YAxis,
  type BarShapeProps,
  type DotItemDotProps,
} from "recharts";
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
  Toolbar,
  ToolbarGroup,
  ToolbarSpacer,
  type TableColumn,
  useToast,
} from "../components/ui";
import { PlatformBadge } from "../components/badges";
import {
  ChartFrame,
  ExactTooltip,
  FocusableDot,
  FocusableRect,
  TableTwin,
  drilldownQuery,
} from "../components/charts/TableTwin";
import { ScopeControls, clearScopeKeys } from "../components/ScopeSelector";
import { useScopeFilters } from "../useScopeFilters";

type DurationStats = {
  count: number;
  min: number | null;
  max: number | null;
  avg: number | null;
  p50: number | null;
  p95: number | null;
};

/** `GET /api/telemetry` (`buildTelemetry`). */
type Telemetry = {
  reportCount: number;
  hostCount: number;
  scanDurationMs: DurationStats;
  ingestDurationMs: DurationStats;
  bytes: { total: number; avg: number; ingestTotal: number };
  rssBytes: { avg: number | null; max: number | null };
  coverage: number;
  decided: number;
  compliant: number;
  nonCompliant: number;
  degraded: number;
  error: number;
  notApplicable: number;
  informational: number;
  commands: number;
  files: number;
  privilege: Record<string, number>;
  evidenceDepth: Record<string, number>;
  platform: Record<string, number>;
  arch: Record<string, number>;
  os: Record<string, number>;
  location: Record<string, number>;
  extractorVersion: Record<string, number>;
  via: Record<string, number>;
  freshness: {
    latestReceivedAt: string | null;
    ageHours: number | null;
    slaHours: number;
    stale: boolean;
    staleHosts: number;
  };
  ingest: { accepted: number; rejected: number; reasons: Record<string, number> };
};

type RiskResponse = {
  weightedRiskScore: number;
  coverage: number;
  riskTrend: Array<{ date: string; score: number; reports: number }>;
};

type ReportRow = {
  id: number;
  hostId: number;
  receivedAt: string;
  via: string | null;
  score: number | null;
  coverage: number | null;
  totalDurationMs: number | null;
};

type ReportList = { reports: ReportRow[]; total: number };

type HostRow = {
  id: number;
  displayId: string;
  hostname: string | null;
  platform: string | null;
  latestReceivedAt: string | null;
  reportCount: number;
  riskScore: number | null;
  coverage: number | null;
};

type HostList = { hosts: HostRow[]; total: number };

type DiagnosticEvent = {
  receivedAt: string;
  accepted: boolean;
  reasonCode: string | null;
};

type DiagnosticResponse = { diagnostic: { ingestEvents: DiagnosticEvent[] } };

export type TelemetryProps = {
  /** Publish a canonical findings query and route to Findings. */
  onDrilldown?: (query: string) => void;
};

function errorMessage(error: unknown): string {
  return error instanceof ApiError ? error.message : "Request failed. Please retry.";
}

function defaultDrilldown(urlQuery: string): void {
  if (typeof window === "undefined") return;
  window.location.assign(urlQuery ? `/findings?${urlQuery}` : "/findings");
}

function formatMs(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return "-";
  return value < 1000 ? `${value} ms` : `${(value / 1000).toFixed(2)} s`;
}

function formatBytes(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return "-";
  if (value < 1024) return `${value} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let size = value / 1024;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(1)} ${units[unit]}`;
}

function formatAge(hours: number | null): string {
  if (hours === null || !Number.isFinite(hours)) return "unknown";
  if (hours < 1) return "<1 hour";
  if (hours < 48) return `${hours.toFixed(1)} h`;
  return `${(hours / 24).toFixed(1)} d`;
}

function tallyEntries(tally: Record<string, number>): Array<{ name: string; count: number }> {
  return Object.entries(tally)
    .map(([name, count]) => ({ name: name === "unknown" ? "Unknown" : name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
}

type DurationBucket = { key: string; label: string; count: number; reportId: number | null };

function bucketDurations(reports: ReportRow[], bins = 8): DurationBucket[] {
  const points = reports.filter(
    (report): report is ReportRow & { totalDurationMs: number } =>
      typeof report.totalDurationMs === "number" && Number.isFinite(report.totalDurationMs),
  );
  if (points.length === 0) return [];
  const values = points.map((point) => point.totalDurationMs);
  const min = Math.min(...values);
  const max = Math.max(...values);
  if (max === min) {
    return [{ key: "single", label: formatMs(min), count: points.length, reportId: points[0]?.id ?? null }];
  }
  const span = (max - min) / bins;
  const buckets: DurationBucket[] = Array.from({ length: bins }, (_, index) => ({
    key: `b${index}`,
    label: `${formatMs(Math.round(min + index * span))}–${formatMs(Math.round(min + (index + 1) * span))}`,
    count: 0,
    reportId: null,
  }));
  const slowest: number[] = Array.from({ length: bins }, () => -1);
  for (const point of points) {
    const index = Math.min(bins - 1, Math.max(0, Math.floor((point.totalDurationMs - min) / span)));
    const bucket = buckets[index];
    if (!bucket) continue;
    bucket.count += 1;
    if (point.totalDurationMs > slowest[index]) {
      slowest[index] = point.totalDurationMs;
      bucket.reportId = point.id;
    }
  }
  return buckets.filter((bucket) => bucket.count > 0);
}

type CoveragePoint = { date: string; coverage: number; reports: number };

function coverageTrend(reports: ReportRow[]): CoveragePoint[] {
  const buckets = new Map<string, { total: number; count: number }>();
  for (const report of reports) {
    if (typeof report.coverage !== "number" || !Number.isFinite(report.coverage)) continue;
    const date = report.receivedAt.slice(0, 10);
    const bucket = buckets.get(date) ?? { total: 0, count: 0 };
    bucket.total += report.coverage;
    bucket.count += 1;
    buckets.set(date, bucket);
  }
  return [...buckets.entries()]
    .map(([date, bucket]) => ({
      date,
      coverage: bucket.count > 0 ? Math.round((bucket.total / bucket.count) * 100) / 100 : 0,
      reports: bucket.count,
    }))
    .sort((a, b) => a.date.localeCompare(b.date));
}

type IngestPoint = { date: string; accepted: number; rejected: number };

function ingestTrend(events: DiagnosticEvent[], reports: ReportRow[]): { points: IngestPoint[]; rejectedAvailable: boolean } {
  if (events.length > 0) {
    const buckets = new Map<string, { accepted: number; rejected: number }>();
    for (const event of events) {
      const date = event.receivedAt.slice(0, 10);
      const bucket = buckets.get(date) ?? { accepted: 0, rejected: 0 };
      if (event.accepted) bucket.accepted += 1;
      else bucket.rejected += 1;
      buckets.set(date, bucket);
    }
    return {
      points: [...buckets.entries()]
        .map(([date, bucket]) => ({ date, ...bucket }))
        .sort((a, b) => a.date.localeCompare(b.date)),
      rejectedAvailable: true,
    };
  }
  const buckets = new Map<string, number>();
  for (const report of reports) {
    const date = report.receivedAt.slice(0, 10);
    buckets.set(date, (buckets.get(date) ?? 0) + 1);
  }
  return {
    points: [...buckets.entries()]
      .map(([date, accepted]) => ({ date, accepted, rejected: 0 }))
      .sort((a, b) => a.date.localeCompare(b.date)),
    rejectedAvailable: false,
  };
}

/** Horizontal adoption bars with drilldown, exact tooltip, and a table twin. */
function AdoptionBars({
  title,
  description,
  entries,
  color,
  chartWidth = 520,
  onActivate,
}: {
  title: string;
  description: string;
  entries: Array<{ name: string; count: number }>;
  color: string;
  chartWidth?: number;
  onActivate?: (name: string) => void;
}) {
  const shown = entries.slice(0, 12);
  const chartHeight = Math.max(120, shown.length * 26 + 30);

  const renderBar = (props: BarShapeProps): ReactNode => {
    const datum = (props.payload ?? {}) as { name?: string };
    const name = datum.name ?? "";
    const count = typeof props.value === "number" ? props.value : 0;
    return (
      <FocusableRect
        x={props.x}
        y={props.y}
        width={props.width}
        height={props.height}
        radius={4}
        fill={color}
        label={onActivate ? `${name}: ${count} reports. Show findings.` : `${name}: ${count} reports.`}
        onActivate={onActivate ? () => onActivate(name) : undefined}
      />
    );
  };

  const chart =
    shown.length === 0 ? (
      <p role="status" className="py-8 text-center text-sm text-ink-muted">
        No data in this scope.
      </p>
    ) : (
      <BarChart
        width={chartWidth}
        height={chartHeight}
        data={shown}
        layout="vertical"
        margin={{ top: 8, right: 24, bottom: 8, left: 8 }}
        accessibilityLayer={false}
      >
        <CartesianGrid horizontal={false} stroke="var(--color-hairline)" />
        <XAxis type="number" allowDecimals={false} stroke="var(--color-ink-subtle)" fontSize={11} />
        <YAxis
          type="category"
          dataKey="name"
          width={132}
          stroke="var(--color-ink-subtle)"
          fontSize={11}
          tickFormatter={(value: string) => (value.length > 18 ? `${value.slice(0, 17)}…` : value)}
        />
        <Tooltip content={ExactTooltip} cursor={{ fill: "var(--color-surface-raised)" }} />
        <Bar dataKey="count" name="Reports" maxBarSize={20} isAnimationActive={false} shape={renderBar} />
      </BarChart>
    );

  const table = (
    <TableTwin
      caption={title}
      columns={[
        { key: "name", header: "Value" },
        { key: "count", header: "Reports" },
      ]}
      rows={entries.map((entry) => ({ key: entry.name, cells: [entry.name, entry.count] }))}
    />
  );

  return <ChartFrame title={title} description={description} chart={chart} table={table} />;
}

export function Telemetry({ onDrilldown }: TelemetryProps = {}) {
  const { filters, query, chips, toggle } = useScopeFilters();
  const toast = useToast();
  const drill = onDrilldown ?? defaultDrilldown;

  const [data, setData] = useState<Telemetry | null>(null);
  const [risk, setRisk] = useState<RiskResponse | null>(null);
  const [reports, setReports] = useState<ReportRow[]>([]);
  const [hosts, setHosts] = useState<HostRow[]>([]);
  const [events, setEvents] = useState<DiagnosticEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(null);
    const suffix = query ? `?${query}` : "";
    const withParams = (params: string): string => {
      const search = new URLSearchParams(query);
      new URLSearchParams(params).forEach((value, key) => search.set(key, value));
      const text = search.toString();
      return text ? `?${text}` : "";
    };

    Promise.all([
      api.raw<Telemetry>("GET", `/api/telemetry${suffix}`),
      api.raw<RiskResponse>("GET", `/api/metrics/risk${suffix}`).catch(() => null),
      api.raw<ReportList>("GET", `/api/reports${withParams("pageSize=200")}`).catch(() => null),
      api.raw<HostList>("GET", `/api/hosts${withParams("pageSize=200")}`).catch(() => null),
      api.raw<DiagnosticResponse>("GET", `/api/diagnostic${suffix}`).catch(() => null),
    ])
      .then(([telemetry, riskResponse, reportResponse, hostResponse, diagnostic]) => {
        if (!alive) return;
        setData(telemetry);
        setRisk(riskResponse);
        setReports(Array.isArray(reportResponse?.reports) ? reportResponse.reports : []);
        setHosts(Array.isArray(hostResponse?.hosts) ? hostResponse.hosts : []);
        setEvents(Array.isArray(diagnostic?.diagnostic?.ingestEvents) ? diagnostic.diagnostic.ingestEvents : []);
      })
      .catch((err) => {
        if (!alive) return;
        const message = errorMessage(err);
        setError(message);
        toast.error("Could not load telemetry", { description: message });
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [query, reloadKey, toast]);

  const durationBuckets = useMemo(() => bucketDurations(reports), [reports]);
  const coveragePoints = useMemo(() => coverageTrend(reports), [reports]);
  const ingest = useMemo(() => ingestTrend(events, reports), [events, reports]);
  const freshnessRows = useMemo(() => {
    const sla = data?.freshness.slaHours ?? 24;
    return [...hosts]
      .map((host) => {
        const seen = host.latestReceivedAt;
        const at = seen ? Date.parse(seen) : NaN;
        const ageHours = Number.isFinite(at) ? Math.round(((Date.now() - at) / 3_600_000) * 100) / 100 : null;
        return { host, ageHours, stale: ageHours !== null && ageHours > sla };
      })
      .sort((a, b) => (b.ageHours ?? -1) - (a.ageHours ?? -1))
      .slice(0, 25);
  }, [hosts, data]);

  const applicable = data ? data.compliant + data.nonCompliant + data.degraded + data.error : 0;
  const degradedPct = data && applicable > 0 ? (data.degraded / applicable) * 100 : 0;

  const refresh = useCallback(() => setReloadKey((key) => key + 1), []);

  const durationChart = durationBuckets.length === 0 ? (
    <p role="status" className="py-8 text-center text-sm text-ink-muted">
      No scan durations in this scope.
    </p>
  ) : (
    <BarChart
      width={560}
      height={230}
      data={durationBuckets}
      margin={{ top: 8, right: 16, bottom: 8, left: 0 }}
      accessibilityLayer={false}
    >
      <CartesianGrid vertical={false} stroke="var(--color-hairline)" />
      <XAxis dataKey="label" stroke="var(--color-ink-subtle)" fontSize={10} interval={0} angle={-12} dy={8} height={44} />
      <YAxis allowDecimals={false} stroke="var(--color-ink-subtle)" fontSize={11} width={36} />
      <Tooltip content={ExactTooltip} cursor={{ fill: "var(--color-surface-raised)" }} />
      <Bar
        dataKey="count"
        name="Reports"
        maxBarSize={40}
        isAnimationActive={false}
        shape={(props: BarShapeProps): ReactNode => {
          const datum = (props.payload ?? {}) as Partial<DurationBucket>;
          const count = typeof props.value === "number" ? props.value : 0;
          const reportId = datum.reportId ?? null;
          return (
            <FocusableRect
              x={props.x}
              y={props.y}
              width={props.width}
              height={props.height}
              radius={4}
              fill="var(--color-accent)"
              label={`${datum.label ?? "bucket"}: ${count} reports. Show findings from the slowest report.`}
              onActivate={
                reportId !== null
                  ? () => drill(`scope=report&reportId=${reportId}`)
                  : undefined
              }
            />
          );
        }}
      />
    </BarChart>
  );

  const durationTable = (
    <TableTwin
      caption="Scan duration distribution"
      columns={[
        { key: "label", header: "Duration" },
        { key: "count", header: "Reports" },
      ]}
      rows={durationBuckets.map((bucket) => ({ key: bucket.key, cells: [bucket.label, bucket.count] }))}
    />
  );

  const coverageChart =
    coveragePoints.length === 0 ? (
      <p role="status" className="py-8 text-center text-sm text-ink-muted">
        No coverage history in this scope.
      </p>
    ) : (
      <LineChart
        width={560}
        height={230}
        data={coveragePoints}
        margin={{ top: 8, right: 16, bottom: 8, left: 0 }}
        accessibilityLayer={false}
      >
        <CartesianGrid stroke="var(--color-hairline)" vertical={false} />
        <XAxis dataKey="date" stroke="var(--color-ink-subtle)" fontSize={11} />
        <YAxis domain={[0, 100]} stroke="var(--color-ink-subtle)" fontSize={11} width={36} />
        <Tooltip content={ExactTooltip} />
        <Line
          type="monotone"
          dataKey="coverage"
          name="Coverage %"
          stroke="var(--color-compliant)"
          strokeWidth={2}
          isAnimationActive={false}
          dot={(props: DotItemDotProps): ReactNode => {
            if (props.cx === undefined || props.cy === undefined) return <g />;
            const datum = props.payload as CoveragePoint | undefined;
            const date = datum?.date ?? "";
            const coverage = datum?.coverage ?? 0;
            return (
              <FocusableDot
                cx={props.cx as number}
                cy={props.cy as number}
                fill="var(--color-compliant)"
                label={`${date}: ${coverage.toFixed(1)}% coverage. Show findings from this day.`}
                onActivate={() => drill(`scope=range&from=${date}T00:00:00.000Z&to=${date}T23:59:59.999Z`)}
              />
            );
          }}
        />
      </LineChart>
    );

  const coverageTable = (
    <TableTwin
      caption="Coverage trend"
      columns={[
        { key: "date", header: "Date" },
        { key: "coverage", header: "Coverage %" },
        { key: "reports", header: "Reports" },
      ]}
      rows={coveragePoints.map((point) => ({
        key: point.date,
        cells: [point.date, point.coverage.toFixed(1), point.reports],
      }))}
    />
  );

  const ingestChart =
    ingest.points.length === 0 ? (
      <p role="status" className="py-8 text-center text-sm text-ink-muted">
        No ingest history in this scope.
      </p>
    ) : (
      <LineChart
        width={900}
        height={240}
        data={ingest.points}
        margin={{ top: 8, right: 24, bottom: 8, left: 0 }}
        accessibilityLayer={false}
      >
        <CartesianGrid stroke="var(--color-hairline)" vertical={false} />
        <XAxis dataKey="date" stroke="var(--color-ink-subtle)" fontSize={11} />
        <YAxis allowDecimals={false} stroke="var(--color-ink-subtle)" fontSize={11} width={36} />
        <Tooltip content={ExactTooltip} />
        <Line
          type="monotone"
          dataKey="accepted"
          name="Accepted"
          stroke="var(--color-compliant)"
          strokeWidth={2}
          isAnimationActive={false}
          dot={(props: DotItemDotProps): ReactNode => {
            if (props.cx === undefined || props.cy === undefined) return <g />;
            const datum = props.payload as IngestPoint | undefined;
            const date = datum?.date ?? "";
            return (
              <FocusableDot
                cx={props.cx as number}
                cy={props.cy as number}
                fill="var(--color-compliant)"
                label={`${date}: ${datum?.accepted ?? 0} accepted ingest events. Show findings from this day.`}
                onActivate={() => drill(`scope=range&from=${date}T00:00:00.000Z&to=${date}T23:59:59.999Z`)}
              />
            );
          }}
        />
        {ingest.rejectedAvailable ? (
          <Line
            type="monotone"
            dataKey="rejected"
            name="Rejected"
            stroke="var(--color-critical-strong)"
            strokeWidth={2}
            isAnimationActive={false}
            dot={(props: DotItemDotProps): ReactNode => {
              if (props.cx === undefined || props.cy === undefined) return <g />;
              const datum = props.payload as IngestPoint | undefined;
              const date = datum?.date ?? "";
              return (
                <FocusableDot
                  cx={props.cx as number}
                  cy={props.cy as number}
                  fill="var(--color-critical-strong)"
                  label={`${date}: ${datum?.rejected ?? 0} rejected ingest events. Show findings from this day.`}
                  onActivate={() => drill(`scope=range&from=${date}T00:00:00.000Z&to=${date}T23:59:59.999Z`)}
                />
              );
            }}
          />
        ) : null}
      </LineChart>
    );

  const ingestTable = (
    <TableTwin
      caption="Ingest accepted and rejected over time"
      columns={[
        { key: "date", header: "Date" },
        { key: "accepted", header: "Accepted" },
        { key: "rejected", header: "Rejected" },
      ]}
      rows={ingest.points.map((point) => ({
        key: point.date,
        cells: [point.date, point.accepted, point.rejected],
      }))}
    />
  );

  const freshnessColumns: Array<TableColumn<(typeof freshnessRows)[number]>> = [
    {
      key: "host",
      header: "Host",
      render: (row) => <span className="text-ink">{row.host.displayId}</span>,
    },
    { key: "platform", header: "Platform", render: (row) => <PlatformBadge platform={row.host.platform} /> },
    {
      key: "latest",
      header: "Last report",
      render: (row) => <span className="text-xs text-ink-muted">{row.host.latestReceivedAt ?? "-"}</span>,
    },
    {
      key: "age",
      header: "Age",
      align: "right",
      sortValue: (row) => row.ageHours ?? -1,
      render: (row) => formatAge(row.ageHours),
    },
    {
      key: "sla",
      header: "SLA",
      align: "center",
      render: (row) =>
        row.stale ? <Badge tone="degraded">Stale</Badge> : <Badge tone="compliant">Within SLA</Badge>,
    },
    { key: "reports", header: "Reports", align: "right", sortable: true, render: (row) => row.host.reportCount },
    {
      key: "risk",
      header: "Risk",
      align: "right",
      sortable: true,
      render: (row) => (row.host.riskScore === null ? "-" : row.host.riskScore.toFixed(1)),
    },
  ];

  const kpis = data ? (
    <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
      <Stat label="Scans" value={data.reportCount} icon={Activity} hint={`${data.hostCount} hosts`} />
      <Stat
        label="Coverage"
        value={`${data.coverage.toFixed(1)}%`}
        icon={ShieldCheck}
        tone={data.coverage >= 90 ? "ok" : data.coverage >= 70 ? "accent" : "high"}
        hint={`${data.decided} decided`}
      />
      <Stat
        label="Avg risk"
        value={risk ? risk.weightedRiskScore.toFixed(1) : "-"}
        icon={Gauge}
        tone={!risk ? "default" : risk.weightedRiskScore >= 80 ? "ok" : risk.weightedRiskScore >= 50 ? "default" : "high"}
        hint="Weighted, server-authoritative"
      />
      <Stat
        label="Degraded"
        value={`${degradedPct.toFixed(1)}%`}
        icon={AlertTriangle}
        tone={degradedPct > 0 ? "high" : "ok"}
        hint={`${data.degraded} degraded results`}
      />
      <Stat
        label="Ingest p50"
        value={formatMs(data.ingestDurationMs.p50)}
        icon={Timer}
        hint={`${data.ingestDurationMs.count} events`}
      />
      <Stat
        label="Ingest p95"
        value={formatMs(data.ingestDurationMs.p95)}
        icon={Timer}
        tone="accent"
        hint={`max ${formatMs(data.ingestDurationMs.max)}`}
      />
      <Stat label="Errors" value={data.error} icon={Signal} tone={data.error > 0 ? "critical" : "ok"} hint="Error results" />
      <Stat
        label="Ingest rejected"
        value={data.ingest.rejected}
        icon={UploadCloud}
        tone={data.ingest.rejected > 0 ? "critical" : "ok"}
        hint={`${data.ingest.accepted} accepted`}
      />
    </div>
  ) : null;

  return (
    <section aria-label="Telemetry" className="mx-auto flex max-w-7xl flex-col gap-5">
      <SectionHeader
        eyebrow="Analyze"
        title="Telemetry"
        description="Ingest health, scan runtime, coverage, and evidence quality for the current scope. Every chart exposes an exact tooltip, keyboard focus, and a table twin."
        icon={Activity}
        actions={
          <Button variant="secondary" icon={RefreshCw} loading={loading} onClick={refresh}>
            Refresh
          </Button>
        }
      />

      <ScopeControls filters={filters} onToggle={toggle} onClearScope={() => clearScopeKeys(filters)} />

      {chips.length > 0 ? (
        <div aria-label="Active filters" className="flex flex-wrap items-center gap-2">
          <span className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">Active</span>
          {chips.map((chip) => (
            <Badge key={`${chip.key}:${chip.value}`} tone="accent">
              {chip.key}: {chip.value}
            </Badge>
          ))}
        </div>
      ) : null}

      {error && !data ? (
        <EmptyState
          icon={AlertTriangle}
          title="Could not load telemetry"
          detail={error}
          action={
            <Button variant="secondary" icon={RefreshCw} onClick={refresh}>
              Try again
            </Button>
          }
        />
      ) : loading && !data ? (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          {Array.from({ length: 8 }).map((_, index) => (
            <Card key={index}>
              <Skeleton width="50%" />
              <Skeleton className="mt-3" width="70%" height={28} />
            </Card>
          ))}
        </div>
      ) : !data ? (
        <EmptyState title="No telemetry available" detail="Ingest reports to populate runtime and ingest health." />
      ) : (
        <>
          {data.freshness.stale ? (
            <div
              role="alert"
              className="flex flex-wrap items-center gap-2 rounded-control border border-high/40 bg-high-soft/60 p-3 text-sm text-high"
            >
              <Clock size={16} aria-hidden />
              Data is stale: latest scan {formatAge(data.freshness.ageHours)} ago (SLA {data.freshness.slaHours}h);{" "}
              <span className="tabular-nums">{data.freshness.staleHosts}</span> host(s) past SLA.
            </div>
          ) : null}
          {applicable > 0 && data.coverage < 80 ? (
            <div
              role="alert"
              className="flex flex-wrap items-center gap-2 rounded-control border border-high/40 bg-high-soft/60 p-3 text-sm text-high"
            >
              <Signal size={16} aria-hidden />
              Low coverage: {data.coverage.toFixed(1)}% of applicable checks were authoritative-decided ({data.decided} decided).
            </div>
          ) : null}

          {kpis}

          <Toolbar label="Telemetry summary">
            <ToolbarGroup>
              <Badge tone="info" icon={HardDrive}>
                Reports {formatBytes(data.bytes.total)}
              </Badge>
              <Badge tone="info" icon={Server}>
                Peak RSS {formatBytes(data.rssBytes.max)}
              </Badge>
              <Badge tone="info" icon={Activity}>
                Commands {data.commands.toLocaleString()} · Files {data.files.toLocaleString()}
              </Badge>
            </ToolbarGroup>
            <ToolbarSpacer />
            <ToolbarGroup>
              <Badge tone="accent" icon={ShieldCheck}>
                Scan p50 {formatMs(data.scanDurationMs.p50)} · p95 {formatMs(data.scanDurationMs.p95)}
              </Badge>
            </ToolbarGroup>
          </Toolbar>

          <div className="grid gap-4 xl:grid-cols-2">
            <ChartFrame
              title="Scan duration distribution"
              description="Reports bucketed by total scan time. Activate a bar to open the slowest report in that bucket."
              chart={durationChart}
              table={durationTable}
            />
            <ChartFrame
              title="Coverage trend"
              description="Average authoritative-decided coverage per day. Activate a point to drill into that day."
              chart={coverageChart}
              table={coverageTable}
            />
          </div>

          <ChartFrame
            title="Ingest accepted vs rejected"
            description={
              ingest.rejectedAvailable
                ? "Redacted ingest events per day (latest 500 from the diagnostic bundle). Activate a point to drill into that day."
                : "Reports received per day. Per-event rejection history requires the super-admin diagnostic bundle; rejected totals remain below."
            }
            chart={ingestChart}
            table={ingestTable}
          />

          <div className="grid gap-4 xl:grid-cols-2">
            <AdoptionBars
              title="Evidence depth"
              description="Authoritative-primary vs fallback vs degraded evidence. Activate a bar to filter findings."
              entries={tallyEntries(data.evidenceDepth)}
              color="var(--color-evidence-fallback)"
              onActivate={(name) => drill(drilldownQuery({ evidenceDepth: [name] }))}
            />
            <AdoptionBars
              title="Platform adoption"
              description="Host platform of the reports in scope. Activate a bar to filter findings."
              entries={tallyEntries(data.platform)}
              color="var(--color-accent)"
              onActivate={(name) =>
                drill(drilldownQuery({ platform: [name.toLowerCase() === "windows" ? "Windows" : "Linux"] }))
              }
            />
            <AdoptionBars
              title="Extractor version adoption"
              description="Extractor build reported by each scan. Activate a bar to filter findings."
              entries={tallyEntries(data.extractorVersion)}
              color="var(--color-low)"
              onActivate={(name) => drill(drilldownQuery({ extractorVersion: [name] }))}
            />
            <AdoptionBars
              title="Operating system adoption"
              description="Normalized OS string per host. Platform-inferable bars drill into findings."
              entries={tallyEntries(data.os)}
              color="var(--color-info)"
              onActivate={(name) => {
                if (/win/i.test(name)) drill(drilldownQuery({ platform: ["Windows"] }));
                else if (/linux|ubuntu|rhel|debian|centos|suse|fedora|amazon/i.test(name)) {
                  drill(drilldownQuery({ platform: ["Linux"] }));
                }
              }}
            />
          </div>

          <Card flush className="overflow-hidden">
            <div className="p-4">
              <CardHeader
                icon={Clock}
                title="Freshness / SLA"
                description={`Hosts sorted by staleness. SLA is ${data.freshness.slaHours}h; ${data.freshness.staleHosts} host(s) are past it.`}
              />
            </div>
            {freshnessRows.length === 0 ? (
              <div className="p-4">
                <EmptyState title="No hosts in scope" />
              </div>
            ) : (
              <Table
                label="Host freshness against the SLA"
                columns={freshnessColumns}
                rows={freshnessRows}
                rowKey={(row) => String(row.host.id)}
                stickyHeader
              />
            )}
          </Card>

          <Card>
            <CardHeader
              icon={BarChart3}
              title="Rejection reasons"
              description="Reason codes for ingest events rejected in scope."
              actions={<Badge tone={data.ingest.rejected > 0 ? "critical" : "compliant"}>{data.ingest.rejected} rejected</Badge>}
            />
            <CardBody>
              {Object.keys(data.ingest.reasons).length === 0 ? (
                <p className="text-sm text-ink-muted">No rejected ingest events in this scope.</p>
              ) : (
                <ul className="flex flex-wrap gap-2">
                  {tallyEntries(data.ingest.reasons).map((entry) => (
                    <li key={entry.name}>
                      <Badge tone="critical">
                        {entry.name}: {entry.count}
                      </Badge>
                    </li>
                  ))}
                </ul>
              )}
            </CardBody>
          </Card>
        </>
      )}
    </section>
  );
}
