import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock,
  FolderKanban,
  Gauge,
  HardDrive,
  LayoutDashboard,
  ListChecks,
  RefreshCw,
  Server,
  ShieldAlert,
} from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Tooltip,
  XAxis,
  YAxis,
  type BarShapeProps,
} from "recharts";
import { api, ApiError } from "../api";
import { Badge, Button, EmptyState, SectionHeader, Sparkline, Stat } from "../components/ui";
import { cn } from "../components/ui/cn";
import { SeverityDonut } from "../components/charts/SeverityDonut";
import { TrendLine } from "../components/charts/TrendLine";
import {
  ChartFrame,
  ExactTooltip,
  FocusableRect,
  TableTwin,
  drilldownQuery,
  severityColor,
} from "../components/charts/TableTwin";
import { serializeFilters } from "../filters";
import type { RouteKey } from "../routes";
import type { OverviewMetrics } from "../types";

export type OverviewProps = {
  /** Publish a canonical findings query and route to Findings. */
  onDrilldown: (query: string) => void;
  onNavigate: (route: RouteKey) => void;
};

type SeverityResponse = { severity: Record<string, number>; total: number };

type FindingRow = { checkId: string; title: string; severity: string; status: string };
type FindingsResponse = { results: FindingRow[]; total: number };

type TelemetryQuality = {
  freshness?: {
    latestReceivedAt: string | null;
    ageHours: number | null;
    slaHours: number;
    stale: boolean;
    staleHosts: number;
  };
  ingest?: { accepted: number; rejected: number };
  coverage?: number;
};

type TopCheck = { checkId: string; title: string; severity: string; count: number };

/** Aggregate the non-compliant findings page into the most common checks. */
function topFailingChecks(rows: FindingRow[]): TopCheck[] {
  const buckets = new Map<string, TopCheck>();
  for (const row of rows) {
    if (row.status !== "NonCompliant") continue;
    const existing = buckets.get(row.checkId);
    if (existing) existing.count += 1;
    else buckets.set(row.checkId, { checkId: row.checkId, title: row.title, severity: row.severity, count: 1 });
  }
  return [...buckets.values()]
    .sort((a, b) => b.count - a.count || a.checkId.localeCompare(b.checkId))
    .slice(0, 8);
}

function formatHours(hours: number | null | undefined): string {
  if (hours === null || hours === undefined || !Number.isFinite(hours)) return "unknown";
  if (hours < 1) return "<1 hour";
  if (hours < 48) return `${hours.toFixed(1)} hours`;
  return `${(hours / 24).toFixed(1)} days`;
}

type FreshnessBannerProps = {
  quality: TelemetryQuality | null;
  coverage: number;
};

/** Data-quality / freshness banner: stale data, ingest rejects, coverage. */
function FreshnessBanner({ quality, coverage }: FreshnessBannerProps) {
  const freshness = quality?.freshness;
  const rejected = quality?.ingest?.rejected ?? 0;
  const stale = Boolean(freshness?.stale);
  const staleHosts = freshness?.staleHosts ?? 0;

  if (!quality) {
    return (
      <div className="hbs-panel flex flex-wrap items-center gap-3 px-4 py-3 text-sm text-ink-muted">
        <Activity size={16} className="text-ink-subtle" aria-hidden />
        <span>Data-quality metrics are unavailable for this scope.</span>
      </div>
    );
  }

  const tone = stale ? "degraded" : rejected > 0 ? "high" : "compliant";
  const Icon = stale ? AlertTriangle : rejected > 0 ? AlertTriangle : CheckCircle2;
  const accent =
    tone === "compliant" ? "text-compliant" : tone === "high" ? "text-high" : "text-degraded";

  return (
    <div
      role="status"
      className={cn(
        "hbs-panel flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3 text-sm",
        stale ? "border-degraded/40" : rejected > 0 ? "border-high/40" : "border-compliant/30",
      )}
    >
      <span className={cn("flex items-center gap-2 font-medium", accent)}>
        <Icon size={16} aria-hidden />
        {stale ? "Data is stale" : rejected > 0 ? "Ingest issues detected" : "Data is fresh"}
      </span>
      <span className="text-ink-muted">
        Latest report <span className="tabular-nums text-ink">{formatHours(freshness?.ageHours)}</span> ago
        {freshness ? (
          <>
            {" "}
            (SLA <span className="tabular-nums text-ink">{freshness.slaHours}h</span>)
          </>
        ) : null}
      </span>
      {staleHosts > 0 ? (
        <span className="text-ink-muted">
          <span className="tabular-nums text-degraded">{staleHosts}</span> stale hosts
        </span>
      ) : null}
      {rejected > 0 ? (
        <span className="text-ink-muted">
          <span className="tabular-nums text-high">{rejected}</span> rejected ingest events
        </span>
      ) : null}
      <span className="ml-auto flex items-center gap-2 text-ink-muted">
        <Clock size={14} className="text-ink-subtle" aria-hidden />
        Coverage <span className="tabular-nums text-ink">{coverage.toFixed(1)}%</span>
      </span>
    </div>
  );
}

function TopFailingChecks({ data, onDrilldown }: { data: TopCheck[]; onDrilldown: (query: string) => void }) {
  const shown = data.slice(0, 8);
  const chartHeight = Math.max(170, shown.length * 34 + 30);

  const renderBar = (props: BarShapeProps): ReactNode => {
    const datum = (props.payload ?? {}) as Partial<TopCheck>;
    const checkId = datum.checkId ?? "";
    const count = typeof props.value === "number" ? props.value : 0;
    return (
      <FocusableRect
        x={props.x}
        y={props.y}
        width={props.width}
        height={props.height}
        radius={4}
        fill={severityColor(datum.severity ?? "")}
        label={`${checkId} (${datum.severity ?? "unknown"}): ${count} failing hosts. Show findings.`}
        onActivate={() => onDrilldown(drilldownQuery({ checkId: [checkId] }))}
      />
    );
  };

  const chart =
    shown.length === 0 ? (
      <p role="status" className="py-8 text-center text-sm text-ink-muted">
        No non-compliant checks in this scope.
      </p>
    ) : (
      <BarChart
        width={620}
        height={chartHeight}
        data={shown}
        layout="vertical"
        margin={{ top: 8, right: 24, bottom: 8, left: 8 }}
        accessibilityLayer={false}
      >
        <CartesianGrid horizontal={false} stroke="var(--color-hairline)" />
        <XAxis type="number" allowDecimals={false} stroke="var(--color-ink-subtle)" fontSize={11} />
        <YAxis type="category" dataKey="checkId" width={104} stroke="var(--color-ink-subtle)" fontSize={11} />
        <Tooltip content={ExactTooltip} cursor={{ fill: "var(--color-surface-raised)" }} />
        <Bar dataKey="count" name="Failing hosts" maxBarSize={22} isAnimationActive={false} shape={renderBar} />
      </BarChart>
    );

  const table = (
    <TableTwin
      caption="Top failing checks"
      columns={[
        { key: "checkId", header: "Check" },
        { key: "title", header: "Title" },
        { key: "severity", header: "Severity" },
        { key: "count", header: "Failing hosts" },
      ]}
      rows={shown.map((check) => ({
        key: check.checkId,
        cells: [check.checkId, check.title, check.severity, check.count],
      }))}
    />
  );

  return (
    <ChartFrame
      title="Top failing checks"
      description="Click or press Enter on a bar to filter findings by that check."
      chart={chart}
      table={table}
    />
  );
}

function SkeletonTile() {
  return (
    <div className="hbs-panel p-4">
      <div className="h-3 w-20 animate-shimmer rounded-full bg-surface-raised" />
      <div className="mt-3 h-7 w-24 animate-shimmer rounded bg-surface-raised" />
      <div className="mt-3 h-3 w-28 animate-shimmer rounded-full bg-surface-raised" />
    </div>
  );
}

/**
 * Enterprise landing view: KPI tiles that drill into Findings with canonical
 * query params, plus risk trend, severity breakdown, top failing checks, and a
 * data-quality/freshness banner.
 */
export function Overview({ onDrilldown, onNavigate }: OverviewProps) {
  const [metrics, setMetrics] = useState<OverviewMetrics | null>(null);
  const [severity, setSeverity] = useState<Record<string, number> | null>(null);
  const [findings, setFindings] = useState<FindingRow[] | null>(null);
  const [quality, setQuality] = useState<TelemetryQuality | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(null);

    const overviewRequest = api.overview();
    const severityRequest = api.raw<SeverityResponse>("GET", "/api/metrics/severity");
    const findingsRequest = api.raw<FindingsResponse>("GET", "/api/findings?status=NonCompliant&pageSize=200");
    const qualityRequest = api.raw<TelemetryQuality>("GET", "/api/telemetry");

    overviewRequest
      .then((value) => {
        if (alive) setMetrics(value);
      })
      .catch((err) => {
        if (alive) setError(err instanceof ApiError ? err.message : "Failed to load overview metrics");
      })
      .finally(() => {
        if (alive) setLoading(false);
      });

    severityRequest
      .then((value) => {
        if (alive) setSeverity(value.severity);
      })
      .catch(() => {
        if (alive) setSeverity(null);
      });

    findingsRequest
      .then((value) => {
        if (alive) setFindings(value.results);
      })
      .catch(() => {
        if (alive) setFindings([]);
      });

    qualityRequest
      .then((value) => {
        if (alive) setQuality(value);
      })
      .catch(() => {
        if (alive) setQuality(null);
      });

    return () => {
      alive = false;
    };
  }, [reloadKey]);

  const refresh = useCallback(() => setReloadKey((value) => value + 1), []);

  const topChecks = useMemo(() => (findings ? topFailingChecks(findings) : []), [findings]);
  const riskScores = useMemo(() => (metrics?.riskTrend ?? []).map((point) => point.score), [metrics]);
  const riskDelta = useMemo(() => {
    const points = metrics?.riskTrend ?? [];
    if (points.length < 2) return undefined;
    const latest = points[points.length - 1]?.score ?? 0;
    const previous = points[points.length - 2]?.score ?? 0;
    const diff = latest - previous;
    if (Math.abs(diff) < 0.05) return { value: "No change", direction: "flat" as const, intent: "neutral" as const };
    return {
      value: `${diff > 0 ? "+" : ""}${diff.toFixed(1)} vs prior report`,
      direction: diff > 0 ? ("up" as const) : ("down" as const),
      intent: diff > 0 ? ("positive" as const) : ("negative" as const),
    };
  }, [metrics]);

  const header = (
    <SectionHeader
      eyebrow="Operate"
      title="Overview"
      description="Global risk posture, coverage, and data quality across every campaign in scope."
      icon={LayoutDashboard}
      actions={
        <Button variant="secondary" icon={RefreshCw} loading={loading} onClick={refresh}>
          Refresh
        </Button>
      }
    />
  );

  if (error && !metrics) {
    return (
      <section className="mx-auto flex max-w-7xl flex-col gap-6">
        {header}
        <EmptyState
          icon={AlertTriangle}
          title="Could not load overview metrics"
          detail={error}
          action={
            <Button variant="secondary" icon={RefreshCw} onClick={refresh}>
              Try again
            </Button>
          }
        />
      </section>
    );
  }

  const kpis = metrics?.kpis;

  return (
    <section aria-label="Global overview" className="mx-auto flex max-w-7xl flex-col gap-6">
      {header}

      {loading && !metrics ? (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 6 }).map((_, index) => (
            <SkeletonTile key={index} />
          ))}
        </div>
      ) : kpis ? (
        <>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
            <Stat
              label="Campaigns"
              value={kpis.campaignCount}
              icon={FolderKanban}
              hint="Engagements tracked"
              onClick={() => onNavigate("campaigns")}
            />
            <Stat
              label="Active locations"
              value={kpis.activeLocations}
              icon={Server}
              hint="Non-retired sites"
              onClick={() => onNavigate("locations")}
            />
            <Stat
              label="Scanned hosts"
              value={kpis.scannedHosts}
              icon={HardDrive}
              hint="Distinct machine ids"
              onClick={() => onNavigate("locations")}
            />
            <Stat
              label="Open criticals"
              value={kpis.openCriticals}
              icon={ShieldAlert}
              tone={kpis.openCriticals > 0 ? "critical" : "ok"}
              hint={kpis.openCriticals > 0 ? "Needs triage" : "None outstanding"}
              onClick={() =>
                onDrilldown(serializeFilters({ severity: ["Critical"], status: ["NonCompliant"] }))
              }
            />
            <Stat
              label="Findings"
              value={kpis.totalFindings}
              icon={ListChecks}
              hint="Across all reports in scope"
              onClick={() => onDrilldown(serializeFilters({}))}
            />
            <Stat
              label="Risk score"
              value={kpis.weightedRiskScore.toFixed(1)}
              icon={Gauge}
              tone={kpis.weightedRiskScore >= 80 ? "ok" : kpis.weightedRiskScore >= 50 ? "default" : "high"}
              hint={`${kpis.coverage.toFixed(1)}% coverage`}
              delta={riskDelta}
              sparkline={<Sparkline values={riskScores} ariaLabel="Risk score trend across reports" />}
              onClick={() => onDrilldown(serializeFilters({ status: ["NonCompliant"] }))}
            />
          </div>

          <FreshnessBanner quality={quality} coverage={kpis.coverage} />

          <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
            <TrendLine points={metrics?.riskTrend ?? []} onDrilldown={onDrilldown} />
            <SeverityDonut data={severity ?? {}} onDrilldown={onDrilldown} />
          </div>

          <TopFailingChecks data={topChecks} onDrilldown={onDrilldown} />

          <p className="flex flex-wrap items-center gap-2 text-2xs text-ink-subtle">
            <Badge tone="accent" icon={Activity}>
              Live scope
            </Badge>
            Every chart exposes an exact-value tooltip, keyboard focus, and a table twin.
          </p>
        </>
      ) : (
        <EmptyState title="No metrics available" detail="Scan reports will populate this view once ingested." />
      )}
    </section>
  );
}
