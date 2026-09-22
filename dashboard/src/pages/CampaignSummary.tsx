import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  ArrowUpRight,
  BarChart3,
  Gauge,
  ListChecks,
  Presentation,
  RefreshCw,
  Server,
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
import { SeverityBadge } from "../components/badges";
import { CategoryBars, type CategoryDatum } from "../components/charts/CategoryBars";
import { HostHeatmap } from "../components/charts/HostHeatmap";
import { RiskGauge } from "../components/charts/RiskGauge";
import { SeverityDonut } from "../components/charts/SeverityDonut";
import { TrendLine, type TrendDatum } from "../components/charts/TrendLine";
import { type LocationRow } from "./Locations";

export type CampaignSummaryResponse = {
  campaign: { id: number; name: string };
  kpis: {
    weightedRiskScore: number;
    coverage: number;
    totalFindings: number;
    hosts: number;
  };
  severityBreakdown: Record<string, number>;
  categoryCompliance: CategoryDatum[];
  topFailingChecks: Array<{
    checkId: string;
    title: string;
    severity: string;
    count: number;
    hosts: number;
  }>;
};

export type RiskMetricsResponse = {
  weightedRiskScore: number;
  coverage: number;
  riskTrend: TrendDatum[];
};

export type SummaryHostRow = {
  id: number;
  hostname: string | null;
  displayId: string;
  lastSeenAt: string;
  severity: Record<string, number>;
};

export type CampaignSummaryProps = {
  campaignId: number;
  /**
   * Called with canonical filter parameters for a chart drilldown. Defaults to
   * navigating to `/findings?<query>` when omitted.
   */
  onDrilldown?: (urlQuery: string) => void;
};

function defaultDrilldown(urlQuery: string): void {
  if (typeof window === "undefined") return;
  window.location.assign(urlQuery ? `/findings?${urlQuery}` : "/findings");
}

type TopCheck = CampaignSummaryResponse["topFailingChecks"][number];

function buildExecutiveSummary(summary: CampaignSummaryResponse): string {
  const { kpis, severityBreakdown, categoryCompliance } = summary;
  const critical = severityBreakdown.Critical ?? 0;
  const high = severityBreakdown.High ?? 0;
  const weakest = [...categoryCompliance]
    .filter((category) => category.applicable > 0)
    .sort((a, b) => a.complianceRate - b.complianceRate)[0];
  const posture =
    kpis.weightedRiskScore >= 90
      ? "a strong"
      : kpis.weightedRiskScore >= 70
        ? "a moderate"
        : "an elevated";
  const parts = [
    `${summary.campaign.name} presents ${posture} risk posture (${kpis.weightedRiskScore.toFixed(1)}/100) with ${kpis.coverage.toFixed(1)}% authoritative coverage across ${kpis.hosts} host${kpis.hosts === 1 ? "" : "s"}.`,
    `${critical} critical and ${high} high finding${critical + high === 1 ? "" : "s"} remain outstanding of ${kpis.totalFindings} total checks.`,
  ];
  if (weakest) {
    parts.push(
      `Weakest control family is ${weakest.category} at ${weakest.complianceRate.toFixed(1)}% compliance (${weakest.nonCompliant} failing of ${weakest.applicable} applicable).`,
    );
  }
  parts.push("Prioritise critical/high remediations and any category below 80% compliance before the next scan window.");
  return parts.join(" ");
}

/** Campaign Summary: server-authoritative KPI + accessible chart kit. */
export function CampaignSummary({ campaignId, onDrilldown }: CampaignSummaryProps) {
  const [summary, setSummary] = useState<CampaignSummaryResponse | null>(null);
  const [hosts, setHosts] = useState<SummaryHostRow[]>([]);
  const [trend, setTrend] = useState<TrendDatum[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [presentation, setPresentation] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);
  const toast = useToast();

  const drill = onDrilldown ?? defaultDrilldown;

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(null);
    async function load() {
      const summaryResponse = await api.raw<CampaignSummaryResponse>(
        "GET",
        `/api/campaigns/${campaignId}/summary`,
      );
      // Campaign detail embeds its locations; there is no dedicated locations GET.
      const campaignRow = await api.raw<{ locations?: LocationRow[] }>(
        "GET",
        `/api/campaigns/${campaignId}`,
      );
      const locations = campaignRow.locations ?? [];
      // A campaign is scoped through its locations (there is no campaignId
      // filter). With no locations there is nothing to scope to, so leave the
      // host/trend charts empty rather than showing global data.
      const scoped =
        locations.length > 0 ? locations.map((location) => `locationId=${location.id}`).join("&") : "";
      const [hostsResponse, riskResponse] = scoped
        ? await Promise.all([
            api.raw<{ hosts: SummaryHostRow[] }>("GET", `/api/hosts?${scoped}`),
            api.raw<RiskMetricsResponse>("GET", `/api/metrics/risk?${scoped}`),
          ])
        : [{ hosts: [] as SummaryHostRow[] }, { riskTrend: [] as TrendDatum[] }];
      if (!alive) return;
      setSummary(summaryResponse);
      setHosts(hostsResponse.hosts ?? []);
      setTrend(riskResponse.riskTrend ?? []);
    }
    load()
      .catch((err) => {
        if (!alive) return;
        const message = err instanceof ApiError ? err.message : "failed to load campaign summary";
        setError(message);
        toast.error("Could not load campaign summary", { description: message });
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [campaignId, reloadKey, toast]);

  const summaryText = useMemo(() => (summary ? buildExecutiveSummary(summary) : ""), [summary]);

  const topColumns: Array<TableColumn<TopCheck>> = [
    {
      key: "checkId",
      header: "Check",
      render: (row) => <span className="font-mono text-xs text-accent">{row.checkId}</span>,
    },
    { key: "title", header: "Title", render: (row) => row.title },
    { key: "severity", header: "Severity", render: (row) => <SeverityBadge severity={row.severity} /> },
    { key: "count", header: "Findings", align: "right", sortable: true },
    { key: "hosts", header: "Hosts", align: "right", sortable: true },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      align: "right",
      render: (row) => (
        <Button size="sm" variant="ghost" iconRight={ArrowUpRight} onClick={() => drill(`checkId=${encodeURIComponent(row.checkId)}`)}>
          Findings
        </Button>
      ),
    },
  ];

  if (error && !summary) {
    return (
      <EmptyState
        icon={AlertTriangle}
        title="Could not load campaign summary"
        detail={error}
        action={
          <Button variant="secondary" icon={RefreshCw} onClick={() => setReloadKey((key) => key + 1)}>
            Try again
          </Button>
        }
      />
    );
  }
  if (loading && !summary) {
    return (
      <Card>
        <Skeleton width="30%" />
        <Skeleton className="mt-3" width="60%" height={28} />
        <Skeleton className="mt-3" width="100%" />
      </Card>
    );
  }
  if (!summary) return <EmptyState title="No summary available" />;

  const { kpis, severityBreakdown, categoryCompliance, topFailingChecks } = summary;
  const heatmapHosts = hosts.map((host) => ({
    hostId: host.id,
    hostname: host.hostname ?? host.displayId,
    severity: host.severity,
  }));

  const kpiRow = (
    <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
      <Stat
        label="Risk score"
        value={kpis.weightedRiskScore.toFixed(1)}
        icon={Gauge}
        tone={kpis.weightedRiskScore >= 80 ? "ok" : kpis.weightedRiskScore >= 50 ? "default" : "high"}
        hint="Weighted, higher is safer"
      />
      <Stat
        label="Coverage"
        value={`${kpis.coverage.toFixed(1)}%`}
        icon={ShieldCheck}
        tone={kpis.coverage >= 90 ? "ok" : kpis.coverage >= 70 ? "accent" : "high"}
        hint="Authoritative decided"
      />
      <Stat label="Hosts" value={kpis.hosts} icon={Server} hint="Distinct machines" />
      <Stat label="Findings" value={kpis.totalFindings} icon={ListChecks} hint="Checks evaluated" />
    </div>
  );

  const topFailing = (
    <Card flush className="overflow-hidden">
      <div className="p-4">
        <CardHeader
          icon={BarChart3}
          title="Top failing checks"
          description="Ten most common non-compliant checks; select one to drill into findings."
          actions={<Badge tone="critical">{topFailingChecks.length} checks</Badge>}
        />
      </div>
      {topFailingChecks.length === 0 ? (
        <div className="p-4">
          <EmptyState title="No failing checks" detail="Every applicable check is compliant in this scope." />
        </div>
      ) : (
        <Table
          label="Top failing checks"
          columns={topColumns}
          rows={topFailingChecks}
          rowKey={(row) => row.checkId}
          stickyHeader
          onRowClick={(row) => drill(`checkId=${encodeURIComponent(row.checkId)}`)}
        />
      )}
    </Card>
  );

  return (
    <section aria-label="Campaign summary" className="flex flex-col gap-5">
      <SectionHeader
        eyebrow="Campaign"
        title={summary.campaign.name}
        description="Executive roll-up and control-family compliance for this campaign."
        icon={BarChart3}
        actions={
          <>
            <Button variant="secondary" icon={RefreshCw} loading={loading} onClick={() => setReloadKey((key) => key + 1)}>
              Refresh
            </Button>
            <Button
              variant="secondary"
              icon={Presentation}
              aria-pressed={presentation}
              onClick={() => setPresentation((value) => !value)}
            >
              {presentation ? "Exit presentation" : "Presentation mode"}
            </Button>
          </>
        }
      />

      {presentation ? (
        <Card className="border-hairline-strong">
          <CardHeader
            title={`${summary.campaign.name} — plain-language posture`}
            description={summaryText}
            icon={BarChart3}
          />
          <CardBody className="grid gap-4 md:grid-cols-3">
            <RiskGauge score={kpis.weightedRiskScore} coverage={kpis.coverage} onDrilldown={drill} />
            <SeverityDonut data={severityBreakdown} onDrilldown={drill} />
            <div className="grid gap-4">
              <Stat label="Coverage" value={`${kpis.coverage.toFixed(1)}%`} icon={ShieldCheck} />
              <Stat label="Hosts" value={kpis.hosts} icon={Server} tone="ok" />
            </div>
          </CardBody>
        </Card>
      ) : (
        <>
          {kpiRow}

          <Card>
            <CardHeader
              icon={BarChart3}
              title="Executive summary"
              description="Plain-language read of the server-authoritative metrics."
            />
            <CardBody>
              <p className="text-sm leading-relaxed text-ink-muted">{summaryText}</p>
            </CardBody>
          </Card>

          <div className="grid gap-4 xl:grid-cols-2">
            <RiskGauge score={kpis.weightedRiskScore} coverage={kpis.coverage} onDrilldown={drill} />
            <SeverityDonut data={severityBreakdown} onDrilldown={drill} />
            <CategoryBars data={categoryCompliance} onDrilldown={drill} />
            <TrendLine points={trend} onDrilldown={drill} />
            <HostHeatmap hosts={heatmapHosts} onDrilldown={drill} />
          </div>

          {topFailing}
        </>
      )}
    </section>
  );
}
