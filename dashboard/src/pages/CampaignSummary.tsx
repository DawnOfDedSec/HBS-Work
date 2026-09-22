import { useEffect, useState } from "react";
import { BarChart3, Presentation } from "lucide-react";
import { api, ApiError } from "../api";
import { EmptyState } from "../components/EmptyState";
import { KpiTile } from "../components/KpiTile";
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

/** Campaign Summary: server-authoritative KPI + accessible chart kit (Task 54). */
export function CampaignSummary({ campaignId, onDrilldown }: CampaignSummaryProps) {
  const [summary, setSummary] = useState<CampaignSummaryResponse | null>(null);
  const [hosts, setHosts] = useState<SummaryHostRow[]>([]);
  const [trend, setTrend] = useState<TrendDatum[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [presentation, setPresentation] = useState(false);

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
        if (alive) setError(err instanceof ApiError ? err.message : "failed to load campaign summary");
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [campaignId]);

  if (error) return <EmptyState title="Could not load campaign summary" detail={error} />;
  if (loading && !summary) return <p role="status">Loading campaign summary…</p>;
  if (!summary) return <EmptyState title="No summary available" />;

  const { kpis, severityBreakdown, categoryCompliance, topFailingChecks } = summary;
  const heatmapHosts = hosts.map((host) => ({
    hostId: host.id,
    hostname: host.hostname ?? host.displayId,
    severity: host.severity,
  }));

  const kpiRow = (
    <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
      <KpiTile
        label="Risk score"
        value={kpis.weightedRiskScore.toFixed(1)}
        tone={kpis.weightedRiskScore >= 80 ? "ok" : kpis.weightedRiskScore >= 50 ? "default" : "high"}
      />
      <KpiTile label="Coverage" value={`${kpis.coverage.toFixed(1)}%`} />
      <KpiTile label="Hosts" value={kpis.hosts} />
      <KpiTile label="Findings" value={kpis.totalFindings} />
    </div>
  );

  return (
    <section aria-label="Campaign summary" className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="inline-flex items-center gap-2">
          <BarChart3 size={18} aria-hidden />
          <h2 className="text-lg font-semibold">{summary.campaign.name}</h2>
        </div>
        <button
          type="button"
          aria-pressed={presentation}
          onClick={() => setPresentation((value) => !value)}
          className="inline-flex items-center gap-1 rounded border border-slate-700 px-2 py-1 text-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
        >
          <Presentation size={14} aria-hidden /> {presentation ? "Exit presentation" : "Presentation mode"}
        </button>
      </div>

      {presentation ? (
        <div className="rounded-lg border border-white/20 bg-black p-6 text-white">
          <h3 className="text-xl font-semibold">{summary.campaign.name} — executive summary</h3>
          <div className="mt-4 grid gap-4 md:grid-cols-3">
            <RiskGauge score={kpis.weightedRiskScore} coverage={kpis.coverage} onDrilldown={drill} />
            <SeverityDonut data={severityBreakdown} onDrilldown={drill} />
            <div className="space-y-4">
              <KpiTile label="Coverage" value={`${kpis.coverage.toFixed(1)}%`} />
              <KpiTile label="Hosts" value={kpis.hosts} tone="ok" />
            </div>
          </div>
        </div>
      ) : (
        <>
          {kpiRow}
          <div className="grid gap-4 xl:grid-cols-2">
            <RiskGauge score={kpis.weightedRiskScore} coverage={kpis.coverage} onDrilldown={drill} />
            <SeverityDonut data={severityBreakdown} onDrilldown={drill} />
            <CategoryBars data={categoryCompliance} onDrilldown={drill} />
            <TrendLine points={trend} onDrilldown={drill} />
            <HostHeatmap hosts={heatmapHosts} onDrilldown={drill} />
          </div>
        </>
      )}

      <section aria-label="Top failing checks" className="space-y-2">
        <h3 className="text-sm font-medium">Top failing checks</h3>
        {topFailingChecks.length === 0 ? (
          <EmptyState title="No failing checks" />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-sm">
              <caption className="pb-2 text-left text-sm text-slate-300">
                Ten most common non-compliant checks
              </caption>
              <thead>
                <tr>
                  <th scope="col" className="border-b border-slate-700 px-2 py-1 text-left text-slate-400">
                    Check
                  </th>
                  <th scope="col" className="border-b border-slate-700 px-2 py-1 text-left text-slate-400">
                    Title
                  </th>
                  <th scope="col" className="border-b border-slate-700 px-2 py-1 text-left text-slate-400">
                    Severity
                  </th>
                  <th scope="col" className="border-b border-slate-700 px-2 py-1 text-right text-slate-400">
                    Findings
                  </th>
                  <th scope="col" className="border-b border-slate-700 px-2 py-1 text-right text-slate-400">
                    Hosts
                  </th>
                </tr>
              </thead>
              <tbody>
                {topFailingChecks.map((check) => (
                  <tr key={check.checkId}>
                    <td className="border-b border-slate-800 px-2 py-1">
                      <button
                        type="button"
                        onClick={() => drill(`checkId=${encodeURIComponent(check.checkId)}`)}
                        className="text-sky-300 underline focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
                      >
                        {check.checkId}
                      </button>
                    </td>
                    <td className="border-b border-slate-800 px-2 py-1">{check.title}</td>
                    <td className="border-b border-slate-800 px-2 py-1">{check.severity}</td>
                    <td className="border-b border-slate-800 px-2 py-1 text-right tabular-nums">{check.count}</td>
                    <td className="border-b border-slate-800 px-2 py-1 text-right tabular-nums">{check.hosts}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </section>
  );
}
