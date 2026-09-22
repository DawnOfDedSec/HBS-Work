import { useEffect, useState } from "react";
import { api, ApiError } from "../api";
import { EmptyState } from "../components/EmptyState";
import { KpiTile } from "../components/KpiTile";
import type { OverviewMetrics } from "../types";

export function Overview() {
  const [data, setData] = useState<OverviewMetrics | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;
    api
      .overview()
      .then((metrics) => {
        if (alive) setData(metrics);
      })
      .catch((err) => {
        if (alive) setError(err instanceof ApiError ? err.message : "failed to load metrics");
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, []);

  if (error) return <EmptyState title="Could not load metrics" detail={error} />;
  if (loading && !data) return <p role="status">Loading metrics…</p>;
  if (!data) return <EmptyState title="No metrics available" />;

  const { kpis, riskTrend } = data;
  return (
    <section aria-label="Global overview" className="space-y-6">
      <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
        <KpiTile label="Campaigns" value={kpis.campaignCount} />
        <KpiTile label="Active locations" value={kpis.activeLocations} />
        <KpiTile label="Scanned hosts" value={kpis.scannedHosts} />
        <KpiTile
          label="Open criticals"
          value={kpis.openCriticals}
          tone={kpis.openCriticals > 0 ? "critical" : "ok"}
        />
        <KpiTile label="Findings" value={kpis.totalFindings} />
        <KpiTile
          label="Risk score"
          value={kpis.weightedRiskScore.toFixed(1)}
          hint={`${kpis.coverage.toFixed(1)}% coverage`}
          tone={kpis.weightedRiskScore >= 80 ? "ok" : kpis.weightedRiskScore >= 50 ? "default" : "high"}
        />
      </div>

      {riskTrend.length > 0 ? (
        <figure aria-label="Risk score trend">
          <figcaption className="mb-2 text-sm text-slate-400">Risk score trend</figcaption>
          <table className="w-full max-w-xl border-collapse text-sm">
            <thead>
              <tr className="text-left text-slate-400">
                <th scope="col" className="border-b border-slate-800 py-1">Date</th>
                <th scope="col" className="border-b border-slate-800 py-1">Score</th>
                <th scope="col" className="border-b border-slate-800 py-1">Reports</th>
              </tr>
            </thead>
            <tbody>
              {riskTrend.map((point) => (
                <tr key={point.date}>
                  <td className="border-b border-slate-900 py-1">{point.date}</td>
                  <td className="border-b border-slate-900 py-1 tabular-nums">{point.score.toFixed(1)}</td>
                  <td className="border-b border-slate-900 py-1 tabular-nums">{point.reports}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </figure>
      ) : null}
    </section>
  );
}
