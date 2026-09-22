import { useEffect, useState } from "react";
import { api, ApiError } from "../api";
import { EmptyState } from "../components/EmptyState";
import { resolveScope, serializeFilters, type ScopeFilters } from "../filters";
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

function formatBytes(value: number | null): string {
  if (value === null || !Number.isFinite(value)) return "—";
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

function formatMs(value: number | null): string {
  if (value === null || !Number.isFinite(value)) return "—";
  return value < 1000 ? `${value} ms` : `${(value / 1000).toFixed(2)} s`;
}

/** Atomically drop scope keys and re-parse the URL-backed filter state. */
function clearScopeKeys(filters: ScopeFilters): void {
  const next: ScopeFilters = { ...filters };
  delete next.scope;
  delete next.reportId;
  delete next.from;
  delete next.to;
  const query = serializeFilters(next);
  const url = query ? `${window.location.pathname}?${query}` : window.location.pathname;
  window.history.pushState({}, "", url);
  window.dispatchEvent(new PopStateEvent("popstate"));
}

function TallyTable({ title, tally }: { title: string; tally: Record<string, number> }) {
  const entries = Object.entries(tally).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  return (
    <section aria-label={title} className="rounded-lg border border-slate-800 p-3">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-400">{title}</h3>
      {entries.length === 0 ? (
        <p className="mt-1 text-xs text-slate-500">No data</p>
      ) : (
        <table className="mt-2 w-full border-collapse text-xs">
          <thead>
            <tr className="text-left text-slate-500">
              <th scope="col" className="border-b border-slate-800 py-1 pr-2">Value</th>
              <th scope="col" className="border-b border-slate-800 py-1 text-right">Count</th>
            </tr>
          </thead>
          <tbody>
            {entries.map(([key, count]) => (
              <tr key={key}>
                <td className="border-b border-slate-900 py-1 pr-2 break-words text-slate-300">{key}</td>
                <td className="border-b border-slate-900 py-1 text-right tabular-nums">{count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

function Stat({ label, value, tone }: { label: string; value: string | number; tone?: string }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-3">
      <dt className="text-xs uppercase tracking-wide text-slate-500">{label}</dt>
      <dd className={`mt-0.5 text-2xl font-semibold tabular-nums ${tone ?? "text-slate-100"}`}>{value}</dd>
    </div>
  );
}

export function Telemetry() {
  const { filters, query, chips, toggle } = useScopeFilters();
  const [data, setData] = useState<Telemetry | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(null);
    api
      .raw<Telemetry>("GET", `/api/telemetry${query ? `?${query}` : ""}`)
      .then((value) => {
        if (alive) setData(value);
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
  }, [query]);

  const scope = resolveScope(filters);

  return (
    <section aria-label="Telemetry" className="space-y-4">
      <fieldset className="flex flex-wrap items-end gap-4 rounded-lg border border-slate-800 p-3">
        <legend className="px-1 text-xs uppercase tracking-wide text-slate-400">Scope</legend>
        <label className="flex items-center gap-2 text-sm">
          <input type="radio" name="telemetry-scope" checked={scope === "latest"} onChange={() => clearScopeKeys(filters)} />
          Latest state
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="radio"
            name="telemetry-scope"
            checked={scope === "report"}
            onChange={() => toggle("scope", "report")}
          />
          Single report
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="radio"
            name="telemetry-scope"
            checked={scope === "range"}
            onChange={() => toggle("scope", "range")}
          />
          Date range
        </label>
        {scope === "report" ? (
          <label className="flex items-center gap-2 text-sm">
            Report ID
            <input
              type="number"
              min={1}
              value={filters.reportId?.[0] ?? ""}
              onChange={(event) => event.target.value && toggle("reportId", event.target.value)}
              className="w-28 rounded border border-slate-700 bg-slate-900 px-2 py-1"
            />
          </label>
        ) : null}
        {scope === "range" ? (
          <>
            <label className="flex items-center gap-2 text-sm">
              From
              <input
                type="datetime-local"
                value={filters.from?.[0] ?? ""}
                onChange={(event) => event.target.value && toggle("from", event.target.value)}
                className="rounded border border-slate-700 bg-slate-900 px-2 py-1"
              />
            </label>
            <label className="flex items-center gap-2 text-sm">
              To
              <input
                type="datetime-local"
                value={filters.to?.[0] ?? ""}
                onChange={(event) => event.target.value && toggle("to", event.target.value)}
                className="rounded border border-slate-700 bg-slate-900 px-2 py-1"
              />
            </label>
          </>
        ) : null}
        {chips.length > 0 ? <span className="text-xs text-slate-400">{chips.length} active filter(s)</span> : null}
      </fieldset>

      {error ? (
        <EmptyState title="Could not load telemetry" detail={error} />
      ) : loading && !data ? (
        <p role="status">Loading telemetry…</p>
      ) : !data ? (
        <EmptyState title="No telemetry available" />
      ) : (
        <>
          {data.freshness.stale ? (
            <p role="alert" className="rounded border border-amber-500/50 bg-amber-500/10 p-3 text-sm text-amber-100">
              Data is stale: latest scan {data.freshness.ageHours === null ? "unknown" : `${data.freshness.ageHours.toFixed(1)}h`} ago (SLA{" "}
              {data.freshness.slaHours}h); {data.freshness.staleHosts} host(s) past SLA.
            </p>
          ) : null}

          {data.decided > 0 && data.coverage < 80 ? (
            <p role="alert" className="rounded border border-amber-500/50 bg-amber-500/10 p-3 text-sm text-amber-100">
              Low coverage: {data.coverage.toFixed(1)}% of applicable checks were authoritative-decided ({data.decided} decided).
            </p>
          ) : null}

          <dl className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
            <Stat label="Reports" value={data.reportCount} />
            <Stat label="Hosts" value={data.hostCount} />
            <Stat label="Coverage" value={`${data.coverage.toFixed(1)}%`} />
            <Stat label="Decided" value={data.decided} />
            <Stat label="Degraded" value={data.degraded} tone={data.degraded > 0 ? "text-amber-300" : undefined} />
            <Stat label="Errors" value={data.error} tone={data.error > 0 ? "text-red-300" : undefined} />
            <Stat label="Commands" value={data.commands} />
            <Stat label="Files read" value={data.files} />
            <Stat label="Accepted ingest" value={data.ingest.accepted} tone="text-emerald-300" />
            <Stat label="Rejected ingest" value={data.ingest.rejected} tone={data.ingest.rejected > 0 ? "text-red-300" : undefined} />
            <Stat label="Peak RSS" value={formatBytes(data.rssBytes.max)} />
            <Stat label="Avg RSS" value={formatBytes(data.rssBytes.avg)} />
          </dl>

          <section aria-label="Durations" className="rounded-lg border border-slate-800 p-3">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-400">Durations</h3>
            <table className="mt-2 w-full border-collapse text-xs">
              <caption className="sr-only">Scan and ingest duration percentiles</caption>
              <thead>
                <tr className="text-left text-slate-500">
                  <th scope="col" className="border-b border-slate-800 py-1 pr-2">Metric</th>
                  <th scope="col" className="border-b border-slate-800 py-1 pr-2 text-right">Count</th>
                  <th scope="col" className="border-b border-slate-800 py-1 pr-2 text-right">p50</th>
                  <th scope="col" className="border-b border-slate-800 py-1 pr-2 text-right">p95</th>
                  <th scope="col" className="border-b border-slate-800 py-1 pr-2 text-right">Min</th>
                  <th scope="col" className="border-b border-slate-800 py-1 text-right">Max</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <th scope="row" className="border-b border-slate-900 py-1 pr-2 text-left font-normal text-slate-300">Scan</th>
                  <td className="border-b border-slate-900 py-1 pr-2 text-right tabular-nums">{data.scanDurationMs.count}</td>
                  <td className="border-b border-slate-900 py-1 pr-2 text-right tabular-nums">{formatMs(data.scanDurationMs.p50)}</td>
                  <td className="border-b border-slate-900 py-1 pr-2 text-right tabular-nums">{formatMs(data.scanDurationMs.p95)}</td>
                  <td className="border-b border-slate-900 py-1 pr-2 text-right tabular-nums">{formatMs(data.scanDurationMs.min)}</td>
                  <td className="border-b border-slate-900 py-1 text-right tabular-nums">{formatMs(data.scanDurationMs.max)}</td>
                </tr>
                <tr>
                  <th scope="row" className="border-b border-slate-900 py-1 pr-2 text-left font-normal text-slate-300">Ingest</th>
                  <td className="border-b border-slate-900 py-1 pr-2 text-right tabular-nums">{data.ingestDurationMs.count}</td>
                  <td className="border-b border-slate-900 py-1 pr-2 text-right tabular-nums">{formatMs(data.ingestDurationMs.p50)}</td>
                  <td className="border-b border-slate-900 py-1 pr-2 text-right tabular-nums">{formatMs(data.ingestDurationMs.p95)}</td>
                  <td className="border-b border-slate-900 py-1 pr-2 text-right tabular-nums">{formatMs(data.ingestDurationMs.min)}</td>
                  <td className="border-b border-slate-900 py-1 text-right tabular-nums">{formatMs(data.ingestDurationMs.max)}</td>
                </tr>
              </tbody>
            </table>
          </section>

          <section aria-label="Bytes and freshness" className="grid gap-3 md:grid-cols-2">
            <dl className="grid grid-cols-3 gap-3">
              <Stat label="Report bytes" value={formatBytes(data.bytes.total)} />
              <Stat label="Avg report" value={formatBytes(data.bytes.avg)} />
              <Stat label="Envelope bytes" value={formatBytes(data.bytes.ingestTotal)} />
            </dl>
            <dl className="grid grid-cols-2 gap-3">
              <Stat label="Last received" value={data.freshness.latestReceivedAt ?? "—"} />
              <Stat label="Age (hours)" value={data.freshness.ageHours === null ? "—" : data.freshness.ageHours.toFixed(1)} />
            </dl>
          </section>

          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            <TallyTable title="Privilege level" tally={data.privilege} />
            <TallyTable title="Evidence depth" tally={data.evidenceDepth} />
            <TallyTable title="Arrival path" tally={data.via} />
            <TallyTable title="Platform" tally={data.platform} />
            <TallyTable title="Architecture" tally={data.arch} />
            <TallyTable title="Operating system" tally={data.os} />
            <TallyTable title="Extractor version" tally={data.extractorVersion} />
            <TallyTable title="Location" tally={data.location} />
            <TallyTable title="Rejection reasons" tally={data.ingest.reasons} />
          </div>
        </>
      )}
    </section>
  );
}
