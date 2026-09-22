import { useEffect, useState } from "react";
import { api, ApiError } from "../api";
import { EmptyState } from "../components/EmptyState";
import { sanitizeText } from "../components/EvidenceDrawer";

/** `GET /api/checks/:checkId` (the By Check pivot). */
type CheckHost = {
  hostId: number;
  hostname: string;
  displayId: string;
  status: string;
  severity: string;
  category: string;
  reportId: number;
  receivedAt: string;
  treatment: string;
  links: Record<string, string>;
};

type CheckDetailResponse = {
  checkId: string;
  total: number;
  statusCounts: Record<string, number>;
  hosts: CheckHost[];
};

export type CheckDetailProps = {
  checkId: string;
  onBack?: () => void;
  onOpenReport?: (reportId: number) => void;
};

const TREATMENT_STATES = ["open", "accepted_risk", "false_positive", "remediated"] as const;

export function CheckDetail({ checkId, onBack, onOpenReport }: CheckDetailProps) {
  const [data, setData] = useState<CheckDetailResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(null);
    api
      .raw<CheckDetailResponse>("GET", `/api/checks/${encodeURIComponent(checkId)}`)
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
  }, [checkId]);

  if (error) return <EmptyState title="Could not load check" detail={error} />;
  if (loading && !data) return <p role="status">Loading check…</p>;
  if (!data) return <EmptyState title="Check not available" />;

  const hosts = Array.isArray(data.hosts) ? data.hosts : [];

  return (
    <section aria-label={`Check ${checkId}`} className="space-y-5">
      <div className="flex flex-wrap items-center gap-3">
        {onBack ? (
          <button
            type="button"
            onClick={onBack}
            className="rounded border border-slate-700 px-2 py-1 text-sm hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
          >
            ← Back
          </button>
        ) : null}
        <h2 className="font-mono text-lg font-semibold">{sanitizeText(data.checkId)}</h2>
        <span className="text-sm text-slate-400">
          {data.total} host result{data.total === 1 ? "" : "s"}
        </span>
      </div>

      <section aria-labelledby="check-treatments" className="rounded-lg border border-slate-800 p-3">
        <h3 id="check-treatments" className="text-xs font-semibold uppercase tracking-wide text-slate-400">
          Treatment breakdown
        </h3>
        <dl className="mt-2 grid grid-cols-2 gap-3 text-xs sm:grid-cols-4">
          {TREATMENT_STATES.map((state) => (
            <div key={state}>
              <dt className="uppercase tracking-wide text-slate-500">{state.replace(/_/g, " ")}</dt>
              <dd className="mt-0.5 text-lg font-semibold tabular-nums">{data.statusCounts?.[state] ?? 0}</dd>
            </div>
          ))}
        </dl>
      </section>

      {hosts.length === 0 ? (
        <EmptyState title="No hosts currently report this check" />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <caption className="sr-only">Hosts reporting this check</caption>
            <thead>
              <tr className="text-left text-slate-400">
                <th scope="col" className="border-b border-slate-800 py-2 pr-3">Host</th>
                <th scope="col" className="border-b border-slate-800 py-2 pr-3">Status</th>
                <th scope="col" className="border-b border-slate-800 py-2 pr-3">Category</th>
                <th scope="col" className="border-b border-slate-800 py-2 pr-3">Severity</th>
                <th scope="col" className="border-b border-slate-800 py-2 pr-3">Treatment</th>
                <th scope="col" className="border-b border-slate-800 py-2 pr-3">Received</th>
                <th scope="col" className="border-b border-slate-800 py-2">Report</th>
              </tr>
            </thead>
            <tbody>
              {hosts.map((host) => (
                <tr key={`${host.hostId}:${host.reportId}`} className="align-top">
                  <td className="border-b border-slate-900 py-2 pr-3">{sanitizeText(host.displayId)}</td>
                  <td className="border-b border-slate-900 py-2 pr-3">{sanitizeText(host.status)}</td>
                  <td className="border-b border-slate-900 py-2 pr-3">{sanitizeText(host.category)}</td>
                  <td className="border-b border-slate-900 py-2 pr-3">{sanitizeText(host.severity)}</td>
                  <td className="border-b border-slate-900 py-2 pr-3">{sanitizeText(host.treatment)}</td>
                  <td className="border-b border-slate-900 py-2 pr-3">{sanitizeText(host.receivedAt)}</td>
                  <td className="border-b border-slate-900 py-2">
                    <button
                      type="button"
                      onClick={() => onOpenReport?.(host.reportId)}
                      disabled={!onOpenReport}
                      className="rounded border border-slate-700 px-2 py-0.5 text-xs hover:bg-slate-800 disabled:opacity-40 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
                    >
                      Open #{host.reportId}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
