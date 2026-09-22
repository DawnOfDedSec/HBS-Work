import { useEffect, useState } from "react";
import { api, ApiError } from "../api";
import { EmptyState } from "../components/EmptyState";
import { sanitizeText } from "../components/EvidenceDrawer";

type DiffEntry = {
  checkId: string;
  title: string;
  severity: string;
  category: string;
  from: string | null;
  to: string | null;
};

type DiffResponse = {
  hostId: number;
  baseReportId: number;
  targetReportId: number;
  summary: { fixed: number; regressed: number; unchanged: number; added: number; removed: number };
  fixed: DiffEntry[];
  regressed: DiffEntry[];
  unchanged: DiffEntry[];
  added: DiffEntry[];
  removed: DiffEntry[];
};

export type DiffProps = {
  /** The earlier (baseline) report. */
  baseReportId: number;
  /** The newer report. When omitted the user supplies one. */
  targetReportId?: number | null;
  onBack?: () => void;
  onOpenCheck?: (checkId: string) => void;
};

const SEVERITY_TONE: Record<string, string> = {
  Critical: "text-red-300",
  High: "text-amber-300",
  Medium: "text-yellow-200",
  Low: "text-sky-300",
  Informational: "text-slate-300",
};

function DiffColumn({
  title,
  detail,
  entries,
  onOpenCheck,
  tone,
}: {
  title: string;
  detail: string;
  entries: DiffEntry[];
  onOpenCheck?: (checkId: string) => void;
  tone: string;
}) {
  return (
    <section aria-label={title} className="rounded-lg border border-slate-800">
      <header className="flex items-baseline justify-between border-b border-slate-800 px-3 py-2">
        <h3 className={`text-sm font-semibold ${tone}`}>{title}</h3>
        <span className="text-xs text-slate-400">{entries.length}</span>
      </header>
      <p className="px-3 pt-2 text-xs text-slate-500">{detail}</p>
      <ul className="space-y-1 p-3">
        {entries.length === 0 ? (
          <li className="text-xs text-slate-500">None</li>
        ) : (
          entries.map((entry) => (
            <li key={entry.checkId} className="rounded border border-slate-800 bg-slate-900/40 p-2 text-xs">
              <button
                type="button"
                onClick={() => onOpenCheck?.(entry.checkId)}
                disabled={!onOpenCheck}
                className="font-mono text-sky-300 underline underline-offset-2 disabled:text-slate-300 disabled:no-underline focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
              >
                {sanitizeText(entry.checkId)}
              </button>
              <p className="mt-0.5 text-slate-200">{sanitizeText(entry.title)}</p>
              <p className="mt-0.5 text-slate-500">
                <span className={SEVERITY_TONE[entry.severity] ?? ""}>{sanitizeText(entry.severity)}</span>
                {" · "}
                {sanitizeText(entry.from) || "absent"} → {sanitizeText(entry.to) || "absent"}
              </p>
            </li>
          ))
        )}
      </ul>
    </section>
  );
}

/** Side-by-side Fixed / Regressed / Unchanged comparison of two reports for one host. */
export function Diff({ baseReportId, targetReportId, onBack, onOpenCheck }: DiffProps) {
  const [targetInput, setTargetInput] = useState(targetReportId ? String(targetReportId) : "");
  const [target, setTarget] = useState<number | null>(targetReportId ?? null);
  const [data, setData] = useState<DiffResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setTarget(targetReportId ?? null);
    setTargetInput(targetReportId ? String(targetReportId) : "");
  }, [targetReportId]);

  useEffect(() => {
    if (target === null) {
      setData(null);
      return;
    }
    let alive = true;
    setLoading(true);
    setError(null);
    api
      .raw<DiffResponse>("GET", `/api/reports/${baseReportId}/diff/${target}`)
      .then((value) => {
        if (alive) setData(value);
      })
      .catch((err) => {
        if (alive) {
          setData(null);
          setError(err instanceof ApiError ? err.message : "Request failed. Please retry.");
        }
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [baseReportId, target]);

  return (
    <section aria-label="Report comparison" className="space-y-5">
      <div className="flex flex-wrap items-end gap-3">
        {onBack ? (
          <button
            type="button"
            onClick={onBack}
            className="rounded border border-slate-700 px-2 py-1 text-sm hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
          >
            ← Back
          </button>
        ) : null}
        <h2 className="text-lg font-semibold">
          Diff · report #{baseReportId}
          {target !== null ? ` → #${target}` : ""}
        </h2>
        <form
          className="flex items-end gap-2"
          onSubmit={(event) => {
            event.preventDefault();
            const parsed = Number(targetInput);
            if (Number.isSafeInteger(parsed) && parsed > 0) setTarget(parsed);
          }}
        >
          <label className="flex flex-col text-xs text-slate-400">
            Compare against report
            <input
              type="number"
              min={1}
              value={targetInput}
              onChange={(event) => setTargetInput(event.target.value)}
              className="mt-1 w-32 rounded border border-slate-700 bg-slate-900 px-2 py-1 text-sm"
            />
          </label>
          <button
            type="submit"
            className="rounded border border-slate-700 px-2 py-1 text-sm hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
          >
            Compare
          </button>
        </form>
      </div>

      {target === null ? (
        <EmptyState title="Choose a report to compare" detail="Enter a report ID from the same host to diff against." />
      ) : error ? (
        <EmptyState title="Could not load diff" detail={error} />
      ) : loading && !data ? (
        <p role="status">Loading diff…</p>
      ) : !data ? (
        <EmptyState title="No diff available" />
      ) : (
        <>
          <dl className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-5">
            <SummaryStat label="Fixed" value={data.summary.fixed} tone="text-emerald-300" />
            <SummaryStat label="Regressed" value={data.summary.regressed} tone="text-red-300" />
            <SummaryStat label="Unchanged" value={data.summary.unchanged} tone="text-slate-300" />
            <SummaryStat label="Added" value={data.summary.added} tone="text-sky-300" />
            <SummaryStat label="Removed" value={data.summary.removed} tone="text-amber-300" />
          </dl>

          <div className="grid gap-4 lg:grid-cols-3">
            <DiffColumn
              title="Fixed"
              detail="Broken before, compliant after."
              entries={data.fixed}
              onOpenCheck={onOpenCheck}
              tone="text-emerald-300"
            />
            <DiffColumn
              title="Regressed"
              detail="Compliant before, broken after."
              entries={data.regressed}
              onOpenCheck={onOpenCheck}
              tone="text-red-300"
            />
            <DiffColumn
              title="Unchanged"
              detail="Same status in both reports."
              entries={data.unchanged}
              onOpenCheck={onOpenCheck}
              tone="text-slate-300"
            />
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <DiffColumn
              title="Added"
              detail="Present only in the newer report."
              entries={data.added}
              onOpenCheck={onOpenCheck}
              tone="text-sky-300"
            />
            <DiffColumn
              title="Removed"
              detail="Present only in the baseline report."
              entries={data.removed}
              onOpenCheck={onOpenCheck}
              tone="text-amber-300"
            />
          </div>
        </>
      )}
    </section>
  );
}

function SummaryStat({ label, value, tone }: { label: string; value: number; tone: string }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-3">
      <dt className="text-xs uppercase tracking-wide text-slate-500">{label}</dt>
      <dd className={`mt-0.5 text-2xl font-semibold tabular-nums ${tone}`}>{value}</dd>
    </div>
  );
}
