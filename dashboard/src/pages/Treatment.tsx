import { useEffect, useId, useMemo, useRef, useState } from "react";
import { X } from "lucide-react";
import { api, ApiError } from "../api";
import { EmptyState } from "../components/EmptyState";
import { sanitizeText } from "../components/EvidenceDrawer";
import { resolveScope, serializeFilters, type ScopeFilters } from "../filters";
import { useScopeFilters } from "../useScopeFilters";

/** Persisted states only — the schema rejects anything else. */
export const TREATMENT_STATES = ["open", "accepted_risk", "false_positive", "remediated"] as const;
export type TreatmentState = (typeof TREATMENT_STATES)[number];

/** `GET /api/treatment` serializes findings with their current treatment projection. */
type TreatmentFinding = {
  reportId: number;
  campaignId: number;
  locationId: number;
  hostId: number;
  hostname: string;
  displayId: string;
  checkId: string;
  title: string;
  severity: string;
  status: string;
  category: string;
  treatment: string;
  treatmentAssignee: string | null;
  treatmentDueDate: string | null;
  treatmentUpdatedAt: string | null;
  receivedAt: string;
};

type TreatmentResponse = {
  autoResolved: number;
  counts: Record<string, number>;
  findings: TreatmentFinding[];
  total: number;
};

/** `POST /api/reports/:id/findings/:checkId/treatment` response. */
type TreatmentMutation = {
  reportId: number;
  checkId: string;
  state: string;
  justification: string | null;
  assignee: string | null;
  dueDate: string | null;
  updatedAt: string;
  historyId: number;
};

type HistoryEntry = {
  historyId: number;
  reportId: number;
  checkId: string;
  state: string;
  justification: string | null;
  assignee: string | null;
  dueDate: string | null;
  changedAt: string;
};

const STATE_LABEL: Record<TreatmentState, string> = {
  open: "Open",
  accepted_risk: "Accepted risk",
  false_positive: "False positive",
  remediated: "Remediated",
};

const STATE_TONE: Record<TreatmentState, string> = {
  open: "border-sky-500/50",
  accepted_risk: "border-amber-500/50",
  false_positive: "border-fuchsia-500/50",
  remediated: "border-emerald-500/50",
};

function isTreatmentState(value: string): value is TreatmentState {
  return (TREATMENT_STATES as readonly string[]).includes(value);
}

function errorMessage(error: unknown): string {
  return error instanceof ApiError ? error.message : "Request failed. Please retry.";
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

export function Treatment() {
  const { filters, query, chips, toggle } = useScopeFilters();
  const [findings, setFindings] = useState<TreatmentFinding[]>([]);
  const [counts, setCounts] = useState<Record<string, number>>({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<TreatmentFinding | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(null);
    api
      .raw<TreatmentResponse>("GET", `/api/treatment${query ? `?${query}` : ""}`)
      .then((response) => {
        if (!alive) return;
        setFindings(Array.isArray(response.findings) ? response.findings : []);
        setCounts(response.counts ?? {});
        if (response.autoResolved > 0) {
          setNotice(`${response.autoResolved} treatment(s) were auto-resolved by a newer scan.`);
        }
      })
      .catch((err) => {
        if (alive) setError(errorMessage(err));
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [query]);

  const grouped = useMemo(() => {
    const map = new Map<TreatmentState, TreatmentFinding[]>();
    for (const state of TREATMENT_STATES) map.set(state, []);
    for (const finding of findings) {
      const state = isTreatmentState(finding.treatment) ? finding.treatment : "open";
      map.get(state)?.push(finding);
    }
    return map;
  }, [findings]);

  const historyByFinding = useMemo(() => {
    const map = new Map<string, HistoryEntry[]>();
    for (const entry of history) {
      const key = `${entry.reportId}:${entry.checkId}`;
      const bucket = map.get(key) ?? [];
      bucket.push(entry);
      map.set(key, bucket);
    }
    return map;
  }, [history]);

  async function apply(
    finding: TreatmentFinding,
    input: { state: TreatmentState; justification: string; assignee: string; dueDate: string },
  ) {
    const response = await api.raw<TreatmentMutation>(
      "POST",
      `/api/reports/${finding.reportId}/findings/${encodeURIComponent(finding.checkId)}/treatment`,
      {
        state: input.state,
        ...(input.justification ? { justification: input.justification } : {}),
        ...(input.assignee ? { assignee: input.assignee } : {}),
        ...(input.dueDate ? { dueDate: input.dueDate } : {}),
      },
    );
    setFindings((current) =>
      current.map((entry) =>
        entry.reportId === finding.reportId && entry.checkId === finding.checkId
          ? {
              ...entry,
              treatment: response.state,
              treatmentAssignee: response.assignee,
              treatmentDueDate: response.dueDate,
              treatmentUpdatedAt: response.updatedAt,
            }
          : entry,
      ),
    );
    setCounts((current) => {
      const next = { ...current };
      next[finding.treatment] = Math.max(0, (next[finding.treatment] ?? 1) - 1);
      next[response.state] = (next[response.state] ?? 0) + 1;
      return next;
    });
    setHistory((current) => [
      {
        historyId: response.historyId,
        reportId: response.reportId,
        checkId: response.checkId,
        state: response.state,
        justification: response.justification,
        assignee: response.assignee,
        dueDate: response.dueDate,
        changedAt: response.updatedAt,
      },
      ...current,
    ]);
    setNotice(`Recorded ${STATE_LABEL[isTreatmentState(response.state) ? response.state : "open"]} for ${finding.checkId}.`);
    setEditing(null);
  }

  const scope = resolveScope(filters);

  return (
    <section aria-label="Treatment board" className="space-y-4">
      <fieldset className="flex flex-wrap items-end gap-4 rounded-lg border border-slate-800 p-3">
        <legend className="px-1 text-xs uppercase tracking-wide text-slate-400">Scope</legend>
        <label className="flex items-center gap-2 text-sm">
          <input type="radio" name="treatment-scope" checked={scope === "latest"} onChange={() => clearScopeKeys(filters)} />
          Latest state
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="radio"
            name="treatment-scope"
            checked={scope === "report"}
            onChange={() => toggle("scope", "report")}
          />
          Single report
        </label>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="radio"
            name="treatment-scope"
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
        {chips.length > 0 ? (
          <span className="text-xs text-slate-400">{chips.length} active filter(s)</span>
        ) : null}
      </fieldset>

      {notice ? (
        <p role="status" className="rounded border border-sky-500/40 bg-sky-500/10 p-2 text-sm text-sky-100">
          {notice}
          <button
            type="button"
            onClick={() => setNotice(null)}
            className="ml-2 underline underline-offset-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-300"
          >
            Dismiss
          </button>
        </p>
      ) : null}

      {error ? (
        <EmptyState title="Could not load the treatment board" detail={error} />
      ) : loading && findings.length === 0 ? (
        <p role="status">Loading treatment board…</p>
      ) : findings.length === 0 ? (
        <EmptyState title="No findings in scope" detail="Choose a scope above to populate treatment states." />
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          {TREATMENT_STATES.map((state) => {
            const column = grouped.get(state) ?? [];
            return (
              <section key={state} aria-label={STATE_LABEL[state]} className="space-y-2">
                <h3 className="flex items-center justify-between text-sm font-semibold">
                  <span>{STATE_LABEL[state]}</span>
                  <span className="text-xs text-slate-400 tabular-nums">{column.length}</span>
                </h3>
                <ul className="space-y-2">
                  {column.length === 0 ? (
                    <li className="rounded border border-dashed border-slate-800 p-3 text-xs text-slate-500">
                      No findings
                    </li>
                  ) : (
                    column.map((finding) => (
                      <li
                        key={`${finding.reportId}:${finding.checkId}`}
                        className={`rounded-lg border bg-slate-900/50 p-3 text-xs ${STATE_TONE[state]}`}
                      >
                        <p className="font-mono text-[11px] text-slate-400">
                          {sanitizeText(finding.checkId)} · #{finding.reportId}
                        </p>
                        <p className="mt-1 text-sm text-slate-100">{sanitizeText(finding.title)}</p>
                        <p className="mt-1 text-slate-400">
                          {sanitizeText(finding.displayId)} · {sanitizeText(finding.severity)} ·{" "}
                          {sanitizeText(finding.status)}
                        </p>
                        {finding.treatmentUpdatedAt ? (
                          <p className="mt-1 text-[11px] text-slate-500">
                            Updated {sanitizeText(finding.treatmentUpdatedAt)}
                            {finding.treatmentAssignee ? ` · ${sanitizeText(finding.treatmentAssignee)}` : ""}
                            {finding.treatmentDueDate ? ` · due ${sanitizeText(finding.treatmentDueDate)}` : ""}
                          </p>
                        ) : null}
                        {(historyByFinding.get(`${finding.reportId}:${finding.checkId}`) ?? [])
                          .slice(0, 2)
                          .map((entry) => (
                          <p key={entry.historyId} className="mt-1 text-[11px] text-slate-500">
                            {sanitizeText(entry.changedAt)}: {STATE_LABEL[isTreatmentState(entry.state) ? entry.state : "open"]}
                          </p>
                        ))}
                        <button
                          type="button"
                          onClick={() => setEditing(finding)}
                          className="mt-2 rounded border border-slate-700 px-2 py-0.5 text-slate-200 hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
                        >
                          Change treatment
                        </button>
                      </li>
                    ))
                  )}
                </ul>
              </section>
            );
          })}
        </div>
      )}

      <section aria-labelledby="treatment-history" className="rounded-lg border border-slate-800 p-3">
        <h3 id="treatment-history" className="text-xs font-semibold uppercase tracking-wide text-slate-400">
          Change history
        </h3>
        <p className="mt-1 text-xs text-slate-500">
          The treatment API returns the current projection plus a `historyId` per mutation; this session&apos;s
          recorded transitions appear below.
        </p>
        {history.length === 0 ? (
          <p className="mt-2 text-xs text-slate-500">No changes recorded in this session.</p>
        ) : (
          <ol className="mt-2 space-y-1 text-xs">
            {history.map((entry) => (
              <li key={entry.historyId} className="rounded border border-slate-800 p-2">
                <span className="font-mono text-slate-400">{sanitizeText(entry.checkId)}</span> →{" "}
                <span className="text-slate-100">
                  {STATE_LABEL[isTreatmentState(entry.state) ? entry.state : "open"]}
                </span>{" "}
                <span className="text-slate-500">at {sanitizeText(entry.changedAt)}</span>
                {entry.justification ? (
                  <span className="ml-1 text-slate-400">· {sanitizeText(entry.justification)}</span>
                ) : null}
              </li>
            ))}
          </ol>
        )}
      </section>

      <TreatmentModal
        finding={editing}
        onCancel={() => setEditing(null)}
        onSubmit={(input) => (editing ? apply(editing, input) : Promise.resolve())}
      />
    </section>
  );
}

function TreatmentModal({
  finding,
  onCancel,
  onSubmit,
}: {
  finding: TreatmentFinding | null;
  onCancel: () => void;
  onSubmit: (input: { state: TreatmentState; justification: string; assignee: string; dueDate: string }) => Promise<void>;
}) {
  const titleId = useId();
  const dialogRef = useRef<HTMLDivElement>(null);
  const [state, setState] = useState<TreatmentState>("open");
  const [justification, setJustification] = useState("");
  const [assignee, setAssignee] = useState("");
  const [dueDate, setDueDate] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!finding) return;
    setState(isTreatmentState(finding.treatment) ? finding.treatment : "open");
    setJustification("");
    setAssignee(finding.treatmentAssignee ?? "");
    setDueDate(finding.treatmentDueDate ? finding.treatmentDueDate.slice(0, 10) : "");
    setError(null);
    const node = dialogRef.current;
    node?.focus();
  }, [finding]);

  useEffect(() => {
    if (!finding) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onCancel();
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [finding, onCancel]);

  if (!finding) return null;

  const justificationRequired = state === "accepted_risk" || state === "false_positive";
  const justificationMissing = justificationRequired && justification.trim().length === 0;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/70 p-4">
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        className="w-full max-w-lg rounded-lg border border-slate-700 bg-slate-900 p-4 shadow-2xl focus:outline-none"
      >
        <div className="flex items-start justify-between gap-3">
          <div>
            <h2 id={titleId} className="text-base font-semibold">
              Change treatment
            </h2>
            <p className="mt-0.5 font-mono text-xs text-slate-400">
              {sanitizeText(finding.checkId)} · report #{finding.reportId}
            </p>
          </div>
          <button
            type="button"
            onClick={onCancel}
            aria-label="Close"
            className="rounded border border-slate-700 p-1 text-slate-300 hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
          >
            <X size={16} aria-hidden />
          </button>
        </div>

        <form
          className="mt-4 space-y-3 text-sm"
          onSubmit={(event) => {
            event.preventDefault();
            if (justificationMissing) {
              setError("Justification is required for accepted risk and false positive.");
              return;
            }
            setSubmitting(true);
            setError(null);
            void onSubmit({ state, justification: justification.trim(), assignee: assignee.trim(), dueDate })
              .catch((err) => {
                setError(errorMessage(err));
              })
              .finally(() => setSubmitting(false));
          }}
        >
          <label className="block">
            <span className="text-xs uppercase tracking-wide text-slate-400">State</span>
            <select
              value={state}
              onChange={(event) => setState(event.target.value as TreatmentState)}
              className="mt-1 w-full rounded border border-slate-700 bg-slate-900 px-2 py-1"
            >
              {TREATMENT_STATES.map((option) => (
                <option key={option} value={option}>
                  {STATE_LABEL[option]}
                </option>
              ))}
            </select>
          </label>

          <label className="block">
            <span className="text-xs uppercase tracking-wide text-slate-400">
              Justification {justificationRequired ? "(required)" : "(optional)"}
            </span>
            <textarea
              value={justification}
              onChange={(event) => setJustification(event.target.value)}
              rows={3}
              aria-invalid={justificationMissing}
              className="mt-1 w-full rounded border border-slate-700 bg-slate-900 px-2 py-1"
            />
          </label>

          <div className="grid gap-3 sm:grid-cols-2">
            <label className="block">
              <span className="text-xs uppercase tracking-wide text-slate-400">Assignee (optional)</span>
              <input
                value={assignee}
                onChange={(event) => setAssignee(event.target.value)}
                className="mt-1 w-full rounded border border-slate-700 bg-slate-900 px-2 py-1"
              />
            </label>
            <label className="block">
              <span className="text-xs uppercase tracking-wide text-slate-400">Due date (optional)</span>
              <input
                type="date"
                value={dueDate}
                onChange={(event) => setDueDate(event.target.value)}
                className="mt-1 w-full rounded border border-slate-700 bg-slate-900 px-2 py-1"
              />
            </label>
          </div>

          {error ? (
            <p role="alert" className="rounded border border-red-500/50 bg-red-500/10 p-2 text-red-200">
              {error}
            </p>
          ) : null}

          <div className="flex justify-end gap-2 pt-1">
            <button
              type="button"
              onClick={onCancel}
              className="rounded border border-slate-700 px-3 py-1.5 hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="rounded bg-sky-600 px-3 py-1.5 font-medium text-white hover:bg-sky-500 disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-300"
            >
              {submitting ? "Saving…" : "Save treatment"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
