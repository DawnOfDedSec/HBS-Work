import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  CircleDot,
  History,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Wrench,
  X,
} from "lucide-react";
import { api, ApiError } from "../api";
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  Chip,
  EmptyState,
  Input,
  Modal,
  SectionHeader,
  Select,
  Skeleton,
  Stat,
  useToast,
} from "../components/ui";
import { cn } from "../components/ui/cn";
import { SeverityBadge, StatusBadge, TreatmentBadge } from "../components/badges";
import { sanitizeText } from "../components/EvidenceDrawer";
import { ScopeControls, clearScopeKeys } from "../components/ScopeSelector";
import { resolveScope, type ScopeFilters } from "../filters";
import { useScopeFilters } from "../useScopeFilters";

/** Persisted states only - the schema rejects anything else. */
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
  source?: "host" | "network";
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

/** `GET /api/reports/:id/findings/:checkId/history` entry. */
type HistoryEntry = {
  id: number;
  actor: string | null;
  changedAt: string;
  fromState: string | null;
  toState: string;
  justification: string | null;
  assignee: string | null;
  dueDate: string | null;
};

const STATE_LABEL: Record<TreatmentState, string> = {
  open: "Open",
  accepted_risk: "Accepted risk",
  false_positive: "False positive",
  remediated: "Remediated",
};

const STATE_ICON: Record<TreatmentState, typeof CircleDot> = {
  open: CircleDot,
  accepted_risk: ShieldAlert,
  false_positive: CircleDot,
  remediated: ShieldCheck,
};

const STATE_ACCENT: Record<TreatmentState, string> = {
  open: "bg-treatment-open",
  accepted_risk: "bg-treatment-accepted",
  false_positive: "bg-treatment-false-positive",
  remediated: "bg-treatment-remediated",
};

const STATE_CARD: Record<TreatmentState, string> = {
  open: "border-treatment-open/35",
  accepted_risk: "border-treatment-accepted/35",
  false_positive: "border-treatment-false-positive/35",
  remediated: "border-treatment-remediated/35",
};

function isTreatmentState(value: string): value is TreatmentState {
  return (TREATMENT_STATES as readonly string[]).includes(value);
}

function errorMessage(error: unknown): string {
  return error instanceof ApiError ? error.message : "Request failed. Please retry.";
}

function InlineAlert({ children }: { children: ReactNode }) {
  return (
    <div
      role="alert"
      className="flex items-start gap-2 rounded-control border border-critical/40 bg-critical-soft/60 p-3 text-sm text-critical"
    >
      <AlertTriangle size={16} aria-hidden className="mt-0.5 shrink-0" />
      <span>{children}</span>
    </div>
  );
}

export function Treatment() {
  const { filters, query, chips, toggle } = useScopeFilters();
  const toast = useToast();
  const [findings, setFindings] = useState<TreatmentFinding[]>([]);
  const [counts, setCounts] = useState<Record<string, number>>({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<TreatmentFinding | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

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
        if (!alive) return;
        const message = errorMessage(err);
        setError(message);
        toast.error("Could not load the treatment board", { description: message });
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [query, reloadKey, toast]);

  const grouped = useMemo(() => {
    const map = new Map<TreatmentState, TreatmentFinding[]>();
    for (const state of TREATMENT_STATES) map.set(state, []);
    for (const finding of findings) {
      const state = isTreatmentState(finding.treatment) ? finding.treatment : "open";
      map.get(state)?.push(finding);
    }
    return map;
  }, [findings]);

  const apply = useCallback(
    async (
      finding: TreatmentFinding,
      input: { state: TreatmentState; justification: string; assignee: string; dueDate: string },
    ) => {
      const isNetwork = finding.source === "network";
      const response = await api.raw<TreatmentMutation>(
        "POST",
        isNetwork
          ? `/api/network/reports/${finding.reportId}/findings/${encodeURIComponent(finding.checkId)}/treatment`
          : `/api/reports/${finding.reportId}/findings/${encodeURIComponent(finding.checkId)}/treatment`,
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
      const label = STATE_LABEL[isTreatmentState(response.state) ? response.state : "open"];
      setNotice(`Recorded ${label} for ${finding.checkId}.`);
      toast.success(`Treatment updated: ${label}`, { description: `${finding.checkId} · report #${finding.reportId}` });
      setEditing(null);
    },
    [toast],
  );

  const scope = resolveScope(filters);
  const totalFindings = Object.values(counts).reduce((sum, value) => sum + value, 0);

  return (
    <section aria-label="Treatment board" className="mx-auto flex max-w-7xl flex-col gap-5">
      <SectionHeader
        eyebrow="Operate"
        title="Treatment"
        description="Own, accept, or remediate findings. Accepted risk and false positives require a written justification."
        icon={Wrench}
        actions={
          <Button variant="secondary" icon={RefreshCw} loading={loading} onClick={() => setReloadKey((key) => key + 1)}>
            Refresh
          </Button>
        }
      />

      <ScopeControls filters={filters} onToggle={toggle} onClearScope={() => clearScopeKeys(filters)} />

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {TREATMENT_STATES.map((state) => (
          <Stat
            key={state}
            label={STATE_LABEL[state]}
            value={counts[state] ?? 0}
            icon={STATE_ICON[state]}
            tone={
              state === "remediated"
                ? "ok"
                : state === "accepted_risk"
                  ? "high"
                  : state === "false_positive"
                    ? "default"
                    : "accent"
            }
            hint={state === "open" ? "Awaiting triage" : "In the current scope"}
          />
        ))}
      </div>

      {notice ? (
        <div
          role="status"
          className="flex items-center justify-between gap-3 rounded-control border border-accent/40 bg-accent-soft/60 p-3 text-sm text-accent"
        >
          <span>{notice}</span>
          <Button size="sm" variant="ghost" icon={X} onClick={() => setNotice(null)} aria-label="Dismiss notice" />
        </div>
      ) : null}

      {error ? <InlineAlert>{error}</InlineAlert> : null}

      {chips.length > 0 ? (
        <div aria-label="Active filters" className="flex flex-wrap items-center gap-2">
          <span className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">Active</span>
          {chips.map((chip) => (
            <Chip
              key={`${chip.key}:${chip.value}`}
              label={`${chip.key}:`}
              value={chip.value}
              active
              onRemove={() => toggle(chip.key, chip.value)}
            />
          ))}
        </div>
      ) : null}

      {loading && findings.length === 0 ? (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          {TREATMENT_STATES.map((state) => (
            <Card key={state}>
              <Skeleton width="50%" />
              <Skeleton className="mt-3" width="100%" height={48} />
              <Skeleton className="mt-2" width="100%" height={48} />
            </Card>
          ))}
        </div>
      ) : findings.length === 0 ? (
        <EmptyState
          icon={Wrench}
          title="No findings in scope"
          detail={`Choose a scope above to populate treatment states (${scope}).`}
        />
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          {TREATMENT_STATES.map((state) => {
            const column = grouped.get(state) ?? [];
            return (
              <section key={state} aria-label={STATE_LABEL[state]} className="flex flex-col gap-2">
                <div className="flex items-center justify-between">
                  <h3 className="flex items-center gap-2 text-sm font-semibold text-ink">
                    <span className={cn("h-2 w-2 rounded-full", STATE_ACCENT[state])} aria-hidden />
                    {STATE_LABEL[state]}
                  </h3>
                  <Badge tone="neutral">{column.length}</Badge>
                </div>
                <ul className="flex flex-col gap-2">
                  {column.length === 0 ? (
                    <li className="rounded-control border border-dashed border-hairline p-3 text-xs text-ink-subtle">
                      No findings
                    </li>
                  ) : (
                    column.map((finding) => (
                      <li
                        key={`${finding.reportId}:${finding.checkId}`}
                        className={cn("hbs-panel flex flex-col gap-2 p-3", STATE_CARD[state])}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="truncate font-mono text-2xs text-ink-subtle">
                            {sanitizeText(finding.checkId)} · #{finding.reportId}
                          </span>
                          <SeverityBadge severity={finding.severity} />
                        </div>
                        <p className="text-xs font-medium text-ink">{sanitizeText(finding.title)}</p>
                        <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-2xs text-ink-subtle">
                          <span>{sanitizeText(finding.displayId)}</span>
                          <StatusBadge status={finding.status} />
                        </div>
                        {finding.treatmentUpdatedAt ? (
                          <p className="text-2xs text-ink-subtle">
                            Updated {sanitizeText(finding.treatmentUpdatedAt)}
                            {finding.treatmentAssignee ? ` · ${sanitizeText(finding.treatmentAssignee)}` : ""}
                            {finding.treatmentDueDate ? ` · due ${sanitizeText(finding.treatmentDueDate)}` : ""}
                          </p>
                        ) : null}
                        <div className="mt-auto flex items-center justify-between gap-2 pt-1">
                          <TreatmentBadge state={finding.treatment} />
                          <Button size="sm" variant="secondary" onClick={() => setEditing(finding)}>
                            Change treatment
                          </Button>
                        </div>
                      </li>
                    ))
                  )}
                </ul>
              </section>
            );
          })}
        </div>
      )}

      <Card>
        <CardHeader
          icon={History}
          title="Change history"
          description="Every transition is append-only; the timeline is fetched per finding when you open the treatment dialog."
        />
        <CardBody>
          <p className="text-xs text-ink-subtle">
            {totalFindings} finding{totalFindings === 1 ? "" : "s"} in scope ·{" "}
            {counts.remediated ?? 0} remediated · {counts.open ?? 0} open.
          </p>
        </CardBody>
      </Card>

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
  const [state, setState] = useState<TreatmentState>("open");
  const [justification, setJustification] = useState("");
  const [assignee, setAssignee] = useState("");
  const [dueDate, setDueDate] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);

  useEffect(() => {
    if (!finding) return;
    setState(isTreatmentState(finding.treatment) ? finding.treatment : "open");
    setJustification("");
    setAssignee(finding.treatmentAssignee ?? "");
    setDueDate(finding.treatmentDueDate ? finding.treatmentDueDate.slice(0, 10) : "");
    setError(null);
    setHistory([]);
    setHistoryLoading(true);
    let alive = true;
    api
      .raw<{ history: HistoryEntry[] }>(
        "GET",
        finding.source === "network"
          ? `/api/network/reports/${finding.reportId}/findings/${encodeURIComponent(finding.checkId)}/history`
          : `/api/reports/${finding.reportId}/findings/${encodeURIComponent(finding.checkId)}/history`,
      )
      .then((response) => {
        if (alive) setHistory(Array.isArray(response.history) ? response.history : []);
      })
      .catch(() => {
        if (alive) setHistory([]);
      })
      .finally(() => {
        if (alive) setHistoryLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [finding]);

  if (!finding) return null;

  const justificationRequired = state === "accepted_risk" || state === "false_positive";
  const justificationMissing = justificationRequired && justification.trim().length === 0;

  return (
    <Modal
      open={Boolean(finding)}
      onClose={onCancel}
      title="Change treatment"
      description={`${sanitizeText(finding.checkId)} · report #${finding.reportId} · ${sanitizeText(finding.displayId)}`}
      size="lg"
      footer={
        <>
          <Button variant="secondary" onClick={onCancel}>
            Cancel
          </Button>
          <Button
            variant="primary"
            loading={submitting}
            disabled={justificationMissing}
            onClick={() => {
              if (justificationMissing) {
                setError("Justification is required for accepted risk and false positive.");
                return;
              }
              setSubmitting(true);
              setError(null);
              void onSubmit({ state, justification: justification.trim(), assignee: assignee.trim(), dueDate })
                .catch((err) => setError(errorMessage(err)))
                .finally(() => setSubmitting(false));
            }}
          >
            Save treatment
          </Button>
        </>
      }
    >
      <div className="grid gap-4 lg:grid-cols-[1fr_18rem]">
        <div className="flex flex-col gap-3">
          <Select
            label="State"
            value={state}
            onChange={(value) => setState(value as TreatmentState)}
            options={TREATMENT_STATES.map((option) => ({ value: option, label: STATE_LABEL[option] }))}
          />
          <label className="block">
            <span className="text-2xs font-medium text-ink-muted">
              Justification {justificationRequired ? "(required)" : "(optional)"}
            </span>
            <textarea
              value={justification}
              onChange={(event) => setJustification(event.target.value)}
              rows={3}
              aria-invalid={justificationMissing}
              className="mt-1 w-full rounded-control border border-control-edge bg-surface-raised px-3 py-2 text-sm text-ink placeholder:text-ink-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus"
            />
          </label>
          <div className="grid gap-3 sm:grid-cols-2">
            <Input label="Assignee (optional)" value={assignee} onChange={(event) => setAssignee(event.target.value)} />
            <Input label="Due date (optional)" type="date" value={dueDate} onChange={(event) => setDueDate(event.target.value)} />
          </div>
          {error ? <InlineAlert>{error}</InlineAlert> : null}
        </div>

        <div className="hbs-inset hbs-scroll max-h-80 overflow-y-auto p-3">
          <h4 className="flex items-center gap-1.5 text-2xs font-semibold uppercase tracking-wide text-ink-subtle">
            <History size={13} aria-hidden /> History
          </h4>
          {historyLoading ? (
            <div className="mt-2 flex flex-col gap-2">
              <Skeleton height={32} />
              <Skeleton height={32} />
            </div>
          ) : history.length === 0 ? (
            <p className="mt-2 flex items-center gap-1.5 text-xs text-ink-subtle">
              <CheckCircle2 size={13} aria-hidden /> No recorded transitions.
            </p>
          ) : (
            <ol className="mt-2 space-y-2">
              {history.map((entry) => (
                <li key={entry.id} className="border-l-2 border-hairline pl-2.5 text-2xs">
                  <div className="flex flex-wrap items-center gap-1.5">
                    {entry.fromState ? <Badge tone="neutral">{STATE_LABEL[isTreatmentState(entry.fromState) ? entry.fromState : "open"]}</Badge> : null}
                    <span className="text-ink-subtle">→</span>
                    <Badge tone="accent">{STATE_LABEL[isTreatmentState(entry.toState) ? entry.toState : "open"]}</Badge>
                  </div>
                  <p className="mt-1 text-ink-muted">
                    {sanitizeText(entry.actor) || "system"} · {sanitizeText(entry.changedAt)}
                  </p>
                  {entry.assignee ? <p className="text-ink-subtle">assignee {sanitizeText(entry.assignee)}</p> : null}
                  {entry.dueDate ? <p className="text-ink-subtle">due {sanitizeText(entry.dueDate)}</p> : null}
                  {entry.justification ? (
                    <p className="mt-1 text-ink-muted">{sanitizeText(entry.justification)}</p>
                  ) : null}
                </li>
              ))}
            </ol>
          )}
        </div>
      </div>
    </Modal>
  );
}
