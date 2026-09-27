// Shared rendering for network configuration-review findings: score badge,
// findings table, and the detail modal with the treatment workflow.

import { useEffect, useState } from "react";
import { ClipboardList, History, ShieldCheck } from "lucide-react";
import { api, ApiError } from "../api";
import {
  Badge,
  Button,
  Input,
  Modal,
  Select,
  Table,
  useToast,
  type BadgeTone,
  type TableColumn,
} from "./ui";
import { SeverityBadge, StatusBadge, TreatmentBadge } from "./badges";
import { sanitizeText } from "./EvidenceDrawer";
import type { NetworkFinding, NetworkTreatmentHistoryEntry } from "../network-types";

const TREATMENT_STATES = ["open", "accepted_risk", "false_positive", "remediated"] as const;
type TreatmentStateValue = (typeof TREATMENT_STATES)[number];

export function scoreTone(score: number | null | undefined): BadgeTone {
  if (typeof score !== "number") return "neutral";
  if (score >= 90) return "compliant";
  if (score >= 70) return "accent";
  if (score >= 40) return "degraded";
  return "critical";
}

const CANONICAL_STATES: ReadonlySet<string> = new Set<string>(TREATMENT_STATES);

function asState(value: string): TreatmentStateValue {
  return (CANONICAL_STATES.has(value) ? value : "open") as TreatmentStateValue;
}

/** Batch treatment editor shared by the multi-select flow. */
function NetworkBulkTreatmentModal({
  reportId,
  checkIds,
  onClose,
  onDone,
}: {
  reportId: number;
  checkIds: string[];
  onClose: () => void;
  onDone: () => void;
}) {
  const toast = useToast();
  const [state, setState] = useState<TreatmentStateValue>("remediated");
  const [justification, setJustification] = useState("");
  const [assignee, setAssignee] = useState("");
  const [dueDate, setDueDate] = useState("");
  const [saving, setSaving] = useState(false);
  const needsJustification = state === "accepted_risk" || state === "false_positive";

  async function submit() {
    setSaving(true);
    try {
      const response = await api.bulkUpdateNetworkTreatment(reportId, {
        checkIds,
        state,
        justification: needsJustification || justification.trim() ? justification.trim() : undefined,
        assignee: assignee.trim() || undefined,
        dueDate: dueDate.trim() || undefined,
      });
      const failed = response.skipped.length;
      toast.success(`${response.applied.length} finding(s) updated`, {
        description: failed > 0 ? `${failed} skipped` : state,
      });
      onDone();
      onClose();
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "could not update treatments";
      toast.error("Could not update treatments", { description: message });
    } finally {
      setSaving(false);
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      size="lg"
      title={`Treat ${checkIds.length} finding(s)`}
      description="The same state and justification are applied to every selected check."
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" icon={ShieldCheck} loading={saving} onClick={() => void submit()}>
            Apply to {checkIds.length}
          </Button>
        </>
      }
    >
      <div className="grid gap-3 sm:grid-cols-2">
        <Select
          label="State"
          value={state}
          onChange={(value) => setState(value as TreatmentStateValue)}
          options={TREATMENT_STATES.map((entry) => ({ value: entry, label: entry.replace("_", " ") }))}
        />
        <Input label="Assignee" value={assignee} onChange={(event) => setAssignee(event.target.value)} placeholder="netops" />
        <Input
          label="Justification"
          value={justification}
          onChange={(event) => setJustification(event.target.value)}
          placeholder={needsJustification ? "Required for accepted risk / false positive" : "Optional"}
          required={needsJustification}
          containerClassName="sm:col-span-2"
        />
        <Input label="Due date" type="date" value={dueDate} onChange={(event) => setDueDate(event.target.value)} />
      </div>
    </Modal>
  );
}

type FindingDetail = {
  finding: NetworkFinding;
  reportId: number;
  canEdit: boolean;
  onChanged?: () => void;
};
/** Full finding detail: evidence, recommendation, standards, treatment, history. */
function NetworkFindingModal({ finding, reportId, canEdit, onChanged, onClose }: FindingDetail & { onClose: () => void }) {
  const toast = useToast();
  const [state, setState] = useState<string>(asState(finding.treatmentState ?? "open"));
  const [justification, setJustification] = useState("");
  const [assignee, setAssignee] = useState("");
  const [dueDate, setDueDate] = useState("");
  const [saving, setSaving] = useState(false);
  const [history, setHistory] = useState<NetworkTreatmentHistoryEntry[] | null>(null);

  useEffect(() => {
    let alive = true;
    api
      .getNetworkTreatmentHistory(reportId, finding.checkId)
      .then((response) => alive && setHistory(response.history))
      .catch(() => alive && setHistory(null));
    return () => {
      alive = false;
    };
  }, [reportId, finding.checkId, saving]);

  const needsJustification = state === "accepted_risk" || state === "false_positive";

  async function submit() {
    setSaving(true);
    try {
      await api.updateNetworkTreatment(reportId, finding.checkId, {
        state: state as TreatmentStateValue,
        justification: needsJustification || justification.trim() ? justification.trim() : undefined,
        assignee: assignee.trim() || undefined,
        dueDate: dueDate.trim() || undefined,
      });
      toast.success("Treatment updated", { description: `${finding.checkId} → ${state}` });
      onChanged?.();
      onClose();
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "could not update treatment";
      toast.error("Could not update treatment", { description: message });
    } finally {
      setSaving(false);
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      size="lg"
      title={
        <span className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-xs text-ink-muted">{finding.checkId}</span>
          {sanitizeText(finding.title)}
        </span>
      }
      description={
        <span className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={finding.severity} />
          <StatusBadge status={finding.status} />
          <TreatmentBadge state={asState(finding.treatmentState ?? "open")} />
        </span>
      }
      footer={
        canEdit ? (
          <>
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" icon={ShieldCheck} loading={saving} onClick={() => void submit()}>
              Save treatment
            </Button>
          </>
        ) : (
          <Button variant="secondary" onClick={onClose}>
            Close
          </Button>
        )
      }
    >
      <div className="flex flex-col gap-4">
        <p className="text-sm text-ink-muted">{sanitizeText(finding.description)}</p>

        {finding.evidence.length > 0 ? (
          <div>
            <h4 className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">Evidence (redacted)</h4>
            <pre className="hbs-inset hbs-scroll mt-1 max-h-44 overflow-auto rounded-control p-3 font-mono text-2xs leading-relaxed text-ink-muted">
              {finding.evidence.join("\n")}
            </pre>
          </div>
        ) : null}

        <div>
          <h4 className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">Recommendation</h4>
          <p className="mt-1 text-sm text-ink">{sanitizeText(finding.recommendation)}</p>
        </div>

        {finding.references.length > 0 ? (
          <div>
            <h4 className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">Standards & references</h4>
            <ul className="mt-1 flex flex-wrap gap-1">
              {finding.references.map((reference) => (
                <li key={reference}>
                  <Badge tone="info">{sanitizeText(reference)}</Badge>
                </li>
              ))}
            </ul>
          </div>
        ) : null}

        {canEdit ? (
          <div className="hbs-inset flex flex-col gap-3 rounded-control p-3">
            <h4 className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">Treatment</h4>
            <div className="grid gap-3 sm:grid-cols-2">
              <Select
                label="State"
                value={state}
                onChange={(value) => setState(value)}
                options={TREATMENT_STATES.map((entry) => ({ value: entry, label: entry.replace("_", " ") }))}
              />
              <Input
                label="Assignee"
                value={assignee}
                onChange={(event) => setAssignee(event.target.value)}
                placeholder="netops"
              />
              <Input
                label="Justification"
                value={justification}
                onChange={(event) => setJustification(event.target.value)}
                placeholder={needsJustification ? "Required for accepted risk / false positive" : "Optional"}
                required={needsJustification}
                containerClassName="sm:col-span-2"
              />
              <Input
                label="Due date"
                type="date"
                value={dueDate}
                onChange={(event) => setDueDate(event.target.value)}
              />
            </div>
          </div>
        ) : null}

        {history && history.length > 0 ? (
          <div>
            <h4 className="flex items-center gap-1.5 text-2xs font-semibold uppercase tracking-wide text-ink-subtle">
              <History size={12} aria-hidden /> Treatment history
            </h4>
            <ol className="mt-1 flex flex-col gap-1">
              {history.map((entry) => (
                <li key={entry.id} className="text-2xs text-ink-muted">
                  <span className="tabular-nums">{new Date(entry.changedAt).toLocaleString()}</span> ·{" "}
                  {sanitizeText(entry.actor) || "system"}: {sanitizeText(entry.fromState ?? "-")} →{" "}
                  <span className="text-ink">{sanitizeText(entry.toState)}</span>
                  {entry.justification ? ` - “${sanitizeText(entry.justification)}”` : ""}
                </li>
              ))}
            </ol>
          </div>
        ) : null}
      </div>
    </Modal>
  );
}

export type NetworkFindingsTableProps = {
  findings: NetworkFinding[];
  reportId: number;
  canEdit: boolean;
  onChanged?: () => void;
  /** Only failing checks by default. */
  failingOnly?: boolean;
};

/** Review findings for one network report, with the treatment workflow. */
export function NetworkFindingsTable({ findings, reportId, canEdit, onChanged, failingOnly = true }: NetworkFindingsTableProps) {
  const [selected, setSelected] = useState<NetworkFinding | null>(null);
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [bulkOpen, setBulkOpen] = useState(false);
  const [showAll, setShowAll] = useState(!failingOnly);

  const visible = showAll ? findings : findings.filter((finding) => finding.status === "NonCompliant");
  const failingCount = findings.filter((finding) => finding.status === "NonCompliant").length;
  const editable = visible.filter((finding) => finding.status === "NonCompliant" || finding.treatmentState !== undefined);
  const selectedIds = [...checked].filter((checkId) => findings.some((finding) => finding.checkId === checkId));

  function toggleChecked(checkId: string) {
    setChecked((current) => {
      const next = new Set(current);
      if (next.has(checkId)) next.delete(checkId);
      else next.add(checkId);
      return next;
    });
  }

  return (
    <div className="flex flex-col gap-3">
      {canEdit && editable.length > 1 ? (
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="ghost" size="sm" icon={ClipboardList} onClick={() => setShowAll((value) => !value)}>
            {showAll ? `Showing all ${findings.length} checks` : `Showing ${failingCount} failing checks`}
          </Button>
          {selectedIds.length > 0 ? (
            <Button variant="secondary" size="sm" icon={ShieldCheck} onClick={() => setBulkOpen(true)}>
              Treat selected ({selectedIds.length})
            </Button>
          ) : null}
        </div>
      ) : failingOnly && failingCount < findings.length ? (
        <div>
          <Button variant="ghost" size="sm" icon={ClipboardList} onClick={() => setShowAll((value) => !value)}>
            {showAll ? `Showing all ${findings.length} checks` : `Showing ${failingCount} failing checks`}
          </Button>
        </div>
      ) : null}
      <Table
        dense
        label="Network review findings"
        rowKey={(row) => row.checkId}
        rows={visible}
        defaultSort={{ key: "severityRank", direction: "desc" }}
        columns={[
          ...(canEdit && editable.length > 1
            ? [
                {
                  key: "selected",
                  header: <span className="sr-only">Select</span>,
                  render: (row: NetworkFinding) => (
                    <input
                      type="checkbox"
                      aria-label={`Select ${row.checkId} for bulk treatment`}
                      checked={checked.has(row.checkId)}
                      onChange={() => toggleChecked(row.checkId)}
                      onClick={(event) => event.stopPropagation()}
                      className="h-3.5 w-3.5"
                    />
                  ),
                  sortValue: (row: NetworkFinding) => (checked.has(row.checkId) ? 1 : 0),
                } as TableColumn<NetworkFinding>,
              ]
            : []),
          {
            key: "checkId",
            header: "Check",
            render: (row) => (
              <div className="flex min-w-0 flex-col">
                <span className="font-mono text-2xs text-ink-subtle">{row.checkId}</span>
                <span className="truncate text-sm text-ink">{sanitizeText(row.title)}</span>
              </div>
            ),
            sortValue: (row) => row.checkId,
          },
          {
            key: "severityRank",
            header: "Severity",
            render: (row) => <SeverityBadge severity={row.severity} />,
            sortValue: (row) => {
              const order = ["Informational", "Low", "Medium", "High", "Critical"];
              return order.indexOf(row.severity);
            },
          },
          { key: "status", header: "Status", render: (row) => <StatusBadge status={row.status} /> },
          { key: "category", header: "Category" },
          {
            key: "treatmentState",
            header: "Treatment",
            render: (row) => <TreatmentBadge state={asState(row.treatmentState ?? "open")} />,
          },
          {
            key: "references",
            header: "Standards",
            render: (row) => (
              <span className="line-clamp-1 text-2xs text-ink-subtle">{row.references.slice(0, 2).map(sanitizeText).join(", ")}</span>
            ),
            sortValue: (row) => row.references.join(", "),
          },
        ]}
        onRowClick={setSelected}
        empty="No findings match the current filter."
      />
      {selected ? (
        <NetworkFindingModal
          finding={selected}
          reportId={reportId}
          canEdit={canEdit}
          onChanged={onChanged}
          onClose={() => setSelected(null)}
        />
      ) : null}
      {bulkOpen && selectedIds.length > 0 ? (
        <NetworkBulkTreatmentModal
          reportId={reportId}
          checkIds={selectedIds}
          onClose={() => setBulkOpen(false)}
          onDone={() => {
            setChecked(new Set());
            onChanged?.();
          }}
        />
      ) : null}
    </div>
  );
}
