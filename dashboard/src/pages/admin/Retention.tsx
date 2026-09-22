import { useEffect, useState } from "react";
import { api, ApiError } from "../../api";
import { EmptyState } from "../../components/EmptyState";
import { sanitizeText } from "../../components/EvidenceDrawer";
import type { Campaign } from "../../types";
import { AdminGate, useAdminRole, type AdminRole } from "./Users";

/** Campaign plus the retention fields the list endpoint serializes. */
type CampaignRow = Campaign & { retentionDays?: number | null };

type RetentionPreview = {
  enabled: boolean;
  cutoff: string | null;
  expiredReports: number;
  heldReports: number;
  unlinkedHosts: number;
  retainedKeys: number;
  confirmation: string;
};

type RetentionResult = {
  reportsDeleted: number;
  hostsDeleted: number;
  heldReports: number;
  keysRetained: number;
};

function errorMessage(error: unknown): string {
  return error instanceof ApiError ? error.message : "Request failed. Please retry.";
}

export function Retention({ role: providedRole }: { role?: AdminRole | null } = {}) {
  const { role, loading: roleLoading, error: roleError } = useAdminRole(providedRole);
  const [campaigns, setCampaigns] = useState<CampaignRow[]>([]);
  const [campaignId, setCampaignId] = useState<number | null>(null);
  const [preview, setPreview] = useState<RetentionPreview | null>(null);
  const [confirmation, setConfirmation] = useState("");
  const [result, setResult] = useState<RetentionResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (role !== "super_admin") return;
    let alive = true;
    api
      .listCampaigns()
      .then((rows) => {
        if (alive) setCampaigns(Array.isArray(rows) ? rows : []);
      })
      .catch((err) => {
        if (alive) setError(errorMessage(err));
      });
    return () => {
      alive = false;
    };
  }, [role]);

  async function dryRun() {
    if (campaignId === null) return;
    setBusy(true);
    setError(null);
    setResult(null);
    setConfirmation("");
    try {
      const response = await api.raw<RetentionPreview>(
        "POST",
        `/api/campaigns/${campaignId}/retention/dry-run`,
      );
      setPreview(response);
    } catch (err) {
      setError(errorMessage(err));
      setPreview(null);
    } finally {
      setBusy(false);
    }
  }

  async function apply() {
    if (campaignId === null || preview === null) return;
    setBusy(true);
    setError(null);
    try {
      const response = await api.raw<RetentionResult>(
        "POST",
        `/api/campaigns/${campaignId}/retention/apply`,
        { confirmation },
      );
      setResult(response);
      setPreview(null);
      setConfirmation("");
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const mayApply = preview?.enabled === true && confirmation === preview.confirmation;

  return (
    <AdminGate role={role} loading={roleLoading} error={roleError} allow={["super_admin"]}>
      <section aria-label="Retention policy" className="space-y-5">
        <h2 className="text-lg font-semibold">Retention</h2>

        {error ? (
          <p role="alert" className="rounded border border-red-500/50 bg-red-500/10 p-3 text-sm text-red-200">
            {error}
          </p>
        ) : null}

        <div className="flex flex-wrap items-end gap-3 rounded-lg border border-slate-800 p-3">
          <label className="flex flex-col text-xs text-slate-400">
            Campaign
            <select
              value={campaignId ?? ""}
              onChange={(event) => {
                const value = Number(event.target.value);
                setCampaignId(Number.isSafeInteger(value) && value > 0 ? value : null);
                setPreview(null);
                setResult(null);
                setConfirmation("");
              }}
              className="mt-1 min-w-56 rounded border border-slate-700 bg-slate-900 px-2 py-1 text-sm"
            >
              <option value="">Select a campaign…</option>
              {campaigns.map((campaign) => (
                <option key={campaign.id} value={campaign.id}>
                  {campaign.name}
                  {campaign.retentionDays ? ` · ${campaign.retentionDays}d` : " · no retention set"}
                </option>
              ))}
            </select>
          </label>
          <button
            type="button"
            disabled={campaignId === null || busy}
            onClick={() => void dryRun()}
            className="rounded border border-slate-700 px-3 py-1.5 text-sm hover:bg-slate-800 disabled:opacity-40 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
          >
            {busy ? "Working…" : "Run dry-run"}
          </button>
        </div>

        {preview ? (
          preview.enabled ? (
            <section aria-labelledby="retention-preview" className="space-y-3 rounded-lg border border-amber-500/40 p-3">
              <h3 id="retention-preview" className="text-sm font-semibold text-amber-200">
                Dry-run preview — nothing has been deleted
              </h3>
              <dl className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
                <Stat label="Expired reports" value={preview.expiredReports} />
                <Stat label="Legal-hold reports" value={preview.heldReports} />
                <Stat label="Unlinked hosts" value={preview.unlinkedHosts} />
                <Stat label="Keys retained" value={preview.retainedKeys} />
              </dl>
              <p className="text-xs text-slate-400">
                Cutoff {sanitizeText(preview.cutoff) || "—"}. Reports under legal hold are never deleted.
              </p>
              <div className="space-y-2">
                <label className="block text-xs text-slate-400">
                  Type <span className="font-mono text-slate-200">{preview.confirmation}</span> to confirm
                  <input
                    value={confirmation}
                    onChange={(event) => setConfirmation(event.target.value)}
                    className="mt-1 w-full max-w-md rounded border border-slate-700 bg-slate-900 px-2 py-1 text-sm"
                  />
                </label>
                <button
                  type="button"
                  disabled={!mayApply || busy}
                  onClick={() => void apply()}
                  className="rounded bg-red-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-red-500 disabled:opacity-40 focus:outline-none focus-visible:ring-2 focus-visible:ring-red-300"
                >
                  Apply cleanup
                </button>
              </div>
            </section>
          ) : (
            <EmptyState
              title="Retention is disabled for this campaign"
              detail="Set a retention policy on the campaign before running cleanup."
            />
          )
        ) : null}

        {result ? (
          <section aria-labelledby="retention-result" className="rounded-lg border border-emerald-500/40 p-3">
            <h3 id="retention-result" className="text-sm font-semibold text-emerald-200">
              Cleanup applied
            </h3>
            <dl className="mt-2 grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
              <Stat label="Reports deleted" value={result.reportsDeleted} />
              <Stat label="Hosts deleted" value={result.hostsDeleted} />
              <Stat label="Held reports" value={result.heldReports} />
              <Stat label="Keys retained" value={result.keysRetained} />
            </dl>
          </section>
        ) : null}
      </section>
    </AdminGate>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-wide text-slate-500">{label}</dt>
      <dd className="mt-0.5 text-xl font-semibold tabular-nums">{value}</dd>
    </div>
  );
}
