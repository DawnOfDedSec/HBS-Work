import { useEffect, useState } from "react";
import { api, ApiError } from "../../api";
import { EmptyState } from "../../components/EmptyState";
import { sanitizeText } from "../../components/EvidenceDrawer";
import type { Campaign, Location } from "../../types";
import { AdminGate, useAdminRole, type AdminRole } from "./Users";

/** `GET /api/campaigns/:id/locations/:loc/issuances` (`serializeIssuance`). */
type Issuance = {
  id: string;
  extractorId: string;
  campaignId: number;
  locationId: number;
  platform: string;
  keyId: number;
  artifactSha256: string;
  artifactSize: number | null;
  downloadCount: number;
  createdAt: string;
  expiresAt: string | null;
  expired: boolean;
  revoked: boolean;
  revokedAt: string | null;
  revokedReason: string | null;
  revokedBy: string | null;
  downloadUrl: string;
  versionStalenessWarning: string | null;
};

function errorMessage(error: unknown): string {
  return error instanceof ApiError ? error.message : "Request failed. Please retry.";
}

function statusOf(issuance: Issuance): string {
  if (issuance.revoked) return "revoked";
  if (issuance.expired) return "expired";
  return "active";
}

export function Keys({ role: providedRole }: { role?: AdminRole | null } = {}) {
  const { role, loading: roleLoading, error: roleError } = useAdminRole(providedRole);
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [campaignId, setCampaignId] = useState<number | null>(null);
  const [locations, setLocations] = useState<Location[]>([]);
  const [locationId, setLocationId] = useState<number | null>(null);
  const [issuances, setIssuances] = useState<Issuance[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<Issuance | null>(null);

  useEffect(() => {
    if (role !== "super_admin" && role !== "auditor") return;
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

  useEffect(() => {
    if (campaignId === null) {
      setLocations([]);
      setLocationId(null);
      return;
    }
    let alive = true;
    setError(null);
    api
      .raw<{ locations?: Location[] }>("GET", `/api/campaigns/${campaignId}`)
      .then((response) => {
        if (alive) setLocations(Array.isArray(response.locations) ? response.locations : []);
      })
      .catch((err) => {
        if (alive) setError(errorMessage(err));
      });
    return () => {
      alive = false;
    };
  }, [campaignId]);

  async function loadIssuances(campaign: number, location: number) {
    setLoading(true);
    setError(null);
    try {
      const rows = await api.raw<Issuance[]>(
        "GET",
        `/api/campaigns/${campaign}/locations/${location}/issuances`,
      );
      setIssuances(Array.isArray(rows) ? rows : []);
    } catch (err) {
      setError(errorMessage(err));
      setIssuances([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (campaignId === null || locationId === null) {
      setIssuances([]);
      return;
    }
    void loadIssuances(campaignId, locationId);
  }, [campaignId, locationId]);

  async function revoke(issuance: Issuance, reason: string) {
    await api.revokeIssuance(issuance.campaignId, issuance.extractorId, reason);
    setNotice(`Revoked ${issuance.extractorId}.`);
    setRevoking(null);
    if (campaignId !== null && locationId !== null) await loadIssuances(campaignId, locationId);
  }

  return (
    <AdminGate role={role} loading={roleLoading} error={roleError} allow={["super_admin", "auditor"]}>
      <section aria-label="Issuance key inventory" className="space-y-5">
        <h2 className="text-lg font-semibold">Issuance keys</h2>

        {error ? (
          <p role="alert" className="rounded border border-red-500/50 bg-red-500/10 p-3 text-sm text-red-200">
            {error}
          </p>
        ) : null}
        {notice ? (
          <p role="status" className="rounded border border-sky-500/40 bg-sky-500/10 p-3 text-sm text-sky-100">
            {notice}
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
                setLocationId(null);
              }}
              className="mt-1 min-w-48 rounded border border-slate-700 bg-slate-900 px-2 py-1 text-sm"
            >
              <option value="">Select a campaign…</option>
              {campaigns.map((campaign) => (
                <option key={campaign.id} value={campaign.id}>
                  {campaign.name}
                </option>
              ))}
            </select>
          </label>
          <label className="flex flex-col text-xs text-slate-400">
            Location
            <select
              value={locationId ?? ""}
              disabled={campaignId === null}
              onChange={(event) => {
                const value = Number(event.target.value);
                setLocationId(Number.isSafeInteger(value) && value > 0 ? value : null);
              }}
              className="mt-1 min-w-48 rounded border border-slate-700 bg-slate-900 px-2 py-1 text-sm disabled:opacity-50"
            >
              <option value="">Select a location…</option>
              {locations.map((location) => (
                <option key={location.id} value={location.id}>
                  {location.name}
                  {location.retiredAt ? " (retired)" : ""}
                </option>
              ))}
            </select>
          </label>
        </div>

        {locationId === null ? (
          <EmptyState title="Choose a campaign and location" detail="Issuances are listed per location." />
        ) : loading ? (
          <p role="status">Loading issuances…</p>
        ) : issuances.length === 0 ? (
          <EmptyState title="No issuances for this location" />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-sm">
              <caption className="sr-only">Issuance inventory</caption>
              <thead>
                <tr className="text-left text-slate-400">
                  <th scope="col" className="border-b border-slate-800 py-2 pr-3">Extractor</th>
                  <th scope="col" className="border-b border-slate-800 py-2 pr-3">Platform</th>
                  <th scope="col" className="border-b border-slate-800 py-2 pr-3">Key ID</th>
                  <th scope="col" className="border-b border-slate-800 py-2 pr-3">Status</th>
                  <th scope="col" className="border-b border-slate-800 py-2 pr-3">Downloads</th>
                  <th scope="col" className="border-b border-slate-800 py-2 pr-3">Expires</th>
                  <th scope="col" className="border-b border-slate-800 py-2">Actions</th>
                </tr>
              </thead>
              <tbody>
                {issuances.map((issuance) => {
                  const status = statusOf(issuance);
                  return (
                    <tr key={issuance.id} className="align-top">
                      <td className="border-b border-slate-900 py-2 pr-3">
                        <span className="font-mono text-xs text-slate-200">{sanitizeText(issuance.extractorId)}</span>
                        {issuance.versionStalenessWarning ? (
                          <p className="mt-0.5 text-xs text-amber-300">{sanitizeText(issuance.versionStalenessWarning)}</p>
                        ) : null}
                      </td>
                      <td className="border-b border-slate-900 py-2 pr-3">{sanitizeText(issuance.platform)}</td>
                      <td className="border-b border-slate-900 py-2 pr-3 tabular-nums">{issuance.keyId}</td>
                      <td className="border-b border-slate-900 py-2 pr-3">
                        <span
                          className={
                            status === "active"
                              ? "text-emerald-300"
                              : status === "revoked"
                                ? "text-red-300"
                                : "text-amber-300"
                          }
                        >
                          {status}
                        </span>
                        {issuance.revokedReason ? (
                          <p className="mt-0.5 text-xs text-slate-500">{sanitizeText(issuance.revokedReason)}</p>
                        ) : null}
                      </td>
                      <td className="border-b border-slate-900 py-2 pr-3 tabular-nums">{issuance.downloadCount}</td>
                      <td className="border-b border-slate-900 py-2 pr-3">{sanitizeText(issuance.expiresAt) || "—"}</td>
                      <td className="border-b border-slate-900 py-2">
                        <div className="flex flex-wrap items-center gap-2">
                          <a
                            href={api.downloadUrl(issuance.id)}
                            className="rounded border border-slate-700 px-2 py-0.5 text-xs hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
                          >
                            Download artifact
                          </a>
                          <button
                            type="button"
                            disabled={issuance.revoked}
                            onClick={() => setRevoking(issuance)}
                            className="rounded border border-slate-700 px-2 py-0.5 text-xs hover:bg-slate-800 disabled:opacity-40 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
                          >
                            Revoke
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        <RevokeModal issuance={revoking} onCancel={() => setRevoking(null)} onConfirm={revoke} />
      </section>
    </AdminGate>
  );
}

function RevokeModal({
  issuance,
  onCancel,
  onConfirm,
}: {
  issuance: Issuance | null;
  onCancel: () => void;
  onConfirm: (issuance: Issuance, reason: string) => Promise<void>;
}) {
  const [reason, setReason] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!issuance) return;
    setReason("");
    setError(null);
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onCancel();
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [issuance, onCancel]);

  if (!issuance) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/70 p-4">
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="revoke-title"
        className="w-full max-w-md rounded-lg border border-slate-700 bg-slate-900 p-4 shadow-2xl"
      >
        <h2 id="revoke-title" className="text-base font-semibold">
          Revoke issuance
        </h2>
        <p className="mt-1 text-xs text-slate-400">
          Future ingest and download for{" "}
          <span className="font-mono text-slate-200">{sanitizeText(issuance.extractorId)}</span> stop immediately.
          Existing reports stay queryable.
        </p>
        <form
          className="mt-3 space-y-3"
          onSubmit={(event) => {
            event.preventDefault();
            if (!reason.trim()) {
              setError("A reason is required to revoke an issuance.");
              return;
            }
            setSubmitting(true);
            setError(null);
            void onConfirm(issuance, reason.trim())
              .catch((err) => setError(errorMessage(err)))
              .finally(() => setSubmitting(false));
          }}
        >
          <label className="block text-xs text-slate-400">
            Reason (required)
            <textarea
              required
              rows={3}
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              className="mt-1 w-full rounded border border-slate-700 bg-slate-900 px-2 py-1 text-sm"
            />
          </label>
          {error ? (
            <p role="alert" className="rounded border border-red-500/50 bg-red-500/10 p-2 text-xs text-red-200">
              {error}
            </p>
          ) : null}
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={onCancel}
              className="rounded border border-slate-700 px-3 py-1.5 text-sm hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="rounded bg-red-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-red-500 disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-red-300"
            >
              {submitting ? "Revoking…" : "Revoke"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
