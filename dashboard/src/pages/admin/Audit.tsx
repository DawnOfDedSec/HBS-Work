import { useCallback, useEffect, useState } from "react";
import { Search } from "lucide-react";
import { api, ApiError } from "../../api";
import { EmptyState } from "../../components/EmptyState";
import { sanitizeText } from "../../components/EvidenceDrawer";
import { AdminGate, useAdminRole, type AdminRole } from "./Users";

/** Shape of `GET /api/admin/audit` once the server exposes it. */
type AuditEntry = {
  id: number;
  actor: string;
  actorIp: string | null;
  action: string;
  resource: string;
  details: string | null;
  createdAt: string;
};

type AuditResponse = { entries: AuditEntry[]; total: number; page: number; pageSize: number };

type DiagnosticEvent = {
  receivedAt: string;
  via: string | null;
  envelopeBytes: number | null;
  durationMs: number | null;
  accepted: boolean;
  reasonCode: string | null;
  reportId: number | null;
  issuanceId: string | null;
};

type DiagnosticBundle = {
  generatedAt: string;
  ingestEvents: DiagnosticEvent[];
};

function errorMessage(error: unknown): string {
  return error instanceof ApiError ? error.message : "Request failed. Please retry.";
}

/**
 * Append-only log explorer. The canonical security audit log is served by
 * `GET /api/admin/audit`; when this build does not expose it (404), the page
 * falls back to the redacted ingest/self-audit events in `GET /api/diagnostic`
 * so operators still have a read-only, append-only record.
 */
export function Audit({ role: providedRole }: { role?: AdminRole | null } = {}) {
  const { role, loading: roleLoading, error: roleError } = useAdminRole(providedRole);
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [applied, setApplied] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [diagnostic, setDiagnostic] = useState<DiagnosticBundle | null>(null);
  const [diagnosticLoading, setDiagnosticLoading] = useState(false);
  const pageSize = 50;

  const loadAudit = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams({ page: String(page), pageSize: String(pageSize) });
      if (applied) params.set("q", applied);
      const response = await api.raw<AuditResponse>("GET", `/api/admin/audit?${params.toString()}`);
      setEntries(Array.isArray(response.entries) ? response.entries : []);
      setTotal(typeof response.total === "number" ? response.total : 0);
      setUnavailable(false);
    } catch (err) {
      if (err instanceof ApiError && (err.status === 404 || err.status === 405)) {
        setUnavailable(true);
        setEntries([]);
        setTotal(0);
      } else {
        setError(errorMessage(err));
      }
    } finally {
      setLoading(false);
    }
  }, [page, applied]);

  useEffect(() => {
    if (role === "super_admin") void loadAudit();
  }, [role, loadAudit]);

  async function loadDiagnostic() {
    setDiagnosticLoading(true);
    setError(null);
    try {
      const response = await api.raw<{ diagnostic: DiagnosticBundle }>("GET", "/api/diagnostic");
      setDiagnostic(response.diagnostic ?? null);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setDiagnosticLoading(false);
    }
  }

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <AdminGate role={role} loading={roleLoading} error={roleError} allow={["super_admin"]}>
      <section aria-label="Audit log" className="space-y-5">
        <h2 className="text-lg font-semibold">Audit log</h2>

        <form
          role="search"
          className="flex flex-wrap items-end gap-3 rounded-lg border border-slate-800 p-3"
          onSubmit={(event) => {
            event.preventDefault();
            setPage(1);
            setApplied(search.trim());
          }}
        >
          <label className="flex flex-col text-xs text-slate-400">
            Search actor, action, or resource
            <div className="mt-1 flex items-center gap-1 rounded border border-slate-700 bg-slate-900 px-2">
              <Search size={14} aria-hidden className="text-slate-500" />
              <input
                type="search"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                className="w-64 bg-transparent py-1 text-sm focus:outline-none"
              />
            </div>
          </label>
          <button
            type="submit"
            className="rounded border border-slate-700 px-3 py-1.5 text-sm hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
          >
            Search
          </button>
          <button
            type="button"
            onClick={() => void loadAudit()}
            className="rounded border border-slate-700 px-3 py-1.5 text-sm hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
          >
            Refresh
          </button>
        </form>

        {error ? (
          <p role="alert" className="rounded border border-red-500/50 bg-red-500/10 p-3 text-sm text-red-200">
            {error}
          </p>
        ) : null}

        {unavailable ? (
          <div className="space-y-3 rounded-lg border border-amber-500/40 bg-amber-500/5 p-3 text-sm text-amber-100">
            <p role="status">
              This build does not expose <code className="font-mono">/api/admin/audit</code>. The redacted diagnostic
              bundle is the closest append-only record available.
            </p>
            <button
              type="button"
              disabled={diagnosticLoading}
              onClick={() => void loadDiagnostic()}
              className="rounded border border-amber-500/60 px-3 py-1.5 text-amber-100 hover:bg-amber-500/10 disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-amber-300"
            >
              {diagnosticLoading ? "Loading…" : "Load redacted diagnostic log"}
            </button>
          </div>
        ) : null}

        {diagnostic ? (
          <section aria-labelledby="diagnostic-log" className="space-y-2">
            <h3 id="diagnostic-log" className="text-sm font-semibold">
              Redacted ingest log · generated {sanitizeText(diagnostic.generatedAt)}
            </h3>
            {diagnostic.ingestEvents.length === 0 ? (
              <EmptyState title="No ingest events recorded" />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-sm">
                  <caption className="sr-only">Redacted diagnostic ingest events</caption>
                  <thead>
                    <tr className="text-left text-slate-400">
                      <th scope="col" className="border-b border-slate-800 py-2 pr-3">Received</th>
                      <th scope="col" className="border-b border-slate-800 py-2 pr-3">Via</th>
                      <th scope="col" className="border-b border-slate-800 py-2 pr-3">Accepted</th>
                      <th scope="col" className="border-b border-slate-800 py-2 pr-3">Bytes</th>
                      <th scope="col" className="border-b border-slate-800 py-2 pr-3">Duration</th>
                      <th scope="col" className="border-b border-slate-800 py-2 pr-3">Report</th>
                      <th scope="col" className="border-b border-slate-800 py-2">Reason</th>
                    </tr>
                  </thead>
                  <tbody>
                    {diagnostic.ingestEvents.map((event, index) => (
                      <tr key={`${event.reportId ?? "x"}:${index}`} className="align-top">
                        <td className="border-b border-slate-900 py-2 pr-3">{sanitizeText(event.receivedAt)}</td>
                        <td className="border-b border-slate-900 py-2 pr-3">{sanitizeText(event.via) || "—"}</td>
                        <td className="border-b border-slate-900 py-2 pr-3">
                          <span className={event.accepted ? "text-emerald-300" : "text-red-300"}>
                            {event.accepted ? "accepted" : "rejected"}
                          </span>
                        </td>
                        <td className="border-b border-slate-900 py-2 pr-3 tabular-nums">{event.envelopeBytes ?? "—"}</td>
                        <td className="border-b border-slate-900 py-2 pr-3 tabular-nums">{event.durationMs ?? "—"}</td>
                        <td className="border-b border-slate-900 py-2 pr-3 tabular-nums">{event.reportId ?? "—"}</td>
                        <td className="border-b border-slate-900 py-2">{sanitizeText(event.reasonCode) || "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        ) : null}

        {!unavailable ? (
          loading && entries.length === 0 ? (
            <p role="status">Loading audit log…</p>
          ) : entries.length === 0 ? (
            <EmptyState title="No audit entries match" />
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-sm">
                  <caption className="sr-only">Audit log entries</caption>
                  <thead>
                    <tr className="text-left text-slate-400">
                      <th scope="col" className="border-b border-slate-800 py-2 pr-3">When</th>
                      <th scope="col" className="border-b border-slate-800 py-2 pr-3">Actor</th>
                      <th scope="col" className="border-b border-slate-800 py-2 pr-3">Action</th>
                      <th scope="col" className="border-b border-slate-800 py-2 pr-3">Resource</th>
                      <th scope="col" className="border-b border-slate-800 py-2">Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {entries.map((entry) => (
                      <tr key={entry.id} className="align-top">
                        <td className="border-b border-slate-900 py-2 pr-3">{sanitizeText(entry.createdAt)}</td>
                        <td className="border-b border-slate-900 py-2 pr-3">{sanitizeText(entry.actor)}</td>
                        <td className="border-b border-slate-900 py-2 pr-3 font-mono text-xs">{sanitizeText(entry.action)}</td>
                        <td className="border-b border-slate-900 py-2 pr-3">{sanitizeText(entry.resource)}</td>
                        <td className="border-b border-slate-900 py-2 font-mono text-xs text-slate-400">
                          {sanitizeText(entry.details) || "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {totalPages > 1 ? (
                <nav aria-label="Audit pagination" className="flex items-center justify-between text-sm">
                  <button
                    type="button"
                    disabled={page <= 1}
                    onClick={() => setPage((value) => Math.max(1, value - 1))}
                    className="rounded border border-slate-700 px-2 py-1 disabled:opacity-40 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
                  >
                    Previous
                  </button>
                  <span className="text-slate-400">
                    Page {page} of {totalPages}
                  </span>
                  <button
                    type="button"
                    disabled={page >= totalPages}
                    onClick={() => setPage((value) => Math.min(totalPages, value + 1))}
                    className="rounded border border-slate-700 px-2 py-1 disabled:opacity-40 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
                  >
                    Next
                  </button>
                </nav>
              ) : null}
            </>
          )
        ) : null}
      </section>
    </AdminGate>
  );
}
