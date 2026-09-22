import { useEffect, useState } from "react";
import { ApiError } from "../../api";
import { EmptyState } from "../../components/EmptyState";
import { AdminGate, useAdminRole, type AdminRole } from "./Users";

async function requestJsonOrBlob(
  method: string,
  path: string,
  init: { json?: unknown; form?: FormData },
): Promise<{ blob: Blob; json: unknown | null }> {
  const options: RequestInit = { method, credentials: "include" };
  if (init.json !== undefined) {
    options.headers = { "content-type": "application/json" };
    options.body = JSON.stringify(init.json);
  }
  if (init.form) options.body = init.form;
  const response = await fetch(path, options);
  if (!response.ok) {
    let message = response.statusText;
    let code = `HTTP_${response.status}`;
    try {
      const parsed = (await response.json()) as { error?: string; code?: string };
      message = parsed.error ?? message;
      code = parsed.code ?? code;
    } catch {
      // non-JSON error body; keep the status text
    }
    throw new ApiError(response.status, code, message);
  }
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    const text = await response.text();
    let json: unknown = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = null;
    }
    return { blob: new Blob([text], { type: contentType }), json };
  }
  return { blob: await response.blob(), json: null };
}

function triggerDownload(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function errorMessage(error: unknown): string {
  return error instanceof ApiError ? error.message : "Request failed. Please retry.";
}

function isUnavailable(error: unknown): boolean {
  return error instanceof ApiError && (error.status === 404 || error.status === 405);
}

/**
 * Encrypted backup export and passphrase-authenticated restore. The server
 * endpoints (`POST /api/admin/backup`, `POST /api/admin/backup/restore`) are
 * super-admin only; when this build does not expose them the page says so and
 * offers the redacted diagnostic bundle instead.
 */
export function Backup({ role: providedRole }: { role?: AdminRole | null } = {}) {
  const { role, loading: roleLoading, error: roleError } = useAdminRole(providedRole);
  const [passphrase, setPassphrase] = useState("");
  const [restorePassphrase, setRestorePassphrase] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (role === "super_admin") {
      setError(null);
      setNotice(null);
    }
  }, [role]);

  async function downloadBackup() {
    if (passphrase.length < 8) {
      setError("Use a backup passphrase of at least 8 characters.");
      return;
    }
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const { blob } = await requestJsonOrBlob("POST", "/api/admin/backup", { json: { passphrase } });
      triggerDownload(blob, `hbs-backup-${new Date().toISOString().replace(/[:.]/g, "-")}.json`);
      setNotice("Encrypted backup downloaded.");
      setUnavailable(false);
    } catch (err) {
      if (isUnavailable(err)) setUnavailable(true);
      else setError(errorMessage(err));
    } finally {
      setPassphrase("");
      setBusy(false);
    }
  }

  async function restoreBackup() {
    if (!file) {
      setError("Choose a backup archive to restore.");
      return;
    }
    if (restorePassphrase.length === 0) {
      setError("Enter the backup passphrase.");
      return;
    }
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const form = new FormData();
      form.append("archive", file, file.name);
      form.append("passphrase", restorePassphrase);
      const { json } = await requestJsonOrBlob("POST", "/api/admin/backup/restore", { form });
      const detail =
        json && typeof json === "object" && "restored" in json
          ? String((json as { restored?: unknown }).restored)
          : "done";
      setNotice(`Restore completed (${detail}).`);
      setUnavailable(false);
    } catch (err) {
      if (isUnavailable(err)) setUnavailable(true);
      else setError(errorMessage(err));
    } finally {
      setRestorePassphrase("");
      setBusy(false);
    }
  }

  async function downloadDiagnostic() {
    setError(null);
    try {
      const { blob } = await requestJsonOrBlob("GET", "/api/diagnostic", {});
      triggerDownload(blob, "hbs-diagnostic-bundle.json");
      setNotice("Redacted diagnostic bundle downloaded.");
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  return (
    <AdminGate role={role} loading={roleLoading} error={roleError} allow={["super_admin"]}>
      <section aria-label="Backup and restore" className="space-y-5">
        <h2 className="text-lg font-semibold">Backup &amp; restore</h2>

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
        {unavailable ? (
          <p role="status" className="rounded border border-amber-500/40 bg-amber-500/5 p-3 text-sm text-amber-100">
            This build does not expose the encrypted backup endpoints. The redacted diagnostic bundle is available
            instead.
          </p>
        ) : null}

        <section aria-labelledby="backup-export" className="space-y-3 rounded-lg border border-slate-800 p-3">
          <h3 id="backup-export" className="text-sm font-semibold">
            Encrypted backup
          </h3>
          <p className="text-xs text-slate-400">
            Snapshots the SQLite database and per-issuance key material under a passphrase-derived key. The
            passphrase is never stored or logged.
          </p>
          <label className="block text-xs text-slate-400">
            Backup passphrase
            <input
              type="password"
              autoComplete="new-password"
              value={passphrase}
              onChange={(event) => setPassphrase(event.target.value)}
              className="mt-1 w-full max-w-sm rounded border border-slate-700 bg-slate-900 px-2 py-1 text-sm"
            />
          </label>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              disabled={busy}
              onClick={() => void downloadBackup()}
              className="rounded bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-500 disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-300"
            >
              {busy ? "Working…" : "Download encrypted backup"}
            </button>
            <button
              type="button"
              onClick={() => void downloadDiagnostic()}
              className="rounded border border-slate-700 px-3 py-1.5 text-sm hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
            >
              Download redacted diagnostic bundle
            </button>
          </div>
        </section>

        <section aria-labelledby="backup-restore" className="space-y-3 rounded-lg border border-slate-800 p-3">
          <h3 id="backup-restore" className="text-sm font-semibold">
            Restore
          </h3>
          <p className="text-xs text-slate-400">
            Everything is verified and staged before any key file or database is replaced.
          </p>
          <label className="block text-xs text-slate-400">
            Backup archive
            <input
              type="file"
              accept="application/json,.json,.hbs"
              onChange={(event) => setFile(event.target.files?.[0] ?? null)}
              className="mt-1 block w-full max-w-sm rounded border border-slate-700 bg-slate-900 px-2 py-1 text-sm file:mr-2 file:rounded file:border-0 file:bg-slate-800 file:px-2 file:py-1 file:text-slate-200"
            />
          </label>
          <label className="block text-xs text-slate-400">
            Restore passphrase
            <input
              type="password"
              autoComplete="off"
              value={restorePassphrase}
              onChange={(event) => setRestorePassphrase(event.target.value)}
              className="mt-1 w-full max-w-sm rounded border border-slate-700 bg-slate-900 px-2 py-1 text-sm"
            />
          </label>
          <button
            type="button"
            disabled={busy || !file}
            onClick={() => void restoreBackup()}
            className="rounded border border-red-500/60 px-3 py-1.5 text-sm text-red-100 hover:bg-red-500/10 disabled:opacity-40 focus:outline-none focus-visible:ring-2 focus-visible:ring-red-300"
          >
            {busy ? "Working…" : "Restore backup"}
          </button>
        </section>

        {!unavailable ? null : <EmptyState title="Backup API unavailable" detail="Ask an operator to deploy the admin backup routes." />}
      </section>
    </AdminGate>
  );
}
