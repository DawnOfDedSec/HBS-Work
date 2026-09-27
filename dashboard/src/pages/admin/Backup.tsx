import { useEffect, useState } from "react";
import { AlertTriangle, DatabaseBackup, Download, Upload } from "lucide-react";
import { ApiError } from "../../api";
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  Input,
  SectionHeader,
  useToast,
} from "../../components/ui";
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
 * super-admin only and validate a passphrase of at least 12 characters.
 */
export function Backup({ role: providedRole }: { role?: AdminRole | null } = {}) {
  const { role, loading: roleLoading, error: roleError } = useAdminRole(providedRole);
  const [passphrase, setPassphrase] = useState("");
  const [restorePassphrase, setRestorePassphrase] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [busy, setBusy] = useState(false);
  const toast = useToast();

  useEffect(() => {
    if (role === "super_admin") {
      setError(null);
    }
  }, [role]);

  async function downloadBackup() {
    if (passphrase.length < 12) {
      setError("Use a backup passphrase of at least 12 characters.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const { blob } = await requestJsonOrBlob("POST", "/api/admin/backup", { json: { passphrase } });
      triggerDownload(blob, `hbs-backup-${new Date().toISOString().replace(/[:.]/g, "-")}.hbsbak`);
      toast.success("Encrypted backup downloaded");
      setUnavailable(false);
    } catch (err) {
      if (isUnavailable(err)) setUnavailable(true);
      else {
        const message = errorMessage(err);
        setError(message);
        toast.error("Backup failed", { description: message });
      }
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
    if (restorePassphrase.length < 12) {
      setError("The restore passphrase must be at least 12 characters.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const form = new FormData();
      form.append("file", file, file.name);
      form.append("passphrase", restorePassphrase);
      const { json } = await requestJsonOrBlob("POST", "/api/admin/backup/restore", { form });
      const message =
        json && typeof json === "object" && "message" in json
          ? String((json as { message?: unknown }).message)
          : "Backup validated and staged.";
      toast.success("Restore staged", { description: message });
      setUnavailable(false);
    } catch (err) {
      if (isUnavailable(err)) setUnavailable(true);
      else {
        const message = errorMessage(err);
        setError(message);
        toast.error("Restore failed", { description: message });
      }
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
      toast.success("Diagnostic bundle downloaded");
    } catch (err) {
      const message = errorMessage(err);
      setError(message);
      toast.error("Diagnostic download failed", { description: message });
    }
  }

  return (
    <AdminGate role={role} loading={roleLoading} error={roleError} allow={["super_admin"]}>
      <section aria-label="Backup and restore" className="flex flex-col gap-5">
        <SectionHeader
          eyebrow="Govern"
          title="Backup & restore"
          description="Snapshot the SQLite database and key material under a passphrase-derived key, or stage a validated restore."
          icon={DatabaseBackup}
        />

        {error ? (
          <div
            role="alert"
            className="flex items-start gap-2 rounded-control border border-critical/40 bg-critical-soft/60 p-3 text-sm text-critical"
          >
            <AlertTriangle size={16} aria-hidden className="mt-0.5 shrink-0" />
            <span>{error}</span>
          </div>
        ) : null}
        {unavailable ? (
          <div role="status" className="rounded-control border border-high/40 bg-high-soft/60 p-3 text-sm text-high">
            This build does not expose the encrypted backup endpoints. The redacted diagnostic bundle is available instead.
          </div>
        ) : null}

        <div className="grid gap-4 lg:grid-cols-2">
          <Card>
            <CardHeader
              icon={Download}
              title="Encrypted backup"
              description="Snapshots the database and per-issuance key material. The passphrase is never stored or logged."
              actions={<Badge tone="accent">≥12 chars</Badge>}
            />
            <CardBody className="flex flex-col gap-3">
              <Input
                label="Backup passphrase"
                type="password"
                autoComplete="new-password"
                value={passphrase}
                onChange={(event) => setPassphrase(event.target.value)}
                hint="Minimum 12 characters."
              />
              <div className="flex flex-wrap gap-2">
                <Button variant="primary" icon={Download} loading={busy} onClick={() => void downloadBackup()}>
                  Download encrypted backup
                </Button>
                <Button variant="secondary" onClick={() => void downloadDiagnostic()}>
                  Download redacted diagnostic bundle
                </Button>
              </div>
            </CardBody>
          </Card>

          <Card>
            <CardHeader
              icon={Upload}
              title="Restore"
              description="The archive is verified and decrypted into a staging file; the live database is never overwritten."
            />
            <CardBody className="flex flex-col gap-3">
              <label className="flex flex-col gap-1 text-2xs font-medium text-ink-muted">
                Backup archive
                <input
                  type="file"
                  accept=".hbsbak,.json,application/octet-stream"
                  onChange={(event) => setFile(event.target.files?.[0] ?? null)}
                  className="mt-0.5 block w-full rounded-control border border-control-edge bg-surface-raised px-3 py-2 text-sm text-ink file:mr-2 file:rounded file:border-0 file:bg-surface-overlay file:px-2 file:py-1 file:text-ink-muted"
                />
              </label>
              <Input
                label="Restore passphrase"
                type="password"
                autoComplete="off"
                value={restorePassphrase}
                onChange={(event) => setRestorePassphrase(event.target.value)}
                hint="Minimum 12 characters."
              />
              <div>
                <Button variant="danger" icon={Upload} disabled={busy || !file} loading={busy} onClick={() => void restoreBackup()}>
                  Restore backup
                </Button>
              </div>
            </CardBody>
          </Card>
        </div>

        {unavailable ? <EmptyState title="Backup API unavailable" detail="Ask an operator to deploy the admin backup routes." /> : null}
      </section>
    </AdminGate>
  );
}
