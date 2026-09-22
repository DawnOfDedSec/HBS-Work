import { useCallback, useEffect, useState } from "react";
import { Copy, Download, RefreshCw } from "lucide-react";
import { api, ApiError } from "../api";
import { EmptyState } from "../components/EmptyState";

/** Platform allowlist mirrors `server/issuances.ts` PLATFORMS exactly. */
export const PLATFORMS = ["linux-amd64", "linux-arm64", "windows-amd64"] as const;
export type Platform = (typeof PLATFORMS)[number];

/** Full issuance shape returned by the issuance endpoints. */
export type IssuanceDetail = {
  id: string;
  extractorId: string;
  campaignId: number;
  locationId: number;
  platform: string;
  keyId: number;
  artifactSha256: string;
  artifactSize: number;
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

export type DownloadsProps = {
  campaignId: number;
  locationId: number;
  onBack?: () => void;
};

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB"];
  const exponent = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  const value = bytes / 1024 ** exponent;
  return `${value.toFixed(exponent === 0 ? 0 : 1)} ${units[exponent]}`;
}

function artifactName(platform: string): string {
  return platform.startsWith("windows") ? "extractor.exe" : "extractor";
}

function artifactUrl(issuance: IssuanceDetail): string {
  if (typeof window === "undefined") return issuance.downloadUrl;
  try {
    return new URL(issuance.downloadUrl, window.location.origin).toString();
  } catch {
    return issuance.downloadUrl;
  }
}

function curlSnippet(issuance: IssuanceDetail): string {
  return `curl -fL -o ${artifactName(issuance.platform)} "${artifactUrl(issuance)}"`;
}

function powershellSnippet(issuance: IssuanceDetail): string {
  return `Invoke-WebRequest -Uri "${artifactUrl(issuance)}" -OutFile ${artifactName(issuance.platform)}`;
}

function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      aria-label={label}
      onClick={() => {
        void navigator.clipboard?.writeText(value).then(
          () => {
            setCopied(true);
            window.setTimeout(() => setCopied(false), 1500);
          },
          () => setCopied(false),
        );
      }}
      className="inline-flex items-center gap-1 rounded border border-slate-700 px-1.5 py-0.5 text-xs hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
    >
      <Copy size={12} aria-hidden />
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

/** Immutable issuance generator + download snippets for one campaign location. */
export function Downloads({ campaignId, locationId, onBack }: DownloadsProps) {
  const [issuances, setIssuances] = useState<IssuanceDetail[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [platform, setPlatform] = useState<Platform>("linux-amd64");
  const [expiry, setExpiry] = useState("");
  const [creating, setCreating] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const rows = await api.raw<IssuanceDetail[]>(
        "GET",
        `/api/campaigns/${campaignId}/locations/${locationId}/issuances`,
      );
      setIssuances(rows);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "failed to load issuances");
    } finally {
      setLoading(false);
    }
  }, [campaignId, locationId]);

  useEffect(() => {
    void load();
  }, [load]);

  async function create(event: React.FormEvent) {
    event.preventDefault();
    setCreating(true);
    setFormError(null);
    try {
      await api.raw<IssuanceDetail>(
        "POST",
        `/api/campaigns/${campaignId}/locations/${locationId}/issuances`,
        { platform, expiry: expiry ? expiry : undefined },
      );
      setExpiry("");
      await load();
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : "could not create issuance");
    } finally {
      setCreating(false);
    }
  }

  return (
    <section aria-label="Downloads" className="space-y-4">
      <div className="flex items-center gap-3">
        {onBack ? (
          <button
            type="button"
            onClick={onBack}
            className="rounded border border-slate-700 px-2 py-1 text-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
          >
            ← Locations
          </button>
        ) : null}
        <h2 className="text-lg font-semibold">Extractor downloads</h2>
      </div>

      <form onSubmit={create} className="flex flex-wrap items-end gap-3 rounded-lg border border-slate-800 p-3">
        <label className="flex flex-col gap-1 text-sm">
          Platform
          <select
            value={platform}
            onChange={(event) => setPlatform(event.target.value as Platform)}
            className="rounded border border-slate-700 bg-slate-900 px-2 py-1"
          >
            {PLATFORMS.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1 text-sm">
          Expiry (optional)
          <input
            type="datetime-local"
            value={expiry}
            onChange={(event) => setExpiry(event.target.value)}
            className="rounded border border-slate-700 bg-slate-900 px-2 py-1"
          />
        </label>
        <button
          type="submit"
          disabled={creating}
          className="rounded bg-sky-600 px-3 py-1.5 text-sm font-medium disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
        >
          {creating ? "Generating…" : "Generate issuance"}
        </button>
        <button
          type="button"
          onClick={() => void load()}
          className="inline-flex items-center gap-1 rounded border border-slate-700 px-2 py-1.5 text-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
        >
          <RefreshCw size={14} aria-hidden /> Refresh
        </button>
        {formError ? (
          <p role="alert" className="text-sm text-red-400">
            {formError}
          </p>
        ) : null}
      </form>

      {error ? <EmptyState title="Could not load issuances" detail={error} /> : null}
      {loading && issuances === null && !error ? <p role="status">Loading issuances…</p> : null}
      {issuances && issuances.length === 0 ? (
        <EmptyState
          title="No issuances yet"
          detail="Generate an extractor to produce a patched artifact with a unique identity."
        />
      ) : null}

      <ul className="space-y-3">
        {(issuances ?? []).map((issuance) => (
          <li key={issuance.id} className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="font-medium">{issuance.platform}</div>
              <div className="flex items-center gap-2 text-xs">
                {issuance.revoked ? (
                  <span className="rounded border border-red-600 px-1.5 py-0.5 text-red-300">Revoked</span>
                ) : null}
                {issuance.expired ? (
                  <span className="rounded border border-amber-500 px-1.5 py-0.5 text-amber-300">Expired</span>
                ) : null}
                {!issuance.revoked && !issuance.expired ? (
                  <span className="rounded border border-emerald-600 px-1.5 py-0.5 text-emerald-300">Active</span>
                ) : null}
              </div>
            </div>

            <dl className="mt-3 grid gap-2 text-xs sm:grid-cols-2">
              <div>
                <dt className="text-slate-400">Key ID</dt>
                <dd className="tabular-nums">{issuance.keyId}</dd>
              </div>
              <div>
                <dt className="text-slate-400">Size</dt>
                <dd className="tabular-nums">{formatBytes(issuance.artifactSize)}</dd>
              </div>
              <div className="sm:col-span-2">
                <dt className="text-slate-400">Artifact SHA-256</dt>
                <dd className="break-all font-mono text-[11px]">{issuance.artifactSha256}</dd>
              </div>
              <div>
                <dt className="text-slate-400">Extractor ID</dt>
                <dd className="break-all font-mono text-[11px]">{issuance.extractorId}</dd>
              </div>
              <div>
                <dt className="text-slate-400">Expires</dt>
                <dd>{issuance.expiresAt ?? "—"}</dd>
              </div>
            </dl>

            {issuance.versionStalenessWarning ? (
              <p role="alert" className="mt-2 text-xs text-amber-300">
                {issuance.versionStalenessWarning}
              </p>
            ) : null}

            <div className="mt-3 space-y-2">
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs uppercase tracking-wide text-slate-400">Download URL</span>
                <CopyButton value={artifactUrl(issuance)} label="Copy download URL" />
              </div>
              <code className="block break-all rounded bg-slate-950 p-2 font-mono text-[11px]">
                {artifactUrl(issuance)}
              </code>

              <div className="flex items-center justify-between gap-2">
                <span className="text-xs uppercase tracking-wide text-slate-400">curl</span>
                <CopyButton value={curlSnippet(issuance)} label="Copy curl command" />
              </div>
              <code className="block break-all rounded bg-slate-950 p-2 font-mono text-[11px]">
                {curlSnippet(issuance)}
              </code>

              <div className="flex items-center justify-between gap-2">
                <span className="text-xs uppercase tracking-wide text-slate-400">PowerShell</span>
                <CopyButton value={powershellSnippet(issuance)} label="Copy PowerShell command" />
              </div>
              <code className="block break-all rounded bg-slate-950 p-2 font-mono text-[11px]">
                {powershellSnippet(issuance)}
              </code>

              <a
                href={issuance.downloadUrl}
                className="inline-flex items-center gap-1 text-xs text-sky-300 underline focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
              >
                <Download size={12} aria-hidden /> Download ({issuance.downloadCount})
              </a>
            </div>
          </li>
        ))}
      </ul>
    </section>
  );
}
