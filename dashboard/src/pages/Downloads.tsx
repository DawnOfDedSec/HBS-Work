import { useCallback, useEffect, useState } from "react";
import { Check, Copy, Download, KeyRound, RefreshCw, ShieldAlert, Terminal } from "lucide-react";
import { api, ApiError } from "../api";
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  Input,
  SectionHeader,
  Select,
  Skeleton,
  useToast,
} from "../components/ui";
import { sanitizeText } from "../components/EvidenceDrawer";

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
    <Button
      size="sm"
      variant="ghost"
      icon={copied ? Check : Copy}
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
    >
      {copied ? "Copied" : "Copy"}
    </Button>
  );
}

function Snippet({ label, value }: { label: string; value: string }) {
  return (
    <div className="overflow-hidden rounded-control border border-hairline-soft">
      <div className="flex items-center justify-between gap-2 border-b border-hairline-soft px-2 py-1">
        <span className="inline-flex items-center gap-1.5 text-2xs font-semibold uppercase tracking-wide text-ink-subtle">
          <Terminal size={12} aria-hidden /> {label}
        </span>
        <CopyButton value={value} label={`Copy ${label}`} />
      </div>
      <pre className="hbs-scroll overflow-x-auto bg-surface-sunken p-2 text-xs">
        <code className="text-ink-muted">{value}</code>
      </pre>
    </div>
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
  const toast = useToast();

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const rows = await api.raw<IssuanceDetail[]>(
        "GET",
        `/api/campaigns/${campaignId}/locations/${locationId}/issuances`,
      );
      setIssuances(Array.isArray(rows) ? rows : []);
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "failed to load issuances";
      setError(message);
      toast.error("Could not load issuances", { description: message });
    } finally {
      setLoading(false);
    }
  }, [campaignId, locationId, toast]);

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
      toast.success("Issuance generated", { description: platform });
      await load();
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "could not create issuance";
      setFormError(message);
      toast.error("Could not generate issuance", { description: message });
    } finally {
      setCreating(false);
    }
  }

  return (
    <section aria-label="Downloads" className="mx-auto flex max-w-7xl flex-col gap-5">
      <SectionHeader
        eyebrow="Operate"
        title="Extractor downloads"
        description={`Immutable patched artifacts for campaign #${campaignId} · location #${locationId}.`}
        icon={Download}
        actions={
          <>
            {onBack ? (
              <Button variant="ghost" onClick={onBack}>
                Back
              </Button>
            ) : null}
            <Button variant="secondary" icon={RefreshCw} loading={loading} onClick={() => void load()}>
              Refresh
            </Button>
          </>
        }
      />

      <Card>
        <CardHeader
          icon={KeyRound}
          title="Generate issuance"
          description="Each issuance has a unique extractor identity and independent keypair."
          actions={formError ? <Badge tone="critical">{formError}</Badge> : null}
        />
        <CardBody>
          <form onSubmit={create} className="flex flex-wrap items-end gap-3">
            <Select
              label="Platform"
              value={platform}
              onChange={(value) => setPlatform(value as Platform)}
              options={PLATFORMS.map((option) => ({ value: option, label: option }))}
              className="w-44"
            />
            <Input
              label="Expiry (optional)"
              type="datetime-local"
              value={expiry}
              onChange={(event) => setExpiry(event.target.value)}
              containerClassName="w-56"
              hint="Defaults to 90 days."
            />
            <Button type="submit" variant="primary" icon={KeyRound} loading={creating}>
              Generate issuance
            </Button>
          </form>
        </CardBody>
      </Card>

      {error ? (
        <div
          role="alert"
          className="flex items-start gap-2 rounded-control border border-critical/40 bg-critical-soft/60 p-3 text-sm text-critical"
        >
          <ShieldAlert size={16} aria-hidden className="mt-0.5 shrink-0" />
          <span>{error}</span>
        </div>
      ) : null}

      {loading && issuances === null ? (
        <div className="flex flex-col gap-4">
          {Array.from({ length: 2 }).map((_, index) => (
            <Card key={index}>
              <Skeleton width="40%" />
              <Skeleton className="mt-3" width="100%" />
            </Card>
          ))}
        </div>
      ) : issuances && issuances.length === 0 ? (
        <EmptyState
          icon={KeyRound}
          title="No issuances yet"
          detail="Generate an extractor to produce a patched artifact with a unique identity."
        />
      ) : (
        <ul className="flex flex-col gap-4">
          {(issuances ?? []).map((issuance) => (
            <li key={issuance.id} className="hbs-panel flex flex-col gap-3 p-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className="flex h-8 w-8 items-center justify-center rounded-control bg-surface-raised text-accent">
                    <Download size={15} aria-hidden />
                  </span>
                  <span className="font-semibold text-ink">{sanitizeText(issuance.platform)}</span>
                </div>
                <div className="flex items-center gap-2">
                  {issuance.revoked ? <Badge tone="critical">Revoked</Badge> : null}
                  {issuance.expired ? <Badge tone="high">Expired</Badge> : null}
                  {!issuance.revoked && !issuance.expired ? <Badge tone="compliant">Active</Badge> : null}
                  <Badge tone="accent">{issuance.downloadCount} downloads</Badge>
                </div>
              </div>

              <dl className="grid gap-2 text-xs sm:grid-cols-2 lg:grid-cols-4">
                <div>
                  <dt className="text-ink-subtle">Key ID</dt>
                  <dd className="tabular-nums text-ink">{issuance.keyId}</dd>
                </div>
                <div>
                  <dt className="text-ink-subtle">Size</dt>
                  <dd className="tabular-nums text-ink">{formatBytes(issuance.artifactSize)}</dd>
                </div>
                <div>
                  <dt className="text-ink-subtle">Expires</dt>
                  <dd className="text-ink">{sanitizeText(issuance.expiresAt) || "—"}</dd>
                </div>
                <div>
                  <dt className="text-ink-subtle">Extractor ID</dt>
                  <dd className="break-all font-mono text-2xs text-ink-muted">{sanitizeText(issuance.extractorId)}</dd>
                </div>
                <div className="sm:col-span-2 lg:col-span-4">
                  <dt className="text-ink-subtle">Artifact SHA-256</dt>
                  <dd className="break-all font-mono text-2xs text-ink-muted">{sanitizeText(issuance.artifactSha256)}</dd>
                </div>
              </dl>

              {issuance.versionStalenessWarning ? (
                <p role="alert" className="text-xs text-high">
                  {sanitizeText(issuance.versionStalenessWarning)}
                </p>
              ) : null}

              <div className="grid gap-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">Download URL</span>
                  <CopyButton value={artifactUrl(issuance)} label="Copy download URL" />
                </div>
                <code className="hbs-scroll block overflow-x-auto break-all rounded-control border border-hairline-soft bg-surface-sunken p-2 font-mono text-2xs text-ink-muted">
                  {artifactUrl(issuance)}
                </code>
                <Snippet label="curl" value={curlSnippet(issuance)} />
                <Snippet label="PowerShell" value={powershellSnippet(issuance)} />
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <a
                  href={issuance.downloadUrl}
                  className="inline-flex items-center gap-1.5 rounded-control border border-hairline bg-surface-raised px-3 py-1.5 text-xs text-ink hover:border-hairline-strong"
                >
                  <Download size={13} aria-hidden /> Download artifact ({issuance.downloadCount})
                </a>
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
