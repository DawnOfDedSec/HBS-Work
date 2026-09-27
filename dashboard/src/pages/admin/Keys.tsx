import { useEffect, useState } from "react";
import { AlertTriangle, Download, KeyRound, RefreshCw, ShieldOff } from "lucide-react";
import { api, ApiError } from "../../api";
import {
  Badge,
  Button,
  Card,
  CardHeader,
  EmptyState,
  Modal,
  SectionHeader,
  Select,
  Skeleton,
  Table,
  type TableColumn,
  useToast,
} from "../../components/ui";
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

function statusOf(issuance: Issuance): "active" | "expired" | "revoked" {
  if (issuance.revoked) return "revoked";
  if (issuance.expired) return "expired";
  return "active";
}

const STATUS_TONE: Record<"active" | "expired" | "revoked", "compliant" | "high" | "critical"> = {
  active: "compliant",
  expired: "high",
  revoked: "critical",
};

function formatBytes(bytes: number | null): string {
  if (bytes === null || !Number.isFinite(bytes) || bytes <= 0) return "-";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KiB", "MiB", "GiB"];
  let size = bytes / 1024;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(1)} ${units[unit]}`;
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
  const [revoking, setRevoking] = useState<Issuance | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const toast = useToast();

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

  const loadIssuances = async (campaign: number, location: number) => {
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
  };

  useEffect(() => {
    if (campaignId === null || locationId === null) {
      setIssuances([]);
      return;
    }
    void loadIssuances(campaignId, locationId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [campaignId, locationId, reloadKey]);

  async function revoke(issuance: Issuance, reason: string) {
    try {
      await api.revokeIssuance(issuance.campaignId, issuance.extractorId, reason);
      toast.success("Issuance revoked", { description: sanitizeText(issuance.extractorId) });
      setRevoking(null);
      setReloadKey((key) => key + 1);
    } catch (err) {
      const message = errorMessage(err);
      setError(message);
      toast.error("Could not revoke issuance", { description: message });
      throw err;
    }
  }

  const columns: Array<TableColumn<Issuance>> = [
    {
      key: "extractorId",
      header: "Extractor",
      render: (issuance) => (
        <div className="flex flex-col gap-1">
          <span className="break-all font-mono text-2xs text-ink">{sanitizeText(issuance.extractorId)}</span>
          {issuance.versionStalenessWarning ? (
            <span className="text-2xs text-high">{sanitizeText(issuance.versionStalenessWarning)}</span>
          ) : null}
        </div>
      ),
    },
    { key: "platform", header: "Platform", render: (issuance) => <Badge tone="info">{sanitizeText(issuance.platform)}</Badge> },
    { key: "keyId", header: "Key ID", align: "right", sortable: true },
    {
      key: "status",
      header: "Status",
      render: (issuance) => {
        const status = statusOf(issuance);
        return (
          <div className="flex flex-col gap-1">
            <Badge tone={STATUS_TONE[status]}>{status}</Badge>
            {issuance.revokedReason ? (
              <span className="text-2xs text-ink-subtle">{sanitizeText(issuance.revokedReason)}</span>
            ) : null}
          </div>
        );
      },
    },
    { key: "downloadCount", header: "Downloads", align: "right", sortable: true },
    {
      key: "artifactSha256",
      header: "SHA-256",
      render: (issuance) => (
        <span className="break-all font-mono text-2xs text-ink-subtle">{sanitizeText(issuance.artifactSha256).slice(0, 16)}…</span>
      ),
    },
    {
      key: "expiresAt",
      header: "Expires",
      sortable: true,
      render: (issuance) => <span className="text-xs text-ink-muted">{sanitizeText(issuance.expiresAt) || "-"}</span>,
    },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      align: "right",
      render: (issuance) => (
        <div className="flex items-center justify-end gap-1.5">
          <a
            href={api.downloadUrl(issuance.id)}
            className="inline-flex items-center gap-1 rounded-control border border-control-edge bg-surface-raised px-2 py-1 text-xs text-ink hover:border-control-edge-strong"
          >
            <Download size={12} aria-hidden /> Artifact
          </a>
          <Button size="sm" variant="secondary" disabled={issuance.revoked} onClick={() => setRevoking(issuance)}>
            Revoke
          </Button>
        </div>
      ),
    },
  ];

  return (
    <AdminGate role={role} loading={roleLoading} error={roleError} allow={["super_admin", "auditor"]}>
      <section aria-label="Issuance key inventory" className="flex flex-col gap-5">
        <SectionHeader
          eyebrow="Govern"
          title="Issuance keys"
          description="Every issued extractor and its artifact hash. Revocation stops future ingest and download."
          icon={KeyRound}
          actions={
            <Button
              variant="secondary"
              icon={RefreshCw}
              loading={loading}
              onClick={() => setReloadKey((key) => key + 1)}
            >
              Refresh
            </Button>
          }
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

        <Card>
          <CardHeader
            icon={KeyRound}
            title="Scope"
            description="Issuances are listed per campaign location."
          />
          <div className="flex flex-wrap items-end gap-3 pt-3">
            <Select
              label="Campaign"
              value={campaignId === null ? "" : String(campaignId)}
              onChange={(value) => {
                const parsed = Number(value);
                setCampaignId(Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null);
                setLocationId(null);
              }}
              options={campaigns.map((campaign) => ({ value: String(campaign.id), label: campaign.name }))}
              placeholder="Select a campaign…"
              className="w-56"
            />
            <Select
              label="Location"
              value={locationId === null ? "" : String(locationId)}
              disabled={campaignId === null}
              onChange={(value) => {
                const parsed = Number(value);
                setLocationId(Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null);
              }}
              options={locations.map((location) => ({
                value: String(location.id),
                label: `${location.name}${location.retiredAt ? " (retired)" : ""}`,
              }))}
              placeholder="Select a location…"
              className="w-56"
            />
          </div>
        </Card>

        <Card flush className="overflow-hidden">
          <div className="p-4">
            <CardHeader
              icon={KeyRound}
              title="Issuance inventory"
              description="Download the immutable artifact or revoke with a reason."
              actions={<Badge tone="accent">{issuances.length} issuances</Badge>}
            />
          </div>
          {locationId === null ? (
            <div className="p-4">
              <EmptyState title="Choose a campaign and location" detail="Issuances are listed per location." />
            </div>
          ) : loading && issuances.length === 0 ? (
            <div className="flex flex-col gap-2 p-4">
              {Array.from({ length: 3 }).map((_, index) => (
                <Skeleton key={index} height={30} />
              ))}
            </div>
          ) : issuances.length === 0 ? (
            <div className="p-4">
              <EmptyState title="No issuances for this location" />
            </div>
          ) : (
            <Table label="Issuance inventory" columns={columns} rows={issuances} rowKey={(row) => row.id} stickyHeader />
          )}
        </Card>

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
  }, [issuance]);

  if (!issuance) return null;

  return (
    <Modal
      open
      onClose={onCancel}
      title="Revoke issuance"
      description={`Future ingest and download for ${sanitizeText(issuance.extractorId)} stop immediately. Existing reports stay queryable.`}
      size="sm"
      footer={
        <>
          <Button variant="secondary" onClick={onCancel}>
            Cancel
          </Button>
          <Button
            variant="danger"
            icon={ShieldOff}
            loading={submitting}
            form="revoke-issuance-form"
            type="submit"
          >
            Revoke
          </Button>
        </>
      }
    >
      <form
        id="revoke-issuance-form"
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
        className="flex flex-col gap-3"
      >
        <label className="block">
          <span className="text-2xs font-medium text-ink-muted">Reason (required)</span>
          <textarea
            required
            rows={3}
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            className="mt-1 w-full rounded-control border border-control-edge bg-surface-raised px-3 py-2 text-sm text-ink placeholder:text-ink-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus"
          />
        </label>
        {error ? (
          <p role="alert" className="rounded-control border border-critical/40 bg-critical-soft/60 p-2 text-xs text-critical">
            {error}
          </p>
        ) : null}
      </form>
    </Modal>
  );
}
