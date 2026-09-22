import { useEffect, useState } from "react";
import { AlertTriangle, Play, ShieldCheck, Trash2 } from "lucide-react";
import { api, ApiError } from "../../api";
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
  Stat,
  useToast,
} from "../../components/ui";
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
  const toast = useToast();

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
      const message = errorMessage(err);
      setError(message);
      setPreview(null);
      toast.error("Dry-run failed", { description: message });
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
      toast.success("Cleanup applied", { description: `${response.reportsDeleted} reports deleted` });
    } catch (err) {
      const message = errorMessage(err);
      setError(message);
      toast.error("Cleanup failed", { description: message });
    } finally {
      setBusy(false);
    }
  }

  const mayApply = preview?.enabled === true && confirmation === preview.confirmation;

  return (
    <AdminGate role={role} loading={roleLoading} error={roleError} allow={["super_admin"]}>
      <section aria-label="Retention policy" className="flex flex-col gap-5">
        <SectionHeader
          eyebrow="Govern"
          title="Retention"
          description="Preview an expiry sweep against a campaign, then confirm with the exact token. Legal-hold reports are never deleted."
          icon={Trash2}
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
            icon={Play}
            title="Choose a campaign"
            description="A dry-run never mutates data; it only reports what an apply would remove."
          />
          <CardBody>
            <div className="flex flex-wrap items-end gap-3">
              <Select
                label="Campaign"
                value={campaignId === null ? "" : String(campaignId)}
                onChange={(value) => {
                  const parsed = Number(value);
                  setCampaignId(Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null);
                  setPreview(null);
                  setResult(null);
                  setConfirmation("");
                }}
                options={campaigns.map((campaign) => ({
                  value: String(campaign.id),
                  label: `${campaign.name}${campaign.retentionDays ? ` · ${campaign.retentionDays}d` : " · no retention set"}`,
                }))}
                placeholder="Select a campaign…"
                className="w-72"
              />
              <Button variant="secondary" icon={Play} loading={busy} disabled={campaignId === null} onClick={() => void dryRun()}>
                Run dry-run
              </Button>
            </div>
          </CardBody>
        </Card>

        {preview ? (
          preview.enabled ? (
            <Card className="border-high/40">
              <CardHeader
                icon={AlertTriangle}
                title="Dry-run preview — nothing has been deleted"
                description={`Cutoff ${sanitizeText(preview.cutoff) || "—"}. Reports under legal hold are never deleted.`}
                actions={<Badge tone="degraded">Preview only</Badge>}
              />
              <CardBody className="flex flex-col gap-4">
                <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
                  <Stat label="Expired reports" value={preview.expiredReports} tone={preview.expiredReports > 0 ? "high" : "ok"} />
                  <Stat label="Legal-hold reports" value={preview.heldReports} />
                  <Stat label="Unlinked hosts" value={preview.unlinkedHosts} />
                  <Stat label="Keys retained" value={preview.retainedKeys} />
                </div>
                <div className="flex flex-wrap items-end gap-3">
                  <Input
                    label={`Type ${preview.confirmation} to confirm`}
                    value={confirmation}
                    onChange={(event) => setConfirmation(event.target.value)}
                    containerClassName="w-96"
                    placeholder={preview.confirmation}
                  />
                  <Button variant="danger" icon={Trash2} disabled={!mayApply || busy} onClick={() => void apply()}>
                    Apply cleanup
                  </Button>
                </div>
              </CardBody>
            </Card>
          ) : (
            <EmptyState
              icon={ShieldCheck}
              title="Retention is disabled for this campaign"
              detail="Set a retention policy on the campaign before running cleanup."
            />
          )
        ) : null}

        {result ? (
          <Card className="border-compliant/40">
            <CardHeader icon={ShieldCheck} title="Cleanup applied" description="The sweep committed to the database." />
            <CardBody>
              <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
                <Stat label="Reports deleted" value={result.reportsDeleted} tone="ok" />
                <Stat label="Hosts deleted" value={result.hostsDeleted} />
                <Stat label="Held reports" value={result.heldReports} />
                <Stat label="Keys retained" value={result.keysRetained} />
              </div>
            </CardBody>
          </Card>
        ) : null}
      </section>
    </AdminGate>
  );
}
