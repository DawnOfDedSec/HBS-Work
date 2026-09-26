// Webhook notification settings: fire a POST when ingested findings meet the
// configured severity threshold (host reports and network configs alike).

import { useCallback, useEffect, useState } from "react";
import { BellRing, Play, Save } from "lucide-react";
import { api, ApiError } from "../../api";
import { Button, Card, CardBody, CardHeader, Input, Select, useToast } from "../../components/ui";
import { sanitizeText } from "../../components/EvidenceDrawer";

type NotificationSettings = {
  enabled: boolean;
  url: string;
  minSeverity: "Critical" | "High";
  lastFiredAt: string | null;
};

function errorMessage(error: unknown): string {
  return error instanceof ApiError ? error.message : "Request failed. Please retry.";
}

export function Notifications({ role }: { role: string }) {
  const [settings, setSettings] = useState<NotificationSettings | null>(null);
  const [url, setUrl] = useState("");
  const [minSeverity, setMinSeverity] = useState<"Critical" | "High">("Critical");
  const [enabled, setEnabled] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const toast = useToast();

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const response = await api.raw<NotificationSettings>("GET", "/api/admin/notifications/settings");
      setSettings(response);
      setUrl(response.url);
      setMinSeverity(response.minSeverity);
      setEnabled(response.enabled);
    } catch (err) {
      toast.error("Could not load notification settings", { description: errorMessage(err) });
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    void load();
  }, [load]);

  async function save() {
    setSaving(true);
    try {
      const response = await api.raw<NotificationSettings>("PUT", "/api/admin/notifications/settings", {
        enabled,
        url: url.trim(),
        minSeverity,
      });
      setSettings(response);
      toast.success("Notification settings saved", { description: enabled ? `Fires at ${minSeverity}+` : "Disabled" });
    } catch (err) {
      toast.error("Could not save settings", { description: errorMessage(err) });
    } finally {
      setSaving(false);
    }
  }

  return (
    <Card>
      <CardHeader
        icon={BellRing}
        title="Critical finding notifications"
        description="POSTs a JSON summary to your webhook when an ingested report contains findings at or above the threshold. Host reports and network configs both trigger."
      />
      <CardBody className="flex flex-col gap-4">
        {loading && settings === null ? (
          <p className="text-sm text-ink-subtle">Loading…</p>
        ) : (
          <>
            <div className="grid gap-4 sm:grid-cols-2">
              <Input
                label="Webhook URL"
                value={url}
                onChange={(event) => setUrl(event.target.value)}
                placeholder="https://example.com/hooks/hbs"
                containerClassName="sm:col-span-2"
              />
              <Select
                label="Minimum severity"
                value={minSeverity}
                onChange={(value) => setMinSeverity(value as "Critical" | "High")}
                options={[
                  { value: "Critical", label: "Critical only" },
                  { value: "High", label: "High and above" },
                ]}
              />
              <Select
                label="Delivery"
                value={enabled ? "enabled" : "disabled"}
                onChange={(value) => setEnabled(value === "enabled")}
                options={[
                  { value: "enabled", label: "Enabled" },
                  { value: "disabled", label: "Disabled" },
                ]}
              />
            </div>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="text-2xs text-ink-subtle">
                {settings?.lastFiredAt ? `Last fired ${sanitizeText(settings.lastFiredAt)}` : "Never fired"}
              </span>
              <div className="flex items-center gap-2">
                <Button variant="ghost" icon={Play} onClick={() => void load()} disabled={loading}>
                  Reload
                </Button>
                <Button
                  variant="primary"
                  icon={Save}
                  loading={saving}
                  disabled={loading || role !== "super_admin"}
                  onClick={() => void save()}
                >
                  Save settings
                </Button>
              </div>
            </div>
          </>
        )}
      </CardBody>
    </Card>
  );
}
