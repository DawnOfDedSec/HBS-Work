import { useEffect, useState } from "react";
import {
  AlertTriangle,
  Copy,
  Globe,
  Lock,
  RefreshCw,
  Save,
  ServerCog,
  ShieldCheck,
} from "lucide-react";
import { api, ApiError } from "../../api";
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  Input,
  SectionHeader,
  Select,
  useToast,
} from "../../components/ui";
import { sanitizeText } from "../../components/EvidenceDrawer";
import { AdminGate, useAdminRole, type AdminRole } from "./Users";

type HostingSettings = {
  host: string;
  port: number;
  tlsCert?: string;
  tlsKey?: string;
  updatedAt?: string;
  updatedBy?: string;
};

type EffectiveSettings = HostingSettings & { tls: boolean; exposed: boolean };

type Storage = {
  path: string | null;
  encrypted: boolean;
  status: "missing" | "ok" | "tampered" | "error";
  error?: string;
  envFile?: string | null;
};

type SettingsResponse = {
  hosting: HostingSettings;
  effective: EffectiveSettings;
  restartRequired: boolean;
  storage: Storage;
};

const LOOPBACK = new Set(["127.0.0.1", "::1", "localhost"]);
type BindMode = "local" | "all" | "custom";

function bindModeOf(host: string): BindMode {
  if (LOOPBACK.has(host)) return "local";
  if (host === "0.0.0.0" || host === "::") return "all";
  return "custom";
}

function errorMessage(error: unknown): string {
  return error instanceof ApiError ? error.message : "Request failed. Please retry.";
}

export function Settings({ role: providedRole }: { role?: AdminRole | null } = {}) {
  const { role, loading: roleLoading, error: roleError } = useAdminRole(providedRole);
  const [state, setState] = useState<SettingsResponse | null>(null);
  const [bindMode, setBindMode] = useState<BindMode>("local");
  const [host, setHost] = useState("127.0.0.1");
  const [port, setPort] = useState("3000");
  const [tlsOn, setTlsOn] = useState(false);
  const [tlsCert, setTlsCert] = useState("");
  const [tlsKey, setTlsKey] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const toast = useToast();

  function applyState(next: SettingsResponse) {
    setState(next);
    setBindMode(bindModeOf(next.hosting.host));
    setHost(next.hosting.host);
    setPort(String(next.hosting.port));
    setTlsOn(Boolean(next.hosting.tlsCert));
    setTlsCert(next.hosting.tlsCert ?? "");
    setTlsKey(next.hosting.tlsKey ?? "");
  }

  async function load() {
    setError(null);
    try {
      const response = await api.raw<SettingsResponse>("GET", "/api/admin/settings");
      applyState(response);
    } catch (err) {
      const message = errorMessage(err);
      setError(message);
      toast.error("Could not load settings", { description: message });
    }
  }

  useEffect(() => {
    if (role !== "super_admin") return;
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [role]);

  function effectiveHost(): string {
    if (bindMode === "local") return "127.0.0.1";
    if (bindMode === "all") return "0.0.0.0";
    return host.trim();
  }

  async function save() {
    setBusy(true);
    setError(null);
    try {
      const response = await api.raw<SettingsResponse & { message?: string }>(
        "PUT",
        "/api/admin/settings",
        {
          host: effectiveHost(),
          port: Number(port),
          tlsCert: tlsOn ? tlsCert.trim() : undefined,
          tlsKey: tlsOn ? tlsKey.trim() : undefined,
        },
      );
      applyState(response);
      if (response.restartRequired) {
        toast.success("Saved - restart required", {
          description: "The new host, port or TLS applies after HBS restarts.",
        });
      } else {
        toast.success("Settings saved");
      }
    } catch (err) {
      const message = errorMessage(err);
      setError(message);
      toast.error("Could not save settings", { description: message });
    } finally {
      setBusy(false);
    }
  }

  async function copyRestartCommand() {
    try {
      await navigator.clipboard.writeText("hbs restart");
      toast.success("Copied", { description: "Run it on the dashboard host." });
    } catch {
      toast.error("Copy failed", { description: "Run `hbs restart` on the dashboard host." });
    }
  }

  const restartRequired = state?.restartRequired === true;
  const exposed = state?.effective.exposed === true;

  return (
    <AdminGate role={role} loading={roleLoading} error={roleError} allow={["super_admin"]}>
      <section aria-label="Hosting settings" className="flex flex-col gap-5">
        <SectionHeader
          eyebrow="Govern"
          title="Hosting & security"
          description="Where the console listens, and whether it speaks HTTPS. Stored sealed, applied on restart."
          icon={ServerCog}
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

        {restartRequired ? (
          <div
            role="status"
            className="flex flex-wrap items-center gap-3 rounded-control border border-degraded/40 bg-degraded-soft/50 p-3 text-sm text-degraded"
          >
            <RefreshCw size={16} aria-hidden className="shrink-0" />
            <span className="min-w-0 flex-1">
              Restart required. The console is still bound to{" "}
              <span className="font-mono">
                {sanitizeText(state?.effective.host ?? "")}:{state?.effective.port}
              </span>
              {state?.effective.tls ? " over HTTPS" : ""}. Restart HBS to apply the saved settings.
            </span>
            <Button size="sm" variant="secondary" icon={Copy} onClick={copyRestartCommand}>
              Copy command
            </Button>
          </div>
        ) : null}

        <Card>
          <CardHeader
            icon={Globe}
            title="Network hosting"
            description="Loopback keeps the console on this machine. Binding every interface makes it reachable from your LAN."
            actions={
              <Badge tone={exposed ? "degraded" : "neutral"}>
                {exposed ? "Reachable on the network" : "Local only"}
              </Badge>
            }
          />
          <CardBody className="flex flex-col gap-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <Select
                label="Bind address"
                value={bindMode}
                onChange={(value) => setBindMode(value as BindMode)}
                options={[
                  { value: "local", label: "Local only (127.0.0.1)" },
                  { value: "all", label: "All interfaces (0.0.0.0)" },
                  { value: "custom", label: "One address…" },
                ]}
                hint={
                  bindMode === "all"
                    ? "Reachable from any host that can route to this machine."
                    : bindMode === "local"
                      ? "Only this machine can connect."
                      : "Bind a single interface, e.g. a VPN or management address."
                }
              />
              {bindMode === "custom" ? (
                <Input
                  label="Address"
                  value={host}
                  onChange={(event) => setHost(event.target.value)}
                  placeholder="10.20.0.5"
                  hint="An IP or hostname that exists on this machine."
                />
              ) : (
                <Input
                  label="Port"
                  type="number"
                  min={1}
                  max={65535}
                  value={port}
                  onChange={(event) => setPort(event.target.value)}
                  hint="Default 3000. The desktop app and tray follow this value."
                />
              )}
              {bindMode === "custom" ? (
                <Input
                  label="Port"
                  type="number"
                  min={1}
                  max={65535}
                  value={port}
                  onChange={(event) => setPort(event.target.value)}
                />
              ) : null}
            </div>

            <label className="flex items-center gap-3 text-sm">
              <input
                type="checkbox"
                checked={tlsOn}
                onChange={(event) => setTlsOn(event.target.checked)}
                className="h-4 w-4 rounded border-control-edge bg-surface-raised accent-accent"
              />
              <span className="inline-flex items-center gap-1.5">
                <Lock size={14} aria-hidden />
                Serve HTTPS (TLS)
              </span>
              <span className="text-2xs text-ink-subtle">Recommended for anything beyond a trusted LAN.</span>
            </label>

            {tlsOn ? (
              <div className="grid gap-4 sm:grid-cols-2">
                <Input
                  label="Certificate path"
                  value={tlsCert}
                  onChange={(event) => setTlsCert(event.target.value)}
                  placeholder="/etc/hbs/tls/hbs.crt"
                  hint="PEM-encoded X.509 certificate, readable by the service account."
                />
                <Input
                  label="Private key path"
                  value={tlsKey}
                  onChange={(event) => setTlsKey(event.target.value)}
                  placeholder="/etc/hbs/tls/hbs.key"
                  hint="PEM private key that matches the certificate. Never stored in the database."
                />
              </div>
            ) : null}
          </CardBody>
        </Card>

        <Card>
          <CardHeader
            icon={ShieldCheck}
            title="Sealed configuration"
            description="Hosting settings live in an encrypted, authenticated file. An edited or transplanted file never loads."
            actions={
              <Badge tone={state?.storage.status === "ok" ? "success" : "neutral"}>
                {state?.storage.status === "ok" ? "Sealed" : "Awaiting first save"}
              </Badge>
            }
          />
          <CardBody className="flex flex-col gap-3 text-sm">
            <dl className="grid gap-2 sm:grid-cols-[10rem_1fr]">
              <dt className="text-ink-subtle">Config file</dt>
              <dd className="break-all font-mono text-xs text-ink-muted">
                {sanitizeText(state?.storage.path ?? "not configured")}
              </dd>
              <dt className="text-ink-subtle">Protection</dt>
              <dd className="text-ink-muted">AES-256-GCM, key held outside the file (0600)</dd>
              <dt className="text-ink-subtle">Last change</dt>
              <dd className="text-ink-muted">
                {state?.hosting.updatedAt
                  ? `${sanitizeText(state.hosting.updatedAt)} by ${sanitizeText(state.hosting.updatedBy ?? "unknown")}`
                  : "set by the installer"}
              </dd>
            </dl>
            {state?.storage.error ? (
              <p role="alert" className="text-xs text-critical">
                {sanitizeText(state.storage.error)} - the server is running from the environment instead.
              </p>
            ) : null}
            <p className="text-xs text-ink-subtle">
              The key is stored beside the config with owner-only permissions. That is at-rest encryption and
              tamper detection, not protection from someone who already owns the service account.
            </p>
          </CardBody>
        </Card>

        <div className="flex flex-wrap items-center gap-3">
          <Button variant="primary" icon={Save} loading={busy} onClick={save}>
            Save settings
          </Button>
          <Button variant="ghost" icon={RefreshCw} onClick={load} disabled={busy}>
            Reload
          </Button>
          <span className="text-2xs text-ink-subtle">
            Changes are sealed first, then applied on the next restart.
          </span>
        </div>
      </section>
    </AdminGate>
  );
}
