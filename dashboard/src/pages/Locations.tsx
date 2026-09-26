import { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  Download,
  MapPin,
  Network,
  Plus,
  RefreshCw,
  Server,
  Tag,
  Upload,
} from "lucide-react";
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
  Skeleton,
  Stat,
  useToast,
} from "../components/ui";
import { sanitizeText } from "../components/EvidenceDrawer";
import { NetworkUploadModal } from "../components/NetworkUploadModal";
import { scoreTone } from "../components/NetworkFindings";
import type { NetworkDeviceSummary } from "../network-types";

export type LocationRow = {
  id: number;
  campaignId: number;
  name: string;
  tags: string[];
  retiredAt: string | null;
  createdAt?: string;
  updatedAt?: string;
};

export type CampaignRow = {
  id: number;
  name: string;
  status: string;
  tags: string[];
  /**
   * Campaign detail embeds its locations (`GET /api/campaigns/:id`). This is
   * the reliable listing source; a dedicated `.../locations` GET is not
   * registered by the server.
   */
  locations?: LocationRow[];
};

export type HostSummary = {
  id: number;
  hostname: string | null;
  displayId: string;
  lastSeenAt: string;
  latestReceivedAt: string | null;
  reportCount: number;
  severity: Record<string, number>;
  links: { host: string };
};

export type LocationStats = {
  hostCount: number;
  critical: number;
  nonCompliant: number;
  freshness: string | null;
  hosts: HostSummary[];
};

export type LocationsProps = {
  campaignId: number;
  /** Session role; upload requires auditor/super_admin. */
  role?: string;
  onOpenHost?: (hostId: number) => void;
  onOpenDownloads?: (locationId: number) => void;
  onOpenNetworkDevice?: (deviceId: number) => void;
};

function parseTagsInput(value: string): string[] {
  return [
    ...new Set(
      value
        .split(",")
        .map((tag) => tag.trim())
        .filter((tag) => tag.length > 0),
    ),
  ];
}

function formatFreshness(value: string | null): { label: string; tone: "compliant" | "degraded" | "critical" } {
  if (!value) return { label: "never seen", tone: "degraded" };
  const at = Date.parse(value);
  if (!Number.isFinite(at)) return { label: value, tone: "degraded" };
  const hours = (Date.now() - at) / 3_600_000;
  if (hours < 1) return { label: "fresh (<1h)", tone: "compliant" };
  if (hours < 24) return { label: `fresh (${Math.floor(hours)}h)`, tone: "compliant" };
  const days = Math.floor(hours / 24);
  if (days < 30) return { label: `stale (${days}d)`, tone: "degraded" };
  return { label: `stale (${days}d)`, tone: "critical" };
}

function statsFromHosts(hosts: HostSummary[]): LocationStats {
  let freshness: string | null = null;
  let critical = 0;
  let nonCompliant = 0;
  for (const host of hosts) {
    const seen = host.latestReceivedAt ?? host.lastSeenAt;
    if (seen && (!freshness || Date.parse(seen) > Date.parse(freshness))) freshness = seen;
    critical += host.severity.Critical ?? 0;
    nonCompliant += host.severity.NonCompliant ?? 0;
  }
  return { hostCount: hosts.length, critical, nonCompliant, freshness, hosts };
}

/** Campaign locations with tags, retirement state, host counts, and freshness. */
export function Locations({ campaignId, role, onOpenHost, onOpenDownloads, onOpenNetworkDevice }: LocationsProps) {
  const [campaign, setCampaign] = useState<CampaignRow | null>(null);
  const [locations, setLocations] = useState<LocationRow[] | null>(null);
  const [stats, setStats] = useState<Record<number, LocationStats>>({});
  const [networkDevices, setNetworkDevices] = useState<Record<number, NetworkDeviceSummary[]>>({});
  const [uploadLocation, setUploadLocation] = useState<LocationRow | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [name, setName] = useState("");
  const [tags, setTags] = useState("");
  const [creating, setCreating] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const toast = useToast();

  const canUpload = role === "super_admin" || role === "auditor";

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const campaignRow = await api.raw<CampaignRow>("GET", `/api/campaigns/${campaignId}`);
      const locationRows = campaignRow.locations ?? [];
      setCampaign(campaignRow);
      setLocations(locationRows);

      const entries = await Promise.all(
        locationRows.map(async (location) => {
          const fallback: LocationStats = { hostCount: 0, critical: 0, nonCompliant: 0, freshness: null, hosts: [] };
          try {
            const [hosts, devices] = await Promise.all([
              api.raw<{ hosts: HostSummary[] }>("GET", `/api/hosts?locationId=${location.id}`),
              api.listNetworkDevices({ locationId: location.id }).catch(() => ({ devices: [] as NetworkDeviceSummary[] })),
            ]);
            return { id: location.id, stats: statsFromHosts(hosts.hosts ?? []), devices: devices.devices ?? [] };
          } catch {
            return { id: location.id, stats: fallback, devices: [] as NetworkDeviceSummary[] };
          }
        }),
      );
      setStats(Object.fromEntries(entries.map((entry) => [entry.id, entry.stats])));
      setNetworkDevices(Object.fromEntries(entries.map((entry) => [entry.id, entry.devices])));
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "failed to load locations";
      setError(message);
      toast.error("Could not load locations", { description: message });
    } finally {
      setLoading(false);
    }
  }, [campaignId, toast]);

  useEffect(() => {
    void load();
  }, [load]);

  async function createLocation(event: React.FormEvent) {
    event.preventDefault();
    if (!name.trim()) return;
    setCreating(true);
    setFormError(null);
    try {
      await api.createLocation(campaignId, { name: name.trim(), tags: parseTagsInput(tags) });
      setName("");
      setTags("");
      toast.success("Location added", { description: name.trim() });
      await load();
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "could not create location";
      setFormError(message);
      toast.error("Could not add location", { description: message });
    } finally {
      setCreating(false);
    }
  }

  async function retire(location: LocationRow) {
    try {
      await api.retireLocation(campaignId, location.id);
      toast.info("Location retired", { description: sanitizeText(location.name) });
      await load();
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "could not retire location";
      setError(message);
      toast.error("Could not retire location", { description: message });
    }
  }

  const totalHosts = Object.values(stats).reduce((sum, entry) => sum + entry.hostCount, 0);
  const totalCritical = Object.values(stats).reduce((sum, entry) => sum + entry.critical, 0);
  const totalNonCompliant = Object.values(stats).reduce((sum, entry) => sum + entry.nonCompliant, 0);
  const totalNetworkDevices = Object.values(networkDevices).reduce((sum, devices) => sum + devices.length, 0);

  return (
    <section aria-label="Locations" className="flex flex-col gap-5">
      <SectionHeader
        eyebrow="Operate"
        title={campaign ? sanitizeText(campaign.name) : `Campaign #${campaignId}`}
        description="Sites and hosts receiving extractors for this campaign."
        icon={MapPin}
        actions={
          <Button variant="secondary" icon={RefreshCw} loading={loading} onClick={() => void load()}>
            Refresh
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        <Stat label="Locations" value={locations?.length ?? 0} icon={MapPin} hint={`Campaign #${campaignId}`} />
        <Stat label="Hosts" value={totalHosts} icon={Server} hint="Distinct machines seen" />
        <Stat label="Network devices" value={totalNetworkDevices} icon={Network} hint="Reviewed configs" />
        <Stat label="Critical" value={totalCritical} icon={AlertTriangle} tone={totalCritical > 0 ? "critical" : "ok"} />
        <Stat
          label="Non-compliant"
          value={totalNonCompliant}
          tone={totalNonCompliant > 0 ? "high" : "ok"}
        />
      </div>

      <Card>
        <CardHeader
          icon={Plus}
          title="Add location"
          description="A location groups hosts and receives immutable extractor issuances."
          actions={formError ? <Badge tone="critical">{formError}</Badge> : null}
        />
        <CardBody>
          <form onSubmit={createLocation} className="flex flex-wrap items-end gap-3">
            <Input
              label="Location name"
              value={name}
              onChange={(event) => setName(event.target.value)}
              required
              containerClassName="w-56"
              placeholder="Datacenter A"
            />
            <Input
              label="Tags (comma separated)"
              value={tags}
              onChange={(event) => setTags(event.target.value)}
              containerClassName="w-56"
              placeholder="prod, pci"
            />
            <Button type="submit" variant="primary" icon={Plus} loading={creating}>
              Add location
            </Button>
          </form>
        </CardBody>
      </Card>

      {error ? (
        <div
          role="alert"
          className="flex items-start gap-2 rounded-control border border-critical/40 bg-critical-soft/60 p-3 text-sm text-critical"
        >
          <AlertTriangle size={16} aria-hidden className="mt-0.5 shrink-0" />
          <span>{error}</span>
        </div>
      ) : null}

      {loading && locations === null ? (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 3 }).map((_, index) => (
            <Card key={index}>
              <Skeleton width="55%" />
              <Skeleton className="mt-3" width="100%" />
            </Card>
          ))}
        </div>
      ) : locations && locations.length === 0 ? (
        <EmptyState
          icon={MapPin}
          title="No locations yet"
          detail="Add a location to generate immutable extractor issuances and receive reports."
        />
      ) : (
        <ul className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {(locations ?? []).map((location) => {
            const locationStats = stats[location.id];
            const freshness = formatFreshness(locationStats?.freshness ?? null);
            return (
              <li key={location.id} className="hbs-panel flex flex-col gap-3 p-4">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div className="flex min-w-0 items-center gap-2">
                    <MapPin size={15} aria-hidden className="text-accent" />
                    <span className="truncate text-sm font-semibold text-ink">{sanitizeText(location.name)}</span>
                  </div>
                  {location.retiredAt ? <Badge tone="high">Retired</Badge> : <Badge tone="compliant">Active</Badge>}
                </div>

                {location.tags.length > 0 ? (
                  <ul className="flex flex-wrap items-center gap-1">
                    <Tag size={12} aria-hidden className="text-ink-subtle" />
                    {location.tags.map((tag) => (
                      <li key={tag}>
                        <Badge tone="neutral">{sanitizeText(tag)}</Badge>
                      </li>
                    ))}
                  </ul>
                ) : null}

                <dl className="grid grid-cols-2 gap-2 text-xs">
                  <div>
                    <dt className="text-ink-subtle">Hosts</dt>
                    <dd className="tabular-nums text-ink">{locationStats?.hostCount ?? 0}</dd>
                  </div>
                  <div>
                    <dt className="text-ink-subtle">Critical</dt>
                    <dd className="tabular-nums text-critical">{locationStats?.critical ?? 0}</dd>
                  </div>
                  <div>
                    <dt className="text-ink-subtle">Non-compliant</dt>
                    <dd className="tabular-nums text-high">{locationStats?.nonCompliant ?? 0}</dd>
                  </div>
                  <div>
                    <dt className="text-ink-subtle">Freshness</dt>
                    <dd>
                      <Badge tone={freshness.tone}>{freshness.label}</Badge>
                    </dd>
                  </div>
                </dl>

                {(locationStats?.hosts.length ?? 0) > 0 ? (
                  <ul className="flex flex-wrap gap-1">
                    {locationStats?.hosts.slice(0, 5).map((host) => (
                      <li key={host.id}>
                        <button
                          type="button"
                          onClick={() => onOpenHost?.(host.id)}
                          className="rounded-full border border-hairline bg-surface-raised px-2 py-0.5 text-2xs text-ink-muted hover:border-hairline-strong hover:text-ink"
                        >
                          {sanitizeText(host.displayId)}
                        </button>
                      </li>
                    ))}
                    {(locationStats?.hosts.length ?? 0) > 5 ? (
                      <li className="px-2 py-0.5 text-2xs text-ink-subtle">
                        +{(locationStats?.hosts.length ?? 0) - 5} more
                      </li>
                    ) : null}
                  </ul>
                ) : null}

                {(networkDevices[location.id]?.length ?? 0) > 0 ? (
                  <div className="flex flex-col gap-1">
                    <span className="flex items-center gap-1 text-2xs font-semibold uppercase tracking-wide text-ink-subtle">
                      <Network size={11} aria-hidden /> Network devices
                    </span>
                    <ul className="flex flex-wrap gap-1">
                      {networkDevices[location.id]?.slice(0, 5).map((device) => (
                        <li key={device.id}>
                          <button
                            type="button"
                            onClick={() => onOpenNetworkDevice?.(device.id)}
                            title={`Review score ${device.score === null ? "—" : device.score.toFixed(0)}`}
                            className="inline-flex items-center gap-1.5 rounded-full border border-hairline bg-surface-raised px-2 py-0.5 text-2xs text-ink-muted hover:border-hairline-strong hover:text-ink"
                          >
                            <span className="max-w-28 truncate">{sanitizeText(device.hostname) || `#${device.id}`}</span>
                            {device.score !== null ? (
                              <Badge tone={scoreTone(device.score)} className="!px-1 !py-0 !text-2xs">
                                {device.score.toFixed(0)}
                              </Badge>
                            ) : null}
                            {device.severity.critical + device.severity.high > 0 ? (
                              <span aria-hidden className="inline-block h-1.5 w-1.5 rounded-full bg-critical" />
                            ) : null}
                          </button>
                        </li>
                      ))}
                      {(networkDevices[location.id]?.length ?? 0) > 5 ? (
                        <li className="px-2 py-0.5 text-2xs text-ink-subtle">
                          +{(networkDevices[location.id]?.length ?? 0) - 5} more
                        </li>
                      ) : null}
                    </ul>
                  </div>
                ) : null}

                <div className="mt-auto flex flex-wrap items-center gap-2 pt-1">
                  <Button size="sm" variant="secondary" icon={Download} onClick={() => onOpenDownloads?.(location.id)}>
                    Downloads
                  </Button>
                  {canUpload && !location.retiredAt ? (
                    <Button size="sm" variant="secondary" icon={Upload} onClick={() => setUploadLocation(location)}>
                      Review configs
                    </Button>
                  ) : null}
                  {!location.retiredAt ? (
                    <Button size="sm" variant="ghost" onClick={() => void retire(location)}>
                      Retire
                    </Button>
                  ) : null}
                </div>
              </li>
            );
          })}
        </ul>
      )}

      {uploadLocation ? (
        <NetworkUploadModal
          open
          campaignId={campaignId}
          locationId={uploadLocation.id}
          locationName={uploadLocation.name}
          onClose={() => setUploadLocation(null)}
          onUploaded={() => void load()}
        />
      ) : null}
    </section>
  );
}
