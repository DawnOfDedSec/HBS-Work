import { useCallback, useEffect, useState } from "react";
import { Download, MapPin, Plus } from "lucide-react";
import { api, ApiError } from "../api";
import { EmptyState } from "../components/EmptyState";
import { ToneBadge } from "../components/charts/TableTwin";

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
  onOpenHost?: (hostId: number) => void;
  onOpenDownloads?: (locationId: number) => void;
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

function formatFreshness(value: string | null): { label: string; tone: "default" | "warning" | "critical" } {
  if (!value) return { label: "never seen", tone: "default" };
  const at = Date.parse(value);
  if (!Number.isFinite(at)) return { label: value, tone: "default" };
  const ageMs = Date.now() - at;
  const hours = ageMs / 3_600_000;
  if (hours < 1) return { label: "fresh (<1h)", tone: "default" };
  if (hours < 24) return { label: `fresh (${Math.floor(hours)}h)`, tone: "default" };
  const days = Math.floor(hours / 24);
  if (days < 7) return { label: `${days}d old`, tone: "default" };
  if (days < 30) return { label: `stale (${days}d)`, tone: "warning" };
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
export function Locations({ campaignId, onOpenHost, onOpenDownloads }: LocationsProps) {
  const [campaign, setCampaign] = useState<CampaignRow | null>(null);
  const [locations, setLocations] = useState<LocationRow[] | null>(null);
  const [stats, setStats] = useState<Record<number, LocationStats>>({});
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [name, setName] = useState("");
  const [tags, setTags] = useState("");
  const [creating, setCreating] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

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
          try {
            const response = await api.raw<{ hosts: HostSummary[] }>(
              "GET",
              `/api/hosts?locationId=${location.id}`,
            );
            return [location.id, statsFromHosts(response.hosts ?? [])] as const;
          } catch {
            return [location.id, { hostCount: 0, critical: 0, nonCompliant: 0, freshness: null, hosts: [] }] as const;
          }
        }),
      );
      setStats(Object.fromEntries(entries));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "failed to load locations");
    } finally {
      setLoading(false);
    }
  }, [campaignId]);

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
      await load();
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : "could not create location");
    } finally {
      setCreating(false);
    }
  }

  async function retire(location: LocationRow) {
    try {
      await api.retireLocation(campaignId, location.id);
      await load();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "could not retire location");
    }
  }

  if (error && !locations) return <EmptyState title="Could not load locations" detail={error} />;
  if (loading && locations === null) return <p role="status">Loading locations…</p>;

  return (
    <section aria-label="Locations" className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-lg font-semibold">{campaign ? campaign.name : `Campaign #${campaignId}`}</h2>
        <span className="text-xs text-slate-400">Campaign #{campaignId}</span>
      </div>

      <form onSubmit={createLocation} className="flex flex-wrap items-end gap-3 rounded-lg border border-slate-800 p-3">
        <label className="flex flex-col gap-1 text-sm">
          Location name
          <input
            value={name}
            onChange={(event) => setName(event.target.value)}
            required
            className="rounded border border-slate-700 bg-slate-900 px-2 py-1"
          />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          Tags (comma separated)
          <input
            value={tags}
            onChange={(event) => setTags(event.target.value)}
            className="rounded border border-slate-700 bg-slate-900 px-2 py-1"
          />
        </label>
        <button
          type="submit"
          disabled={creating}
          className="inline-flex items-center gap-1 rounded bg-sky-600 px-3 py-1.5 text-sm font-medium disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
        >
          <Plus size={14} aria-hidden /> {creating ? "Adding…" : "Add location"}
        </button>
        {formError ? (
          <p role="alert" className="text-sm text-red-400">
            {formError}
          </p>
        ) : null}
      </form>

      {error ? (
        <p role="alert" className="text-sm text-red-400">
          {error}
        </p>
      ) : null}

      {locations && locations.length === 0 ? (
        <EmptyState
          title="No locations yet"
          detail="Add a location to generate immutable extractor issuances and receive reports."
        />
      ) : null}

      <ul className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {(locations ?? []).map((location) => {
          const locationStats = stats[location.id];
          const freshness = formatFreshness(locationStats?.freshness ?? null);
          const downloadsHref = `/downloads?campaignId=${campaignId}&locationId=${location.id}`;
          return (
            <li key={location.id} className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="inline-flex items-center gap-1 font-medium">
                  <MapPin size={14} aria-hidden /> {location.name}
                </div>
                {location.retiredAt ? (
                  <ToneBadge label="Retired" tone="warning" />
                ) : (
                  <ToneBadge label="Active" tone="ok" />
                )}
              </div>

              {location.tags.length > 0 ? (
                <ul className="mt-2 flex flex-wrap gap-1">
                  {location.tags.map((tag) => (
                    <li
                      key={tag}
                      className="rounded border border-slate-700 px-1.5 py-0.5 text-xs text-slate-300"
                    >
                      {tag}
                    </li>
                  ))}
                </ul>
              ) : null}

              <dl className="mt-3 grid grid-cols-2 gap-2 text-xs">
                <div>
                  <dt className="text-slate-400">Hosts</dt>
                  <dd className="tabular-nums">{locationStats?.hostCount ?? 0}</dd>
                </div>
                <div>
                  <dt className="text-slate-400">Critical findings</dt>
                  <dd className="tabular-nums">{locationStats?.critical ?? 0}</dd>
                </div>
                <div>
                  <dt className="text-slate-400">Non-compliant</dt>
                  <dd className="tabular-nums">{locationStats?.nonCompliant ?? 0}</dd>
                </div>
                <div>
                  <dt className="text-slate-400">Freshness</dt>
                  <dd>
                    <ToneBadge label={freshness.label} tone={freshness.tone} />
                  </dd>
                </div>
              </dl>

              {(locationStats?.hosts.length ?? 0) > 0 ? (
                <ul className="mt-3 flex flex-wrap gap-1">
                  {locationStats?.hosts.slice(0, 5).map((host) => (
                    <li key={host.id}>
                      <a
                        href={host.links.host}
                        onClick={(event) => {
                          if (onOpenHost) {
                            event.preventDefault();
                            onOpenHost(host.id);
                          }
                        }}
                        className="rounded border border-slate-700 px-1.5 py-0.5 text-xs hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
                      >
                        {host.displayId}
                      </a>
                    </li>
                  ))}
                </ul>
              ) : null}

              <div className="mt-3 flex flex-wrap items-center gap-2">
                <a
                  href={downloadsHref}
                  onClick={(event) => {
                    if (onOpenDownloads) {
                      event.preventDefault();
                      onOpenDownloads(location.id);
                    }
                  }}
                  className="inline-flex items-center gap-1 rounded border border-slate-700 px-2 py-1 text-xs hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
                >
                  <Download size={12} aria-hidden /> Downloads
                </a>
                {!location.retiredAt ? (
                  <button
                    type="button"
                    onClick={() => void retire(location)}
                    className="rounded border border-slate-700 px-2 py-1 text-xs hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
                  >
                    Retire
                  </button>
                ) : null}
              </div>
            </li>
          );
        })}
      </ul>
    </section>
  );
}
