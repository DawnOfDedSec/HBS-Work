import { useEffect, useState } from "react";
import { Command } from "cmdk";
import {
  ArrowRight,
  BookOpen,
  Building2,
  Check,
  Command as CommandIcon,
  ListChecks,
  Moon,
  Search,
  Server,
  ShieldAlert,
  Sun,
  Wrench,
  XCircle,
} from "lucide-react";
import { Kbd } from "./ui";
import { api } from "../api";
import { visibleNav, type RouteKey } from "../routes";
import { serializeFilters } from "../filters";
import type { AuthUser, Campaign } from "../types";
import type { Theme } from "../useTheme";

export type CommandPaletteProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  role: AuthUser["role"];
  currentRoute: RouteKey;
  onNavigate: (route: RouteKey) => void;
  /** Publish a canonical findings query and route to Findings. */
  onDrilldown: (query: string) => void;
  /** Open a campaign by id (App-owned navigation). */
  onOpenCampaign?: (campaignId: number) => void;
  theme: Theme;
  onToggleTheme: () => void;
};

type HostEntity = {
  id: number;
  machineId: string;
  hostname: string | null;
  displayId: string;
  platform: string | null;
};

type CheckEntity = { checkId: string; title: string; severity: string };

type FindingsResponse = {
  results: Array<{ checkId: string; title: string; severity: string }>;
};

type HostsResponse = { hosts: HostEntity[] };

const ENTITY_LIMIT = 6;

type QuickAction = {
  id: string;
  label: string;
  hint: string;
  icon: typeof ShieldAlert;
  query: string;
};

const QUICK_FILTERS: QuickAction[] = [
  {
    id: "qf-critical",
    label: "Critical findings",
    hint: "severity=Critical",
    icon: ShieldAlert,
    query: serializeFilters({ severity: ["Critical"] }),
  },
  {
    id: "qf-high",
    label: "High findings",
    hint: "severity=High",
    icon: ShieldAlert,
    query: serializeFilters({ severity: ["High"] }),
  },
  {
    id: "qf-noncompliant",
    label: "Non-compliant only",
    hint: "status=NonCompliant",
    icon: XCircle,
    query: serializeFilters({ status: ["NonCompliant"] }),
  },
  {
    id: "qf-open",
    label: "Open treatment",
    hint: "treatment=open",
    icon: Wrench,
    query: serializeFilters({ treatment: ["open"] }),
  },
  {
    id: "qf-accepted",
    label: "Accepted risk",
    hint: "treatment=accepted_risk",
    icon: Wrench,
    query: serializeFilters({ treatment: ["accepted_risk"] }),
  },
];

const SCOPES: QuickAction[] = [  {
    id: "scope-latest",
    label: "Latest scans only",
    hint: "scope=latest",
    icon: ListChecks,
    query: serializeFilters({ scope: ["latest"] }),
  },
  {
    id: "scope-standards",
    label: "Browse standards coverage",
    hint: "CIS · NIST · ISO · PCI",
    icon: BookOpen,
    query: "",
  },
];

const ENTITY_GROUP_CLASS =
  "[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-2xs [&_[cmdk-group-heading]]:font-semibold [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wide [&_[cmdk-group-heading]]:text-ink-subtle";

const ENTITY_ITEM_CLASS =
  "flex cursor-pointer items-center gap-3 rounded-control px-2 py-2 text-sm text-ink-muted data-[selected=true]:bg-surface-raised data-[selected=true]:text-ink";

/**
 * Ctrl/Cmd-K command palette. Navigation, quick scope switches, live entity
 * search (campaigns, hosts, checks), and a findings search action.
 */
export function CommandPalette({
  open,
  onOpenChange,
  role,
  currentRoute,
  onNavigate,
  onDrilldown,
  onOpenCampaign,
  theme,
  onToggleTheme,
}: CommandPaletteProps) {
  const [search, setSearch] = useState("");
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [hosts, setHosts] = useState<HostEntity[]>([]);
  const [checks, setChecks] = useState<CheckEntity[]>([]);
  const items = visibleNav(role);

  // Load campaign + host entities when the palette opens.
  useEffect(() => {
    if (!open) return;
    let alive = true;
    Promise.allSettled([
      api.raw<Campaign[]>("GET", "/api/campaigns"),
      api.raw<HostsResponse>("GET", "/api/hosts?pageSize=200"),
    ]).then(([campaignResult, hostResult]) => {
      if (!alive) return;
      if (campaignResult.status === "fulfilled") {
        setCampaigns(Array.isArray(campaignResult.value) ? campaignResult.value : []);
      }
      if (hostResult.status === "fulfilled") {
        setHosts(Array.isArray(hostResult.value.hosts) ? hostResult.value.hosts : []);
      }
    });
    return () => {
      alive = false;
    };
  }, [open]);

  // Check entities follow the search term (server-side q) with a short debounce.
  useEffect(() => {
    if (!open) return;
    const term = search.trim();
    let alive = true;
    const timer = window.setTimeout(() => {
      const path = `/api/findings?pageSize=100${term ? `&q=${encodeURIComponent(term)}` : ""}`;
      api
        .raw<FindingsResponse>("GET", path)
        .then((response) => {
          if (!alive) return;
          const seen = new Map<string, CheckEntity>();
          for (const result of response.results ?? []) {
            if (!seen.has(result.checkId)) {
              seen.set(result.checkId, { checkId: result.checkId, title: result.title, severity: result.severity });
            }
          }
          setChecks([...seen.values()].slice(0, ENTITY_LIMIT));
        })
        .catch(() => {
          if (alive) setChecks([]);
        });
    }, term ? 180 : 0);
    return () => {
      alive = false;
      window.clearTimeout(timer);
    };
  }, [open, search]);

  const term = search.trim().toLowerCase();
  const matchedCampaigns = campaigns
    .filter(
      (campaign) =>
        !term ||
        campaign.name.toLowerCase().includes(term) ||
        (campaign.client ?? "").toLowerCase().includes(term),
    )
    .slice(0, ENTITY_LIMIT);
  const matchedHosts = hosts
    .filter(
      (host) =>
        !term ||
        (host.hostname ?? "").toLowerCase().includes(term) ||
        host.machineId.toLowerCase().includes(term) ||
        host.displayId.toLowerCase().includes(term),
    )
    .slice(0, ENTITY_LIMIT);
  const matchedChecks = checks.filter(
    (check) => !term || check.checkId.toLowerCase().includes(term) || check.title.toLowerCase().includes(term),
  );

  function run(action: () => void) {
    action();
    onOpenChange(false);
    setSearch("");
  }

  return (
    <Command.Dialog
      open={open}
      onOpenChange={onOpenChange}
      label="Command palette"
      loop
      overlayClassName="fixed inset-0 z-[90] bg-canvas/70 backdrop-blur-sm animate-fade-in"
      contentClassName="fixed left-1/2 top-[10vh] z-[91] w-[min(42rem,calc(100vw-2rem))] -translate-x-1/2 overflow-hidden rounded-panel border border-hairline bg-surface shadow-overlay animate-scale-in"
      className="flex flex-col"
    >
      <div className="flex items-center gap-2.5 border-b border-hairline px-3.5">
        <Search size={17} className="shrink-0 text-ink-subtle" aria-hidden />
        <Command.Input
          autoFocus
          value={search}
          onValueChange={setSearch}
          placeholder="Search pages, commands, and findings…"
          className="h-12 w-full bg-transparent text-sm text-ink outline-none placeholder:text-ink-subtle"
        />
        <Kbd>Esc</Kbd>
      </div>

      <Command.List
        label="Commands"
        className="hbs-scroll max-h-[58vh] overflow-y-auto p-2"
      >
        <Command.Empty className="px-3 py-10 text-center text-sm text-ink-muted">
          No matches for “{search}”.
        </Command.Empty>

        <Command.Group
          heading="Navigation"
          className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-2xs [&_[cmdk-group-heading]]:font-semibold [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wide [&_[cmdk-group-heading]]:text-ink-subtle"
        >
          {items.map((item) => {
            const Icon = item.icon;
            const active = item.key === currentRoute;
            return (
              <Command.Item
                key={item.key}
                value={item.label}
                keywords={[item.key, ...(item.keywords ?? [])]}
                onSelect={() => run(() => onNavigate(item.key))}
                className="group flex cursor-pointer items-center gap-3 rounded-control px-2 py-2 text-sm text-ink-muted data-[selected=true]:bg-surface-raised data-[selected=true]:text-ink"
              >
                <Icon size={16} className="shrink-0 text-ink-subtle" aria-hidden />
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-medium text-ink">{item.label}</span>
                  <span className="block truncate text-2xs text-ink-subtle">{item.description}</span>
                </span>
                {active ? <Check size={14} className="text-accent" aria-hidden /> : null}
                <ArrowRight size={13} className="text-ink-subtle opacity-0 group-data-[selected=true]:opacity-100" aria-hidden />
              </Command.Item>
            );
          })}
        </Command.Group>

        <Command.Separator className="my-1 h-px bg-hairline-soft" />

        <Command.Group
          heading="Quick filters"
          className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-2xs [&_[cmdk-group-heading]]:font-semibold [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wide [&_[cmdk-group-heading]]:text-ink-subtle"
        >
          {[...SCOPES, ...QUICK_FILTERS].map((action) => {
            const Icon = action.icon;
            return (
              <Command.Item
                key={action.id}
                value={action.label}
                keywords={[action.id, action.hint]}
                onSelect={() =>
                  run(() => {
                    if (action.id === "scope-standards") onNavigate("standards");
                    else onDrilldown(action.query);
                  })
                }
                className="flex cursor-pointer items-center gap-3 rounded-control px-2 py-2 text-sm text-ink-muted data-[selected=true]:bg-surface-raised data-[selected=true]:text-ink"
              >
                <Icon size={16} className="shrink-0 text-ink-subtle" aria-hidden />
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-medium text-ink">{action.label}</span>
                  <span className="block truncate font-mono text-2xs text-ink-subtle">{action.hint}</span>
                </span>
              </Command.Item>
            );
          })}
        </Command.Group>

        {matchedCampaigns.length > 0 ? (
          <>
            <Command.Separator className="my-1 h-px bg-hairline-soft" />
            <Command.Group heading="Campaigns" className={ENTITY_GROUP_CLASS}>
              {matchedCampaigns.map((campaign) => (
                <Command.Item
                  key={`campaign:${campaign.id}`}
                  value={`campaign:${campaign.id}`}
                  keywords={["campaign", campaign.name, campaign.client ?? ""]}
                  onSelect={() =>
                    run(() => {
                      if (onOpenCampaign) onOpenCampaign(campaign.id);
                      else onNavigate("campaigns");
                    })
                  }
                  className={ENTITY_ITEM_CLASS}
                >
                  <Building2 size={16} className="shrink-0 text-ink-subtle" aria-hidden />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate font-medium text-ink">{campaign.name}</span>
                    <span className="block truncate text-2xs text-ink-subtle">
                      {campaign.client ? `${campaign.client} · ` : ""}Open campaign
                    </span>
                  </span>
                </Command.Item>
              ))}
            </Command.Group>
          </>
        ) : null}

        {matchedHosts.length > 0 ? (
          <>
            <Command.Separator className="my-1 h-px bg-hairline-soft" />
            <Command.Group heading="Hosts" className={ENTITY_GROUP_CLASS}>
              {matchedHosts.map((host) => (
                <Command.Item
                  key={`host:${host.id}`}
                  value={`host:${host.id}`}
                  keywords={["host", host.displayId, host.machineId, host.hostname ?? ""]}
                  onSelect={() => run(() => onDrilldown(serializeFilters({ hostId: [String(host.id)] })))}
                  className={ENTITY_ITEM_CLASS}
                >
                  <Server size={16} className="shrink-0 text-ink-subtle" aria-hidden />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate font-medium text-ink">{host.displayId}</span>
                    <span className="block truncate font-mono text-2xs text-ink-subtle">{host.machineId}</span>
                  </span>
                </Command.Item>
              ))}
            </Command.Group>
          </>
        ) : null}

        {matchedChecks.length > 0 ? (
          <>
            <Command.Separator className="my-1 h-px bg-hairline-soft" />
            <Command.Group heading="Checks" className={ENTITY_GROUP_CLASS}>
              {matchedChecks.map((check) => (
                <Command.Item
                  key={`check:${check.checkId}`}
                  value={`check:${check.checkId}`}
                  keywords={["check", check.checkId, check.title, check.severity]}
                  onSelect={() => run(() => onDrilldown(serializeFilters({ checkId: [check.checkId] })))}
                  className={ENTITY_ITEM_CLASS}
                >
                  <ListChecks size={16} className="shrink-0 text-ink-subtle" aria-hidden />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate font-medium text-ink">{check.title}</span>
                    <span className="block truncate font-mono text-2xs text-ink-subtle">{check.checkId}</span>
                  </span>
                  <ShieldAlert size={13} className="shrink-0 text-ink-subtle" aria-hidden />
                </Command.Item>
              ))}
            </Command.Group>
          </>
        ) : null}

        {search.trim() ? (
          <>
            <Command.Separator className="my-1 h-px bg-hairline-soft" />
            <Command.Group
              heading="Search"
              className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-2xs [&_[cmdk-group-heading]]:font-semibold [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wide [&_[cmdk-group-heading]]:text-ink-subtle"
            >
              <Command.Item
                value={`findings-search:${search}`}
                keywords={[search, `search findings ${search}`]}
                onSelect={() => run(() => onDrilldown(serializeFilters({ q: [search.trim()] })))}
                className="flex cursor-pointer items-center gap-3 rounded-control px-2 py-2 text-sm text-ink-muted data-[selected=true]:bg-surface-raised data-[selected=true]:text-ink"
              >
                <Search size={16} className="shrink-0 text-accent" aria-hidden />
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-medium text-ink">
                    Search findings for “{search.trim()}”
                  </span>
                  <span className="block truncate font-mono text-2xs text-ink-subtle">q={search.trim()}</span>
                </span>
              </Command.Item>
            </Command.Group>
          </>
        ) : null}

        <Command.Separator className="my-1 h-px bg-hairline-soft" />

        <Command.Group
          heading="Actions"
          className="[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-2xs [&_[cmdk-group-heading]]:font-semibold [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wide [&_[cmdk-group-heading]]:text-ink-subtle"
        >
          <Command.Item
            value={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
            keywords={["theme", "appearance", "dark", "light"]}
            onSelect={() => run(onToggleTheme)}
            className="flex cursor-pointer items-center gap-3 rounded-control px-2 py-2 text-sm text-ink-muted data-[selected=true]:bg-surface-raised data-[selected=true]:text-ink"
          >
            {theme === "dark" ? (
              <Sun size={16} className="shrink-0 text-ink-subtle" aria-hidden />
            ) : (
              <Moon size={16} className="shrink-0 text-ink-subtle" aria-hidden />
            )}
            <span className="flex-1 font-medium text-ink">
              {theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
            </span>
          </Command.Item>
        </Command.Group>
      </Command.List>

      <div className="flex items-center justify-between gap-3 border-t border-hairline px-3.5 py-2 text-2xs text-ink-subtle">
        <span className="inline-flex items-center gap-1.5">
          <CommandIcon size={12} aria-hidden />
          Command palette
        </span>
        <span className="inline-flex items-center gap-2">
          <span className="inline-flex items-center gap-1">
            <Kbd>↑</Kbd>
            <Kbd>↓</Kbd> navigate
          </span>
          <span className="inline-flex items-center gap-1">
            <Kbd>↵</Kbd> select
          </span>
        </span>
      </div>
    </Command.Dialog>
  );
}
