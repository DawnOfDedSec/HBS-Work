import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  CalendarDays,
  FolderKanban,
  Plus,
  RefreshCw,
  Search,
  Users,
} from "lucide-react";
import { api, ApiError } from "../api";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  Input,
  SectionHeader,
  Skeleton,
  Toolbar,
  ToolbarGroup,
  ToolbarSpacer,
  useToast,
} from "../components/ui";
import { CreateCampaignModal } from "../components/CreateCampaignModal";
import { sanitizeText } from "../components/EvidenceDrawer";
import type { Campaign } from "../types";

type Props = { onOpen: (campaignId: number) => void };

const STATUS_TONE: Record<Campaign["status"], "compliant" | "degraded" | "na"> = {
  active: "compliant",
  completed: "degraded",
  archived: "na",
};

function formatDate(value: string): string {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? new Date(parsed).toLocaleDateString() : sanitizeText(value);
}

export function Campaigns({ onOpen }: Props) {
  const [campaigns, setCampaigns] = useState<Campaign[] | null>(null);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [reloadKey, setReloadKey] = useState(0);
  const toast = useToast();

  useEffect(() => {
    let alive = true;
    setLoading(true);
    api
      .listCampaigns()
      .then((rows) => {
        if (alive) setCampaigns(Array.isArray(rows) ? rows : []);
      })
      .catch((err) => {
        if (!alive) return;
        const message = err instanceof ApiError ? err.message : "failed to load campaigns";
        setError(message);
        toast.error("Could not load campaigns", { description: message });
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [reloadKey, toast]);

  const visible = useMemo(() => {
    const rows = campaigns ?? [];
    const term = search.trim().toLowerCase();
    if (!term) return rows;
    return rows.filter((campaign) =>
      [campaign.name, campaign.client ?? "", campaign.scope ?? "", ...campaign.tags]
        .join("\n")
        .toLowerCase()
        .includes(term),
    );
  }, [campaigns, search]);

  return (
    <section aria-label="Campaigns" className="mx-auto flex max-w-7xl flex-col gap-5">
      <SectionHeader
        eyebrow="Operate"
        title="Campaigns"
        description="Engagements that group locations, hosts, and every sealed report."
        icon={FolderKanban}
        actions={
          <>
            <Button variant="secondary" icon={RefreshCw} loading={loading} onClick={() => setReloadKey((key) => key + 1)}>
              Refresh
            </Button>
            <Button variant="primary" icon={Plus} onClick={() => setCreating(true)}>
              New campaign
            </Button>
          </>
        }
      />

      <Toolbar label="Campaign search">
        <ToolbarGroup>
          <Input
            type="search"
            aria-label="Search campaigns"
            icon={Search}
            placeholder="Search name, client, tags…"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            containerClassName="w-72"
          />
        </ToolbarGroup>
        <ToolbarSpacer />
        <Badge tone="accent">{visible.length} shown</Badge>
      </Toolbar>

      {error ? (
        <div
          role="alert"
          className="flex items-start gap-2 rounded-control border border-critical/40 bg-critical-soft/60 p-3 text-sm text-critical"
        >
          <AlertTriangle size={16} aria-hidden className="mt-0.5 shrink-0" />
          <span>{error}</span>
        </div>
      ) : null}

      {loading && campaigns === null ? (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 3 }).map((_, index) => (
            <Card key={index}>
              <Skeleton width="60%" />
              <Skeleton className="mt-3" width="40%" />
            </Card>
          ))}
        </div>
      ) : visible.length === 0 ? (
        <EmptyState
          icon={FolderKanban}
          title={campaigns && campaigns.length > 0 ? "No campaigns match your search" : "No campaigns yet"}
          detail={
            campaigns && campaigns.length > 0
              ? "Clear the search to see every campaign."
              : "Create a campaign to issue extractors and receive reports."
          }
          action={
            <Button variant="primary" icon={Plus} onClick={() => setCreating(true)}>
              New campaign
            </Button>
          }
        />
      ) : (
        <ul className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {visible.map((campaign) => (
            <li key={campaign.id}>
              <button
                type="button"
                onClick={() => onOpen(campaign.id)}
                className="hbs-panel group flex h-full w-full flex-col gap-3 p-4 text-left transition-colors hover:border-hairline-strong hover:bg-surface-raised"
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex min-w-0 items-center gap-2">
                    <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-control bg-accent-soft text-accent">
                      <FolderKanban size={16} aria-hidden />
                    </span>
                    <span className="truncate text-sm font-semibold text-ink">{sanitizeText(campaign.name)}</span>
                  </div>
                  <Badge tone={STATUS_TONE[campaign.status]}>{campaign.status}</Badge>
                </div>
                <p className="text-xs text-ink-muted">{sanitizeText(campaign.client) || "No client recorded"}</p>
                {campaign.tags.length > 0 ? (
                  <ul className="flex flex-wrap gap-1">
                    {campaign.tags.slice(0, 4).map((tag) => (
                      <li key={tag}>
                        <Badge tone="neutral">{sanitizeText(tag)}</Badge>
                      </li>
                    ))}
                  </ul>
                ) : null}
                <div className="mt-auto flex flex-wrap items-center justify-between gap-2 text-2xs text-ink-subtle">
                  <span className="inline-flex items-center gap-1">
                    <CalendarDays size={12} aria-hidden /> Created {formatDate(campaign.createdAt)}
                  </span>
                  <span className="inline-flex items-center gap-1">
                    <Users size={12} aria-hidden /> Campaign #{campaign.id}
                  </span>
                </div>
              </button>
            </li>
          ))}
        </ul>
      )}

      <CreateCampaignModal
        open={creating}
        onClose={() => setCreating(false)}
        onCreated={(campaign) => setCampaigns((current) => [...(current ?? []), campaign])}
      />
    </section>
  );
}
