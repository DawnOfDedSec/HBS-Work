import { useEffect, useState } from "react";
import {
  Activity,
  BarChart3,
  BookOpen,
  FolderKanban,
  ListChecks,
  MapPin,
  RefreshCw,
  ScrollText,
  Wrench,
} from "lucide-react";
import { api, ApiError } from "../api";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  SectionHeader,
  Skeleton,
  TabPanel,
  Table,
  Tabs,
  type TabItem,
  type TableColumn,
  useToast,
} from "../components/ui";
import { ScopeSelector } from "../components/ScopeSelector";
import { CampaignSummary } from "./CampaignSummary";
import { Findings } from "./Findings";
import { Locations } from "./Locations";
import { Telemetry } from "./Telemetry";
import { Treatment } from "./Treatment";
import { Standards } from "./Standards";
import { sanitizeText } from "../components/EvidenceDrawer";
import type { Location } from "../types";

type Props = {
  campaignId: number;
  onBack: () => void;
  onOpenHost: (hostId: number) => void;
  onOpenDownloads: (locationId: number) => void;
  onDrilldown: (query: string) => void;
};

type ReportListRow = {
  id: number;
  hostId: number;
  hostname: string | null;
  extractorVersion: string | null;
  receivedAt: string;
  via: string | null;
  score: number | null;
  coverage: number | null;
};

type Tab = "summary" | "findings" | "reports" | "locations" | "treatment" | "standards" | "telemetry";

const TABS: Array<TabItem & { value: Tab }> = [
  { value: "summary", label: "Summary", icon: BarChart3 },
  { value: "findings", label: "Findings", icon: ListChecks },
  { value: "reports", label: "Reports", icon: ScrollText },
  { value: "locations", label: "Locations & Hosts", icon: MapPin },
  { value: "treatment", label: "Treatment", icon: Wrench },
  { value: "standards", label: "Standards", icon: BookOpen },
  { value: "telemetry", label: "Telemetry", icon: Activity },
];

/** Reports received for every location in the campaign, newest first. */
function ReportsPanel({ campaignId, onDrilldown }: { campaignId: number; onDrilldown: (query: string) => void }) {
  const [rows, setRows] = useState<ReportListRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [reloadKey, setReloadKey] = useState(0);
  const toast = useToast();

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(null);
    async function load() {
      const campaign = await api.raw<{ locations?: Location[] }>("GET", `/api/campaigns/${campaignId}`);
      const locations = campaign.locations ?? [];
      if (locations.length === 0) return [];
      const params = new URLSearchParams();
      for (const location of locations) params.append("locationId", String(location.id));
      params.set("pageSize", "100");
      const response = await api.raw<{ reports: ReportListRow[] }>("GET", `/api/reports?${params.toString()}`);
      return Array.isArray(response.reports) ? response.reports : [];
    }
    load()
      .then((value) => {
        if (alive) setRows(value);
      })
      .catch((err) => {
        if (!alive) return;
        const message = err instanceof ApiError ? err.message : "failed to load reports";
        setError(message);
        toast.error("Could not load reports", { description: message });
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [campaignId, reloadKey, toast]);

  const columns: Array<TableColumn<ReportListRow>> = [
    { key: "id", header: "Report", render: (row) => <span className="font-mono text-xs text-ink">#{row.id}</span> },
    { key: "hostname", header: "Host", render: (row) => sanitizeText(row.hostname) || "—" },
    {
      key: "receivedAt",
      header: "Received",
      sortable: true,
      render: (row) => <span className="text-xs text-ink-muted">{sanitizeText(row.receivedAt)}</span>,
    },
    { key: "extractorVersion", header: "Extractor", render: (row) => sanitizeText(row.extractorVersion) || "—" },
    { key: "via", header: "Via", render: (row) => <Badge tone="neutral">{sanitizeText(row.via) || "—"}</Badge> },
    {
      key: "score",
      header: "Risk",
      align: "right",
      sortable: true,
      render: (row) => (row.score === null ? "—" : row.score.toFixed(1)),
    },
    {
      key: "coverage",
      header: "Coverage",
      align: "right",
      sortable: true,
      render: (row) => (row.coverage === null ? "—" : `${row.coverage.toFixed(1)}%`),
    },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      align: "right",
      render: (row) => (
        <Button
          size="sm"
          variant="ghost"
          onClick={(event) => {
            event.stopPropagation();
            onDrilldown(`scope=report&reportId=${row.id}`);
          }}
        >
          Open findings
        </Button>
      ),
    },
  ];

  if (loading && rows === null) {
    return (
      <Card>
        <Skeleton width="30%" />
        <Skeleton className="mt-3" width="100%" />
      </Card>
    );
  }
  if (error) {
    return (
      <EmptyState
        title="Could not load reports"
        detail={error}
        action={
          <Button variant="secondary" icon={RefreshCw} onClick={() => setReloadKey((key) => key + 1)}>
            Try again
          </Button>
        }
      />
    );
  }

  return (
    <Card flush className="overflow-hidden">
      <div className="p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-ink">Reports</h3>
            <p className="mt-0.5 text-xs text-ink-muted">
              Sealed reports received for this campaign's locations, newest first.
            </p>
          </div>
          <Badge tone="accent">{rows?.length ?? 0} reports</Badge>
        </div>
      </div>
      {!rows || rows.length === 0 ? (
        <div className="p-4">
          <EmptyState title="No reports yet" detail="Issued extractors will push sealed reports here." />
        </div>
      ) : (
        <Table
          label="Campaign reports"
          columns={columns}
          rows={rows}
          rowKey={(row) => String(row.id)}
          stickyHeader
          onRowClick={(row) => onDrilldown(`scope=report&reportId=${row.id}`)}
        />
      )}
    </Card>
  );
}

/** Campaign workspace shell. Tabs map to the real findings/locations/telemetry workspaces. */
export function CampaignDetail({ campaignId, onBack, onOpenHost, onOpenDownloads, onDrilldown }: Props) {
  const [tab, setTab] = useState<Tab>("summary");

  return (
    <section aria-label={`Campaign ${campaignId}`} className="mx-auto flex max-w-7xl flex-col gap-5">
      <SectionHeader
        eyebrow="Campaign"
        title={`Campaign #${campaignId}`}
        description="Everything scoped to this engagement: summary, findings, reports, locations, treatment, standards, and telemetry."
        icon={FolderKanban}
        actions={
          <Button variant="ghost" onClick={onBack}>
            Campaigns
          </Button>
        }
      />

      <ScopeSelector />

      <Tabs
        items={TABS}
        value={tab}
        onChange={(value) => setTab(value as Tab)}
        label="Campaign views"
        idBase="campaign-tabs"
      />

      <TabPanel id="summary" active={tab === "summary"} idBase="campaign-tabs">
        <CampaignSummary campaignId={campaignId} onDrilldown={onDrilldown} />
      </TabPanel>
      <TabPanel id="findings" active={tab === "findings"} idBase="campaign-tabs">
        <Findings />
      </TabPanel>
      <TabPanel id="reports" active={tab === "reports"} idBase="campaign-tabs">
        <ReportsPanel campaignId={campaignId} onDrilldown={onDrilldown} />
      </TabPanel>
      <TabPanel id="locations" active={tab === "locations"} idBase="campaign-tabs">
        <Locations campaignId={campaignId} onOpenHost={onOpenHost} onOpenDownloads={onOpenDownloads} />
      </TabPanel>
      <TabPanel id="treatment" active={tab === "treatment"} idBase="campaign-tabs">
        <Treatment />
      </TabPanel>
      <TabPanel id="standards" active={tab === "standards"} idBase="campaign-tabs">
        <Standards onDrilldown={onDrilldown} />
      </TabPanel>
      <TabPanel id="telemetry" active={tab === "telemetry"} idBase="campaign-tabs">
        <Telemetry onDrilldown={onDrilldown} />
      </TabPanel>
    </section>
  );
}
