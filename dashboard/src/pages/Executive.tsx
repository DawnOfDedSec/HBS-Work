import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Building2,
  CalendarDays,
  Copy,
  Gauge,
  Presentation,
  Printer,
  ShieldAlert,
  ShieldCheck,
  Target,
  TrendingUp,
} from "lucide-react";
import { api, ApiError } from "../api";
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  ProgressBar,
  SectionHeader,
  Select,
  Table,
  Toolbar,
  ToolbarGroup,
  ToolbarSpacer,
  useToast,
  type TableColumn,
} from "../components/ui";
import { SeverityDonut } from "../components/charts/SeverityDonut";
import { RiskGauge } from "../components/charts/RiskGauge";
import { TrendLine } from "../components/charts/TrendLine";
import { LastUpdated } from "../components/LastUpdated";
import { TreatmentBadge } from "../components/badges";
import { sanitizeText } from "../components/EvidenceDrawer";
import { useScopeFilters } from "../useScopeFilters";
import { useLiveEvents } from "../useLiveEvents";
import type { Campaign, OverviewMetrics, RiskTrendPoint } from "../types";

export type ExecutiveProps = {
  /** Publish a canonical findings query and route to Findings. */
  onDrilldown: (query: string) => void;
};

type SeverityResponse = { severity: Record<string, number>; total: number };
type RiskResponse = { weightedRiskScore: number; coverage: number; riskTrend: RiskTrendPoint[] };

type TelemetryResponse = {
  hostCount: number;
  coverage: number;
  freshness: {
    latestReceivedAt: string | null;
    ageHours: number | null;
    slaHours: number;
    stale: boolean;
    staleHosts: number;
  };
  ingest: { accepted: number; rejected: number };
};

type TopFailingCheck = {
  checkId: string;
  title: string;
  severity: string;
  count: number;
  hosts: number;
};

type CampaignSummary = {
  campaign: { id: number; name: string };
  kpis: { weightedRiskScore: number; coverage: number; totalFindings: number; hosts: number };
  severityBreakdown: Record<string, number>;
  topFailingChecks: TopFailingCheck[];
};

type RemediationTreatmentSummary = {
  open: number;
  accepted_risk: number;
  false_positive: number;
  remediated: number;
  assignees: string[];
  nextDueDate: string | null;
};

type RemediationItem = {
  checkId: string;
  title: string;
  severity: string;
  category: string;
  status: string;
  failingHosts: number;
  hostCount: number;
  treatmentSummary: RemediationTreatmentSummary;
};

type RemediationResponse = { total: number; items: RemediationItem[] };

/** One row of the board's "top risks" list. */
type RiskRow = {
  checkId: string;
  title: string;
  severity: string;
  failingHosts: number;
  owner: string;
  treatment: string;
};

const TREATMENT_ORDER: Array<keyof Omit<RemediationTreatmentSummary, "assignees" | "nextDueDate">> = [
  "open",
  "accepted_risk",
  "false_positive",
  "remediated",
];

function formatDate(iso: string | null | undefined): string {
  if (!iso) return "-";
  const date = new Date(iso);
  return Number.isFinite(date.getTime())
    ? date.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" })
    : iso;
}

function ownerOf(summary: RemediationTreatmentSummary | undefined): string {
  if (!summary || summary.assignees.length === 0) return "Unassigned";
  return summary.assignees.join(", ");
}

function dominantTreatment(summary: RemediationTreatmentSummary | undefined): string {
  if (!summary) return "open";
  let best: string = "open";
  let bestCount = -1;
  for (const state of TREATMENT_ORDER) {
    if (summary[state] > bestCount) {
      bestCount = summary[state];
      best = state;
    }
  }
  return best;
}

function last30Days(points: RiskTrendPoint[]): RiskTrendPoint[] {
  const cutoff = new Date(Date.now() - 30 * 24 * 3600 * 1000).toISOString().slice(0, 10);
  const recent = points.filter((point) => point.date >= cutoff);
  return recent.length >= 2 ? recent : points.slice(-30);
}

function RiskTable({ rows }: { rows: RiskRow[] }) {
  const columns: Array<TableColumn<RiskRow>> = [
    {
      key: "checkId",
      header: "Check",
      render: (row) => <span className="font-mono text-xs text-accent">{sanitizeText(row.checkId)}</span>,
    },
    {
      key: "title",
      header: "Risk",
      render: (row) => <span className="text-ink">{sanitizeText(row.title)}</span>,
    },
    {
      key: "severity",
      header: "Severity",
      render: (row) => <Badge tone={severityTone(row.severity)}>{sanitizeText(row.severity)}</Badge>,
    },
    { key: "failingHosts", header: "Hosts", align: "right", sortable: true },
    {
      key: "owner",
      header: "Owner",
      render: (row) => <span className="text-xs text-ink-muted">{sanitizeText(row.owner)}</span>,
    },
    {
      key: "treatment",
      header: "Status",
      render: (row) => <TreatmentBadge state={row.treatment} />,
    },
  ];
  return (
    <Table
      label="Top risks with owners and treatment status"
      caption="Top risks with owners and treatment status"
      columns={columns}
      rows={rows}
      rowKey={(row) => row.checkId}
      empty="No failing checks in this scope."
    />
  );
}

function severityTone(severity: string): "critical" | "high" | "medium" | "low" | "info" {
  if (severity === "Critical") return "critical";
  if (severity === "High") return "high";
  if (severity === "Medium") return "medium";
  if (severity === "Low") return "low";
  return "info";
}

function MetaItem({ icon: Icon, label, value }: { icon: typeof Building2; label: string; value: string }) {
  return (
    <div className="flex items-start gap-2">
      <span className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-control bg-surface-raised text-ink-muted">
        <Icon size={14} aria-hidden />
      </span>
      <div className="min-w-0">
        <p className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">{label}</p>
        <p className="truncate text-sm text-ink">{sanitizeText(value)}</p>
      </div>
    </div>
  );
}

/**
 * Upper-management one-pager: campaign meta, risk gauge, severity/coverage,
 * top risks with owners, a 30-day trend, and a plain-language summary. Includes
 * a distraction-free Presentation mode and a print/PDF layout.
 */
export function Executive({ onDrilldown }: ExecutiveProps) {
  const { query } = useScopeFilters();
  const { lastEventAt } = useLiveEvents();
  const toast = useToast();
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [campaignId, setCampaignId] = useState<number | null>(null);
  const [overview, setOverview] = useState<OverviewMetrics | null>(null);
  const [summary, setSummary] = useState<CampaignSummary | null>(null);
  const [severity, setSeverity] = useState<Record<string, number> | null>(null);
  const [risk, setRisk] = useState<RiskResponse | null>(null);
  const [telemetry, setTelemetry] = useState<TelemetryResponse | null>(null);
  const [remediation, setRemediation] = useState<RemediationItem[]>([]);
  const [presentation, setPresentation] = useState(false);
  const [printStamp, setPrintStamp] = useState<string>(() => new Date().toISOString());
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [reloadKey, setReloadKey] = useState(0);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    api
      .raw<Campaign[]>("GET", "/api/campaigns")
      .then((value) => alive && setCampaigns(Array.isArray(value) ? value : []))
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, [lastEventAt]);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(null);
    const qs = query ? `?${query}` : "";

    api
      .raw<OverviewMetrics>("GET", `/api/overview${qs}`)
      .then((value) => {
        if (alive) setOverview(value);
      })
      .catch((err) => {
        if (alive) setError(err instanceof ApiError ? err.message : "Failed to load overview metrics");
      })
      .finally(() => {
        if (alive) {
          setLoading(false);
          setLastUpdated(new Date().toISOString());
        }
      });

    api
      .raw<SeverityResponse>("GET", `/api/metrics/severity${qs}`)
      .then((value) => alive && setSeverity(value.severity))
      .catch(() => alive && setSeverity(null));

    api
      .raw<RiskResponse>("GET", `/api/metrics/risk${qs}`)
      .then((value) => alive && setRisk(value))
      .catch(() => alive && setRisk(null));

    api
      .raw<TelemetryResponse>("GET", `/api/telemetry${qs}`)
      .then((value) => alive && setTelemetry(value))
      .catch(() => alive && setTelemetry(null));

    api
      .raw<RemediationResponse>("GET", `/api/remediation${qs}`)
      .then((value) => alive && setRemediation(Array.isArray(value.items) ? value.items : []))
      .catch(() => alive && setRemediation([]));

    if (campaignId !== null) {
      api
        .raw<CampaignSummary>("GET", `/api/campaigns/${campaignId}/summary${qs}`)
        .then((value) => alive && setSummary(value))
        .catch(() => alive && setSummary(null));
    } else {
      setSummary(null);
    }

    return () => {
      alive = false;
    };
  }, [query, campaignId, lastEventAt, reloadKey]);

  // Presentation mode hides the console chrome through a body class.
  useEffect(() => {
    const body = document.body;
    body.classList.toggle("hbs-presentation", presentation);
    return () => body.classList.remove("hbs-presentation");
  }, [presentation]);

  const refresh = () => setReloadKey((value) => value + 1);

  const selectedCampaign = useMemo(
    () => campaigns.find((campaign) => campaign.id === campaignId) ?? null,
    [campaigns, campaignId],
  );

  const riskScore = summary?.kpis.weightedRiskScore ?? risk?.weightedRiskScore ?? overview?.kpis.weightedRiskScore ?? 0;
  const coverage = summary?.kpis.coverage ?? risk?.coverage ?? overview?.kpis.coverage ?? 0;
  const severityData = summary?.severityBreakdown ?? severity ?? {};
  const trend = useMemo(
    () => last30Days(risk?.riskTrend ?? overview?.riskTrend ?? []),
    [risk, overview],
  );

  const remediationByCheck = useMemo(() => {
    const map = new Map<string, RemediationItem>();
    for (const item of remediation) map.set(item.checkId, item);
    return map;
  }, [remediation]);

  const topRisks = useMemo<RiskRow[]>(() => {
    if (summary) {
      return summary.topFailingChecks.slice(0, 10).map((check) => {
        const item = remediationByCheck.get(check.checkId);
        return {
          checkId: check.checkId,
          title: check.title,
          severity: check.severity,
          failingHosts: check.hosts,
          owner: ownerOf(item?.treatmentSummary),
          treatment: dominantTreatment(item?.treatmentSummary),
        };
      });
    }
    return remediation.slice(0, 10).map((item) => ({
      checkId: item.checkId,
      title: item.title,
      severity: item.severity,
      failingHosts: item.failingHosts,
      owner: ownerOf(item.treatmentSummary),
      treatment: dominantTreatment(item.treatmentSummary),
    }));
  }, [summary, remediation, remediationByCheck]);

  const hostsReviewed = telemetry?.hostCount ?? summary?.kpis.hosts ?? overview?.kpis.scannedHosts ?? 0;
  const hostsTotal = overview?.kpis.scannedHosts ?? hostsReviewed;
  const metaName = selectedCampaign?.name ?? "Portfolio";
  const metaClient = selectedCampaign?.client ?? "All clients";
  const metaScope = selectedCampaign?.scope ?? "All campaigns in scope";
  const metaDate = selectedCampaign?.updatedAt ?? telemetry?.freshness.latestReceivedAt ?? null;

  const plainSummary = useMemo(() => {
    const top = topRisks
      .slice(0, 3)
      .map((row) => `${row.title} (${row.failingHosts} host${row.failingHosts === 1 ? "" : "s"})`);
    const lead =
      hostsTotal > 0
        ? `${hostsReviewed} of ${hostsTotal} hosts were reviewed in this scope`
        : `${hostsReviewed} hosts were reviewed in this scope`;
    const coverageText = `${coverage.toFixed(0)}% of applicable checks were decided`;
    const riskText =
      top.length > 0
        ? `the highest risks are ${top.join(", ")}`
        : "no failing checks were recorded";
    return `${lead}; ${coverageText}. At present, ${riskText}.`;
  }, [hostsReviewed, hostsTotal, coverage, topRisks]);

  const copySummary = () => {
    const text = `${metaName} - security posture summary (${formatDate(metaDate)})\n\n${plainSummary}\n\nRisk score: ${riskScore.toFixed(1)}/100 · Coverage: ${coverage.toFixed(1)}%`;
    if (typeof navigator === "undefined" || !navigator.clipboard) {
      toast.error("Clipboard unavailable");
      return;
    }
    navigator.clipboard
      .writeText(text)
      .then(() => toast.success("Board summary copied"))
      .catch(() => toast.error("Clipboard unavailable"));
  };

  const print = () => {
    // Update the timestamp first, then let React paint before the print dialog.
    setPrintStamp(new Date().toISOString());
    window.setTimeout(() => window.print(), 0);
  };

  const actions = (
    <>
      <div className="hbs-presentation-hide flex flex-wrap items-center gap-2">
        <LastUpdated at={lastUpdated} onRefresh={refresh} loading={loading} />
        <Select
          size="sm"
          aria-label="Campaign"
          value={campaignId === null ? "all" : String(campaignId)}
          onChange={(value) => setCampaignId(value === "all" ? null : Number(value))}
          options={[
            { value: "all", label: "All campaigns" },
            ...campaigns.map((campaign) => ({ value: String(campaign.id), label: campaign.name })),
          ]}
        />
        <Button size="sm" variant="secondary" icon={Copy} onClick={copySummary}>
          Copy summary
        </Button>
        <Button size="sm" variant="secondary" icon={Printer} onClick={print}>
          Print / Save PDF
        </Button>
      </div>
      <Button
        size="sm"
        variant={presentation ? "primary" : "secondary"}
        icon={Presentation}
        aria-pressed={presentation}
        onClick={() => setPresentation((value) => !value)}
      >
        {presentation ? "Exit presentation" : "Presentation mode"}
      </Button>
    </>
  );

  if (error && !overview) {
    return (
      <section className="mx-auto flex max-w-7xl flex-col gap-6">
        <SectionHeader eyebrow="Govern" title="Executive Summary" icon={Presentation} />
        <EmptyState
          icon={AlertTriangle}
          title="Could not load the executive summary"
          detail={error}
          action={
            <Button variant="secondary" onClick={refresh}>
              Try again
            </Button>
          }
        />
      </section>
    );
  }

  return (
    <section aria-label="Executive summary" className="mx-auto flex max-w-7xl flex-col gap-6">
      {/* Print-only branded header with the generation timestamp. */}
      <div className="hbs-print-only">
        <div className="flex items-center justify-between border-b border-hairline pb-3">
          <div className="flex items-center gap-2">
            <ShieldCheck size={20} aria-hidden />
            <span className="text-lg font-semibold">HBS Security Posture</span>
          </div>
          <div className="text-right text-xs">
            <p>{metaName} · {metaClient}</p>
            <p>Generated {new Date(printStamp).toLocaleString()}</p>
          </div>
        </div>
        {typeof window !== "undefined" ? (
          <span className="hbs-print-url">{`${window.location.origin}${window.location.pathname}`}</span>
        ) : null}
      </div>

      <SectionHeader
        eyebrow="Govern"
        title="Executive Summary"
        description="Board-ready posture for the current scope: risk, coverage, top risks, and their owners."
        icon={Presentation}
        actions={actions}
      />

      <Toolbar label="Executive summary actions" className="hbs-presentation-hide">
        <ToolbarGroup>
          <Badge tone="accent" icon={Target}>
            {selectedCampaign ? "Campaign scope" : "Portfolio scope"}
          </Badge>
        </ToolbarGroup>
        <ToolbarSpacer />
        <span className="text-2xs text-ink-subtle">
          Data: /api/overview · /api/metrics/severity · /api/metrics/risk · /api/telemetry
          {selectedCampaign ? " · /api/campaigns/:id/summary" : ""}
        </span>
      </Toolbar>

      <Card>
        <CardHeader title="Campaign" description="Engagement context for this summary" icon={Building2} />
        <CardBody className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <MetaItem icon={ShieldCheck} label="Name" value={metaName} />
          <MetaItem icon={Building2} label="Client" value={metaClient} />
          <MetaItem icon={Target} label="Scope" value={metaScope} />
          <MetaItem icon={CalendarDays} label="As of" value={formatDate(metaDate)} />
        </CardBody>
      </Card>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <RiskGauge score={riskScore} coverage={coverage} onDrilldown={onDrilldown} />
        <SeverityDonut data={severityData} onDrilldown={onDrilldown} />
        <Card className="flex flex-col">
          <CardHeader title="Coverage" description="Applicable checks decided" icon={Gauge} />
          <CardBody className="flex flex-1 flex-col justify-center gap-4">
            <div>
              <p className="text-3xl font-semibold tabular-nums text-ink">{coverage.toFixed(1)}%</p>
              <p className="mt-1 text-xs text-ink-muted">
                {hostsReviewed} of {hostsTotal} hosts reviewed
              </p>
            </div>
            <ProgressBar
              value={coverage}
              label="Coverage"
              showValue
              tone={coverage >= 90 ? "compliant" : coverage >= 60 ? "accent" : "critical"}
            />
            <div className="flex flex-wrap gap-2">
              <Badge tone={telemetry?.freshness.stale ? "high" : "compliant"}>
                {telemetry?.freshness.stale ? "Stale data" : "Fresh data"}
              </Badge>
              {telemetry && telemetry.ingest.rejected > 0 ? (
                <Badge tone="critical" icon={ShieldAlert}>
                  {telemetry.ingest.rejected} ingest rejects
                </Badge>
              ) : null}
              {overview ? <Badge tone="neutral">{overview.kpis.openCriticals} open criticals</Badge> : null}
            </div>
          </CardBody>
        </Card>
      </div>

      <Card>
        <CardHeader
          title="Plain-language summary"
          description="Suitable for a board narrative or an email update"
          icon={TrendingUp}
          actions={
            <Button size="sm" variant="ghost" icon={Copy} onClick={copySummary} className="hbs-presentation-hide">
              Copy
            </Button>
          }
        />
        <CardBody>
          <p className="max-w-4xl text-sm leading-relaxed text-ink">{plainSummary}</p>
        </CardBody>
      </Card>

      <TrendLine points={trend} onDrilldown={onDrilldown} />

      <Card flush className="overflow-hidden">
        <div className="p-4">
          <CardHeader
            title="Top 10 risks"
            description="Highest-severity failing checks, with owners and treatment status"
            icon={ShieldAlert}
          />
        </div>
        <div className="px-0 pb-0">
          <RiskTable rows={topRisks} />
        </div>
      </Card>
    </section>
  );
}
