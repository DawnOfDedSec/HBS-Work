import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Copy,
  FileDown,
  FileSpreadsheet,
  Hammer,
  Search,
  Server,
  Terminal,
  X,
} from "lucide-react";
import { api, ApiError } from "../api";
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  Chip,
  Drawer,
  EmptyState,
  IconButton,
  Input,
  SectionHeader,
  Select,
  Skeleton,
  Table,
  Toolbar,
  ToolbarDivider,
  ToolbarGroup,
  ToolbarSpacer,
  useToast,
  type TableColumn,
} from "../components/ui";
import { SeverityBadge, StatusBadge, TreatmentBadge } from "../components/badges";
import { DensityToggle } from "../components/DensityToggle";
import { LastUpdated } from "../components/LastUpdated";
import { sanitizeText } from "../components/EvidenceDrawer";
import { ScopeControls, clearScopeKeys } from "../components/ScopeSelector";
import { serializeFilters } from "../filters";
import { useScopeFilters } from "../useScopeFilters";
import { useDensity } from "../useDensity";
import { useLiveEvents } from "../useLiveEvents";
import type { Campaign } from "../types";

export type RemediationProps = {
  /** Publish a canonical findings query and route to Findings. */
  onDrilldown: (query: string) => void;
};

type RemediationHost = {
  hostId: number;
  hostname: string;
  displayId: string;
  reportId: number;
  status: string;
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
  hosts: RemediationHost[];
  recommendation: string;
  impact: string;
  references: string[];
  repro: string;
  exampleLocation: string;
  treatmentSummary: RemediationTreatmentSummary;
};

type RemediationResponse = { total: number; items: RemediationItem[] };
type CategoryResponse = { categories: Array<{ category: string }> };

const SEVERITY_OPTIONS = ["Critical", "High", "Medium", "Low", "Informational"];
const TREATMENT_OPTIONS = ["open", "accepted_risk", "false_positive", "remediated"];

function errorMessage(error: unknown): string {
  return error instanceof ApiError ? error.message : "Request failed. Please retry.";
}

function treatmentLabel(summary: RemediationTreatmentSummary): string {
  const parts: string[] = [];
  if (summary.open > 0) parts.push(`${summary.open} open`);
  if (summary.accepted_risk > 0) parts.push(`${summary.accepted_risk} accepted`);
  if (summary.false_positive > 0) parts.push(`${summary.false_positive} false positive`);
  if (summary.remediated > 0) parts.push(`${summary.remediated} remediated`);
  return parts.length > 0 ? parts.join(" · ") : "Open";
}

function severityWeight(severity: string): number {
  const index = SEVERITY_OPTIONS.indexOf(severity);
  return index === -1 ? SEVERITY_OPTIONS.length : index;
}

/** A fieldset of removable toggle chips for one canonical filter key. */
function FilterToggle({
  label,
  options,
  active,
  onToggle,
}: {
  label: string;
  options: string[];
  active: Set<string>;
  onToggle: (value: string) => void;
}) {
  return (
    <ToolbarGroup>
      <span className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">{label}</span>
      {options.map((option) => (
        <Chip
          key={option}
          label={option.replace(/_/g, " ")}
          active={active.has(option)}
          onClick={() => onToggle(option)}
        />
      ))}
    </ToolbarGroup>
  );
}

/**
 * Sysadmin Remediation Center: every failing check in scope grouped into one
 * actionable unit with hosts, references, and a copy-ready command. Filters are
 * canonical URL state; row clicks drill into the Findings explorer.
 */
export function Remediation({ onDrilldown }: RemediationProps) {
  const { filters, query, chips, toggle, clearKey, clear } = useScopeFilters();
  const { dense, density, setDensity } = useDensity();
  const { lastEventAt } = useLiveEvents();
  const toast = useToast();

  const [items, setItems] = useState<RemediationItem[]>([]);
  const [categories, setCategories] = useState<string[]>([]);
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [exportCampaignId, setExportCampaignId] = useState<number | null>(null);
  const [search, setSearch] = useState(filters.q?.[0] ?? "");
  const [loading, setLoading] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const [detail, setDetail] = useState<RemediationItem | null>(null);

  useEffect(() => {
    setSearch(filters.q?.[0] ?? "");
  }, [filters.q]);

  useEffect(() => {
    let alive = true;
    api
      .raw<Campaign[]>("GET", "/api/campaigns")
      .then((value) => {
        if (!alive) return;
        const list = Array.isArray(value) ? value : [];
        setCampaigns(list);
        setExportCampaignId((current) => current ?? list[0]?.id ?? null);
      })
      .catch(() => undefined);
    api
      .raw<CategoryResponse>("GET", "/api/metrics/category")
      .then((value) => {
        if (!alive) return;
        setCategories(
          (Array.isArray(value.categories) ? value.categories : []).map((entry) => entry.category),
        );
      })
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, []);

  const refresh = useCallback(() => setReloadKey((value) => value + 1), []);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(null);
    const path = `/api/remediation${query ? `?${query}` : ""}`;
    api
      .raw<RemediationResponse>("GET", path)
      .then((value) => {
        if (!alive) return;
        setItems(Array.isArray(value.items) ? value.items : []);
      })
      .catch((err) => {
        if (!alive) return;
        const message = errorMessage(err);
        setError(message);
        toast.error("Could not load remediation data", { description: message });
      })
      .finally(() => {
        if (alive) {
          setLoading(false);
          setLastUpdated(new Date().toISOString());
        }
      });
    return () => {
      alive = false;
    };
  }, [query, reloadKey, lastEventAt, toast]);

  const sorted = useMemo(
    () =>
      [...items].sort(
        (a, b) =>
          severityWeight(a.severity) - severityWeight(b.severity) ||
          b.failingHosts - a.failingHosts ||
          a.checkId.localeCompare(b.checkId),
      ),
    [items],
  );

  const copy = useCallback(
    (text: string, label: string) => {
      if (typeof navigator === "undefined" || !navigator.clipboard) {
        toast.error("Clipboard unavailable", { description: "Copy the command manually." });
        return;
      }
      navigator.clipboard
        .writeText(text)
        .then(() => toast.success(label))
        .catch(() => toast.error("Clipboard unavailable", { description: "Copy the command manually." }));
    },
    [toast],
  );

  const copyAllCommands = useCallback(() => {
    const commands = sorted
      .map((item) => item.repro)
      .filter((command) => command.trim().length > 0);
    if (commands.length === 0) {
      toast.info("No commands to copy");
      return;
    }
    copy(commands.join("\n"), `Copied ${commands.length} command${commands.length === 1 ? "" : "s"}`);
  }, [sorted, copy, toast]);

  const exportUrl = useCallback(
    (format: "xlsx" | "csv") =>
      exportCampaignId === null ? null : api.exportUrl("campaign", exportCampaignId, format),
    [exportCampaignId],
  );

  const columns: Array<TableColumn<RemediationItem>> = [
    {
      key: "checkId",
      header: "Check",
      sortable: true,
      render: (row) => <span className="font-mono text-xs text-accent">{sanitizeText(row.checkId)}</span>,
    },
    {
      key: "title",
      header: "Title",
      render: (row) => <span className="text-ink">{sanitizeText(row.title)}</span>,
    },
    {
      key: "severity",
      header: "Severity",
      sortable: true,
      sortValue: (row) => severityWeight(row.severity),
      render: (row) => <SeverityBadge severity={row.severity} />,
    },
    {
      key: "category",
      header: "Category",
      render: (row) => <span className="text-xs text-ink-muted">{sanitizeText(row.category)}</span>,
    },
    { key: "status", header: "Status", render: (row) => <StatusBadge status={row.status} /> },
    {
      key: "failingHosts",
      header: "Hosts",
      align: "right",
      sortable: true,
      render: (row) => (
        <span className="tabular-nums text-ink" title={`${row.failingHosts} failing of ${row.hostCount} reporting`}>
          {row.failingHosts}
          <span className="text-ink-subtle">/{row.hostCount}</span>
        </span>
      ),
    },
    {
      key: "treatment",
      header: "Treatment",
      render: (row) => <span className="text-xs text-ink-muted">{treatmentLabel(row.treatmentSummary)}</span>,
    },
    {
      key: "command",
      header: "Command",
      render: (row) => (
        <div className="flex max-w-xs items-center gap-1.5">
          <code
            className="truncate rounded bg-surface-sunken px-1.5 py-0.5 font-mono text-2xs text-ink-muted"
            title={row.repro || "No command recorded"}
          >
            {row.repro || "—"}
          </code>
          <IconButton
            size="sm"
            icon={Copy}
            label={`Copy remediation command for ${row.checkId}`}
            disabled={!row.repro}
            onClick={(event) => {
              event.stopPropagation();
              copy(row.repro, `Copied ${row.checkId} command`);
            }}
          />
        </div>
      ),
    },
    {
      key: "details",
      header: <span className="sr-only">Details</span>,
      align: "right",
      render: (row) => (
        <Button
          size="sm"
          variant="secondary"
          onClick={(event) => {
            event.stopPropagation();
            setDetail(row);
          }}
        >
          Details
        </Button>
      ),
    },
  ];

  const activeSeverity = new Set(filters.severity ?? []);
  const activeTreatment = new Set(filters.treatment ?? []);
  const activeCategory = new Set(filters.category ?? []);

  return (
    <section aria-label="Remediation Center" className="mx-auto flex max-w-7xl flex-col gap-5">
      <SectionHeader
        eyebrow="Operate"
        title="Remediation Center"
        description="Every failing check in scope, grouped with its hosts and a copy-ready command."
        icon={Hammer}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <LastUpdated at={lastUpdated} onRefresh={refresh} loading={loading} />
            <DensityToggle density={density} onChange={setDensity} />
            <Button size="sm" variant="secondary" icon={Copy} onClick={copyAllCommands}>
              Copy all commands
            </Button>
          </div>
        }
      />

      <ScopeControls
        filters={filters}
        onToggle={toggle}
        onClearScope={() => {
          clearScopeKeys(filters);
        }}
      />

      <Card>
        <CardHeader
          title="Filters"
          description={`${sorted.length} remediation unit${sorted.length === 1 ? "" : "s"} in scope`}
          icon={Search}
          actions={
            chips.length > 0 ? (
              <Button size="sm" variant="ghost" icon={X} onClick={clear}>
                Clear all
              </Button>
            ) : null
          }
        />
        <CardBody className="flex flex-col gap-3">
          <Toolbar label="Remediation filters">
            <form
              role="search"
              className="flex items-center gap-2"
              onSubmit={(event) => {
                event.preventDefault();
                const value = search.trim();
                if (value) toggle("q", value);
                else clearKey("q");
              }}
            >
              <Input
                type="search"
                aria-label="Search remediation units"
                icon={Search}
                placeholder="Search checks, titles, commands…"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                containerClassName="w-72"
              />
              <Button size="sm" variant="secondary" type="submit">
                Apply
              </Button>
            </form>
            <ToolbarDivider />
            <FilterToggle
              label="Severity"
              options={SEVERITY_OPTIONS}
              active={activeSeverity}
              onToggle={(value) => toggle("severity", value)}
            />
            <ToolbarDivider />
            <FilterToggle
              label="Treatment"
              options={TREATMENT_OPTIONS}
              active={activeTreatment}
              onToggle={(value) => toggle("treatment", value)}
            />
            <ToolbarSpacer />
            <Select
              size="sm"
              aria-label="Category"
              value={filters.category?.[0] ?? ""}
              onChange={(value) => {
                if (value) toggle("category", value);
                else clearKey("category");
              }}
              options={[
                { value: "", label: "All categories" },
                ...categories.map((category) => ({ value: category, label: category })),
              ]}
            />
            <ToolbarDivider />
            <Select
              size="sm"
              aria-label="Export campaign"
              value={exportCampaignId === null ? "" : String(exportCampaignId)}
              onChange={(value) => setExportCampaignId(value ? Number(value) : null)}
              options={campaigns.map((campaign) => ({ value: String(campaign.id), label: campaign.name }))}
              disabled={campaigns.length === 0}
            />
            <Button
              size="sm"
              variant="ghost"
              icon={FileSpreadsheet}
              disabled={exportUrl("xlsx") === null}
              onClick={() => {
                const url = exportUrl("xlsx");
                if (url) window.location.href = url;
              }}
            >
              XLSX
            </Button>
            <Button
              size="sm"
              variant="ghost"
              icon={FileDown}
              disabled={exportUrl("csv") === null}
              onClick={() => {
                const url = exportUrl("csv");
                if (url) window.location.href = url;
              }}
            >
              CSV
            </Button>
          </Toolbar>

          {chips.length > 0 ? (
            <div aria-label="Active filters" className="flex flex-wrap items-center gap-2">
              <span className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">Active</span>
              {chips.map((chip) => (
                <Chip
                  key={`${chip.key}:${chip.value}`}
                  label={`${chip.key}:`}
                  value={chip.value}
                  active
                  onRemove={() => toggle(chip.key, chip.value)}
                />
              ))}
            </div>
          ) : null}
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

      <Card flush className="overflow-hidden">
        {loading && sorted.length === 0 ? (
          <div className="flex flex-col gap-2 p-4">
            {Array.from({ length: 6 }).map((_, index) => (
              <Skeleton key={index} height={28} />
            ))}
          </div>
        ) : sorted.length === 0 ? (
          <div className="p-4">
            <EmptyState
              title="No failing checks in the current scope"
              detail="Adjust or clear filters, or ingest new reports to populate remediation work."
            />
          </div>
        ) : (
          <Table
            label="Failing checks grouped for remediation"
            columns={columns}
            rows={sorted}
            rowKey={(row) => row.checkId}
            dense={dense}
            stickyHeader
            onRowClick={(row) => onDrilldown(serializeFilters({ checkId: [row.checkId] }))}
          />
        )}
      </Card>

      <p className="flex flex-wrap items-center gap-2 text-2xs text-ink-subtle">
        <Badge tone="accent" icon={Terminal}>
          {sorted.length} units
        </Badge>
        Row click drills into Findings filtered by check id. Use Details for references and the full command.
      </p>

      <Drawer
        open={detail !== null}
        onClose={() => setDetail(null)}
        title={detail ? `${detail.checkId} — ${detail.title}` : "Remediation"}
        description={detail ? `${detail.severity} · ${detail.category} · ${detail.failingHosts} failing hosts` : undefined}
        size="lg"
      >
        {detail ? (
          <div className="flex flex-col gap-5">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={detail.severity} />
              <StatusBadge status={detail.status} />
              <TreatmentBadge state={dominantTreatment(detail.treatmentSummary)} />
              <Badge tone="neutral" icon={Server}>
                {detail.failingHosts} of {detail.hostCount} hosts
              </Badge>
            </div>

            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wide text-ink-subtle">Recommendation</h3>
              <p className="mt-1 text-sm text-ink">{sanitizeText(detail.recommendation) || "—"}</p>
            </div>

            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wide text-ink-subtle">Impact</h3>
              <p className="mt-1 text-sm text-ink">{sanitizeText(detail.impact) || "—"}</p>
            </div>

            <div>
              <div className="flex items-center justify-between gap-2">
                <h3 className="text-xs font-semibold uppercase tracking-wide text-ink-subtle">Command</h3>
                <Button
                  size="sm"
                  variant="secondary"
                  icon={Copy}
                  disabled={!detail.repro}
                  onClick={() => copy(detail.repro, `Copied ${detail.checkId} command`)}
                >
                  Copy
                </Button>
              </div>
              <pre className="hbs-scroll mt-1 overflow-x-auto rounded-control border border-hairline bg-surface-sunken p-3 font-mono text-xs text-ink">
                {detail.repro || "No command recorded for this check."}
              </pre>
              {detail.exampleLocation ? (
                <p className="mt-1 text-2xs text-ink-subtle">
                  Evidence: <span className="font-mono">{sanitizeText(detail.exampleLocation)}</span>
                </p>
              ) : null}
            </div>

            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wide text-ink-subtle">References</h3>
              {detail.references.length === 0 ? (
                <p className="mt-1 text-sm text-ink-muted">—</p>
              ) : (
                <ul className="mt-1 flex flex-wrap gap-1.5">
                  {detail.references.map((reference) => (
                    <li key={reference}>
                      <Badge tone="info">{sanitizeText(reference)}</Badge>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wide text-ink-subtle">
                Affected hosts ({detail.failingHosts})
              </h3>
              <ul className="mt-1 flex flex-col gap-1">
                {detail.hosts.map((host) => (
                  <li key={host.hostId} className="flex items-center justify-between gap-2 text-sm">
                    <span className="font-mono text-xs text-ink">{sanitizeText(host.displayId)}</span>
                    <StatusBadge status={host.status} />
                  </li>
                ))}
              </ul>
            </div>

            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wide text-ink-subtle">Treatment</h3>
              <p className="mt-1 text-sm text-ink">{treatmentLabel(detail.treatmentSummary)}</p>
              <p className="mt-1 text-xs text-ink-muted">
                Owner: {detail.treatmentSummary.assignees.join(", ") || "Unassigned"}
                {detail.treatmentSummary.nextDueDate
                  ? ` · Due ${detail.treatmentSummary.nextDueDate.slice(0, 10)}`
                  : ""}
              </p>
            </div>

            <Button
              variant="secondary"
              block
              onClick={() => onDrilldown(serializeFilters({ checkId: [detail.checkId] }))}
            >
              Open in Findings
            </Button>
          </div>
        ) : null}
      </Drawer>
    </section>
  );
}

function dominantTreatment(summary: RemediationTreatmentSummary): string {
  const entries: Array<[string, number]> = [
    ["open", summary.open],
    ["accepted_risk", summary.accepted_risk],
    ["false_positive", summary.false_positive],
    ["remediated", summary.remediated],
  ];
  let best = "open";
  let bestCount = -1;
  for (const [state, count] of entries) {
    if (count > bestCount) {
      bestCount = count;
      best = state;
    }
  }
  return best;
}
