import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  FileSearch,
  ListChecks,
  RefreshCw,
  Search,
  Server,
  ShieldAlert,
  Table2,
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
  EmptyState,
  Input,
  Pagination,
  SectionHeader,
  Skeleton,
  TabPanel,
  Tabs,
  Table,
  Toolbar,
  ToolbarDivider,
  ToolbarGroup,
  ToolbarSpacer,
  type TabItem,
  type TableColumn,
  useToast,
} from "../components/ui";
import {
  SeverityBadge,
  StatusBadge,
  TreatmentBadge,
  EvidenceDepthBadge,
  PlatformBadge,
} from "../components/badges";
import {
  EvidenceDrawer,
  sanitizeText,
  type EvidenceFinding,
} from "../components/EvidenceDrawer";
import { ScopeControls, clearScopeKeys } from "../components/ScopeSelector";
import { resolveScope, type FilterKey, type ScopeFilters } from "../filters";
import { useScopeFilters } from "../useScopeFilters";
import type { CheckResult } from "../types";
import { CheckDetail } from "./CheckDetail";
import { ReportDetail } from "./ReportDetail";

/** A serialized finding from `GET /api/findings` (`serializeFinding`). */
type Finding = {
  reportId: number;
  campaignId: number;
  locationId: number;
  hostId: number;
  hostname: string;
  displayId: string;
  checkId: string;
  title: string;
  severity: string;
  status: string;
  category: string;
  references: string[];
  treatment: string;
  treatmentAssignee: string | null;
  treatmentDueDate: string | null;
  treatmentUpdatedAt: string | null;
  extractorVersion: string | null;
  platform: string | null;
  os: string | null;
  arch: string | null;
  via: string | null;
  evidenceDepth: string | null;
  receivedAt: string;
  scanTimestamp: string | null;
  reportScore: number | null;
  reportCoverage: number | null;
  links: Record<string, string>;
};

type FindingsResponse = { results: Finding[]; total: number; page: number; pageSize: number };

/** A host group from `GET /api/hosts` (`groupByHost`). */
type HostGroup = {
  id: number;
  machineId: string;
  hostname: string | null;
  displayId: string;
  platform: string | null;
  os: string | null;
  arch: string | null;
  firstSeenAt: string;
  lastSeenAt: string;
  reportCount: number;
  latestReportId: number | null;
  latestReceivedAt: string | null;
  riskScore: number | null;
  coverage: number | null;
  severity: Record<string, number>;
  treatment: Record<string, number>;
  links: { host: string };
};

type HostsResponse = { hosts: HostGroup[]; total: number; page: number; pageSize: number };

type ReportResponse = { id: number; hostname: string | null; results: CheckResult[] };

type Pivot = "findings" | "hosts" | "checks";

const SEVERITY_OPTIONS = ["Critical", "High", "Medium", "Low", "Informational"];
const STATUS_OPTIONS = ["NonCompliant", "DegradedPartial", "Error", "Compliant", "NotApplicable"];
const TREATMENT_OPTIONS = ["open", "accepted_risk", "false_positive", "remediated"];
const DEPTH_OPTIONS = ["AuthoritativePrimary", "AuthoritativeFallback", "DegradedPartial"];
const PAGE_SIZES = [25, 50, 100, 200];

type CheckAggregate = {
  checkId: string;
  title: string;
  severity: string;
  category: string;
  count: number;
  hosts: Set<number>;
};

function errorMessage(error: unknown): string {
  return error instanceof ApiError ? error.message : "Request failed. Please retry.";
}

function toEvidence(result: CheckResult): EvidenceFinding {
  return {
    checkId: result.id,
    title: result.title,
    severity: result.severity,
    status: result.status,
    category: result.category,
    impact: result.impact,
    recommendation: result.recommendation,
    references: Array.isArray(result.references) ? result.references : [],
    repro: result.repro,
    evidence: result.evidence,
    degradedReason: result.degradedReason ?? null,
    fallbackLog: Array.isArray(result.fallbackLog) ? result.fallbackLog : [],
    evidenceBlocks: Array.isArray(result.evidenceBlocks) ? result.evidenceBlocks : [],
    runContext: result.runContext,
  };
}

/** A fieldset of removable toggle chips for one canonical filter key. */
function FilterToggle({
  label,
  filterKey,
  options,
  filters,
  onToggle,
}: {
  label: string;
  filterKey: FilterKey;
  options: string[];
  filters: ScopeFilters;
  onToggle: (key: FilterKey, value: string) => void;
}) {
  const active = new Set(filters[filterKey] ?? []);
  return (
    <ToolbarGroup>
      <span className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">{label}</span>
      {options.map((option) => (
        <Chip
          key={option}
          label={option.replace(/([a-z])([A-Z])/g, "$1 $2").replace(/_/g, " ")}
          active={active.has(option)}
          onClick={() => onToggle(filterKey, option)}
        />
      ))}
    </ToolbarGroup>
  );
}

function InlineAlert({ children }: { children: React.ReactNode }) {
  return (
    <div role="alert" className="flex items-start gap-2 rounded-control border border-critical/40 bg-critical-soft/60 p-3 text-sm text-critical">
      <AlertTriangle size={16} aria-hidden className="mt-0.5 shrink-0" />
      <span>{children}</span>
    </div>
  );
}

/**
 * Scope-aware findings explorer. The filter bar is bound to `useScopeFilters`
 * so the URL query string stays the single source of truth; All findings / By
 * Host / By Check pivots share the same scope.
 */
export function Findings() {
  const { filters, query, chips, toggle, clearKey, clear } = useScopeFilters();
  const toast = useToast();
  const [pivot, setPivot] = useState<Pivot>("findings");
  const [search, setSearch] = useState(filters.q?.[0] ?? "");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [hosts, setHosts] = useState<HostGroup[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pendingRow, setPendingRow] = useState<string | null>(null);
  const [activeReportId, setActiveReportId] = useState<number | null>(null);
  const [activeCheckId, setActiveCheckId] = useState<string | null>(null);
  const [evidence, setEvidence] = useState<{
    finding: EvidenceFinding;
    reportId: number;
    hostname: string | null;
  } | null>(null);

  useEffect(() => {
    setSearch(filters.q?.[0] ?? "");
  }, [filters.q]);

  useEffect(() => {
    setPage(1);
  }, [query]);

  const refresh = useCallback(() => setPage(1), []);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(null);
    const params = new URLSearchParams(query);
    const isPivotHosts = pivot === "hosts";
    const effectiveSize = pivot === "checks" ? 200 : pageSize;
    params.set("page", pivot === "checks" ? "1" : String(page));
    params.set("pageSize", String(effectiveSize));
    const path = isPivotHosts ? `/api/hosts?${params.toString()}` : `/api/findings?${params.toString()}`;
    api
      .raw<FindingsResponse | HostsResponse>("GET", path)
      .then((response) => {
        if (!alive) return;
        if (isPivotHosts) {
          const hostResponse = response as HostsResponse;
          setHosts(Array.isArray(hostResponse.hosts) ? hostResponse.hosts : []);
          setFindings([]);
        } else {
          const findingResponse = response as FindingsResponse;
          setFindings(Array.isArray(findingResponse.results) ? findingResponse.results : []);
          setHosts([]);
        }
        setTotal(typeof response.total === "number" ? response.total : 0);
      })
      .catch((err) => {
        if (!alive) return;
        const message = errorMessage(err);
        setError(message);
        toast.error("Could not load findings", { description: message });
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [query, page, pageSize, pivot, toast]);

  const checks = useMemo<CheckAggregate[]>(() => {
    const grouped = new Map<string, CheckAggregate>();
    for (const finding of findings) {
      const bucket =
        grouped.get(finding.checkId) ??
        {
          checkId: finding.checkId,
          title: finding.title,
          severity: finding.severity,
          category: finding.category,
          count: 0,
          hosts: new Set<number>(),
        };
      bucket.count += 1;
      bucket.hosts.add(finding.hostId);
      grouped.set(finding.checkId, bucket);
    }
    return [...grouped.values()].sort((a, b) => a.checkId.localeCompare(b.checkId));
  }, [findings]);

  const openEvidence = useCallback(
    async (finding: Finding) => {
      const key = `${finding.reportId}:${finding.checkId}`;
      setPendingRow(key);
      try {
        const report = await api.raw<ReportResponse>("GET", `/api/reports/${finding.reportId}`);
        const result = (report.results ?? []).find((entry) => entry.id === finding.checkId);
        if (!result) {
          const message = `Finding ${finding.checkId} is no longer present in report #${finding.reportId}.`;
          setError(message);
          toast.error("Evidence unavailable", { description: message });
          return;
        }
        setEvidence({
          finding: toEvidence(result),
          reportId: finding.reportId,
          hostname: report.hostname ?? finding.hostname,
        });
      } catch (err) {
        const message = errorMessage(err);
        setError(message);
        toast.error("Could not load evidence", { description: message });
      } finally {
        setPendingRow(null);
      }
    },
    [toast],
  );

  if (activeReportId !== null) {
    return (
      <ReportDetail
        reportId={activeReportId}
        onBack={() => setActiveReportId(null)}
        onOpenCheck={(checkId) => {
          setActiveReportId(null);
          setActiveCheckId(checkId);
        }}
      />
    );
  }

  if (activeCheckId !== null) {
    return (
      <CheckDetail
        checkId={activeCheckId}
        onBack={() => setActiveCheckId(null)}
        onOpenReport={(reportId) => {
          setActiveCheckId(null);
          setActiveReportId(reportId);
        }}
      />
    );
  }

  const findingColumns: Array<TableColumn<Finding>> = [
    {
      key: "checkId",
      header: "Check",
      render: (row) => (
        <button
          type="button"
          onClick={(event) => {
            event.stopPropagation();
            setActiveCheckId(row.checkId);
          }}
          className="rounded font-mono text-xs text-accent underline decoration-dotted underline-offset-2 hover:text-accent-strong"
        >
          {sanitizeText(row.checkId)}
        </button>
      ),
    },
    {
      key: "title",
      header: "Title",
      render: (row) => <span className="text-ink">{sanitizeText(row.title)}</span>,
    },
    {
      key: "displayId",
      header: "Host",
      render: (row) => (
        <button
          type="button"
          onClick={(event) => {
            event.stopPropagation();
            toggle("hostId", String(row.hostId));
          }}
          className="rounded text-left text-ink-muted underline decoration-dotted underline-offset-2 hover:text-ink"
        >
          {sanitizeText(row.displayId)}
        </button>
      ),
    },
    { key: "severity", header: "Severity", render: (row) => <SeverityBadge severity={row.severity} /> },
    { key: "status", header: "Status", render: (row) => <StatusBadge status={row.status} /> },
    {
      key: "treatment",
      header: "Treatment",
      render: (row) => <TreatmentBadge state={row.treatment} />,
    },
    {
      key: "evidenceDepth",
      header: "Evidence",
      render: (row) =>
        row.evidenceDepth ? (
          <EvidenceDepthBadge depth={row.evidenceDepth} />
        ) : (
          <span className="text-2xs text-ink-subtle">—</span>
        ),
    },
    {
      key: "receivedAt",
      header: "Received",
      sortable: true,
      render: (row) => <span className="text-xs text-ink-muted">{sanitizeText(row.receivedAt)}</span>,
    },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      align: "right",
      render: (row) => (
        <div className="flex items-center justify-end gap-1.5">
          <Button
            size="sm"
            variant="secondary"
            loading={pendingRow === `${row.reportId}:${row.checkId}`}
            onClick={(event) => {
              event.stopPropagation();
              void openEvidence(row);
            }}
          >
            View
          </Button>
          <Button
            size="sm"
            variant="ghost"
            onClick={(event) => {
              event.stopPropagation();
              setActiveReportId(row.reportId);
            }}
          >
            Report
          </Button>
        </div>
      ),
    },
  ];

  const hostColumns: Array<TableColumn<HostGroup>> = [
    {
      key: "displayId",
      header: "Host",
      render: (row) => (
        <button
          type="button"
          onClick={() => {
            toggle("hostId", String(row.id));
            setPivot("findings");
          }}
          className="rounded text-left text-accent underline decoration-dotted underline-offset-2 hover:text-accent-strong"
        >
          {sanitizeText(row.displayId)}
        </button>
      ),
    },
    {
      key: "platform",
      header: "Platform",
      render: (row) => <PlatformBadge platform={row.platform} />,
    },
    { key: "reportCount", header: "Reports", align: "right", sortable: true },
    {
      key: "riskScore",
      header: "Risk",
      align: "right",
      sortable: true,
      render: (row) => (row.riskScore === null ? "—" : row.riskScore.toFixed(1)),
    },
    {
      key: "coverage",
      header: "Coverage",
      align: "right",
      sortable: true,
      render: (row) => (row.coverage === null ? "—" : `${row.coverage.toFixed(1)}%`),
    },
    {
      key: "latestReceivedAt",
      header: "Last report",
      render: (row) => (
        <span className="text-xs text-ink-muted">{sanitizeText(row.latestReceivedAt) || "—"}</span>
      ),
    },
  ];

  const checkColumns: Array<TableColumn<CheckAggregate>> = [
    {
      key: "checkId",
      header: "Check",
      render: (row) => (
        <button
          type="button"
          onClick={() => setActiveCheckId(row.checkId)}
          className="rounded font-mono text-xs text-accent underline decoration-dotted underline-offset-2 hover:text-accent-strong"
        >
          {sanitizeText(row.checkId)}
        </button>
      ),
    },
    { key: "title", header: "Title", render: (row) => sanitizeText(row.title) },
    { key: "severity", header: "Severity", render: (row) => <SeverityBadge severity={row.severity} /> },
    { key: "category", header: "Category", render: (row) => <span className="text-xs text-ink-muted">{sanitizeText(row.category)}</span> },
    {
      key: "hosts",
      header: "Hosts",
      align: "right",
      sortable: true,
      sortValue: (row) => row.hosts.size,
      render: (row) => row.hosts.size,
    },
    { key: "count", header: "Results", align: "right", sortable: true },
  ];

  const tabs: TabItem[] = [
    { value: "findings", label: "All findings", icon: ListChecks },
    { value: "hosts", label: "By Host", icon: Server },
    { value: "checks", label: "By Check", icon: Table2 },
  ];

  const scope = resolveScope(filters);

  return (
    <section aria-label="Findings explorer" className="mx-auto flex max-w-7xl flex-col gap-5">
      <SectionHeader
        eyebrow="Operate"
        title="Findings"
        description="Search, filter, and triage checks across the current scope. Every row opens pinned evidence."
        icon={ListChecks}
        actions={
          <Button variant="secondary" icon={RefreshCw} loading={loading} onClick={refresh}>
            Refresh
          </Button>
        }
      />

      <ScopeControls
        filters={filters}
        onToggle={toggle}
        onClearScope={() => {
          clearScopeKeys(filters);
          setPivot("findings");
        }}
      />

      <Card>
        <CardHeader
          title="Filters"
          description={`${total} result${total === 1 ? "" : "s"} in the ${scope} scope`}
          icon={FileSearch}
          actions={
            chips.length > 0 ? (
              <Button size="sm" variant="ghost" icon={X} onClick={clear}>
                Clear all
              </Button>
            ) : null
          }
        />
        <CardBody className="flex flex-col gap-3">
          <Toolbar label="Findings filters">
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
                aria-label="Search findings"
                icon={Search}
                placeholder="Search titles, IDs, references…"
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
              filterKey="severity"
              options={SEVERITY_OPTIONS}
              filters={filters}
              onToggle={toggle}
            />
            <ToolbarDivider />
            <FilterToggle
              label="Status"
              filterKey="status"
              options={STATUS_OPTIONS}
              filters={filters}
              onToggle={toggle}
            />
            <ToolbarDivider />
            <FilterToggle
              label="Treatment"
              filterKey="treatment"
              options={TREATMENT_OPTIONS}
              filters={filters}
              onToggle={toggle}
            />
            <ToolbarDivider />
            <FilterToggle
              label="Evidence"
              filterKey="evidenceDepth"
              options={DEPTH_OPTIONS}
              filters={filters}
              onToggle={toggle}
            />
            <ToolbarSpacer />
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

      <Tabs
        items={tabs}
        value={pivot}
        onChange={(value) => {
          setPivot(value as Pivot);
          setPage(1);
        }}
        label="Findings pivots"
        idBase="findings-pivots"
      />

      {error ? <InlineAlert>{error}</InlineAlert> : null}

      <TabPanel id="findings" active={pivot === "findings"} idBase="findings-pivots">
        <Card flush className="overflow-hidden">
          {loading && findings.length === 0 ? (
            <div className="flex flex-col gap-2 p-4">
              {Array.from({ length: 8 }).map((_, index) => (
                <Skeleton key={index} height={28} />
              ))}
            </div>
          ) : findings.length === 0 ? (
            <div className="p-4">
              <EmptyState
                title="No findings match the current filters"
                detail="Adjust or clear filters to widen the search."
              />
            </div>
          ) : (
            <Table
              label="Findings matching the current scope and filters"
              columns={findingColumns}
              rows={findings}
              rowKey={(row) => `${row.reportId}:${row.checkId}`}
              stickyHeader
              onRowClick={(row) => void openEvidence(row)}
            />
          )}
        </Card>
        {pivot === "findings" && total > 0 ? (
          <div className="mt-3">
            <Pagination
              page={page}
              pageSize={pageSize}
              total={total}
              pageSizeOptions={PAGE_SIZES}
              onPageChange={setPage}
              onPageSizeChange={(size) => {
                setPageSize(size);
                setPage(1);
              }}
            />
          </div>
        ) : null}
      </TabPanel>

      <TabPanel id="hosts" active={pivot === "hosts"} idBase="findings-pivots">
        <Card flush className="overflow-hidden">
          {loading && hosts.length === 0 ? (
            <div className="flex flex-col gap-2 p-4">
              {Array.from({ length: 6 }).map((_, index) => (
                <Skeleton key={index} height={28} />
              ))}
            </div>
          ) : hosts.length === 0 ? (
            <div className="p-4">
              <EmptyState title="No hosts match the current filters" />
            </div>
          ) : (
            <Table
              label="Hosts matching the current scope and filters"
              caption="Hosts matching the current scope and filters"
              columns={hostColumns}
              rows={hosts}
              rowKey={(row) => String(row.id)}
              stickyHeader
              onRowClick={(row) => {
                toggle("hostId", String(row.id));
                setPivot("findings");
              }}
            />
          )}
        </Card>
        {total > 0 ? (
          <div className="mt-3">
            <Pagination
              page={page}
              pageSize={pageSize}
              total={total}
              pageSizeOptions={PAGE_SIZES}
              onPageChange={setPage}
              onPageSizeChange={(size) => {
                setPageSize(size);
                setPage(1);
              }}
            />
          </div>
        ) : null}
      </TabPanel>

      <TabPanel id="checks" active={pivot === "checks"} idBase="findings-pivots">
        <Card flush className="overflow-hidden">
          {loading && checks.length === 0 ? (
            <div className="flex flex-col gap-2 p-4">
              {Array.from({ length: 6 }).map((_, index) => (
                <Skeleton key={index} height={28} />
              ))}
            </div>
          ) : checks.length === 0 ? (
            <div className="p-4">
              <EmptyState title="No checks match the current filters" />
            </div>
          ) : (
            <Table
              label="Checks matching the current filters"
              caption="Checks matching the current filters"
              columns={checkColumns}
              rows={checks}
              rowKey={(row) => row.checkId}
              stickyHeader
              onRowClick={(row) => setActiveCheckId(row.checkId)}
            />
          )}
        </Card>
        <p className="mt-3 flex items-center gap-2 text-2xs text-ink-subtle">
          <Badge tone="accent" icon={ShieldAlert}>
            By Check
          </Badge>
          Selected checks open the host-by-host breakdown from GET /api/checks/:checkId.
        </p>
      </TabPanel>

      <EvidenceDrawer
        open={evidence !== null}
        finding={evidence?.finding ?? null}
        reportId={evidence?.reportId ?? null}
        hostname={evidence?.hostname ?? null}
        onClose={() => setEvidence(null)}
      />
    </section>
  );
}
