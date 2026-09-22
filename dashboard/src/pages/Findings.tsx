import { useEffect, useMemo, useState } from "react";
import { Search, X } from "lucide-react";
import { api, ApiError } from "../api";
import { EmptyState } from "../components/EmptyState";
import {
  EvidenceDrawer,
  sanitizeText,
  type EvidenceFinding,
} from "../components/EvidenceDrawer";
import { resolveScope, serializeFilters, type FilterKey, type ScopeFilters } from "../filters";
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

const SEVERITY_TONE: Record<string, string> = {
  Critical: "text-red-300",
  High: "text-amber-300",
  Medium: "text-yellow-200",
  Low: "text-sky-300",
  Informational: "text-slate-300",
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

function ToggleGroup({
  label,
  keyName,
  options,
  filters,
  onToggle,
}: {
  label: string;
  keyName: FilterKey;
  options: string[];
  filters: ScopeFilters;
  onToggle: (key: FilterKey, value: string) => void;
}) {
  const active = new Set(filters[keyName] ?? []);
  return (
    <fieldset className="flex flex-wrap items-center gap-1">
      <legend className="sr-only">{label}</legend>
      <span className="mr-1 text-xs uppercase tracking-wide text-slate-500">{label}</span>
      {options.map((option) => {
        const on = active.has(option);
        return (
          <button
            key={option}
            type="button"
            aria-pressed={on}
            onClick={() => onToggle(keyName, option)}
            className={`rounded-full border px-2 py-0.5 text-xs focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 ${
              on
                ? "border-sky-400 bg-sky-500/20 text-sky-100"
                : "border-slate-700 text-slate-300 hover:bg-slate-800"
            }`}
          >
            {option}
          </button>
        );
      })}
    </fieldset>
  );
}

/**
 * Atomically drop the scope keys (`scope`, `reportId`, `from`, `to`) and make
 * the URL-backed filter hook re-parse. Clearing them one-by-one would race
 * because each commit reads the same captured filter state.
 */
function clearScopeKeys(filters: ScopeFilters): void {
  const next: ScopeFilters = { ...filters };
  delete next.scope;
  delete next.reportId;
  delete next.from;
  delete next.to;
  const query = serializeFilters(next);
  const url = query ? `${window.location.pathname}?${query}` : window.location.pathname;
  window.history.pushState({}, "", url);
  window.dispatchEvent(new PopStateEvent("popstate"));
}

function ScopeControls({
  filters,
  onToggle,
  onLatest,
}: {
  filters: ScopeFilters;
  onToggle: (key: FilterKey, value: string) => void;
  onLatest: () => void;
}) {
  const scope = resolveScope(filters);
  return (
    <fieldset className="flex flex-wrap items-end gap-4 rounded-lg border border-slate-800 p-3">
      <legend className="px-1 text-xs uppercase tracking-wide text-slate-400">Scope</legend>
      <label className="flex items-center gap-2 text-sm">
        <input type="radio" name="findings-scope" checked={scope === "latest"} onChange={onLatest} />
        Latest state
      </label>
      <label className="flex items-center gap-2 text-sm">
        <input
          type="radio"
          name="findings-scope"
          checked={scope === "report"}
          onChange={() => onToggle("scope", "report")}
        />
        Single report
      </label>
      <label className="flex items-center gap-2 text-sm">
        <input
          type="radio"
          name="findings-scope"
          checked={scope === "range"}
          onChange={() => onToggle("scope", "range")}
        />
        Date range
      </label>
      {scope === "report" ? (
        <label className="flex items-center gap-2 text-sm">
          Report ID
          <input
            type="number"
            min={1}
            value={filters.reportId?.[0] ?? ""}
            onChange={(event) => event.target.value && onToggle("reportId", event.target.value)}
            className="w-28 rounded border border-slate-700 bg-slate-900 px-2 py-1"
          />
        </label>
      ) : null}
      {scope === "range" ? (
        <>
          <label className="flex items-center gap-2 text-sm">
            From
            <input
              type="datetime-local"
              value={filters.from?.[0] ?? ""}
              onChange={(event) => event.target.value && onToggle("from", event.target.value)}
              className="rounded border border-slate-700 bg-slate-900 px-2 py-1"
            />
          </label>
          <label className="flex items-center gap-2 text-sm">
            To
            <input
              type="datetime-local"
              value={filters.to?.[0] ?? ""}
              onChange={(event) => event.target.value && onToggle("to", event.target.value)}
              className="rounded border border-slate-700 bg-slate-900 px-2 py-1"
            />
          </label>
        </>
      ) : null}
    </fieldset>
  );
}

/**
 * Scope-aware findings explorer. The filter bar is bound to `useScopeFilters`
 * so the URL query string stays the single source of truth; scope selection
 * precedes the By Host / By Check pivots.
 */
export function Findings() {
  const { filters, query, chips, toggle, clearKey, clear } = useScopeFilters();
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
        if (alive) setError(errorMessage(err));
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [query, page, pageSize, pivot]);

  const checks = useMemo(() => {
    const grouped = new Map<string, { checkId: string; title: string; severity: string; category: string; count: number; hosts: Set<number> }>();
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

  async function openEvidence(finding: Finding) {
    const key = `${finding.reportId}:${finding.checkId}`;
    setPendingRow(key);
    try {
      const report = await api.raw<ReportResponse>("GET", `/api/reports/${finding.reportId}`);
      const result = (report.results ?? []).find((entry) => entry.id === finding.checkId);
      if (!result) {
        setError(`Finding ${finding.checkId} is no longer present in report #${finding.reportId}.`);
        return;
      }
      setEvidence({
        finding: toEvidence(result),
        reportId: finding.reportId,
        hostname: report.hostname ?? finding.hostname,
      });
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setPendingRow(null);
    }
  }

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

  const totalPages = Math.max(1, Math.ceil(total / (pivot === "checks" ? 200 : pageSize)));

  return (
    <section aria-label="Findings explorer" className="space-y-4">
      <ScopeControls filters={filters} onToggle={toggle} onLatest={() => clearScopeKeys(filters)} />

      <div className="space-y-3 rounded-lg border border-slate-800 p-3">
        <div className="flex flex-wrap items-center gap-3">
          <form
            className="flex items-center gap-2"
            role="search"
            onSubmit={(event) => {
              event.preventDefault();
              const value = search.trim();
              if (value) toggle("q", value);
              else clearKey("q");
            }}
          >
            <label className="sr-only" htmlFor="findings-search">
              Search findings
            </label>
            <div className="flex items-center gap-1 rounded border border-slate-700 bg-slate-900 px-2">
              <Search size={14} aria-hidden className="text-slate-500" />
              <input
                id="findings-search"
                type="search"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Search titles, IDs, references…"
                className="w-64 bg-transparent py-1 text-sm focus:outline-none"
              />
            </div>
            <button
              type="submit"
              className="rounded border border-slate-700 px-2 py-1 text-sm hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
            >
              Apply
            </button>
          </form>
          <span className="text-xs text-slate-500">
            {loading ? "Loading…" : `${total} result${total === 1 ? "" : "s"}`}
          </span>
        </div>

        <ToggleGroup label="Severity" keyName="severity" options={SEVERITY_OPTIONS} filters={filters} onToggle={toggle} />
        <ToggleGroup label="Status" keyName="status" options={STATUS_OPTIONS} filters={filters} onToggle={toggle} />
        <ToggleGroup
          label="Treatment"
          keyName="treatment"
          options={TREATMENT_OPTIONS}
          filters={filters}
          onToggle={toggle}
        />
        <ToggleGroup
          label="Evidence depth"
          keyName="evidenceDepth"
          options={DEPTH_OPTIONS}
          filters={filters}
          onToggle={toggle}
        />

        {chips.length > 0 ? (
          <div className="flex flex-wrap items-center gap-2" aria-label="Active filters">
            {chips.map((chip) => (
              <span
                key={`${chip.key}:${chip.value}`}
                className="flex items-center gap-1 rounded-full border border-sky-500/50 bg-sky-500/10 px-2 py-0.5 text-xs text-sky-100"
              >
                <span className="text-sky-300/80">{chip.key}:</span>
                {chip.value}
                <button
                  type="button"
                  aria-label={`Remove filter ${chip.key} ${chip.value}`}
                  onClick={() => toggle(chip.key, chip.value)}
                  className="rounded-full p-0.5 hover:bg-sky-500/30 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-300"
                >
                  <X size={12} aria-hidden />
                </button>
              </span>
            ))}
            <button
              type="button"
              onClick={clear}
              className="rounded border border-slate-600 px-2 py-0.5 text-xs hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
            >
              Clear all
            </button>
          </div>
        ) : null}
      </div>

      <div role="tablist" aria-label="Findings pivots" className="flex flex-wrap gap-1 border-b border-slate-800">
        {(["findings", "hosts", "checks"] as const).map((value) => (
          <button
            key={value}
            role="tab"
            type="button"
            aria-selected={pivot === value}
            onClick={() => {
              setPivot(value);
              setPage(1);
            }}
            className={`px-3 py-2 text-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 ${
              pivot === value ? "border-b-2 border-sky-400 text-sky-200" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            {value === "findings" ? "All findings" : value === "hosts" ? "By Host" : "By Check"}
          </button>
        ))}
      </div>

      {error ? (
        <EmptyState title="Could not load findings" detail={error} />
      ) : loading && findings.length === 0 && hosts.length === 0 ? (
        <p role="status" className="p-4 text-sm text-slate-400">
          Loading findings…
        </p>
      ) : pivot === "hosts" ? (
        hosts.length === 0 ? (
          <EmptyState title="No hosts match the current filters" />
        ) : (
          <HostTable hosts={hosts} onFilterHost={(id) => { toggle("hostId", String(id)); setPivot("findings"); }} />
        )
      ) : pivot === "checks" ? (
        checks.length === 0 ? (
          <EmptyState title="No checks match the current filters" />
        ) : (
          <table className="w-full border-collapse text-sm">
            <caption className="sr-only">Checks matching the current filters</caption>
            <thead>
              <tr className="text-left text-slate-400">
                <th scope="col" className="border-b border-slate-800 py-2 pr-3">Check</th>
                <th scope="col" className="border-b border-slate-800 py-2 pr-3">Title</th>
                <th scope="col" className="border-b border-slate-800 py-2 pr-3">Severity</th>
                <th scope="col" className="border-b border-slate-800 py-2 pr-3">Hosts</th>
                <th scope="col" className="border-b border-slate-800 py-2">Results</th>
              </tr>
            </thead>
            <tbody>
              {checks.map((check) => (
                <tr key={check.checkId} className="align-top">
                  <td className="border-b border-slate-900 py-2 pr-3">
                    <button
                      type="button"
                      onClick={() => setActiveCheckId(check.checkId)}
                      className="font-mono text-sky-300 underline underline-offset-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
                    >
                      {check.checkId}
                    </button>
                  </td>
                  <td className="border-b border-slate-900 py-2 pr-3">{sanitizeText(check.title)}</td>
                  <td className={`border-b border-slate-900 py-2 pr-3 ${SEVERITY_TONE[check.severity] ?? ""}`}>
                    {sanitizeText(check.severity)}
                  </td>
                  <td className="border-b border-slate-900 py-2 pr-3 tabular-nums">{check.hosts.size}</td>
                  <td className="border-b border-slate-900 py-2 tabular-nums">{check.count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )
      ) : findings.length === 0 ? (
        <EmptyState title="No findings match the current filters" detail="Adjust or clear filters to widen the search." />
      ) : (
        <FindingsTable
          findings={findings}
          pendingRow={pendingRow}
          onOpenEvidence={openEvidence}
          onOpenCheck={setActiveCheckId}
          onOpenReport={setActiveReportId}
          onFilterHost={(id) => toggle("hostId", String(id))}
        />
      )}

      {pivot !== "checks" && totalPages > 1 ? (
        <nav aria-label="Pagination" className="flex items-center justify-between gap-3 text-sm">
          <button
            type="button"
            disabled={page <= 1}
            onClick={() => setPage((value) => Math.max(1, value - 1))}
            className="rounded border border-slate-700 px-2 py-1 disabled:opacity-40 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
          >
            Previous
          </button>
          <span aria-live="polite" className="text-slate-400">
            Page {page} of {totalPages}
          </span>
          <div className="flex items-center gap-2">
            <label className="flex items-center gap-1 text-xs text-slate-400">
              Rows
              <select
                value={pageSize}
                onChange={(event) => {
                  setPageSize(Number(event.target.value));
                  setPage(1);
                }}
                className="rounded border border-slate-700 bg-slate-900 px-1 py-0.5"
              >
                {PAGE_SIZES.map((size) => (
                  <option key={size} value={size}>
                    {size}
                  </option>
                ))}
              </select>
            </label>
            <button
              type="button"
              disabled={page >= totalPages}
              onClick={() => setPage((value) => Math.min(totalPages, value + 1))}
              className="rounded border border-slate-700 px-2 py-1 disabled:opacity-40 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
            >
              Next
            </button>
          </div>
        </nav>
      ) : null}

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

function FindingsTable({
  findings,
  pendingRow,
  onOpenEvidence,
  onOpenCheck,
  onOpenReport,
  onFilterHost,
}: {
  findings: Finding[];
  pendingRow: string | null;
  onOpenEvidence: (finding: Finding) => void;
  onOpenCheck: (checkId: string) => void;
  onOpenReport: (reportId: number) => void;
  onFilterHost: (hostId: number) => void;
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-sm">
        <caption className="sr-only">Findings matching the current scope and filters</caption>
        <thead>
          <tr className="text-left text-slate-400">
            <th scope="col" className="border-b border-slate-800 py-2 pr-3">Check</th>
            <th scope="col" className="border-b border-slate-800 py-2 pr-3">Title</th>
            <th scope="col" className="border-b border-slate-800 py-2 pr-3">Host</th>
            <th scope="col" className="border-b border-slate-800 py-2 pr-3">Severity</th>
            <th scope="col" className="border-b border-slate-800 py-2 pr-3">Status</th>
            <th scope="col" className="border-b border-slate-800 py-2 pr-3">Treatment</th>
            <th scope="col" className="border-b border-slate-800 py-2">Evidence</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((finding) => {
            const key = `${finding.reportId}:${finding.checkId}`;
            return (
              <tr
                key={key}
                onClick={() => void onOpenEvidence(finding)}
                className="cursor-pointer align-top hover:bg-slate-800/40"
              >
                <td className="border-b border-slate-900 py-2 pr-3">
                  <button
                    type="button"
                    onClick={(event) => {
                      event.stopPropagation();
                      onOpenCheck(finding.checkId);
                    }}
                    className="font-mono text-sky-300 underline underline-offset-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
                  >
                    {sanitizeText(finding.checkId)}
                  </button>
                </td>
                <td className="border-b border-slate-900 py-2 pr-3">{sanitizeText(finding.title)}</td>
                <td className="border-b border-slate-900 py-2 pr-3">
                  <button
                    type="button"
                    onClick={(event) => {
                      event.stopPropagation();
                      onFilterHost(finding.hostId);
                    }}
                    className="text-left text-slate-200 underline decoration-dotted underline-offset-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
                  >
                    {sanitizeText(finding.displayId)}
                  </button>
                </td>
                <td className={`border-b border-slate-900 py-2 pr-3 ${SEVERITY_TONE[finding.severity] ?? ""}`}>
                  {sanitizeText(finding.severity)}
                </td>
                <td className="border-b border-slate-900 py-2 pr-3">{sanitizeText(finding.status)}</td>
                <td className="border-b border-slate-900 py-2 pr-3">{sanitizeText(finding.treatment)}</td>
                <td className="border-b border-slate-900 py-2">
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={(event) => {
                        event.stopPropagation();
                        void onOpenEvidence(finding);
                      }}
                      className="rounded border border-slate-700 px-2 py-0.5 text-xs hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
                    >
                      {pendingRow === key ? "Opening…" : "View"}
                    </button>
                    <button
                      type="button"
                      onClick={(event) => {
                        event.stopPropagation();
                        onOpenReport(finding.reportId);
                      }}
                      className="rounded border border-slate-700 px-2 py-0.5 text-xs hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
                    >
                      Report
                    </button>
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function HostTable({ hosts, onFilterHost }: { hosts: HostGroup[]; onFilterHost: (hostId: number) => void }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-sm">
        <caption className="sr-only">Hosts matching the current scope and filters</caption>
        <thead>
          <tr className="text-left text-slate-400">
            <th scope="col" className="border-b border-slate-800 py-2 pr-3">Host</th>
            <th scope="col" className="border-b border-slate-800 py-2 pr-3">Platform</th>
            <th scope="col" className="border-b border-slate-800 py-2 pr-3">Reports</th>
            <th scope="col" className="border-b border-slate-800 py-2 pr-3">Risk</th>
            <th scope="col" className="border-b border-slate-800 py-2 pr-3">Coverage</th>
            <th scope="col" className="border-b border-slate-800 py-2">Last seen</th>
          </tr>
        </thead>
        <tbody>
          {hosts.map((host) => (
            <tr key={host.id} className="align-top">
              <td className="border-b border-slate-900 py-2 pr-3">
                <button
                  type="button"
                  onClick={() => onFilterHost(host.id)}
                  className="text-left text-sky-300 underline underline-offset-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
                >
                  {sanitizeText(host.displayId)}
                </button>
              </td>
              <td className="border-b border-slate-900 py-2 pr-3">
                {sanitizeText([host.platform, host.os, host.arch].filter(Boolean).join(" · ")) || "—"}
              </td>
              <td className="border-b border-slate-900 py-2 pr-3 tabular-nums">{host.reportCount}</td>
              <td className="border-b border-slate-900 py-2 pr-3 tabular-nums">
                {host.riskScore === null ? "—" : host.riskScore.toFixed(1)}
              </td>
              <td className="border-b border-slate-900 py-2 pr-3 tabular-nums">
                {host.coverage === null ? "—" : `${host.coverage.toFixed(1)}%`}
              </td>
              <td className="border-b border-slate-900 py-2">{sanitizeText(host.latestReceivedAt) || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
