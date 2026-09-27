import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  ArrowUpRight,
  BookOpen,
  RefreshCw,
  ShieldCheck,
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
  Skeleton,
  Stat,
  Table,
  type ProgressTone,
  type TableColumn,
} from "../components/ui";
import { serializeFilters } from "../filters";
import type { RouteKey } from "../routes";

type StandardRow = {
  standard: string;
  total: number;
  compliant: number;
  nonCompliant: number;
  decided: number;
  coverage: number;
};

type ReferenceRow = {
  reference: string;
  total: number;
  compliant: number;
  nonCompliant: number;
};

type StandardsResponse = {
  standards: StandardRow[];
  references: ReferenceRow[];
  total: number;
};

export type StandardsProps = {
  /** Publish a canonical findings query and route to Findings. */
  onDrilldown: (query: string) => void;
  /** Optional navigation handler for the empty-state CTA. */
  onNavigate?: (route: RouteKey) => void;
};

const STANDARD_META: Record<string, { title: string; detail: string }> = {
  CIS: { title: "CIS Benchmarks", detail: "Center for Internet Security hardened configuration baselines." },
  NIST: { title: "NIST SP 800-53", detail: "Security and privacy controls for federal information systems." },
  ISO: { title: "ISO/IEC 27001", detail: "Information security management system controls (Annex A)." },
  PCI: { title: "PCI-DSS", detail: "Payment Card Industry Data Security Standard requirements." },
  HIPAA: { title: "HIPAA", detail: "Health Insurance Portability and Accountability Act safeguards." },
  SOC2: { title: "SOC 2", detail: "Trust Services Criteria for service organisations." },
  GDPR: { title: "GDPR", detail: "EU General Data Protection Regulation obligations." },
  STIG: { title: "DISA STIG", detail: "Security Technical Implementation Guides." },
  CMMC: { title: "CMMC", detail: "Cybersecurity Maturity Model Certification practices." },
};

function coverageTone(coverage: number): ProgressTone {
  if (coverage >= 90) return "compliant";
  if (coverage >= 70) return "accent";
  if (coverage >= 40) return "degraded";
  return "critical";
}

function standardTitle(standard: string): { title: string; detail: string } {
  return (
    STANDARD_META[standard.toUpperCase()] ?? {
      title: standard,
      detail: "Custom reference group discovered from scan results.",
    }
  );
}

/**
 * Standards coverage: how the scanned checks map onto CIS / NIST 800-53 /
 * ISO 27001 / PCI-DSS (and any other reference in the corpus), with a
 * drill-down into the matching findings.
 */
export function Standards({ onDrilldown, onNavigate }: StandardsProps) {
  const [data, setData] = useState<StandardsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(null);
    api
      .raw<StandardsResponse>("GET", "/api/standards")
      .then((value) => {
        if (alive) setData(value);
      })
      .catch((err) => {
        if (alive) setError(err instanceof ApiError ? err.message : "Failed to load standards coverage");
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [reloadKey]);

  const refresh = useCallback(() => setReloadKey((value) => value + 1), []);

  const standards = useMemo(
    () => [...(data?.standards ?? [])].sort((a, b) => b.total - a.total || a.standard.localeCompare(b.standard)),
    [data],
  );

  const referenceColumns = useMemo<Array<TableColumn<ReferenceRow>>>(
    () => [
      {
        key: "reference",
        header: "Reference",
        sortable: true,
        render: (row) => <span className="font-mono text-xs text-ink">{row.reference}</span>,
      },
      { key: "total", header: "Checks", align: "right", sortable: true, width: "6rem" },
      { key: "compliant", header: "Compliant", align: "right", sortable: true, width: "7rem" },
      { key: "nonCompliant", header: "Non-compliant", align: "right", sortable: true, width: "8.5rem" },
      {
        key: "coverage",
        header: "Decided",
        align: "right",
        width: "9rem",
        sortValue: (row) => (row.total > 0 ? (row.compliant + row.nonCompliant) / row.total : 0),
        render: (row) => {
          const decided = row.total > 0 ? ((row.compliant + row.nonCompliant) / row.total) * 100 : 0;
          return (
            <div className="flex items-center justify-end gap-2">
              <div className="w-20">
                <ProgressBar value={decided} tone={coverageTone(decided)} />
              </div>
              <span className="w-10 text-right">{decided.toFixed(0)}%</span>
            </div>
          );
        },
      },
    ],
    [],
  );

  const header = (
    <SectionHeader
      eyebrow="Analyze"
      title="Standards"
      description="Coverage of scanned checks against CIS, NIST 800-53, ISO 27001, and PCI-DSS references."
      icon={BookOpen}
      actions={
        <Button variant="secondary" icon={RefreshCw} loading={loading} onClick={refresh}>
          Refresh
        </Button>
      }
    />
  );

  if (error && !data) {
    return (
      <section className="mx-auto flex max-w-7xl flex-col gap-6">
        {header}
        <EmptyState
          icon={AlertTriangle}
          title="Could not load standards coverage"
          detail={error}
          action={
            <Button variant="secondary" icon={RefreshCw} onClick={refresh}>
              Try again
            </Button>
          }
        />
      </section>
    );
  }

  return (
    <section aria-label="Standards coverage" className="mx-auto flex max-w-7xl flex-col gap-6">
      {header}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <Stat
          label="Standards"
          value={loading && !data ? "-" : standards.length}
          icon={ShieldCheck}
          hint="Reference families in scope"
        />
        <Stat
          label="References"
          value={loading && !data ? "-" : data?.references.length ?? 0}
          icon={BookOpen}
          hint="Distinct control references"
        />
        <Stat
          label="Checks evaluated"
          value={loading && !data ? "-" : data?.total ?? 0}
          icon={ShieldCheck}
          hint="Results contributing to coverage"
        />
      </div>

      {loading && !data ? (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
          {Array.from({ length: 4 }).map((_, index) => (
            <Card key={index}>
              <Skeleton width="55%" />
              <Skeleton className="mt-3" width="80%" height={28} />
              <Skeleton className="mt-3" width="100%" />
            </Card>
          ))}
        </div>
      ) : standards.length === 0 ? (
        <EmptyState
          title="No standards references found"
          detail="Ingest reports that include CIS, NIST, ISO, or PCI references to map coverage."
          action={
            onNavigate ? (
              <Button variant="secondary" onClick={() => onNavigate("campaigns")}>
                Go to campaigns
              </Button>
            ) : undefined
          }
        />
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
          {standards.map((row) => {
            const meta = standardTitle(row.standard);
            const coverage = row.coverage;
            return (
              <Card key={row.standard} className="flex flex-col">
                <CardHeader
                  icon={ShieldCheck}
                  title={meta.title}
                  description={meta.detail}
                />
                <CardBody className="flex flex-1 flex-col">
                  <div className="flex items-end justify-between gap-2">
                    <span
                      className={
                        coverage >= 90
                          ? "text-2xl font-semibold tabular-nums text-compliant"
                          : coverage >= 70
                            ? "text-2xl font-semibold tabular-nums text-accent"
                            : coverage >= 40
                              ? "text-2xl font-semibold tabular-nums text-degraded"
                              : "text-2xl font-semibold tabular-nums text-critical"
                      }
                    >
                      {coverage.toFixed(1)}%
                    </span>
                    <span className="text-2xs text-ink-subtle">decided</span>
                  </div>
                  <div className="mt-3">
                    <ProgressBar value={coverage} tone={coverageTone(coverage)} />
                  </div>
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    <Badge tone="compliant">{row.compliant} compliant</Badge>
                    <Badge tone={row.nonCompliant > 0 ? "noncompliant" : "na"}>
                      {row.nonCompliant} failing
                    </Badge>
                    <Badge tone="neutral">{row.total} checks</Badge>
                  </div>
                  <div className="mt-4 flex-1" />
                  <Button
                    variant="ghost"
                    size="sm"
                    iconRight={ArrowUpRight}
                    className="self-start"
                    onClick={() => onDrilldown(serializeFilters({ standard: [row.standard] }))}
                  >
                    View findings
                  </Button>
                </CardBody>
              </Card>
            );
          })}
        </div>
      )}

      <Card flush className="overflow-hidden">
        <div className="p-4">
          <CardHeader
            title="Reference detail"
            description="Every control reference discovered in the scanned results. Select a row to filter findings."
            icon={BookOpen}
            actions={
              <Badge tone="accent">{data?.references.length ?? 0} references</Badge>
            }
          />
        </div>
        <Table
          label="Standards references"
          columns={referenceColumns}
          rows={data?.references ?? []}
          rowKey={(row) => row.reference}
          defaultSort={{ key: "total", direction: "desc" }}
          stickyHeader
          onRowClick={(row) => onDrilldown(serializeFilters({ standard: [row.reference] }))}
          empty={loading ? "Loading references…" : "No references in scope."}
        />
      </Card>
    </section>
  );
}
