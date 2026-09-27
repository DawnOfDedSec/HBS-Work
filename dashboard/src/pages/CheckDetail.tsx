import { useEffect, useState } from "react";
import { AlertTriangle, ArrowLeft, ListChecks, RefreshCw, Users } from "lucide-react";
import { api, ApiError } from "../api";
import {
  Badge,
  Button,
  Card,
  CardHeader,
  EmptyState,
  SectionHeader,
  Skeleton,
  Stat,
  Table,
  type TableColumn,
  useToast,
} from "../components/ui";
import { SeverityBadge, StatusBadge, TreatmentBadge } from "../components/badges";
import { sanitizeText } from "../components/EvidenceDrawer";
import { TREATMENT_STATES } from "./Treatment";

/** `GET /api/checks/:checkId` (the By Check pivot). */
type CheckHost = {
  hostId: number;
  hostname: string;
  displayId: string;
  status: string;
  severity: string;
  category: string;
  reportId: number;
  receivedAt: string;
  treatment: string;
  links: Record<string, string>;
};

type CheckDetailResponse = {
  checkId: string;
  total: number;
  statusCounts: Record<string, number>;
  hosts: CheckHost[];
};

export type CheckDetailProps = {
  checkId: string;
  onBack?: () => void;
  onOpenReport?: (reportId: number) => void;
};

const STATE_LABEL: Record<string, string> = {
  open: "Open",
  accepted_risk: "Accepted risk",
  false_positive: "False positive",
  remediated: "Remediated",
};

export function CheckDetail({ checkId, onBack, onOpenReport }: CheckDetailProps) {
  const [data, setData] = useState<CheckDetailResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const toast = useToast();

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(null);
    api
      .raw<CheckDetailResponse>("GET", `/api/checks/${encodeURIComponent(checkId)}`)
      .then((value) => {
        if (alive) setData(value);
      })
      .catch((err) => {
        if (!alive) return;
        const message = err instanceof ApiError ? err.message : "Request failed. Please retry.";
        setError(message);
        toast.error("Could not load check", { description: message });
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [checkId, reloadKey, toast]);

  const hosts = Array.isArray(data?.hosts) ? data.hosts : [];
  const statusCounts = data?.statusCounts ?? {};

  const columns: Array<TableColumn<CheckHost>> = [
    {
      key: "displayId",
      header: "Host",
      render: (row) => <span className="text-ink">{sanitizeText(row.displayId)}</span>,
    },
    { key: "status", header: "Status", render: (row) => <StatusBadge status={row.status} /> },
    { key: "severity", header: "Severity", render: (row) => <SeverityBadge severity={row.severity} /> },
    {
      key: "category",
      header: "Category",
      render: (row) => <span className="text-xs text-ink-muted">{sanitizeText(row.category)}</span>,
    },
    {
      key: "treatment",
      header: "Treatment",
      render: (row) => <TreatmentBadge state={row.treatment} />,
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
      render: (row) =>
        onOpenReport ? (
          <Button size="sm" variant="secondary" onClick={() => onOpenReport(row.reportId)}>
            Open #{row.reportId}
          </Button>
        ) : (
          <span className="text-2xs text-ink-subtle">-</span>
        ),
    },
  ];

  return (
    <section aria-label={`Check ${checkId}`} className="mx-auto flex max-w-7xl flex-col gap-5">
      <SectionHeader
        eyebrow="By Check"
        title={<span className="font-mono">{sanitizeText(checkId)}</span>}
        description={
          data
            ? `${data.total} host result${data.total === 1 ? "" : "s"} across the current scope.`
            : "Host-by-host breakdown for this check."
        }
        icon={ListChecks}
        actions={
          <>
            {onBack ? (
              <Button variant="ghost" icon={ArrowLeft} onClick={onBack}>
                Back
              </Button>
            ) : null}
            <Button variant="secondary" icon={RefreshCw} loading={loading} onClick={() => setReloadKey((key) => key + 1)}>
              Refresh
            </Button>
          </>
        }
      />

      {error && !data ? (
        <EmptyState
          icon={AlertTriangle}
          title="Could not load check"
          detail={error}
          action={
            <Button variant="secondary" icon={RefreshCw} onClick={() => setReloadKey((key) => key + 1)}>
              Try again
            </Button>
          }
        />
      ) : loading && !data ? (
        <Card>
          <Skeleton width="40%" />
          <Skeleton className="mt-3" width="70%" height={28} />
        </Card>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            {TREATMENT_STATES.map((state) => (
              <Stat
                key={state}
                label={STATE_LABEL[state] ?? state}
                value={statusCounts[state] ?? 0}
                icon={state === "remediated" ? Users : undefined}
                tone={state === "false_positive" ? "default" : state === "accepted_risk" ? "high" : state === "remediated" ? "ok" : "accent"}
              />
            ))}
          </div>

          <Card flush className="overflow-hidden">
            <div className="p-4">
              <CardHeader
                title="Hosts reporting this check"
                description="Each row is one host's latest result for the check in scope."
                icon={Users}
                actions={<Badge tone="accent">{hosts.length} hosts</Badge>}
              />
            </div>
            {hosts.length === 0 ? (
              <div className="p-4">
                <EmptyState title="No hosts currently report this check" />
              </div>
            ) : (
              <Table
                label="Hosts reporting this check"
                columns={columns}
                rows={hosts}
                rowKey={(row) => `${row.hostId}:${row.reportId}`}
                stickyHeader
              />
            )}
          </Card>
        </>
      )}
    </section>
  );
}
