import { useCallback, useEffect, useMemo, useState } from "react";
import { AlertTriangle, RefreshCw, ScrollText, Search } from "lucide-react";
import { api, ApiError } from "../../api";
import {
  Badge,
  Button,
  Card,
  CardHeader,
  EmptyState,
  Input,
  Pagination,
  SectionHeader,
  Select,
  Skeleton,
  Table,
  Toolbar,
  ToolbarGroup,
  ToolbarSpacer,
  type TableColumn,
  useToast,
} from "../../components/ui";
import { sanitizeText } from "../../components/EvidenceDrawer";
import { AdminGate, useAdminRole, type AdminRole } from "./Users";

/** `GET /api/admin/audit` → `{ total, limit, offset, events }`. */
type AuditEntry = {
  id: number;
  actor: string | null;
  actorIp: string | null;
  action: string;
  resource: string | null;
  details: string | null;
  createdAt: string;
};

type AuditResponse = { total: number; limit: number; offset: number; events: AuditEntry[] };

function errorMessage(error: unknown): string {
  return error instanceof ApiError ? error.message : "Request failed. Please retry.";
}

/**
 * Append-only audit log explorer. The server exposes limit/offset paging and an
 * exact `action` filter; free-text search filters the loaded page.
 */
export function Audit({ role: providedRole }: { role?: AdminRole | null } = {}) {
  const { role, loading: roleLoading, error: roleError } = useAdminRole(providedRole);
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(100);
  const [action, setAction] = useState("");
  const [actions, setActions] = useState<string[]>([]);
  const [search, setSearch] = useState("");
  const [applied, setApplied] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const toast = useToast();

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams({
        limit: String(pageSize),
        offset: String((page - 1) * pageSize),
      });
      if (action) params.set("action", action);
      const response = await api.raw<AuditResponse>("GET", `/api/admin/audit?${params.toString()}`);
      const rows = Array.isArray(response.events) ? response.events : [];
      setEntries(rows);
      setTotal(typeof response.total === "number" ? response.total : rows.length);
      setActions((current) => [...new Set([...current, ...rows.map((row) => row.action)])].sort());
    } catch (err) {
      const message = errorMessage(err);
      setError(message);
      toast.error("Could not load the audit log", { description: message });
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, action, toast]);

  useEffect(() => {
    if (role === "super_admin") void load();
  }, [role, load]);

  const visible = useMemo(() => {
    const term = applied.trim().toLowerCase();
    if (!term) return entries;
    return entries.filter((entry) =>
      [entry.actor ?? "", entry.action, entry.resource ?? "", entry.details ?? "", entry.actorIp ?? ""]
        .join("\n")
        .toLowerCase()
        .includes(term),
    );
  }, [entries, applied]);

  const columns: Array<TableColumn<AuditEntry>> = [
    {
      key: "createdAt",
      header: "When",
      sortable: true,
      render: (entry) => <span className="text-xs text-ink-muted">{sanitizeText(entry.createdAt)}</span>,
    },
    {
      key: "actor",
      header: "Actor",
      render: (entry) => (
        <div className="flex flex-col gap-0.5">
          <span className="text-ink">{sanitizeText(entry.actor) || "-"}</span>
          {entry.actorIp ? <span className="text-2xs text-ink-subtle">{sanitizeText(entry.actorIp)}</span> : null}
        </div>
      ),
    },
    {
      key: "action",
      header: "Action",
      render: (entry) => <Badge tone="accent">{sanitizeText(entry.action)}</Badge>,
    },
    {
      key: "resource",
      header: "Resource",
      render: (entry) => (
        <span className="break-all font-mono text-2xs text-ink-muted">{sanitizeText(entry.resource) || "-"}</span>
      ),
    },
    {
      key: "details",
      header: "Details",
      render: (entry) => (
        <span className="break-words font-mono text-2xs text-ink-subtle">{sanitizeText(entry.details) || "-"}</span>
      ),
    },
  ];

  return (
    <AdminGate role={role} loading={roleLoading} error={roleError} allow={["super_admin"]}>
      <section aria-label="Audit log" className="flex flex-col gap-5">
        <SectionHeader
          eyebrow="Govern"
          title="Audit log"
          description="Append-only record of every privileged action: actors, resources, and redacted details."
          icon={ScrollText}
          actions={
            <Button variant="secondary" icon={RefreshCw} loading={loading} onClick={() => void load()}>
              Refresh
            </Button>
          }
        />

        {error ? (
          <div
            role="alert"
            className="flex items-start gap-2 rounded-control border border-critical/40 bg-critical-soft/60 p-3 text-sm text-critical"
          >
            <AlertTriangle size={16} aria-hidden className="mt-0.5 shrink-0" />
            <span>{error}</span>
          </div>
        ) : null}

        <Toolbar label="Audit filters">
          <ToolbarGroup>
            <form
              role="search"
              className="flex items-center gap-2"
              onSubmit={(event) => {
                event.preventDefault();
                setApplied(search.trim());
              }}
            >
              <Input
                type="search"
                aria-label="Search audit entries"
                icon={Search}
                placeholder="Search actor, resource, details…"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                containerClassName="w-72"
              />
              <Button size="sm" variant="secondary" type="submit">
                Search
              </Button>
            </form>
          </ToolbarGroup>
          <ToolbarGroup>
            <Select
              aria-label="Filter by action"
              value={action}
              onChange={(value) => {
                setAction(value);
                setPage(1);
              }}
              options={[
                { value: "", label: "All actions" },
                ...actions.map((item) => ({ value: item, label: item })),
              ]}
              className="w-56"
            />
          </ToolbarGroup>
          <ToolbarSpacer />
          <Badge tone="accent">
            {applied ? `${visible.length} of ${entries.length} on page` : `${total} entries`}
          </Badge>
        </Toolbar>

        <Card flush className="overflow-hidden">
          <div className="p-4">
            <CardHeader
              icon={ScrollText}
              title="Audit events"
              description="Newest first. Details are redacted server-side before they reach the console."
            />
          </div>
          {loading && entries.length === 0 ? (
            <div className="flex flex-col gap-2 p-4">
              {Array.from({ length: 6 }).map((_, index) => (
                <Skeleton key={index} height={30} />
              ))}
            </div>
          ) : visible.length === 0 ? (
            <div className="p-4">
              <EmptyState
                title={applied ? "No audit entries match your search" : "No audit entries yet"}
                detail={applied ? "Clear the search to see every loaded entry." : undefined}
              />
            </div>
          ) : (
            <Table label="Audit log entries" columns={columns} rows={visible} rowKey={(row) => String(row.id)} stickyHeader />
          )}
        </Card>

        {total > 0 ? (
          <Pagination
            page={page}
            pageSize={pageSize}
            total={total}
            pageSizeOptions={[50, 100, 250, 500]}
            onPageChange={setPage}
            onPageSizeChange={(size) => {
              setPageSize(size);
              setPage(1);
            }}
          />
        ) : null}
      </section>
    </AdminGate>
  );
}
