import { CalendarRange, ListFilter } from "lucide-react";
import { Button, ButtonGroup, Card, CardBody, CardHeader, Input } from "./ui";
import { resolveScope, serializeFilters, type FilterKey, type ScopeFilters } from "../filters";
import { useScopeFilters } from "../useScopeFilters";

/**
 * Atomically drop the scope keys (`scope`, `reportId`, `from`, `to`) and make
 * the URL-backed filter hook re-parse. Clearing them one-by-one would race
 * because each commit reads the same captured filter state.
 */
export function clearScopeKeys(filters: ScopeFilters): void {
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

export type ScopeControlsProps = {
  filters: ScopeFilters;
  onToggle: (key: FilterKey, value: string) => void;
  onClearScope: () => void;
};

/**
 * Presentational scope selector driven by a caller-owned filter controller, so
 * any page can render it against its own `useScopeFilters()` instance.
 */
export function ScopeControls({ filters, onToggle, onClearScope }: ScopeControlsProps) {
  const scope = resolveScope(filters);

  return (
    <Card>
      <CardHeader
        icon={ListFilter}
        title="Scope"
        description="Latest state per host, a single sealed report, or an inclusive received-at range."
        actions={
          <ButtonGroup>
            <Button
              size="sm"
              variant={scope === "latest" ? "primary" : "ghost"}
              aria-pressed={scope === "latest"}
              onClick={onClearScope}
            >
              Latest
            </Button>
            <Button
              size="sm"
              variant={scope === "report" ? "primary" : "ghost"}
              aria-pressed={scope === "report"}
              onClick={() => onToggle("scope", "report")}
            >
              Single report
            </Button>
            <Button
              size="sm"
              variant={scope === "range" ? "primary" : "ghost"}
              aria-pressed={scope === "range"}
              onClick={() => onToggle("scope", "range")}
            >
              Date range
            </Button>
          </ButtonGroup>
        }
      />
      {scope === "report" || scope === "range" ? (
        <CardBody className="flex flex-wrap items-end gap-3">
          {scope === "report" ? (
            <Input
              label="Report ID"
              type="number"
              min={1}
              inputMode="numeric"
              value={filters.reportId?.[0] ?? ""}
              onChange={(event) => event.target.value && onToggle("reportId", event.target.value)}
              containerClassName="w-36"
            />
          ) : (
            <>
              <Input
                label="From (UTC)"
                type="datetime-local"
                value={filters.from?.[0]?.slice(0, 16) ?? ""}
                onChange={(event) => event.target.value && onToggle("from", event.target.value)}
                containerClassName="w-52"
              />
              <Input
                label="To (UTC)"
                type="datetime-local"
                value={filters.to?.[0]?.slice(0, 16) ?? ""}
                onChange={(event) => event.target.value && onToggle("to", event.target.value)}
                containerClassName="w-52"
              />
              <p className="flex items-center gap-1.5 pb-2 text-2xs text-ink-subtle">
                <CalendarRange size={13} aria-hidden />
                Inclusive of both bounds.
              </p>
            </>
          )}
        </CardBody>
      ) : null}
    </Card>
  );
}

/**
 * Self-contained scope selector for callers that do not own a filter
 * controller (e.g. the campaign workspace shell).
 */
export function ScopeSelector() {
  const { filters, toggle } = useScopeFilters();
  return (
    <ScopeControls filters={filters} onToggle={toggle} onClearScope={() => clearScopeKeys(filters)} />
  );
}
