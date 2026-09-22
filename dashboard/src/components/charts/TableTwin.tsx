import { useState, type KeyboardEvent as ReactKeyboardEvent, type ReactNode } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  HelpCircle,
  MinusCircle,
  ShieldAlert,
  XCircle,
  type LucideIcon,
} from "lucide-react";
import { Sector, type TooltipContentProps } from "recharts";
import { serializeFilters, type ScopeFilters } from "../../filters";

// Shared chart scaffolding (Task 54).
//
// Every chart gets the same three accessibility guarantees:
//   * an exact-value tooltip (see `ExactTooltip`),
//   * keyboard-focusable marks that drill down on Click/Enter/Space,
//   * a "table twin" toggle that renders an accessible <table> instead.

/** Canonical severity ordering and palettes (dataviz tokens, no dual axes). */
export const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"] as const;

export const SEVERITY_COLOR: Record<string, string> = {
  Critical: "#dc2626",
  High: "#f59e0b",
  Medium: "#eab308",
  Low: "#38bdf8",
  Informational: "#64748b",
};

export function severityColor(severity: string): string {
  return SEVERITY_COLOR[severity] ?? "#64748b";
}

/**
 * Build a drilldown query string from canonical filter values only. Using the
 * shared serializer guarantees exact parameter names and stable ordering, so
 * the same query can be replayed against `/api/findings` verbatim.
 */
export function drilldownQuery(filters: ScopeFilters): string {
  return serializeFilters(filters);
}

/** Exact-value tooltip content shared by every chart. */
export function ExactTooltip(props: TooltipContentProps): ReactNode {
  const { active, payload, label } = props;
  if (!active || !payload || payload.length === 0) return null;
  return (
    <div className="rounded border border-slate-700 bg-slate-950/95 px-2 py-1 text-xs shadow-lg">
      {label !== undefined && label !== "" ? (
        <div className="mb-1 font-medium text-slate-200">{String(label)}</div>
      ) : null}
      <ul className="space-y-0.5">
        {payload.map((entry, index) => (
          <li key={`${String(entry.dataKey ?? index)}-${index}`} className="text-slate-300">
            <span className="text-slate-400">{String(entry.name ?? entry.dataKey ?? "value")}: </span>
            <span className="tabular-nums text-slate-100">{String(entry.value)}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export type TableTwinColumn = { key: string; header: string };
export type TableTwinRow = { key: string; cells: Array<string | number> };

export type TableTwinProps = {
  /** Accessible table caption; describes the chart it mirrors. */
  caption: string;
  columns: TableTwinColumn[];
  rows: TableTwinRow[];
};

/** The accessible <table> alternative rendered by a chart's table twin toggle. */
export function TableTwin({ caption, columns, rows }: TableTwinProps) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-sm">
        <caption className="pb-2 text-left text-sm text-slate-300">{caption}</caption>
        <thead>
          <tr>
            {columns.map((column) => (
              <th
                key={column.key}
                scope="col"
                className="border-b border-slate-700 px-2 py-1 text-left font-medium text-slate-400"
              >
                {column.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.key}>
              {row.cells.map((cell, index) => (
                <td
                  key={`${row.key}-${columns[index]?.key ?? index}`}
                  className="border-b border-slate-800 px-2 py-1 tabular-nums"
                >
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export type ChartFrameProps = {
  title: string;
  description?: string;
  /** The rendered chart. */
  chart: ReactNode;
  /** The accessible table alternative for the same data. */
  table: ReactNode;
  /** Optional extra controls rendered next to the table toggle. */
  actions?: ReactNode;
};

/**
 * Chart chrome: title, an optional presentation action, and a table twin
 * toggle. The toggle is a real button with `aria-pressed` so keyboard and
 * screen-reader users can swap between the chart and its table equivalent.
 */
export function ChartFrame({ title, description, chart, table, actions }: ChartFrameProps) {
  const [showTable, setShowTable] = useState(false);
  return (
    <figure className="rounded-lg border border-slate-800 bg-slate-900/50 p-4">
      <figcaption className="mb-3 flex flex-wrap items-start justify-between gap-2">
        <span>
          <span className="text-sm font-medium text-slate-100">{title}</span>
          {description ? (
            <span className="mt-0.5 block text-xs text-slate-400">{description}</span>
          ) : null}
        </span>
        <span className="flex items-center gap-2">
          {actions}
          <button
            type="button"
            aria-pressed={showTable}
            onClick={() => setShowTable((value) => !value)}
            className="rounded border border-slate-700 px-2 py-1 text-xs hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
          >
            {showTable ? "Show chart" : "Show table"}
          </button>
        </span>
      </figcaption>
      {showTable ? table : chart}
    </figure>
  );
}

const FOCUS_RING = "#38bdf8";

/** Keyboard activation shared by every focusable chart mark. */
function activateOnKey(event: ReactKeyboardEvent, onActivate: () => void) {
  if (event.key === "Enter" || event.key === " " || event.key === "Spacebar") {
    event.preventDefault();
    onActivate();
  }
}

export type FocusableSectorProps = {
  cx: number;
  cy: number;
  innerRadius: number;
  outerRadius: number;
  startAngle: number;
  endAngle: number;
  cornerRadius?: number;
  fill: string;
  stroke?: string;
  strokeWidth?: number;
  /** Accessible name; when present the sector becomes an interactive mark. */
  label?: string;
  onActivate?: () => void;
};

/**
 * A pie/radial sector that becomes a real button for keyboard users:
 * focusable, Enter/Space activated, with a visible focus ring.
 */
export function FocusableSector({ label, onActivate, fill, ...geometry }: FocusableSectorProps) {
  const [focused, setFocused] = useState(false);
  const interactive = typeof onActivate === "function";
  return (
    <g
      role={interactive ? "button" : undefined}
      tabIndex={interactive ? 0 : undefined}
      aria-label={interactive ? label : undefined}
      className={interactive ? "cursor-pointer outline-none" : undefined}
      onFocus={() => setFocused(true)}
      onBlur={() => setFocused(false)}
      onClick={onActivate}
      onKeyDown={(event) => {
        if (interactive && onActivate) activateOnKey(event, onActivate);
      }}
    >
      <Sector
        cx={geometry.cx}
        cy={geometry.cy}
        innerRadius={geometry.innerRadius}
        outerRadius={geometry.outerRadius}
        startAngle={geometry.startAngle}
        endAngle={geometry.endAngle}
        cornerRadius={geometry.cornerRadius ?? 0}
        fill={fill}
        stroke={focused ? FOCUS_RING : geometry.stroke ?? "transparent"}
        strokeWidth={focused ? 3 : geometry.strokeWidth ?? 0}
      />
    </g>
  );
}

export type FocusableRectProps = {
  x: number;
  y: number;
  width: number;
  height: number;
  radius?: number;
  fill: string;
  fillOpacity?: number;
  stroke?: string;
  label?: string;
  onActivate?: () => void;
};

/** A bar / heatmap cell rect that is a focusable, Enter/Space-activatable mark. */
export function FocusableRect({ radius = 0, label, onActivate, stroke, ...geometry }: FocusableRectProps) {
  const [focused, setFocused] = useState(false);
  const interactive = typeof onActivate === "function";
  return (
    <rect
      {...geometry}
      rx={radius}
      role={interactive ? "button" : undefined}
      tabIndex={interactive ? 0 : undefined}
      aria-label={interactive ? label : undefined}
      className={interactive ? "cursor-pointer outline-none" : undefined}
      onFocus={() => setFocused(true)}
      onBlur={() => setFocused(false)}
      onClick={onActivate}
      onKeyDown={(event) => {
        if (interactive && onActivate) activateOnKey(event, onActivate);
      }}
      stroke={focused ? FOCUS_RING : stroke ?? "transparent"}
      strokeWidth={focused ? 3 : 0}
    />
  );
}

export type FocusableDotProps = {
  cx: number;
  cy: number;
  r?: number;
  fill: string;
  label?: string;
  onActivate?: () => void;
};

/** A line-chart dot that is a focusable, Enter/Space-activatable mark. */
export function FocusableDot({ cx, cy, r = 4, fill, label, onActivate }: FocusableDotProps) {
  const [focused, setFocused] = useState(false);
  const interactive = typeof onActivate === "function";
  return (
    <circle
      cx={cx}
      cy={cy}
      r={focused ? r + 2 : r}
      fill={fill}
      role={interactive ? "button" : undefined}
      tabIndex={interactive ? 0 : undefined}
      aria-label={interactive ? label : undefined}
      className={interactive ? "cursor-pointer outline-none" : undefined}
      onFocus={() => setFocused(true)}
      onBlur={() => setFocused(false)}
      onClick={onActivate}
      onKeyDown={(event) => {
        if (interactive && onActivate) activateOnKey(event, onActivate);
      }}
      stroke={focused ? FOCUS_RING : "#0b0f14"}
      strokeWidth={focused ? 3 : 2}
    />
  );
}

const STATUS_META: Record<string, { icon: LucideIcon; label: string; className: string }> = {
  Compliant: { icon: CheckCircle2, label: "Compliant", className: "text-emerald-400" },
  NonCompliant: { icon: XCircle, label: "Non-compliant", className: "text-red-400" },
  NotApplicable: { icon: MinusCircle, label: "Not applicable", className: "text-slate-400" },
  Error: { icon: AlertTriangle, label: "Error", className: "text-orange-400" },
  DegradedPartial: { icon: ShieldAlert, label: "Degraded (partial)", className: "text-amber-400" },
};

export type StatusLabelProps = { status: string };

/**
 * Status is never conveyed by colour alone: callers must render this
 * icon + text label pair for every check status.
 */
export function StatusLabel({ status }: StatusLabelProps) {
  const meta = STATUS_META[status] ?? { icon: HelpCircle, label: status, className: "text-slate-400" };
  const Icon = meta.icon;
  return (
    <span className={`inline-flex items-center gap-1 text-xs ${meta.className}`}>
      <Icon size={14} aria-hidden />
      <span>{meta.label}</span>
    </span>
  );
}

export type ToneBadgeProps = { label: string; tone?: "default" | "critical" | "warning" | "ok" };

const TONE_CLASS: Record<NonNullable<ToneBadgeProps["tone"]>, string> = {
  default: "border-slate-700 text-slate-300",
  critical: "border-red-600 text-red-300",
  warning: "border-amber-500 text-amber-300",
  ok: "border-emerald-600 text-emerald-300",
};

/** A small labelled badge; used for retired locations, duplicates, and results. */
export function ToneBadge({ label, tone = "default" }: ToneBadgeProps) {
  return (
    <span className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-xs ${TONE_CLASS[tone]}`}>
      {label}
    </span>
  );
}
