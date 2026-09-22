import type { ReactNode } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Tooltip,
  XAxis,
  YAxis,
  type BarShapeProps,
} from "recharts";
import {
  ChartFrame,
  ExactTooltip,
  FocusableRect,
  TableTwin,
  drilldownQuery,
} from "./TableTwin";

export type CategoryDatum = {
  category: string;
  total: number;
  compliant: number;
  nonCompliant: number;
  notApplicable: number;
  /** Applicable = total - notApplicable. */
  applicable: number;
  /** Percentage of applicable checks that are compliant. */
  complianceRate: number;
};

export type CategoryBarsProps = {
  data: CategoryDatum[];
  onDrilldown: (urlQuery: string) => void;
};

const CHART_WIDTH = 560;
const MAX_BARS = 12;

function barColor(datum: CategoryDatum): string {
  if (datum.nonCompliant === 0) return "#38bdf8";
  if (datum.complianceRate < 50) return "#dc2626";
  if (datum.complianceRate < 80) return "#f59e0b";
  return "#eab308";
}

/** Non-compliant findings per category (single shared axis, never dual). */
export function CategoryBars({ data, onDrilldown }: CategoryBarsProps) {
  const sorted = [...data].sort(
    (a, b) => b.nonCompliant - a.nonCompliant || a.category.localeCompare(b.category),
  );
  const shown = sorted.slice(0, MAX_BARS);
  const chartHeight = Math.max(140, shown.length * 30 + 30);

  const renderBar = (props: BarShapeProps): ReactNode => {
    const datum = (props.payload ?? {}) as Partial<CategoryDatum>;
    const category = datum.category ?? "";
    const count = typeof props.value === "number" ? props.value : 0;
    const label = `${category}: ${count} non-compliant findings. Show findings.`;
    return (
      <FocusableRect
        x={props.x}
        y={props.y}
        width={props.width}
        height={props.height}
        radius={4}
        fill={barColor({
          category,
          total: datum.total ?? 0,
          compliant: datum.compliant ?? 0,
          nonCompliant: datum.nonCompliant ?? count,
          notApplicable: datum.notApplicable ?? 0,
          applicable: datum.applicable ?? 0,
          complianceRate: datum.complianceRate ?? 100,
        })}
        label={label}
        onActivate={() => onDrilldown(drilldownQuery({ category: [category] }))}
      />
    );
  };

  const chart =
    shown.length === 0 ? (
      <p role="status" className="py-8 text-center text-sm text-slate-400">
        No category data in this scope.
      </p>
    ) : (
      <BarChart
        width={CHART_WIDTH}
        height={chartHeight}
        data={shown}
        layout="vertical"
        margin={{ top: 8, right: 24, bottom: 8, left: 8 }}
        accessibilityLayer={false}
      >
        <CartesianGrid horizontal={false} stroke="#1e293b" />
        <XAxis type="number" allowDecimals={false} stroke="#94a3b8" fontSize={11} />
        <YAxis
          type="category"
          dataKey="category"
          width={140}
          stroke="#94a3b8"
          fontSize={11}
          tickFormatter={(value: string) => (value.length > 20 ? `${value.slice(0, 19)}…` : value)}
        />
        <Tooltip content={ExactTooltip} cursor={{ fill: "rgba(148,163,184,0.08)" }} />
        <Bar
          dataKey="nonCompliant"
          name="Non-compliant"
          maxBarSize={24}
          isAnimationActive={false}
          shape={renderBar}
        />
      </BarChart>
    );

  const table = (
    <TableTwin
      caption="Findings by category"
      columns={[
        { key: "category", header: "Category" },
        { key: "total", header: "Total" },
        { key: "compliant", header: "Compliant" },
        { key: "nonCompliant", header: "Non-compliant" },
        { key: "notApplicable", header: "N/A" },
        { key: "rate", header: "Compliance %" },
      ]}
      rows={sorted.map((datum) => ({
        key: datum.category,
        cells: [
          datum.category,
          datum.total,
          datum.compliant,
          datum.nonCompliant,
          datum.notApplicable,
          datum.complianceRate.toFixed(1),
        ],
      }))}
    />
  );

  return (
    <ChartFrame
      title="Findings by category"
      description="Click or press Enter on a bar to filter findings by category."
      chart={chart}
      table={table}
    />
  );
}
