import type { ReactNode } from "react";
import { Cell, Pie, PieChart, Tooltip, type PieSectorShapeProps } from "recharts";
import {
  ChartFrame,
  ExactTooltip,
  FocusableSector,
  SEVERITY_ORDER,
  TableTwin,
  drilldownQuery,
  severityColor,
} from "./TableTwin";

export type SeverityDonutProps = {
  /** Counts keyed by canonical severity name (Critical..Informational). */
  data: Record<string, number>;
  onDrilldown: (urlQuery: string) => void;
};

const CHART_SIZE = 220;

/**
 * Severity breakdown donut. The canonical severity set is five segments, well
 * under the six-segment cap where a donut stays readable (no dual axes here).
 */
export function SeverityDonut({ data, onDrilldown }: SeverityDonutProps) {
  const segments = SEVERITY_ORDER.map((severity) => ({
    severity,
    count: data[severity] ?? 0,
    fill: severityColor(severity),
  }));
  const nonzero = segments.filter((segment) => segment.count > 0);

  const renderSector = (props: PieSectorShapeProps): ReactNode => {
    const datum = (props.payload ?? {}) as { severity?: string };
    const severity = datum.severity ?? "Informational";
    const count = typeof props.value === "number" ? props.value : 0;
    return (
      <FocusableSector
        cx={props.cx}
        cy={props.cy}
        innerRadius={props.innerRadius}
        outerRadius={props.outerRadius}
        startAngle={props.startAngle}
        endAngle={props.endAngle}
        cornerRadius={props.cornerRadius}
        fill={typeof props.fill === "string" ? props.fill : severityColor(severity)}
        stroke="var(--color-surface-sunken)"
        strokeWidth={4}
        label={`${severity} severity: ${count} findings. Show findings.`}
        onActivate={() => onDrilldown(drilldownQuery({ severity: [severity] }))}
      />
    );
  };

  const total = segments.reduce((sum, segment) => sum + segment.count, 0);

  const chart =
    nonzero.length === 0 ? (
      <p role="status" className="py-8 text-center text-sm text-ink-muted">
        No findings in this scope.
      </p>
    ) : (
      <div className="relative mx-auto" style={{ width: CHART_SIZE, height: CHART_SIZE }}>
        <PieChart width={CHART_SIZE} height={CHART_SIZE} accessibilityLayer={false}>
          <Pie
            data={nonzero}
            dataKey="count"
            nameKey="severity"
            cx="50%"
            cy="50%"
            innerRadius="55%"
            outerRadius="85%"
            paddingAngle={2}
            isAnimationActive={false}
            shape={renderSector}
          >
            {nonzero.map((segment) => (
              <Cell key={segment.severity} fill={segment.fill} />
            ))}
          </Pie>
          <Tooltip content={ExactTooltip} />
        </PieChart>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-semibold tabular-nums text-ink">{total}</span>
          <span className="text-xs text-ink-muted">findings</span>
        </div>
      </div>
    );

  const table = (
    <TableTwin
      caption="Severity breakdown"
      columns={[
        { key: "severity", header: "Severity" },
        { key: "count", header: "Findings" },
      ]}
      rows={segments.map((segment) => ({
        key: segment.severity,
        cells: [segment.severity, segment.count],
      }))}
    />
  );

  return (
    <ChartFrame
      title="Severity breakdown"
      description="Click or press Enter on a segment to filter findings by severity."
      chart={chart}
      table={table}
    />
  );
}
