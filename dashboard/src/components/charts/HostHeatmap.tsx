import type { ReactNode } from "react";
import {
  Scatter,
  ScatterChart,
  Tooltip,
  XAxis,
  YAxis,
  type ScatterShapeProps,
  type TooltipContentProps,
} from "recharts";
import {
  ChartFrame,
  FocusableRect,
  SEVERITY_ORDER,
  TableTwin,
  drilldownQuery,
  severityColor,
} from "./TableTwin";

export type HostSeverityDatum = {
  hostId: number;
  hostname: string;
  severity: Record<string, number>;
};

export type HostHeatmapProps = {
  hosts: HostSeverityDatum[];
  onDrilldown: (urlQuery: string) => void;
};

const CHART_WIDTH = 560;
const MAX_HOSTS = 20;
const CELL_WIDTH = 62;
const CELL_HEIGHT = 24;

type HeatPoint = {
  x: number;
  y: number;
  value: number;
  hostId: number;
  hostname: string;
  severity: string;
};

function heatTooltip(props: TooltipContentProps): ReactNode {
  const { active, payload } = props;
  const point = payload?.[0]?.payload as HeatPoint | undefined;
  if (!active || !point) return null;
  return (
    <div className="rounded-control border border-hairline-strong bg-surface-overlay px-2.5 py-1.5 text-xs shadow-overlay">
      <div className="font-semibold text-ink">{point.hostname}</div>
      <div className="text-ink-muted">
        <span className="text-ink-subtle">{point.severity}: </span>
        <span className="tabular-nums text-ink">{point.value}</span>
      </div>
    </div>
  );
}

/**
 * Host × severity heatmap. Each cell is a focusable mark; activating it filters
 * findings by that host and severity on the single shared value scale.
 */
export function HostHeatmap({ hosts, onDrilldown }: HostHeatmapProps) {
  const rows = hosts.slice(0, MAX_HOSTS);
  const chartHeight = Math.max(120, rows.length * 30 + 40);
  const maxValue = Math.max(
    1,
    ...rows.flatMap((host) => SEVERITY_ORDER.map((severity) => host.severity[severity] ?? 0)),
  );

  const points: HeatPoint[] = [];
  rows.forEach((host, rowIndex) => {
    SEVERITY_ORDER.forEach((severity, columnIndex) => {
      points.push({
        x: columnIndex,
        y: rowIndex,
        value: host.severity[severity] ?? 0,
        hostId: host.hostId,
        hostname: host.hostname,
        severity,
      });
    });
  });

  const renderCell = (props: ScatterShapeProps): ReactNode => {
    const point = props.payload as HeatPoint | undefined;
    if (!point || props.cx === undefined || props.cy === undefined) return <g />;
    const intensity = maxValue > 0 ? point.value / maxValue : 0;
    return (
      <FocusableRect
        x={props.cx - CELL_WIDTH / 2}
        y={props.cy - CELL_HEIGHT / 2}
        width={CELL_WIDTH}
        height={CELL_HEIGHT}
        radius={4}
        fill={severityColor(point.severity)}
        fillOpacity={point.value === 0 ? 0.12 : 0.25 + 0.75 * intensity}
        stroke="var(--color-surface-sunken)"
        label={`${point.hostname} ${point.severity}: ${point.value} findings. Show findings.`}
        onActivate={
          point.value > 0
            ? () =>
                onDrilldown(
                  drilldownQuery({
                    hostId: [String(point.hostId)],
                    severity: [point.severity],
                  }),
                )
            : undefined
        }
      />
    );
  };

  const chart =
    rows.length === 0 ? (
      <p role="status" className="py-8 text-center text-sm text-ink-muted">
        No host data in this scope.
      </p>
    ) : (
      <div className="overflow-x-auto">
        <ScatterChart
          width={CHART_WIDTH}
          height={chartHeight}
          margin={{ top: 8, right: 16, bottom: 8, left: 8 }}
          accessibilityLayer={false}
        >
          <XAxis
            type="number"
            dataKey="x"
            name="Severity"
            domain={[-0.5, SEVERITY_ORDER.length - 0.5]}
            ticks={SEVERITY_ORDER.map((_, index) => index)}
            interval={0}
            tickFormatter={(value: number) => SEVERITY_ORDER[value] ?? ""}
            stroke="var(--color-ink-subtle)"
            fontSize={10}
          />
          <YAxis
            type="number"
            dataKey="y"
            name="Host"
            domain={[-0.5, rows.length - 0.5]}
            ticks={rows.map((_, index) => index)}
            interval={0}
            tickFormatter={(value: number) => {
              const name = rows[value]?.hostname ?? "";
              return name.length > 18 ? `${name.slice(0, 17)}…` : name;
            }}
            width={140}
            stroke="var(--color-ink-subtle)"
            fontSize={10}
          />
          <Tooltip content={heatTooltip} />
          <Scatter data={points} shape={renderCell} isAnimationActive={false} />
        </ScatterChart>
      </div>
    );

  const table = (
    <TableTwin
      caption="Findings by host and severity"
      columns={[
        { key: "host", header: "Host" },
        ...SEVERITY_ORDER.map((severity) => ({ key: severity, header: severity })),
        { key: "total", header: "Total" },
      ]}
      rows={rows.map((host) => {
        const counts = SEVERITY_ORDER.map((severity) => host.severity[severity] ?? 0);
        return {
          key: String(host.hostId),
          cells: [host.hostname, ...counts, counts.reduce((sum, count) => sum + count, 0)],
        };
      })}
    />
  );

  return (
    <ChartFrame
      title="Hosts by severity"
      description={`Top ${MAX_HOSTS} hosts. Click or press Enter on a cell to filter by host and severity.`}
      chart={chart}
      table={table}
    />
  );
}
