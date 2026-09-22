import type { ReactNode } from "react";
import { Cell, Pie, PieChart, Tooltip, type PieSectorShapeProps } from "recharts";
import {
  ChartFrame,
  ExactTooltip,
  FocusableSector,
  TableTwin,
  drilldownQuery,
} from "./TableTwin";

export type RiskGaugeProps = {
  /** Weighted risk score in [0, 100], higher = safer (server-authoritative). */
  score: number;
  /** Optional coverage percentage shown as a secondary metric. */
  coverage?: number;
  /** Called with canonical findings params when the gauge is activated. */
  onDrilldown: (urlQuery: string) => void;
};

const GAUGE_WIDTH = 240;
const GAUGE_HEIGHT = 150;

function riskBand(score: number): { label: string; color: string } {
  if (score >= 90) return { label: "Excellent", color: "var(--color-compliant)" };
  if (score >= 70) return { label: "Good", color: "var(--color-low)" };
  if (score >= 40) return { label: "At risk", color: "var(--color-high-strong)" };
  return { label: "Critical", color: "var(--color-critical-strong)" };
}

/**
 * Single-value risk gauge. The arc is the interactive mark: click, Enter, or
 * Space drills into the non-compliant findings that produce the score.
 */
export function RiskGauge({ score, coverage, onDrilldown }: RiskGaugeProps) {
  const clamped = Number.isFinite(score) ? Math.max(0, Math.min(100, score)) : 0;
  const band = riskBand(clamped);
  const data = [
    { name: "Risk score", value: clamped, fill: band.color, interactive: true },
    { name: "Remaining", value: 100 - clamped, fill: "var(--color-surface-raised)", interactive: false },
  ];

  const renderSector = (props: PieSectorShapeProps): ReactNode => {
    const datum = (props.payload ?? {}) as { interactive?: boolean; name?: string };
    const interactive = datum.interactive === true;
    const value = typeof props.value === "number" ? props.value : 0;
    return (
      <FocusableSector
        cx={props.cx}
        cy={props.cy}
        innerRadius={props.innerRadius}
        outerRadius={props.outerRadius}
        startAngle={props.startAngle}
        endAngle={props.endAngle}
        cornerRadius={props.cornerRadius}
        fill={typeof props.fill === "string" ? props.fill : "var(--color-surface-raised)"}
        label={interactive ? `Risk score ${value.toFixed(1)} out of 100. Show non-compliant findings.` : undefined}
        onActivate={
          interactive ? () => onDrilldown(drilldownQuery({ status: ["NonCompliant"] })) : undefined
        }
      />
    );
  };

  const chart = (
    <div className="relative mx-auto" style={{ width: GAUGE_WIDTH, height: GAUGE_HEIGHT }}>
      <PieChart width={GAUGE_WIDTH} height={GAUGE_HEIGHT} accessibilityLayer={false}>
        <Pie
          data={data}
          dataKey="value"
          cx="50%"
          cy="92%"
          startAngle={180}
          endAngle={0}
          innerRadius="72%"
          outerRadius="100%"
          isAnimationActive={false}
          shape={renderSector}
        >
          {data.map((entry) => (
            <Cell key={entry.name} fill={entry.fill} />
          ))}
        </Pie>
        <Tooltip content={ExactTooltip} />
      </PieChart>
      <div className="pointer-events-none absolute inset-x-0 bottom-1 text-center">
        <div className="text-3xl font-semibold tabular-nums" style={{ color: band.color }}>
          {clamped.toFixed(1)}
        </div>
        <div className="text-xs text-ink-muted">{band.label}</div>
      </div>
    </div>
  );

  const table = (
    <TableTwin
      caption="Risk score values"
      columns={[
        { key: "metric", header: "Metric" },
        { key: "value", header: "Value" },
      ]}
      rows={[
        { key: "score", cells: ["Risk score", clamped.toFixed(1)] },
        { key: "band", cells: ["Band", band.label] },
        { key: "coverage", cells: ["Coverage", coverage === undefined ? "—" : `${coverage.toFixed(1)}%`] },
      ]}
    />
  );

  return (
    <ChartFrame
      title="Risk score"
      description="Click or press Enter on the arc to see non-compliant findings."
      chart={chart}
      table={table}
    />
  );
}
