import type { ReactNode } from "react";
import {
  CartesianGrid,
  Line,
  LineChart,
  Tooltip,
  XAxis,
  YAxis,
  type DotItemDotProps,
} from "recharts";
import {
  ChartFrame,
  ExactTooltip,
  FocusableDot,
  TableTwin,
  drilldownQuery,
} from "./TableTwin";

export type TrendDatum = {
  /** Calendar day in `YYYY-MM-DD` form. */
  date: string;
  score: number;
  reports: number;
};

export type TrendLineProps = {
  points: TrendDatum[];
  onDrilldown: (urlQuery: string) => void;
};

const CHART_WIDTH = 560;
const CHART_HEIGHT = 220;

function dayBounds(date: string): { from: string; to: string } {
  return {
    from: `${date}T00:00:00.000Z`,
    to: `${date}T23:59:59.999Z`,
  };
}

/** Risk score over time (single value axis). Dots drill into that day's range. */
export function TrendLine({ points, onDrilldown }: TrendLineProps) {
  const renderDot = (props: DotItemDotProps): ReactNode => {
    if (props.cx === undefined || props.cy === undefined) return <g />;
    const datum = props.payload as TrendDatum | undefined;
    const date = datum?.date ?? "";
    const score = typeof datum?.score === "number" ? datum.score : 0;
    return (
      <FocusableDot
        cx={props.cx as number}
        cy={props.cy as number}
        fill="#38bdf8"
        label={`${date}: risk score ${score.toFixed(1)}. Show findings from this day.`}
        onActivate={() => {
          const bounds = dayBounds(date);
          onDrilldown(drilldownQuery({ from: [bounds.from], to: [bounds.to] }));
        }}
      />
    );
  };

  const chart =
    points.length === 0 ? (
      <p role="status" className="py-8 text-center text-sm text-slate-400">
        No trend data in this scope.
      </p>
    ) : (
      <LineChart
        width={CHART_WIDTH}
        height={CHART_HEIGHT}
        data={points}
        margin={{ top: 8, right: 24, bottom: 8, left: 0 }}
        accessibilityLayer={false}
      >
        <CartesianGrid stroke="#1e293b" vertical={false} />
        <XAxis dataKey="date" stroke="#94a3b8" fontSize={11} />
        <YAxis domain={[0, 100]} stroke="#94a3b8" fontSize={11} width={40} />
        <Tooltip content={ExactTooltip} />
        <Line
          type="monotone"
          dataKey="score"
          name="Risk score"
          stroke="#38bdf8"
          strokeWidth={2}
          dot={renderDot}
          activeDot={false}
          isAnimationActive={false}
        />
      </LineChart>
    );

  const table = (
    <TableTwin
      caption="Risk score trend"
      columns={[
        { key: "date", header: "Date" },
        { key: "score", header: "Risk score" },
        { key: "reports", header: "Reports" },
      ]}
      rows={points.map((point) => ({
        key: point.date,
        cells: [point.date, point.score.toFixed(1), point.reports],
      }))}
    />
  );

  return (
    <ChartFrame
      title="Risk score trend"
      description="Click or press Enter on a point to filter findings by that day."
      chart={chart}
      table={table}
    />
  );
}
