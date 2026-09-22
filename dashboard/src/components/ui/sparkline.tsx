import { cn } from "./cn";

export type SparklineProps = {
  values: number[];
  width?: number;
  height?: number;
  /** Optional accessible description; omit for purely decorative sparklines. */
  ariaLabel?: string;
  className?: string;
  /** Draw a subtle filled area under the line. */
  area?: boolean;
};

/** A tiny, dependency-free trend line used in KPI tiles. */
export function Sparkline({
  values,
  width = 120,
  height = 32,
  ariaLabel,
  className,
  area = true,
}: SparklineProps) {
  if (values.length < 2) return null;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const span = max - min || 1;
  const stepX = width / (values.length - 1);
  const points = values.map((value, index) => {
    const x = index * stepX;
    const y = height - 2 - ((value - min) / span) * (height - 4);
    return [x, y] as const;
  });
  const line = points.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
  const areaPath = `M0,${height} L${line.replace(/ /g, " L")} L${width},${height} Z`;

  return (
    <svg
      viewBox={`0 0 ${width} ${height}`}
      width={width}
      height={height}
      preserveAspectRatio="none"
      className={cn("overflow-visible text-accent", className)}
      role={ariaLabel ? "img" : undefined}
      aria-label={ariaLabel}
      aria-hidden={ariaLabel ? undefined : true}
      focusable="false"
    >
      {area ? <path d={areaPath} fill="currentColor" opacity={0.14} /> : null}
      <polyline
        points={line}
        fill="none"
        stroke="currentColor"
        strokeWidth={1.75}
        strokeLinejoin="round"
        strokeLinecap="round"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  );
}
