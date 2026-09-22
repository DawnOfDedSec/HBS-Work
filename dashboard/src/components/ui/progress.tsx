import { cn } from "./cn";

export type ProgressTone = "accent" | "compliant" | "degraded" | "critical";

export type ProgressBarProps = {
  /** Current value in the range 0..max. */
  value: number;
  max?: number;
  label?: string;
  tone?: ProgressTone;
  /** Render the percentage (or `value/max`) to the right of the bar. */
  showValue?: boolean;
  /** Animated stripes for "in progress" states. */
  indeterminate?: boolean;
  className?: string;
};

const TONE_CLASS: Record<ProgressTone, string> = {
  accent: "bg-accent",
  compliant: "bg-compliant",
  degraded: "bg-degraded",
  critical: "bg-critical",
};

/** A linear progress meter with full ARIA value semantics. */
export function ProgressBar({
  value,
  max = 100,
  label,
  tone = "accent",
  showValue = false,
  indeterminate = false,
  className,
}: ProgressBarProps) {
  const safeMax = max > 0 ? max : 1;
  const clamped = Math.max(0, Math.min(value, safeMax));
  const percent = (clamped / safeMax) * 100;

  return (
    <div className={cn("w-full", className)}>
      {label || showValue ? (
        <div className="mb-1 flex items-center justify-between gap-2 text-2xs text-ink-muted">
          {label ? <span>{label}</span> : <span />}
          {showValue && !indeterminate ? <span className="tabular-nums">{percent.toFixed(0)}%</span> : null}
        </div>
      ) : null}
      <div
        role="progressbar"
        aria-label={label}
        aria-valuenow={indeterminate ? undefined : clamped}
        aria-valuemin={0}
        aria-valuemax={safeMax}
        className="h-1.5 w-full overflow-hidden rounded-full bg-surface-raised"
      >
        <div
          className={cn(
            "h-full rounded-full transition-[width]",
            TONE_CLASS[tone],
            indeterminate && "animate-shimmer",
          )}
          style={{ width: `${indeterminate ? 100 : percent}%` }}
        />
      </div>
    </div>
  );
}
