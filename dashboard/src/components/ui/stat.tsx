import type { ReactNode } from "react";
import { ArrowDownRight, ArrowUpRight, Minus, type LucideIcon } from "lucide-react";
import { cn, focusRing } from "./cn";

export type StatTone = "default" | "accent" | "critical" | "high" | "medium" | "low" | "ok";

export type StatDelta = {
  value: string;
  direction: "up" | "down" | "flat";
  /** Whether the delta represents improvement or regression. */
  intent?: "positive" | "negative" | "neutral";
};

export type StatProps = {
  label: string;
  value: ReactNode;
  /** Small caption under the value (e.g. "coverage 98.4%"). */
  hint?: ReactNode;
  icon?: LucideIcon;
  delta?: StatDelta;
  /** Render a sparkline (or any node) in the tile's trailing area. */
  sparkline?: ReactNode;
  tone?: StatTone;
  /** When present the tile becomes a keyboard-activatable drill-down link. */
  onClick?: () => void;
  className?: string;
};

const TONE_ACCENT: Record<StatTone, string> = {
  default: "text-ink",
  accent: "text-accent",
  critical: "text-critical",
  high: "text-high",
  medium: "text-medium",
  low: "text-low",
  ok: "text-compliant",
};

const TONE_ICON: Record<StatTone, string> = {
  default: "bg-surface-raised text-ink-muted",
  accent: "bg-accent-soft text-accent",
  critical: "bg-critical-soft text-critical",
  high: "bg-high-soft text-high",
  medium: "bg-medium-soft text-medium",
  low: "bg-low-soft text-low",
  ok: "bg-compliant-soft text-compliant",
};

const DELTA_INTENT: Record<NonNullable<StatDelta["intent"]>, string> = {
  positive: "text-compliant",
  negative: "text-critical",
  neutral: "text-ink-muted",
};

const DELTA_ICON = { up: ArrowUpRight, down: ArrowDownRight, flat: Minus } as const;

/**
 * A KPI tile. `value` uses tabular numerals so metrics stay aligned across a
 * row. When `onClick` is supplied the whole tile is a real button for
 * keyboard drill-down.
 */
export function Stat({
  label,
  value,
  hint,
  icon: Icon,
  delta,
  sparkline,
  tone = "default",
  onClick,
  className,
}: StatProps) {
  const DeltaIcon = delta ? DELTA_ICON[delta.direction] : null;

  const body = (
    <>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">{label}</p>
          <p className={cn("mt-1.5 text-2xl font-semibold leading-none tabular-nums", TONE_ACCENT[tone])}>{value}</p>
        </div>
        {Icon ? (
          <span className={cn("flex h-8 w-8 shrink-0 items-center justify-center rounded-control", TONE_ICON[tone])}>
            <Icon size={16} aria-hidden />
          </span>
        ) : null}
      </div>
      <div className="mt-3 flex items-end justify-between gap-3">
        <div className="min-w-0">
          {hint ? <p className="text-xs text-ink-muted">{hint}</p> : null}
          {delta && DeltaIcon ? (
            <p
              className={cn(
                "mt-1 inline-flex items-center gap-1 text-xs font-medium",
                DELTA_INTENT[delta.intent ?? "neutral"],
              )}
            >
              <DeltaIcon size={13} aria-hidden />
              <span className="tabular-nums">{delta.value}</span>
            </p>
          ) : null}
        </div>
        {sparkline ? <div className="shrink-0 opacity-80">{sparkline}</div> : null}
      </div>
    </>
  );

  if (onClick) {
    return (
      <button
        type="button"
        onClick={onClick}
        className={cn(
          "hbs-panel block w-full p-4 text-left transition-colors hover:border-hairline-strong hover:bg-surface-raised",
          focusRing,
          className,
        )}
      >
        {body}
      </button>
    );
  }

  return (
    <div className={cn("hbs-panel p-4", className)} role="group" aria-label={label}>
      {body}
    </div>
  );
}
