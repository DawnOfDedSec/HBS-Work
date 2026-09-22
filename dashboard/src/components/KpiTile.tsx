import type { ReactNode } from "react";

export type KpiTileProps = {
  label: string;
  value: string | number;
  hint?: string;
  tone?: "default" | "critical" | "high" | "ok";
  onClick?: () => void;
};

const TONE_CLASS: Record<NonNullable<KpiTileProps["tone"]>, string> = {
  default: "border-slate-700",
  critical: "border-red-600",
  high: "border-amber-500",
  ok: "border-emerald-600",
};

/**
 * A KPI stat tile. When `onClick` is present it becomes a keyboard-accessible
 * button that drills down into the exact filtered view.
 */
export function KpiTile({ label, value, hint, tone = "default", onClick }: KpiTileProps) {
  const content: ReactNode = (
    <>
      <div className="text-xs uppercase tracking-wide text-slate-400">{label}</div>
      <div className="mt-1 text-3xl font-semibold tabular-nums">{value}</div>
      {hint ? <div className="mt-1 text-xs text-slate-400">{hint}</div> : null}
    </>
  );

  if (onClick) {
    return (
      <button
        type="button"
        onClick={onClick}
        className={`rounded-lg border bg-slate-900/60 p-4 text-left transition hover:bg-slate-800/70 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 ${TONE_CLASS[tone]}`}
      >
        {content}
      </button>
    );
  }

  return (
    <div className={`rounded-lg border bg-slate-900/60 p-4 ${TONE_CLASS[tone]}`} role="group" aria-label={label}>
      {content}
    </div>
  );
}
