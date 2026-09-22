import type { HTMLAttributes, ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import { cn } from "./cn";

export type BadgeTone =
  | "neutral"
  | "accent"
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "info"
  | "compliant"
  | "noncompliant"
  | "degraded"
  | "na"
  | "error"
  | "success"
  | "open"
  | "accepted"
  | "false-positive"
  | "remediated"
  | "evidence-primary"
  | "evidence-fallback"
  | "evidence-degraded";

const TONE_CLASS: Record<BadgeTone, string> = {
  neutral: "bg-surface-raised text-ink-muted border-hairline",
  accent: "bg-accent-soft text-accent border-accent/30",
  critical: "bg-critical-soft text-critical border-critical/35",
  high: "bg-high-soft text-high border-high/35",
  medium: "bg-medium-soft text-medium border-medium/35",
  low: "bg-low-soft text-low border-low/35",
  info: "bg-info-soft text-info border-info/30",
  compliant: "bg-compliant-soft text-compliant border-compliant/35",
  noncompliant: "bg-noncompliant-soft text-noncompliant border-noncompliant/35",
  degraded: "bg-degraded-soft text-degraded border-degraded/35",
  na: "bg-na-soft text-na border-na/30",
  error: "bg-error-soft text-error border-error/35",
  success: "bg-compliant-soft text-compliant border-compliant/35",
  open: "bg-treatment-open-soft text-treatment-open border-treatment-open/35",
  accepted: "bg-treatment-accepted-soft text-treatment-accepted border-treatment-accepted/35",
  "false-positive":
    "bg-treatment-false-positive-soft text-treatment-false-positive border-treatment-false-positive/35",
  remediated: "bg-treatment-remediated-soft text-treatment-remediated border-treatment-remediated/35",
  "evidence-primary": "bg-evidence-primary-soft text-evidence-primary border-evidence-primary/35",
  "evidence-fallback": "bg-evidence-fallback-soft text-evidence-fallback border-evidence-fallback/35",
  "evidence-degraded": "bg-evidence-degraded-soft text-evidence-degraded border-evidence-degraded/35",
};

export type BadgeProps = HTMLAttributes<HTMLSpanElement> & {
  tone?: BadgeTone;
  /** Leading icon component; label text always accompanies colour. */
  icon?: LucideIcon;
  /** Pill (fully rounded) vs. squared chip shape. */
  pill?: boolean;
  children: ReactNode;
};

/** A compact status/label token. Never conveys meaning by colour alone. */
export function Badge({ tone = "neutral", icon: Icon, pill = false, className, children, ...rest }: BadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 border px-1.5 py-0.5 text-2xs font-medium",
        pill ? "rounded-full" : "rounded",
        TONE_CLASS[tone],
        className,
      )}
      {...rest}
    >
      {Icon ? <Icon size={12} aria-hidden /> : null}
      {children}
    </span>
  );
}
