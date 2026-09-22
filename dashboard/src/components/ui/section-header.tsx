import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import { cn } from "./cn";

export type SectionHeaderProps = {
  title: ReactNode;
  description?: ReactNode;
  /** Small caps label above the title (e.g. "Analyze"). */
  eyebrow?: ReactNode;
  icon?: LucideIcon;
  actions?: ReactNode;
  className?: string;
  id?: string;
};

/** Standard page/section heading with optional actions. */
export function SectionHeader({
  title,
  description,
  eyebrow,
  icon: Icon,
  actions,
  className,
  id,
}: SectionHeaderProps) {
  return (
    <div className={cn("flex flex-wrap items-start justify-between gap-3", className)}>
      <div className="flex min-w-0 items-start gap-3">
        {Icon ? (
          <span className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-control bg-surface-raised text-accent">
            <Icon size={18} aria-hidden />
          </span>
        ) : null}
        <div className="min-w-0">
          {eyebrow ? (
            <p className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">{eyebrow}</p>
          ) : null}
          <h1 id={id} className="text-lg font-semibold tracking-tight text-ink">
            {title}
          </h1>
          {description ? <p className="mt-1 max-w-3xl text-sm text-ink-muted">{description}</p> : null}
        </div>
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}
