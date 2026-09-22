import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import { Inbox } from "lucide-react";
import { cn } from "./cn";

export type EmptyStateProps = {
  title: string;
  detail?: ReactNode;
  icon?: LucideIcon;
  /** Optional call to action (usually a Button). */
  action?: ReactNode;
  className?: string;
};

/** A friendly, centred placeholder for views with no data (or no selection). */
export function EmptyState({ title, detail, icon: Icon = Inbox, action, className }: EmptyStateProps) {
  return (
    <div
      role="status"
      className={cn(
        "flex flex-col items-center justify-center rounded-panel border border-dashed border-hairline bg-surface/40 px-6 py-12 text-center",
        className,
      )}
    >
      <span className="mb-3 flex h-11 w-11 items-center justify-center rounded-full bg-surface-raised text-ink-subtle">
        <Icon size={20} aria-hidden />
      </span>
      <p className="text-sm font-semibold text-ink">{title}</p>
      {detail ? <p className="mt-1 max-w-md text-xs text-ink-muted">{detail}</p> : null}
      {action ? <div className="mt-4">{action}</div> : null}
    </div>
  );
}
