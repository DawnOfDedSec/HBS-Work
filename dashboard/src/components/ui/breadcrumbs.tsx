import type { ReactNode } from "react";
import { ChevronRight, type LucideIcon } from "lucide-react";
import { cn, focusRing } from "./cn";

export type BreadcrumbItem = {
  label: ReactNode;
  icon?: LucideIcon;
  /** When present the crumb is a keyboard-operable link. */
  onClick?: () => void;
};

export type BreadcrumbsProps = {
  items: BreadcrumbItem[];
  label?: string;
  className?: string;
};

/** Path-style breadcrumbs; the final item is announced as the current page. */
export function Breadcrumbs({ items, label = "Breadcrumb", className }: BreadcrumbsProps) {
  return (
    <nav aria-label={label} className={cn("min-w-0", className)}>
      <ol className="flex min-w-0 items-center gap-1 text-xs text-ink-muted">
        {items.map((item, index) => {
          const isLast = index === items.length - 1;
          const Icon = item.icon;
          return (
            <li key={index} className="flex min-w-0 items-center gap-1">
              {index > 0 ? <ChevronRight size={13} className="shrink-0 text-ink-subtle" aria-hidden /> : null}
              {item.onClick && !isLast ? (
                <button
                  type="button"
                  onClick={item.onClick}
                  className={cn(
                    "inline-flex min-w-0 items-center gap-1 truncate rounded px-0.5 hover:text-ink",
                    focusRing,
                  )}
                >
                  {Icon ? <Icon size={13} aria-hidden /> : null}
                  <span className="truncate">{item.label}</span>
                </button>
              ) : (
                <span
                  aria-current={isLast ? "page" : undefined}
                  className={cn("inline-flex min-w-0 items-center gap-1 truncate", isLast && "font-medium text-ink")}
                >
                  {Icon ? <Icon size={13} aria-hidden /> : null}
                  <span className="truncate">{item.label}</span>
                </span>
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
