import { useRef, type KeyboardEvent, type ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import { cn, focusRing } from "./cn";

export type TabItem = {
  value: string;
  label: ReactNode;
  icon?: LucideIcon;
  /** Optional trailing count/token rendered after the label. */
  count?: ReactNode;
  disabled?: boolean;
};

export type TabsProps = {
  items: TabItem[];
  value: string;
  onChange: (value: string) => void;
  /** Accessible name for the tablist. */
  label: string;
  size?: "sm" | "md";
  className?: string;
  /** Stable id prefix used to wire tab/panel relationships. */
  idBase?: string;
};

/**
 * Accessible tabs with a roving tabindex: only the selected tab is in the tab
 * order, and Left/Right/Home/End move selection. Uses automatic activation, so
 * arrow keys change the panel immediately.
 */
export function Tabs({ items, value, onChange, label, size = "md", className, idBase = "tabs" }: TabsProps) {
  const listRef = useRef<HTMLDivElement>(null);

  const enabled = items.filter((item) => !item.disabled);
  const currentIndex = enabled.findIndex((item) => item.value === value);

  function move(delta: number | "first" | "last") {
    if (enabled.length === 0) return;
    let next: number;
    if (delta === "first") next = 0;
    else if (delta === "last") next = enabled.length - 1;
    else {
      const base = currentIndex < 0 ? 0 : currentIndex;
      next = (base + delta + enabled.length) % enabled.length;
    }
    const target = enabled[next];
    if (target) {
      onChange(target.value);
      const node = listRef.current?.querySelector<HTMLButtonElement>(`[data-tab-value="${CSS.escape(target.value)}"]`);
      node?.focus();
    }
  }

  function onKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    switch (event.key) {
      case "ArrowRight":
      case "ArrowDown":
        event.preventDefault();
        move(1);
        break;
      case "ArrowLeft":
      case "ArrowUp":
        event.preventDefault();
        move(-1);
        break;
      case "Home":
        event.preventDefault();
        move("first");
        break;
      case "End":
        event.preventDefault();
        move("last");
        break;
      default:
        break;
    }
  }

  return (
    <div
      ref={listRef}
      role="tablist"
      aria-label={label}
      aria-orientation="horizontal"
      onKeyDown={onKeyDown}
      className={cn(
        "flex w-full items-center gap-1 border-b border-hairline",
        size === "sm" ? "text-xs" : "text-sm",
        className,
      )}
    >
      {items.map((item) => {
        const selected = item.value === value;
        const Icon = item.icon;
        return (
          <button
            key={item.value}
            type="button"
            role="tab"
            id={`${idBase}-tab-${item.value}`}
            data-tab-value={item.value}
            aria-selected={selected}
            aria-controls={`${idBase}-panel-${item.value}`}
            tabIndex={selected ? 0 : -1}
            disabled={item.disabled}
            onClick={() => onChange(item.value)}
            className={cn(
              "relative -mb-px inline-flex items-center gap-1.5 whitespace-nowrap rounded-t-md border-b-2 px-3 py-2 font-medium transition-colors",
              focusRing,
              selected
                ? "border-accent text-ink"
                : "border-transparent text-ink-muted hover:text-ink",
              item.disabled && "cursor-not-allowed opacity-50 hover:text-ink-muted",
            )}
          >
            {Icon ? <Icon size={15} aria-hidden /> : null}
            <span>{item.label}</span>
            {item.count !== undefined && item.count !== null ? (
              <span className="rounded-full bg-surface-raised px-1.5 text-2xs tabular-nums text-ink-muted">
                {item.count}
              </span>
            ) : null}
          </button>
        );
      })}
    </div>
  );
}

export type TabPanelProps = {
  id: string;
  active: boolean;
  children: ReactNode;
  className?: string;
  idBase?: string;
};

/** The panel matched to a `Tabs` item. */
export function TabPanel({ id, active, children, className, idBase = "tabs" }: TabPanelProps) {
  if (!active) return null;
  return (
    <div
      role="tabpanel"
      id={`${idBase}-panel-${id}`}
      aria-labelledby={`${idBase}-tab-${id}`}
      tabIndex={0}
      className={cn("pt-4", focusRing, className)}
    >
      {children}
    </div>
  );
}
