import { groupedNav, type RouteKey } from "../routes";
import type { AuthUser } from "../types";
import { cn, focusRing } from "./ui";

export type NavigationProps = {
  route: RouteKey;
  role: AuthUser["role"];
  onNavigate: (route: RouteKey) => void;
  /** Icon-only rail when true. */
  collapsed?: boolean;
};

/**
 * Primary navigation, grouped into Operate / Analyze / Govern. Every item is a
 * real focusable control with an active indicator (bar + surface + colour).
 */
export function Navigation({ route, role, onNavigate, collapsed = false }: NavigationProps) {
  const groups = groupedNav(role);

  return (
    <nav aria-label="Primary" className="flex flex-col gap-5 px-2 py-3">
      {groups.map((group) => (
        <div key={group.key}>
          {collapsed ? (
            <div className="mx-auto mb-2 h-px w-6 bg-hairline" aria-hidden />
          ) : (
            <p className="mb-1.5 px-2.5 text-2xs font-semibold uppercase tracking-wider text-ink-subtle">
              {group.label}
            </p>
          )}
          <ul className="flex flex-col gap-0.5">
            {group.items.map((item) => {
              const Icon = item.icon;
              const active = item.key === route;
              return (
                <li key={item.key}>
                  <button
                    type="button"
                    aria-current={active ? "page" : undefined}
                    aria-label={collapsed ? item.label : undefined}
                    title={collapsed ? item.label : undefined}
                    onClick={() => onNavigate(item.key)}
                    className={cn(
                      "group relative flex w-full items-center gap-2.5 rounded-control py-2 text-sm transition-colors",
                      collapsed ? "justify-center px-0" : "px-2.5",
                      focusRing,
                      active
                        ? "bg-accent-soft font-medium text-accent"
                        : "text-ink-muted hover:bg-surface-raised hover:text-ink",
                    )}
                  >
                    <span
                      aria-hidden
                      className={cn(
                        "absolute left-0 top-1/2 h-4 w-0.5 -translate-y-1/2 rounded-full bg-accent transition-opacity",
                        active ? "opacity-100" : "opacity-0",
                      )}
                    />
                    <Icon size={17} className="shrink-0" aria-hidden />
                    {!collapsed ? <span className="truncate">{item.label}</span> : null}
                  </button>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </nav>
  );
}
