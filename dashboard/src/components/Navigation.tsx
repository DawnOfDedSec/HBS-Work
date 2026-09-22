import { visibleNav, type RouteKey } from "../routes";
import type { AuthUser } from "../types";

type Props = {
  route: RouteKey;
  role: AuthUser["role"];
  onNavigate: (route: RouteKey) => void;
};

/** Primary navigation. Role-gated; every item is a real focusable control. */
export function Navigation({ route, role, onNavigate }: Props) {
  const items = visibleNav(role);
  return (
    <nav aria-label="Primary" className="flex flex-col gap-1 p-3">
      {items.map((item) => {
        const Icon = item.icon;
        const active = item.key === route;
        return (
          <button
            key={item.key}
            type="button"
            aria-current={active ? "page" : undefined}
            onClick={() => onNavigate(item.key)}
            className={`flex items-center gap-2 rounded-md px-3 py-2 text-left text-sm transition focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 ${
              active ? "bg-sky-600/20 text-sky-200" : "text-slate-300 hover:bg-slate-800/70"
            }`}
          >
            <Icon size={16} aria-hidden />
            {item.label}
          </button>
        );
      })}
    </nav>
  );
}
