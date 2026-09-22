import type { ReactNode } from "react";
import { LogOut, Moon, Sun } from "lucide-react";
import { Navigation } from "./Navigation";
import type { RouteKey } from "../routes";
import type { AuthUser } from "../types";
import { useTheme } from "../useTheme";

type Props = {
  user: AuthUser;
  route: RouteKey;
  onNavigate: (route: RouteKey) => void;
  onLogout: () => void;
  children: ReactNode;
};

export function Layout({ user, route, onNavigate, onLogout, children }: Props) {
  const { theme, toggle } = useTheme();
  return (
    <div className="flex min-h-full">
      <aside className="w-60 shrink-0 border-r border-slate-800 bg-slate-950/60">
        <div className="px-4 py-4 text-sm font-semibold tracking-wide">HBS Console</div>
        <Navigation route={route} role={user.role} onNavigate={onNavigate} />
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-between border-b border-slate-800 px-4 py-3">
          <h1 className="text-sm font-medium capitalize">{route}</h1>
          <div className="flex items-center gap-3 text-sm">
            <span className="text-slate-400">
              {user.username} · {user.role}
            </span>
            <button
              type="button"
              onClick={toggle}
              aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
              className="rounded-md border border-slate-700 p-1.5 hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
            >
              {theme === "dark" ? <Sun size={16} aria-hidden /> : <Moon size={16} aria-hidden />}
            </button>
            <button
              type="button"
              onClick={onLogout}
              className="flex items-center gap-1 rounded-md border border-slate-700 px-2 py-1.5 hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
            >
              <LogOut size={16} aria-hidden /> Sign out
            </button>
          </div>
        </header>
        <main className="min-w-0 flex-1 p-6">{children}</main>
      </div>
    </div>
  );
}
