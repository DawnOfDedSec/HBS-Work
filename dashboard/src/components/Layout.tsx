import { useEffect, useRef, useState, type ReactNode } from "react";
import {
  ChevronDown,
  ChevronsLeft,
  ChevronsRight,
  LogOut,
  Menu,
  Moon,
  PanelLeft,
  Search,
  ShieldCheck,
  Sun,
  X,
} from "lucide-react";
import { Navigation } from "./Navigation";
import { CommandPalette } from "./CommandPalette";
import { LiveActivity } from "./LiveActivity";
import { Breadcrumbs, IconButton, Kbd, type BreadcrumbItem } from "./ui";
import { cn, focusRing } from "./ui/cn";
import { navItem, routeLabel, type RouteKey } from "../routes";
import type { AuthUser } from "../types";
import { useTheme } from "../useTheme";

const COLLAPSE_KEY = "hbs-nav-collapsed";

export type LayoutProps = {
  user: AuthUser;
  route: RouteKey;
  onNavigate: (route: RouteKey) => void;
  onDrilldown: (query: string) => void;
  onLogout: () => void;
  /** Open a report by id from the live-activity feed. */
  onOpenReport?: (reportId: number) => void;
  /** Open a host by id from the live-activity feed. */
  onOpenHost?: (hostId: number) => void;
  /** Open a reviewed network device by id from the live-activity feed. */
  onOpenNetworkDevice?: (deviceId: number) => void;
  /** Open a campaign by id from the command palette. */
  onOpenCampaign?: (campaignId: number) => void;
  breadcrumbs?: BreadcrumbItem[];
  children: ReactNode;
};

function initials(username: string): string {
  return username.slice(0, 2).toUpperCase();
}

function roleLabel(role: AuthUser["role"]): string {
  if (role === "super_admin") return "Super admin";
  if (role === "auditor") return "Auditor";
  return "Viewer";
}

/**
 * The console shell: collapsible grouped sidebar, topbar with breadcrumbs and
 * global search, theme toggle, and a keyboard-accessible user menu. Owns the
 * command palette and its Ctrl/Cmd-K shortcut.
 */
export function Layout({
  user,
  route,
  onNavigate,
  onDrilldown,
  onLogout,
  onOpenReport,
  onOpenHost,
  onOpenNetworkDevice,
  onOpenCampaign,
  breadcrumbs,
  children,
}: LayoutProps) {
  const { theme, toggle } = useTheme();
  const [collapsed, setCollapsed] = useState<boolean>(() => {
    if (typeof window === "undefined") return false;
    return window.localStorage.getItem(COLLAPSE_KEY) === "1";
  });
  const [mobileOpen, setMobileOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    try {
      window.localStorage.setItem(COLLAPSE_KEY, collapsed ? "1" : "0");
    } catch {
      // storage may be unavailable; the session value still applies
    }
  }, [collapsed]);

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setPaletteOpen((value) => !value);
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  useEffect(() => {
    if (!menuOpen) return;
    function onPointerDown(event: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) setMenuOpen(false);
    }
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") setMenuOpen(false);
    }
    document.addEventListener("mousedown", onPointerDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onPointerDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [menuOpen]);

  const crumbs: BreadcrumbItem[] =
    breadcrumbs && breadcrumbs.length > 0
      ? breadcrumbs
      : [{ label: routeLabel(route), icon: navItem(route)?.icon }];

  return (
    <div className="flex min-h-screen bg-canvas text-ink">
      {/* Mobile backdrop */}
      {mobileOpen ? (
        <div
          className="fixed inset-0 z-30 bg-canvas/70 backdrop-blur-sm md:hidden"
          onClick={() => setMobileOpen(false)}
          aria-hidden
        />
      ) : null}

      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-40 flex w-64 shrink-0 flex-col border-r border-hairline bg-canvas-elevated transition-transform duration-200 md:static md:translate-x-0",
          collapsed ? "md:w-[4.5rem]" : "md:w-64",
          mobileOpen ? "translate-x-0" : "-translate-x-full",
        )}
      >
        <div className={cn("flex h-14 items-center gap-2.5 border-b border-hairline px-3", collapsed && "md:justify-center md:px-0")}>
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-control bg-accent-soft text-accent">
            <ShieldCheck size={18} aria-hidden />
          </span>
          {!collapsed ? (
            <span className="min-w-0">
              <span className="block truncate text-sm font-semibold tracking-tight">HBS Console</span>
              <span className="block truncate text-2xs text-ink-subtle">Security posture</span>
            </span>
          ) : null}
          <IconButton
            icon={X}
            label="Close navigation"
            className="ml-auto md:hidden"
            onClick={() => setMobileOpen(false)}
          />
        </div>

        <div className="hbs-scroll min-h-0 flex-1 overflow-y-auto">
          <Navigation route={route} role={user.role} onNavigate={onNavigate} collapsed={collapsed} />
        </div>

        <div className={cn("hidden border-t border-hairline p-2 md:block", collapsed && "px-1")}>
          <button
            type="button"
            onClick={() => setCollapsed((value) => !value)}
            aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}
            aria-pressed={collapsed}
            className={cn(
              "flex w-full items-center gap-2 rounded-control px-2.5 py-2 text-xs text-ink-subtle hover:bg-surface-raised hover:text-ink",
              focusRing,
              collapsed && "justify-center px-0",
            )}
          >
            {collapsed ? <ChevronsRight size={16} aria-hidden /> : <ChevronsLeft size={16} aria-hidden />}
            {!collapsed ? <span>Collapse</span> : null}
          </button>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-20 flex h-14 items-center gap-3 border-b border-hairline bg-canvas-elevated/85 px-3 backdrop-blur sm:px-4">
          <IconButton
            icon={Menu}
            label="Open navigation"
            className="md:hidden"
            onClick={() => setMobileOpen(true)}
          />
          <IconButton
            icon={PanelLeft}
            label={collapsed ? "Expand navigation" : "Collapse navigation"}
            className="hidden md:inline-flex"
            onClick={() => setCollapsed((value) => !value)}
          />

          <div className="hidden min-w-0 md:block">
            <Breadcrumbs items={crumbs} />
          </div>

          <div className="flex flex-1 items-center justify-end gap-2">
            <button
              type="button"
              onClick={() => setPaletteOpen(true)}
              className={cn(
                "group flex h-9 items-center gap-2 rounded-control border border-hairline bg-surface px-3 text-sm text-ink-subtle transition-colors hover:border-hairline-strong hover:text-ink",
                focusRing,
              )}
            >
              <Search size={15} aria-hidden />
              <span className="hidden sm:inline">Search…</span>
              <span className="ml-2 hidden items-center gap-0.5 sm:inline-flex">
                <Kbd>⌘</Kbd>
                <Kbd>K</Kbd>
              </span>
            </button>

            <IconButton
              icon={theme === "dark" ? Sun : Moon}
              label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
              variant="secondary"
              onClick={toggle}
            />

            <div className="hbs-presentation-hide">
              <LiveActivity onOpenReport={onOpenReport} onOpenHost={onOpenHost} onOpenNetworkDevice={onOpenNetworkDevice} />
            </div>

            <div className="relative" ref={menuRef}>
              <button
                type="button"
                aria-haspopup="menu"
                aria-expanded={menuOpen}
                onClick={() => setMenuOpen((value) => !value)}
                className={cn(
                  "flex h-9 items-center gap-2 rounded-control border border-hairline bg-surface px-2 pr-2.5 text-sm hover:border-hairline-strong",
                  focusRing,
                )}
              >
                <span className="flex h-6 w-6 items-center justify-center rounded-full bg-accent-soft text-2xs font-semibold text-accent">
                  {initials(user.username)}
                </span>
                <span className="hidden max-w-32 truncate text-ink sm:inline">{user.username}</span>
                <ChevronDown size={14} className="text-ink-subtle" aria-hidden />
              </button>

              {menuOpen ? (
                <div
                  role="menu"
                  aria-label="User menu"
                  className="absolute right-0 top-11 z-50 w-60 overflow-hidden rounded-panel border border-hairline bg-surface-overlay p-1.5 shadow-overlay animate-scale-in"
                >
                  <div className="px-2.5 py-2">
                    <p className="truncate text-sm font-medium text-ink">{user.username}</p>
                    <p className="mt-0.5 inline-flex items-center rounded-full border border-hairline bg-surface-raised px-1.5 py-0.5 text-2xs text-ink-muted">
                      {roleLabel(user.role)}
                    </p>
                  </div>
                  <div className="my-1 h-px bg-hairline-soft" />
                  <button
                    type="button"
                    role="menuitem"
                    onClick={onLogout}
                    className={cn(
                      "flex w-full items-center gap-2 rounded-control px-2.5 py-2 text-sm text-ink-muted hover:bg-surface-raised hover:text-ink",
                      focusRing,
                    )}
                  >
                    <LogOut size={15} aria-hidden />
                    Sign out
                  </button>
                </div>
              ) : null}
            </div>
          </div>
        </header>

        <main className="min-w-0 flex-1 p-4 sm:p-6">{children}</main>
      </div>

      <CommandPalette
        open={paletteOpen}
        onOpenChange={setPaletteOpen}
        role={user.role}
        currentRoute={route}
        onNavigate={onNavigate}
        onDrilldown={onDrilldown}
        onOpenCampaign={onOpenCampaign}
        theme={theme}
        onToggleTheme={toggle}
      />
    </div>
  );
}
