import { useEffect, useRef, useState } from "react";
import { Bell, Network, Server, Wifi, WifiOff } from "lucide-react";
import { Badge } from "./ui";
import { cn, focusRing } from "./ui/cn";
import { useLiveEvents, type LiveStatus } from "../useLiveEvents";
import { useRelativeTime } from "../useRelativeTime";

export type LiveActivityProps = {
  /** Open a report by id (App-owned navigation). */
  onOpenReport?: (reportId: number) => void;
  /** Open a host by id (App-owned navigation). */
  onOpenHost?: (hostId: number) => void;
  /** Open a reviewed network device by id (App-owned navigation). */
  onOpenNetworkDevice?: (deviceId: number) => void;
};

const STATUS_META: Record<LiveStatus, { label: string; dot: string; text: string }> = {
  live: { label: "Live", dot: "bg-compliant", text: "text-compliant" },
  connecting: { label: "Connecting", dot: "bg-accent", text: "text-accent" },
  reconnecting: { label: "Reconnecting", dot: "bg-high", text: "text-high" },
};

function TimeAgo({ at }: { at: string }) {
  const label = useRelativeTime(at);
  return <span className="tabular-nums text-2xs text-ink-subtle">{label}</span>;
}

/**
 * Topbar live indicator + notification bell. Subscribes to the shared SSE
 * context and lists the most recent `report-arrived` events with in-app links.
 */
export function LiveActivity({ onOpenReport, onOpenHost, onOpenNetworkDevice }: LiveActivityProps) {
  const { status, events, unread, markAllSeen } = useLiveEvents();
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);
  const meta = STATUS_META[status];
  const reconnect = status === "reconnecting";

  useEffect(() => {
    if (!open) return;
    function onPointerDown(event: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) setOpen(false);
    }
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", onPointerDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onPointerDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <div className="flex items-center gap-1.5">
      <span
        role="status"
        aria-live="polite"
        title={reconnect ? "Live updates are reconnecting" : "Connected to live updates"}
        className={cn("hidden items-center gap-1.5 rounded-full border border-hairline px-2 py-1 text-2xs sm:inline-flex", meta.text)}
      >
        <span className={cn("h-1.5 w-1.5 rounded-full", meta.dot, status === "live" && "animate-pulse")} aria-hidden />
        {meta.label}
      </span>

      <div className="relative" ref={containerRef}>
        <button
          type="button"
          aria-haspopup="menu"
          aria-expanded={open}
          aria-label={unread > 0 ? `Notifications, ${unread} unread` : "Notifications"}
          onClick={() => {
            setOpen((value) => {
              const next = !value;
              if (next) markAllSeen();
              return next;
            });
          }}
          className={cn(
            "relative inline-flex h-9 w-9 items-center justify-center rounded-control border border-hairline bg-surface text-ink-muted hover:border-hairline-strong hover:text-ink",
            focusRing,
          )}
        >
          {reconnect ? <WifiOff size={16} aria-hidden /> : <Wifi size={16} aria-hidden />}
          {unread > 0 ? (
            <span className="absolute -right-1 -top-1 inline-flex min-w-4 items-center justify-center rounded-full bg-accent px-1 text-2xs font-semibold text-accent-contrast tabular-nums">
              {unread > 9 ? "9+" : unread}
            </span>
          ) : null}
        </button>

        {open ? (
          <div
            role="menu"
            aria-label="Recent live events"
            className="absolute right-0 top-11 z-50 w-80 overflow-hidden rounded-panel border border-hairline bg-surface-overlay p-1.5 shadow-overlay animate-scale-in"
          >
            <div className="flex items-center justify-between px-2.5 py-2">
              <span className="inline-flex items-center gap-1.5 text-sm font-medium text-ink">
                <Bell size={14} aria-hidden /> Live activity
              </span>
              <Badge tone={status === "live" ? "compliant" : reconnect ? "high" : "accent"}>{meta.label}</Badge>
            </div>
            <div className="my-1 h-px bg-hairline-soft" />
            {events.length === 0 ? (
              <p className="px-2.5 py-6 text-center text-xs text-ink-muted">
                No report events yet. New scans appear here as they arrive.
              </p>
            ) : (
              <ul className="hbs-scroll max-h-80 overflow-y-auto">
                {events.map((event) => (
                  <li key={event.id} className="rounded-control px-2.5 py-2 hover:bg-surface-raised">
                    <div className="flex items-start justify-between gap-2">
                      <p className="text-xs font-medium text-ink">{event.title}</p>
                      <TimeAgo at={event.receivedAt} />
                    </div>
                    <p className="mt-0.5 font-mono text-2xs text-ink-subtle">{event.description}</p>
                    <div className="mt-1.5 flex items-center gap-2">
                      {onOpenReport && event.links.deviceId === null ? (
                        <button
                          type="button"
                          role="menuitem"
                          onClick={() => {
                            onOpenReport(event.links.reportId as number);
                            setOpen(false);
                          }}
                          className={cn("rounded text-2xs font-medium text-accent hover:underline", focusRing)}
                        >
                          Open report
                        </button>
                      ) : null}
                      {onOpenNetworkDevice && event.links.deviceId !== null ? (
                        <button
                          type="button"
                          role="menuitem"
                          onClick={() => {
                            onOpenNetworkDevice(event.links.deviceId as number);
                            setOpen(false);
                          }}
                          className={cn("inline-flex items-center gap-1 rounded text-2xs text-ink-muted hover:text-ink", focusRing)}
                        >
                          <Network size={11} aria-hidden /> Device
                        </button>
                      ) : null}
                      {onOpenHost && event.links.hostId !== null ? (
                        <button
                          type="button"
                          role="menuitem"
                          onClick={() => {
                            onOpenHost(event.links.hostId as number);
                            setOpen(false);
                          }}
                          className={cn("inline-flex items-center gap-1 rounded text-2xs text-ink-muted hover:text-ink", focusRing)}
                        >
                          <Server size={11} aria-hidden /> Host
                        </button>
                      ) : null}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        ) : null}
      </div>
    </div>
  );
}
