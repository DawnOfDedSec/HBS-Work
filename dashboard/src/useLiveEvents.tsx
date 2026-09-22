// Live activity stream (SSE) provider.
//
// One `EventSource` subscription per authenticated session, exposed to the whole
// console through context. It is defensive by design: it reconnects with
// exponential backoff, validates every payload before trusting it, never leaks
// the source on unmount, and degrades quietly when `EventSource` is unavailable.

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { useToast } from "./components/ui";

export type LiveStatus = "connecting" | "live" | "reconnecting";

export type LiveEventLinks = {
  reportId: number;
  campaignId: number;
  locationId: number;
  hostId: number;
};

export type LiveEvent = {
  id: string;
  kind: string;
  receivedAt: string;
  duplicate: boolean;
  title: string;
  description: string;
  links: LiveEventLinks;
};

export type LiveEventsApi = {
  status: LiveStatus;
  events: LiveEvent[];
  unread: number;
  /** ISO timestamp of the most recent event, or null when none have arrived. */
  lastEventAt: string | null;
  markAllSeen: () => void;
};

const LiveEventsContext = createContext<LiveEventsApi | null>(null);

const MAX_EVENTS = 12;
const BASE_RETRY_MS = 1_000;
const MAX_RETRY_MS = 30_000;
const EVENT_NAME = "report-arrived";

type ReportArrivedPayload = {
  reportId?: unknown;
  campaignId?: unknown;
  locationId?: unknown;
  hostId?: unknown;
  duplicate?: unknown;
};

function num(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function parseEvent(raw: MessageEvent<string>): LiveEvent | null {
  let parsed: ReportArrivedPayload;
  try {
    parsed = JSON.parse(raw.data) as ReportArrivedPayload;
  } catch {
    return null;
  }
  const reportId = num(parsed.reportId);
  const campaignId = num(parsed.campaignId);
  const locationId = num(parsed.locationId);
  const hostId = num(parsed.hostId);
  if (reportId === null || campaignId === null || locationId === null || hostId === null) return null;
  const duplicate = parsed.duplicate === true;
  return {
    id: `report-${reportId}-${raw.timeStamp ?? Date.now()}`,
    kind: EVENT_NAME,
    receivedAt: new Date().toISOString(),
    duplicate,
    title: duplicate ? "Duplicate report received" : "New report received",
    description: `Report #${reportId} · host #${hostId} · campaign #${campaignId}`,
    links: { reportId, campaignId, locationId, hostId },
  };
}

export function LiveEventsProvider({ children }: { children: ReactNode }) {
  const toast = useToast();
  const [status, setStatus] = useState<LiveStatus>("connecting");
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [unread, setUnread] = useState(0);
  const [lastEventAt, setLastEventAt] = useState<string | null>(null);

  // Latest toast API without resubscribing the stream when it changes identity.
  const toastRef = useRef(toast);
  toastRef.current = toast;

  useEffect(() => {
    if (typeof window === "undefined" || typeof EventSource === "undefined") {
      setStatus("reconnecting");
      return;
    }
    let disposed = false;
    let source: EventSource | null = null;
    let retryTimer: number | null = null;
    let attempt = 0;

    const connect = () => {
      if (disposed) return;
      source = new EventSource("/api/events", { withCredentials: true });

      source.onopen = () => {
        attempt = 0;
        setStatus("live");
      };

      source.addEventListener(EVENT_NAME, (event) => {
        const parsed = parseEvent(event as MessageEvent<string>);
        if (!parsed) return;
        setEvents((current) => [parsed, ...current].slice(0, MAX_EVENTS));
        setUnread((current) => current + 1);
        setLastEventAt(parsed.receivedAt);
        toastRef.current.info(parsed.title, { description: parsed.description });
      });

      source.onerror = () => {
        source?.close();
        source = null;
        if (disposed) return;
        setStatus("reconnecting");
        attempt += 1;
        const delay = Math.min(MAX_RETRY_MS, BASE_RETRY_MS * 2 ** Math.min(attempt, 5));
        retryTimer = window.setTimeout(connect, delay);
      };
    };

    connect();

    return () => {
      disposed = true;
      if (retryTimer !== null) window.clearTimeout(retryTimer);
      source?.close();
      source = null;
    };
  }, []);

  const markAllSeen = useCallback(() => setUnread(0), []);

  const value = useMemo<LiveEventsApi>(
    () => ({ status, events, unread, lastEventAt, markAllSeen }),
    [status, events, unread, lastEventAt, markAllSeen],
  );

  return <LiveEventsContext.Provider value={value}>{children}</LiveEventsContext.Provider>;
}

/** Access the live event stream. Throws outside `LiveEventsProvider`. */
export function useLiveEvents(): LiveEventsApi {
  const context = useContext(LiveEventsContext);
  if (!context) throw new Error("useLiveEvents must be used within a LiveEventsProvider");
  return context;
}
