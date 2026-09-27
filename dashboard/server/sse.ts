// Tiny in-process SSE event bus (Task 48).
//
// The ingest pipeline emits `report-arrived` only after a report transaction
// has committed. Payloads carry IDs and route links only - never evidence,
// never decrypted findings, never credentials.

export type SseEvent = {
  event: string;
  data: unknown;
};

export type SseListener = (event: SseEvent) => void;

export class EventBus {
  private readonly listeners = new Set<SseListener>();

  /** Subscribe and get an unsubscribe function. */
  subscribe(listener: SseListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  unsubscribe(listener: SseListener): void {
    this.listeners.delete(listener);
  }

  /** Emit to every subscriber. A throwing listener never blocks the others. */
  emit(event: SseEvent): void {
    for (const listener of [...this.listeners]) {
      try {
        listener(event);
      } catch {
        // A broken SSE client must not break ingest.
      }
    }
  }

  clear(): void {
    this.listeners.clear();
  }

  get size(): number {
    return this.listeners.size;
  }
}

/** Process-wide bus the HTTP layer can subscribe to for live refresh. */
export const reportEvents = new EventBus();

export type ReportArrivedLinks = {
  campaign: string;
  location: string;
  host: string;
  report: string;
};

export type ReportArrivedPayload = {
  reportId: number;
  campaignId: number;
  locationId: number;
  hostId: number;
  duplicate: boolean;
  links: ReportArrivedLinks;
};

export const REPORT_ARRIVED_EVENT = "report-arrived";

/** Emit the post-commit live-refresh event. IDs/links only. */
export function emitReportArrived(
  payload: ReportArrivedPayload,
  bus: EventBus = reportEvents,
): void {
  bus.emit({ event: REPORT_ARRIVED_EVENT, data: payload });
}
