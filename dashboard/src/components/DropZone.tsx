import { useEffect, useRef, useState, type DragEvent } from "react";
import { FolderDown, Upload } from "lucide-react";
import { api, ApiError } from "../api";
import type { IngestResult } from "../types";

/** Max files per multipart batch (Global Constraints fixed ingest bound). */
export const MAX_BATCH_FILES = 32;

export type ReportArrivedEvent = {
  reportId: number;
  campaignId: number;
  locationId: number;
  hostId: number;
  duplicate: boolean;
  links: { campaign: string; location: string; host: string; report: string };
};

export type DropZoneProps = {
  /** Called for every `report-arrived` SSE event while mounted. */
  onReportArrived?: (event: ReportArrivedEvent) => void;
  className?: string;
};

type UploadState = "queued" | "uploading" | "done" | "error";

type UploadEntry = {
  key: string;
  name: string;
  size: number;
  state: UploadState;
  result?: IngestResult;
  message?: string;
};

function resultLabel(entry: UploadEntry): string {
  if (!entry.result) return entry.state === "error" ? entry.message ?? "failed" : "pending";
  if (entry.result.ok) {
    return entry.result.duplicate ? "duplicate (already ingested)" : "ingested";
  }
  return entry.result.code;
}

/**
 * Drag-and-drop multipart report upload with live SSE refresh.
 *
 * Files are uploaded in one multipart batch (server field name `files`). Each
 * file keeps its own progress/result row, and successful ingests render the
 * exact resolved Campaign → Location → Host links returned by the server.
 */
export function DropZone({ onReportArrived, className }: DropZoneProps) {
  const [entries, setEntries] = useState<UploadEntry[]>([]);
  const [dragging, setDragging] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const filesRef = useRef<File[]>([]);
  const handlerRef = useRef(onReportArrived);

  useEffect(() => {
    handlerRef.current = onReportArrived;
  }, [onReportArrived]);

  // Live refresh: one EventSource for the component lifetime, cleaned up on unmount.
  useEffect(() => {
    if (typeof EventSource === "undefined") return undefined;
    const source = new EventSource("/api/events");
    const onMessage = (event: MessageEvent<string>) => {
      try {
        const data = JSON.parse(event.data) as ReportArrivedEvent;
        handlerRef.current?.(data);
      } catch {
        // Ignore malformed frames; the stream is best-effort refresh only.
      }
    };
    source.addEventListener("report-arrived", onMessage as EventListener);
    return () => {
      source.removeEventListener("report-arrived", onMessage as EventListener);
      source.close();
    };
  }, []);

  function addFiles(incoming: File[]) {
    const allowed = [...filesRef.current, ...incoming];
    if (allowed.length > MAX_BATCH_FILES) {
      setNotice(`At most ${MAX_BATCH_FILES} files per batch; extra files were ignored.`);
    } else {
      setNotice(null);
    }
    const kept = allowed.slice(0, MAX_BATCH_FILES);
    filesRef.current = kept;
    setEntries(
      kept.map((file, index) => ({
        key: `${index}-${file.name}`,
        name: file.name,
        size: file.size,
        state: "queued" as UploadState,
      })),
    );
  }

  function onDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setDragging(false);
    const files = Array.from(event.dataTransfer?.files ?? []);
    if (files.length > 0) addFiles(files);
  }

  async function upload() {
    if (filesRef.current.length === 0) return;
    setBusy(true);
    setNotice(null);
    setEntries((current) => current.map((entry) => ({ ...entry, state: "uploading" })));
    try {
      const response = await api.uploadReports(filesRef.current);
      setEntries((current) =>
        current.map((entry, index) => {
          const match = response.results[index];
          return {
            ...entry,
            state: "done",
            result: match?.result,
          };
        }),
      );
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "upload failed";
      setEntries((current) => current.map((entry) => ({ ...entry, state: "error", message })));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-label="Report upload" className={className}>
      <div
        onDragOver={(event) => {
          event.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        className={`rounded-lg border-2 border-dashed p-6 text-center transition ${
          dragging ? "border-sky-400 bg-sky-950/30" : "border-slate-700 bg-slate-900/40"
        }`}
      >
        <FolderDown className="mx-auto text-slate-400" size={28} aria-hidden />
        <p className="mt-2 text-sm">Drag sealed `.hbs` reports here</p>
        <p className="text-xs text-slate-400">Up to {MAX_BATCH_FILES} files per batch.</p>
        <div className="mt-3 flex flex-wrap items-center justify-center gap-2">
          <input
            ref={inputRef}
            type="file"
            multiple
            className="sr-only"
            onChange={(event) => {
              const files = Array.from(event.target.files ?? []);
              if (files.length > 0) addFiles(files);
              event.target.value = "";
            }}
          />
          <button
            type="button"
            onClick={() => inputRef.current?.click()}
            className="rounded border border-slate-700 px-3 py-1.5 text-sm hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
          >
            Choose files
          </button>
          <button
            type="button"
            disabled={busy || filesRef.current.length === 0}
            onClick={() => void upload()}
            className="inline-flex items-center gap-1 rounded bg-sky-600 px-3 py-1.5 text-sm font-medium disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
          >
            <Upload size={14} aria-hidden /> {busy ? "Uploading…" : "Upload batch"}
          </button>
        </div>
      </div>

      {notice ? (
        <p role="status" className="mt-2 text-xs text-amber-300">
          {notice}
        </p>
      ) : null}

      {entries.length > 0 ? (
        <ul className="mt-3 space-y-2">
          {entries.map((entry) => (
            <li key={entry.key} className="rounded border border-slate-800 bg-slate-900/50 p-3 text-sm">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="break-all font-mono text-xs">{entry.name}</span>
                <span
                  className={
                    entry.state === "error"
                      ? "text-xs text-red-400"
                      : entry.state === "done"
                        ? "text-xs text-emerald-300"
                        : "text-xs text-slate-400"
                  }
                >
                  {resultLabel(entry)}
                </span>
              </div>
              <progress
                className="mt-2 h-1.5 w-full"
                max={100}
                value={entry.state === "done" || entry.state === "error" ? 100 : undefined}
                aria-label={`Upload progress for ${entry.name}`}
              />
              {entry.result?.ok ? (
                <div className="mt-2 flex flex-wrap items-center gap-1 text-xs">
                  {entry.result.duplicate ? (
                    <span className="rounded border border-amber-500 px-1.5 py-0.5 text-amber-300">
                      Duplicate replay
                    </span>
                  ) : null}
                  <a
                    href={entry.result.links.campaign}
                    className="rounded border border-slate-700 px-1.5 py-0.5 hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
                  >
                    Campaign #{entry.result.campaignId}
                  </a>
                  <span aria-hidden className="text-slate-500">
                    →
                  </span>
                  <a
                    href={entry.result.links.location}
                    className="rounded border border-slate-700 px-1.5 py-0.5 hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
                  >
                    Location #{entry.result.locationId}
                  </a>
                  <span aria-hidden className="text-slate-500">
                    →
                  </span>
                  <a
                    href={entry.result.links.host}
                    className="rounded border border-slate-700 px-1.5 py-0.5 hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
                  >
                    Host #{entry.result.hostId}
                  </a>
                  <a
                    href={entry.result.links.report}
                    className="rounded border border-slate-700 px-1.5 py-0.5 text-sky-300 hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
                  >
                    Report #{entry.result.reportId}
                  </a>
                </div>
              ) : null}
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
}
