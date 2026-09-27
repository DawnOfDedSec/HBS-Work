import { useEffect, useRef, useState, type DragEvent } from "react";
import { FileUp, FolderDown, Upload } from "lucide-react";
import { api, ApiError } from "../api";
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  ProgressBar,
  useToast,
} from "./ui";
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

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
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
  const toast = useToast();

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
        current.map((entry, index) => ({
          ...entry,
          state: "done",
          result: response.results[index]?.result,
        })),
      );
      const ingested = response.results.filter((item) => item.result.ok && !item.result.duplicate).length;
      toast.success("Batch uploaded", { description: `${ingested} ingested` });
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "upload failed";
      setEntries((current) => current.map((entry) => ({ ...entry, state: "error", message })));
      toast.error("Upload failed", { description: message });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card aria-label="Report upload" className={className}>
      <CardHeader
        icon={FolderDown}
        title="Ingest sealed reports"
        description={`Drag .hbs envelopes or choose files. Up to ${MAX_BATCH_FILES} files per batch.`}
        actions={filesRef.current.length > 0 ? <Badge tone="accent">{filesRef.current.length} queued</Badge> : null}
      />
      <CardBody className="flex flex-col gap-3">
        <div
          onDragOver={(event) => {
            event.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          className={
            dragging
              ? "rounded-panel border-2 border-dashed border-accent bg-accent-soft/50 p-6 text-center"
              : "rounded-panel border-2 border-dashed border-control-edge bg-surface-sunken/60 p-6 text-center"
          }
        >
          <FileUp className="mx-auto text-ink-subtle" size={26} aria-hidden />
          <p className="mt-2 text-sm text-ink">Drag sealed `.hbs` reports here</p>
          <p className="text-xs text-ink-muted">Files are hashed and deduplicated server-side.</p>
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
            <Button variant="secondary" onClick={() => inputRef.current?.click()}>
              Choose files
            </Button>
            <Button
              variant="primary"
              icon={Upload}
              disabled={busy || filesRef.current.length === 0}
              loading={busy}
              onClick={() => void upload()}
            >
              Upload batch
            </Button>
          </div>
        </div>

        {notice ? (
          <p role="status" className="text-xs text-high">
            {notice}
          </p>
        ) : null}

        {entries.length === 0 ? (
          <EmptyState title="No files queued" detail="Choose or drop sealed reports to ingest them." />
        ) : (
          <ul className="flex flex-col gap-2">
            {entries.map((entry) => (
              <li key={entry.key} className="hbs-inset flex flex-col gap-2 p-3 text-sm">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="break-all font-mono text-xs text-ink-muted">{entry.name}</span>
                  <span className="flex items-center gap-2">
                    <span className="text-2xs text-ink-subtle">{formatSize(entry.size)}</span>
                    <Badge
                      tone={
                        entry.state === "error"
                          ? "critical"
                          : entry.state === "done"
                            ? "compliant"
                            : entry.state === "uploading"
                              ? "accent"
                              : "neutral"
                      }
                    >
                      {resultLabel(entry)}
                    </Badge>
                  </span>
                </div>
                <ProgressBar
                  value={entry.state === "done" || entry.state === "error" ? 100 : entry.state === "uploading" ? 60 : 0}
                  tone={entry.state === "error" ? "critical" : entry.state === "done" ? "compliant" : "accent"}
                  className={entry.state === "uploading" ? "animate-pulse" : undefined}
                />
                {entry.result?.ok ? (
                  <div className="flex flex-wrap items-center gap-1.5 text-2xs">
                    {entry.result.duplicate ? <Badge tone="high">Duplicate replay</Badge> : null}
                    <a
                      href={entry.result.links.campaign}
                      className="rounded-full border border-control-edge bg-surface-raised px-2 py-0.5 text-ink-muted hover:text-ink"
                    >
                      Campaign #{entry.result.campaignId}
                    </a>
                    <span aria-hidden className="text-ink-subtle">
                      →
                    </span>
                    <a
                      href={entry.result.links.location}
                      className="rounded-full border border-control-edge bg-surface-raised px-2 py-0.5 text-ink-muted hover:text-ink"
                    >
                      Location #{entry.result.locationId}
                    </a>
                    <span aria-hidden className="text-ink-subtle">
                      →
                    </span>
                    <a
                      href={entry.result.links.host}
                      className="rounded-full border border-control-edge bg-surface-raised px-2 py-0.5 text-ink-muted hover:text-ink"
                    >
                      Host #{entry.result.hostId}
                    </a>
                    <a
                      href={entry.result.links.report}
                      className="rounded-full border border-accent/40 bg-accent-soft px-2 py-0.5 text-accent"
                    >
                      Report #{entry.result.reportId}
                    </a>
                  </div>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </CardBody>
    </Card>
  );
}
