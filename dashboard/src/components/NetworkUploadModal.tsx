// Upload dialog for network device / firewall configuration files.
// Posts multipart to /api/network/upload with the campaign/location target and
// renders a per-file result list (parsed vendor, review score, severity).

import { useCallback, useRef, useState } from "react";
import { FileUp, TriangleAlert, Upload } from "lucide-react";
import { api, ApiError } from "../api";
import { Badge, Button, Modal, ProgressBar, useToast } from "./ui";
import { sanitizeText } from "./EvidenceDrawer";
import { scoreTone } from "./NetworkFindings";
import type { NetworkUploadResult } from "../network-types";

export const MAX_NETWORK_BATCH_FILES = 32;

type EntryState =
  | { kind: "queued" }
  | { kind: "uploading" }
  | { kind: "done"; result: NetworkUploadResult }
  | { kind: "error"; message: string };

export type NetworkUploadModalProps = {
  open: boolean;
  campaignId: number;
  locationId: number;
  locationName: string;
  onClose: () => void;
  /** Called after at least one config was accepted, so lists can refresh. */
  onUploaded?: () => void;
};

/** Drag-and-drop / file-picker batch upload of device configurations. */
export function NetworkUploadModal({ open, campaignId, locationId, locationName, onClose, onUploaded }: NetworkUploadModalProps) {
  const toast = useToast();
  const inputRef = useRef<HTMLInputElement>(null);
  const [files, setFiles] = useState<File[]>([]);
  const [entries, setEntries] = useState<Map<string, EntryState>>(new Map());
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading] = useState(false);

  const addFiles = useCallback((incoming: File[]) => {
    setFiles((current) => {
      const merged = [...current];
      for (const file of incoming) {
        if (merged.length >= MAX_NETWORK_BATCH_FILES) break;
        if (!merged.some((existing) => existing.name === file.name && existing.size === file.size)) merged.push(file);
      }
      return merged;
    });
    setEntries((current) => {
      const next = new Map(current);
      for (const file of incoming) next.set(file.name, { kind: "queued" });
      return next;
    });
  }, []);

  function removeFile(name: string) {
    setFiles((current) => current.filter((file) => file.name !== name));
    setEntries((current) => {
      const next = new Map(current);
      next.delete(name);
      return next;
    });
  }

  async function upload() {
    if (files.length === 0) return;
    setUploading(true);
    setEntries((current) => {
      const next = new Map(current);
      for (const file of files) next.set(file.name, { kind: "uploading" });
      return next;
    });
    try {
      const response = await api.uploadNetworkConfigs(campaignId, locationId, files);
      setEntries((current) => {
        const next = new Map(current);
        for (const entry of response.results) {
          next.set(entry.name, { kind: "done", result: entry.result });
        }
        return next;
      });
      const accepted = response.results.filter((entry) => entry.result.ok).length;
      const duplicates = response.results.filter((entry) => entry.result.ok && entry.result.duplicate).length;
      const rejected = response.results.length - accepted;
      if (accepted > 0) {
        toast.success(`${accepted - duplicates} config(s) reviewed`, {
          description: duplicates > 0 ? `${duplicates} duplicate(s) skipped · ${rejected} rejected` : `${rejected} rejected`,
        });
        onUploaded?.();
      } else {
        toast.error("No configuration accepted", { description: `${rejected} file(s) rejected` });
      }
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "upload failed";
      toast.error("Could not upload configurations", { description: message });
      setEntries((current) => {
        const next = new Map(current);
        for (const file of files) if (next.get(file.name)?.kind === "uploading") next.set(file.name, { kind: "error", message });
        return next;
      });
    } finally {
      setUploading(false);
    }
  }

  function reset() {
    setFiles([]);
    setEntries(new Map());
    setDragging(false);
    setUploading(false);
  }

  function close() {
    if (uploading) return;
    reset();
    onClose();
  }

  const accepted = [...entries.values()].filter((entry) => entry.kind === "done" && entry.result.ok).length;
  const progress = files.length === 0 ? 0 : Math.round(([...entries.values()].filter((entry) => entry.kind !== "queued" && entry.kind !== "uploading").length / files.length) * 100);

  return (
    <Modal
      open={open}
      onClose={close}
      size="lg"
      title="Upload device configurations"
      description={`Parse and review firewall / network configs for ${sanitizeText(locationName)}.`}
      footer={
        <>
          <Button variant="ghost" onClick={close} disabled={uploading}>
            Close
          </Button>
          <Button
            variant="primary"
            icon={Upload}
            loading={uploading}
            disabled={files.length === 0}
            onClick={() => void upload()}
          >
            Review {files.length > 0 ? `${files.length} file(s)` : ""}
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-4">
        <div
          role="button"
          tabIndex={0}
          aria-label="Add configuration files"
          onClick={() => inputRef.current?.click()}
          onKeyDown={(event) => {
            if (event.key === "Enter" || event.key === " ") {
              event.preventDefault();
              inputRef.current?.click();
            }
          }}
          onDragOver={(event) => {
            event.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(event) => {
            event.preventDefault();
            setDragging(false);
            addFiles([...event.dataTransfer.files]);
          }}
          className={`flex cursor-pointer flex-col items-center gap-2 rounded-control border border-dashed p-6 text-center transition-colors ${
            dragging ? "border-accent bg-accent/5" : "border-hairline hover:border-hairline-strong"
          }`}
        >
          <FileUp size={22} aria-hidden className="text-ink-subtle" />
          <span className="text-sm text-ink">Drop configuration files here, or click to browse</span>
          <span className="text-2xs text-ink-subtle">
            Cisco IOS/NX-OS/ASA/WLC, Juniper, Palo Alto, Fortinet, Aruba, Ubiquiti, F5, SonicWall · max 4 MiB each ·
            up to {MAX_NETWORK_BATCH_FILES} files
          </span>
          <input
            ref={inputRef}
            type="file"
            multiple
            className="sr-only"
            onChange={(event) => {
              addFiles([...(event.target.files ?? [])]);
              event.target.value = "";
            }}
          />
        </div>

        {files.length > 0 ? (
          <>
            <ProgressBar value={progress} aria-label="Upload progress" />
            <ul className="hbs-scroll flex max-h-72 flex-col gap-1.5 overflow-auto">
              {files.map((file) => {
                const entry = entries.get(file.name) ?? { kind: "queued" as const };
                return (
                  <li key={`${file.name}-${file.size}`} className="hbs-inset flex flex-wrap items-center justify-between gap-2 p-2.5">
                    <div className="flex min-w-0 flex-col">
                      <span className="truncate text-sm text-ink">{sanitizeText(file.name)}</span>
                      <span className="text-2xs text-ink-subtle">{(file.size / 1024).toFixed(1)} KiB</span>
                    </div>
                    <div className="flex items-center gap-2">
                      {entry.kind === "done" ? (
                        entry.result.ok ? (
                          <>
                            <Badge tone="info">{sanitizeText(entry.result.vendorLabel)}</Badge>
                            <Badge tone={scoreTone(entry.result.score)}>score {entry.result.score.toFixed(0)}</Badge>
                            {entry.result.findings.critical + entry.result.findings.high > 0 ? (
                              <Badge tone="critical">
                                {entry.result.findings.critical + entry.result.findings.high} crit/high
                              </Badge>
                            ) : null}
                            {entry.result.duplicate ? <Badge tone="neutral">duplicate</Badge> : null}
                          </>
                        ) : (
                          <>
                            <TriangleAlert size={13} aria-hidden className="text-critical" />
                            <Badge tone="critical">{sanitizeText(entry.result.code)}</Badge>
                            <span className="text-2xs text-ink-subtle">{sanitizeText(entry.result.error)}</span>
                          </>
                        )
                      ) : entry.kind === "error" ? (
                        <Badge tone="critical">{sanitizeText(entry.message)}</Badge>
                      ) : entry.kind === "uploading" ? (
                        <Badge tone="accent">reviewing…</Badge>
                      ) : (
                        <Badge tone="neutral">queued</Badge>
                      )}
                      {entry.kind === "queued" ? (
                        <Button variant="ghost" size="sm" onClick={() => removeFile(file.name)} aria-label={`Remove ${file.name}`}>
                          Remove
                        </Button>
                      ) : null}
                    </div>
                  </li>
                );
              })}
            </ul>
            {accepted > 0 ? (
              <p className="text-2xs text-ink-subtle">
                Devices and review reports appear alongside the machines of this location once the upload completes.
              </p>
            ) : null}
          </>
        ) : null}
      </div>
    </Modal>
  );
}
