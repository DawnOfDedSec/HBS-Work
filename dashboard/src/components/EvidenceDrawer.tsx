import { useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import { Check, Copy, X } from "lucide-react";
import type { EvidenceBlock, FallbackAttempt, RunContext } from "../types";

/**
 * The evidence a drawer renders comes straight off `GET /api/reports/:id`
 * (each `results[]` entry is the serialized extractor `CheckResult`). These
 * fields are the ones the drawer needs; everything else on the result is
 * ignored.
 */
export type EvidenceFinding = {
  checkId: string;
  title: string;
  severity: string;
  status: string;
  category: string;
  impact: string;
  recommendation: string;
  references: string[];
  repro: string;
  evidence: string;
  degradedReason?: string | null;
  fallbackLog: FallbackAttempt[];
  evidenceBlocks: EvidenceBlock[];
  runContext: RunContext;
};

export type EvidenceDrawerProps = {
  open: boolean;
  finding: EvidenceFinding | null;
  /** Optional report/host context shown in the header. */
  reportId?: number | null;
  hostname?: string | null;
  onClose: () => void;
};

/** Strip control characters and line/paragraph separators so hostile report text cannot spoof the UI. */
export function sanitizeText(value: unknown): string {
  if (typeof value !== "string") return "";
  return value.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, " ");
}

/** Only http(s) URLs may become links; every other scheme stays inert text. */
export function safeHref(value: unknown): string | null {
  if (typeof value !== "string") return null;
  return /^https?:\/\/[^\s]+$/i.test(value.trim()) ? value.trim() : null;
}

const FOCUSABLE =
  'a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])';

const SEVERITY_TONE: Record<string, string> = {
  Critical: "border-red-500/60 bg-red-500/10 text-red-200",
  High: "border-amber-500/60 bg-amber-500/10 text-amber-200",
  Medium: "border-yellow-500/50 bg-yellow-500/10 text-yellow-100",
  Low: "border-sky-500/50 bg-sky-500/10 text-sky-100",
  Informational: "border-slate-500/50 bg-slate-500/10 text-slate-200",
};

const STATUS_TONE: Record<string, string> = {
  NonCompliant: "border-red-500/60 bg-red-500/10 text-red-200",
  DegradedPartial: "border-amber-500/60 bg-amber-500/10 text-amber-200",
  Error: "border-fuchsia-500/60 bg-fuchsia-500/10 text-fuchsia-200",
  Compliant: "border-emerald-500/60 bg-emerald-500/10 text-emerald-200",
  NotApplicable: "border-slate-500/50 bg-slate-500/10 text-slate-300",
};

type ContextWindow = {
  before: string[];
  offending: string | null;
  after: string[];
};

/** Derive the exact ±3 context window around the offending line. */
export function contextWindow(block: EvidenceBlock): ContextWindow {
  const lines = Array.isArray(block.context) ? block.context : [];
  if (lines.length === 0) return { before: [], offending: null, after: [] };
  const index = Math.min(Math.max(block.targetIndex, 0), lines.length - 1);
  return {
    before: lines.slice(Math.max(0, index - 3), index),
    offending: lines[index] ?? null,
    after: lines.slice(index + 1, index + 4),
  };
}

/**
 * Accessible, modal evidence drawer. Escape closes, focus is moved in on open,
 * restored on close, and Tab is trapped inside while open.
 */
export function EvidenceDrawer({ open, finding, reportId, hostname, onClose }: EvidenceDrawerProps) {
  const titleId = useId();
  const dialogRef = useRef<HTMLDivElement>(null);
  const restoreFocusRef = useRef<HTMLElement | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!open) return;
    restoreFocusRef.current = document.activeElement as HTMLElement | null;
    const node = dialogRef.current;
    if (node) {
      const first = node.querySelector<HTMLElement>(FOCUSABLE);
      (first ?? node).focus();
    }
    return () => {
      const previous = restoreFocusRef.current;
      if (previous && typeof previous.focus === "function") previous.focus();
    };
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.stopPropagation();
        onClose();
        return;
      }
      if (event.key !== "Tab") return;
      const node = dialogRef.current;
      if (!node) return;
      const focusable = Array.from(node.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
        (element) => element.offsetParent !== null || element === document.activeElement,
      );
      if (focusable.length === 0) {
        event.preventDefault();
        node.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKeyDown, true);
    return () => document.removeEventListener("keydown", onKeyDown, true);
  }, [open, onClose]);

  const copy = useCallback(async (value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  }, []);

  const blocks = useMemo<EvidenceBlock[]>(
    () => (finding && Array.isArray(finding.evidenceBlocks) ? finding.evidenceBlocks : []),
    [finding],
  );

  if (!open || !finding) return null;

  const fallback = Array.isArray(finding.fallbackLog) ? finding.fallbackLog : [];
  const run = finding.runContext;

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end bg-slate-950/70"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        className="flex h-full w-full max-w-3xl flex-col overflow-y-auto border-l border-slate-700 bg-slate-900 shadow-2xl focus:outline-none"
      >
        <header className="sticky top-0 z-10 flex items-start justify-between gap-3 border-b border-slate-800 bg-slate-900/95 px-5 py-4">
          <div className="min-w-0">
            <p className="text-xs uppercase tracking-wide text-slate-400">
              {sanitizeText(finding.category) || "Finding"} · {sanitizeText(finding.checkId)}
            </p>
            <h2 id={titleId} className="mt-1 text-lg font-semibold">
              {sanitizeText(finding.title) || sanitizeText(finding.checkId)}
            </h2>
            <div className="mt-2 flex flex-wrap items-center gap-2 text-xs">
              <span
                className={`rounded border px-1.5 py-0.5 ${SEVERITY_TONE[finding.severity] ?? "border-slate-600 text-slate-200"}`}
              >
                {sanitizeText(finding.severity)}
              </span>
              <span
                className={`rounded border px-1.5 py-0.5 ${STATUS_TONE[finding.status] ?? "border-slate-600 text-slate-200"}`}
              >
                {sanitizeText(finding.status)}
              </span>
              {reportId ? <span className="text-slate-400">Report #{reportId}</span> : null}
              {hostname ? <span className="text-slate-400">{sanitizeText(hostname)}</span> : null}
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close evidence"
            className="rounded-md border border-slate-700 p-1.5 text-slate-300 hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
          >
            <X size={18} aria-hidden />
          </button>
        </header>

        <div className="space-y-6 px-5 py-5 text-sm">
          {finding.degradedReason ? (
            <p role="note" className="rounded border border-amber-500/50 bg-amber-500/10 p-3 text-amber-100">
              Degraded evidence: {sanitizeText(finding.degradedReason)}
            </p>
          ) : null}

          <section aria-labelledby={`${titleId}-impact`}>
            <h3 id={`${titleId}-impact`} className="text-xs font-semibold uppercase tracking-wide text-slate-400">
              Impact
            </h3>
            <p className="mt-1 whitespace-pre-wrap text-slate-200">
              {sanitizeText(finding.impact) || "No impact statement provided."}
            </p>
          </section>

          <section aria-labelledby={`${titleId}-recommendation`}>
            <h3
              id={`${titleId}-recommendation`}
              className="text-xs font-semibold uppercase tracking-wide text-slate-400"
            >
              Recommendation
            </h3>
            <p className="mt-1 whitespace-pre-wrap text-slate-200">
              {sanitizeText(finding.recommendation) || "No recommendation provided."}
            </p>
          </section>

          <section aria-labelledby={`${titleId}-evidence`} className="space-y-3">
            <h3 id={`${titleId}-evidence`} className="text-xs font-semibold uppercase tracking-wide text-slate-400">
              Pinpoint evidence
            </h3>
            {blocks.length === 0 ? (
              <p className="rounded border border-dashed border-slate-700 p-3 text-slate-400" role="status">
                No locatable evidence block was emitted for this result.
              </p>
            ) : (
              blocks.map((block, index) => {
                const window = contextWindow(block);
                const locator = `${sanitizeText(block.path)}:${block.line}:${block.col}`;
                return (
                  <article
                    key={`${block.path}:${block.line}:${block.col}:${index}`}
                    className="overflow-hidden rounded-lg border border-slate-700 bg-slate-950/60"
                  >
                    <header className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 px-3 py-2">
                      <div className="min-w-0">
                        <p className="truncate font-mono text-xs text-sky-200">{sanitizeText(block.path)}</p>
                        <p className="text-[11px] text-slate-400">
                          line {block.line}, column {block.col}
                          {block.fileMode != null ? ` · mode ${block.fileMode.toString(8)}` : ""}
                          {block.fileUid != null ? ` · uid ${block.fileUid}` : ""}
                          {block.fileGid != null ? ` · gid ${block.fileGid}` : ""}
                        </p>
                      </div>
                      <button
                        type="button"
                        onClick={() => void copy(locator)}
                        className="flex items-center gap-1 rounded border border-slate-700 px-2 py-1 text-xs hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
                        aria-label={`Copy locator ${locator}`}
                      >
                        {copied ? <Check size={13} aria-hidden /> : <Copy size={13} aria-hidden />}
                        {copied ? "Copied" : "Copy locator"}
                      </button>
                    </header>
                    <div className="overflow-x-auto">
                      <pre className="min-w-full py-2 text-xs leading-5">
                        <code>
                          {window.before.map((line, offset) => (
                            <span key={`b${offset}`} className="flex">
                              <span className="w-14 shrink-0 select-none pr-3 text-right text-slate-500 tabular-nums">
                                {block.line - (window.before.length - offset)}
                              </span>
                              <span className="whitespace-pre text-slate-400">{sanitizeText(line)}</span>
                            </span>
                          ))}
                          <span className="flex bg-red-500/15">
                            <span className="w-14 shrink-0 select-none pr-3 text-right font-semibold text-red-300 tabular-nums">
                              {block.line}
                            </span>
                            <span className="whitespace-pre font-semibold text-red-100">
                              {window.offending === null ? "(line unavailable)" : sanitizeText(window.offending)}
                            </span>
                          </span>
                          {window.after.map((line, offset) => (
                            <span key={`a${offset}`} className="flex">
                              <span className="w-14 shrink-0 select-none pr-3 text-right text-slate-500 tabular-nums">
                                {block.line + (offset + 1)}
                              </span>
                              <span className="whitespace-pre text-slate-400">{sanitizeText(line)}</span>
                            </span>
                          ))}
                        </code>
                      </pre>
                    </div>
                  </article>
                );
              })
            )}
            <p className="text-[11px] text-slate-500" role="note">
              Redacted extractor-side: locators, context lines, fallback outcomes, and repro commands are
              masked before the report leaves the scanned host, so the console only ever renders redacted
              evidence.
            </p>
          </section>

          <section aria-labelledby={`${titleId}-fallback`}>
            <h3 id={`${titleId}-fallback`} className="text-xs font-semibold uppercase tracking-wide text-slate-400">
              Ordered fallback attempts
            </h3>
            {fallback.length === 0 ? (
              <p className="mt-1 text-slate-400">Primary source succeeded; no fallback attempted.</p>
            ) : (
              <table className="mt-2 w-full border-collapse text-xs">
                <thead>
                  <tr className="text-left text-slate-400">
                    <th scope="col" className="border-b border-slate-800 py-1 pr-2">
                      #
                    </th>
                    <th scope="col" className="border-b border-slate-800 py-1 pr-2">
                      Source
                    </th>
                    <th scope="col" className="border-b border-slate-800 py-1">
                      Outcome
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {fallback.map((attempt, index) => (
                    <tr key={`${attempt.source}:${index}`}>
                      <td className="border-b border-slate-900 py-1 pr-2 tabular-nums text-slate-500">
                        {index + 1}
                      </td>
                      <td className="border-b border-slate-900 py-1 pr-2 font-mono text-slate-300">
                        {sanitizeText(attempt.source)}
                      </td>
                      <td className="border-b border-slate-900 py-1 text-slate-300">
                        {sanitizeText(attempt.outcome)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>

          <section aria-labelledby={`${titleId}-repro`}>
            <h3 id={`${titleId}-repro`} className="text-xs font-semibold uppercase tracking-wide text-slate-400">
              Reproduction command
            </h3>
            {sanitizeText(finding.repro) ? (
              <pre className="mt-1 overflow-x-auto rounded border border-slate-800 bg-slate-950 p-2 text-xs">
                <code>{sanitizeText(finding.repro)}</code>
              </pre>
            ) : (
              <p className="mt-1 text-slate-400">No reproduction command was emitted for this result.</p>
            )}
          </section>

          {finding.references.length > 0 ? (
            <section aria-labelledby={`${titleId}-references`}>
              <h3
                id={`${titleId}-references`}
                className="text-xs font-semibold uppercase tracking-wide text-slate-400"
              >
                References
              </h3>
              <ul className="mt-1 list-disc space-y-1 pl-5">
                {finding.references.map((reference, index) => {
                  const href = safeHref(reference);
                  return (
                    <li key={`${reference}:${index}`} className="break-words">
                      {href ? (
                        <a
                          href={href}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-sky-300 underline underline-offset-2"
                        >
                          {reference}
                        </a>
                      ) : (
                        <span className="font-mono text-slate-300">{sanitizeText(reference)}</span>
                      )}
                    </li>
                  );
                })}
              </ul>
            </section>
          ) : null}

          <section aria-labelledby={`${titleId}-run`}>
            <h3 id={`${titleId}-run`} className="text-xs font-semibold uppercase tracking-wide text-slate-400">
              Run context
            </h3>
            <dl className="mt-1 grid grid-cols-2 gap-x-4 gap-y-1 text-xs sm:grid-cols-3">
              <div>
                <dt className="text-slate-500">User</dt>
                <dd className="font-mono text-slate-200">{sanitizeText(run.user) || "unknown"}</dd>
              </div>
              <div>
                <dt className="text-slate-500">UID</dt>
                <dd className="font-mono text-slate-200">{run.uid ?? "—"}</dd>
              </div>
              <div>
                <dt className="text-slate-500">Elevated</dt>
                <dd className="text-slate-200">{run.elevated ? "yes" : "no"}</dd>
              </div>
            </dl>
          </section>

          {sanitizeText(finding.evidence) ? (
            <section aria-labelledby={`${titleId}-raw`}>
              <h3 id={`${titleId}-raw`} className="text-xs font-semibold uppercase tracking-wide text-slate-400">
                Evidence summary
              </h3>
              <p className="mt-1 whitespace-pre-wrap text-slate-300">{sanitizeText(finding.evidence)}</p>
            </section>
          ) : null}
        </div>
      </div>
    </div>
  );
}
