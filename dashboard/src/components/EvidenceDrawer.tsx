import { useCallback, useMemo, useState } from "react";
import { Check, Copy, FileCode2, Link2 } from "lucide-react";
import {
  Badge,
  Button,
  Card,
  Drawer,
  EmptyState,
  Table,
  type TableColumn,
} from "./ui";
import { SeverityBadge, StatusBadge } from "./badges";
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

/** A small copy-to-clipboard control with a transient confirmation. */
function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      variant="ghost"
      size="sm"
      icon={copied ? Check : Copy}
      aria-label={label}
      onClick={() => {
        void navigator.clipboard?.writeText(value).then(
          () => {
            setCopied(true);
            window.setTimeout(() => setCopied(false), 1500);
          },
          () => setCopied(false),
        );
      }}
    >
      {copied ? "Copied" : "Copy"}
    </Button>
  );
}

/**
 * Accessible, modal evidence drawer. The kit `Drawer` provides Escape-to-close,
 * focus trapping, and focus restoration; this component renders the redacted
 * pinpoint evidence, fallback chain, repro, and run context.
 */
export function EvidenceDrawer({ open, finding, reportId, hostname, onClose }: EvidenceDrawerProps) {
  const blocks = useMemo<EvidenceBlock[]>(
    () => (finding && Array.isArray(finding.evidenceBlocks) ? finding.evidenceBlocks : []),
    [finding],
  );

  const copyPath = useCallback((locator: string) => locator, []);

  if (!open || !finding) return null;

  const fallback = Array.isArray(finding.fallbackLog) ? finding.fallbackLog : [];
  const run = finding.runContext;
  const title = sanitizeText(finding.title) || sanitizeText(finding.checkId) || "Finding evidence";

  const fallbackColumns: Array<TableColumn<FallbackAttempt & { index: number }>> = [
    { key: "index", header: "#", width: "3rem", render: (row) => row.index + 1 },
    {
      key: "source",
      header: "Source",
      render: (row) => <span className="font-mono text-xs text-ink">{sanitizeText(row.source)}</span>,
    },
    { key: "outcome", header: "Outcome", render: (row) => sanitizeText(row.outcome) },
  ];

  return (
    <Drawer
      open={open}
      onClose={onClose}
      size="lg"
      title={title}
      description={
        <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <span className="text-ink-subtle">{sanitizeText(finding.category) || "Finding"}</span>
          <span className="font-mono text-ink-muted">{sanitizeText(finding.checkId)}</span>
          {reportId ? <span className="text-ink-subtle">· Report #{reportId}</span> : null}
          {hostname ? <span className="text-ink-subtle">· {sanitizeText(hostname)}</span> : null}
        </span>
      }
    >
      <div className="flex flex-col gap-5 text-sm">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={finding.severity} />
          <StatusBadge status={finding.status} />
          <Badge tone="neutral" icon={FileCode2}>
            {blocks.length} evidence block{blocks.length === 1 ? "" : "s"}
          </Badge>
        </div>

        {finding.degradedReason ? (
          <p role="note" className="rounded-control border border-high/40 bg-high-soft/60 p-3 text-xs text-high">
            Degraded evidence: {sanitizeText(finding.degradedReason)}
          </p>
        ) : null}

        <section aria-labelledby="evidence-impact">
          <h3 id="evidence-impact" className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">
            Impact
          </h3>
          <p className="mt-1 whitespace-pre-wrap text-ink">
            {sanitizeText(finding.impact) || "No impact statement provided."}
          </p>
        </section>

        <section aria-labelledby="evidence-recommendation">
          <h3
            id="evidence-recommendation"
            className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle"
          >
            Recommendation
          </h3>
          <p className="mt-1 whitespace-pre-wrap text-ink">
            {sanitizeText(finding.recommendation) || "No recommendation provided."}
          </p>
        </section>

        <section aria-labelledby="evidence-pinpoint" className="space-y-3">
          <h3 id="evidence-pinpoint" className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">
            Pinpoint evidence
          </h3>
          {blocks.length === 0 ? (
            <EmptyState
              title="No locatable evidence block"
              detail="The extractor did not emit a pinned source location for this result."
            />
          ) : (
            blocks.map((block, index) => {
              const window = contextWindow(block);
              const locator = `${sanitizeText(block.path)}:${block.line}:${block.col}`;
              return (
                <Card key={`${block.path}:${block.line}:${block.col}:${index}`} flush className="overflow-hidden">
                  <div className="flex flex-wrap items-start justify-between gap-2 border-b border-hairline-soft p-3">
                    <div className="min-w-0">
                      <p className="truncate font-mono text-xs text-accent">{sanitizeText(block.path)}</p>
                      <p className="mt-0.5 text-2xs text-ink-muted">
                        line {block.line}, column {block.col}
                        {block.fileMode != null ? ` · mode ${block.fileMode.toString(8)}` : ""}
                        {block.fileUid != null ? ` · uid ${block.fileUid}` : ""}
                        {block.fileGid != null ? ` · gid ${block.fileGid}` : ""}
                      </p>
                    </div>
                    <CopyButton value={copyPath(locator)} label={`Copy locator ${locator}`} />
                  </div>
                  <div className="hbs-scroll overflow-x-auto">
                    <pre className="min-w-full py-2 text-xs leading-5">
                      <code>
                        {window.before.map((line, offset) => (
                          <span key={`b${offset}`} className="flex">
                            <span className="w-14 shrink-0 select-none pr-3 text-right text-ink-subtle tabular-nums">
                              {block.line - (window.before.length - offset)}
                            </span>
                            <span className="whitespace-pre text-ink-muted">{sanitizeText(line)}</span>
                          </span>
                        ))}
                        <span className="flex bg-critical-soft/70">
                          <span className="w-14 shrink-0 select-none pr-3 text-right font-semibold text-critical tabular-nums">
                            {block.line}
                          </span>
                          <span className="whitespace-pre font-semibold text-critical">
                            {window.offending === null ? "(line unavailable)" : sanitizeText(window.offending)}
                          </span>
                        </span>
                        {window.after.map((line, offset) => (
                          <span key={`a${offset}`} className="flex">
                            <span className="w-14 shrink-0 select-none pr-3 text-right text-ink-subtle tabular-nums">
                              {block.line + (offset + 1)}
                            </span>
                            <span className="whitespace-pre text-ink-muted">{sanitizeText(line)}</span>
                          </span>
                        ))}
                      </code>
                    </pre>
                  </div>
                </Card>
              );
            })
          )}
          <p className="text-2xs text-ink-subtle" role="note">
            Redacted extractor-side: locators, context lines, fallback outcomes, and repro commands are masked
            before the report leaves the scanned host, so the console only ever renders redacted evidence.
          </p>
        </section>

        <section aria-labelledby="evidence-fallback">
          <h3 id="evidence-fallback" className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">
            Ordered fallback attempts
          </h3>
          {fallback.length === 0 ? (
            <p className="mt-1 text-ink-muted">Primary source succeeded; no fallback attempted.</p>
          ) : (
            <div className="mt-2">
              <Table
                dense
                label="Ordered fallback attempts"
                columns={fallbackColumns}
                rows={fallback.map((attempt, index) => ({ ...attempt, index }))}
                rowKey={(row, index) => `${row.source}:${index}`}
              />
            </div>
          )}
        </section>

        <section aria-labelledby="evidence-repro">
          <h3 id="evidence-repro" className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">
            Reproduction command
          </h3>
          {sanitizeText(finding.repro) ? (
            <div className="mt-1 overflow-hidden rounded-control border border-hairline-soft">
              <div className="flex items-center justify-between gap-2 border-b border-hairline-soft px-2 py-1">
                <span className="text-2xs uppercase tracking-wide text-ink-subtle">repro</span>
                <CopyButton value={sanitizeText(finding.repro)} label="Copy reproduction command" />
              </div>
              <pre className="hbs-scroll overflow-x-auto bg-surface-sunken p-2 text-xs">
                <code className="text-ink-muted">{sanitizeText(finding.repro)}</code>
              </pre>
            </div>
          ) : (
            <p className="mt-1 text-ink-muted">No reproduction command was emitted for this result.</p>
          )}
        </section>

        {finding.references.length > 0 ? (
          <section aria-labelledby="evidence-references">
            <h3 id="evidence-references" className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">
              References
            </h3>
            <ul className="mt-1 space-y-1">
              {finding.references.map((reference, index) => {
                const href = safeHref(reference);
                return (
                  <li key={`${reference}:${index}`} className="flex items-start gap-1.5 break-words">
                    <Link2 size={12} aria-hidden className="mt-1 shrink-0 text-ink-subtle" />
                    {href ? (
                      <a
                        href={href}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-accent underline underline-offset-2"
                      >
                        {reference}
                      </a>
                    ) : (
                      <span className="font-mono text-xs text-ink-muted">{sanitizeText(reference)}</span>
                    )}
                  </li>
                );
              })}
            </ul>
          </section>
        ) : null}

        <section aria-labelledby="evidence-run">
          <h3 id="evidence-run" className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">
            Run context
          </h3>
          <dl className="mt-1 grid grid-cols-2 gap-x-4 gap-y-1 text-xs sm:grid-cols-3">
            <div>
              <dt className="text-ink-subtle">User</dt>
              <dd className="font-mono text-ink">{sanitizeText(run.user) || "unknown"}</dd>
            </div>
            <div>
              <dt className="text-ink-subtle">UID</dt>
              <dd className="font-mono text-ink">{run.uid ?? "-"}</dd>
            </div>
            <div>
              <dt className="text-ink-subtle">Elevated</dt>
              <dd className="text-ink">{run.elevated ? "yes" : "no"}</dd>
            </div>
          </dl>
        </section>

        {sanitizeText(finding.evidence) ? (
          <section aria-labelledby="evidence-summary">
            <h3 id="evidence-summary" className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">
              Evidence summary
            </h3>
            <p className="mt-1 whitespace-pre-wrap font-mono text-xs text-ink-muted">
              {sanitizeText(finding.evidence)}
            </p>
          </section>
        ) : null}
      </div>
    </Drawer>
  );
}
