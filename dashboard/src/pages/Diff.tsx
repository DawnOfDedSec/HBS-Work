import { useEffect, useState } from "react";
import {
  ArrowLeft,
  ArrowRight,
  GitCompareArrows,
  Minus,
  Plus,
  TrendingDown,
  TrendingUp,
} from "lucide-react";
import { api, ApiError } from "../api";
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  Input,
  SectionHeader,
  Skeleton,
  Stat,
  useToast,
} from "../components/ui";
import { cn } from "../components/ui/cn";
import { SeverityBadge, StatusBadge } from "../components/badges";
import { sanitizeText } from "../components/EvidenceDrawer";

type DiffEntry = {
  checkId: string;
  title: string;
  severity: string;
  category: string;
  from: string | null;
  to: string | null;
};

type DiffResponse = {
  hostId: number;
  baseReportId: number;
  targetReportId: number;
  summary: { fixed: number; regressed: number; unchanged: number; added: number; removed: number };
  fixed: DiffEntry[];
  regressed: DiffEntry[];
  unchanged: DiffEntry[];
  added: DiffEntry[];
  removed: DiffEntry[];
};

export type DiffProps = {
  /** The earlier (baseline) report. */
  baseReportId: number;
  /** The newer report. When omitted the user supplies one. */
  targetReportId?: number | null;
  onBack?: () => void;
  onOpenCheck?: (checkId: string) => void;
};

type DiffSectionProps = {
  id: string;
  title: string;
  detail: string;
  entries: DiffEntry[];
  onOpenCheck?: (checkId: string) => void;
  accent: string;
};

function DiffSection({ id, title, detail, entries, onOpenCheck, accent }: DiffSectionProps) {
  return (
    <section aria-label={title} className="hbs-panel flex flex-col overflow-hidden">
      <header className="flex items-center justify-between gap-2 border-b border-hairline-soft px-3 py-2">
        <div className="flex items-center gap-2">
          <span className={cn("h-2 w-2 rounded-full", accent)} aria-hidden />
          <h3 className="text-sm font-semibold text-ink">{title}</h3>
        </div>
        <Badge tone="neutral">{entries.length}</Badge>
      </header>
      <p className="px-3 pt-2 text-xs text-ink-subtle">{detail}</p>
      <ul className="hbs-scroll max-h-96 space-y-1.5 overflow-y-auto p-3">
        {entries.length === 0 ? (
          <li className="text-xs text-ink-subtle">None</li>
        ) : (
          entries.map((entry) => (
            <li key={entry.checkId} className="hbs-inset p-2 text-xs">
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={() => onOpenCheck?.(entry.checkId)}
                  disabled={!onOpenCheck}
                  className="rounded font-mono text-xs text-accent underline decoration-dotted underline-offset-2 hover:text-accent-strong disabled:text-ink-muted disabled:no-underline"
                >
                  {sanitizeText(entry.checkId)}
                </button>
                <SeverityBadge severity={entry.severity} />
              </div>
              <p className="mt-1 text-ink">{sanitizeText(entry.title)}</p>
              <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-2xs text-ink-subtle">
                {entry.from ? <StatusBadge status={entry.from} /> : <span className="italic">absent</span>}
                <ArrowRight size={11} aria-hidden />
                {entry.to ? <StatusBadge status={entry.to} /> : <span className="italic">absent</span>}
              </div>
            </li>
          ))
        )}
      </ul>
    </section>
  );
}

/** Side-by-side Fixed / Regressed / Unchanged comparison of two reports for one host. */
export function Diff({ baseReportId, targetReportId, onBack, onOpenCheck }: DiffProps) {
  const [targetInput, setTargetInput] = useState(targetReportId ? String(targetReportId) : "");
  const [target, setTarget] = useState<number | null>(targetReportId ?? null);
  const [data, setData] = useState<DiffResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const toast = useToast();

  useEffect(() => {
    setTarget(targetReportId ?? null);
    setTargetInput(targetReportId ? String(targetReportId) : "");
  }, [targetReportId]);

  useEffect(() => {
    if (target === null) {
      setData(null);
      return;
    }
    let alive = true;
    setLoading(true);
    setError(null);
    api
      .raw<DiffResponse>("GET", `/api/reports/${baseReportId}/diff/${target}`)
      .then((value) => {
        if (alive) setData(value);
      })
      .catch((err) => {
        if (!alive) return;
        const message = err instanceof ApiError ? err.message : "Request failed. Please retry.";
        setData(null);
        setError(message);
        toast.error("Could not load diff", { description: message });
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [baseReportId, target, toast]);

  return (
    <section aria-label="Report comparison" className="mx-auto flex max-w-7xl flex-col gap-5">
      <SectionHeader
        eyebrow="Compare"
        title="Report comparison"
        description={`Diff report #${baseReportId}${target !== null ? ` against #${target}` : ""} for the same host.`}
        icon={GitCompareArrows}
        actions={
          <>
            {onBack ? (
              <Button variant="ghost" icon={ArrowLeft} onClick={onBack}>
                Back
              </Button>
            ) : null}
            {data ? (
              <Badge tone="accent">{data.fixed.length + data.regressed.length} changed</Badge>
            ) : null}
          </>
        }
      />

      <Card>
        <CardHeader
          title="Baseline checksum"
          description="Reports must belong to the same host; identity is machine-id keyed."
          icon={GitCompareArrows}
        />
        <CardBody>
          <form
            className="flex flex-wrap items-end gap-3"
            onSubmit={(event) => {
              event.preventDefault();
              const parsed = Number(targetInput);
              if (Number.isSafeInteger(parsed) && parsed > 0) setTarget(parsed);
            }}
          >
            <Input
              label="Compare against report"
              type="number"
              min={1}
              inputMode="numeric"
              value={targetInput}
              onChange={(event) => setTargetInput(event.target.value)}
              containerClassName="w-40"
            />
            <Button type="submit" variant="secondary">
              Compare
            </Button>
          </form>
        </CardBody>
      </Card>

      {target === null ? (
        <EmptyState title="Choose a report to compare" detail="Enter a report ID from the same host to diff against." />
      ) : error ? (
        <EmptyState
          icon={GitCompareArrows}
          title="Could not load diff"
          detail={error}
        />
      ) : loading && !data ? (
        <Card>
          <Skeleton width="30%" />
          <Skeleton className="mt-3" width="100%" />
        </Card>
      ) : !data ? (
        <EmptyState title="No diff available" />
      ) : (
        <>
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-5">
            <Stat label="Fixed" value={data.summary.fixed} icon={TrendingUp} tone="ok" hint="Broken → compliant" />
            <Stat label="Regressed" value={data.summary.regressed} icon={TrendingDown} tone="critical" hint="Compliant → broken" />
            <Stat label="Unchanged" value={data.summary.unchanged} icon={Minus} hint="Same status" />
            <Stat label="Added" value={data.summary.added} icon={Plus} tone="accent" hint="Only in newer" />
            <Stat label="Removed" value={data.summary.removed} icon={Minus} tone="high" hint="Only in baseline" />
          </div>

          <div className="grid gap-4 lg:grid-cols-3">
            <DiffSection
              id="fixed"
              title="Fixed"
              detail="Broken before, compliant after."
              entries={data.fixed}
              onOpenCheck={onOpenCheck}
              accent="bg-compliant"
            />
            <DiffSection
              id="regressed"
              title="Regressed"
              detail="Compliant before, broken after."
              entries={data.regressed}
              onOpenCheck={onOpenCheck}
              accent="bg-critical"
            />
            <DiffSection
              id="unchanged"
              title="Unchanged"
              detail="Same status in both reports."
              entries={data.unchanged}
              onOpenCheck={onOpenCheck}
              accent="bg-na"
            />
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <DiffSection
              id="added"
              title="Added"
              detail="Present only in the newer report."
              entries={data.added}
              onOpenCheck={onOpenCheck}
              accent="bg-accent"
            />
            <DiffSection
              id="removed"
              title="Removed"
              detail="Present only in the baseline report."
              entries={data.removed}
              onOpenCheck={onOpenCheck}
              accent="bg-high"
            />
          </div>
        </>
      )}
    </section>
  );
}
