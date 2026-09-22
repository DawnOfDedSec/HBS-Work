import { RefreshCw } from "lucide-react";
import { Button } from "./ui";
import { relativeTime, useRelativeTime } from "../useRelativeTime";

export type LastUpdatedProps = {
  /** ISO timestamp of the last successful load. */
  at: string | null;
  onRefresh?: () => void;
  loading?: boolean;
  className?: string;
};

/** "Updated 12s ago" plus an optional Refresh button for data pages. */
export function LastUpdated({ at, onRefresh, loading = false, className }: LastUpdatedProps) {
  const label = useRelativeTime(at);
  return (
    <div className={className}>
      <div className="flex items-center gap-2">
        <span className="text-2xs text-ink-subtle" title={at ? new Date(at).toLocaleString() : undefined}>
          Updated <span className="tabular-nums">{label}</span>
        </span>
        {onRefresh ? (
          <Button
            size="sm"
            variant="ghost"
            icon={RefreshCw}
            loading={loading}
            onClick={onRefresh}
            aria-label="Refresh data"
          >
            Refresh
          </Button>
        ) : null}
      </div>
      <span className="sr-only">{at ? `Last updated ${relativeTime(at)}` : "Not yet updated"}</span>
    </div>
  );
}
