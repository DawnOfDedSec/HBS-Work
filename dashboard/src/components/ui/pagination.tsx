import { ChevronLeft, ChevronRight } from "lucide-react";
import { cn, focusRing } from "./cn";
import { Button } from "./button";
import { Select } from "./select";

export type PaginationProps = {
  page: number;
  pageSize: number;
  total: number;
  onPageChange: (page: number) => void;
  onPageSizeChange?: (size: number) => void;
  pageSizeOptions?: number[];
  /** Hide the page-size selector when the caller controls it elsewhere. */
  showPageSize?: boolean;
  label?: string;
  className?: string;
};

/** Build a compact page window with first/last and ellipses. */
function pageWindow(page: number, pageCount: number): Array<number | "gap"> {
  if (pageCount <= 7) return Array.from({ length: pageCount }, (_, index) => index + 1);
  const pages = new Set<number>([1, pageCount, page, page - 1, page + 1]);
  const sorted = [...pages].filter((value) => value >= 1 && value <= pageCount).sort((a, b) => a - b);
  const result: Array<number | "gap"> = [];
  let previous = 0;
  for (const value of sorted) {
    if (previous && value - previous > 1) result.push("gap");
    result.push(value);
    previous = value;
  }
  return result;
}

/** Page navigation with a compact numbered window and page-size selector. */
export function Pagination({
  page,
  pageSize,
  total,
  onPageChange,
  onPageSizeChange,
  pageSizeOptions = [25, 50, 100, 200],
  showPageSize = true,
  label = "Pagination",
  className,
}: PaginationProps) {
  const pageCount = Math.max(1, Math.ceil(total / Math.max(1, pageSize)));
  const current = Math.min(Math.max(1, page), pageCount);
  const from = total === 0 ? 0 : (current - 1) * pageSize + 1;
  const to = Math.min(current * pageSize, total);

  return (
    <nav aria-label={label} className={cn("flex flex-wrap items-center justify-between gap-3", className)}>
      <p className="text-xs text-ink-muted" aria-live="polite">
        <span className="tabular-nums">{from}</span>–<span className="tabular-nums">{to}</span> of{" "}
        <span className="tabular-nums">{total}</span>
      </p>
      <div className="flex items-center gap-3">
        {showPageSize && onPageSizeChange ? (
          <div className="flex items-center gap-1.5 text-xs text-ink-muted">
            <span id="pagination-page-size">Rows</span>
            <Select
              aria-labelledby="pagination-page-size"
              value={String(pageSize)}
              onChange={(value) => onPageSizeChange(Number(value))}
              options={pageSizeOptions.map((size) => ({ value: String(size), label: String(size) }))}
              className="w-20"
            />
          </div>
        ) : null}
        <div className="flex items-center gap-1">
          <Button
            variant="secondary"
            size="sm"
            icon={ChevronLeft}
            aria-label="Previous page"
            disabled={current <= 1}
            onClick={() => onPageChange(current - 1)}
          />
          {pageWindow(current, pageCount).map((entry, index) =>
            entry === "gap" ? (
              <span key={`gap-${index}`} className="px-1 text-xs text-ink-subtle" aria-hidden>
                …
              </span>
            ) : (
              <button
                key={entry}
                type="button"
                aria-label={`Page ${entry}`}
                aria-current={entry === current ? "page" : undefined}
                onClick={() => onPageChange(entry)}
                className={cn(
                  "h-8 min-w-8 rounded-md border px-2 text-xs tabular-nums transition-colors",
                  focusRing,
                  entry === current
                    ? "border-accent/40 bg-accent-soft text-accent"
                    : "border-control-edge bg-surface-raised text-ink-muted hover:text-ink",
                )}
              >
                {entry}
              </button>
            ),
          )}
          <Button
            variant="secondary"
            size="sm"
            icon={ChevronRight}
            aria-label="Next page"
            disabled={current >= pageCount}
            onClick={() => onPageChange(current + 1)}
          />
        </div>
      </div>
    </nav>
  );
}
