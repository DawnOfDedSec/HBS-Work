import { useMemo, useState, type KeyboardEvent, type ReactNode } from "react";
import { ArrowDown, ArrowUp, ChevronsUpDown } from "lucide-react";
import { cn, focusRing } from "./cn";

export type SortDirection = "asc" | "desc";

export type TableColumn<T> = {
  key: string;
  header: ReactNode;
  align?: "left" | "right" | "center";
  /** Enables the sortable affordance + `aria-sort` on the header cell. */
  sortable?: boolean;
  /** Custom cell renderer. Defaults to the row's `key` field. */
  render?: (row: T, index: number) => ReactNode;
  /** Value used for sorting; defaults to `row[key]`. */
  sortValue?: (row: T) => string | number;
  width?: string;
  className?: string;
  headerClassName?: string;
};

export type TableProps<T> = {
  columns: Array<TableColumn<T>>;
  rows: T[];
  rowKey: (row: T, index: number) => string;
  caption?: ReactNode;
  /** Accessible name when no caption is rendered. */
  label?: string;
  zebra?: boolean;
  stickyHeader?: boolean;
  dense?: boolean;
  empty?: ReactNode;
  className?: string;
  /** Makes rows interactive (Click / Enter / Space). */
  onRowClick?: (row: T) => void;
  defaultSort?: { key: string; direction: SortDirection };
};

const ALIGN_CLASS: Record<"left" | "right" | "center", string> = {
  left: "text-left",
  right: "text-right",
  center: "text-center",
};

function defaultSortValue<T>(row: T, key: string): string | number {
  const value = (row as Record<string, unknown>)[key];
  if (typeof value === "number" || typeof value === "string") return value;
  return value === null || value === undefined ? "" : String(value);
}

/**
 * A dense data table with an optional sticky header and zebra striping.
 * Sortable columns advertise their state through `aria-sort` and are operated
 * by real buttons, so sorting is keyboard- and screen-reader-accessible.
 */
export function Table<T>({
  columns,
  rows,
  rowKey,
  caption,
  label,
  zebra = true,
  stickyHeader = false,
  dense = false,
  empty,
  className,
  onRowClick,
  defaultSort,
}: TableProps<T>) {
  const [sort, setSort] = useState<{ key: string; direction: SortDirection } | null>(defaultSort ?? null);

  const sortedRows = useMemo(() => {
    if (!sort) return rows;
    const column = columns.find((candidate) => candidate.key === sort.key);
    if (!column) return rows;
    const read = column.sortValue ?? ((row: T) => defaultSortValue(row, column.key));
    const factor = sort.direction === "asc" ? 1 : -1;
    return [...rows].sort((a, b) => {
      const left = read(a);
      const right = read(b);
      if (typeof left === "number" && typeof right === "number") return (left - right) * factor;
      return String(left).localeCompare(String(right), undefined, { numeric: true }) * factor;
    });
  }, [rows, sort, columns]);

  function toggleSort(key: string) {
    setSort((current) => {
      if (!current || current.key !== key) return { key, direction: "asc" };
      return { key, direction: current.direction === "asc" ? "desc" : "asc" };
    });
  }

  const cellPad = dense ? "px-2.5 py-1.5" : "px-3 py-2.5";

  function activateRow(row: T, event: KeyboardEvent<HTMLTableRowElement>) {
    if (!onRowClick) return;
    if (event.key === "Enter" || event.key === " " || event.key === "Spacebar") {
      event.preventDefault();
      onRowClick(row);
    }
  }

  return (
    <div className={cn("hbs-scroll overflow-auto", className)}>
      <table className="w-full border-collapse text-sm">
        {caption ? <caption className="pb-2 text-left text-xs text-ink-muted">{caption}</caption> : null}
        {!caption && label ? <caption className="sr-only">{label}</caption> : null}
        <thead className={cn(stickyHeader && "sticky top-0 z-10 bg-surface")}>
          <tr>
            {columns.map((column) => {
              const isSorted = sort?.key === column.key;
              return (
                <th
                  key={column.key}
                  scope="col"
                  style={column.width ? { width: column.width } : undefined}
                  aria-sort={
                    column.sortable
                      ? isSorted
                        ? sort.direction === "asc"
                          ? "ascending"
                          : "descending"
                        : "none"
                      : undefined
                  }
                  className={cn(
                    "border-b border-hairline bg-surface text-2xs font-semibold uppercase tracking-wide text-ink-subtle",
                    cellPad,
                    ALIGN_CLASS[column.align ?? "left"],
                    column.headerClassName,
                  )}
                >
                  {column.sortable ? (
                    <button
                      type="button"
                      onClick={() => toggleSort(column.key)}
                      className={cn(
                        "inline-flex items-center gap-1 rounded px-0.5 uppercase tracking-wide hover:text-ink",
                        focusRing,
                        ALIGN_CLASS[column.align ?? "left"],
                        isSorted && "text-ink",
                      )}
                    >
                      {column.header}
                      {isSorted ? (
                        sort.direction === "asc" ? (
                          <ArrowUp size={12} aria-hidden />
                        ) : (
                          <ArrowDown size={12} aria-hidden />
                        )
                      ) : (
                        <ChevronsUpDown size={12} className="opacity-50" aria-hidden />
                      )}
                    </button>
                  ) : (
                    column.header
                  )}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {sortedRows.length === 0 ? (
            <tr>
              <td colSpan={columns.length} className={cn("text-center text-ink-muted", cellPad)}>
                {empty ?? "No rows."}
              </td>
            </tr>
          ) : (
            sortedRows.map((row, index) => (
              <tr
                key={rowKey(row, index)}
                tabIndex={onRowClick ? 0 : undefined}
                onClick={onRowClick ? () => onRowClick(row) : undefined}
                onKeyDown={onRowClick ? (event) => activateRow(row, event) : undefined}
                className={cn(
                  "border-b border-hairline-soft transition-colors last:border-b-0",
                  zebra && index % 2 === 1 && "bg-surface-sunken/40",
                  onRowClick && cn("cursor-pointer hover:bg-surface-raised", focusRing),
                )}
              >
                {columns.map((column) => (
                  <td
                    key={column.key}
                    className={cn(
                      cellPad,
                      ALIGN_CLASS[column.align ?? "left"],
                      "text-ink",
                      column.align === "right" && "tabular-nums",
                      column.className,
                    )}
                  >
                    {column.render ? column.render(row, index) : String(defaultSortValue(row, column.key))}
                  </td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
