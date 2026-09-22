import type { ReactNode } from "react";

/** A real, styled empty state for a view with no data (or no selection yet). */
export function EmptyState({ title, detail }: { title: string; detail?: ReactNode }) {
  return (
    <div className="rounded-lg border border-dashed border-slate-700 bg-slate-900/40 p-8 text-center" role="status">
      <p className="text-base font-medium">{title}</p>
      {detail ? <p className="mt-1 text-sm text-slate-400">{detail}</p> : null}
    </div>
  );
}
