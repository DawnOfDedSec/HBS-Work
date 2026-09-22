import { useScopeFilters } from "../useScopeFilters";
import { resolveScope } from "../filters";

/** Scope selector: latest campaign state, one report, or an inclusive date range. */
export function ScopeSelector() {
  const { filters, toggle, clearKey } = useScopeFilters();
  const scope = resolveScope(filters);

  return (
    <fieldset className="flex flex-wrap items-end gap-4 rounded-lg border border-slate-800 p-3">
      <legend className="px-1 text-xs uppercase tracking-wide text-slate-400">Scope</legend>
      <label className="flex items-center gap-2 text-sm">
        <input type="radio" name="scope" checked={scope === "latest"} onChange={() => clearKey("scope")} />
        Latest state
      </label>
      <label className="flex items-center gap-2 text-sm">
        <input
          type="radio"
          name="scope"
          checked={scope === "report"}
          onChange={() => toggle("scope", "report")}
        />
        Single report
      </label>
      <label className="flex items-center gap-2 text-sm">
        <input
          type="radio"
          name="scope"
          checked={scope === "range"}
          onChange={() => toggle("scope", "range")}
        />
        Date range
      </label>

      {scope === "report" ? (
        <label className="flex items-center gap-2 text-sm">
          Report ID
          <input
            type="number"
            min={1}
            value={filters.reportId?.[0] ?? ""}
            onChange={(event) => event.target.value && toggle("reportId", event.target.value)}
            className="w-28 rounded border border-slate-700 bg-slate-900 px-2 py-1"
          />
        </label>
      ) : null}

      {scope === "range" ? (
        <>
          <label className="flex items-center gap-2 text-sm">
            From
            <input
              type="datetime-local"
              value={filters.from?.[0] ?? ""}
              onChange={(event) => event.target.value && toggle("from", event.target.value)}
              className="rounded border border-slate-700 bg-slate-900 px-2 py-1"
            />
          </label>
          <label className="flex items-center gap-2 text-sm">
            To
            <input
              type="datetime-local"
              value={filters.to?.[0] ?? ""}
              onChange={(event) => event.target.value && toggle("to", event.target.value)}
              className="rounded border border-slate-700 bg-slate-900 px-2 py-1"
            />
          </label>
        </>
      ) : null}
    </fieldset>
  );
}
