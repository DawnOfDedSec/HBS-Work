import { useCallback, useEffect, useState } from "react";
import {
  activeChips,
  clearAllFilters,
  clearFilter,
  parseFilters,
  serializeFilters,
  toggleFilter,
  type FilterKey,
  type ScopeFilters,
} from "./filters";

export type ScopeFilterController = {
  filters: ScopeFilters;
  query: string;
  chips: ReturnType<typeof activeChips>;
  toggle: (key: FilterKey, value: string) => void;
  clearKey: (key: FilterKey) => void;
  clear: () => void;
};

/**
 * URL-backed filter state. The query string is the single source of truth:
 * every mutation pushes a history entry, and back/forward restore it.
 */
export function useScopeFilters(): ScopeFilterController {
  const [filters, setFilters] = useState<ScopeFilters>(() =>
    typeof window === "undefined" ? {} : parseFilters(window.location.search),
  );

  useEffect(() => {
    const onPopState = () => setFilters(parseFilters(window.location.search));
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  const commit = useCallback((next: ScopeFilters) => {
    const query = serializeFilters(next);
    const url = query ? `${window.location.pathname}?${query}` : window.location.pathname;
    window.history.pushState({}, "", url);
    setFilters(next);
  }, []);

  return {
    filters,
    query: serializeFilters(filters),
    chips: activeChips(filters),
    toggle: (key, value) => commit(toggleFilter(filters, key, value)),
    clearKey: (key) => commit(clearFilter(filters, key)),
    clear: () => commit(clearAllFilters()),
  };
}
