// Canonical, URL-backed filter state. Global Constraints define the query
// string as the single source of truth, so reloads, the back button, and
// shared links preserve the exact active filters. Names here are the
// canonical API parameter names (Global Constraints), which the plan's
// Task 50 shorthand (`search`, `location`, `version`) maps onto.

export const FILTER_KEYS = [
  "scope",
  "reportId",
  "from",
  "to",
  "severity",
  "category",
  "status",
  "treatment",
  "locationId",
  "hostId",
  "checkId",
  "standard",
  "via",
  "privilege",
  "extractorVersion",
  "platform",
  "evidenceDepth",
  "q",
] as const;

export type FilterKey = (typeof FILTER_KEYS)[number];

/** Keys that make sense only once; every other key is multi-valued. */
const SINGLE_KEYS = new Set<FilterKey>(["scope", "reportId", "from", "to", "q"]);

export const CANONICAL_SCOPE = ["latest", "report", "range"] as const;
export type Scope = (typeof CANONICAL_SCOPE)[number];

export type ScopeFilters = Partial<Record<FilterKey, string[]>>;
export type ActiveChip = { key: FilterKey; value: string };

const KEY_SET = new Set<string>(FILTER_KEYS);

function canonicalizeValues(key: FilterKey, values: string[]): string[] {
  const cleaned = values
    .map((value) => value.trim())
    .filter((value) => value.length > 0);
  const unique = [...new Set(cleaned)];
  unique.sort((a, b) => a.localeCompare(b));
  if (SINGLE_KEYS.has(key)) return unique.slice(0, 1);
  return unique;
}

/** Parse a query string (`?a=1&a=2&b=3`) into canonical filter state. */
export function parseFilters(search: string): ScopeFilters {
  const params = new URLSearchParams(search.startsWith("?") ? search.slice(1) : search);
  const collected = new Map<FilterKey, string[]>();
  for (const [rawKey, rawValue] of params.entries()) {
    const key = rawKey as FilterKey;
    if (!KEY_SET.has(key)) continue;
    const bucket = collected.get(key) ?? [];
    bucket.push(rawValue);
    collected.set(key, bucket);
  }
  const filters: ScopeFilters = {};
  for (const key of FILTER_KEYS) {
    const values = collected.get(key);
    if (!values) continue;
    const canonical = canonicalizeValues(key, values);
    if (canonical.length > 0) filters[key] = canonical;
  }
  return filters;
}

/** Serialize canonical filter state back to a sorted query string. */
export function serializeFilters(filters: ScopeFilters): string {
  const params = new URLSearchParams();
  for (const key of FILTER_KEYS) {
    const values = filters[key];
    if (!values) continue;
    for (const value of canonicalizeValues(key, values)) params.append(key, value);
  }
  return params.toString();
}

export function toggleFilter(filters: ScopeFilters, key: FilterKey, value: string): ScopeFilters {
  const next: ScopeFilters = { ...filters };
  const current = next[key] ?? [];
  if (SINGLE_KEYS.has(key)) {
    if (current[0] === value) delete next[key];
    else next[key] = [value];
    return next;
  }
  const values = current.includes(value)
    ? current.filter((existing) => existing !== value)
    : [...current, value];
  if (values.length === 0) delete next[key];
  else next[key] = canonicalizeValues(key, values);
  return next;
}

export function clearFilter(filters: ScopeFilters, key: FilterKey): ScopeFilters {
  const next: ScopeFilters = { ...filters };
  delete next[key];
  return next;
}

export function clearAllFilters(): ScopeFilters {
  return {};
}

/** Visible chips for the active filter bar, in canonical key order. */
export function activeChips(filters: ScopeFilters): ActiveChip[] {
  const chips: ActiveChip[] = [];
  for (const key of FILTER_KEYS) {
    for (const value of filters[key] ?? []) chips.push({ key, value });
  }
  return chips;
}

/** True when the filter set is empty (nothing to clear). */
export function isEmpty(filters: ScopeFilters): boolean {
  return FILTER_KEYS.every((key) => (filters[key] ?? []).length === 0);
}

/** Validate the scope selector; anything unknown falls back to `latest`. */
export function resolveScope(filters: ScopeFilters): Scope {
  const raw = filters.scope?.[0];
  return (CANONICAL_SCOPE as readonly string[]).includes(raw ?? "")
    ? (raw as Scope)
    : "latest";
}
