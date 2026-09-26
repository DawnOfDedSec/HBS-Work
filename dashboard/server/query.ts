// Canonical scoped-query parser (Task 49).
//
// Global Constraints make the URL query string the single source of truth for
// every report/findings/host/check/summary/chart/telemetry endpoint. This module
// is the ONE place that knows the canonical parameter names and their allowed
// values, so no route can drift.
//
// The result is a deeply frozen, normalized value plus a SQL fragment builder
// that is 100% parameterized: user values are only ever emitted through `?`
// placeholders, never interpolated into SQL text.

import { SEVERITY_WEIGHTS, STATUS } from "./metrics";

// ---------------------------------------------------------------------------
// Canonical parameter names
// ---------------------------------------------------------------------------

/** Filter parameters exactly as named by Global Constraints. */
export const FILTER_KEYS = [
  "severity",
  "category",
  "status",
  "treatment",
  "locationId",
  "hostId",
  "checkId",
  "reportId",
  "standard",
  "from",
  "to",
  "via",
  "privilege",
  "extractorVersion",
  "platform",
  "evidenceDepth",
  "source",
  "q",
] as const;

export type FilterKey = (typeof FILTER_KEYS)[number];

/** Non-filter controls: scope selector and pagination. */
export const SCOPE_KEY = "scope" as const;
export const PAGINATION_KEYS = ["page", "pageSize"] as const;

/** Every key the parser will ever read. Anything else is ignored. */
export const ALLOWED_KEYS: readonly string[] = [
  SCOPE_KEY,
  ...FILTER_KEYS,
  ...PAGINATION_KEYS,
];

export const SCOPES = ["latest", "report", "range"] as const;
export type Scope = (typeof SCOPES)[number];

/** Multi-valued filters (everything except the explicit singletons). */
const MULTI_VALUE_KEYS: readonly string[] = FILTER_KEYS.filter(
  (key) => key !== "from" && key !== "to" && key !== "q",
);

const SINGLETON_KEYS: readonly string[] = ["from", "to", "q", SCOPE_KEY, ...PAGINATION_KEYS];

// ---------------------------------------------------------------------------
// Allowed enum-ish value sets
// ---------------------------------------------------------------------------

/** Rust `Severity` variant names, verbatim. */
export const ALLOWED_SEVERITY: readonly string[] = Object.keys(SEVERITY_WEIGHTS);
/** Rust `Status` variant names, verbatim. */
export const ALLOWED_STATUS: readonly string[] = Object.values(STATUS);
/** Persisted treatment states (schema `finding_states.state`). */
export const ALLOWED_TREATMENT: readonly string[] = [
  "open",
  "accepted_risk",
  "false_positive",
  "remediated",
];
export const ALLOWED_VIA: readonly string[] = ["push", "upload"];
export const ALLOWED_PRIVILEGE: readonly string[] = [
  "elevated",
  "degraded",
  "not-needed",
  "requested",
  "granted",
  "refused",
];
export const ALLOWED_PLATFORM: readonly string[] = ["Linux", "Windows"];
export const ALLOWED_EVIDENCE_DEPTH: readonly string[] = [
  "AuthoritativePrimary",
  "AuthoritativeFallback",
  "DegradedPartial",
];
/** Finding origin: sealed host reports or uploaded network configs. */
export const ALLOWED_SOURCE: readonly string[] = ["host", "network"];

const CASE_INSENSITIVE: Record<string, readonly string[]> = {
  platform: ALLOWED_PLATFORM,
  evidenceDepth: ALLOWED_EVIDENCE_DEPTH,
  treatment: ALLOWED_TREATMENT,
  via: ALLOWED_VIA,
  privilege: ALLOWED_PRIVILEGE,
};

// ---------------------------------------------------------------------------
// Limits + error codes
// ---------------------------------------------------------------------------

export const MAX_Q_LENGTH = 200;
export const MAX_CATEGORY_LENGTH = 128;
export const MAX_STANDARD_LENGTH = 128;
export const MAX_CHECK_ID_LENGTH = 64;
export const MAX_VERSION_LENGTH = 64;
export const MAX_VALUES_PER_FILTER = 50;
export const DEFAULT_PAGE_SIZE = 50;
export const MAX_PAGE_SIZE = 200;

export const QUERY_ERROR_CODES = {
  INVALID_FILTER: "INVALID_FILTER",
  INVALID_ID: "INVALID_ID",
  INVALID_RANGE: "INVALID_RANGE",
  QUERY_TOO_LONG: "QUERY_TOO_LONG",
  SCOPE_REQUIRES_REPORT: "SCOPE_REQUIRES_REPORT",
  SCOPE_REQUIRES_RANGE: "SCOPE_REQUIRES_RANGE",
  SCOPE_CONFLICT: "SCOPE_CONFLICT",
} as const;

export type QueryErrorCode = (typeof QUERY_ERROR_CODES)[keyof typeof QUERY_ERROR_CODES];

export type QueryParseError = {
  ok: false;
  code: QueryErrorCode;
  message: string;
};

// ---------------------------------------------------------------------------
// Normalized query
// ---------------------------------------------------------------------------

export type QueryFilters = {
  severity: readonly string[];
  category: readonly string[];
  status: readonly string[];
  treatment: readonly string[];
  locationId: readonly number[];
  hostId: readonly number[];
  checkId: readonly string[];
  reportId: readonly number[];
  standard: readonly string[];
  via: readonly string[];
  privilege: readonly string[];
  extractorVersion: readonly string[];
  platform: readonly string[];
  evidenceDepth: readonly string[];
  source: readonly string[];
  from: string | null;
  to: string | null;
  q: string | null;
};

export type Pagination = {
  page: number;
  pageSize: number;
  offset: number;
};

export type NormalizedQuery = {
  scope: Scope;
  filters: QueryFilters;
  campaignId: number | null;
  /** Server-derived campaign fence (path scope + user restriction); empty = all. */
  campaignIds: readonly number[];
  pagination: Pagination;
  /** Keys present in the query string that are not canonical (safe to ignore). */
  ignored: readonly string[];
  /** The original search text, for round-tripping. */
  raw: string;
};

export type QueryParseOk = { ok: true; query: NormalizedQuery };

export type ParseQueryOptions = {
  /** Campaign scope supplied by a route path (e.g. `/api/campaigns/:id/summary`). */
  campaignId?: number | null;
  /** Server-side access restriction from the session user (per-campaign scoping). */
  campaignIds?: readonly number[] | null;
};

// ---------------------------------------------------------------------------
// Primitive validation
// ---------------------------------------------------------------------------

function clean(value: string): string {
  return value.trim();
}

function stripControls(value: string): string {
  // Control chars and ANSI escapes must never reach storage, SQL, or JSON.
  return value.replace(/[\u0000-\u001f\u007f-\u009f]/g, "");
}

function parsePositiveInt(value: string): number | null {
  if (!/^[0-9]+$/.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
}

function parseIso(value: string): string | null {
  const trimmed = clean(value);
  if (!trimmed) return null;
  const millis = Date.parse(trimmed);
  if (!Number.isFinite(millis)) return null;
  return new Date(millis).toISOString();
}

function parseEnum(
  key: string,
  values: string[],
  allowed: readonly string[],
): { ok: true; values: string[] } | QueryParseError {
  const caseInsensitive = CASE_INSENSITIVE[key] !== undefined;
  const out: string[] = [];
  for (const raw of values) {
    const value = stripControls(clean(raw));
    if (!value) continue;
    const match = caseInsensitive
      ? allowed.find((candidate) => candidate.toLowerCase() === value.toLowerCase())
      : allowed.find((candidate) => candidate === value);
    if (!match) {
      return {
        ok: false,
        code: QUERY_ERROR_CODES.INVALID_FILTER,
        message: `invalid ${key} value`,
      };
    }
    if (!out.includes(match)) out.push(match);
    if (out.length > MAX_VALUES_PER_FILTER) {
      return {
        ok: false,
        code: QUERY_ERROR_CODES.INVALID_FILTER,
        message: `too many ${key} values`,
      };
    }
  }
  return { ok: true, values: out };
}

function parseIds(
  key: string,
  values: string[],
): { ok: true; values: number[] } | QueryParseError {
  const out: number[] = [];
  for (const raw of values) {
    const value = clean(raw);
    if (!value) continue;
    const parsed = parsePositiveInt(value);
    if (parsed === null) {
      return { ok: false, code: QUERY_ERROR_CODES.INVALID_ID, message: `${key} must be a positive integer` };
    }
    if (!out.includes(parsed)) out.push(parsed);
  }
  return { ok: true, values: out };
}

function parseBoundedStrings(
  values: string[],
  maxLength: number,
): string[] {
  const out: string[] = [];
  for (const raw of values) {
    const value = stripControls(clean(raw));
    if (!value) continue;
    if (value.length > maxLength) continue;
    if (!out.includes(value)) out.push(value);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/**
 * Parse a URL query string into a normalized, immutable query. Unknown keys are
 * ignored (the frontend drops them the same way) and reported in `ignored`.
 */
export function parseQuery(search: string, options: ParseQueryOptions = {}): QueryParseOk | QueryParseError {
  const raw = search.startsWith("?") ? search.slice(1) : search;
  const params = new URLSearchParams(raw);

  const buckets = new Map<string, string[]>();
  const ignored: string[] = [];
  for (const [key, value] of params.entries()) {
    if (!ALLOWED_KEYS.includes(key)) {
      if (!ignored.includes(key)) ignored.push(key);
      continue;
    }
    const bucket = buckets.get(key) ?? [];
    bucket.push(value);
    buckets.set(key, bucket);
  }

  const valuesFor = (key: string): string[] => buckets.get(key) ?? [];
  const first = (key: string): string | null => {
    const values = valuesFor(key);
    return values.length > 0 ? values[0] : null;
  };

  // --- ids ---
  const locationId = parseIds("locationId", valuesFor("locationId"));
  if (!locationId.ok) return locationId;
  const hostId = parseIds("hostId", valuesFor("hostId"));
  if (!hostId.ok) return hostId;
  const reportId = parseIds("reportId", valuesFor("reportId"));
  if (!reportId.ok) return reportId;

  // --- enums ---
  const severity = parseEnum("severity", valuesFor("severity"), ALLOWED_SEVERITY);
  if (!severity.ok) return severity;
  const status = parseEnum("status", valuesFor("status"), ALLOWED_STATUS);
  if (!status.ok) return status;
  const treatment = parseEnum("treatment", valuesFor("treatment"), ALLOWED_TREATMENT);
  if (!treatment.ok) return treatment;
  const via = parseEnum("via", valuesFor("via"), ALLOWED_VIA);
  if (!via.ok) return via;
  const privilege = parseEnum("privilege", valuesFor("privilege"), ALLOWED_PRIVILEGE);
  if (!privilege.ok) return privilege;
  const platform = parseEnum("platform", valuesFor("platform"), ALLOWED_PLATFORM);
  if (!platform.ok) return platform;
  const evidenceDepth = parseEnum(
    "evidenceDepth",
    valuesFor("evidenceDepth"),
    ALLOWED_EVIDENCE_DEPTH,
  );
  if (!evidenceDepth.ok) return evidenceDepth;
  const source = parseEnum("source", valuesFor("source"), ALLOWED_SOURCE);
  if (!source.ok) return source;

  // --- free strings ---
  const category = parseBoundedStrings(valuesFor("category"), MAX_CATEGORY_LENGTH);
  const standard = parseBoundedStrings(valuesFor("standard"), MAX_STANDARD_LENGTH);
  const extractorVersion = parseBoundedStrings(valuesFor("extractorVersion"), MAX_VERSION_LENGTH);
  const rawCheckIds = parseBoundedStrings(valuesFor("checkId"), MAX_CHECK_ID_LENGTH);
  const checkId = rawCheckIds.filter((value) => /^[A-Za-z0-9_-]+$/.test(value));

  // --- range ---
  let from: string | null = null;
  let to: string | null = null;
  const fromRaw = first("from");
  if (fromRaw !== null && clean(fromRaw)) {
    const parsed = parseIso(fromRaw);
    if (!parsed) {
      return { ok: false, code: QUERY_ERROR_CODES.INVALID_FILTER, message: "from must be an ISO timestamp" };
    }
    from = parsed;
  }
  const toRaw = first("to");
  if (toRaw !== null && clean(toRaw)) {
    const parsed = parseIso(toRaw);
    if (!parsed) {
      return { ok: false, code: QUERY_ERROR_CODES.INVALID_FILTER, message: "to must be an ISO timestamp" };
    }
    to = parsed;
  }
  if (from !== null && to !== null && from > to) {
    return { ok: false, code: QUERY_ERROR_CODES.INVALID_RANGE, message: "from must be <= to" };
  }

  // --- free-text search (hostile input, capped, never evidence) ---
  let q: string | null = null;
  const qRaw = first("q");
  if (qRaw !== null && clean(qRaw)) {
    const cleaned = stripControls(clean(qRaw));
    if (cleaned.length > MAX_Q_LENGTH) {
      return { ok: false, code: QUERY_ERROR_CODES.QUERY_TOO_LONG, message: `q must be <= ${MAX_Q_LENGTH} characters` };
    }
    q = cleaned;
  }

  // --- scope resolution + validation ---
  const scopeRaw = first(SCOPE_KEY);
  let scope: Scope;
  if (scopeRaw !== null && clean(scopeRaw)) {
    const cleaned = clean(scopeRaw);
    if (!(SCOPES as readonly string[]).includes(cleaned)) {
      return { ok: false, code: QUERY_ERROR_CODES.INVALID_FILTER, message: "invalid scope" };
    }
    scope = cleaned as Scope;
  } else {
    scope = reportId.values.length > 0 ? "report" : from !== null || to !== null ? "range" : "latest";
  }

  if (scope === "report") {
    if (reportId.values.length === 0) {
      return { ok: false, code: QUERY_ERROR_CODES.SCOPE_REQUIRES_REPORT, message: "report scope requires reportId" };
    }
    if (from !== null || to !== null) {
      return { ok: false, code: QUERY_ERROR_CODES.SCOPE_CONFLICT, message: "report scope cannot combine with from/to" };
    }
  } else if (scope === "range") {
    if (from === null && to === null) {
      return { ok: false, code: QUERY_ERROR_CODES.SCOPE_REQUIRES_RANGE, message: "range scope requires from and/or to" };
    }
    if (reportId.values.length > 0) {
      return { ok: false, code: QUERY_ERROR_CODES.SCOPE_CONFLICT, message: "range scope cannot combine with reportId" };
    }
  } else {
    // latest
    if (reportId.values.length > 0) {
      return { ok: false, code: QUERY_ERROR_CODES.SCOPE_CONFLICT, message: "latest scope cannot combine with reportId" };
    }
    if (from !== null || to !== null) {
      return { ok: false, code: QUERY_ERROR_CODES.SCOPE_CONFLICT, message: "latest scope cannot combine with from/to" };
    }
  }

  // --- pagination ---
  let page = 1;
  const pageRaw = first("page");
  if (pageRaw !== null && clean(pageRaw)) {
    const parsed = parsePositiveInt(clean(pageRaw));
    if (parsed === null) {
      return { ok: false, code: QUERY_ERROR_CODES.INVALID_FILTER, message: "page must be a positive integer" };
    }
    page = parsed;
  }
  let pageSize = DEFAULT_PAGE_SIZE;
  const pageSizeRaw = first("pageSize");
  if (pageSizeRaw !== null && clean(pageSizeRaw)) {
    const parsed = parsePositiveInt(clean(pageSizeRaw));
    if (parsed === null || parsed > MAX_PAGE_SIZE) {
      return {
        ok: false,
        code: QUERY_ERROR_CODES.INVALID_FILTER,
        message: `pageSize must be an integer in 1..${MAX_PAGE_SIZE}`,
      };
    }
    pageSize = parsed;
  }

  const campaignId =
    options.campaignId !== undefined && options.campaignId !== null && options.campaignId > 0
      ? options.campaignId
      : null;

  // The campaign fence is server-derived (route path + session user
  // restriction); the client can never widen it through the query string.
  let campaignIds: number[] = [];
  if (campaignId !== null) {
    campaignIds = [campaignId];
  } else if (options.campaignIds && options.campaignIds.length > 0) {
    campaignIds = [...options.campaignIds];
  }

  const filters: QueryFilters = Object.freeze({
    severity: Object.freeze(severity.values),
    category: Object.freeze(category),
    status: Object.freeze(status.values),
    treatment: Object.freeze(treatment.values),
    locationId: Object.freeze(locationId.values),
    hostId: Object.freeze(hostId.values),
    checkId: Object.freeze(checkId),
    reportId: Object.freeze(reportId.values),
    standard: Object.freeze(standard),
    via: Object.freeze(via.values),
    privilege: Object.freeze(privilege.values),
    extractorVersion: Object.freeze(extractorVersion),
    platform: Object.freeze(platform.values),
    evidenceDepth: Object.freeze(evidenceDepth.values),
    source: Object.freeze(source.values),
    from,
    to,
    q,
  });

  const pagination: Pagination = Object.freeze({
    page,
    pageSize,
    offset: (page - 1) * pageSize,
  });

  const query: NormalizedQuery = Object.freeze({
    scope,
    filters,
    campaignId,
    campaignIds: Object.freeze(campaignIds),
    pagination,
    ignored: Object.freeze([...ignored]),
    raw,
  });

  return { ok: true, query };
}

// ---------------------------------------------------------------------------
// SQL fragment builder (100% parameterized)
// ---------------------------------------------------------------------------

export type SqlValue = string | number;

export type SqlFilter = {
  /** Each clause is a fragment containing only `?` placeholders. */
  clauses: readonly string[];
  params: readonly SqlValue[];
};

export type BuildWhereOptions = {
  /** Table alias for `reports`. */
  alias?: string;
  /** Additional trusted, already-parameterized clauses (path/campaign scope). */
  extra?: SqlFilter;
};

/**
 * Build a parameterized WHERE body for the `reports` table from a normalized
 * query. Report-level filters only; result-level filters are applied after the
 * report JSON is parsed. No user value is ever concatenated into SQL.
 */
export function buildReportWhere(query: NormalizedQuery, options: BuildWhereOptions = {}): SqlFilter {
  const alias = options.alias ?? "r";
  const clauses: string[] = [...(options.extra?.clauses ?? [])];
  const params: SqlValue[] = [...(options.extra?.params ?? [])];

  const inClause = (column: string, values: readonly SqlValue[]): void => {
    if (values.length === 0) return;
    const placeholders = values.map(() => "?").join(", ");
    clauses.push(`${alias}.${column} IN (${placeholders})`);
    params.push(...values);
  };

  inClause("location_id", query.filters.locationId);
  inClause("host_id", query.filters.hostId);
  inClause("id", query.filters.reportId);
  inClause("campaign_id", query.campaignIds);
  inClause("via", query.filters.via);
  inClause("privilege_level", query.filters.privilege);
  inClause("evidence_depth", query.filters.evidenceDepth);

  if (query.filters.platform.length > 0) {
    const placeholders = query.filters.platform.map(() => "?").join(", ");
    clauses.push(`${alias}.host_id IN (SELECT id FROM hosts WHERE platform IN (${placeholders}))`);
    params.push(...query.filters.platform);
  }

  if (query.filters.from !== null) {
    clauses.push(`${alias}.received_at >= ?`);
    params.push(query.filters.from);
  }
  if (query.filters.to !== null) {
    clauses.push(`${alias}.received_at <= ?`);
    params.push(query.filters.to);
  }

  return { clauses, params };
}

/** `WHERE ...` text for a built filter, or empty string when there is none. */
export function whereText(filter: SqlFilter): string {
  return filter.clauses.length > 0 ? `WHERE ${filter.clauses.join(" AND ")}` : "";
}

// ---------------------------------------------------------------------------
// Serialization (canonical, stable ordering)
// ---------------------------------------------------------------------------

/** Serialize a normalized query back to a canonical, sorted query string. */
export function serializeQuery(query: NormalizedQuery): string {
  const params = new URLSearchParams();
  const add = (key: string, values: readonly (string | number)[]): void => {
    for (const value of [...values].map(String).sort((a, b) => a.localeCompare(b))) {
      params.append(key, value);
    }
  };
  add("severity", query.filters.severity);
  add("category", query.filters.category);
  add("status", query.filters.status);
  add("treatment", query.filters.treatment);
  add("locationId", query.filters.locationId);
  add("hostId", query.filters.hostId);
  add("checkId", query.filters.checkId);
  add("reportId", query.filters.reportId);
  add("standard", query.filters.standard);
  add("via", query.filters.via);
  add("privilege", query.filters.privilege);
  add("extractorVersion", query.filters.extractorVersion);
  add("platform", query.filters.platform);
  add("evidenceDepth", query.filters.evidenceDepth);
  add("source", query.filters.source);
  if (query.filters.from !== null) params.set("from", query.filters.from);
  if (query.filters.to !== null) params.set("to", query.filters.to);
  if (query.filters.q !== null) params.set("q", query.filters.q);
  if (query.scope !== "latest" || query.filters.reportId.length > 0 || query.filters.from !== null) {
    params.set("scope", query.scope);
  }
  if (query.pagination.page !== 1) params.set("page", String(query.pagination.page));
  if (query.pagination.pageSize !== DEFAULT_PAGE_SIZE) {
    params.set("pageSize", String(query.pagination.pageSize));
  }
  return params.toString();
}
