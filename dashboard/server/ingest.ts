// Unified bounded ingest pipeline (Task 48, spec §6.3).
//
// Push (`POST /api/ingest`) and multipart upload (`POST /api/reports/upload`)
// both funnel through `validateAndIngestEnvelope`. The pipeline:
//   1. enforces every fixed envelope/decompression/JSON bound before costly work;
//   2. resolves exactly one active issuance (v2 by authenticated extractor id,
//      v1 by globally unique legacy key id, then inner identity);
//   3. authenticates push tokens with a constant-time hash comparison scoped to
//      the resolved campaign;
//   4. decrypts and bounded-decompresses, then schema-validates and cross-binds
//      inner/outer/DB identity;
//   5. derives campaign/location ONLY from the issuance row;
//   6. recomputes summary/score/coverage server-side (never trusts report aggregates);
//   7. writes report + host + host_locations + ingest_event in one transaction;
//   8. emits `report-arrived` over SSE only after commit.
//
// Every rejection writes only a redacted `ingest_events` row (no evidence, no
// secrets) and leaves no host/report/orphan mapping. Crypto errors are mapped
// to stable codes and never escape.

import type { Database } from "bun:sqlite";
import { createHash, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  ENVELOPE_ERROR_CODES,
  EnvelopeError,
  parseEnvelope,
  unsealEnvelope,
  type ParsedEnvelope,
} from "./envelope";
import { KeyLifecycle, KeyLifecycleError } from "./keys";
import { SLOT_LEN, SLOT_MAGIC, readSlot } from "./patcher";
import {
  computeCoverage,
  computeRiskScore,
  computeSummary,
  isValidSeverity,
  isValidStatus,
} from "./metrics";
import {
  normalizeHostname,
  normalizeMachineId,
  upsertHost,
  upsertHostLocation,
} from "./hosts";
import { EventBus, emitReportArrived, reportEvents, type ReportArrivedLinks } from "./sse";
import { notifyFindings } from "./notifications";

export type Via = "push" | "upload";
export type PushAuth = { kind: "push"; token: string };
export type SessionAuth = {
  kind: "session";
  user?: { id: number; username: string; role: string };
};
export type IngestAuth = PushAuth | SessionAuth;

export type IngestLinks = ReportArrivedLinks;

export type IngestResult =
  | {
      ok: true;
      duplicate: boolean;
      reportId: number;
      campaignId: number;
      locationId: number;
      hostId: number;
      links: { campaign: string; location: string; host: string; report: string };
    }
  | { ok: false; code: string };

// Fixed ingest bounds (Global Constraints / spec §6.3).
export const MAX_ENVELOPE_BYTES = 16 * 1024 * 1024;
export const MAX_DECOMPRESSED_BYTES = 64 * 1024 * 1024;
export const MAX_JSON_DEPTH = 32;
export const MAX_STRING_LENGTH = 1024 * 1024;
export const MAX_ARRAY_ELEMENTS = 10_000;
export const MAX_RESULTS = 1000;
export const MAX_BATCH_FILES = 32;
export const CURRENT_SCHEMA_VERSION = 1;

/** Stable rejection codes. Envelope codes are reused verbatim. */
export const REJECTION_CODES = {
  ...ENVELOPE_ERROR_CODES,
  JSON_DEPTH_EXCEEDED: "JSON_DEPTH_EXCEEDED",
  STRING_TOO_LONG: "STRING_TOO_LONG",
  ARRAY_TOO_LONG: "ARRAY_TOO_LONG",
  RESULTS_TOO_MANY: "RESULTS_TOO_MANY",
  SCHEMA_INVALID: "SCHEMA_INVALID",
  SCHEMA_VERSION_UNSUPPORTED: "SCHEMA_VERSION_UNSUPPORTED",
  DUPLICATE_CHECK_ID: "DUPLICATE_CHECK_ID",
  EMPTY_MACHINE_ID: "EMPTY_MACHINE_ID",
  EMPTY_HOSTNAME: "EMPTY_HOSTNAME",
  UNKNOWN_ISSUANCE: "UNKNOWN_ISSUANCE",
  REVOKED_ISSUANCE: "REVOKED_ISSUANCE",
  KEY_ID_MISMATCH: "KEY_ID_MISMATCH",
  AMBIGUOUS_V1_KEY: "AMBIGUOUS_V1_KEY",
  INNER_IDENTITY_MISMATCH: "INNER_IDENTITY_MISMATCH",
  MISSING_PUSH_TOKEN: "MISSING_PUSH_TOKEN",
  INVALID_PUSH_TOKEN: "INVALID_PUSH_TOKEN",
  AUTH_REQUIRED: "AUTH_REQUIRED",
  KEY_UNAVAILABLE: "KEY_UNAVAILABLE",
  BATCH_TOO_LARGE: "BATCH_TOO_LARGE",
  INTERNAL_ERROR: "INTERNAL_ERROR",
} as const;

export type RejectionCode = (typeof REJECTION_CODES)[keyof typeof REJECTION_CODES];

export type IngestOptions = {
  db: Database;
  dataRoot?: string;
  bus?: EventBus;
};

let configured: IngestOptions | null = null;

/** Bind the pipeline to a database/data root. Tests and the HTTP layer call this. */
export function configureIngest(options: IngestOptions): void {
  configured = options;
}

export function resetIngest(): void {
  configured = null;
}

function dataRootOf(options: IngestOptions): string {
  return options.dataRoot ?? process.env.HBS_DATA_ROOT ?? "server/data";
}

class IngestRejection extends Error {
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.name = "IngestRejection";
    this.code = code;
  }
}

function fail(code: string): never {
  throw new IngestRejection(code);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hexOf(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

/** Canonicalize a 16-byte identifier: lowercase, dashes removed. */
function normalizeHexId(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const cleaned = value.trim().toLowerCase().replace(/-/g, "");
  return cleaned ? cleaned : null;
}

/** Parse a u16 key id from the DB (decimal/hex text) or JSON (number). */
function parseKeyId(value: unknown): number | null {
  if (typeof value === "number") {
    return Number.isInteger(value) && value >= 0 && value <= 0xffff ? value : null;
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (/^\d+$/.test(trimmed)) {
      const parsed = Number(trimmed);
      return parsed <= 0xffff ? parsed : null;
    }
    if (/^0x[0-9a-f]+$/i.test(trimmed)) {
      const parsed = Number.parseInt(trimmed, 16);
      return parsed <= 0xffff ? parsed : null;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// JSON bounds (depth / string / array / results)
// ---------------------------------------------------------------------------

/**
 * Cheap string-aware pre-scan that rejects over-deep nesting before JSON.parse
 * ever runs, so a nesting bomb cannot exhaust the parser stack.
 */
function prescanDepth(text: string): string | null {
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    if (inString) {
      if (escaped) escaped = false;
      else if (code === 0x5c) escaped = true;
      else if (code === 0x22) inString = false;
      continue;
    }
    if (code === 0x22) {
      inString = true;
      continue;
    }
    if (code === 0x7b || code === 0x5b) {
      depth += 1;
      if (depth > MAX_JSON_DEPTH) return REJECTION_CODES.JSON_DEPTH_EXCEEDED;
    } else if (code === 0x7d || code === 0x5d) {
      depth -= 1;
      if (depth < 0) return REJECTION_CODES.SCHEMA_INVALID;
    }
  }
  if (inString || depth !== 0) return REJECTION_CODES.SCHEMA_INVALID;
  return null;
}

/** Iterative walk: string/array/depth bounds without recursion. */
function walkBounds(root: unknown): string | null {
  const stack: { value: unknown; depth: number }[] = [{ value: root, depth: 1 }];
  while (stack.length > 0) {
    const current = stack.pop() as { value: unknown; depth: number };
    const value = current.value;
    if (typeof value === "string") {
      if (value.length > MAX_STRING_LENGTH) return REJECTION_CODES.STRING_TOO_LONG;
      continue;
    }
    if (Array.isArray(value)) {
      if (value.length > MAX_ARRAY_ELEMENTS) return REJECTION_CODES.ARRAY_TOO_LONG;
      if (current.depth > MAX_JSON_DEPTH) return REJECTION_CODES.JSON_DEPTH_EXCEEDED;
      for (const item of value) stack.push({ value: item, depth: current.depth + 1 });
      continue;
    }
    if (isRecord(value)) {
      if (current.depth > MAX_JSON_DEPTH) return REJECTION_CODES.JSON_DEPTH_EXCEEDED;
      for (const key of Object.keys(value)) {
        if (key.length > MAX_STRING_LENGTH) return REJECTION_CODES.STRING_TOO_LONG;
        stack.push({ value: value[key], depth: current.depth + 1 });
      }
    }
  }
  return null;
}

type ValidatedReport = {
  schemaVersion: number;
  scan: Record<string, unknown>;
  metadata: Record<string, unknown>;
  results: Record<string, unknown>[];
  doc: Record<string, unknown>;
};

function parseAndValidateReport(plaintext: Uint8Array): ValidatedReport {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
  } catch {
    fail(REJECTION_CODES.SCHEMA_INVALID);
  }

  const depthError = prescanDepth(text);
  if (depthError) fail(depthError);

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    fail(REJECTION_CODES.SCHEMA_INVALID);
  }

  const boundsError = walkBounds(parsed);
  if (boundsError) fail(boundsError);

  if (!isRecord(parsed)) fail(REJECTION_CODES.SCHEMA_INVALID);

  const schemaVersion = parsed.schemaVersion;
  if (!Number.isInteger(schemaVersion)) fail(REJECTION_CODES.SCHEMA_INVALID);
  if ((schemaVersion as number) > CURRENT_SCHEMA_VERSION) {
    fail(REJECTION_CODES.SCHEMA_VERSION_UNSUPPORTED);
  }
  if ((schemaVersion as number) < 1) fail(REJECTION_CODES.SCHEMA_INVALID);

  const rawResults = parsed.results;
  if (!Array.isArray(rawResults)) fail(REJECTION_CODES.SCHEMA_INVALID);
  if (rawResults.length > MAX_RESULTS) fail(REJECTION_CODES.RESULTS_TOO_MANY);

  const results: Record<string, unknown>[] = [];
  const ids = new Set<string>();
  for (const entry of rawResults) {
    if (!isRecord(entry)) fail(REJECTION_CODES.SCHEMA_INVALID);
    if (typeof entry.id !== "string" || !entry.id.trim()) fail(REJECTION_CODES.SCHEMA_INVALID);
    if (ids.has(entry.id)) fail(REJECTION_CODES.DUPLICATE_CHECK_ID);
    ids.add(entry.id);
    if (!isValidStatus(entry.status)) fail(REJECTION_CODES.SCHEMA_INVALID);
    if (!isValidSeverity(entry.severity)) fail(REJECTION_CODES.SCHEMA_INVALID);
    results.push(entry);
  }

  return {
    schemaVersion: schemaVersion as number,
    scan: isRecord(parsed.scan) ? parsed.scan : {},
    metadata: isRecord(parsed.metadata) ? parsed.metadata : {},
    results,
    doc: parsed,
  };
}

// ---------------------------------------------------------------------------
// Identity extraction + cross-binding
// ---------------------------------------------------------------------------

function identityField(report: ValidatedReport, name: string): unknown {
  if (report.scan[name] !== undefined) return report.scan[name];
  if (report.doc[name] !== undefined) return report.doc[name];
  if (report.metadata[name] !== undefined) return report.metadata[name];
  return undefined;
}

function readMachineId(report: ValidatedReport): unknown {
  return (
    report.scan.machineId ??
    report.doc.machineId ??
    report.metadata.machineId ??
    report.metadata.machine_id
  );
}

function readHostname(report: ValidatedReport): unknown {
  return report.scan.hostname ?? report.doc.hostname ?? report.metadata.hostname;
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function locateSingleSlot(bytes: Uint8Array): number | null {
  const candidates: number[] = [];
  for (let i = 0; i + SLOT_MAGIC.length <= bytes.length; i += 1) {
    let match = true;
    for (let k = 0; k < SLOT_MAGIC.length; k += 1) {
      if (bytes[i + k] !== SLOT_MAGIC[k]) {
        match = false;
        break;
      }
    }
    if (!match) continue;
    if (i + SLOT_LEN > bytes.length) continue;
    // The magic literal also appears in program code: only a region that
    // parses as a valid slot (or a pristine placeholder) is a real slot.
    let real = false;
    try {
      readSlot(bytes, i);
      real = true;
    } catch {
      real = bytes.subarray(i + 480, i + 512).every((b) => b === 0);
    }
    if (real) {
      candidates.push(i);
      if (candidates.length > 1) return null;
    }
  }
  return candidates.length === 1 ? candidates[0]! : null;
}

/**
 * Recover the keyslot campaign UUID from the issuance's immutable artifact.
 * The DB schema stores no keyslot campaign column, so the artifact is the
 * authoritative source when present. Unreadable artifacts simply contribute
 * no candidate.
 */
function readArtifactCampaignId(path: string | null): string | null {
  if (!path) return null;
  try {
    const bytes = new Uint8Array(readFileSync(path));
    const offset = locateSingleSlot(bytes);
    if (offset === null) return null;
    const slot = readSlot(bytes, offset);
    return Buffer.from(slot.campaignId).toString("hex");
  } catch {
    return null;
  }
}

function acceptableCampaignIds(issuance: IssuanceRow): string[] {
  const ids = new Set<string>();
  const decimal = normalizeHexId(String(issuance.campaign_id));
  if (decimal) ids.add(decimal);
  const artifact = readArtifactCampaignId(issuance.artifact_path);
  if (artifact) ids.add(artifact);
  return [...ids];
}

function assertCrossBinding(
  report: ValidatedReport,
  parsed: ParsedEnvelope,
  issuance: IssuanceRow,
): void {
  const innerExtractor = normalizeHexId(identityField(report, "extractorId"));
  const expectedExtractor =
    parsed.version === 2 ? hexOf(parsed.extractorId) : normalizeHexId(issuance.extractor_id);
  if (!innerExtractor || !expectedExtractor || innerExtractor !== expectedExtractor) {
    fail(REJECTION_CODES.INNER_IDENTITY_MISMATCH);
  }

  const innerKey = parseKeyId(identityField(report, "keyId"));
  const issuanceKey = parseKeyId(issuance.key_id);
  if (
    innerKey === null ||
    innerKey !== parsed.keyId ||
    issuanceKey === null ||
    innerKey !== issuanceKey
  ) {
    fail(REJECTION_CODES.INNER_IDENTITY_MISMATCH);
  }

  const innerCampaign = normalizeHexId(identityField(report, "campaignId"));
  if (!innerCampaign || !acceptableCampaignIds(issuance).includes(innerCampaign)) {
    fail(REJECTION_CODES.INNER_IDENTITY_MISMATCH);
  }
}

// ---------------------------------------------------------------------------
// Issuance resolution
// ---------------------------------------------------------------------------

type IssuanceRow = {
  id: string;
  extractor_id: string;
  campaign_id: number;
  location_id: number;
  key_id: string;
  artifact_path: string | null;
  revoked_at: string | null;
  is_legacy_v1: number;
};

type Resolution =
  | { ok: true; issuance: IssuanceRow }
  | { ok: false; code: string };

function resolveIssuance(db: Database, parsed: ParsedEnvelope): Resolution {
  if (parsed.version === 2) {
    const headerExtractor = hexOf(parsed.extractorId);
    const row = db
      .query(
        "SELECT * FROM issuances WHERE REPLACE(LOWER(extractor_id), '-', '') = ?",
      )
      .get(headerExtractor) as IssuanceRow | null;
    if (!row) return { ok: false, code: REJECTION_CODES.UNKNOWN_ISSUANCE };
    if (row.revoked_at !== null) return { ok: false, code: REJECTION_CODES.REVOKED_ISSUANCE };
    if (parseKeyId(row.key_id) !== parsed.keyId) {
      return { ok: false, code: REJECTION_CODES.KEY_ID_MISMATCH };
    }
    return { ok: true, issuance: row };
  }

  // v1: header carries only key_id. Require exactly one active legacy candidate.
  const legacy = db
    .query("SELECT * FROM issuances WHERE is_legacy_v1 = 1")
    .all() as IssuanceRow[];
  const matches = legacy.filter((row) => parseKeyId(row.key_id) === parsed.keyId);
  const active = matches.filter((row) => row.revoked_at === null);
  if (active.length === 0) {
    return {
      ok: false,
      code: matches.length > 0 ? REJECTION_CODES.REVOKED_ISSUANCE : REJECTION_CODES.UNKNOWN_ISSUANCE,
    };
  }
  if (active.length > 1) return { ok: false, code: REJECTION_CODES.AMBIGUOUS_V1_KEY };
  return { ok: true, issuance: active[0] };
}

// ---------------------------------------------------------------------------
// Push token authentication
// ---------------------------------------------------------------------------

function ensureCampaignTokenTable(db: Database): void {
  db.run(`CREATE TABLE IF NOT EXISTS campaign_tokens (
    campaign_id INTEGER NOT NULL REFERENCES campaigns(id),
    kind TEXT NOT NULL CHECK (kind IN ('download','push')),
    token_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (campaign_id, kind)
  )`);
}

/** Constant-time compare of sha256(token) against the campaign's stored push hash. */
function verifyPushToken(db: Database, campaignId: number, token: string): boolean {
  ensureCampaignTokenTable(db);
  const row = db
    .query("SELECT token_hash FROM campaign_tokens WHERE campaign_id = ? AND kind = 'push'")
    .get(campaignId) as { token_hash: string } | null;
  if (!row || typeof row.token_hash !== "string") return false;
  const actual = createHash("sha256").update(token, "utf8").digest();
  let expected: Buffer;
  try {
    expected = Buffer.from(row.token_hash, "hex");
  } catch {
    return false;
  }
  if (expected.length !== actual.length) return false;
  return timingSafeEqual(actual, expected);
}

// ---------------------------------------------------------------------------
// Audit trail
// ---------------------------------------------------------------------------

type EventInput = {
  via: Via;
  envelopeBytes: number;
  durationMs: number;
  accepted: boolean;
  code: string | null;
  reportId?: number | null;
  issuanceId?: string | null;
};

function recordIngestEvent(db: Database, input: EventInput): void {
  try {
    db.query(
      `INSERT INTO ingest_events
         (received_at, via, envelope_bytes, duration_ms, accepted, reason_code, report_id, issuance_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      new Date().toISOString(),
      input.via,
      input.envelopeBytes,
      input.durationMs,
      input.accepted ? 1 : 0,
      input.code,
      input.reportId ?? null,
      input.issuanceId ?? null,
    );
  } catch {
    // The audit trail must never break or mask an ingest outcome.
  }
}

function mapErrorToCode(error: unknown): string {
  if (error instanceof IngestRejection) return error.code;
  if (error instanceof EnvelopeError) return error.code;
  if (error instanceof KeyLifecycleError) return REJECTION_CODES.KEY_UNAVAILABLE;
  return REJECTION_CODES.INTERNAL_ERROR;
}

function makeLinks(
  campaignId: number,
  locationId: number,
  hostId: number,
  reportId: number,
): IngestLinks {
  return {
    campaign: `/api/campaigns/${campaignId}`,
    location: `/api/campaigns/${campaignId}/locations/${locationId}`,
    host: `/api/hosts/${hostId}`,
    report: `/api/reports/${reportId}`,
  };
}

function isUniqueViolation(error: unknown): boolean {
  return /UNIQUE constraint failed/i.test((error as Error)?.message ?? "");
}

function numeric(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

export async function validateAndIngestEnvelope(
  bytes: Uint8Array,
  via: Via,
  auth: PushAuth | SessionAuth,
): Promise<IngestResult> {
  const options = configured;
  if (!options) return { ok: false, code: REJECTION_CODES.INTERNAL_ERROR };

  const { db } = options;
  const started = Date.now();
  let issuanceId: string | null = null;

  try {
    // Auth shape gate (cheap; before any crypto).
    if (via === "push" && auth?.kind !== "push") fail(REJECTION_CODES.AUTH_REQUIRED);
    if (via === "upload" && auth?.kind !== "session") fail(REJECTION_CODES.AUTH_REQUIRED);

    // 1. Envelope bounds + header parse (envelope size delegated to parseEnvelope).
    const parsed = parseEnvelope(bytes);

    // 2. Issuance resolution (v2 by authenticated extractor id; v1 by legacy key id).
    const resolution = resolveIssuance(db, parsed);
    if (!resolution.ok) fail(resolution.code);
    const issuance = resolution.issuance;
    issuanceId = issuance.id;

    // 3. Push token (only for push), scoped to the resolved campaign.
    if (via === "push") {
      const token = (auth as PushAuth).token;
      if (!token) fail(REJECTION_CODES.MISSING_PUSH_TOKEN);
      if (!verifyPushToken(db, issuance.campaign_id, token)) {
        fail(REJECTION_CODES.INVALID_PUSH_TOKEN);
      }
    }

    // 4. Load the issuance key and bounded-decompress the report.
    const lifecycle = new KeyLifecycle(db, { dataRoot: dataRootOf(options) });
    const privRaw = lifecycle.loadPriv(issuance.id);
    const plaintext = unsealEnvelope(parsed, privRaw, {
      maxDecompressedBytes: MAX_DECOMPRESSED_BYTES,
    });

    // 5. JSON bounds, schema validation, outer/inner/DB cross-binding.
    const report = parseAndValidateReport(plaintext);
    assertCrossBinding(report, parsed, issuance);

    const machineId = normalizeMachineId(readMachineId(report));
    if (!machineId) fail(REJECTION_CODES.EMPTY_MACHINE_ID);
    const hostname = normalizeHostname(readHostname(report));
    if (!hostname) fail(REJECTION_CODES.EMPTY_HOSTNAME);

    const scanIdHex = hexOf(parsed.scanId);
    const reportExtractorId = normalizeHexId(issuance.extractor_id) ?? issuance.extractor_id;
    const receivedAt = new Date().toISOString();

    // 6/9. Duplicate replay is idempotent: return the original links.
    const existing = db
      .query(
        "SELECT id, host_id, location_id, campaign_id FROM reports WHERE extractor_id = ? AND scan_id = ?",
      )
      .get(reportExtractorId, scanIdHex) as
      | { id: number; host_id: number; location_id: number; campaign_id: number }
      | null;
    if (existing) {
      recordIngestEvent(db, {
        via,
        envelopeBytes: bytes.length,
        durationMs: Date.now() - started,
        accepted: true,
        code: "DUPLICATE",
        reportId: existing.id,
        issuanceId: issuance.id,
      });
      return {
        ok: true,
        duplicate: true,
        reportId: existing.id,
        campaignId: existing.campaign_id,
        locationId: existing.location_id,
        hostId: existing.host_id,
        links: makeLinks(existing.campaign_id, existing.location_id, existing.host_id, existing.id),
      };
    }

    // 7. Server-authoritative metrics (never trust supplied aggregates).
    const summary = computeSummary(report.results);
    const score = computeRiskScore(report.results);
    const coverage = computeCoverage(report.results);

    const platform = asString(report.scan.platform) ?? asString(report.metadata.platform);
    const os = asString(report.scan.osName) ?? asString(report.metadata.os_name);
    const arch = asString(report.scan.arch) ?? asString(report.metadata.arch);
    const scanTimestamp =
      numeric(report.scan.startedUnix) !== null
        ? new Date((report.scan.startedUnix as number) * 1000).toISOString()
        : null;
    const peakRssKb = numeric(report.scan.peakRssKb);
    const totalDurationMs = numeric(report.scan.durationMs);
    const privilegeLevel =
      asString(report.scan.privilege) ?? (report.scan.privileged === true ? "elevated" : "degraded");
    const catalogFingerprint = asString(report.scan.catalogFingerprint);
    const evidenceDepth = asString(report.scan.evidenceDepth);

    let hostId = 0;
    let reportId = 0;

    // 8. One transaction: host, host_locations, report, ingest event.
    const commit = db.transaction(() => {
      const host = upsertHost(db, {
        machineId,
        hostname,
        platform,
        os,
        arch,
        seenAt: receivedAt,
      });
      hostId = host.hostId;
      upsertHostLocation(db, hostId, issuance.location_id, receivedAt);

      const inserted = db
        .query(
          `INSERT INTO reports
             (issuance_id, host_id, location_id, campaign_id, extractor_id, scan_id,
              schema_fingerprint, catalog_fingerprint, envelope, report_json, score, coverage,
              summary_json, scan_timestamp, received_at, via, total_duration_ms, collect_duration_ms,
              bytes, peak_rss_bytes, privilege_level, evidence_depth)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          issuance.id,
          hostId,
          issuance.location_id,
          issuance.campaign_id,
          reportExtractorId,
          scanIdHex,
          null,
          catalogFingerprint,
          Buffer.from(bytes),
          JSON.stringify(report.doc),
          score,
          coverage,
          JSON.stringify(summary),
          scanTimestamp,
          receivedAt,
          via,
          totalDurationMs,
          null,
          bytes.length,
          peakRssKb === null ? null : Math.trunc(peakRssKb * 1024),
          privilegeLevel,
          evidenceDepth,
        );
      reportId = Number(inserted.lastInsertRowid);

      recordIngestEvent(db, {
        via,
        envelopeBytes: bytes.length,
        durationMs: Date.now() - started,
        accepted: true,
        code: null,
        reportId,
        issuanceId: issuance.id,
      });
    });

    try {
      commit();
    } catch (error) {
      if (!isUniqueViolation(error)) throw error;
      // Concurrent replay lost the race: return the original idempotently.
      const winner = db
        .query(
          "SELECT id, host_id, location_id, campaign_id FROM reports WHERE extractor_id = ? AND scan_id = ?",
        )
        .get(reportExtractorId, scanIdHex) as
        | { id: number; host_id: number; location_id: number; campaign_id: number }
        | null;
      if (!winner) throw error;
      recordIngestEvent(db, {
        via,
        envelopeBytes: bytes.length,
        durationMs: Date.now() - started,
        accepted: true,
        code: "DUPLICATE",
        reportId: winner.id,
        issuanceId: issuance.id,
      });
      return {
        ok: true,
        duplicate: true,
        reportId: winner.id,
        campaignId: winner.campaign_id,
        locationId: winner.location_id,
        hostId: winner.host_id,
        links: makeLinks(winner.campaign_id, winner.location_id, winner.host_id, winner.id),
      };
    }

    // 11. Post-commit only: live refresh with IDs/links, never evidence.
    const links = makeLinks(issuance.campaign_id, issuance.location_id, hostId, reportId);
    emitReportArrived(
      {
        reportId,
        campaignId: issuance.campaign_id,
        locationId: issuance.location_id,
        hostId,
        duplicate: false,
        links,
      },
      options.bus ?? reportEvents,
    );

    // 12. Post-commit webhook. Deliberately not awaited so ingest latency is
    // unaffected; notifyFindings is best effort and never throws.
    void notifyFindings(db, {
      source: "host",
      reportId,
      campaignId: issuance.campaign_id,
      locationId: issuance.location_id,
      label: hostname,
      findings: report.results.map((entry) => ({
        checkId: String(entry.id ?? ""),
        severity: String(entry.severity ?? ""),
        title: String(entry.title ?? ""),
      })),
    });

    return {
      ok: true,
      duplicate: false,
      reportId,
      campaignId: issuance.campaign_id,
      locationId: issuance.location_id,
      hostId,
      links,
    };
  } catch (error) {
    const code = mapErrorToCode(error);
    recordIngestEvent(db, {
      via,
      envelopeBytes: bytes.length,
      durationMs: Date.now() - started,
      accepted: false,
      code,
      reportId: null,
      issuanceId,
    });
    return { ok: false, code };
  }
}

/**
 * Process a multipart batch. Each file is independent: one corrupt or revoked
 * report never blocks its valid siblings.
 */
export async function ingestBatch(
  files: { name: string; bytes: Uint8Array }[],
  auth: SessionAuth,
): Promise<{ name: string; result: IngestResult }[]> {
  if (files.length > MAX_BATCH_FILES) {
    return files.map((file) => ({
      name: file.name,
      result: { ok: false, code: REJECTION_CODES.BATCH_TOO_LARGE } as IngestResult,
    }));
  }
  const results: { name: string; result: IngestResult }[] = [];
  for (const file of files) {
    const result = await validateAndIngestEnvelope(file.bytes, "upload", auth);
    results.push({ name: file.name, result });
  }
  return results;
}
