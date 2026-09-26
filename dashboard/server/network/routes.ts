// Network device & firewall configuration review — API routes and ingest.
//
// Mirrors the sealed-report model where it applies:
//   * one stable device identity per hostname (or config hash when the
//     hostname is absent), like hosts keyed by machine_id;
//   * per-location presence (`network_device_locations`, like host_locations);
//   * one immutable row per uploaded configuration version
//     (`network_reports`, UNIQUE(device, location, sha256) — replay-safe);
//   * server-authoritative score/summary recomputed from raw findings;
//   * append-only treatment history with justification enforcement;
//   * bounded multipart batch (≤32 files, ≤4 MiB per config) with a single
//     transaction per file so one bad file never blocks its siblings.

import { createHash } from "node:crypto";
import type { Database } from "bun:sqlite";
import type { Context, MiddlewareHandler } from "hono";
import { MAX_CONFIG_BYTES, parseNetworkConfig, redactConfigText, VENDOR_LABELS } from "./config-parser";
import type { ParsedNetworkConfig, VendorId } from "./config-parser";
import { reviewConfig, ruleCatalog } from "./review";
import type { NetworkFinding } from "./review";
import { registerNetworkExportRoutes } from "./export-routes";
import { notifyFindings } from "../notifications";
import { reportEvents } from "../sse";

export const MAX_NETWORK_BATCH_FILES = 32;

const READ_ROLES = ["super_admin", "auditor", "viewer"];
const WRITE_ROLES = ["super_admin", "auditor"];
const ALLOWED_TREATMENT = ["open", "accepted_risk", "false_positive", "remediated"] as const;
type TreatmentState = (typeof ALLOWED_TREATMENT)[number];

export type NetworkAuth = {
  requireRole: (...roles: string[]) => MiddlewareHandler;
};

type Actor = { id: number; username: string; role: string };

function nowIso(): string {
  return new Date().toISOString();
}

function actorOf(c: Context): Actor {
  const user = c.get("user") as Actor | undefined;
  return user ?? { id: 0, username: "unknown", role: "viewer" };
}

function positiveInt(value: unknown): number | null {
  const parsed = typeof value === "number" ? value : Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
}

function stripAndTrim(value: string, maxLength: number): string | null {
  const trimmed = value.trim();
  if (!trimmed) return null;
  return trimmed.slice(0, maxLength);
}

type DeviceRow = {
  id: number;
  device_key: string;
  hostname: string | null;
  vendor: VendorId;
  device_type: string | null;
  model: string | null;
  os_version: string | null;
  serial: string | null;
  first_seen_at: string;
  last_seen_at: string;
};

// ---- ingest -----------------------------------------------------------------

export type NetworkUploadResult =
  | {
      ok: true;
      duplicate: boolean;
      deviceId: number;
      reportId: number;
      campaignId: number;
      locationId: number;
      vendor: VendorId;
      vendorLabel: string;
      deviceType: string;
      hostname: string | null;
      score: number;
      findings: { critical: number; high: number; medium: number; low: number; informational: number; compliant: number; notApplicable: number };
      links: { device: string; report: string };
    }
  | { ok: false; code: string; error: string };

type ParsedReportPayload = {
  profile: ParsedNetworkConfig;
  findings: NetworkFinding[];
  score: number;
  summary: ReturnType<typeof reviewConfig>["summary"];
};

function parseAndReview(text: string, filename: string): ParsedReportPayload {
  const { profile } = parseNetworkConfig(text, filename);
  const lines = text.split(/\r\n|\r|\n/).map((line, index) => ({
    n: index + 1,
    text: line.replace(/\t/g, "  "),
    lower: line.toLowerCase(),
  }));
  const review = reviewConfig(profile, lines);
  return { profile, findings: review.findings, score: review.score, summary: review.summary };
}

function deviceKeyFor(profile: ParsedNetworkConfig, configSha256: string): string {
  const hostname = profile.hostname?.trim().toLowerCase();
  if (hostname) return `host:${hostname.slice(0, 200)}`;
  return `config:${configSha256.slice(0, 16)}`;
}

function upsertNetworkDevice(db: Database, input: {
  deviceKey: string;
  hostname: string | null;
  vendor: VendorId;
  deviceType: string;
  model: string | null;
  osVersion: string | null;
  serial: string | null;
  seenAt: string;
}): { deviceId: number; created: boolean } {
  const existing = db
    .query("SELECT id FROM network_devices WHERE device_key = ?")
    .get(input.deviceKey) as { id: number } | null;
  if (existing) {
    db.query(
      `UPDATE network_devices
         SET hostname = COALESCE(?, hostname),
             last_seen_at = ?,
             vendor = ?,
             device_type = COALESCE(?, device_type),
             model = COALESCE(?, model),
             os_version = COALESCE(?, os_version),
             serial = COALESCE(?, serial)
       WHERE id = ?`,
    ).run(input.hostname, input.seenAt, input.vendor, input.deviceType, input.model, input.osVersion, input.serial, existing.id);
    return { deviceId: existing.id, created: false };
  }
  const inserted = db
    .query(
      `INSERT INTO network_devices
         (device_key, hostname, vendor, device_type, model, os_version, serial, first_seen_at, last_seen_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(input.deviceKey, input.hostname, input.vendor, input.deviceType, input.model, input.osVersion, input.serial, input.seenAt, input.seenAt);
  return { deviceId: Number(inserted.lastInsertRowid), created: true };
}

function upsertNetworkDeviceLocation(db: Database, deviceId: number, locationId: number, seenAt: string): void {
  db.query(
    `INSERT INTO network_device_locations (device_id, location_id, first_seen_at, last_seen_at)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(device_id, location_id)
     DO UPDATE SET last_seen_at = excluded.last_seen_at`,
  ).run(deviceId, locationId, seenAt, seenAt);
}

/** Parse + review + persist one configuration file. Never throws. */
export function ingestNetworkConfig(
  db: Database,
  input: {
    name: string;
    bytes: Uint8Array;
    campaignId: number;
    locationId: number;
    uploadedBy: string;
  },
): NetworkUploadResult {
  if (input.bytes.length === 0) {
    return { ok: false, code: "EMPTY_FILE", error: "configuration file is empty" };
  }
  if (input.bytes.length > MAX_CONFIG_BYTES) {
    return { ok: false, code: "FILE_TOO_LARGE", error: `configuration exceeds ${MAX_CONFIG_BYTES} byte limit` };
  }

  // Resolve and validate the target campaign/location pair.
  const location = db
    .query(
      `SELECT l.id, l.campaign_id, l.retired_at, c.id AS campaign_exists
         FROM locations l
         JOIN campaigns c ON c.id = l.campaign_id
        WHERE l.id = ?`,
    )
    .get(input.locationId) as { id: number; campaign_id: number; retired_at: string | null } | null;
  if (!location) return { ok: false, code: "LOCATION_NOT_FOUND", error: "location not found" };
  if (location.campaign_id !== input.campaignId) {
    return { ok: false, code: "LOCATION_MISMATCH", error: "location does not belong to this campaign" };
  }
  if (location.retired_at) {
    return { ok: false, code: "LOCATION_RETIRED", error: "cannot upload to a retired location" };
  }

  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: false }).decode(input.bytes);
  } catch {
    return { ok: false, code: "BINARY_NOT_CONFIG", error: "file is not decodable text" };
  }
  // Reject obvious binary payloads (sealed reports, images, …).
  if (/\u0000/.test(text.slice(0, 4096))) {
    return { ok: false, code: "BINARY_NOT_CONFIG", error: "file does not look like a text configuration" };
  }

  const configSha256 = createHash("sha256").update(input.bytes).digest("hex");
  let payload: ParsedReportPayload;
  try {
    payload = parseAndReview(text, input.name);
  } catch {
    return { ok: false, code: "PARSE_FAILED", error: "configuration could not be parsed" };
  }

  const timestamp = nowIso();
  const deviceKey = deviceKeyFor(payload.profile, configSha256);

  try {
    const outcome = db.transaction(() => {
      const device = upsertNetworkDevice(db, {
        deviceKey,
        hostname: payload.profile.hostname,
        vendor: payload.profile.vendor,
        deviceType: payload.profile.deviceType,
        model: payload.profile.model,
        osVersion: payload.profile.osVersion,
        serial: payload.profile.serial,
        seenAt: timestamp,
      });
      upsertNetworkDeviceLocation(db, device.deviceId, input.locationId, timestamp);

      const duplicate = db
        .query(
          "SELECT id FROM network_reports WHERE device_id = ? AND location_id = ? AND config_sha256 = ?",
        )
        .get(device.deviceId, input.locationId, configSha256) as { id: number } | null;
      if (duplicate) {
        return { reportId: duplicate.id, duplicate: true, deviceId: device.deviceId };
      }

      const inserted = db
        .query(
          `INSERT INTO network_reports
             (device_id, location_id, campaign_id, config_name, config_sha256, config_size,
              config_text, parsed_json, findings_json, summary_json, score, received_at, uploaded_by)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          device.deviceId,
          input.locationId,
          input.campaignId,
          input.name.slice(0, 256),
          configSha256,
          input.bytes.length,
          text,
          JSON.stringify(payload.profile),
          JSON.stringify(payload.findings),
          JSON.stringify(payload.summary),
          payload.score,
          timestamp,
          input.uploadedBy,
        );
      db.query(
        `INSERT INTO audit_log (actor, actor_ip, action, resource, details, created_at)
         VALUES (?, NULL, 'network.config.upload', ?, ?, ?)`,
      ).run(
        input.uploadedBy,
        `network_report:${Number(inserted.lastInsertRowid)}`,
        JSON.stringify({
          vendor: payload.profile.vendor,
          hostname: payload.profile.hostname,
          findings: payload.summary.critical + payload.summary.high + payload.summary.medium + payload.summary.low,
          bytes: input.bytes.length,
        }),
        timestamp,
      );
      return { reportId: Number(inserted.lastInsertRowid), duplicate: false, deviceId: device.deviceId };
    })();

    reportEvents.emit({
      event: "network-config-arrived",
      data: {
        reportId: outcome.reportId,
        deviceId: outcome.deviceId,
        campaignId: input.campaignId,
        locationId: input.locationId,
        duplicate: outcome.duplicate,
        links: {
          device: `/api/network/devices/${outcome.deviceId}`,
          report: `/api/network/reports/${outcome.reportId}`,
        },
      },
    });

    // Fire-and-forget webhook when configured (shared with host ingest).
    if (!outcome.duplicate) {
      void notifyFindings(db, {
        source: "network",
        reportId: outcome.reportId,
        campaignId: input.campaignId,
        locationId: input.locationId,
        label: `${payload.profile.hostname ?? `device #${outcome.deviceId}`} (${payload.profile.vendorLabel})`,
        findings: payload.findings.map((finding) => ({ checkId: finding.checkId, severity: finding.severity, title: finding.title })),
      });
    }

    return {
      ok: true,
      duplicate: outcome.duplicate,
      deviceId: outcome.deviceId,
      reportId: outcome.reportId,
      campaignId: input.campaignId,
      locationId: input.locationId,
      vendor: payload.profile.vendor,
      vendorLabel: payload.profile.vendorLabel,
      deviceType: payload.profile.deviceType,
      hostname: payload.profile.hostname,
      score: payload.score,
      findings: {
        critical: payload.summary.critical,
        high: payload.summary.high,
        medium: payload.summary.medium,
        low: payload.summary.low,
        informational: payload.summary.informational,
        compliant: payload.summary.compliant,
        notApplicable: payload.summary.notApplicable,
      },
      links: {
        device: `/api/network/devices/${outcome.deviceId}`,
        report: `/api/network/reports/${outcome.reportId}`,
      },
    };
  } catch (error) {
    return { ok: false, code: "STORAGE_FAILED", error: (error as Error).message.slice(0, 200) };
  }
}

// ---- read models ----------------------------------------------------------------

type FindingStateRow = { check_id: string; state: string };

function treatmentMapFor(db: Database, reportId: number): Map<string, string> {
  const rows = db
    .query("SELECT check_id, state FROM network_finding_states WHERE report_id = ?")
    .all(reportId) as FindingStateRow[];
  return new Map(rows.map((row) => [row.check_id, row.state]));
}

type SeveritySummary = { critical: number; high: number; medium: number; low: number; informational: number };

function knownFindingsFor(db: Database, reportId: number): string[] | null {
  const report = db.query("SELECT findings_json FROM network_reports WHERE id = ?").get(reportId) as {
    findings_json: string;
  } | null;
  if (!report) return null;
  try {
    return (JSON.parse(report.findings_json) as NetworkFinding[]).map((finding) => finding.checkId);
  } catch {
    return [];
  }
}

type ParsedTreatmentInput = {
  state: TreatmentState;
  justification: string | null;
  assignee: string | null;
  dueDate: string | null;
};

function parseTreatmentInput(body: Record<string, unknown>): ParsedTreatmentInput | { error: string; code: string } {
  const state = typeof body.state === "string" ? body.state : "";
  if (!ALLOWED_TREATMENT.includes(state as TreatmentState)) {
    return { error: "invalid treatment state", code: "INVALID_TREATMENT_STATE" };
  }
  const justification = typeof body.justification === "string" ? stripAndTrim(body.justification, 2048) : null;
  if ((state === "accepted_risk" || state === "false_positive") && !justification) {
    return { error: "justification is required for accepted_risk and false_positive", code: "JUSTIFICATION_REQUIRED" };
  }
  const assignee = typeof body.assignee === "string" ? stripAndTrim(body.assignee, 128) : null;
  let dueDate: string | null = null;
  if (typeof body.dueDate === "string" && body.dueDate.trim()) {
    const millis = Date.parse(body.dueDate);
    if (!Number.isFinite(millis)) {
      return { error: "dueDate must be an ISO timestamp", code: "INVALID_DUE_DATE" };
    }
    dueDate = new Date(millis).toISOString();
  }
  return { state: state as TreatmentState, justification, assignee, dueDate };
}

function applyTreatmentChange(
  db: Database,
  args: {
    reportId: number;
    checkId: string;
    input: ParsedTreatmentInput;
    actor: string;
    actorIp: string | null;
  },
): { historyId: number; timestamp: string } {
  const { reportId, checkId, input } = args;
  const timestamp = nowIso();
  const previous = db
    .query("SELECT state FROM network_finding_states WHERE report_id = ? AND check_id = ?")
    .get(reportId, checkId) as { state: string } | null;
  // Baseline row so the very first treatment records a from_state of
  // "open" and consistently takes the UPDATE path (which the append-only
  // history trigger listens to).
  db.query(
    `INSERT INTO network_finding_states (report_id, check_id, state, assignee, due_date, updated_at)
     VALUES (?, ?, 'open', NULL, NULL, ?)
     ON CONFLICT(report_id, check_id) DO NOTHING`,
  ).run(reportId, checkId, timestamp);
  db.query(
    `INSERT INTO network_finding_states (report_id, check_id, state, assignee, due_date, updated_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(report_id, check_id) DO UPDATE SET
       state = excluded.state,
       assignee = excluded.assignee,
       due_date = excluded.due_date,
       updated_at = excluded.updated_at`,
  ).run(reportId, checkId, input.state, input.assignee, input.dueDate, timestamp);
  const projection = db
    .query("SELECT id FROM network_finding_states WHERE report_id = ? AND check_id = ?")
    .get(reportId, checkId) as { id: number };
  const history = db
    .query(
      `INSERT INTO network_finding_state_history
         (finding_state_id, actor, changed_at, from_state, to_state, justification, assignee, due_date)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(projection.id, args.actor, timestamp, previous?.state ?? "open", input.state, input.justification, input.assignee, input.dueDate);
  db.query(
    `INSERT INTO audit_log (actor, actor_ip, action, resource, details, created_at)
     VALUES (?, ?, 'network.treatment.update', ?, ?, ?)`,
  ).run(
    args.actor,
    args.actorIp,
    `network_report:${reportId}:finding:${checkId}`,
    JSON.stringify({ state: input.state, from: previous?.state ?? "open" }),
    timestamp,
  );
  return { historyId: Number(history.lastInsertRowid), timestamp };
}

/** Status transitions between two review runs of the same device. */
export type NetworkDiffEntry = { checkId: string; title: string; severity: string; from: string; to: string };

export function diffNetworkFindings(
  from: NetworkFinding[],
  to: NetworkFinding[],
): { fixed: NetworkDiffEntry[]; regressed: NetworkDiffEntry[]; changed: NetworkDiffEntry[]; unchangedCount: number } {
  const fromMap = new Map(from.map((finding) => [finding.checkId, finding]));
  const toMap = new Map(to.map((finding) => [finding.checkId, finding]));
  const failRank = (status: string): number => (status === "NonCompliant" ? 1 : 0);
  const fixed: NetworkDiffEntry[] = [];
  const regressed: NetworkDiffEntry[] = [];
  const changed: NetworkDiffEntry[] = [];
  let unchangedCount = 0;
  for (const [checkId, before] of fromMap) {
    const after = toMap.get(checkId);
    if (!after) {
      unchangedCount += 1;
      continue;
    }
    const entry: NetworkDiffEntry = { checkId, title: after.title, severity: after.severity, from: before.status, to: after.status };
    if (failRank(before.status) > failRank(after.status)) fixed.push(entry);
    else if (failRank(before.status) < failRank(after.status)) regressed.push(entry);
    else if (before.status !== after.status || before.severity !== after.severity) changed.push(entry);
    else unchangedCount += 1;
  }
  for (const [checkId, after] of toMap) {
    if (fromMap.has(checkId)) continue;
    const entry: NetworkDiffEntry = { checkId, title: after.title, severity: after.severity, from: "NewCheck", to: after.status };
    if (after.status === "NonCompliant") regressed.push(entry);
    else unchangedCount += 1;
  }
  return { fixed, regressed, changed, unchangedCount };
}

function severityOfFindings(findings: NetworkFinding[], statusesToCount: string[] = ["NonCompliant"]): SeveritySummary {
  const summary: SeveritySummary = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  for (const finding of findings) {
    if (!statusesToCount.includes(finding.status)) continue;
    const key = finding.severity.toLowerCase() as keyof SeveritySummary;
    summary[key] += 1;
  }
  return summary;
}

function deviceSummary(db: Database, device: DeviceRow): {
  reportCount: number;
  latestReportId: number | null;
  latestReceivedAt: string | null;
  score: number | null;
  severity: SeveritySummary;
  locationCount: number;
} {
  const reportRows = db
    .query(
      `SELECT id, score, received_at, findings_json
         FROM network_reports
        WHERE device_id = ?
        ORDER BY received_at DESC, id DESC`,
    )
    .all(device.id) as Array<{ id: number; score: number | null; received_at: string; findings_json: string }>;
  const locations = db
    .query("SELECT COUNT(*) AS n FROM network_device_locations WHERE device_id = ?")
    .get(device.id) as { n: number };
  let severity: SeveritySummary = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  if (reportRows.length > 0) {
    try {
      const findings = JSON.parse(reportRows[0].findings_json) as NetworkFinding[];
      severity = severityOfFindings(findings);
    } catch {
      severity = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
    }
  }
  return {
    reportCount: reportRows.length,
    latestReportId: reportRows[0]?.id ?? null,
    latestReceivedAt: reportRows[0]?.received_at ?? null,
    score: reportRows[0]?.score ?? null,
    severity,
    locationCount: Number(locations?.n ?? 0),
  };
}

// ---- route registration -------------------------------------------------------------

export function registerNetworkRoutes(app: import("hono").Hono, db: Database, auth: NetworkAuth): void {
  registerNetworkExportRoutes(app, db, auth);
  // ---- upload (multipart batch) ----
  app.post("/api/network/upload", auth.requireRole(...WRITE_ROLES), async (c) => {
    const declared = Number(c.req.header("content-length") ?? "0");
    if (Number.isFinite(declared) && declared > 64 * 1024 * 1024) {
      return c.json({ error: "payload too large", code: "BODY_TOO_LARGE" }, 413);
    }
    let form: FormData | null = null;
    try {
      form = await c.req.formData();
    } catch {
      return c.json({ error: "expected multipart form data", code: "INVALID_FORM" }, 400);
    }
    if (!form) return c.json({ error: "expected multipart form data", code: "INVALID_FORM" }, 400);

    const campaignId = positiveInt(form.get("campaignId"));
    const locationId = positiveInt(form.get("locationId"));
    if (!campaignId || !locationId) {
      return c.json({ error: "campaignId and locationId are required", code: "INVALID_TARGET" }, 400);
    }

    const files: Array<{ name: string; bytes: Uint8Array }> = [];
    for (const value of form.values()) {
      if (typeof value === "string") continue;
      const file = value as unknown as { name?: string; arrayBuffer(): Promise<ArrayBuffer> };
      files.push({ name: file.name || "config.txt", bytes: new Uint8Array(await file.arrayBuffer()) });
    }
    if (files.length === 0) return c.json({ error: "no files provided", code: "NO_FILES" }, 400);
    if (files.length > MAX_NETWORK_BATCH_FILES) {
      return c.json({ error: `at most ${MAX_NETWORK_BATCH_FILES} files per batch`, code: "BATCH_TOO_LARGE" }, 413);
    }

    const user = actorOf(c);
    const results = files.map((file) => ({
      name: file.name,
      result: ingestNetworkConfig(db, {
        name: file.name,
        bytes: file.bytes,
        campaignId,
        locationId,
        uploadedBy: user.username,
      }),
    }));
    return c.json({ results }, results.some((entry) => entry.result.ok) ? 200 : 400);
  });

  // ---- rule catalog (UI legend / client tooling) ----
  app.get("/api/network/rules", auth.requireRole(...READ_ROLES), (c) => {
    const catalog = ruleCatalog();
    return c.json({ total: catalog.length, rules: catalog });
  });

  // ---- device listing ----
  app.get("/api/network/devices", auth.requireRole(...READ_ROLES), (c) => {
    const campaignId = positiveInt(c.req.query("campaignId"));
    const locationId = positiveInt(c.req.query("locationId"));
    if (!campaignId && !locationId) {
      return c.json({ error: "campaignId or locationId is required", code: "INVALID_FILTER" }, 400);
    }

    const rows = (
      locationId
        ? db.query(
            `SELECT DISTINCT d.*
               FROM network_devices d
               JOIN network_device_locations dl ON dl.device_id = d.id
              WHERE dl.location_id = ?
              ORDER BY d.hostname`,
          ).all(locationId)
        : db.query(
            `SELECT DISTINCT d.*
               FROM network_devices d
               JOIN network_reports nr ON nr.device_id = d.id
              WHERE nr.campaign_id = ?
              ORDER BY d.hostname`,
          ).all(campaignId)
    ) as DeviceRow[];

    const devices = rows.map((row) => {
      const summary = deviceSummary(db, row);
      return {
        id: row.id,
        hostname: row.hostname,
        vendor: row.vendor,
        vendorLabel: VENDOR_LABELS[row.vendor] ?? row.vendor,
        deviceType: row.device_type,
        model: row.model,
        osVersion: row.os_version,
        serial: row.serial,
        firstSeenAt: row.first_seen_at,
        lastSeenAt: row.last_seen_at,
        reportCount: summary.reportCount,
        latestReportId: summary.latestReportId,
        latestReceivedAt: summary.latestReceivedAt,
        score: summary.score,
        severity: summary.severity,
        locationCount: summary.locationCount,
        links: { device: `/api/network/devices/${row.id}` },
      };
    });
    return c.json({ devices });
  });

  // ---- device detail ----
  app.get("/api/network/devices/:id", auth.requireRole(...READ_ROLES), (c) => {
    const deviceId = positiveInt(c.req.param("id"));
    if (!deviceId) return c.json({ error: "invalid device id", code: "INVALID_ID" }, 400);
    const device = db
      .query("SELECT * FROM network_devices WHERE id = ?")
      .get(deviceId) as DeviceRow | null;
    if (!device) return c.json({ error: "device not found", code: "NOT_FOUND" }, 404);

    const locations = db
      .query(
        `SELECT l.id, l.name, l.campaign_id, dl.first_seen_at, dl.last_seen_at
           FROM network_device_locations dl
           JOIN locations l ON l.id = dl.location_id
          WHERE dl.device_id = ?
          ORDER BY dl.last_seen_at DESC`,
      )
      .all(deviceId) as Array<{ id: number; name: string; campaign_id: number; first_seen_at: string; last_seen_at: string }>;

    const reportRows = db
      .query(
        `SELECT id, campaign_id, location_id, config_name, config_size, config_sha256, score, received_at, uploaded_by
           FROM network_reports
          WHERE device_id = ?
          ORDER BY received_at DESC, id DESC`,
      )
      .all(deviceId) as Array<{
      id: number;
      campaign_id: number;
      location_id: number;
      config_name: string;
      config_size: number;
      config_sha256: string;
      score: number | null;
      received_at: string;
      uploaded_by: string | null;
    }>;

    const reports = reportRows.map((row) => ({
      id: row.id,
      campaignId: row.campaign_id,
      locationId: row.location_id,
      configName: row.config_name,
      configSize: row.config_size,
      configSha256: row.config_sha256,
      score: row.score,
      receivedAt: row.received_at,
      uploadedBy: row.uploaded_by,
      links: { report: `/api/network/reports/${row.id}` },
    }));

    // Latest report drives the summary + current findings.
    let latest: {
      reportId: number | null;
      receivedAt: string | null;
      score: number | null;
      parsed: ParsedNetworkConfig | null;
      findings: NetworkFinding[];
      severity: SeveritySummary;
    } = {
      reportId: null,
      receivedAt: null,
      score: null,
      parsed: null,
      findings: [],
      severity: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
    };
    if (reports.length > 0) {
      const latestRow = db
        .query("SELECT id, received_at, score, parsed_json, findings_json FROM network_reports WHERE id = ?")
        .get(reports[0].id) as { id: number; received_at: string; score: number | null; parsed_json: string; findings_json: string } | null;
      if (latestRow) {
        const treatment = treatmentMapFor(db, latestRow.id);
        let findings: NetworkFinding[] = [];
        let parsed: ParsedNetworkConfig | null = null;
        try {
          findings = JSON.parse(latestRow.findings_json) as NetworkFinding[];
          parsed = JSON.parse(latestRow.parsed_json) as ParsedNetworkConfig;
        } catch {
          findings = [];
        }
        findings = findings.map((finding) => ({
          ...finding,
          treatmentState: treatment.get(finding.checkId) ?? "open",
        }));
        latest = {
          reportId: latestRow.id,
          receivedAt: latestRow.received_at,
          score: latestRow.score,
          parsed,
          findings,
          severity: severityOfFindings(findings, ["NonCompliant"]),
        };
      }
    }

    return c.json({
      device: {
        id: device.id,
        deviceKey: device.device_key,
        hostname: device.hostname,
        vendor: device.vendor,
        vendorLabel: VENDOR_LABELS[device.vendor] ?? device.vendor,
        deviceType: device.device_type,
        model: device.model,
        osVersion: device.os_version,
        serial: device.serial,
        firstSeenAt: device.first_seen_at,
        lastSeenAt: device.last_seen_at,
      },
      locations: locations.map((row) => ({
        id: row.id,
        name: row.name,
        campaignId: row.campaign_id,
        firstSeenAt: row.first_seen_at,
        lastSeenAt: row.last_seen_at,
        links: { location: `/api/campaigns/${row.campaign_id}/locations/${row.id}` },
      })),
      reports,
      latest,
      summary: {
        severity: latest.severity,
        reportCount: reports.length,
      },
    });
  });

  // ---- configuration drift between two review runs ----
  app.get("/api/network/devices/:id/diff", auth.requireRole(...READ_ROLES), (c) => {
    const deviceId = positiveInt(c.req.param("id"));
    if (!deviceId) return c.json({ error: "invalid device id", code: "INVALID_ID" }, 400);
    const device = db.query("SELECT * FROM network_devices WHERE id = ?").get(deviceId) as DeviceRow | null;
    if (!device) return c.json({ error: "device not found", code: "NOT_FOUND" }, 404);

    const reportRows = db
      .query(
        `SELECT id, received_at, score, findings_json
           FROM network_reports
          WHERE device_id = ?
          ORDER BY received_at DESC, id DESC`,
      )
      .all(deviceId) as Array<{ id: number; received_at: string; score: number | null; findings_json: string }>;

    if (reportRows.length < 2) {
      return c.json({ device: { id: device.id, hostname: device.hostname }, diff: null, reason: "NEED_TWO_REPORTS" });
    }

    const toParam = positiveInt(c.req.query("to"));
    const fromParam = positiveInt(c.req.query("from"));
    const to = toParam !== null ? reportRows.find((row) => row.id === toParam) : reportRows[0];
    const from = fromParam !== null ? reportRows.find((row) => row.id === fromParam) : reportRows[1];
    if (!to || !from || to.id === from.id) {
      return c.json({ error: "from/to must reference two distinct reports of this device", code: "INVALID_FILTER" }, 400);
    }

    const parse = (row: { findings_json: string }): NetworkFinding[] => {
      try {
        return JSON.parse(row.findings_json) as NetworkFinding[];
      } catch {
        return [];
      }
    };
    const diff = diffNetworkFindings(parse(from), parse(to));
    return c.json({
      device: { id: device.id, hostname: device.hostname },
      from: { reportId: from.id, receivedAt: from.received_at, score: from.score },
      to: { reportId: to.id, receivedAt: to.received_at, score: to.score },
      ...diff,
      links: {
        from: `/api/network/reports/${from.id}`,
        to: `/api/network/reports/${to.id}`,
      },
    });
  });

  // ---- report detail (parsed config + findings + redacted raw config) ----
  app.get("/api/network/reports/:id", auth.requireRole(...READ_ROLES), (c) => {
    const reportId = positiveInt(c.req.param("id"));
    if (!reportId) return c.json({ error: "invalid report id", code: "INVALID_ID" }, 400);
    const row = db
      .query(
        `SELECT nr.id, nr.device_id, nr.location_id, nr.campaign_id, nr.config_name, nr.config_sha256,
                nr.config_size, nr.config_text, nr.parsed_json, nr.findings_json, nr.summary_json,
                nr.score, nr.received_at, nr.uploaded_by,
                d.hostname, d.vendor, d.device_type, d.model, d.os_version, d.serial
           FROM network_reports nr
           JOIN network_devices d ON d.id = nr.device_id
          WHERE nr.id = ?`,
      )
      .get(reportId) as
      | {
          id: number;
          device_id: number;
          location_id: number;
          campaign_id: number;
          config_name: string;
          config_sha256: string;
          config_size: number;
          config_text: string;
          parsed_json: string;
          findings_json: string;
          summary_json: string | null;
          score: number | null;
          received_at: string;
          uploaded_by: string | null;
          hostname: string | null;
          vendor: VendorId;
          device_type: string | null;
          model: string | null;
          os_version: string | null;
          serial: string | null;
        }
      | null;
    if (!row) return c.json({ error: "report not found", code: "NOT_FOUND" }, 404);

    const treatment = treatmentMapFor(db, reportId);
    let findings: NetworkFinding[] = [];
    try {
      findings = (JSON.parse(row.findings_json) as NetworkFinding[]).map((finding) => ({
        ...finding,
        treatmentState: treatment.get(finding.checkId) ?? "open",
      }));
    } catch {
      findings = [];
    }
    let parsed: ParsedNetworkConfig | null = null;
    try {
      parsed = JSON.parse(row.parsed_json) as ParsedNetworkConfig;
    } catch {
      parsed = null;
    }

    return c.json({
      report: {
        id: row.id,
        deviceId: row.device_id,
        campaignId: row.campaign_id,
        locationId: row.location_id,
        configName: row.config_name,
        configSha256: row.config_sha256,
        configSize: row.config_size,
        receivedAt: row.received_at,
        uploadedBy: row.uploaded_by,
        score: row.score,
      },
      device: {
        id: row.device_id,
        hostname: row.hostname,
        vendor: row.vendor,
        vendorLabel: VENDOR_LABELS[row.vendor] ?? row.vendor,
        deviceType: row.device_type,
        model: row.model,
        osVersion: row.os_version,
        serial: row.serial,
      },
      parsed,
      findings,
      configText: redactConfigText(row.config_text ?? ""),
      links: {
        device: `/api/network/devices/${row.device_id}`,
        campaign: `/api/campaigns/${row.campaign_id}`,
        location: `/api/campaigns/${row.campaign_id}/locations/${row.location_id}`,
      },
    });
  });

  // ---- treatment ----
  app.post("/api/network/reports/:id/findings/:checkId/treatment", auth.requireRole(...WRITE_ROLES), async (c) => {
    const reportId = positiveInt(c.req.param("id"));
    const checkId = String(c.req.param("checkId") ?? "");
    if (!reportId || !/^[A-Za-z0-9_-]+$/.test(checkId)) {
      return c.json({ error: "invalid report or check id", code: "INVALID_FILTER" }, 400);
    }
    const knownCheckIds = knownFindingsFor(db, reportId);
    if (knownCheckIds === null) return c.json({ error: "report not found", code: "NOT_FOUND" }, 404);
    if (!knownCheckIds.includes(checkId)) {
      return c.json({ error: "finding not found in report", code: "NOT_FOUND" }, 404);
    }

    let body: Record<string, unknown> | null = null;
    try {
      const parsed = await c.req.json();
      body = typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : null;
    } catch {
      return c.json({ error: "invalid JSON", code: "INVALID_BODY" }, 400);
    }
    if (!body) return c.json({ error: "invalid JSON", code: "INVALID_BODY" }, 400);

    const input = parseTreatmentInput(body);
    if ("error" in input) return c.json({ error: input.error, code: input.code }, 400);
    const actor = actorOf(c);

    const result = applyTreatmentChange(db, {
      reportId,
      checkId,
      input,
      actor: actor.username,
      actorIp: c.req.header("x-forwarded-for") ?? null,
    });

    return c.json({
      reportId,
      checkId,
      ...input,
      updatedAt: result.timestamp,
      historyId: result.historyId,
    });
  });

  // ---- bulk treatment (per-report batch, e.g. clearing false positives) ----
  app.post("/api/network/reports/:id/findings/treatment-bulk", auth.requireRole(...WRITE_ROLES), async (c) => {
    const reportId = positiveInt(c.req.param("id"));
    if (!reportId) return c.json({ error: "invalid report id", code: "INVALID_ID" }, 400);

    let body: Record<string, unknown> | null = null;
    try {
      const parsed = await c.req.json();
      body = typeof parsed === "object" && parsed !== null ? (parsed as Record<string, unknown>) : null;
    } catch {
      return c.json({ error: "invalid JSON", code: "INVALID_BODY" }, 400);
    }
    if (!body) return c.json({ error: "invalid JSON", code: "INVALID_BODY" }, 400);

    const rawIds = body.checkIds;
    if (!Array.isArray(rawIds) || rawIds.length === 0 || rawIds.length > 100) {
      return c.json({ error: "checkIds must be an array of 1-100 check ids", code: "INVALID_CHECK_IDS" }, 400);
    }
    const checkIds: string[] = [];
    for (const entry of rawIds) {
      const checkId = String(entry ?? "");
      if (!/^[A-Za-z0-9_-]+$/.test(checkId)) {
        return c.json({ error: "invalid check id in checkIds", code: "INVALID_CHECK_IDS" }, 400);
      }
      if (!checkIds.includes(checkId)) checkIds.push(checkId);
    }

    const knownCheckIds = knownFindingsFor(db, reportId);
    if (knownCheckIds === null) return c.json({ error: "report not found", code: "NOT_FOUND" }, 404);
    const knownSet = new Set(knownCheckIds);

    const input = parseTreatmentInput(body);
    if ("error" in input) return c.json({ error: input.error, code: input.code }, 400);
    const actor = actorOf(c);
    const actorIp = c.req.header("x-forwarded-for") ?? null;
    const applied: Array<{ checkId: string; state: TreatmentState; historyId: number }> = [];
    const skipped: Array<{ checkId: string; reason: string }> = [];

    db.transaction(() => {
      for (const checkId of checkIds) {
        if (!knownSet.has(checkId)) {
          skipped.push({ checkId, reason: "NOT_IN_REPORT" });
          continue;
        }
        try {
          const result = applyTreatmentChange(db, { reportId, checkId, input, actor: actor.username, actorIp });
          applied.push({ checkId, state: input.state, historyId: result.historyId });
        } catch (err) {
          skipped.push({ checkId, reason: (err as Error).message.slice(0, 120) || "FAILED" });
        }
      }
    })();

    db.query(
      `INSERT INTO audit_log (actor, actor_ip, action, resource, details, created_at)
       VALUES (?, ?, 'network.treatment.bulk', ?, ?, ?)`,
    ).run(
      actor.username,
      actorIp,
      `network_report:${reportId}`,
      JSON.stringify({ state: input.state, requested: checkIds.length, applied: applied.length, skipped: skipped.length }),
      nowIso(),
    );

    return c.json({ reportId, state: input.state, applied, skipped });
  });

  // ---- treatment history (read) ----
  app.get("/api/network/reports/:id/findings/:checkId/history", auth.requireRole(...READ_ROLES), (c) => {
    const reportId = positiveInt(c.req.param("id"));
    const checkId = String(c.req.param("checkId") ?? "");
    if (!reportId || !/^[A-Za-z0-9_-]+$/.test(checkId)) {
      return c.json({ error: "invalid report or check id", code: "INVALID_FILTER" }, 400);
    }
    const report = db.query("SELECT id FROM network_reports WHERE id = ?").get(reportId) as { id: number } | null;
    if (!report) return c.json({ error: "report not found", code: "NOT_FOUND" }, 404);
    const rows = db
      .query(
        `SELECT h.id, h.actor, h.changed_at, h.from_state, h.to_state, h.justification, h.assignee, h.due_date
           FROM network_finding_state_history h
           JOIN network_finding_states s ON s.id = h.finding_state_id
          WHERE s.report_id = ? AND s.check_id = ?
          ORDER BY h.id ASC`,
      )
      .all(reportId, checkId) as Array<{
      id: number;
      actor: string | null;
      changed_at: string;
      from_state: string | null;
      to_state: string;
      justification: string | null;
      assignee: string | null;
      due_date: string | null;
    }>;
    return c.json({
      reportId,
      checkId,
      history: rows.map((row) => ({
        id: row.id,
        actor: row.actor,
        changedAt: row.changed_at,
        fromState: row.from_state,
        toState: row.to_state,
        justification: row.justification,
        assignee: row.assignee,
        dueDate: row.due_date,
      })),
    });
  });

  // ---- device deletion (admin cleanup) ----
  app.delete("/api/network/devices/:id", auth.requireRole("super_admin"), (c) => {
    const deviceId = positiveInt(c.req.param("id"));
    if (!deviceId) return c.json({ error: "invalid device id", code: "INVALID_ID" }, 400);
    const device = db.query("SELECT id FROM network_devices WHERE id = ?").get(deviceId) as { id: number } | null;
    if (!device) return c.json({ error: "device not found", code: "NOT_FOUND" }, 404);
    const actor = actorOf(c);
    db.transaction(() => {
      const reportIds = db
        .query("SELECT id FROM network_reports WHERE device_id = ?")
        .all(deviceId) as Array<{ id: number }>;
      for (const report of reportIds) {
        db.query("DELETE FROM network_finding_state_history WHERE finding_state_id IN (SELECT id FROM network_finding_states WHERE report_id = ?)").run(report.id);
        db.query("DELETE FROM network_finding_states WHERE report_id = ?").run(report.id);
      }
      db.query("DELETE FROM network_reports WHERE device_id = ?").run(deviceId);
      db.query("DELETE FROM network_device_locations WHERE device_id = ?").run(deviceId);
      db.query("DELETE FROM network_devices WHERE id = ?").run(deviceId);
      db.query(
        `INSERT INTO audit_log (actor, actor_ip, action, resource, details, created_at)
         VALUES (?, NULL, 'network.device.delete', ?, ?, ?)`,
      ).run(actor.username, `network_device:${deviceId}`, JSON.stringify({ reports: reportIds.length }), nowIso());
    })();
    return c.json({ deleted: true, deviceId });
  });
}
