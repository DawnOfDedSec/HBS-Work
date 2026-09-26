// Outbound webhook notifications for high-severity findings.
//
// Settings live in the shared `settings` key/value table under
// `notifications.webhook` as a JSON document (migration v4 adds the JSON
// column). `notifyFindings` is intentionally fire-and-forget: it never throws,
// never blocks or fails ingest, and hashes out to a single POST with a 5s
// timeout. Every attempt (success or failure) leaves exactly one append-only
// audit row and refreshes `lastFiredAt`.

import type { Database } from "bun:sqlite";

export type MinSeverity = "Critical" | "High";

export type NotificationSettings = {
  enabled: boolean;
  url: string;
  minSeverity: MinSeverity;
  lastFiredAt: string | null;
};

export const DEFAULT_SETTINGS: NotificationSettings = {
  enabled: false,
  url: "",
  minSeverity: "Critical",
  lastFiredAt: null,
};

export type NotificationFinding = { checkId: string; severity: string; title: string };

export type NotifyFindingsInput = {
  source: "host" | "network";
  reportId: number;
  campaignId: number | null;
  locationId: number | null;
  label: string;
  findings: NotificationFinding[];
};

const SETTINGS_KEY = "notifications.webhook";
const MAX_URL_LENGTH = 2048;
const MAX_FINDINGS = 20;
const MAX_ERROR_LENGTH = 200;
const REQUEST_TIMEOUT_MS = 5000;

const SEVERITY_RANK: Record<string, number> = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
  Informational: 0,
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Defensive read: tolerate missing rows, malformed JSON, and partial fields. */
export function getNotificationSettings(db: Database): NotificationSettings {
  let raw: string | null = null;
  try {
    const row = db
      .query("SELECT value_json FROM settings WHERE key = ?")
      .get(SETTINGS_KEY) as { value_json: string | null } | null;
    raw = row?.value_json ?? null;
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
  if (!raw) return { ...DEFAULT_SETTINGS };
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!isRecord(parsed)) return { ...DEFAULT_SETTINGS };
    return {
      enabled: typeof parsed.enabled === "boolean" ? parsed.enabled : DEFAULT_SETTINGS.enabled,
      url: typeof parsed.url === "string" ? parsed.url : DEFAULT_SETTINGS.url,
      minSeverity: parsed.minSeverity === "High" ? "High" : "Critical",
      lastFiredAt: typeof parsed.lastFiredAt === "string" ? parsed.lastFiredAt : null,
    };
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

export function saveNotificationSettings(
  db: Database,
  input: { enabled: boolean; url: string; minSeverity: MinSeverity },
  actor: string,
): NotificationSettings {
  const url = typeof input?.url === "string" ? input.url.trim() : "";
  if (url.length > MAX_URL_LENGTH || !/^https?:\/\//.test(url)) {
    throw new Error("invalid webhook url");
  }
  const previous = getNotificationSettings(db);
  const settings: NotificationSettings = {
    enabled: input?.enabled === true,
    url,
    minSeverity: input?.minSeverity === "High" ? "High" : "Critical",
    lastFiredAt: previous.lastFiredAt,
  };
  db.query(
    `INSERT INTO settings (key, value_json, updated_at, updated_by)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(key) DO UPDATE SET
       value_json = excluded.value_json,
       updated_at = excluded.updated_at,
       updated_by = excluded.updated_by`,
  ).run(SETTINGS_KEY, JSON.stringify(settings), new Date().toISOString(), actor);
  return settings;
}

/** Severity ranking: Critical >= High >= Medium >= Low >= Informational. */
export function severityAtLeast(severity: string, min: MinSeverity): boolean {
  const rank = SEVERITY_RANK[severity];
  const floor = SEVERITY_RANK[min];
  return typeof rank === "number" && typeof floor === "number" && rank >= floor;
}

function toFinding(value: unknown): NotificationFinding | null {
  if (!isRecord(value) || typeof value.severity !== "string") return null;
  return {
    checkId: typeof value.checkId === "string" ? value.checkId : String(value.checkId ?? ""),
    severity: value.severity,
    title: typeof value.title === "string" ? value.title : String(value.title ?? ""),
  };
}

function writeAudit(
  db: Database,
  reportId: number,
  details: { ok: boolean; status?: number; error?: string; source: string },
): void {
  try {
    db.query(
      `INSERT INTO audit_log (actor, actor_ip, action, resource, details, created_at)
       VALUES ('system', NULL, 'notification.webhook', ?, ?, ?)`,
    ).run(`report:${reportId}`, JSON.stringify(details), new Date().toISOString());
  } catch {
    // The audit trail must never break or mask a notification outcome.
  }
}

function setLastFiredAt(db: Database, at: string): void {
  try {
    const current = getNotificationSettings(db);
    current.lastFiredAt = at;
    db.query("UPDATE settings SET value_json = ? WHERE key = ?").run(
      JSON.stringify(current),
      SETTINGS_KEY,
    );
  } catch {
    // Best effort: a settings write failure must not surface to the caller.
  }
}

/**
 * Fire a `critical-findings` webhook when enabled and at least one finding
 * meets the configured minimum severity. Never throws; resolves once the
 * attempt (and its audit row) is complete.
 */
export async function notifyFindings(db: Database, input: NotifyFindingsInput): Promise<void> {
  try {
    const settings = getNotificationSettings(db);
    if (!settings.enabled) return;
    if (!settings.url) return;

    const threshold = (Array.isArray(input.findings) ? input.findings : [])
      .map(toFinding)
      .filter((finding): finding is NotificationFinding => finding !== null)
      .filter((finding) => severityAtLeast(finding.severity, settings.minSeverity));
    if (threshold.length === 0) return;

    const severities = [...new Set(threshold.map((finding) => finding.severity))];
    const body = JSON.stringify({
      event: "critical-findings",
      source: input.source,
      reportId: input.reportId,
      campaignId: input.campaignId,
      locationId: input.locationId,
      label: input.label,
      severities,
      findings: threshold.slice(0, MAX_FINDINGS),
    });

    let ok = false;
    let status: number | undefined;
    let error: string | undefined;
    try {
      const response = await fetch(settings.url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body,
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      status = response.status;
      ok = response.ok;
      if (!ok) error = `HTTP ${response.status}`;
    } catch (err) {
      error = (err instanceof Error ? err.message : "request failed").slice(0, MAX_ERROR_LENGTH);
    }

    writeAudit(db, input.reportId, {
      ok,
      ...(status !== undefined ? { status } : {}),
      ...(error !== undefined ? { error } : {}),
      source: input.source,
    });
    setLastFiredAt(db, new Date().toISOString());
  } catch {
    // notifyFindings is best effort by contract: never propagate.
  }
}
