import type { Database } from "bun:sqlite";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { Hono, type MiddlewareHandler } from "hono";
import { parseTags, registerLocationRoutes, serializeLocation, type LocationRow } from "./locations";

export type CampaignAuth = {
  requireRole: (...roles: string[]) => MiddlewareHandler;
};

type CampaignRow = {
  id: number;
  name: string;
  client: string | null;
  scope: string | null;
  expires_at: string | null;
  status: "active" | "completed" | "archived";
  tags: string;
  retention_days: number | null;
  created_at: string;
  updated_at: string;
};

type TokenKind = "download" | "push";

const STATUSES = new Set(["active", "completed", "archived"]);
const TOKEN_KINDS = new Set<TokenKind>(["download", "push"]);

function prepareTables(db: Database): void {
  db.run(`CREATE TABLE IF NOT EXISTS campaign_tokens (
    campaign_id INTEGER NOT NULL REFERENCES campaigns(id),
    kind TEXT NOT NULL CHECK (kind IN ('download','push')),
    token_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (campaign_id, kind)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS legal_holds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id INTEGER NOT NULL REFERENCES campaigns(id),
    report_id INTEGER REFERENCES reports(id),
    reason TEXT,
    created_at TEXT NOT NULL
  )`);
  db.run("CREATE INDEX IF NOT EXISTS idx_legal_holds_campaign ON legal_holds(campaign_id)");
}

function now(): string {
  return new Date().toISOString();
}

function id(value: string): number | null {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
}

function token(): string {
  return randomBytes(32).toString("base64url");
}

export function hashCampaignToken(raw: string): string {
  return createHash("sha256").update(raw, "utf8").digest("hex");
}

/** Compares fixed-length SHA-256 digests with a constant-time primitive. */
export function verifyCampaignToken(db: Database, campaignId: number, kind: TokenKind, raw: string): boolean {
  if (!TOKEN_KINDS.has(kind) || typeof raw !== "string") return false;
  const row = db.query("SELECT token_hash FROM campaign_tokens WHERE campaign_id = ? AND kind = ?")
    .get(campaignId, kind) as { token_hash: string } | null;
  const actual = Buffer.from(hashCampaignToken(raw), "hex");
  const expected = Buffer.from(row?.token_hash ?? "0".repeat(64), "hex");
  return timingSafeEqual(actual, expected) && !!row;
}

export function retentionConfirmation(campaignId: number): string {
  return `DELETE EXPIRED DATA FOR CAMPAIGN ${campaignId}`;
}

function actor(c: any): string {
  const user = c.get("user");
  return user?.username ?? user?.id?.toString() ?? c.get("actor") ?? "unknown";
}

function audit(db: Database, c: any, action: string, resource: string, details: object): void {
  db.query(`INSERT INTO audit_log (actor, actor_ip, action, resource, details, created_at)
    VALUES (?, ?, ?, ?, ?, ?)`).run(actor(c), c.req.header("x-forwarded-for") ?? null, action, resource, JSON.stringify(details), now());
}

function serializeCampaign(row: CampaignRow, locations?: LocationRow[]) {
  return {
    id: row.id,
    name: row.name,
    client: row.client,
    scope: row.scope,
    expiresAt: row.expires_at,
    status: row.status,
    tags: JSON.parse(row.tags) as string[],
    retentionDays: row.retention_days,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    ...(locations ? { locations: locations.map(serializeLocation) } : {}),
  };
}

function optionalString(value: unknown, field: string): string | null | undefined {
  if (value === undefined) return undefined;
  if (value === null) return null;
  if (typeof value !== "string") throw new Error(`${field} must be a string or null`);
  return value.trim() || null;
}

function expiry(value: unknown): string | null | undefined {
  const result = optionalString(value, "expiresAt");
  if (!result) return result;
  if (!Number.isFinite(Date.parse(result))) throw new Error("expiresAt must be an ISO date");
  return new Date(result).toISOString();
}

function retentionDays(value: unknown): number | null | undefined {
  if (value === undefined) return undefined;
  if (value === null) return null;
  if (!Number.isInteger(value) || Number(value) < 1) throw new Error("retentionDays must be a positive integer or null");
  return Number(value);
}

function parseInitialLocations(value: unknown): { name: string; tags: string[] }[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new Error("locations must be an array");
  const names = new Set<string>();
  return value.map((entry) => {
    if (!entry || typeof entry !== "object" || typeof entry.name !== "string" || !entry.name.trim()) {
      throw new Error("each location requires a name");
    }
    const name = entry.name.trim();
    if (names.has(name)) throw new Error("location names must be unique");
    names.add(name);
    return { name, tags: parseTags(entry.tags) };
  });
}

function retentionPreview(db: Database, campaign: CampaignRow) {
  if (campaign.retention_days === null) {
    return { enabled: false, cutoff: null, expiredReports: 0, heldReports: 0, unlinkedHosts: 0, retainedKeys: 0 };
  }
  const cutoff = new Date(Date.now() - campaign.retention_days * 86_400_000).toISOString();
  const expired = db.query(`SELECT r.id, r.host_id FROM reports r
    WHERE r.campaign_id = ? AND r.received_at < ?
      AND NOT EXISTS (SELECT 1 FROM legal_holds h WHERE h.campaign_id = r.campaign_id AND (h.report_id IS NULL OR h.report_id = r.id))`)
    .all(campaign.id, cutoff) as { id: number; host_id: number }[];
  const held = db.query(`SELECT COUNT(*) AS count FROM reports r
    WHERE r.campaign_id = ? AND r.received_at < ?
      AND EXISTS (SELECT 1 FROM legal_holds h WHERE h.campaign_id = r.campaign_id AND (h.report_id IS NULL OR h.report_id = r.id))`)
    .get(campaign.id, cutoff) as { count: number };
  const reportIds = new Set(expired.map((row) => row.id));
  const hostIds = [...new Set(expired.map((row) => row.host_id))];
  let unlinkedHosts = 0;
  for (const hostId of hostIds) {
    const reports = db.query("SELECT id FROM reports WHERE host_id = ?").all(hostId) as { id: number }[];
    if (reports.every((row) => reportIds.has(row.id))) unlinkedHosts++;
  }
  const retainedKeys = (db.query(`SELECT COUNT(DISTINCT k.issuance_id) AS count FROM keys k
    JOIN reports r ON r.issuance_id = k.issuance_id
    WHERE r.id IN (SELECT r2.id FROM reports r2 WHERE r2.campaign_id = ? AND r2.received_at < ?
      AND NOT EXISTS (SELECT 1 FROM legal_holds h WHERE h.campaign_id = r2.campaign_id AND (h.report_id IS NULL OR h.report_id = r2.id)))`)
    .get(campaign.id, cutoff) as { count: number }).count;
  return { enabled: true, cutoff, expiredReports: expired.length, heldReports: held.count, unlinkedHosts, retainedKeys };
}

export function createCampaignRoutes(db: Database, auth: CampaignAuth): Hono<any> {
  prepareTables(db);
  const app = new Hono<any>();

  app.get("/api/campaigns", auth.requireRole("super_admin", "auditor", "viewer"), (c) => {
    const tag = c.req.query("tag");
    const rows = db.query("SELECT * FROM campaigns ORDER BY id").all() as CampaignRow[];
    return c.json(rows.filter((row) => !tag || (JSON.parse(row.tags) as string[]).includes(tag)).map((row) => serializeCampaign(row)));
  });

  app.post("/api/campaigns", auth.requireRole("super_admin", "auditor"), async (c) => {
    let body: any;
    try { body = await c.req.json(); } catch { return c.json({ error: "invalid JSON" }, 400); }
    if (typeof body.name !== "string" || !body.name.trim()) return c.json({ error: "name is required" }, 400);
    let tags: string[], locations: { name: string; tags: string[] }[], expiresAt: string | null | undefined, retention: number | null | undefined;
    try {
      tags = parseTags(body.tags);
      locations = parseInitialLocations(body.locations);
      expiresAt = expiry(body.expiresAt ?? body.expiry);
      retention = retentionDays(body.retentionDays ?? body.retentionPolicy?.days);
    } catch (error) { return c.json({ error: (error as Error).message }, 400); }
    const downloadToken = token();
    const pushToken = token();
    const timestamp = now();
    db.run("BEGIN");
    try {
      const result = db.query(`INSERT INTO campaigns
        (name, client, scope, expires_at, status, tags, retention_days, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?)`).run(
          body.name.trim(), optionalString(body.client, "client") ?? null, optionalString(body.scope, "scope") ?? null,
          expiresAt ?? null, JSON.stringify(tags), retention ?? null, timestamp, timestamp,
        );
      const campaignId = Number(result.lastInsertRowid);
      const insertToken = db.query("INSERT INTO campaign_tokens (campaign_id, kind, token_hash, created_at) VALUES (?, ?, ?, ?)");
      insertToken.run(campaignId, "download", hashCampaignToken(downloadToken), timestamp);
      insertToken.run(campaignId, "push", hashCampaignToken(pushToken), timestamp);
      const insertLocation = db.query(`INSERT INTO locations (campaign_id, name, tags, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`);
      for (const location of locations) insertLocation.run(campaignId, location.name, JSON.stringify(location.tags), timestamp, timestamp);
      audit(db, c, "campaign.create", `campaign:${campaignId}`, { name: body.name.trim(), locations: locations.length });
      db.run("COMMIT");
      const row = db.query("SELECT * FROM campaigns WHERE id = ?").get(campaignId) as CampaignRow;
      const locationRows = db.query("SELECT * FROM locations WHERE campaign_id = ? ORDER BY id").all(campaignId) as LocationRow[];
      return c.json({ ...serializeCampaign(row, locationRows), downloadToken, pushToken }, 201);
    } catch (error) {
      db.run("ROLLBACK");
      if ((error as Error).message.includes("UNIQUE")) return c.json({ error: "campaign name already exists" }, 409);
      if ((error as Error).message.includes("must be")) return c.json({ error: (error as Error).message }, 400);
      throw error;
    }
  });

  app.get("/api/campaigns/:id", auth.requireRole("super_admin", "auditor", "viewer"), (c) => {
    const campaignId = id(c.req.param("id"));
    const row = campaignId && db.query("SELECT * FROM campaigns WHERE id = ?").get(campaignId) as CampaignRow | null;
    if (!row) return c.json({ error: "campaign not found" }, 404);
    const locations = db.query("SELECT * FROM locations WHERE campaign_id = ? ORDER BY id").all(campaignId) as LocationRow[];
    return c.json(serializeCampaign(row, locations));
  });

  app.patch("/api/campaigns/:id", auth.requireRole("super_admin", "auditor"), async (c) => {
    const campaignId = id(c.req.param("id"));
    const current = campaignId && db.query("SELECT * FROM campaigns WHERE id = ?").get(campaignId) as CampaignRow | null;
    if (!current) return c.json({ error: "campaign not found" }, 404);
    let body: any;
    try { body = await c.req.json(); } catch { return c.json({ error: "invalid JSON" }, 400); }
    let tags: string[], expiresAt: string | null | undefined, retention: number | null | undefined;
    try {
      tags = body.tags === undefined ? JSON.parse(current.tags) : parseTags(body.tags);
      expiresAt = expiry(body.expiresAt ?? body.expiry);
      retention = retentionDays(body.retentionDays ?? body.retentionPolicy?.days);
      if (body.name !== undefined && (typeof body.name !== "string" || !body.name.trim())) throw new Error("name must be non-empty");
      if (body.status !== undefined && !STATUSES.has(body.status)) throw new Error("invalid status");
    } catch (error) { return c.json({ error: (error as Error).message }, 400); }
    const rotations = new Set<TokenKind>();
    const requested = body.rotateToken ?? body.rotate;
    if (requested !== undefined) {
      const values = Array.isArray(requested) ? requested : [requested];
      for (const value of values) {
        if (!TOKEN_KINDS.has(value)) return c.json({ error: "rotateToken must be download or push" }, 400);
        rotations.add(value);
      }
    }
    if (body.rotateDownloadToken === true) rotations.add("download");
    if (body.rotatePushToken === true) rotations.add("push");
    const rawTokens: Partial<Record<`${TokenKind}Token`, string>> = {};
    db.run("BEGIN");
    try {
      db.query(`UPDATE campaigns SET name = ?, client = ?, scope = ?, expires_at = ?, status = ?, tags = ?, retention_days = ?, updated_at = ? WHERE id = ?`).run(
        body.name?.trim() ?? current.name,
        body.client === undefined ? current.client : optionalString(body.client, "client"),
        body.scope === undefined ? current.scope : optionalString(body.scope, "scope"),
        expiresAt === undefined ? current.expires_at : expiresAt,
        body.status ?? current.status,
        JSON.stringify(tags), retention === undefined ? current.retention_days : retention, now(), campaignId,
      );
      for (const kind of rotations) {
        const raw = token();
        db.query("UPDATE campaign_tokens SET token_hash = ?, created_at = ? WHERE campaign_id = ? AND kind = ?")
          .run(hashCampaignToken(raw), now(), campaignId, kind);
        rawTokens[`${kind}Token`] = raw;
        audit(db, c, `campaign.token.rotate.${kind}`, `campaign:${campaignId}`, { kind });
      }
      audit(db, c, "campaign.update", `campaign:${campaignId}`, { fields: Object.keys(body).filter((key) => !key.toLowerCase().includes("token")) });
      db.run("COMMIT");
    } catch (error) {
      db.run("ROLLBACK");
      if ((error as Error).message.includes("UNIQUE")) return c.json({ error: "campaign name already exists" }, 409);
      throw error;
    }
    const row = db.query("SELECT * FROM campaigns WHERE id = ?").get(campaignId) as CampaignRow;
    return c.json({ ...serializeCampaign(row), ...rawTokens });
  });

  app.delete("/api/campaigns/:id", auth.requireRole("super_admin", "auditor"), (c) => {
    const campaignId = id(c.req.param("id"));
    const current = campaignId && db.query("SELECT * FROM campaigns WHERE id = ?").get(campaignId) as CampaignRow | null;
    if (!current) return c.json({ error: "campaign not found" }, 404);
    db.query("UPDATE campaigns SET status = 'archived', updated_at = ? WHERE id = ?").run(now(), campaignId);
    audit(db, c, "campaign.archive", `campaign:${campaignId}`, {});
    return c.body(null, 204);
  });

  app.post("/api/campaigns/:id/retention/dry-run", auth.requireRole("super_admin"), (c) => {
    const campaignId = id(c.req.param("id"));
    const campaign = campaignId && db.query("SELECT * FROM campaigns WHERE id = ?").get(campaignId) as CampaignRow | null;
    if (!campaign) return c.json({ error: "campaign not found" }, 404);
    return c.json({ ...retentionPreview(db, campaign), confirmation: retentionConfirmation(campaignId) });
  });

  app.post("/api/campaigns/:id/retention/apply", auth.requireRole("super_admin"), async (c) => {
    const campaignId = id(c.req.param("id"));
    const campaign = campaignId && db.query("SELECT * FROM campaigns WHERE id = ?").get(campaignId) as CampaignRow | null;
    if (!campaign) return c.json({ error: "campaign not found" }, 404);
    let body: any;
    try { body = await c.req.json(); } catch { return c.json({ error: "invalid JSON" }, 400); }
    const required = retentionConfirmation(campaignId);
    if (body.confirmation !== required) return c.json({ error: "confirmation mismatch", confirmation: required }, 400);
    const preview = retentionPreview(db, campaign);
    if (!preview.enabled) return c.json({ error: "retention is disabled" }, 409);
    db.run("BEGIN");
    try {
      db.query(`UPDATE ingest_events SET report_id = NULL WHERE report_id IN (
        SELECT r.id FROM reports r WHERE r.campaign_id = ? AND r.received_at < ?
          AND NOT EXISTS (SELECT 1 FROM legal_holds h WHERE h.campaign_id = r.campaign_id AND (h.report_id IS NULL OR h.report_id = r.id)))`).run(campaignId, preview.cutoff);
      db.query(`DELETE FROM comments WHERE report_id IN (
        SELECT r.id FROM reports r WHERE r.campaign_id = ? AND r.received_at < ?
          AND NOT EXISTS (SELECT 1 FROM legal_holds h WHERE h.campaign_id = r.campaign_id AND (h.report_id IS NULL OR h.report_id = r.id)))`).run(campaignId, preview.cutoff);
      db.query(`DELETE FROM finding_state_history WHERE finding_state_id IN (SELECT fs.id FROM finding_states fs JOIN reports r ON r.id = fs.report_id
        WHERE r.campaign_id = ? AND r.received_at < ? AND NOT EXISTS
          (SELECT 1 FROM legal_holds h WHERE h.campaign_id = r.campaign_id AND (h.report_id IS NULL OR h.report_id = r.id)))`).run(campaignId, preview.cutoff);
      db.query(`DELETE FROM finding_states WHERE report_id IN (
        SELECT r.id FROM reports r WHERE r.campaign_id = ? AND r.received_at < ?
          AND NOT EXISTS (SELECT 1 FROM legal_holds h WHERE h.campaign_id = r.campaign_id AND (h.report_id IS NULL OR h.report_id = r.id)))`).run(campaignId, preview.cutoff);
      const deleted = db.query(`DELETE FROM reports WHERE campaign_id = ? AND received_at < ?
        AND NOT EXISTS (SELECT 1 FROM legal_holds h WHERE h.campaign_id = reports.campaign_id AND (h.report_id IS NULL OR h.report_id = reports.id))`).run(campaignId, preview.cutoff).changes;
      db.run("DELETE FROM host_locations WHERE host_id NOT IN (SELECT DISTINCT host_id FROM reports)");
      const hostsDeleted = db.run("DELETE FROM hosts WHERE id NOT IN (SELECT DISTINCT host_id FROM reports)").changes;
      audit(db, c, "campaign.retention.apply", `campaign:${campaignId}`, {
        cutoff: preview.cutoff, reportsDeleted: deleted, hostsDeleted, heldReports: preview.heldReports, keysRetained: preview.retainedKeys,
      });
      db.run("COMMIT");
      return c.json({ reportsDeleted: deleted, hostsDeleted, heldReports: preview.heldReports, keysRetained: preview.retainedKeys });
    } catch (error) {
      db.run("ROLLBACK");
      throw error;
    }
  });

  registerLocationRoutes(app, db, auth);
  return app;
}
