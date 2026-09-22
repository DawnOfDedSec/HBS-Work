import type { Database } from "bun:sqlite";
import type { Hono } from "hono";
import type { CampaignAuth } from "./campaigns";

export type LocationRow = {
  id: number;
  campaign_id: number;
  name: string;
  tags: string;
  retired_at: string | null;
  created_at: string;
  updated_at: string;
};

export function parseTags(value: unknown): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some((tag) => typeof tag !== "string" || !tag.trim())) {
    throw new Error("tags must be an array of non-empty strings");
  }
  return [...new Set(value.map((tag) => tag.trim()))];
}

export function serializeLocation(row: LocationRow) {
  return {
    id: row.id,
    campaignId: row.campaign_id,
    name: row.name,
    tags: JSON.parse(row.tags) as string[],
    retiredAt: row.retired_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export function locationAcceptsIssuance(db: Database, campaignId: number, locationId: number): boolean {
  return !!db.query(`SELECT 1 FROM locations l JOIN campaigns c ON c.id = l.campaign_id
    WHERE l.id = ? AND l.campaign_id = ? AND l.retired_at IS NULL AND c.status = 'active'
      AND (c.expires_at IS NULL OR c.expires_at > ?)`).get(locationId, campaignId, new Date().toISOString());
}

export function requireIssuableLocation(db: Database, campaignId: number, locationId: number): void {
  if (!locationAcceptsIssuance(db, campaignId, locationId)) {
    throw new Error("campaign or location is not active");
  }
}

function id(value: string): number | null {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
}

function now(): string {
  return new Date().toISOString();
}

function actor(c: any): string {
  const user = c.get("user");
  return user?.username ?? user?.id?.toString() ?? c.get("actor") ?? "unknown";
}

function audit(db: Database, c: any, action: string, resource: string, details: object) {
  db.query(`INSERT INTO audit_log (actor, actor_ip, action, resource, details, created_at)
    VALUES (?, ?, ?, ?, ?, ?)`).run(actor(c), c.req.header("x-forwarded-for") ?? null, action, resource, JSON.stringify(details), now());
}

export function registerLocationRoutes(app: Hono<any>, db: Database, auth: CampaignAuth): void {
  app.get("/api/campaigns/:id/locations", auth.requireRole("super_admin", "auditor", "viewer"), (c) => {
    const campaignId = id(c.req.param("id"));
    if (!campaignId || !db.query("SELECT 1 FROM campaigns WHERE id = ?").get(campaignId)) {
      return c.json({ error: "campaign not found" }, 404);
    }
    const rows = db
      .query("SELECT * FROM locations WHERE campaign_id = ? ORDER BY id")
      .all(campaignId) as LocationRow[];
    return c.json(rows.map(serializeLocation));
  });

  app.post("/api/campaigns/:id/locations", auth.requireRole("super_admin", "auditor"), async (c) => {
    const campaignId = id(c.req.param("id"));
    if (!campaignId || !db.query("SELECT 1 FROM campaigns WHERE id = ?").get(campaignId)) {
      return c.json({ error: "campaign not found" }, 404);
    }
    let body: any;
    try { body = await c.req.json(); } catch { return c.json({ error: "invalid JSON" }, 400); }
    if (typeof body.name !== "string" || !body.name.trim()) return c.json({ error: "name is required" }, 400);
    let tags: string[];
    try { tags = parseTags(body.tags); } catch (error) { return c.json({ error: (error as Error).message }, 400); }
    const timestamp = now();
    try {
      const result = db.query(`INSERT INTO locations (campaign_id, name, tags, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?)`).run(campaignId, body.name.trim(), JSON.stringify(tags), timestamp, timestamp);
      const row = db.query("SELECT * FROM locations WHERE id = ?").get(Number(result.lastInsertRowid)) as LocationRow;
      audit(db, c, "location.create", `location:${row.id}`, { campaignId, name: row.name });
      return c.json(serializeLocation(row), 201);
    } catch (error) {
      if ((error as Error).message.includes("UNIQUE")) return c.json({ error: "location name already exists" }, 409);
      throw error;
    }
  });

  app.patch("/api/campaigns/:id/locations/:loc", auth.requireRole("super_admin", "auditor"), async (c) => {
    const campaignId = id(c.req.param("id"));
    const locationId = id(c.req.param("loc"));
    if (!campaignId || !locationId) return c.json({ error: "location not found" }, 404);
    const current = db.query("SELECT * FROM locations WHERE id = ? AND campaign_id = ?").get(locationId, campaignId) as LocationRow | null;
    if (!current) return c.json({ error: "location not found" }, 404);
    let body: any;
    try { body = await c.req.json(); } catch { return c.json({ error: "invalid JSON" }, 400); }
    if (body.name !== undefined && (typeof body.name !== "string" || !body.name.trim())) {
      return c.json({ error: "name must be non-empty" }, 400);
    }
    let tags: string[];
    try { tags = body.tags === undefined ? JSON.parse(current.tags) : parseTags(body.tags); }
    catch (error) { return c.json({ error: (error as Error).message }, 400); }
    let retiredAt = current.retired_at;
    if (body.retired === true || body.retiredAt !== undefined && body.retiredAt !== null) retiredAt = body.retiredAt || now();
    if (body.retired === false || body.retiredAt === null) retiredAt = null;
    try {
      db.query(`UPDATE locations SET name = ?, tags = ?, retired_at = ?, updated_at = ?
        WHERE id = ? AND campaign_id = ?`).run(body.name?.trim() ?? current.name, JSON.stringify(tags), retiredAt, now(), locationId, campaignId);
      const row = db.query("SELECT * FROM locations WHERE id = ?").get(locationId) as LocationRow;
      audit(db, c, retiredAt && !current.retired_at ? "location.retire" : "location.update", `location:${locationId}`, { campaignId, retiredAt });
      return c.json(serializeLocation(row));
    } catch (error) {
      if ((error as Error).message.includes("UNIQUE")) return c.json({ error: "location name already exists" }, 409);
      throw error;
    }
  });
}
