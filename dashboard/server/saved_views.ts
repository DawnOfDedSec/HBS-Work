// Saved views (Task 49).
//
// A saved view preserves an owner, its canonical scope, the exact canonical
// query string, and a `personal|team` visibility. Personal views are visible
// only to their owner; team views are visible to every authenticated user.
// Mutations are restricted to auditors/super admins and to the view's owner.

import type { Database } from "bun:sqlite";
import { Hono, type MiddlewareHandler } from "hono";
import { parseQuery, serializeQuery, SCOPES } from "./query";

export type SavedViewAuth = {
  requireRole: (...roles: string[]) => MiddlewareHandler;
};

type SavedViewRow = {
  id: number;
  owner_id: number;
  campaign_id: number | null;
  name: string;
  scope: string;
  query: string;
  visibility: "personal" | "team";
  created_at: string;
  updated_at: string;
};

type Actor = { id: number; username: string; role: string };

const READ_ROLES = ["super_admin", "auditor", "viewer"];
const WRITE_ROLES = ["super_admin", "auditor"];
const VISIBILITIES = new Set(["personal", "team"]);
const MAX_NAME_LENGTH = 128;

function actorOf(c: any): Actor {
  const user = c.get("user") as Actor | undefined;
  return user ?? { id: 0, username: "unknown", role: "viewer" };
}

function positiveInt(value: unknown): number | null {
  const parsed = typeof value === "number" ? value : Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
}

function parseBody(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function serialize(row: SavedViewRow, viewer: Actor): Record<string, unknown> {
  return {
    id: row.id,
    ownerId: row.owner_id,
    campaignId: row.campaign_id,
    name: row.name,
    scope: row.scope,
    query: row.query,
    visibility: row.visibility,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    canEdit: viewer.id === row.owner_id || viewer.role === "super_admin",
    canDelete: viewer.id === row.owner_id || viewer.role === "super_admin",
  };
}

/** Owner or super admin may mutate a saved view. */
export function canMutateSavedView(row: { owner_id: number }, viewer: Actor): boolean {
  return viewer.id === row.owner_id || viewer.role === "super_admin";
}

export function registerSavedViewRoutes(app: Hono<any>, db: Database, auth: SavedViewAuth): void {
  app.get("/api/saved-views", auth.requireRole(...READ_ROLES), (c) => {
    const viewer = actorOf(c);
    const rows = db
      .query("SELECT * FROM saved_views ORDER BY name COLLATE NOCASE, id")
      .all() as SavedViewRow[];
    const scopeFilter = c.req.query("scope");
    const campaignFilter = c.req.query("campaignId");
    const campaignId = campaignFilter === undefined ? null : positiveInt(campaignFilter);
    const views = rows
      .filter((row) => row.visibility === "team" || row.owner_id === viewer.id)
      .filter((row) => !scopeFilter || row.scope === scopeFilter)
      .filter((row) => campaignId === null || row.campaign_id === campaignId)
      .map((row) => serialize(row, viewer));
    return c.json({ views });
  });

  app.post("/api/saved-views", auth.requireRole(...WRITE_ROLES), async (c) => {
    const viewer = actorOf(c);
    let body: Record<string, unknown> | null = null;
    try {
      body = parseBody(await c.req.json());
    } catch {
      return c.json({ error: "invalid JSON" }, 400);
    }
    if (!body) return c.json({ error: "invalid JSON" }, 400);

    const name = typeof body.name === "string" ? body.name.trim() : "";
    if (!name || name.length > MAX_NAME_LENGTH) {
      return c.json({ error: "name is required", code: "INVALID_NAME" }, 400);
    }
    if (typeof body.query !== "string") {
      return c.json({ error: "query is required", code: "INVALID_QUERY" }, 400);
    }
    const parsed = parseQuery(body.query, {
      campaignId: positiveInt(body.campaignId),
    });
    if (!parsed.ok) {
      return c.json({ error: parsed.message, code: parsed.code }, 400);
    }
    const scope = typeof body.scope === "string" && body.scope ? body.scope : parsed.query.scope;
    if (!(SCOPES as readonly string[]).includes(scope)) {
      return c.json({ error: "invalid scope", code: "INVALID_SCOPE" }, 400);
    }
    const visibility = typeof body.visibility === "string" ? body.visibility : "personal";
    if (!VISIBILITIES.has(visibility)) {
      return c.json({ error: "invalid visibility", code: "INVALID_VISIBILITY" }, 400);
    }
    const canonical = serializeQuery(parsed.query);
    const campaignId = positiveInt(body.campaignId) ?? parsed.query.campaignId;
    if (campaignId !== null && !db.query("SELECT 1 FROM campaigns WHERE id = ?").get(campaignId)) {
      return c.json({ error: "campaign not found", code: "NOT_FOUND" }, 404);
    }
    const timestamp = new Date().toISOString();
    try {
      const result = db
        .query(
          `INSERT INTO saved_views
             (owner_id, campaign_id, name, scope, query, visibility, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(viewer.id, campaignId, name, scope, canonical, visibility, timestamp, timestamp);
      const row = db.query("SELECT * FROM saved_views WHERE id = ?").get(
        Number(result.lastInsertRowid),
      ) as SavedViewRow;
      return c.json({ view: serialize(row, viewer) }, 201);
    } catch (error) {
      if (/UNIQUE/i.test((error as Error).message)) {
        return c.json({ error: "a saved view with that name already exists", code: "DUPLICATE_VIEW" }, 409);
      }
      throw error;
    }
  });

  app.patch("/api/saved-views/:id", auth.requireRole(...WRITE_ROLES), async (c) => {
    const viewer = actorOf(c);
    const viewId = positiveInt(c.req.param("id"));
    const current = viewId
      ? (db.query("SELECT * FROM saved_views WHERE id = ?").get(viewId) as SavedViewRow | null)
      : null;
    if (!current) return c.json({ error: "saved view not found", code: "NOT_FOUND" }, 404);
    if (!canMutateSavedView(current, viewer)) {
      return c.json({ error: "forbidden", code: "FORBIDDEN" }, 403);
    }
    let body: Record<string, unknown> | null = null;
    try {
      body = parseBody(await c.req.json());
    } catch {
      return c.json({ error: "invalid JSON" }, 400);
    }
    if (!body) return c.json({ error: "invalid JSON" }, 400);

    const name = body.name === undefined ? current.name : typeof body.name === "string" ? body.name.trim() : "";
    if (!name || name.length > MAX_NAME_LENGTH) {
      return c.json({ error: "invalid name", code: "INVALID_NAME" }, 400);
    }
    let query = current.query;
    let scope = current.scope;
    if (body.query !== undefined) {
      if (typeof body.query !== "string") {
        return c.json({ error: "query must be a string", code: "INVALID_QUERY" }, 400);
      }
      const parsed = parseQuery(body.query, { campaignId: current.campaign_id });
      if (!parsed.ok) return c.json({ error: parsed.message, code: parsed.code }, 400);
      query = serializeQuery(parsed.query);
      scope = parsed.query.scope;
    }
    const visibility = body.visibility === undefined ? current.visibility : body.visibility;
    if (typeof visibility !== "string" || !VISIBILITIES.has(visibility)) {
      return c.json({ error: "invalid visibility", code: "INVALID_VISIBILITY" }, 400);
    }
    try {
      db.query(
        `UPDATE saved_views SET name = ?, query = ?, scope = ?, visibility = ?, updated_at = ? WHERE id = ?`,
      ).run(name, query, scope, visibility, new Date().toISOString(), current.id);
    } catch (error) {
      if (/UNIQUE/i.test((error as Error).message)) {
        return c.json({ error: "a saved view with that name already exists", code: "DUPLICATE_VIEW" }, 409);
      }
      throw error;
    }
    const row = db.query("SELECT * FROM saved_views WHERE id = ?").get(current.id) as SavedViewRow;
    return c.json({ view: serialize(row, viewer) });
  });

  app.delete("/api/saved-views/:id", auth.requireRole(...WRITE_ROLES), (c) => {
    const viewer = actorOf(c);
    const viewId = positiveInt(c.req.param("id"));
    const current = viewId
      ? (db.query("SELECT * FROM saved_views WHERE id = ?").get(viewId) as SavedViewRow | null)
      : null;
    if (!current) return c.json({ error: "saved view not found", code: "NOT_FOUND" }, 404);
    if (!canMutateSavedView(current, viewer)) {
      return c.json({ error: "forbidden", code: "FORBIDDEN" }, 403);
    }
    db.query("DELETE FROM saved_views WHERE id = ?").run(current.id);
    return c.body(null, 204);
  });
}
