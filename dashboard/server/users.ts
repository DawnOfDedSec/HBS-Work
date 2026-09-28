import type { Database } from "bun:sqlite";
import { Hono } from "hono";
import { normalizeUsername, parseAllowedCampaigns, requireAuth, requireRole, type AuthEnv, type UserRole } from "./auth";

import { assessPassword, hashPassword } from "./password";

const roles = new Set<UserRole>(["super_admin", "auditor", "viewer"]);
type MutableUser = { username?: unknown; password?: unknown; role?: unknown; active?: unknown; allowedCampaigns?: unknown };

function isoNow(): string {
  return new Date().toISOString();
}

async function body(c: { req: { json(): Promise<unknown> } }): Promise<MutableUser | null> {
  try {
    const value = await c.req.json();
    return value && typeof value === "object" ? value as MutableUser : null;
  } catch {
    return null;
  }
}

function userId(value: string): number | null {
  const id = Number(value);
  return Number.isInteger(id) && id > 0 ? id : null;
}

function activeSuperAdmins(db: Database): number {
  return (db.query("SELECT COUNT(*) AS count FROM users WHERE role = 'super_admin' AND active = 1").get() as { count: number }).count;
}

/** Validate an allowedCampaigns payload: null = unrestricted, else positive ints. */
function parseCampaignRestriction(value: unknown): number[] | null | Error {
  if (value === null || value === undefined) return null;
  if (!Array.isArray(value)) return new Error("allowedCampaigns must be null or an array of campaign ids");
  const ids: number[] = [];
  for (const entry of value) {
    const id = typeof entry === "number" ? entry : Number(entry);
    if (!Number.isSafeInteger(id) || id <= 0) return new Error("allowedCampaigns must contain positive integers");
    if (!ids.includes(id)) ids.push(id);
  }
  return ids;
}

function currentAllowedRaw(db: Database, id: number): string | null {
  const row = db.query("SELECT allowed_campaigns FROM users WHERE id = ?").get(id) as { allowed_campaigns: string | null } | null;
  return row?.allowed_campaigns ?? null;
}

export function createUserRoutes(db: Database): Hono<AuthEnv> {
  const app = new Hono<AuthEnv>();
  app.use("/api/users", requireAuth(db), requireRole("super_admin"));
  app.use("/api/users/*", requireAuth(db), requireRole("super_admin"));

  app.get("/api/users", (c) => {
    const rows = db.query(`
      SELECT id, username, role, active, allowed_campaigns, created_at, updated_at FROM users ORDER BY id
    `).all() as Array<Record<string, unknown>>;
    return c.json({
      users: rows.map((row) => ({
        id: row.id,
        username: row.username,
        role: row.role,
        active: row.active,
        allowedCampaigns: parseAllowedCampaigns(row.allowed_campaigns as string | null),
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      })),
    });
  });

  app.post("/api/users", async (c) => {
    const input = await body(c);
    if (!input || typeof input.username !== "string" || typeof input.password !== "string") {
      return c.json({ error: "username and password required" }, 400);
    }
    const username = normalizeUsername(input.username);
    const role = input.role ?? "viewer";
    if (!username || !input.password || typeof role !== "string" || !roles.has(role as UserRole)) {
      return c.json({ error: "invalid user" }, 400);
    }
    const verdict = assessPassword(input.password, username);
    if (!verdict.ok) return c.json({ error: `weak password: ${verdict.reason}` }, 400);
    const passwordHash = await hashPassword(input.password);
    const restriction = parseCampaignRestriction(input.allowedCampaigns);
    if (restriction instanceof Error) return c.json({ error: restriction.message }, 400);
    const timestamp = isoNow();
    try {
      const result = db.query(`
        INSERT INTO users (username, password_hash, role, active, allowed_campaigns, created_at, updated_at)
        VALUES (?, ?, ?, 1, ?, ?, ?)
      `).run(username, passwordHash, role, restriction === null ? null : JSON.stringify(restriction), timestamp, timestamp);
      return c.json({
        user: {
          id: Number(result.lastInsertRowid),
          username,
          role,
          active: true,
          allowedCampaigns: restriction,
        },
      }, 201);
    } catch (error) {
      if ((error as Error).message.includes("UNIQUE")) return c.json({ error: "username already exists" }, 409);
      throw error;
    }
  });

  app.patch("/api/users/:id", async (c) => {
    const id = userId(c.req.param("id"));
    const input = await body(c);
    if (!id || !input) return c.json({ error: "invalid request" }, 400);
    const current = db.query("SELECT id, username, role, active FROM users WHERE id = ?").get(id) as { id: number; username: string; role: UserRole; active: number } | null;
    if (!current) return c.json({ error: "user not found" }, 404);

    const role = input.role === undefined ? current.role : input.role;
    const active = input.active === undefined ? !!current.active : input.active;
    if (typeof role !== "string" || !roles.has(role as UserRole) || typeof active !== "boolean") {
      return c.json({ error: "invalid user update" }, 400);
    }
    if (current.role === "super_admin" && current.active && (role !== "super_admin" || !active) && activeSuperAdmins(db) <= 1) {
      return c.json({ error: "cannot deactivate last active super_admin" }, 409);
    }

    let passwordHash: string | null = null;
    if (input.password !== undefined) {
      if (typeof input.password !== "string" || !input.password) return c.json({ error: "invalid password" }, 400);
      const verdict = assessPassword(input.password, current.username);
      if (!verdict.ok) return c.json({ error: `weak password: ${verdict.reason}` }, 400);
      passwordHash = await hashPassword(input.password);
    }
    const currentAllowedRawValue = currentAllowedRaw(db, id);
    let restriction: number[] | null;
    let restrictionRaw: string | null;
    if (input.allowedCampaigns === undefined) {
      restriction = parseAllowedCampaigns(currentAllowedRawValue);
      restrictionRaw = currentAllowedRawValue;
    } else {
      const parsed = parseCampaignRestriction(input.allowedCampaigns);
      if (parsed instanceof Error) return c.json({ error: parsed.message }, 400);
      restriction = parsed;
      restrictionRaw = restriction === null ? null : JSON.stringify(restriction);
    }
    // A campaign-restricted account must not retain (or gain) super_admin:
    // unrestricted globals like admin settings would leak across the fence.
    const effectiveRole: UserRole =
      restriction !== null && restriction.length > 0 && role === "super_admin" ? "auditor" : role as UserRole;
    db.query(`
      UPDATE users SET role = ?, active = ?, password_hash = COALESCE(?, password_hash), allowed_campaigns = ?, updated_at = ? WHERE id = ?
    `).run(effectiveRole, active ? 1 : 0, passwordHash, restrictionRaw, isoNow(), id);
    return c.json({
      user: {
        id,
        role: effectiveRole,
        active,
        allowedCampaigns: parseAllowedCampaigns(restrictionRaw),
      },
    });
  });

  app.delete("/api/users/:id", (c) => {
    const id = userId(c.req.param("id"));
    if (!id) return c.json({ error: "invalid user id" }, 400);
    const current = db.query("SELECT id, username, role, active FROM users WHERE id = ?").get(id) as { id: number; username: string; role: UserRole; active: number } | null;
    if (!current) return c.json({ error: "user not found" }, 404);
    if (current.role === "super_admin" && current.active && activeSuperAdmins(db) <= 1) {
      return c.json({ error: "cannot deactivate last active super_admin" }, 409);
    }
    db.query("UPDATE users SET active = 0, updated_at = ? WHERE id = ?").run(isoNow(), id);
    db.query("DELETE FROM sessions WHERE user_id = ?").run(id);
    return c.body(null, 204);
  });

  return app;
}
