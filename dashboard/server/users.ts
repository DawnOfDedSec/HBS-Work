import type { Database } from "bun:sqlite";
import { Hono } from "hono";
import { normalizeUsername, requireAuth, requireRole, type AuthEnv, type UserRole } from "./auth";

const roles = new Set<UserRole>(["super_admin", "auditor", "viewer"]);
type MutableUser = { username?: unknown; password?: unknown; role?: unknown; active?: unknown };

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

export function createUserRoutes(db: Database): Hono<AuthEnv> {
  const app = new Hono<AuthEnv>();
  app.use("/api/users", requireAuth(db), requireRole("super_admin"));
  app.use("/api/users/*", requireAuth(db), requireRole("super_admin"));

  app.get("/api/users", (c) => c.json({ users: db.query(`
    SELECT id, username, role, active, created_at, updated_at FROM users ORDER BY id
  `).all() }));

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
    const passwordHash = await Bun.password.hash(input.password, { algorithm: "argon2id" });
    const timestamp = isoNow();
    try {
      const result = db.query(`
        INSERT INTO users (username, password_hash, role, active, created_at, updated_at)
        VALUES (?, ?, ?, 1, ?, ?)
      `).run(username, passwordHash, role, timestamp, timestamp);
      return c.json({ user: { id: Number(result.lastInsertRowid), username, role, active: true } }, 201);
    } catch (error) {
      if ((error as Error).message.includes("UNIQUE")) return c.json({ error: "username already exists" }, 409);
      throw error;
    }
  });

  app.patch("/api/users/:id", async (c) => {
    const id = userId(c.req.param("id"));
    const input = await body(c);
    if (!id || !input) return c.json({ error: "invalid request" }, 400);
    const current = db.query("SELECT id, role, active FROM users WHERE id = ?").get(id) as { id: number; role: UserRole; active: number } | null;
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
      passwordHash = await Bun.password.hash(input.password, { algorithm: "argon2id" });
    }
    db.query(`
      UPDATE users SET role = ?, active = ?, password_hash = COALESCE(?, password_hash), updated_at = ? WHERE id = ?
    `).run(role, active ? 1 : 0, passwordHash, isoNow(), id);
    return c.json({ user: { id, role, active } });
  });

  app.delete("/api/users/:id", (c) => {
    const id = userId(c.req.param("id"));
    if (!id) return c.json({ error: "invalid user id" }, 400);
    const current = db.query("SELECT id, role, active FROM users WHERE id = ?").get(id) as { id: number; role: UserRole; active: number } | null;
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
