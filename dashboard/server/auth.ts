import type { Database } from "bun:sqlite";
import { Hono, type MiddlewareHandler } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import { assessPassword, hashPassword, verifyPassword } from "./password";

export type UserRole = "super_admin" | "auditor" | "viewer";
export type AuthUser = {
  id: number;
  username: string;
  role: UserRole;
  /** Campaign ids this user may see; null/undefined = unrestricted. */
  allowedCampaigns?: number[] | null;
};
export type AuthEnv = { Variables: { user: AuthUser } };

const SESSION_COOKIE = "hbs_session";
const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
const RATE_WINDOW_MS = 15 * 60 * 1000;
const MAX_FAILURES = 5;

type LoginFailures = { count: number; firstAt: number };
type AuthOptions = { now?: () => number };

type UserRow = AuthUser & { active: number };

export function normalizeUsername(username: string): string {
  return username.trim().toLowerCase();
}

export function hashToken(token: string): string {
  return new Bun.CryptoHasher("sha256").update(token).digest("hex");
}

function randomToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Buffer.from(bytes).toString("base64url");
}

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

function requestIsSecure(url: string, forwardedProto?: string): boolean {
  return new URL(url).protocol === "https:" || forwardedProto?.split(",", 1)[0]?.trim() === "https";
}

function setSessionCookie(c: Parameters<typeof setCookie>[0], token: string): void {
  setCookie(c, SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: "Lax",
    secure: requestIsSecure(c.req.url, c.req.header("x-forwarded-proto")),
    path: "/",
    maxAge: SESSION_TTL_SECONDS,
  });
}

function clearSessionCookie(c: Parameters<typeof setCookie>[0]): void {
  setCookie(c, SESSION_COOKIE, "", {
    httpOnly: true,
    sameSite: "Lax",
    secure: requestIsSecure(c.req.url, c.req.header("x-forwarded-proto")),
    path: "/",
    maxAge: 0,
  });
}

function createSession(db: Database, userId: number, now: number): string {
  const token = randomToken();
  db.query(
    "INSERT INTO sessions (user_id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?)",
  ).run(userId, hashToken(token), iso(now), iso(now + SESSION_TTL_SECONDS * 1000));
  return token;
}

function sessionUser(db: Database, token: string | undefined, now: number): AuthUser | null {
  return resolveSessionUser(db, token, now);
}

/** Parse the stored campaign restriction; anything malformed = unrestricted. */
export function parseAllowedCampaigns(raw: string | null | undefined): number[] | null {
  if (!raw) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return null;
    const ids = parsed
      .map((value) => (typeof value === "number" ? value : Number(value)))
      .filter((value) => Number.isSafeInteger(value) && value > 0);
    return ids.length > 0 ? [...new Set(ids)] : null;
  } catch {
    return null;
  }
}

/**
 * Resolve a raw session token to its active user, or null. Additive export
 * (Task 47): the issuance download route authenticates session cookie holders
 * through this without duplicating the session lookup. Same result as the
 * internal `sessionUser` used by the auth middleware.
 */
export function resolveSessionUser(
  db: Database,
  token: string | undefined,
  now: number = Date.now(),
): AuthUser | null {
  if (!token) return null;
  const row = db.query(`
    SELECT users.id, users.username, users.role, users.active, users.allowed_campaigns
    FROM sessions JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ? AND sessions.expires_at > ?
  `).get(hashToken(token), iso(now)) as UserRow | null;
  if (!row || !row.active) return null;
  return {
    id: row.id,
    username: row.username,
    role: row.role,
    allowedCampaigns: parseAllowedCampaigns((row as { allowed_campaigns?: string | null }).allowed_campaigns),
  };
}

/** Reads the session cookie out of a raw `Cookie:` header value. */
function sessionCookieValue(cookieHeader: string | undefined): string | undefined {
  if (!cookieHeader) return undefined;
  for (const part of cookieHeader.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    if (part.slice(0, separator).trim() !== SESSION_COOKIE) continue;
    const value = part.slice(separator + 1).trim();
    if (!value) return undefined;
    try {
      return decodeURIComponent(value);
    } catch {
      return value;
    }
  }
  return undefined;
}

/**
 * Resolve a session user from a raw `Cookie:` header (or undefined). Additive
 * export (Task 47) so routes outside auth.ts can offer session authentication
 * while `getCookie` usage stays inside this module.
 */
export function sessionFromHeaders(
  db: Database,
  cookieHeader: string | undefined,
  now: number = Date.now(),
): AuthUser | null {
  return resolveSessionUser(db, sessionCookieValue(cookieHeader), now);
}

export function requireAuth(db: Database, now: () => number = Date.now): MiddlewareHandler<AuthEnv> {
  return async (c, next) => {
    const user = sessionUser(db, getCookie(c, SESSION_COOKIE), now());
    if (!user) return c.json({ error: "authentication required" }, 401);
    c.set("user", user);
    await next();
  };
}

export function requireRole(...roles: UserRole[]): MiddlewareHandler<AuthEnv> {
  return async (c, next) => {
    const user = c.get("user");
    if (!user || !roles.includes(user.role)) return c.json({ error: "forbidden" }, 403);
    await next();
  };
}

function clientIp(c: { req: { header(name: string): string | undefined } }): string {
  return c.req.header("x-forwarded-for")?.split(",", 1)[0]?.trim()
    || c.req.header("x-real-ip")?.trim()
    || "unknown";
}

async function credentials(c: { req: { json(): Promise<unknown> } }): Promise<{ username: string; password: string } | null> {
  try {
    const body = await c.req.json() as Record<string, unknown>;
    if (typeof body.username !== "string" || typeof body.password !== "string") return null;
    const username = normalizeUsername(body.username);
    if (!username || !body.password) return null;
    return { username, password: body.password };
  } catch {
    return null;
  }
}

export function createAuthRoutes(db: Database, options: AuthOptions = {}): Hono<AuthEnv> {
  const app = new Hono<AuthEnv>();
  const failures = new Map<string, LoginFailures>();
  const now = options.now ?? Date.now;

  app.post("/api/auth/setup", async (c) => {
    if ((db.query("SELECT COUNT(*) AS count FROM users").get() as { count: number }).count > 0) {
      return c.json({ error: "already initialized" }, 409);
    }
    const input = await credentials(c);
    if (!input) return c.json({ error: "username and password required" }, 400);
    // The first administrator is the most valuable account in the install, so
    // the wizard's rules are enforced server-side, not only in the browser.
    const verdict = assessPassword(input.password, input.username);
    if (!verdict.ok) return c.json({ error: `weak password: ${verdict.reason}` }, 400);
    const passwordHash = await hashPassword(input.password);
    const timestamp = now();
    try {
      const result = db.transaction(() => {
        if ((db.query("SELECT COUNT(*) AS count FROM users").get() as { count: number }).count > 0) {
          throw new Error("already initialized");
        }
        const insert = db.query(`
          INSERT INTO users (username, password_hash, role, active, created_at, updated_at)
          VALUES (?, ?, 'super_admin', 1, ?, ?)
        `).run(input.username, passwordHash, iso(timestamp), iso(timestamp));
        const userId = Number(insert.lastInsertRowid);
        return { userId, token: createSession(db, userId, timestamp) };
      })();
      setSessionCookie(c, result.token);
      return c.json({ user: { id: result.userId, username: input.username, role: "super_admin" } }, 201);
    } catch (error) {
      if ((error as Error).message === "already initialized") return c.json({ error: "already initialized" }, 409);
      throw error;
    }
  });

  app.post("/api/auth/login", async (c) => {
    const input = await credentials(c);
    if (!input) return c.json({ error: "username and password required" }, 400);
    const key = `${input.username}\0${clientIp(c)}`;
    const timestamp = now();
    let failure = failures.get(key);
    if (failure && timestamp - failure.firstAt >= RATE_WINDOW_MS) {
      failures.delete(key);
      failure = undefined;
    }
    if (failure && failure.count >= MAX_FAILURES) return c.json({ error: "too many login attempts" }, 429);

    const user = db.query(`
      SELECT id, username, password_hash, role, active FROM users WHERE username = ?
    `).get(input.username) as (UserRow & { password_hash: string }) | null;
    const valid = !!user && !!user.active && await verifyPassword(input.password, user.password_hash);
    if (!valid) {
      if (failure) failure.count += 1;
      else failures.set(key, { count: 1, firstAt: timestamp });
      return c.json({ error: "invalid credentials" }, 401);
    }

    failures.delete(key);
    const token = createSession(db, user.id, timestamp);
    setSessionCookie(c, token);
    return c.json({ user: { id: user.id, username: user.username, role: user.role } });
  });

  app.post("/api/auth/logout", (c) => {
    const token = getCookie(c, SESSION_COOKIE);
    if (token) db.query("DELETE FROM sessions WHERE token_hash = ?").run(hashToken(token));
    clearSessionCookie(c);
    return c.body(null, 204);
  });

  app.get("/api/auth/status", (c) => {
    const initialized = (db.query("SELECT COUNT(*) AS count FROM users").get() as { count: number }).count > 0;
    const user = sessionUser(db, getCookie(c, SESSION_COOKIE), now());
    return c.json(user ? { initialized, user, role: user.role } : { initialized });
  });

  return app;
}
