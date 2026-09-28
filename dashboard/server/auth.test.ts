import { describe, expect, it } from "bun:test";
import { Hono } from "hono";
import { openDb, runMigrations } from "./db";
import { verifyPassword } from "./password";
import { createAuthRoutes, hashToken, type AuthEnv } from "./auth";
import { createUserRoutes } from "./users";

function testApp() {
  const db = openDb(":memory:");
  runMigrations(db);
  const app = new Hono<AuthEnv>();
  app.route("/", createAuthRoutes(db));
  app.route("/", createUserRoutes(db));
  return { app, db };
}

function json(method: string, body?: unknown, headers: Record<string, string> = {}): RequestInit {
  return {
    method,
    headers: { "content-type": "application/json", ...headers },
    body: body === undefined ? undefined : JSON.stringify(body),
  };
}

function sessionCookie(response: Response): string {
  const header = response.headers.get("set-cookie");
  expect(header).toContain("hbs_session=");
  return header!.split(";", 1)[0]!;
}

async function setup(app: Hono<AuthEnv>, username = "Admin", password = "correct horse battery staple") {
  const response = await app.request("http://localhost/api/auth/setup", json("POST", { username, password }));
  return { response, cookie: sessionCookie(response) };
}

describe("auth routes", () => {
  it("creates only first user as normalized super_admin with argon2id and a hashed session", async () => {
    const { app, db } = testApp();
    const { response, cookie } = await setup(app, "  ADMIN  ");

    expect(response.status).toBe(201);
    expect(response.headers.get("set-cookie")).toContain("HttpOnly");
    expect(response.headers.get("set-cookie")).toContain("SameSite=Lax");
    expect(response.headers.get("set-cookie")).not.toContain("Secure");
    const user = db.query("SELECT username, role, password_hash FROM users").get() as Record<string, string>;
    expect(user.username).toBe("admin");
    expect(user.role).toBe("super_admin");
    expect(user.password_hash).toStartWith("$argon2id$");
    expect(await verifyPassword("correct horse battery staple", user.password_hash)).toBe(true);

    const rawToken = cookie.slice("hbs_session=".length);
    const stored = db.query("SELECT token_hash FROM sessions").get() as { token_hash: string };
    expect(stored.token_hash).toBe(hashToken(rawToken));
    expect(stored.token_hash).not.toBe(rawToken);

    const second = await app.request("/api/auth/setup", json("POST", { username: "other", password: "correct-horse-battery-42" }));
    expect(second.status).toBe(409);
  });

  it("refuses a weak password for the first administrator", async () => {
    const { app, db } = testApp();
    const weak = await app.request(
      "/api/auth/setup",
      json("POST", { username: "admin", password: "password123" }),
    );
    expect(weak.status).toBe(400);
    const body = await weak.json() as { error: string };
    expect(body.error).toStartWith("weak password:");
    expect((db.query("SELECT COUNT(*) AS count FROM users").get() as { count: number }).count).toBe(0);

    // A password that merely restates the username is refused as well.
    const echoesUser = await app.request(
      "/api/auth/setup",
      json("POST", { username: "operator", password: "operator-passphrase-1" }),
    );
    expect(echoesUser.status).toBe(400);

    const strong = await app.request(
      "/api/auth/setup",
      json("POST", { username: "operator", password: "correct horse battery staple" }),
    );
    expect(strong.status).toBe(201);
  });

  it("marks HTTPS session cookies Secure", async () => {
    const { app } = testApp();
    const response = await app.request("https://localhost/api/auth/setup", json("POST", { username: "admin", password: "correct-horse-battery-42" }));
    expect(response.headers.get("set-cookie")).toContain("Secure");
  });

  it("verifies login, returns status, and invalidates logout", async () => {
    const { app, db } = testApp();
    await setup(app, "Admin", "right-passphrase-123");

    const wrong = await app.request("/api/auth/login", json("POST", { username: "ADMIN", password: "wrong" }));
    expect(wrong.status).toBe(401);

    const login = await app.request("/api/auth/login", json("POST", { username: " ADMIN ", password: "right-passphrase-123" }));
    expect(login.status).toBe(200);
    const cookie = sessionCookie(login);
    const status = await app.request("/api/auth/status", { headers: { cookie } });
    expect(await status.json()).toEqual({
      initialized: true,
      user: { id: 1, username: "admin", role: "super_admin", allowedCampaigns: null },
      role: "super_admin",
    });

    const logout = await app.request("/api/auth/logout", { method: "POST", headers: { cookie } });
    expect(logout.status).toBe(204);
    expect(logout.headers.get("set-cookie")).toContain("Max-Age=0");
    expect((db.query("SELECT COUNT(*) AS count FROM sessions").get() as { count: number }).count).toBe(1);
    const loggedOut = await app.request("/api/auth/status", { headers: { cookie } });
    expect(await loggedOut.json()).toEqual({ initialized: true });
  });

  it("limits each normalized username and IP after five failures for 15 minutes", async () => {
    let time = 1_000_000;
    const db = openDb(":memory:");
    runMigrations(db);
    const app = new Hono<AuthEnv>();
    app.route("/", createAuthRoutes(db, { now: () => time }));
    const headers = { "x-forwarded-for": "192.0.2.10" };

    for (let attempt = 0; attempt < 5; attempt++) {
      const username = attempt % 2 ? " Nobody " : "NOBODY";
      const response = await app.request("/api/auth/login", json("POST", { username, password: "wrong" }, headers));
      expect(response.status).toBe(401);
    }
    expect((await app.request("/api/auth/login", json("POST", { username: "nobody", password: "wrong" }, headers))).status).toBe(429);
    expect((await app.request("/api/auth/login", json("POST", { username: "nobody", password: "wrong" }, { "x-forwarded-for": "192.0.2.11" }))).status).toBe(401);

    time += 15 * 60 * 1000;
    expect((await app.request("/api/auth/login", json("POST", { username: "nobody", password: "wrong" }, headers))).status).toBe(401);
  });
});

describe("user administration", () => {
  it("allows super_admin CRUD and denies auditor", async () => {
    const { app } = testApp();
    const { cookie: adminCookie } = await setup(app);
    const created = await app.request("/api/users", json("POST", {
      username: "Auditor",
      password: "quarterly-review-2026",
      role: "auditor",
    }, { cookie: adminCookie }));
    expect(created.status).toBe(201);
    expect((await created.json()).user).toMatchObject({ id: 2, username: "auditor", role: "auditor", active: true });

    const login = await app.request("/api/auth/login", json("POST", { username: "auditor", password: "quarterly-review-2026" }));
    const auditorCookie = sessionCookie(login);
    expect((await app.request("/api/users", { headers: { cookie: auditorCookie } })).status).toBe(403);

    const reset = await app.request("/api/users/2", json("PATCH", { password: "new-passphrase-123", role: "viewer" }, { cookie: adminCookie }));
    expect(reset.status).toBe(200);
    expect((await app.request("/api/auth/login", json("POST", { username: "auditor", password: "new-passphrase-123" }))).status).toBe(200);

    expect((await app.request("/api/users/2", { method: "DELETE", headers: { cookie: adminCookie } })).status).toBe(204);
    expect((await app.request("/api/auth/login", json("POST", { username: "auditor", password: "new-passphrase-123" }))).status).toBe(401);
  });

  it("never deactivates or demotes last active super_admin", async () => {
    const { app } = testApp();
    const { cookie } = await setup(app);

    expect((await app.request("/api/users/1", json("PATCH", { active: false }, { cookie }))).status).toBe(409);
    expect((await app.request("/api/users/1", json("PATCH", { role: "viewer" }, { cookie }))).status).toBe(409);
    expect((await app.request("/api/users/1", { method: "DELETE", headers: { cookie } })).status).toBe(409);
  });
});
