import { describe, expect, it } from "bun:test";
import { openDb, runMigrations } from "./db";
import { ensureBootstrapAdmin } from "./bootstrap";

function freshDb() {
  const db = openDb(":memory:");
  runMigrations(db);
  return db;
}

describe("first-run admin bootstrap", () => {
  it("creates a super_admin and returns the credentials once", async () => {
    const db = freshDb();
    const created = await ensureBootstrapAdmin(db);
    expect(created).not.toBeNull();
    expect(created!.username).toBe("admin");
    expect(created!.password.length).toBeGreaterThanOrEqual(16);

    const row = db.query("SELECT username, password_hash, role, active FROM users").get() as {
      username: string;
      password_hash: string;
      role: string;
      active: number;
    };
    expect(row.role).toBe("super_admin");
    expect(row.active).toBe(1);
    expect(row.password_hash).not.toContain(created!.password);
    expect(await Bun.password.verify(created!.password, row.password_hash)).toBeTrue();

    // Second call is a no-op.
    expect(await ensureBootstrapAdmin(db)).toBeNull();
    db.close();
  });

  it("honors supplied credentials", async () => {
    const db = freshDb();
    const created = await ensureBootstrapAdmin(db, { username: "Root-Admin", password: "chosen-password-123" });
    expect(created).toEqual({ username: "root-admin", password: "chosen-password-123" });
    const row = db.query("SELECT username FROM users").get() as { username: string };
    expect(row.username).toBe("root-admin");
    db.close();
  });

  it("does nothing when a user already exists", async () => {
    const db = freshDb();
    db.query(
      `INSERT INTO users (username, password_hash, role, active, created_at, updated_at)
       VALUES ('existing', 'x', 'auditor', 1, '2026-01-01', '2026-01-01')`,
    ).run();
    expect(await ensureBootstrapAdmin(db)).toBeNull();
    expect((db.query("SELECT COUNT(*) AS n FROM users").get() as { n: number }).n).toBe(1);
    db.close();
  });
});
