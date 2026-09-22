import { describe, expect, it } from "bun:test";
import { Database } from "bun:sqlite";
import { openDb, runMigrations, schemaVersion, SCHEMA_VERSION, MIGRATIONS } from "./db";

function makeDb(): Database {
  const db = openDb(":memory:");
  runMigrations(db);
  return db;
}

describe("Database schema and migrations", () => {
  it("applies migrations to fresh DB and returns latest version", () => {
    const db = openDb(":memory:");
    expect(schemaVersion(db)).toBe(0);
    const ver = runMigrations(db);
    expect(ver).toBe(SCHEMA_VERSION);
    expect(schemaVersion(db)).toBe(SCHEMA_VERSION);

    // Verify key tables exist
    const tables = (
      db.query("SELECT name FROM sqlite_master WHERE type='table'").all() as { name: string }[]
    ).map((t) => t.name);
    for (const expected of [
      "users",
      "sessions",
      "tokens",
      "comments",
      "campaigns",
      "locations",
      "issuances",
      "keys",
      "hosts",
      "host_locations",
      "reports",
      "ingest_events",
      "finding_states",
      "finding_state_history",
      "saved_views",
      "audit_log",
      "settings",
      "backups",
      "migrations",
    ]) {
      expect(tables).toContain(expected);
    }
  });

  it("is idempotent when migrations are rerun", () => {
    const db = openDb(":memory:");
    const v1 = runMigrations(db);
    const v2 = runMigrations(db);
    expect(v1).toBe(SCHEMA_VERSION);
    expect(v2).toBe(SCHEMA_VERSION);
  });

  it("enforces foreign key constraints", () => {
    const db = makeDb();
    // Inserting a location referencing non-existent campaign should fail
    expect(() => {
      db.query(
        "INSERT INTO locations (campaign_id, name, created_at, updated_at) VALUES (999, 'loc1', 'now', 'now')"
      ).run();
    }).toThrow(/FOREIGN KEY/i);

    // Inserting an issuance referencing non-existent campaign/location should fail
    expect(() => {
      db.query(`
        INSERT INTO issuances (id, extractor_id, campaign_id, location_id, key_id, created_at)
        VALUES ('iss1', 'ext1', 999, 888, 'k1', 'now')
      `).run();
    }).toThrow(/FOREIGN KEY/i);
  });

  it("enforces required one-to-one key relationship on issuances", () => {
    const db = makeDb();
    db.query("INSERT INTO campaigns (id, name, created_at, updated_at) VALUES (1, 'CampA', 'now', 'now')").run();
    db.query("INSERT INTO locations (id, campaign_id, name, created_at, updated_at) VALUES (1, 1, 'LocA', 'now', 'now')").run();
    db.query(`
      INSERT INTO issuances (id, extractor_id, campaign_id, location_id, key_id, created_at)
      VALUES ('iss1', 'ext1', 1, 1, 'k1', 'now')
    `).run();

    db.query(`
      INSERT INTO keys (issuance_id, public_key, private_key_path, created_at)
      VALUES ('iss1', 'pubkey-hex', '/path/to/key', 'now')
    `).run();

    // Duplicate key for same issuance fails UNIQUE constraint
    expect(() => {
      db.query(`
        INSERT INTO keys (issuance_id, public_key, private_key_path, created_at)
        VALUES ('iss1', 'pubkey-hex-2', '/path/to/key2', 'now')
      `).run();
    }).toThrow(/UNIQUE constraint failed/i);
  });

  it("rejects duplicate report replay on (extractor_id, scan_id)", () => {
    const db = makeDb();
    db.query("INSERT INTO campaigns (id, name, created_at, updated_at) VALUES (1, 'CampA', 'now', 'now')").run();
    db.query("INSERT INTO locations (id, campaign_id, name, created_at, updated_at) VALUES (1, 1, 'LocA', 'now', 'now')").run();
    db.query(`
      INSERT INTO issuances (id, extractor_id, campaign_id, location_id, key_id, created_at)
      VALUES ('iss1', 'ext1', 1, 1, 'k1', 'now')
    `).run();
    db.query(`
      INSERT INTO hosts (id, machine_id, first_seen_at, last_seen_at)
      VALUES (1, 'mach-uuid-1', 'now', 'now')
    `).run();

    db.query(`
      INSERT INTO reports (
        issuance_id, host_id, location_id, campaign_id, extractor_id, scan_id, received_at
      ) VALUES ('iss1', 1, 1, 1, 'ext1', 'scan-alpha', 'now')
    `).run();

    // Replay of same extractor_id + scan_id must fail UNIQUE constraint
    expect(() => {
      db.query(`
        INSERT INTO reports (
          issuance_id, host_id, location_id, campaign_id, extractor_id, scan_id, received_at
        ) VALUES ('iss1', 1, 1, 1, 'ext1', 'scan-alpha', 'now')
      `).run();
    }).toThrow(/UNIQUE constraint failed: reports\.extractor_id, reports\.scan_id/i);
  });

  it("supports cross-location host mapping via host_locations table", () => {
    const db = makeDb();
    db.query("INSERT INTO campaigns (id, name, created_at, updated_at) VALUES (1, 'CampA', 'now', 'now')").run();
    db.query("INSERT INTO locations (id, campaign_id, name, created_at, updated_at) VALUES (1, 1, 'HQ', 'now', 'now')").run();
    db.query("INSERT INTO locations (id, campaign_id, name, created_at, updated_at) VALUES (2, 1, 'Branch', 'now', 'now')").run();
    db.query("INSERT INTO hosts (id, machine_id, first_seen_at, last_seen_at) VALUES (10, 'mid-10', 'now', 'now')").run();

    // Host 10 mapped to Location 1
    db.query("INSERT INTO host_locations (host_id, location_id, first_seen_at, last_seen_at) VALUES (10, 1, 'now', 'now')").run();
    // Same Host 10 mapped to Location 2
    db.query("INSERT INTO host_locations (host_id, location_id, first_seen_at, last_seen_at) VALUES (10, 2, 'now', 'now')").run();

    const locs = db.query("SELECT location_id FROM host_locations WHERE host_id = 10 ORDER BY location_id").all() as { location_id: number }[];
    expect(locs.map((l) => l.location_id)).toEqual([1, 2]);
  });

  it("enforces append-only triggers on audit_log", () => {
    const db = makeDb();
    db.query(`
      INSERT INTO audit_log (actor, actor_ip, action, resource, details, created_at)
      VALUES ('admin', '127.0.0.1', 'create_user', 'user:2', '{"role":"auditor"}', 'now')
    `).run();

    // UPDATE on audit_log must be rejected
    expect(() => {
      db.query("UPDATE audit_log SET action = 'tampered' WHERE id = 1").run();
    }).toThrow(/audit_log is append-only/i);

    // DELETE on audit_log must be rejected
    expect(() => {
      db.query("DELETE FROM audit_log WHERE id = 1").run();
    }).toThrow(/audit_log is append-only/i);
  });

  it("enforces append-only triggers on finding_state_history and auto-records on state change", () => {
    const db = makeDb();
    db.query("INSERT INTO campaigns (id, name, created_at, updated_at) VALUES (1, 'CampA', 'now', 'now')").run();
    db.query("INSERT INTO locations (id, campaign_id, name, created_at, updated_at) VALUES (1, 1, 'HQ', 'now', 'now')").run();
    db.query("INSERT INTO issuances (id, extractor_id, campaign_id, location_id, key_id, created_at) VALUES ('iss1', 'ext1', 1, 1, 'k1', 'now')").run();
    db.query("INSERT INTO hosts (id, machine_id, first_seen_at, last_seen_at) VALUES (1, 'mid-1', 'now', 'now')").run();
    db.query(`
      INSERT INTO reports (id, issuance_id, host_id, location_id, campaign_id, extractor_id, scan_id, received_at)
      VALUES (1, 'iss1', 1, 1, 1, 'ext1', 'scan-1', 'now')
    `).run();

    db.query(`
      INSERT INTO finding_states (id, report_id, check_id, state, updated_at)
      VALUES (1, 1, 'CIS-1.1', 'open', 'now')
    `).run();

    // Updating state triggers automatic history insert
    db.query("UPDATE finding_states SET state = 'accepted_risk', assignee = 'alice' WHERE id = 1").run();

    const history = db.query("SELECT * FROM finding_state_history WHERE finding_state_id = 1").all() as any[];
    expect(history.length).toBe(1);
    expect(history[0].from_state).toBe("open");
    expect(history[0].to_state).toBe("accepted_risk");

    // Direct UPDATE on finding_state_history must fail
    expect(() => {
      db.query("UPDATE finding_state_history SET to_state = 'remediated' WHERE id = 1").run();
    }).toThrow(/finding_state_history is append-only/i);

    // Direct DELETE on finding_state_history must fail
    expect(() => {
      db.query("DELETE FROM finding_state_history WHERE id = 1").run();
    }).toThrow(/finding_state_history is append-only/i);
  });

  it("blocks issuance creation on retired locations", () => {
    const db = makeDb();
    db.query("INSERT INTO campaigns (id, name, created_at, updated_at) VALUES (1, 'CampA', 'now', 'now')").run();
    db.query("INSERT INTO locations (id, campaign_id, name, retired_at, created_at, updated_at) VALUES (1, 1, 'OldLab', '2026-01-01', 'now', 'now')").run();

    expect(() => {
      db.query(`
        INSERT INTO issuances (id, extractor_id, campaign_id, location_id, key_id, created_at)
        VALUES ('iss1', 'ext1', 1, 1, 'k1', 'now')
      `).run();
    }).toThrow(/cannot issue for a retired location/i);
  });

  it("supports partial migration / upgrade simulation", () => {
    const db = openDb(":memory:");
    // Migrate to v1 only
    const v1 = runMigrations(db, { to: 1 });
    expect(v1).toBe(1);
    expect(schemaVersion(db)).toBe(1);

    // Settings table is present from v1
    const settings = db.query("SELECT COUNT(*) AS count FROM settings").all() as { count: number }[];
    expect(settings[0].count).toBe(0);

    // Upgrade to latest
    const vLatest = runMigrations(db);
    expect(vLatest).toBe(SCHEMA_VERSION);
    expect(schemaVersion(db)).toBe(SCHEMA_VERSION);

    // Defaults populated in v2
    const rows = db.query("SELECT key, value FROM settings ORDER BY key").all() as { key: string; value: string }[];
    expect(rows).toEqual([
      { key: "freshness_sla_hours", value: "24" },
      { key: "retention_days", value: "365" },
    ]);
  });

  it("rolls back transaction on injected migration failure leaving DB intact", () => {
    const db = openDb(":memory:");
    runMigrations(db, { to: 1 });
    expect(schemaVersion(db)).toBe(1);

    // Insert canary data
    db.query("INSERT INTO campaigns (id, name, created_at, updated_at) VALUES (99, 'CanaryCamp', 'now', 'now')").run();

    // Inject failure during v2
    expect(() => {
      runMigrations(db, {
        beforeStep: (ver) => {
          if (ver === 2) {
            throw new Error("simulated disk error during migration");
          }
        },
      });
    }).toThrow(/simulated disk error during migration/);

    // DB remains at v1
    expect(schemaVersion(db)).toBe(1);
    // Canary data is intact
    const canary = db.query("SELECT name FROM campaigns WHERE id = 99").all() as { name: string }[];
    expect(canary[0]?.name).toBe("CanaryCamp");
  });

  it("migrates a persistent on-disk database idempotently across restarts", () => {
    const tmpPath = `server/data/test-${Date.now()}-${Math.random().toString(36).slice(2)}.sqlite`;
    try {
      // First run: brand new file
      const db1 = openDb(tmpPath);
      const v1 = runMigrations(db1);
      expect(v1).toBe(SCHEMA_VERSION);
      db1.close();

      // Second run: reopen existing file
      const db2 = openDb(tmpPath);
      expect(schemaVersion(db2)).toBe(SCHEMA_VERSION);
      const v2 = runMigrations(db2);
      expect(v2).toBe(SCHEMA_VERSION);
      db2.close();
    } finally {
      try {
        const { unlinkSync } = require("node:fs");
        unlinkSync(tmpPath);
      } catch {
        // ignore if not created
      }
    }
  });

  it("serves health route", async () => {
    process.env.HBS_DB_PATH = ":memory:";
    const { app } = await import("./index");
    const res = await app.request("/api/health");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });
});

