import { afterEach, describe, expect, it } from "bun:test";
import { Database } from "bun:sqlite";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openDb, runMigrations } from "./db";
import {
  KeyLifecycle,
  KeyLifecycleError,
  createEncryptedBackup,
  keygen,
  restoreEncryptedBackup,
} from "./keys";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function root(): string {
  const value = mkdtempSync(join(tmpdir(), "hbs-keys-"));
  roots.push(value);
  return value;
}

function seededDb(path = ":memory:"): Database {
  const db = openDb(path);
  runMigrations(db);
  db.query("INSERT INTO campaigns (id, name, created_at, updated_at) VALUES (1, 'campaign', '2026-01-01', '2026-01-01')").run();
  db.query("INSERT INTO locations (id, campaign_id, name, created_at, updated_at) VALUES (1, 1, 'location', '2026-01-01', '2026-01-01')").run();
  return db;
}

function issuance(db: Database, id: string, extractorId = `extractor-${id}`): void {
  db.query(`INSERT INTO issuances
    (id, extractor_id, campaign_id, location_id, key_id, artifact_path, created_at)
    VALUES (?, ?, 1, 1, ?, ?, '2026-01-01')`
  ).run(id, extractorId, `key-${id}`, `binaries/${id}.bin`);
}

describe("per-issuance keys", () => {
  it("generates fresh non-nil raw X25519 pairs", () => {
    const first = keygen();
    const second = keygen();
    expect(first.publicKey).toHaveLength(32);
    expect(first.privateKey).toHaveLength(32);
    expect(first.publicKey.some(Boolean)).toBeTrue();
    expect(first.privateKey.some(Boolean)).toBeTrue();
    expect(first.publicKey).not.toEqual(second.publicKey);
    expect(first.privateKey).not.toEqual(second.privateKey);
  });

  it("saves atomically with 0600 mode and loads only through DB mapping", () => {
    const dataRoot = root();
    const db = seededDb();
    issuance(db, "iss-1");
    const lifecycle = new KeyLifecycle(db, { dataRoot });
    const pair = keygen();

    lifecycle.saveKey("iss-1", pair.privateKey, pair.publicKey);
    const keyPath = join(dataRoot, "keys", "iss-1.key");
    expect(readFileSync(keyPath)).toEqual(Buffer.from(pair.privateKey));
    if (process.platform !== "win32") expect(statSync(keyPath).mode & 0o777).toBe(0o600);
    expect(lifecycle.loadPriv("iss-1")).toEqual(pair.privateKey);
    expect(() => lifecycle.loadPriv("missing")).toThrow(KeyLifecycleError);
    db.close();
  });

  it("rejects nil and duplicate public keys without orphan files", () => {
    const dataRoot = root();
    const db = seededDb();
    issuance(db, "iss-1");
    issuance(db, "iss-2");
    const lifecycle = new KeyLifecycle(db, { dataRoot });
    const pair = keygen();
    lifecycle.saveKey("iss-1", pair.privateKey, pair.publicKey);

    expect(() => lifecycle.saveKey("iss-2", pair.privateKey, new Uint8Array(32))).toThrow(/nil/i);
    expect(() => lifecycle.saveKey("iss-2", pair.privateKey, pair.publicKey)).toThrow(/duplicate/i);
    expect(() => readFileSync(join(dataRoot, "keys", "iss-2.key"))).toThrow();
    db.close();
  });

  it("cleans up file when mapping insert rolls back", () => {
    const dataRoot = root();
    const db = seededDb();
    const lifecycle = new KeyLifecycle(db, { dataRoot });
    const pair = keygen();

    expect(() => lifecycle.saveKey("unknown-issuance", pair.privateKey, pair.publicKey)).toThrow();
    expect(() => readFileSync(join(dataRoot, "keys", "unknown-issuance.key"))).toThrow();
    db.close();
  });

  it("revokes without deleting key, artifact, or mapping and blocks use", async () => {
    const dataRoot = root();
    const db = seededDb();
    issuance(db, "iss-1");
    const lifecycle = new KeyLifecycle(db, { dataRoot });
    const pair = keygen();
    lifecycle.saveKey("iss-1", pair.privateKey, pair.publicKey);
    const artifact = join(dataRoot, "binaries", "iss-1.bin");
    await Bun.write(artifact, "artifact");

    lifecycle.revokeIssuance("iss-1", { actor: "admin", reason: "retired" });
    expect(() => lifecycle.assertIssuanceUsable("iss-1", "ingest")).toThrow(/revoked/i);
    expect(() => lifecycle.assertIssuanceUsable("iss-1", "download")).toThrow(/revoked/i);
    expect(lifecycle.loadPriv("iss-1")).toEqual(pair.privateKey);
    expect(readFileSync(artifact, "utf8")).toBe("artifact");
    expect(db.query("SELECT COUNT(*) AS n FROM keys WHERE issuance_id = 'iss-1'").get() as { n: number }).toEqual({ n: 1 });
    expect(db.query("SELECT action FROM audit_log").get() as { action: string }).toEqual({ action: "issuance.revoked" });
    db.close();
  });

  it("guards irreversible purge and leaves redacted audit metadata", () => {
    const dataRoot = root();
    const db = seededDb();
    issuance(db, "iss-1", "typed-extractor-id");
    const lifecycle = new KeyLifecycle(db, {
      dataRoot,
      purgePolicy: () => ({ retentionSatisfied: true, legalHold: false }),
    });
    const pair = keygen();
    lifecycle.saveKey("iss-1", pair.privateKey, pair.publicKey);

    expect(() => lifecycle.purgeIssuance("iss-1", {
      actor: "admin", role: "viewer", typedExtractorId: "typed-extractor-id", confirmIrreversible: true,
    })).toThrow(/super_admin/i);
    expect(() => lifecycle.purgeIssuance("iss-1", {
      actor: "admin", role: "super_admin", typedExtractorId: "wrong", confirmIrreversible: true,
    })).toThrow(/confirmation/i);

    lifecycle.purgeIssuance("iss-1", {
      actor: "admin", role: "super_admin", typedExtractorId: "typed-extractor-id", confirmIrreversible: true,
    });
    expect(db.query("SELECT id FROM issuances WHERE id = 'iss-1'").get()).toBeNull();
    expect(db.query("SELECT action, details FROM audit_log WHERE action = 'issuance.purged'").get()).toEqual({
      action: "issuance.purged",
      details: JSON.stringify({ extractorId: "typed-extractor-id", irreversible: true }),
    });
    expect(() => readFileSync(join(dataRoot, "keys", "iss-1.key"))).toThrow();
    db.close();
  });
});

describe("encrypted backup and restore", () => {
  it("round-trips database and one-to-one key files", () => {
    const sourceRoot = root();
    const db = seededDb();
    issuance(db, "iss-1");
    const lifecycle = new KeyLifecycle(db, { dataRoot: sourceRoot });
    const pair = keygen();
    lifecycle.saveKey("iss-1", pair.privateKey, pair.publicKey);
    const archive = createEncryptedBackup(db, "correct horse battery staple", { dataRoot: sourceRoot });

    const targetRoot = root();
    const databasePath = join(targetRoot, "dashboard.sqlite");
    restoreEncryptedBackup(archive, "correct horse battery staple", { dataRoot: targetRoot, databasePath });

    const restored = openDb(databasePath);
    expect(restored.query("SELECT extractor_id FROM issuances WHERE id = 'iss-1'").get()).toEqual({ extractor_id: "extractor-iss-1" });
    expect(readFileSync(join(targetRoot, "keys", "iss-1.key"))).toEqual(Buffer.from(pair.privateKey));
    restored.close();
    db.close();
  });

  it("rejects wrong passphrase, tampering, and unsupported versions", () => {
    const dataRoot = root();
    const db = seededDb();
    const archive = createEncryptedBackup(db, "passphrase", { dataRoot });
    expect(() => restoreEncryptedBackup(archive, "wrong", {
      dataRoot: root(), databasePath: join(root(), "wrong.sqlite"),
    })).toThrow(/authentication/i);

    const tampered = Uint8Array.from(archive);
    tampered[tampered.length - 8] ^= 1;
    expect(() => restoreEncryptedBackup(tampered, "passphrase", {
      dataRoot: root(), databasePath: join(root(), "tampered.sqlite"),
    })).toThrow();

    const parsed = JSON.parse(Buffer.from(archive).toString("utf8"));
    parsed.version = 999;
    expect(() => restoreEncryptedBackup(Buffer.from(JSON.stringify(parsed)), "passphrase", {
      dataRoot: root(), databasePath: join(root(), "old.sqlite"),
    })).toThrow(/version/i);
    db.close();
  });

  it("rejects missing or extra key files before replacing live data", () => {
    const sourceRoot = root();
    const db = seededDb();
    issuance(db, "iss-1");
    const lifecycle = new KeyLifecycle(db, { dataRoot: sourceRoot });
    const pair = keygen();
    lifecycle.saveKey("iss-1", pair.privateKey, pair.publicKey);
    rmSync(join(sourceRoot, "keys", "iss-1.key"));
    expect(() => createEncryptedBackup(db, "passphrase", { dataRoot: sourceRoot })).toThrow(/key/i);

    const targetRoot = root();
    const targetDb = join(targetRoot, "dashboard.sqlite");
    writeFileSync(targetDb, "live-db");
    expect(readFileSync(targetDb, "utf8")).toBe("live-db");
    db.close();
  });
});
