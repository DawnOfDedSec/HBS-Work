import { Database } from "bun:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

// Authoritative HBS dashboard schema. Versioned, transactional, idempotent migrations.
// Contract: docs/superpowers/plans/2026-09-21-hbs-platform.md Task 41.

export type Migration = {
  version: number;
  up: string[];
};

type MigrationOptions = {
  /** Migrate only up to this version (default: latest). */
  to?: number;
  /** Test hook: called before each statement; throw to inject a mid-migration failure. */
  beforeStep?: (version: number, step: number) => void;
};

export const MIGRATIONS: Migration[] = [
  {
    version: 1,
    up: [
      // ---- core account tables ----
      `CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('super_admin','auditor','viewer')),
        active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id),
        token_hash TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id),
        name TEXT NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL,
        revoked_at TEXT
      )`,
      `CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        report_id INTEGER REFERENCES reports(id),
        host_id INTEGER REFERENCES hosts(id),
        author_id INTEGER NOT NULL REFERENCES users(id),
        body TEXT NOT NULL,
        created_at TEXT NOT NULL
      )`,
      // ---- campaign hierarchy ----
      `CREATE TABLE IF NOT EXISTS campaigns (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        client TEXT,
        scope TEXT,
        expires_at TEXT,
        status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','completed','archived')),
        tags TEXT NOT NULL DEFAULT '[]',
        retention_days INTEGER,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS locations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        campaign_id INTEGER NOT NULL REFERENCES campaigns(id),
        name TEXT NOT NULL,
        tags TEXT NOT NULL DEFAULT '[]',
        retired_at TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE (campaign_id, name)
      )`,
      `CREATE TABLE IF NOT EXISTS issuances (
        id TEXT PRIMARY KEY,
        extractor_id TEXT NOT NULL UNIQUE,
        campaign_id INTEGER NOT NULL REFERENCES campaigns(id),
        location_id INTEGER NOT NULL REFERENCES locations(id),
        key_id TEXT NOT NULL,
        platform TEXT,
        artifact_path TEXT,
        artifact_hash TEXT,
        artifact_size INTEGER,
        expires_at TEXT,
        created_at TEXT NOT NULL,
        download_count INTEGER NOT NULL DEFAULT 0,
        revoked_at TEXT,
        revoked_reason TEXT,
        revoked_by TEXT,
        is_legacy_v1 INTEGER NOT NULL DEFAULT 0
      )`,
      `CREATE TABLE IF NOT EXISTS keys (
        issuance_id TEXT NOT NULL UNIQUE REFERENCES issuances(id),
        public_key TEXT NOT NULL,
        private_key_path TEXT NOT NULL,
        created_at TEXT NOT NULL
      )`,
      // ---- host routing ----
      `CREATE TABLE IF NOT EXISTS hosts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        machine_id TEXT NOT NULL UNIQUE,
        hostname TEXT,
        platform TEXT,
        os TEXT,
        arch TEXT,
        first_seen_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS host_locations (
        host_id INTEGER NOT NULL REFERENCES hosts(id),
        location_id INTEGER NOT NULL REFERENCES locations(id),
        first_seen_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        PRIMARY KEY (host_id, location_id)
      )`,
      // ---- reports / ingest ----
      `CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        issuance_id TEXT NOT NULL REFERENCES issuances(id),
        host_id INTEGER NOT NULL REFERENCES hosts(id),
        location_id INTEGER NOT NULL REFERENCES locations(id),
        campaign_id INTEGER NOT NULL REFERENCES campaigns(id),
        extractor_id TEXT NOT NULL,
        scan_id TEXT NOT NULL,
        schema_fingerprint TEXT,
        catalog_fingerprint TEXT,
        envelope BLOB,
        report_json TEXT,
        score REAL,
        coverage REAL,
        summary_json TEXT,
        scan_timestamp TEXT,
        received_at TEXT NOT NULL,
        via TEXT,
        total_duration_ms INTEGER,
        collect_duration_ms INTEGER,
        bytes INTEGER,
        peak_rss_bytes INTEGER,
        privilege_level TEXT,
        evidence_depth TEXT,
        UNIQUE (extractor_id, scan_id)
      )`,
      `CREATE TABLE IF NOT EXISTS ingest_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        received_at TEXT NOT NULL,
        via TEXT,
        envelope_bytes INTEGER,
        duration_ms INTEGER,
        accepted INTEGER NOT NULL CHECK (accepted IN (0,1)),
        reason_code TEXT,
        report_id INTEGER REFERENCES reports(id),
        issuance_id TEXT REFERENCES issuances(id)
      )`,
      // ---- treatment workflow ----
      `CREATE TABLE IF NOT EXISTS finding_states (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        report_id INTEGER NOT NULL REFERENCES reports(id),
        check_id TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'open'
          CHECK (state IN ('open','accepted_risk','false_positive','remediated')),
        assignee TEXT,
        due_date TEXT,
        updated_at TEXT NOT NULL,
        UNIQUE (report_id, check_id)
      )`,
      `CREATE TABLE IF NOT EXISTS finding_state_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_state_id INTEGER NOT NULL REFERENCES finding_states(id),
        actor TEXT,
        changed_at TEXT NOT NULL,
        from_state TEXT,
        to_state TEXT NOT NULL,
        justification TEXT,
        assignee TEXT,
        due_date TEXT
      )`,
      // ---- saved views ----
      `CREATE TABLE IF NOT EXISTS saved_views (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_id INTEGER NOT NULL REFERENCES users(id),
        campaign_id INTEGER REFERENCES campaigns(id),
        name TEXT NOT NULL,
        scope TEXT NOT NULL,
        query TEXT NOT NULL,
        visibility TEXT NOT NULL DEFAULT 'personal' CHECK (visibility IN ('personal','team')),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE (owner_id, name, scope)
      )`,
      // ---- audit log (append-only, redacted details) ----
      `CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor TEXT,
        actor_ip TEXT,
        action TEXT NOT NULL,
        resource TEXT,
        details TEXT,
        created_at TEXT NOT NULL
      )`,
      // ---- settings & backups ----
      `CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT,
        updated_at TEXT NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS backups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        path TEXT NOT NULL,
        size INTEGER,
        sha256 TEXT,
        created_at TEXT NOT NULL
      )`,
      // ---- append-only enforcement ----
      `CREATE TRIGGER IF NOT EXISTS trg_audit_log_no_update
        BEFORE UPDATE ON audit_log
        BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END`,
      `CREATE TRIGGER IF NOT EXISTS trg_audit_log_no_delete
        BEFORE DELETE ON audit_log
        BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END`,
      `CREATE TRIGGER IF NOT EXISTS trg_finding_state_history_no_update
        BEFORE UPDATE ON finding_state_history
        BEGIN SELECT RAISE(ABORT, 'finding_state_history is append-only'); END`,
      `CREATE TRIGGER IF NOT EXISTS trg_finding_state_history_no_delete
        BEFORE DELETE ON finding_state_history
        BEGIN SELECT RAISE(ABORT, 'finding_state_history is append-only'); END`,
      // projection updates append history automatically
      `CREATE TRIGGER IF NOT EXISTS trg_finding_states_history_insert
        AFTER UPDATE OF state ON finding_states
        BEGIN
          INSERT INTO finding_state_history
            (finding_state_id, actor, changed_at, from_state, to_state, justification, assignee, due_date)
          VALUES
            (NEW.id, NEW.assignee, strftime('%Y-%m-%dT%H:%M:%fZ','now'), OLD.state, NEW.state, NULL, NEW.assignee, NEW.due_date);
        END`,
      // retired locations must not receive new issuances
      `CREATE TRIGGER IF NOT EXISTS trg_issuances_no_retired_location
        BEFORE INSERT ON issuances
        WHEN NEW.location_id IN (SELECT id FROM locations WHERE retired_at IS NOT NULL)
        BEGIN SELECT RAISE(ABORT, 'cannot issue for a retired location'); END`,
      // legacy v1 routing: key_id unique only for marked legacy records
      `CREATE UNIQUE INDEX IF NOT EXISTS idx_issuances_key_id_legacy_v1
        ON issuances(key_id) WHERE is_legacy_v1 = 1`,
      // ---- indexes: every FK + query paths ----
      `CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)`,
      `CREATE INDEX IF NOT EXISTS idx_tokens_user ON tokens(user_id)`,
      `CREATE INDEX IF NOT EXISTS idx_comments_report ON comments(report_id)`,
      `CREATE INDEX IF NOT EXISTS idx_comments_host ON comments(host_id)`,
      `CREATE INDEX IF NOT EXISTS idx_comments_author ON comments(author_id)`,
      `CREATE INDEX IF NOT EXISTS idx_locations_campaign ON locations(campaign_id)`,
      `CREATE INDEX IF NOT EXISTS idx_issuances_campaign ON issuances(campaign_id)`,
      `CREATE INDEX IF NOT EXISTS idx_issuances_location ON issuances(location_id)`,
      `CREATE INDEX IF NOT EXISTS idx_issuances_extractor ON issuances(extractor_id)`,
      `CREATE INDEX IF NOT EXISTS idx_host_locations_location ON host_locations(location_id)`,
      `CREATE INDEX IF NOT EXISTS idx_reports_issuance ON reports(issuance_id)`,
      `CREATE INDEX IF NOT EXISTS idx_reports_host ON reports(host_id)`,
      `CREATE INDEX IF NOT EXISTS idx_reports_location ON reports(location_id)`,
      `CREATE INDEX IF NOT EXISTS idx_reports_campaign ON reports(campaign_id)`,
      `CREATE INDEX IF NOT EXISTS idx_reports_campaign_time ON reports(campaign_id, received_at)`,
      `CREATE INDEX IF NOT EXISTS idx_reports_host_time ON reports(host_id, received_at)`,
      `CREATE INDEX IF NOT EXISTS idx_ingest_events_report ON ingest_events(report_id)`,
      `CREATE INDEX IF NOT EXISTS idx_ingest_events_issuance ON ingest_events(issuance_id)`,
      `CREATE INDEX IF NOT EXISTS idx_ingest_events_status_time ON ingest_events(accepted, received_at)`,
      `CREATE INDEX IF NOT EXISTS idx_finding_states_report ON finding_states(report_id)`,
      `CREATE INDEX IF NOT EXISTS idx_finding_states_check ON finding_states(check_id)`,
      `CREATE INDEX IF NOT EXISTS idx_finding_states_state ON finding_states(state)`,
      `CREATE INDEX IF NOT EXISTS idx_finding_state_history_state ON finding_state_history(finding_state_id)`,
      `CREATE INDEX IF NOT EXISTS idx_saved_views_owner ON saved_views(owner_id)`,
      `CREATE INDEX IF NOT EXISTS idx_saved_views_campaign ON saved_views(campaign_id)`,
      `CREATE INDEX IF NOT EXISTS idx_hosts_last_seen ON hosts(last_seen_at)`,
      `CREATE INDEX IF NOT EXISTS idx_audit_log_time ON audit_log(created_at)`,
      `CREATE INDEX IF NOT EXISTS idx_backups_created ON backups(created_at)`,
    ],
  },
  {
    version: 2,
    up: [
      `INSERT OR IGNORE INTO settings (key, value, updated_at)
         VALUES ('retention_days', '365', strftime('%Y-%m-%dT%H:%M:%fZ','now'))`,
      `INSERT OR IGNORE INTO settings (key, value, updated_at)
         VALUES ('freshness_sla_hours', '24', strftime('%Y-%m-%dT%H:%M:%fZ','now'))`,
    ],
  },
  {
    // Network device / firewall configuration review (uploads).
    // Mirrors the host model: stable device identity, per-location presence,
    // one row per uploaded config version, and a treatment projection for
    // configuration-review findings with append-only history.
    version: 3,
    up: [
      `CREATE TABLE IF NOT EXISTS network_devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_key TEXT NOT NULL UNIQUE,
        hostname TEXT,
        vendor TEXT NOT NULL,
        device_type TEXT,
        model TEXT,
        os_version TEXT,
        serial TEXT,
        first_seen_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS network_device_locations (
        device_id INTEGER NOT NULL REFERENCES network_devices(id),
        location_id INTEGER NOT NULL REFERENCES locations(id),
        first_seen_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        PRIMARY KEY (device_id, location_id)
      )`,
      `CREATE TABLE IF NOT EXISTS network_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER NOT NULL REFERENCES network_devices(id),
        location_id INTEGER NOT NULL REFERENCES locations(id),
        campaign_id INTEGER NOT NULL REFERENCES campaigns(id),
        config_name TEXT NOT NULL,
        config_sha256 TEXT NOT NULL,
        config_size INTEGER NOT NULL,
        config_text TEXT NOT NULL,
        parsed_json TEXT NOT NULL,
        findings_json TEXT NOT NULL,
        summary_json TEXT,
        score REAL,
        received_at TEXT NOT NULL,
        uploaded_by TEXT,
        UNIQUE (device_id, location_id, config_sha256)
      )`,
      `CREATE TABLE IF NOT EXISTS network_finding_states (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        report_id INTEGER NOT NULL REFERENCES network_reports(id),
        check_id TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'open'
          CHECK (state IN ('open','accepted_risk','false_positive','remediated')),
        assignee TEXT,
        due_date TEXT,
        updated_at TEXT NOT NULL,
        UNIQUE (report_id, check_id)
      )`,
      `CREATE TABLE IF NOT EXISTS network_finding_state_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_state_id INTEGER NOT NULL REFERENCES network_finding_states(id),
        actor TEXT,
        changed_at TEXT NOT NULL,
        from_state TEXT,
        to_state TEXT NOT NULL,
        justification TEXT,
        assignee TEXT,
        due_date TEXT
      )`,
      // append-only enforcement for the network treatment history: updates are
      // rejected outright. Row deletion stays possible only for the device
      // cascade delete, which removes the whole treatment lineage.
      `CREATE TRIGGER IF NOT EXISTS trg_network_finding_state_history_no_update
        BEFORE UPDATE ON network_finding_state_history
        BEGIN SELECT RAISE(ABORT, 'network_finding_state_history is append-only'); END`,
      // projection updates append history automatically
      `CREATE TRIGGER IF NOT EXISTS trg_network_finding_states_history_insert
        AFTER UPDATE OF state ON network_finding_states
        BEGIN
          INSERT INTO network_finding_state_history
            (finding_state_id, actor, changed_at, from_state, to_state, justification, assignee, due_date)
          VALUES
            (NEW.id, NEW.assignee, strftime('%Y-%m-%dT%H:%M:%fZ','now'), OLD.state, NEW.state, NULL, NEW.assignee, NEW.due_date);
        END`,
      `CREATE INDEX IF NOT EXISTS idx_network_device_locations_location ON network_device_locations(location_id)`,
      `CREATE INDEX IF NOT EXISTS idx_network_reports_device ON network_reports(device_id)`,
      `CREATE INDEX IF NOT EXISTS idx_network_reports_location ON network_reports(location_id)`,
      `CREATE INDEX IF NOT EXISTS idx_network_reports_campaign ON network_reports(campaign_id)`,
      `CREATE INDEX IF NOT EXISTS idx_network_reports_device_time ON network_reports(device_id, received_at)`,
      `CREATE INDEX IF NOT EXISTS idx_network_finding_states_report ON network_finding_states(report_id)`,
      `CREATE INDEX IF NOT EXISTS idx_network_finding_states_state ON network_finding_states(state)`,
      `CREATE INDEX IF NOT EXISTS idx_network_finding_state_history_state ON network_finding_state_history(finding_state_id)`,
    ],
  },
  {
    // Webhook notification settings. v1 already created a scalar
    // `settings(key, value, updated_at)` table that reports.ts still reads
    // (`value` for retention/freshness), so v4 extends it in place with a JSON
    // payload + actor column instead of recreating it. Notification config
    // lives under the `notifications.webhook` key; legacy scalar rows are
    // untouched (their `value_json` defaults to `{}`).
    version: 4,
    up: [
      `ALTER TABLE settings ADD COLUMN value_json TEXT NOT NULL DEFAULT '{}'`,
      `ALTER TABLE settings ADD COLUMN updated_by TEXT`,
    ],
  },
  {
    // Per-campaign access restriction. NULL or an empty array means
    // "unrestricted"; otherwise the user only sees the listed campaigns.
    version: 5,
    up: [`ALTER TABLE users ADD COLUMN allowed_campaigns TEXT`],
  },
];

export const SCHEMA_VERSION = MIGRATIONS[MIGRATIONS.length - 1].version;

export function openDb(path: string): Database {
  // SQLite will not create missing parent directories; do it up front so
  // on-disk databases (and restored backups) work without extra setup.
  if (path !== ":memory:" && !path.startsWith("file:")) {
    const parent = dirname(path);
    if (parent && parent !== ".") mkdirSync(parent, { recursive: true });
  }
  const db = new Database(path);
  db.run("PRAGMA foreign_keys = ON");
  return db;
}

/** Runs pending migrations. Each migration is applied inside one transaction and
 *  recorded in the `migrations` table, so reruns are no-ops (idempotent). Returns
 *  the resulting schema version. */
export function runMigrations(db: Database, opts: MigrationOptions = {}): number {
  db.run(`CREATE TABLE IF NOT EXISTS migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
  )`);
  const appliedRows = db.query("SELECT version FROM migrations").all() as { version: number }[];
  const applied = new Set(appliedRows.map((r) => r.version));
  const target = opts.to ?? SCHEMA_VERSION;

  for (const migration of MIGRATIONS) {
    if (migration.version > target || applied.has(migration.version)) continue;
    db.run("BEGIN");
    try {
      let step = 0;
      for (const statement of migration.up) {
        opts.beforeStep?.(migration.version, step);
        db.run(statement);
        step++;
      }
      db.query("INSERT INTO migrations (version, applied_at) VALUES (?, ?)").run(
        migration.version,
        new Date().toISOString(),
      );
      db.run("COMMIT");
    } catch (err) {
      db.run("ROLLBACK");
      throw new Error(`migration ${migration.version} failed and was rolled back: ${(err as Error).message}`);
    }
  }
  return schemaVersion(db);
}

export function schemaVersion(db: Database): number {
  const hasMigrations = db
    .query("SELECT 1 FROM sqlite_master WHERE type='table' AND name='migrations'")
    .get();
  if (!hasMigrations) return 0;
  const rows = db.query("SELECT COALESCE(MAX(version), 0) AS v FROM migrations").all() as { v: number }[];
  return rows[0]?.v ?? 0;
}
