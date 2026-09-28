import type { Database } from "bun:sqlite";
import type { Hono, MiddlewareHandler } from "hono";
import { createEncryptedBackup, restoreEncryptedBackup } from "./keys";
import { getNotificationSettings, saveNotificationSettings, type MinSeverity } from "./notifications";
import { redactDiagnosticText } from "./reports";
import {
  configPath,
  effectiveFromEnv,
  loadHostingSettings,
  saveHostingSettings,
  settingsFingerprint,
  type HostingInput,
} from "./config-store";
import { isExposed } from "./options";

// Admin-only endpoints backing the Admin workspace (plan Task 56): the
// append-only audit trail, per-finding treatment history, encrypted
// backup/restore, and the sealed hosting settings. All require super_admin.

export type AdminAuth = { requireRole: (...roles: string[]) => MiddlewareHandler };

/** The settings the running process actually bound to, plus derived flags. */
export type EffectiveSettings = HostingInput & { tls: boolean; exposed: boolean };

export type AdminOptions = {
  dataRoot?: string;
  /** Live SQLite path; used only to stage a validated restore for the operator. */
  databasePath?: string;
  /** Environment the config store reads (defaults to process.env). */
  env?: Record<string, string | undefined>;
  /** Runtime host/port/TLS, so the API can say whether a restart is pending. */
  effective?: EffectiveSettings;
};

type AuditRow = {
  id: number;
  actor: string | null;
  actor_ip: string | null;
  action: string;
  resource: string | null;
  details: string | null;
  created_at: string;
};

function positiveInt(value: string | undefined, fallback: number, max: number): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) return fallback;
  return Math.min(parsed, max);
}

function actorOf(c: { get(name: string): unknown }): string {
  const user = c.get("user") as { username?: string } | undefined;
  return user?.username ?? "unknown";
}

/** Runtime binding, derived from env when the caller did not supply it. */
function effectiveOf(opts: AdminOptions): EffectiveSettings {
  if (opts.effective) return opts.effective;
  const base = effectiveFromEnv(opts.env ?? process.env);
  return {
    host: base.host,
    port: base.port,
    tlsCert: base.tlsCert,
    tlsKey: base.tlsKey,
    tls: !!base.tlsCert,
    exposed: isExposed(base.host),
  };
}

/** Sealed config status: a tampered file is surfaced, never applied. */
function storageOf(env: Record<string, string | undefined>) {
  const loaded = loadHostingSettings(env);
  const storage: Record<string, unknown> = {
    path: configPath(env),
    encrypted: true,
    status: loaded.status,
  };
  if (loaded.status === "tampered" || loaded.status === "error") storage.error = loaded.error;
  return storage;
}

export function registerAdminRoutes(
  app: Hono<any>,
  db: Database,
  auth: AdminAuth,
  opts: AdminOptions = {},
): void {
  const dataRoot = opts.dataRoot ?? process.env.HBS_DATA_ROOT ?? "server/data";
  const superAdmin = auth.requireRole("super_admin");

  app.get("/api/admin/audit", superAdmin, (c) => {
    const limit = positiveInt(c.req.query("limit"), 100, 500);
    const offset = positiveInt(c.req.query("offset"), 0, Number.MAX_SAFE_INTEGER);
    const action = c.req.query("action");
    const rows = (
      action
        ? db
            .query(
              `SELECT id, actor, actor_ip, action, resource, details, created_at
               FROM audit_log WHERE action = ? ORDER BY id DESC LIMIT ? OFFSET ?`,
            )
            .all(action, limit, offset)
        : db
            .query(
              `SELECT id, actor, actor_ip, action, resource, details, created_at
               FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?`,
            )
            .all(limit, offset)
    ) as AuditRow[];
    const total = (
      db.query(
        action
          ? "SELECT COUNT(*) AS count FROM audit_log WHERE action = ?"
          : "SELECT COUNT(*) AS count FROM audit_log",
      ).get(...(action ? [action] : [])) as { count: number }
    ).count;
    return c.json({
      total,
      limit,
      offset,
      events: rows.map((row) => ({
        id: row.id,
        actor: row.actor,
        actorIp: row.actor_ip,
        action: row.action,
        resource: row.resource,
        details: row.details ? redactDiagnosticText(row.details, 2000) : null,
        createdAt: row.created_at,
      })),
    });
  });

  app.get("/api/reports/:id/findings/:checkId/history", auth.requireRole("super_admin", "auditor", "viewer"), (c) => {
    const reportId = Number(c.req.param("id"));
    if (!Number.isSafeInteger(reportId) || reportId < 1) return c.json({ error: "invalid report id" }, 400);
    const checkId = c.req.param("checkId");
    const rows = db
      .query(
        `SELECT h.id, h.actor, h.changed_at, h.from_state, h.to_state, h.justification, h.assignee, h.due_date
         FROM finding_state_history h
         JOIN finding_states s ON s.id = h.finding_state_id
         WHERE s.report_id = ? AND s.check_id = ?
         ORDER BY h.id ASC`,
      )
      .all(reportId, checkId) as {
      id: number;
      actor: string | null;
      changed_at: string;
      from_state: string | null;
      to_state: string;
      justification: string | null;
      assignee: string | null;
      due_date: string | null;
    }[];
    return c.json({
      reportId,
      checkId,
      history: rows.map((row) => ({
        id: row.id,
        actor: row.actor,
        changedAt: row.changed_at,
        fromState: row.from_state,
        toState: row.to_state,
        justification: row.justification,
        assignee: row.assignee,
        dueDate: row.due_date,
      })),
    });
  });

  app.get("/api/admin/notifications/settings", superAdmin, (c) => {
    return c.json(getNotificationSettings(db));
  });

  app.put("/api/admin/notifications/settings", superAdmin, async (c) => {
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "expected JSON body" }, 400);
    }
    if (typeof body !== "object" || body === null || Array.isArray(body)) {
      return c.json({ error: "expected a JSON object" }, 400);
    }
    const input = body as Record<string, unknown>;
    const minSeverity: MinSeverity = input.minSeverity === "High" ? "High" : "Critical";
    let saved: ReturnType<typeof saveNotificationSettings>;
    try {
      saved = saveNotificationSettings(
        db,
        {
          enabled: input.enabled === true,
          url: typeof input.url === "string" ? input.url : "",
          minSeverity,
        },
        actorOf(c),
      );
    } catch (error) {
      return c.json({ error: (error as Error).message }, 400);
    }
    db.query(
      `INSERT INTO audit_log (actor, actor_ip, action, resource, details, created_at)
       VALUES (?, ?, 'notification.settings.update', 'settings:notifications.webhook', ?, ?)`,
    ).run(
      actorOf(c),
      c.req.header("x-forwarded-for") ?? null,
      JSON.stringify({ enabled: saved.enabled, url: saved.url, minSeverity: saved.minSeverity }),
      new Date().toISOString(),
    );
    return c.json(saved);
  });

  // --- hosting settings (sealed config) ------------------------------------
  // The installer writes hbs.env; from then on this sealed file is the source
  // of truth. Changing host/port/TLS needs a restart, so the response says so
  // and the UI shows the pending state until the process is restarted.
  app.get("/api/admin/settings", superAdmin, (c) => {
    const env = opts.env ?? process.env;
    const effective = effectiveOf(opts);
    const loaded = loadHostingSettings(env);
    const hosting = loaded.status === "ok" ? loaded.settings : effectiveFromEnv(env);
    return c.json({
      hosting,
      effective,
      restartRequired: settingsFingerprint(hosting) !== settingsFingerprint(effective),
      storage: storageOf(env),
    });
  });

  app.put("/api/admin/settings", superAdmin, async (c) => {
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "expected JSON body" }, 400);
    }
    const env = opts.env ?? process.env;
    const result = saveHostingSettings(body, env, actorOf(c));
    if (!result.ok) return c.json({ error: result.error }, 400);
    db.query(
      `INSERT INTO audit_log (actor, actor_ip, action, resource, details, created_at)
       VALUES (?, ?, 'settings.hosting.update', 'settings:hosting', ?, ?)`,
    ).run(
      actorOf(c),
      c.req.header("x-forwarded-for") ?? null,
      JSON.stringify({
        host: result.settings.host,
        port: result.settings.port,
        tls: !!result.settings.tlsCert,
      }),
      new Date().toISOString(),
    );
    const effective = effectiveOf(opts);
    return c.json({
      hosting: result.settings,
      effective,
      restartRequired: settingsFingerprint(result.settings) !== settingsFingerprint(effective),
      storage: { ...storageOf(env), envFile: result.envFile },
      message: "Saved. Restart HBS for the new host, port or TLS settings to take effect.",
    });
  });

  app.post("/api/admin/backup", superAdmin, async (c) => {
    let passphrase = "";
    try {
      const body = (await c.req.json()) as Record<string, unknown>;
      if (typeof body.passphrase === "string") passphrase = body.passphrase;
    } catch {
      return c.json({ error: "expected JSON body with a passphrase" }, 400);
    }
    if (passphrase.length < 12) return c.json({ error: "passphrase must be at least 12 characters" }, 400);
    try {
      const archive = createEncryptedBackup(db, passphrase, { dataRoot });
      db.query(
        `INSERT INTO audit_log (actor, actor_ip, action, resource, details, created_at)
         VALUES (?, ?, 'backup.create', 'backup', ?, ?)`,
      ).run(
        actorOf(c),
        c.req.header("x-forwarded-for") ?? null,
        JSON.stringify({ bytes: archive.length }),
        new Date().toISOString(),
      );
      const bytes = archive.buffer.slice(
        archive.byteOffset,
        archive.byteOffset + archive.byteLength,
      ) as ArrayBuffer;
      return c.body(bytes, 200, {
        "content-type": "application/octet-stream",
        "content-disposition": `attachment; filename="hbs-backup-${Date.now()}.hbsbak"`,
      });
    } catch (error) {
      return c.json({ error: (error as Error).message }, 400);
    }
  });

  app.post("/api/admin/backup/restore", superAdmin, async (c) => {
    const form = await c.req.formData().catch(() => null);
    if (!form) return c.json({ error: "expected multipart form data" }, 400);
    const passphrase = form.get("passphrase");
    const file = form.get("file");
    if (typeof passphrase !== "string" || passphrase.length < 12) {
      return c.json({ error: "passphrase must be at least 12 characters" }, 400);
    }
    if (!file || typeof file === "string") return c.json({ error: "backup file is required" }, 400);
    const bytes = new Uint8Array(await file.arrayBuffer());

    // Validate and decrypt into a staging file; never overwrite the live DB
    // while the server holds it open. The operator swaps and restarts.
    const databasePath = opts.databasePath;
    if (!databasePath) return c.json({ error: "restore target is not configured" }, 503);
    const staging = `${databasePath}.restore.${Date.now()}`;
    try {
      restoreEncryptedBackup(bytes, passphrase, { dataRoot, databasePath: staging });
    } catch (error) {
      return c.json({ error: `restore rejected: ${(error as Error).message}` }, 400);
    }
    db.query(
      `INSERT INTO audit_log (actor, actor_ip, action, resource, details, created_at)
       VALUES (?, ?, 'backup.restore.staged', 'backup', ?, ?)`,
    ).run(
      actorOf(c),
      c.req.header("x-forwarded-for") ?? null,
      JSON.stringify({ staged: true }),
      new Date().toISOString(),
    );
    return c.json({
      staged: true,
      message: "backup validated and staged; stop the server, replace the database file, and restart",
      stagingPath: staging,
    });
  });
}
