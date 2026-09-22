import type { Database } from "bun:sqlite";
import type { Hono, MiddlewareHandler } from "hono";
import { createEncryptedBackup, restoreEncryptedBackup } from "./keys";
import { redactDiagnosticText } from "./reports";

// Admin-only endpoints backing the Admin workspace (plan Task 56): the
// append-only audit trail, per-finding treatment history, and encrypted
// backup/restore. All require super_admin.

export type AdminAuth = { requireRole: (...roles: string[]) => MiddlewareHandler };

export type AdminOptions = {
  dataRoot?: string;
  /** Live SQLite path; used only to stage a validated restore for the operator. */
  databasePath?: string;
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
