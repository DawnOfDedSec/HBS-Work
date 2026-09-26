import { afterEach, describe, expect, it } from "bun:test";
import type { Database } from "bun:sqlite";
import { openDb, runMigrations } from "./db";
import {
  DEFAULT_SETTINGS,
  getNotificationSettings,
  notifyFindings,
  saveNotificationSettings,
  severityAtLeast,
} from "./notifications";

const servers: { stop: (force?: boolean) => void | Promise<void> }[] = [];
afterEach(async () => {
  for (const server of servers.splice(0)) await server.stop(true);
});

function makeDb(): Database {
  const db = openDb(":memory:");
  runMigrations(db);
  return db;
}

function startReceiver(): {
  url: string;
  hits: { path: string; body: Record<string, unknown> }[];
} {
  const hits: { path: string; body: Record<string, unknown> }[] = [];
  const server = Bun.serve({
    port: 0,
    fetch: async (req) => {
      let body: Record<string, unknown> = {};
      try {
        body = (await req.json()) as Record<string, unknown>;
      } catch {
        body = {};
      }
      hits.push({ path: new URL(req.url).pathname, body });
      return new Response("ok", { status: 200 });
    },
  });
  servers.push(server);
  return { url: `http://127.0.0.1:${server.port}/hook`, hits };
}

describe("notification settings", () => {
  it("returns defaults when nothing is stored", () => {
    const db = makeDb();
    expect(getNotificationSettings(db)).toEqual(DEFAULT_SETTINGS);
    db.close();
  });

  it("round-trips saved settings", () => {
    const db = makeDb();
    const saved = saveNotificationSettings(
      db,
      { enabled: true, url: "https://example.test/hook", minSeverity: "High" },
      "root",
    );
    expect(saved).toEqual({
      enabled: true,
      url: "https://example.test/hook",
      minSeverity: "High",
      lastFiredAt: null,
    });
    expect(getNotificationSettings(db)).toEqual(saved);

    const row = db
      .query("SELECT value_json, updated_by FROM settings WHERE key = 'notifications.webhook'")
      .get() as { value_json: string; updated_by: string | null };
    expect(row.updated_by).toBe("root");
    expect(JSON.parse(row.value_json)).toEqual(saved);
    db.close();
  });

  it("rejects an invalid webhook url", () => {
    const db = makeDb();
    expect(() =>
      saveNotificationSettings(db, { enabled: true, url: "ftp://example.test", minSeverity: "Critical" }, "root"),
    ).toThrow("invalid webhook url");
    expect(() =>
      saveNotificationSettings(db, { enabled: true, url: "", minSeverity: "Critical" }, "root"),
    ).toThrow("invalid webhook url");
    expect(() =>
      saveNotificationSettings(
        db,
        { enabled: true, url: `https://example.test/${"a".repeat(2048)}`, minSeverity: "Critical" },
        "root",
      ),
    ).toThrow("invalid webhook url");
    expect(getNotificationSettings(db)).toEqual(DEFAULT_SETTINGS);
    db.close();
  });

  it("ranks severities from Critical down to Informational", () => {
    expect(severityAtLeast("Critical", "High")).toBeTrue();
    expect(severityAtLeast("High", "Critical")).toBeFalse();
    expect(severityAtLeast("Medium", "High")).toBeFalse();
    expect(severityAtLeast("Bogus", "Critical")).toBeFalse();
  });
});

describe("notifyFindings", () => {
  it("posts a webhook and records the audit row when critical findings meet the threshold", async () => {
    const db = makeDb();
    const receiver = startReceiver();
    saveNotificationSettings(db, { enabled: true, url: receiver.url, minSeverity: "Critical" }, "root");

    await notifyFindings(db, {
      source: "host",
      reportId: 7,
      campaignId: 3,
      locationId: 5,
      label: "host-alpha",
      findings: [
        { checkId: "LIN-001", severity: "Critical", title: "Kernel hardening missing" },
        { checkId: "LIN-002", severity: "High", title: "Audit logging thin" },
        { checkId: "LIN-003", severity: "Medium", title: "Password policy weak" },
      ],
    });

    expect(receiver.hits.length).toBe(1);
    expect(receiver.hits[0]?.path).toBe("/hook");
    const body = receiver.hits[0]?.body ?? {};
    expect(body.event).toBe("critical-findings");
    expect(body.source).toBe("host");
    expect(body.reportId).toBe(7);
    expect(body.campaignId).toBe(3);
    expect(body.locationId).toBe(5);
    expect(body.label).toBe("host-alpha");
    expect(body.severities).toEqual(["Critical"]);
    expect(body.findings).toEqual([
      { checkId: "LIN-001", severity: "Critical", title: "Kernel hardening missing" },
    ]);

    const audit = db
      .query("SELECT actor, action, resource, details FROM audit_log WHERE action = 'notification.webhook'")
      .get() as { actor: string; action: string; resource: string; details: string } | null;
    expect(audit?.actor).toBe("system");
    expect(audit?.resource).toBe("report:7");
    expect(JSON.parse(audit?.details ?? "{}")).toEqual({ ok: true, status: 200, source: "host" });

    expect(getNotificationSettings(db).lastFiredAt).not.toBeNull();
    db.close();
  });

  it("does not fire when disabled", async () => {
    const db = makeDb();
    const receiver = startReceiver();
    saveNotificationSettings(db, { enabled: false, url: receiver.url, minSeverity: "Critical" }, "root");

    await notifyFindings(db, {
      source: "host",
      reportId: 8,
      campaignId: null,
      locationId: null,
      label: "host-beta",
      findings: [{ checkId: "LIN-001", severity: "Critical", title: "critical" }],
    });

    expect(receiver.hits.length).toBe(0);
    const count = db
      .query("SELECT COUNT(*) AS count FROM audit_log WHERE action = 'notification.webhook'")
      .get() as { count: number };
    expect(count.count).toBe(0);
    expect(getNotificationSettings(db).lastFiredAt).toBeNull();
    db.close();
  });

  it("does not fire when no finding meets the minimum severity", async () => {
    const db = makeDb();
    const receiver = startReceiver();
    saveNotificationSettings(db, { enabled: true, url: receiver.url, minSeverity: "Critical" }, "root");

    await notifyFindings(db, {
      source: "host",
      reportId: 9,
      campaignId: 1,
      locationId: 1,
      label: "host-gamma",
      findings: [
        { checkId: "LIN-A", severity: "High", title: "high" },
        { checkId: "LIN-B", severity: "Medium", title: "medium" },
        { checkId: "LIN-C", severity: "Informational", title: "info" },
      ],
    });

    expect(receiver.hits.length).toBe(0);
    const count = db
      .query("SELECT COUNT(*) AS count FROM audit_log WHERE action = 'notification.webhook'")
      .get() as { count: number };
    expect(count.count).toBe(0);
    db.close();
  });
});
