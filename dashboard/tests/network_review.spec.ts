import { expect, request, test, type APIRequestContext } from "@playwright/test";
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Network device / firewall configuration review: full upload → review →
// device listing → device/report detail → treatment → device deletion flow
// against a real dashboard server with an in-memory database.
//
// If the server cannot start, the tests skip rather than block.

test.describe.configure({ mode: "serial" });

const PORT = Number(process.env.HBS_NETWORK_PORT ?? 34571);
const BASE = `http://127.0.0.1:${PORT}`;
const USER = "admin";
const PASSWORD = "network-test-password";

const CISCO_IOS_SWITCH = `
version 15.2
service timestamps log datetime msec
hostname CORE-SW-01
enable secret 5 $1$AbCd$EfGhIjKlMnOpQrStUvWxw0
username backup password 7 08224F40081A0A0602
ip ssh version 2
snmp-server community public RW
logging host 10.10.0.20
line vty 0 4
 exec-timeout 10 0
 transport input telnet
end
`.trim();

let server: ChildProcess | undefined;
let api: APIRequestContext | undefined;

function resolveBun(): string {
  if (process.env.BUN_BINARY) return process.env.BUN_BINARY;
  const candidates = [
    join(process.env.APPDATA ?? "", "npm", "node_modules", "bun", "bin", "bun.exe"),
    join(process.env.HOME ?? process.env.USERPROFILE ?? "", ".bun", "bin", "bun"),
  ];
  for (const candidate of candidates) {
    if (candidate && existsSync(candidate)) return candidate;
  }
  return process.platform === "win32" ? "bun.exe" : "bun";
}

async function waitForHealth(timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${BASE}/api/health`);
      if (response.ok) return true;
    } catch {
      // server not up yet
    }
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  return false;
}

test.beforeAll(async () => {
  try {
    server = spawn(resolveBun(), ["run", "server/index.ts"], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        PORT: String(PORT),
        HOST: "127.0.0.1",
        HBS_DB_PATH: ":memory:",
        HBS_DATA_ROOT: mkdtempSync(join(tmpdir(), "hbs-network-")),
        // The spec provisions its own superuser via /api/auth/setup; the
        // first-run bootstrap admin would make setup return 409.
        HBS_BOOTSTRAP_ADMIN: "false",
      },
      stdio: "ignore",
    });
    server.on("error", () => {
      server = undefined;
    });
    await new Promise((resolve) => setTimeout(resolve, 300));
    if (!server) return;
    if (!(await waitForHealth(20_000))) return;
    api = await request.newContext({ baseURL: BASE });
    const status = (await (await api.get("/api/auth/status")).json()) as { initialized?: boolean };
    if (!status.initialized) {
      const created = await api.post("/api/auth/setup", { data: { username: USER, password: PASSWORD } });
      expect(created.status()).toBe(201);
    } else {
      const loggedIn = await api.post("/api/auth/login", { data: { username: USER, password: PASSWORD } });
      expect(loggedIn.ok()).toBeTruthy();
    }
  } catch {
    api = undefined;
  }
});

test.afterAll(async () => {
  await api?.dispose();
  server?.kill();
});

function requireApi(): APIRequestContext {
  test.skip(!api, "dashboard server unavailable");
  return api as APIRequestContext;
}

async function seedCampaign(context: APIRequestContext): Promise<{ campaignId: number; locationId: number }> {
  const created = await context.post("/api/campaigns", {
    data: {
      name: `Network Campaign ${Date.now()}`,
      locations: [{ name: `DC-Network ${Date.now()}`, tags: ["core"] }],
    },
  });
  expect(created.status()).toBe(201);
  const body = (await created.json()) as { id: number; locations: Array<{ id: number }> };
  return { campaignId: body.id, locationId: body.locations[0].id };
}

let shared: { campaignId: number; locationId: number; deviceId: number; reportId: number } | null = null;

test("upload reviews a config and posts the device alongside the location", async () => {
  const context = requireApi();
  const target = await seedCampaign(context);

  const form = new FormData();
  form.append("campaignId", String(target.campaignId));
  form.append("locationId", String(target.locationId));
  form.append("files", new File([CISCO_IOS_SWITCH], "core-sw.cfg"));
  const uploaded = await context.post("/api/network/upload", { multipart: form });
  expect(uploaded.status()).toBe(200);
  const body = (await uploaded.json()) as {
    results: Array<{ name: string; result: { ok: boolean; deviceId: number; reportId: number; hostname: string | null; vendorLabel: string; score: number; findings: { critical: number; high: number } } }>;
  };
  const result = body.results[0]?.result;
  expect(result?.ok).toBe(true);
  expect(result?.hostname).toBe("CORE-SW-01");
  expect(result?.findings.critical + result?.findings.high).toBeGreaterThan(0);

  shared = { ...target, deviceId: result.deviceId, reportId: result.reportId };

  // The reviewed device appears in the location listing the Locations page uses.
  const listed = await context.get(`/api/network/devices?locationId=${target.locationId}`);
  expect(listed.status()).toBe(200);
  const devices = (await listed.json()) as { devices: Array<{ id: number; hostname: string | null; score: number | null }> };
  expect(devices.devices.some((device) => device.id === result.deviceId && device.hostname === "CORE-SW-01")).toBe(true);

  // The rule catalog is exposed for tooling and the UI legend.
  const rules = await context.get("/api/network/rules");
  expect(rules.status()).toBe(200);
  const rulesBody = (await rules.json()) as { total: number; rules: Array<{ id: string }> };
  expect(rulesBody.total).toBeGreaterThanOrEqual(46);
  expect(rulesBody.rules.some((rule) => rule.id === "NET-LIFE-001")).toBe(true);

  // Network findings are merged into the global findings explorer.
  const merged = await context.get("/api/findings?source=network");
  expect(merged.status()).toBe(200);
  const mergedBody = (await merged.json()) as { total: number; results: Array<{ source: string; checkId: string }> };
  expect(mergedBody.total).toBeGreaterThan(0);
  expect(mergedBody.results.every((row) => row.source === "network")).toBe(true);

  const hostOnly = await context.get("/api/findings?source=host");
  const hostBody = (await hostOnly.json()) as { total: number; results: Array<{ source: string }> };
  expect(hostBody.results.every((row) => row.source === "host")).toBe(true);
});

test("device diff detects fixes between two uploads of the same device", async () => {
  const context = requireApi();
  test.skip(!shared, "upload step did not run");
  const target = shared as { campaignId: number; locationId: number; deviceId: number; reportId: number };

  const hardened = CISCO_IOS_SWITCH
    .replace("transport input telnet", "transport input ssh")
    .replace("snmp-server community public RW", "snmp-server community public RO");
  const form = new FormData();
  form.append("campaignId", String(target.campaignId));
  form.append("locationId", String(target.locationId));
  form.append("files", new File([hardened], "core-sw.cfg"));
  const uploaded = await context.post("/api/network/upload", { multipart: form });
  expect(uploaded.status()).toBe(200);
  const body = (await uploaded.json()) as { results: Array<{ result: { ok: boolean; deviceId: number; reportId: number } }> };
  expect(body.results[0].result.ok).toBe(true);
  expect(body.results[0].result.deviceId).toBe(target.deviceId);

  const diff = await context.get(`/api/network/devices/${target.deviceId}/diff`);
  expect(diff.status()).toBe(200);
  const diffBody = (await diff.json()) as {
    from: { reportId: number; score: number | null };
    to: { reportId: number; score: number | null };
    fixed: Array<{ checkId: string }>;
    regressed: Array<{ checkId: string }>;
    unchangedCount: number;
  };
  expect(diffBody.from.reportId).toBe(target.reportId);
  expect(diffBody.fixed.some((entry) => entry.checkId === "NET-MGMT-001")).toBe(true);
  expect(diffBody.fixed.some((entry) => entry.checkId === "NET-SNMP-003")).toBe(true);
  expect(diffBody.regressed).toHaveLength(0);
  expect(diffBody.to.score ?? 0).toBeGreaterThan(diffBody.from.score ?? 0);
});

test("bulk treatment applies one justification to many findings", async () => {
  const context = requireApi();
  test.skip(!shared, "upload step did not run");
  const target = shared as { campaignId: number; locationId: number; deviceId: number; reportId: number };

  const missing = await context.post(`/api/network/reports/${target.reportId}/findings/treatment-bulk`, {
    data: { checkIds: ["NET-SNMP-001"], state: "false_positive" },
  });
  expect(missing.status()).toBe(400);

  const bulk = await context.post(`/api/network/reports/${target.reportId}/findings/treatment-bulk`, {
    data: {
      checkIds: ["NET-SNMP-001", "NET-MGMT-001", "NET-FAKE-001"],
      state: "false_positive",
      justification: "Verified as scanner noise by netops.",
    },
  });
  expect(bulk.status()).toBe(200);
  const bulkBody = (await bulk.json()) as {
    applied: Array<{ checkId: string }>;
    skipped: Array<{ checkId: string; reason: string }>;
  };
  expect(bulkBody.applied).toHaveLength(2);
  expect(bulkBody.skipped).toHaveLength(1);
  expect(bulkBody.skipped[0].reason).toBe("NOT_IN_REPORT");
});

test("exports review findings as xlsx and csv", async () => {
  const context = requireApi();
  test.skip(!shared, "upload step did not run");
  const target = shared as { campaignId: number; locationId: number; deviceId: number; reportId: number };

  const xlsx = await context.get(`/api/network/reports/${target.reportId}/export?format=xlsx`);
  expect(xlsx.status()).toBe(200);
  expect(xlsx.headers()["content-type"]).toContain("spreadsheetml");

  const csv = await context.get(`/api/network/devices/${target.deviceId}/export?format=csv`);
  expect(csv.status()).toBe(200);
  expect(await csv.text()).toContain("NET-MGMT-001");

  expect((await context.get(`/api/network/reports/${target.reportId}/export?format=pdf`)).status()).toBe(400);
});

test("device detail exposes findings; report detail redacts secrets", async () => {
  const context = requireApi();
  test.skip(!shared, "upload step did not run");
  const target = shared as { campaignId: number; locationId: number; deviceId: number; reportId: number };

  const detail = await context.get(`/api/network/devices/${target.deviceId}`);
  expect(detail.status()).toBe(200);
  const deviceBody = (await detail.json()) as {
    device: { hostname: string | null };
    reports: Array<{ id: number }>;
    latest: { findings: Array<{ checkId: string; status: string }> } | null;
  };
  expect(deviceBody.device.hostname).toBe("CORE-SW-01");
  // The diff test uploaded a hardened variant, so the device now has both.
  expect(deviceBody.reports.length).toBe(2);

  // The original weak report still fails the telnet check.
  const report = await context.get(`/api/network/reports/${target.reportId}`);
  expect(report.status()).toBe(200);
  const reportBody = (await report.json()) as { configText: string; findings: Array<{ checkId: string; status: string }> };
  const mgmt = reportBody.findings.find((finding) => finding.checkId === "NET-MGMT-001");
  expect(mgmt?.status).toBe("NonCompliant");
  expect(reportBody.configText).toContain("hostname CORE-SW-01");
  expect(reportBody.configText).not.toContain("08224F40081A0A0602");
  expect(reportBody.findings.length).toBeGreaterThanOrEqual(40);
});

test("treatment workflow updates a finding and is readable via history", async () => {
  const context = requireApi();
  test.skip(!shared, "upload step did not run");
  const target = shared as { campaignId: number; locationId: number; deviceId: number; reportId: number };

  const rejected = await context.post(`/api/network/reports/${target.reportId}/findings/NET-SNMP-001/treatment`, {
    data: { state: "accepted_risk" },
  });
  expect(rejected.status()).toBe(400);

  const accepted = await context.post(`/api/network/reports/${target.reportId}/findings/NET-SNMP-001/treatment`, {
    data: { state: "accepted_risk", justification: "Legacy NMS depends on v2c.", assignee: "netops" },
  });
  expect(accepted.status()).toBe(200);

  const report = await context.get(`/api/network/reports/${target.reportId}`);
  const reportBody = (await report.json()) as { findings: Array<{ checkId: string; treatmentState: string }> };
  expect(reportBody.findings.find((finding) => finding.checkId === "NET-SNMP-001")?.treatmentState).toBe("accepted_risk");

  const history = await context.get(`/api/network/reports/${target.reportId}/findings/NET-SNMP-001/history`);
  expect(history.status()).toBe(200);
  const historyBody = (await history.json()) as { history: Array<{ toState: string; fromState: string | null }> };
  expect(historyBody.history.length).toBeGreaterThanOrEqual(2);
  expect(historyBody.history.at(-1)?.toState).toBe("accepted_risk");
});

test("super_admin deletes the device and its treatment lineage", async () => {
  const context = requireApi();
  test.skip(!shared, "upload step did not run");
  const target = shared as { campaignId: number; locationId: number; deviceId: number; reportId: number };

  const deleted = await context.delete(`/api/network/devices/${target.deviceId}`);
  expect(deleted.status()).toBe(200);
  expect(((await deleted.json()) as { deleted: boolean }).deleted).toBe(true);

  const gone = await context.get(`/api/network/devices/${target.deviceId}`);
  expect(gone.status()).toBe(404);
  shared = null;
});
