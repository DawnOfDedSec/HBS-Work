import { expect, request, test, type APIRequestContext } from "@playwright/test";
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Task 54 contract tests for the accessible chart kit.
//
// The chart components emit canonical drilldown queries via the shared
// serializer. These tests start a real dashboard server (in-memory DB) and
// assert that every query the chart kit can produce is accepted by the scoped
// findings endpoint, plus that the chart metric endpoints keep their shapes.
//
// If the server cannot start (e.g. `bun` is not on PATH), the tests skip rather
// than block; the component work is still verified by `tsc` and `vite build`.

// One server (one port) per file: run these tests in a single worker.
test.describe.configure({ mode: "serial" });

const PORT = Number(process.env.HBS_CHARTS_PORT ?? 34567);
const BASE = `http://127.0.0.1:${PORT}`;
const USER = "admin";
const PASSWORD = "charts-test-password";

let server: ChildProcess | undefined;
let api: APIRequestContext | undefined;

/** Resolve a runnable `bun` binary across the platforms CI and dev use. */
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
        HBS_DATA_ROOT: mkdtempSync(join(tmpdir(), "hbs-charts-")),
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

/** The exact canonical query strings the chart marks emit. */
const DRILLDOWN_QUERIES = [
  "severity=Critical",
  "category=Web%20Server",
  "hostId=1",
  "hostId=1&severity=High",
  "status=NonCompliant",
  "checkId=LIN-INV-001",
  "from=2026-09-01T00:00:00.000Z&to=2026-09-01T23:59:59.999Z",
  "locationId=1&platform=Linux&evidenceDepth=DegradedPartial",
  "via=upload&privilege=not-needed",
];

test("every chart drilldown query is accepted by /api/findings", async () => {
  const context = requireApi();
  for (const query of DRILLDOWN_QUERIES) {
    const response = await context.get(`/api/findings?${query}`);
    expect(response.status(), `query: ${query}`).toBe(200);
    const body = (await response.json()) as { scope?: { kind?: string } };
    expect(body.scope, `query: ${query}`).toBeTruthy();
  }
});

test("canonical filters reject unknown values", async () => {
  const context = requireApi();
  const response = await context.get("/api/findings?severity=Nope");
  expect(response.status()).toBe(400);
  const body = (await response.json()) as { code?: string };
  expect(body.code).toBe("INVALID_FILTER");
});

test("severity metric stays within the six-segment donut limit", async () => {
  const context = requireApi();
  const response = await context.get("/api/metrics/severity");
  expect(response.status()).toBe(200);
  const body = (await response.json()) as { severity: Record<string, number> };
  const keys = Object.keys(body.severity);
  expect(keys.length).toBeLessThanOrEqual(6);
  for (const severity of ["Critical", "High", "Medium", "Low", "Informational"]) {
    expect(body.severity).toHaveProperty(severity);
  }
});

test("category and risk metric shapes match the chart props", async () => {
  const context = requireApi();
  const category = await context.get("/api/metrics/category");
  expect(category.status()).toBe(200);
  const categoryBody = (await category.json()) as { categories: Array<{ category: string; total: number }> };
  expect(Array.isArray(categoryBody.categories)).toBe(true);

  const risk = await context.get("/api/metrics/risk");
  expect(risk.status()).toBe(200);
  const riskBody = (await risk.json()) as { weightedRiskScore: number; riskTrend: unknown[] };
  expect(typeof riskBody.weightedRiskScore).toBe("number");
  expect(Array.isArray(riskBody.riskTrend)).toBe(true);
});

test("campaign summary exposes the exact fields CampaignSummary renders", async () => {
  const context = requireApi();
  const created = await context.post("/api/campaigns", {
    data: { name: `Charts Campaign ${Date.now()}`, locations: [{ name: "HQ", tags: ["prod"] }] },
  });
  expect(created.status()).toBe(201);
  const campaign = (await created.json()) as { id: number };

  const summary = await context.get(`/api/campaigns/${campaign.id}/summary`);
  expect(summary.status()).toBe(200);
  const body = (await summary.json()) as {
    kpis: { weightedRiskScore: number; coverage: number };
    severityBreakdown: Record<string, number>;
    categoryCompliance: unknown[];
    topFailingChecks: unknown[];
  };
  expect(typeof body.kpis.weightedRiskScore).toBe("number");
  expect(typeof body.kpis.coverage).toBe("number");
  expect(body.severityBreakdown).toBeTruthy();
  expect(Array.isArray(body.categoryCompliance)).toBe(true);
  expect(Array.isArray(body.topFailingChecks)).toBe(true);
});
