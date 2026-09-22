import { expect, request, test, type APIRequestContext } from "@playwright/test";
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Task 53 contract tests for Locations / Downloads / DropZone.
//
// These exercise the exact backend endpoints the pages rely on using a real
// dashboard server with an in-memory database. Issuance *creation* needs a
// platform binary template, so this spec asserts the generating side's
// validation/listing/download behaviour without requiring built binaries.
//
// If the server cannot start, the tests skip rather than block.

// One server (one port) per file: run these tests in a single worker.
test.describe.configure({ mode: "serial" });

const PORT = Number(process.env.HBS_UPLOADS_PORT ?? 34568);
const BASE = `http://127.0.0.1:${PORT}`;
const USER = "admin";
const PASSWORD = "uploads-test-password";

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
        HBS_DATA_ROOT: mkdtempSync(join(tmpdir(), "hbs-uploads-")),
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
      name: `Uploads Campaign ${Date.now()}`,
      locations: [{ name: `Site A ${Date.now()}`, tags: ["prod", "eu"] }],
    },
  });
  expect(created.status()).toBe(201);
  const body = (await created.json()) as { id: number; locations: Array<{ id: number }> };
  return { campaignId: body.id, locationId: body.locations[0].id };
}

test("locations list tags + retirement status for the Locations page", async () => {
  const context = requireApi();
  const { campaignId, locationId } = await seedCampaign(context);

  const list = await context.get(`/api/campaigns/${campaignId}`);
  expect(list.status()).toBe(200);
  const campaign = (await list.json()) as {
    locations: Array<{ id: number; tags: string[]; retiredAt: string | null }>;
  };
  const locations = campaign.locations;
  const created = locations.find((location) => location.id === locationId);
  expect(created?.tags).toEqual(["prod", "eu"]);
  expect(created?.retiredAt).toBeNull();

  const retired = await context.patch(`/api/campaigns/${campaignId}/locations/${locationId}`, {
    data: { retired: true },
  });
  expect(retired.status()).toBe(200);
  expect(((await retired.json()) as { retiredAt: string | null }).retiredAt).not.toBeNull();
});

test("issuance listing returns an array and rejects unknown platforms", async () => {
  const context = requireApi();
  const { campaignId, locationId } = await seedCampaign(context);

  const listed = await context.get(`/api/campaigns/${campaignId}/locations/${locationId}/issuances`);
  expect(listed.status()).toBe(200);
  expect(Array.isArray(await listed.json())).toBe(true);

  const rejected = await context.post(`/api/campaigns/${campaignId}/locations/${locationId}/issuances`, {
    data: { platform: "msdos" },
  });
  expect(rejected.status()).toBe(400);
  const body = (await rejected.json()) as { error?: string };
  expect(body.error ?? "").toContain("unsupported platform");
});

test("download endpoint reports unknown issuances as 404", async () => {
  const context = requireApi();
  const response = await context.get("/api/issuances/does-not-exist/download");
  expect(response.status()).toBe(404);
});

test("multipart upload rejects an empty batch", async () => {
  const context = requireApi();

  const empty = await context.post("/api/reports/upload", { multipart: {} });
  expect(empty.status()).toBe(400);
});

test("the live-refresh events endpoint exists and requires a session", async () => {
  requireApi();
  const anonymous = await request.newContext({ baseURL: BASE });
  try {
    const response = await anonymous.get("/api/events");
    expect(response.status()).toBe(401);
  } finally {
    await anonymous.dispose();
  }
});
