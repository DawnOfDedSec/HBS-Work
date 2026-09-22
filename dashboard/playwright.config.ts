import { defineConfig, devices } from "@playwright/test";

// End-to-end specs live in tests/ and are gated behind HBS_E2E=1 so the fast
// unit suite (`bun test`, which ignores tests/** via bunfig.toml) and CI that
// has no browser/server stay green.
export default defineConfig({
  testDir: "tests",
  timeout: 30_000,
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: [["list"]],
  use: {
    baseURL: process.env.HBS_E2E_BASE_URL ?? "http://127.0.0.1:3000",
    trace: "on-first-retry",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
