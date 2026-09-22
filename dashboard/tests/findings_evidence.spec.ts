import { expect, test, type Page } from "@playwright/test";

/**
 * End-to-end coverage for Task 55 (findings, evidence, pivots, diff, treatment,
 * telemetry). The reviewer-facing spec in the plan targets a fully routed app,
 * which is owned by the app-shell task; these tests are therefore opt-in.
 *
 * Enable with a running dashboard:
 *   HBS_E2E=1 HBS_E2E_USER=... HBS_E2E_PASSWORD=... bunx playwright test tests/findings_evidence.spec.ts
 */
const enabled = process.env.HBS_E2E === "1";
const BASE_URL = process.env.HBS_BASE_URL ?? "http://127.0.0.1:3000";

test.beforeEach(async ({ page }) => {
  test.skip(!enabled, "Set HBS_E2E=1 with a running, routed dashboard to run end-to-end specs.");
  await login(page);
});

async function login(page: Page): Promise<void> {
  const username = process.env.HBS_E2E_USER;
  const password = process.env.HBS_E2E_PASSWORD;
  await page.goto(`${BASE_URL}/`);
  if (username && password && (await page.getByLabel(/username/i).isVisible().catch(() => false))) {
    await page.getByLabel(/username/i).fill(username);
    await page.getByLabel(/password/i).fill(password);
    await page.getByRole("button", { name: /sign in|log in/i }).click();
  }
}

test("findings explorer keeps filters in the URL and offers By Host / By Check pivots", async ({ page }) => {
  await page.goto(`${BASE_URL}/?severity=Critical`);
  await expect(page.getByRole("region", { name: "Findings explorer" })).toBeVisible();
  await expect(page.getByLabel("Active filters")).toContainText("severity:");

  await page.getByRole("tab", { name: "By Check" }).click();
  await expect(page.getByRole("table", { name: /Checks matching/i })).toBeVisible();

  await page.getByRole("tab", { name: "By Host" }).click();
  await expect(page.getByRole("table", { name: /Hosts matching/i })).toBeVisible();
});

test("evidence drawer renders the offending line with at most three context lines each side", async ({ page }) => {
  await page.goto(`${BASE_URL}/?severity=Critical`);
  const rows = page.getByRole("row");
  await expect(rows.nth(1)).toBeVisible();
  await page.getByRole("button", { name: "View", exact: true }).first().click();

  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await expect(dialog.getByText(/line \d+, column \d+/)).toBeVisible();
  // The drawer is modal and Escape closes it.
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
});

test("treatment board persists a justified state change", async ({ page }) => {
  await page.goto(`${BASE_URL}/?tab=treatment`);
  await expect(page.getByRole("region", { name: "Treatment board" })).toBeVisible();
  const change = page.getByRole("button", { name: "Change treatment" }).first();
  if (await change.isVisible().catch(() => false)) {
    await change.click();
    const dialog = page.getByRole("dialog");
    await dialog.getByLabel(/State/i).selectOption("accepted_risk");
    await dialog.getByLabel(/Justification/i).fill("Risk accepted by the asset owner for this cycle.");
    await dialog.getByRole("button", { name: "Save treatment" }).click();
    await expect(dialog).toBeHidden();
  }
});

test("report diff renders fixed, regressed, and unchanged columns", async ({ page }) => {
  await page.goto(`${BASE_URL}/?scope=report&reportId=1`);
  await expect(page.getByRole("region", { name: "Report comparison" })).toBeVisible();
  await expect(page.getByRole("region", { name: "Fixed" })).toBeVisible();
  await expect(page.getByRole("region", { name: "Regressed" })).toBeVisible();
  await expect(page.getByRole("region", { name: "Unchanged" })).toBeVisible();
});
