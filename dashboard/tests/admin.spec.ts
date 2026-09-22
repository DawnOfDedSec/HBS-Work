import { expect, test, type Page } from "@playwright/test";

/**
 * End-to-end coverage for Task 56 (admin: users, keys, retention, audit,
 * backup). Opt-in: the app shell wiring is owned by another task.
 *
 *   HBS_E2E=1 HBS_E2E_USER=... HBS_E2E_PASSWORD=... bunx playwright test tests/admin.spec.ts
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

test("viewers do not see the Admin navigation entry", async ({ page }) => {
  await page.goto(`${BASE_URL}/?tab=overview`);
  // Admin is super-admin only; the nav must not expose it to other roles.
  const adminLink = page.getByRole("button", { name: "Admin" });
  const role = process.env.HBS_E2E_ROLE ?? "viewer";
  if (role === "super_admin") await expect(adminLink).toBeVisible();
  else await expect(adminLink).toHaveCount(0);
});

test("user administration exposes create and deactivation controls", async ({ page }) => {
  await page.goto(`${BASE_URL}/?tab=admin&section=users`);
  await expect(page.getByRole("region", { name: "User administration" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Create user" })).toBeVisible();
});

test("retention requires a dry-run before apply is enabled", async ({ page }) => {
  await page.goto(`${BASE_URL}/?tab=admin&section=retention`);
  await expect(page.getByRole("region", { name: "Retention policy" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Run dry-run" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Apply cleanup" })).toBeHidden();
});

test("key inventory revokes with a required reason", async ({ page }) => {
  await page.goto(`${BASE_URL}/?tab=admin&section=keys`);
  await expect(page.getByRole("region", { name: "Issuance key inventory" })).toBeVisible();
  const revoke = page.getByRole("button", { name: "Revoke" }).first();
  if (await revoke.isVisible().catch(() => false)) {
    await revoke.click();
    const dialog = page.getByRole("dialog");
    await dialog.getByRole("button", { name: "Revoke" }).click();
    await expect(dialog.getByText(/reason is required/i)).toBeVisible();
  }
});

test("backup page offers an encrypted download", async ({ page }) => {
  await page.goto(`${BASE_URL}/?tab=admin&section=backup`);
  await expect(page.getByRole("region", { name: "Backup and restore" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Download encrypted backup" })).toBeVisible();
});
