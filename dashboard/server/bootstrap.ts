import type { Database } from "bun:sqlite";
import { assessPassword, hashPassword } from "./password";

// Administrative bootstrap for unattended installs. The normal first-run path
// is the console's setup wizard (`POST /api/auth/setup`, `src/pages/Setup.tsx`):
// nothing is created until a human picks a username and password. Enable this
// helper with `HBS_BOOTSTRAP_ADMIN=true` and optionally `HBS_ADMIN_USERNAME` /
// `HBS_ADMIN_PASSWORD` (both are ignored while HBS_BOOTSTRAP_ADMIN=false).

export type BootstrapCredentials = { username: string; password: string };

export type BootstrapOptions = {
  username?: string;
  password?: string;
};

const PASSWORD_ALPHABET =
  "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#%^*-_+=";

function randomPassword(length = 20): string {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes, (b) => PASSWORD_ALPHABET[b % PASSWORD_ALPHABET.length]).join("");
}

function userCount(db: Database): number {
  return (db.query("SELECT COUNT(*) AS count FROM users").get() as { count: number }).count;
}

/**
 * Create the initial super_admin when none exists. Returns the generated
 * credentials (so the caller can display them once), or null when a user
 * already exists or another process won the race.
 */
export async function ensureBootstrapAdmin(
  db: Database,
  options: BootstrapOptions = {},
): Promise<BootstrapCredentials | null> {
  if (userCount(db) > 0) return null;

  const username =
    (options.username?.trim() || process.env.HBS_ADMIN_USERNAME?.trim() || "admin")
      .trim()
      .toLowerCase() || "admin";
  // An env var that is set but empty (blank line in a .env, CI variable with no
  // value) must fall back to a generated password, not crash the hash step.
  const password = options.password?.trim() || process.env.HBS_ADMIN_PASSWORD?.trim() || randomPassword();
  // Generated passwords always satisfy the policy. An operator-supplied one is
  // reported, never silently replaced - that would break unattended installs.
  const verdict = assessPassword(password, username);
  if (!verdict.ok) {
    console.warn(`hbs-dashboard: the HBS_ADMIN_PASSWORD from the environment is weak (${verdict.reason}) - change it after signing in`);
  }
  const hash = await hashPassword(password);
  const now = new Date().toISOString();

  try {
    db.query(
      `INSERT INTO users (username, password_hash, role, active, created_at, updated_at)
       VALUES (?, ?, 'super_admin', 1, ?, ?)`,
    ).run(username, hash, now, now);
  } catch {
    // UNIQUE violation => another process bootstrapped first.
    return null;
  }
  return { username, password };
}
