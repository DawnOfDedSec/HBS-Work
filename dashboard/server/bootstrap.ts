import type { Database } from "bun:sqlite";

// First-run administrator bootstrap. On the very first launch (zero users) the
// server creates a super_admin and prints its credentials once in the CLI, so
// an operator can sign in without a separate setup step. Set
// `HBS_BOOTSTRAP_ADMIN=false` to disable, or override with `HBS_ADMIN_USERNAME`
// / `HBS_ADMIN_PASSWORD`.

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
    (options.username ?? process.env.HBS_ADMIN_USERNAME ?? "admin").trim().toLowerCase() || "admin";
  const password = options.password ?? process.env.HBS_ADMIN_PASSWORD ?? randomPassword();
  const hash = await Bun.password.hash(password, { algorithm: "argon2id" });
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
