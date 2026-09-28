// Password hashing, verification and policy for HBS Console.
//
// Threat model: whoever obtains the database (a backup, a support dump, a copied
// sqlite file) must not be able to recover anyone's password.
//   * Layer 1 - Argon2id with explicit memory-hard parameters (64 MiB, 3 passes)
//     and a per-hash random salt that Bun generates and stores inside the hash
//     string. Verification reads the parameters back out of the stored hash, so
//     strengthening them later keeps every existing hash working.
//   * Layer 2 - an optional pepper: a random secret mixed into the password
//     before hashing. A leaked database alone is then useless, because the
//     pepper lives outside it. Peppered hashes carry a `peppered:` marker, so
//     hashes created before the pepper existed still verify.
//
// Memory hygiene: the pepper is read for the duration of one hash/verify call
// and never cached in module state, and the plaintext password stays inside the
// request handler that received it - never in a module-level variable, never in
// a log, never in a URL. JavaScript strings cannot be reliably zeroed, so a
// plaintext copy does exist briefly on the heap; keeping it single-copy and
// short-lived is the achievable goal, and the reason nothing here retains it.
//
// Nothing in this module ever writes a password, hash or pepper to the log.

import { createHmac, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

/** Minimum length accepted by `assessPassword`. */
export const PASSWORD_MIN_LENGTH = 12;

/** Argon2id parameters. Bun's default is 64 MiB / 2 passes; we use 3. */
const ARGON2ID = { algorithm: "argon2id", memoryCost: 65536, timeCost: 3 } as const;

/** Marker that tells `verifyPassword` the hash was computed with the pepper. */
const PEPPERED = "peppered:";

/**
 * Passwords that show up in every credential-stuffing wordlist. A short block
 * list is not a dictionary attack on the user; it stops the handful of choices
 * that an offline cracker recovers in milliseconds even with Argon2id.
 */
const COMMON_PASSWORDS = new Set([
  "123456789012",
  "1234567890123",
  "12345678901234",
  "password123",
  "password1234",
  "password12345",
  "passwordpassword",
  "qwertyuiopas",
  "qwerty123456",
  "administrator",
  "letmein12345",
  "welcometothejungle",
  "iloveyou1234",
  "monkey123456",
  "dragon123456",
  "abc123456789",
  "changeme1234",
  "welcome12345",
  "adminadmin12",
  "aaaaaaaaaaaa",
  "111111111111",
  "hbsconsole12",
]);

const SEQUENCES = ["0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop", "asdfghjkl", "zxcvbnm"];

export type PasswordVerdict = { ok: true } | { ok: false; reason: string };

function characterClasses(password: string): number {
  let classes = 0;
  if (/[a-z]/.test(password)) classes += 1;
  if (/[A-Z]/.test(password)) classes += 1;
  if (/[0-9]/.test(password)) classes += 1;
  if (/[^A-Za-z0-9]/.test(password)) classes += 1;
  return classes;
}

function looksSequential(lower: string): boolean {
  for (const sequence of SEQUENCES) {
    for (let i = 0; i + 6 <= sequence.length; i += 1) {
      const run = sequence.slice(i, i + 6);
      if (lower.includes(run) || lower.includes([...run].reverse().join(""))) return true;
    }
  }
  return false;
}

/**
 * Policy for a *human-chosen* password (the setup wizard, the users admin page).
 * Long passphrases are welcome: 16+ characters need two character classes, a
 * shorter password needs three, which keeps "correct horse battery staple"
 * acceptable while rejecting "Password1!".
 */
export function assessPassword(password: string, username?: string): PasswordVerdict {
  const lower = password.toLowerCase();
  if (password.length < PASSWORD_MIN_LENGTH) {
    return { ok: false, reason: `use at least ${PASSWORD_MIN_LENGTH} characters` };
  }
  if (COMMON_PASSWORDS.has(lower)) {
    return { ok: false, reason: "that password appears in public breach wordlists" };
  }
  if (/^(.)\1*$/.test(password)) {
    return { ok: false, reason: "use more than one repeated character" };
  }
  if (looksSequential(lower)) {
    return { ok: false, reason: "avoid keyboard runs and sequences like 0123456789" };
  }
  const user = username?.trim().toLowerCase();
  if (user && user.length >= 3 && (lower === user || lower.includes(user))) {
    return { ok: false, reason: "the password must not contain the username" };
  }
  const classes = characterClasses(password);
  if (password.length < 16 && classes < 3) {
    return {
      ok: false,
      reason: "mix upper case, lower case, digits or symbols (a 16+ character passphrase may skip this)",
    };
  }
  if (password.length >= 16 && classes < 2) {
    return { ok: false, reason: "use at least two kinds of characters" };
  }
  return { ok: true };
}

/**
 * Where the pepper lives. `HBS_PASSWORD_PEPPER_FILE` wins; otherwise it sits
 * beside the database inside the data root (0600), which keeps it out of the
 * database file itself. Set `HBS_PASSWORD_PEPPER` to keep it in a secret
 * manager instead, or `HBS_DISABLE_PASSWORD_PEPPER=true` to turn it off.
 */
function pepperPath(): string | null {
  const explicit = process.env.HBS_PASSWORD_PEPPER_FILE?.trim();
  if (explicit) return explicit;
  const dataRoot = process.env.HBS_DATA_ROOT?.trim();
  if (dataRoot) return join(dataRoot, "pepper.key");
  const dbPath = process.env.HBS_DB_PATH?.trim();
  if (dbPath && dbPath !== ":memory:" && !dbPath.startsWith("file:")) {
    return join(dirname(dbPath), "pepper.key");
  }
  // No durable data location known (unit tests, ad-hoc runs): no pepper, and no
  // surprise files written next to the working directory.
  return null;
}

let pepperNoticeLogged = false;

/** Reads the pepper for this call only - it is deliberately not cached. */
function pepperSecret(): string | null {
  if (process.env.HBS_DISABLE_PASSWORD_PEPPER?.trim() === "true") return null;
  const fromEnv = process.env.HBS_PASSWORD_PEPPER?.trim();
  if (fromEnv) return fromEnv;

  const file = pepperPath();
  if (!file) {
    if (!pepperNoticeLogged) {
      pepperNoticeLogged = true;
      console.log("hbs-dashboard: password pepper disabled (no HBS_DATA_ROOT or HBS_DB_PATH to keep it in)");
    }
    return null;
  }
  try {
    if (!existsSync(file)) {
      mkdirSync(dirname(file), { recursive: true });
      // 0600: owner-only. On Windows the file inherits the (per-user) profile
      // ACL of %LOCALAPPDATA%, which is already owner-only.
      writeFileSync(file, randomBytes(32).toString("hex"), { mode: 0o600 });
      chmodSync(file, 0o600);
    }
    const value = readFileSync(file, "utf8").trim();
    return value || null;
  } catch (error) {
    if (!pepperNoticeLogged) {
      pepperNoticeLogged = true;
      console.error(`hbs-dashboard: could not read the password pepper at ${file}: ${String(error)}`);
    }
    return null;
  }
}

function mix(password: string, pepper: string): string {
  return createHmac("sha256", pepper).update(password, "utf8").digest("hex");
}

/**
 * Hash a password for storage. Returns an Argon2id string (prefixed with
 * `peppered:` when the pepper is active).
 */
export async function hashPassword(password: string): Promise<string> {
  const pepper = pepperSecret();
  const prepared = pepper ? mix(password, pepper) : password;
  const hash = await Bun.password.hash(prepared, ARGON2ID);
  return pepper ? PEPPERED + hash : hash;
}

/**
 * Verify a password against a stored hash. Returns false - never throws - for
 * malformed hashes and for peppered hashes when the pepper is missing (a pepper
 * that is lost cannot be recovered; sign in with another administrator and
 * reset the password).
 */
export async function verifyPassword(password: string, stored: string | null | undefined): Promise<boolean> {
  if (!stored) return false;
  try {
    if (stored.startsWith(PEPPERED)) {
      const pepper = pepperSecret();
      if (!pepper) return false;
      return await Bun.password.verify(mix(password, pepper), stored.slice(PEPPERED.length));
    }
    return await Bun.password.verify(password, stored);
  } catch {
    return false;
  }
}

/** True when the stored value was produced with the pepper (surfaced by admin). */
export function isPepperedHash(stored: string): boolean {
  return stored.startsWith(PEPPERED);
}
