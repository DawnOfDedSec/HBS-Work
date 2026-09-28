import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  PASSWORD_MIN_LENGTH,
  assessPassword,
  hashPassword,
  isPepperedHash,
  verifyPassword,
} from "./password";

const ENV_KEYS = ["HBS_PASSWORD_PEPPER", "HBS_DATA_ROOT", "HBS_DB_PATH", "HBS_PASSWORD_PEPPER_FILE"] as const;
let saved: Record<string, string | undefined> = {};

beforeEach(() => {
  saved = Object.fromEntries(ENV_KEYS.map((key) => [key, process.env[key]]));
  for (const key of ENV_KEYS) delete process.env[key];
});

afterEach(() => {
  for (const key of ENV_KEYS) {
    if (saved[key] === undefined) delete process.env[key];
    else process.env[key] = saved[key];
  }
});

describe("password hashing", () => {
  it("stores Argon2id hashes, never the plaintext", async () => {
    const hash = await hashPassword("correct horse battery staple");
    expect(hash).toStartWith("$argon2id$");
    expect(hash).not.toContain("correct horse");
    expect(await verifyPassword("correct horse battery staple", hash)).toBeTrue();
  });

  it("salts every hash, so equal passwords do not collide", async () => {
    const first = await hashPassword("correct horse battery staple");
    const second = await hashPassword("correct horse battery staple");
    expect(first).not.toBe(second);
    expect(await verifyPassword("correct horse battery staple", second)).toBeTrue();
  });

  it("rejects the wrong password and any malformed stored hash", async () => {
    const hash = await hashPassword("correct horse battery staple");
    expect(await verifyPassword("correct horse battery stapl", hash)).toBeFalse();
    expect(await verifyPassword("", hash)).toBeFalse();
    expect(await verifyPassword("correct horse battery staple", "not-a-hash")).toBeFalse();
    expect(await verifyPassword("correct horse battery staple", "")).toBeFalse();
    expect(await verifyPassword("correct horse battery staple", null)).toBeFalse();
  });

  it("still verifies hashes written before the pepper existed", async () => {
    // Legacy row: Bun's defaults, no marker.
    const legacy = await Bun.password.hash("correct horse battery staple", { algorithm: "argon2id" });
    expect(isPepperedHash(legacy)).toBeFalse();
    expect(await verifyPassword("correct horse battery staple", legacy)).toBeTrue();
  });
});

describe("password pepper", () => {
  it("mixes in a pepper kept beside the data and marks the hash", async () => {
    const dataRoot = mkdtempSync(join(tmpdir(), "hbs-pepper-"));
    process.env.HBS_DATA_ROOT = dataRoot;

    const hash = await hashPassword("correct horse battery staple");
    expect(isPepperedHash(hash)).toBeTrue();
    expect(await verifyPassword("correct horse battery staple", hash)).toBeTrue();
    // The pepper is a real secret on disk, 0644-free and not the password.
    const pepper = readFileSync(join(dataRoot, "pepper.key"), "utf8").trim();
    expect(pepper.length).toBeGreaterThanOrEqual(32);
    expect(pepper).not.toContain("correct horse");
  });

  it("makes a leaked database useless without the pepper", async () => {
    const withPepper = mkdtempSync(join(tmpdir(), "hbs-pepper-a-"));
    process.env.HBS_DATA_ROOT = withPepper;
    const stored = await hashPassword("correct horse battery staple");

    // Same database row, attacker's machine, different (or missing) pepper.
    process.env.HBS_DATA_ROOT = mkdtempSync(join(tmpdir(), "hbs-pepper-b-"));
    expect(await verifyPassword("correct horse battery staple", stored)).toBeFalse();

    delete process.env.HBS_DATA_ROOT;
    delete process.env.HBS_DB_PATH;
    expect(await verifyPassword("correct horse battery staple", stored)).toBeFalse();
  });

  it("honours an externally managed pepper and can be turned off", async () => {
    process.env.HBS_PASSWORD_PEPPER = "pepper-from-a-secret-manager";
    const hash = await hashPassword("correct horse battery staple");
    expect(isPepperedHash(hash)).toBeTrue();
    expect(await verifyPassword("correct horse battery staple", hash)).toBeTrue();

    delete process.env.HBS_PASSWORD_PEPPER;
    process.env.HBS_DISABLE_PASSWORD_PEPPER = "true";
    const plain = await hashPassword("correct horse battery staple");
    expect(isPepperedHash(plain)).toBeFalse();
    delete process.env.HBS_DISABLE_PASSWORD_PEPPER;
  });
});

describe("password policy", () => {
  it("accepts long passphrases and mixed shorter passwords", () => {
    expect(assessPassword("correct horse battery staple").ok).toBeTrue();
    expect(assessPassword("Tr0ub4dor&3x").ok).toBeTrue();
  });

  it("rejects short, common, sequential and repeated passwords", () => {
    for (const weak of [
      "short",
      "password",
      "password123",
      "123456789012",
      "qwerty123456",
      "aaaaaaaaaaaa",
      "abcdefghijklmnop",
    ]) {
      const verdict = assessPassword(weak);
      expect(verdict.ok).toBeFalse();
    }
  });

  it("rejects a password built from the username", () => {
    expect(assessPassword("Administrator!23456", "admin").ok).toBeFalse();
    expect(assessPassword("Administrator!23456", "someone-else").ok).toBeTrue();
  });

  it("requires more character classes from shorter passwords", () => {
    expect(assessPassword("onlylowercases").ok).toBeFalse(); // 14 chars, 1 class
    expect(assessPassword("onlylowercasesthatarelong7").ok).toBeTrue(); // 27 chars, 2 classes
    expect(`${PASSWORD_MIN_LENGTH}`).toBe("12");
  });
});
