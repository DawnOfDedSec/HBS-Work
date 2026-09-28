import { afterEach, describe, expect, it } from "bun:test";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  configPath,
  effectiveFromEnv,
  loadHostingSettings,
  saveHostingSettings,
  settingsFingerprint,
  settingsToEnv,
  syncEnvFile,
  validateHostingInput,
} from "./config-store";

const dirs: string[] = [];
function dataEnv(extra: Record<string, string> = {}): Record<string, string | undefined> {
  const dir = mkdtempSync(join(tmpdir(), "hbs-config-"));
  dirs.push(dir);
  return { HBS_DATA_ROOT: dir, HBS_DB_PATH: join(dir, "hbs.sqlite"), ...extra };
}

afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

describe("sealed hosting config", () => {
  it("round-trips settings through an encrypted file", () => {
    const env = dataEnv();
    const result = saveHostingSettings({ host: "0.0.0.0", port: 8443 }, env, "root");
    expect(result.ok).toBeTrue();
    const path = configPath(env)!;
    // The file on disk is ciphertext, not the settings.
    const raw = readFileSync(path, "utf8");
    expect(raw).not.toContain("0.0.0.0");
    expect(raw).not.toContain("8443");

    const loaded = loadHostingSettings(env);
    expect(loaded.status).toBe("ok");
    if (loaded.status !== "ok") return;
    expect(loaded.settings.host).toBe("0.0.0.0");
    expect(loaded.settings.port).toBe(8443);
    expect(loaded.settings.updatedBy).toBe("root");
  });

  it("reports a missing file instead of inventing settings", () => {
    const env = dataEnv();
    expect(loadHostingSettings(env).status).toBe("missing");
  });

  it("refuses a config with a flipped byte", () => {
    const env = dataEnv();
    saveHostingSettings({ host: "127.0.0.1", port: 3000 }, env, "root");
    const path = configPath(env)!;
    const envelope = JSON.parse(readFileSync(path, "utf8"));
    const ct = Buffer.from(envelope.ct, "base64");
    ct[0] ^= 0x01;
    envelope.ct = ct.toString("base64");
    writeFileSync(path, JSON.stringify(envelope));

    const loaded = loadHostingSettings(env);
    expect(loaded.status).toBe("tampered");
  });

  it("refuses a config sealed with a different key", () => {
    const source = dataEnv({ HBS_CONFIG_KEY: "aa".repeat(32) });
    saveHostingSettings({ host: "10.0.0.1", port: 3001 }, source, "root");
    const sealed = readFileSync(configPath(source)!, "utf8");

    // Same ciphertext, different install/key: GCM must reject it.
    const target = dataEnv({ HBS_CONFIG_KEY: "bb".repeat(32) });
    writeFileSync(configPath(target)!, sealed);
    expect(loadHostingSettings(target).status).toBe("tampered");
  });

  it("validates host, port and TLS pairs", () => {
    expect(validateHostingInput({ host: "127.0.0.1", port: 3000 }).ok).toBeTrue();
    expect(validateHostingInput({ host: "bad host", port: 3000 }).ok).toBeFalse();
    expect(validateHostingInput({ host: "127.0.0.1", port: 0 }).ok).toBeFalse();
    expect(validateHostingInput({ host: "127.0.0.1", port: 70000 }).ok).toBeFalse();
    expect(validateHostingInput({ host: "127.0.0.1", port: 3000, tlsCert: "/x.crt" }).ok).toBeFalse();
    const missing = validateHostingInput({
      host: "127.0.0.1",
      port: 3000,
      tlsCert: "/does/not/exist.crt",
      tlsKey: "/does/not/exist.key",
    });
    expect(missing.ok).toBeFalse();
    if (!missing.ok) expect(missing.error).toContain("not found");
  });

  it("mirrors the choice into hbs.env and removes keys when disabled", () => {
    const env = dataEnv();
    const envFile = join(env.HBS_DATA_ROOT!, "hbs.env");
    writeFileSync(
      envFile,
      "# HBS Console environment\nPORT=3000\nHBS_DATA_ROOT=keep-me\nHBS_BOOTSTRAP_ADMIN=false\n",
    );
    const saved = saveHostingSettings({ host: "0.0.0.0", port: 9443 }, env, "root");
    expect(saved.ok).toBeTrue();
    if (!saved.ok) return;
    let text = readFileSync(envFile, "utf8");
    expect(text).toContain("PORT=9443");
    expect(text).toContain("HOST=0.0.0.0");
    // Comments and keys we do not own survive.
    expect(text).toContain("# HBS Console environment");
    expect(text).toContain("HBS_DATA_ROOT=keep-me");
    expect(text).toContain("HBS_BOOTSTRAP_ADMIN=false");

    // Back to loopback: HOST disappears rather than lingering as 127.0.0.1.
    syncEnvFile({ ...saved.settings, host: "127.0.0.1", port: 3000 }, env);
    text = readFileSync(envFile, "utf8");
    expect(text).not.toContain("HOST=");
    expect(text).toContain("PORT=3000");
  });

  it("turns a stored config into env overrides and a stable fingerprint", () => {
    const settings = {
      host: "0.0.0.0",
      port: 8080,
      tlsCert: "/c.pem",
      tlsKey: "/k.pem",
      updatedAt: "2026-01-01T00:00:00.000Z",
      updatedBy: "root",
    };
    expect(settingsToEnv(settings)).toEqual({
      HOST: "0.0.0.0",
      PORT: "8080",
      HBS_TLS_CERT: "/c.pem",
      HBS_TLS_KEY: "/k.pem",
    });
    // Fingerprints ignore bookkeeping fields but change with the binding.
    const withoutMeta = { host: "0.0.0.0", port: 8080, tlsCert: "/c.pem", tlsKey: "/k.pem" };
    expect(settingsFingerprint(settings)).toBe(settingsFingerprint(withoutMeta));
    expect(settingsFingerprint(settings)).not.toBe(settingsFingerprint({ ...withoutMeta, port: 8081 }));
  });

  it("derives effective settings from the environment", () => {
    const effective = effectiveFromEnv({ HOST: "0.0.0.0", PORT: "7443", HBS_TLS_CERT: "/c", HBS_TLS_KEY: "/k" });
    expect(effective).toMatchObject({ host: "0.0.0.0", port: 7443, tlsCert: "/c", tlsKey: "/k" });
    expect(effectiveFromEnv({}).port).toBe(3000);
    expect(effectiveFromEnv({ PORT: "not-a-number" }).port).toBe(3000);
  });
});
