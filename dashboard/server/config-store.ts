// Encrypted, tamper-evident hosting configuration.
//
// The installer writes a plaintext data/hbs.env because systemd, launchd and
// the tray helpers need to launch the engine before any code of ours runs. The
// server then owns the authoritative copy in an AEAD-sealed file:
//
//   data/hbs.config   AES-256-GCM(JSON settings), AAD = "hbs-config-v1"
//   data/config.key   32 random bytes, 0600 (or HBS_CONFIG_KEY = 64 hex chars)
//
// Two properties matter:
//   * confidentiality at rest - the file is ciphertext, so a copied backup or
//     a support dump does not leak the bind address, port or TLS paths;
//   * tamper-evidence - the GCM tag authenticates the payload, so an edited or
//     transplanted config never loads. A tampered file is reported and ignored
//     (the server falls back to hbs.env), never silently applied.
//
// The key sits beside the file with 0600 permissions. That is at-rest
// encryption plus tamper detection for anyone who can read or write the file
// without also owning the service account; it is not a defence against an
// attacker who already runs as that account. This is the same honest boundary
// the password pepper documents in SECURITY.md.

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  X509Certificate,
} from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";

export const CONFIG_VERSION = 1;
/** Envelope label; the cipher name Node/Bun accept is the lowercase form. */
const ALG = "A256GCM";
const CIPHER = "aes-256-gcm";
const AAD = Buffer.from("hbs-config-v1");
const IV_BYTES = 12;
const KEY_BYTES = 32;
const KEY_FILE_MODE = 0o600;

export type HostingSettings = {
  host: string;
  port: number;
  tlsCert?: string;
  tlsKey?: string;
  updatedAt: string;
  updatedBy: string;
};

export type HostingInput = {
  host: string;
  port: number;
  tlsCert?: string;
  tlsKey?: string;
};

export type SettingsLoad =
  | { status: "missing" }
  | { status: "ok"; settings: HostingSettings }
  | { status: "tampered"; error: string }
  | { status: "error"; error: string };

export type SettingsSaveResult =
  | { ok: true; settings: HostingSettings; configPath: string; envFile: string | null }
  | { ok: false; error: string };

type Env = Record<string, string | undefined>;

const LOOPBACK = new Set(["127.0.0.1", "::1", "localhost"]);

function randomSuffix(): string {
  return randomBytes(8).toString("hex");
}

function writeFileAtomic(path: string, data: Uint8Array, mode: number): void {
  const dir = dirname(path);
  mkdirSync(dir, { recursive: true });
  const temp = join(dir, `.${basename(path)}.${randomSuffix()}.tmp`);
  writeFileSync(temp, data, { mode });
  try {
    // POSIX permissions; best effort where mode bits are ignored (win32).
    chmodSync(temp, mode);
  } catch {
    // ignore
  }
  renameSync(temp, path);
}

/** Directory that holds the config and its key, mirroring the pepper lookup. */
function dataDir(env: Env): string | null {
  const root = env.HBS_DATA_ROOT?.trim();
  if (root) return root;
  const dbPath = env.HBS_DB_PATH?.trim();
  if (dbPath && dbPath !== ":memory:" && !dbPath.startsWith("file:")) return dirname(dbPath);
  return null;
}

export function configPath(env: Env): string | null {
  const explicit = env.HBS_CONFIG_FILE?.trim();
  if (explicit) return explicit;
  const dir = dataDir(env);
  return dir ? join(dir, "hbs.config") : null;
}

export function configKeyPath(env: Env): string | null {
  const explicit = env.HBS_CONFIG_KEY_FILE?.trim();
  if (explicit) return explicit;
  const dir = dataDir(env);
  return dir ? join(dir, "config.key") : null;
}

/** The key is an env secret when provided, otherwise a 0600 file we create. */
function loadOrCreateKey(env: Env): { key: Buffer; source: "env" | "file"; path: string | null } {
  const fromEnv = env.HBS_CONFIG_KEY?.trim();
  if (fromEnv) {
    if (!/^[a-f0-9]{64}$/i.test(fromEnv)) throw new Error("HBS_CONFIG_KEY must be 64 hex characters");
    return { key: Buffer.from(fromEnv, "hex"), source: "env", path: null };
  }
  const path = configKeyPath(env);
  if (!path) throw new Error("no data root for the config key (set HBS_DATA_ROOT or HBS_DB_PATH)");
  if (!existsSync(path)) {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, randomBytes(KEY_BYTES).toString("hex"), { mode: KEY_FILE_MODE });
    try {
      chmodSync(path, KEY_FILE_MODE);
    } catch {
      // ignore
    }
  }
  const raw = readFileSync(path, "utf8").trim();
  if (!/^[a-f0-9]{64}$/i.test(raw)) throw new Error(`config key at ${path} is malformed`);
  return { key: Buffer.from(raw, "hex"), source: "file", path };
}

function seal(settings: HostingSettings, env: Env): { envelope: string; keyPath: string | null } {
  const { key, path } = loadOrCreateKey(env);
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(CIPHER, key, iv, { authTagLength: 16 });
  cipher.setAAD(AAD);
  const plaintext = Buffer.from(JSON.stringify(settings), "utf8");
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const envelope = JSON.stringify({
    v: CONFIG_VERSION,
    alg: ALG,
    iv: iv.toString("base64"),
    ct: ct.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
  });
  return { envelope, keyPath: path };
}

function looksLikeSettings(value: unknown): value is HostingSettings {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return typeof v.host === "string" && typeof v.port === "number";
}

export function loadHostingSettings(env: Env): SettingsLoad {
  const path = configPath(env);
  if (!path || !existsSync(path)) return { status: "missing" };
  let parsed: { v?: unknown; alg?: unknown; iv?: unknown; ct?: unknown; tag?: unknown };
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return { status: "tampered", error: `config file at ${path} is not valid JSON` };
  }
  if (parsed.v !== CONFIG_VERSION || parsed.alg !== ALG) {
    return { status: "error", error: `unsupported config envelope (version ${String(parsed.v)})` };
  }
  if (typeof parsed.iv !== "string" || typeof parsed.ct !== "string" || typeof parsed.tag !== "string") {
    return { status: "tampered", error: "config envelope is missing its sealed fields" };
  }
  try {
    const { key } = loadOrCreateKey(env);
    const decipher = createDecipheriv(CIPHER, key, Buffer.from(parsed.iv, "base64"), { authTagLength: 16 });
    decipher.setAAD(AAD);
    decipher.setAuthTag(Buffer.from(parsed.tag, "base64"));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(parsed.ct, "base64")),
      decipher.final(),
    ]);
    const settings = JSON.parse(plaintext.toString("utf8"));
    if (!looksLikeSettings(settings)) return { status: "tampered", error: "config payload has an unexpected shape" };
    return { status: "ok", settings: settings as HostingSettings };
  } catch {
    // Wrong key or a single flipped byte: GCM cannot tell them apart, and both
    // mean "do not trust this file". Report, never apply.
    return { status: "tampered", error: "config failed authentication (tampered, or sealed with a different key)" };
  }
}

/** The settings the current process is actually running with. */
export function effectiveFromEnv(env: Env): HostingSettings {
  const host = env.HOST?.trim() || "127.0.0.1";
  const portRaw = env.PORT?.trim();
  const port = portRaw && /^\d+$/.test(portRaw) ? Number(portRaw) : 3000;
  return {
    host,
    port,
    tlsCert: env.HBS_TLS_CERT?.trim() || undefined,
    tlsKey: env.HBS_TLS_KEY?.trim() || undefined,
    updatedAt: "",
    updatedBy: "installer",
  };
}

/** Env overrides so a stored config wins over hbs.env but loses to CLI flags. */
export function settingsToEnv(settings: HostingSettings): Env {
  const out: Env = { HOST: settings.host, PORT: String(settings.port) };
  if (settings.tlsCert && settings.tlsKey) {
    out.HBS_TLS_CERT = settings.tlsCert;
    out.HBS_TLS_KEY = settings.tlsKey;
  }
  return out;
}

export type ValidationResult = { ok: true; value: HostingInput } | { ok: false; error: string };

/** Field-level validation shared by the API, the CLI and the desktop shell. */
export function validateHostingInput(input: unknown): ValidationResult {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    return { ok: false, error: "expected a JSON object with host and port" };
  }
  const raw = input as Record<string, unknown>;
  const host = typeof raw.host === "string" ? raw.host.trim() : "";
  if (!host) return { ok: false, error: "host is required (use 127.0.0.1 for local-only)" };
  if (host.length > 255 || /[\s\x00-\x1f]/.test(host)) {
    return { ok: false, error: "host contains whitespace or control characters" };
  }
  const port = typeof raw.port === "number" ? raw.port : Number(raw.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return { ok: false, error: "port must be an integer between 1 and 65535" };
  }
  const tlsCert = typeof raw.tlsCert === "string" && raw.tlsCert.trim() ? raw.tlsCert.trim() : undefined;
  const tlsKey = typeof raw.tlsKey === "string" && raw.tlsKey.trim() ? raw.tlsKey.trim() : undefined;
  if (!!tlsCert !== !!tlsKey) return { ok: false, error: "TLS needs both a certificate and a key path" };
  if (tlsCert && tlsKey) {
    const problem = checkTlsPair(tlsCert, tlsKey);
    if (problem) return { ok: false, error: problem };
  }
  return { ok: true, value: { host, port, tlsCert, tlsKey } };
}

/** Read both PEM files and prove the key belongs to the certificate. */
function checkTlsPair(certPath: string, keyPath: string): string | null {
  for (const p of [certPath, keyPath]) {
    if (!existsSync(p)) return `TLS file not found: ${p}`;
    try {
      if (!statSync(p).isFile()) return `TLS path is not a file: ${p}`;
    } catch {
      return `TLS file is not readable: ${p}`;
    }
  }
  let cert: X509Certificate;
  let keyDer: Buffer;
  try {
    cert = new X509Certificate(readFileSync(certPath));
  } catch {
    return `certificate is not valid PEM/X.509: ${certPath}`;
  }
  try {
    keyDer = createPublicKey(createPrivateKey(readFileSync(keyPath))).export({
      type: "spki",
      format: "der",
    }) as Buffer;
  } catch {
    return `private key is not valid PEM: ${keyPath}`;
  }
  const certDer = cert.publicKey.export({ type: "spki", format: "der" }) as Buffer;
  if (!certDer.equals(keyDer)) return "the private key does not match the certificate";
  return null;
}

// --- hbs.env mirror ---------------------------------------------------------
// Supervisors and the control CLIs parse this file, so it stays in sync with
// the sealed config. Same single-KEY=value convention as the installers.

function envFilePath(env: Env): string | null {
  const explicit = env.HBS_ENV_FILE?.trim();
  if (explicit) return explicit;
  const dir = dataDir(env);
  return dir ? join(dir, "hbs.env") : null;
}

function setEnvLine(lines: string[], key: string, value: string | undefined): string[] {
  const kept = lines.filter((line) => !line.startsWith(`${key}=`));
  if (value !== undefined) kept.push(`${key}=${value}`);
  return kept;
}

/** Rewrite only the keys we own, leaving comments and unknown keys intact. */
export function syncEnvFile(settings: HostingSettings, env: Env): string | null {
  const path = envFilePath(env);
  if (!path) return null;
  let lines: string[] = [];
  if (existsSync(path)) {
    lines = readFileSync(path, "utf8").split(/\r?\n/);
    while (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  }
  lines = setEnvLine(lines, "PORT", String(settings.port));
  lines = setEnvLine(lines, "HOST", LOOPBACK.has(settings.host) ? undefined : settings.host);
  lines = setEnvLine(lines, "HBS_TLS_CERT", settings.tlsCert);
  lines = setEnvLine(lines, "HBS_TLS_KEY", settings.tlsKey);
  writeFileAtomic(path, Buffer.from(`${lines.join("\n")}\n`, "utf8"), 0o600);
  return path;
}

/** Validate, seal and persist. Throws nothing; callers get a result object. */
export function saveHostingSettings(
  input: unknown,
  env: Env,
  actor: string,
): SettingsSaveResult {
  const validated = validateHostingInput(input);
  if (!validated.ok) return { ok: false, error: validated.error };
  const path = configPath(env);
  if (!path) return { ok: false, error: "no data root for the config file (set HBS_DATA_ROOT or HBS_DB_PATH)" };
  const settings: HostingSettings = {
    ...validated.value,
    updatedAt: new Date().toISOString(),
    updatedBy: actor || "unknown",
  };
  try {
    const { envelope } = seal(settings, env);
    writeFileAtomic(path, Buffer.from(envelope, "utf8"), 0o600);
    const envFile = syncEnvFile(settings, env);
    return { ok: true, settings, configPath: path, envFile };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : "could not write the config file" };
  }
}

/** Stable fingerprint of the settings, used to spot a change needing restart. */
export function settingsFingerprint(settings: HostingInput): string {
  return createHash("sha256")
    .update(JSON.stringify([settings.host, settings.port, settings.tlsCert ?? "", settings.tlsKey ?? ""]))
    .digest("hex");
}
