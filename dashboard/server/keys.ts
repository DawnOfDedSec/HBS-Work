import { Database } from "bun:sqlite";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  generateKeyPairSync,
  randomBytes,
  scryptSync,
} from "node:crypto";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";

// Per-issuance key lifecycle, revocation, purge, and encrypted backup/restore.
// Contract: docs/superpowers/plans/2026-09-21-hbs-platform.md Task 43.

export class KeyLifecycleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KeyLifecycleError";
  }
}

export type PurgePolicyResult = { retentionSatisfied: boolean; legalHold: boolean };

export type KeyLifecycleOptions = {
  dataRoot: string;
  purgePolicy?: (issuanceId: string) => PurgePolicyResult;
};

type IssuancePurgeRow = { extractor_id: string };

type BackupKeysEntry = { issuanceId: string; privateKey: string };
type BackupPayload = { database: string; keys: BackupKeysEntry[] };
type BackupEnvelope = {
  version: number;
  kdf: string;
  salt: string;
  nonce: string;
  ciphertext: string;
  digest: string;
};

const BACKUP_VERSION = 1;
const NONCE_BYTES = 12;
const GCM_TAG_BYTES = 16;
const RAW_KEY_BYTES = 32;
const KEY_FILE_MODE = 0o600;

// Bun's `Bun.write` resolves asynchronously; tests await their writes rather
// than relying on test-only global monkey-patching.

function randomSuffix(): string {
  return randomBytes(8).toString("hex");
}

function errorCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error
    ? (error as { code?: string }).code
    : undefined;
}

/** True for a zero-length or all-zero byte sequence. */
function isNil(bytes: Uint8Array): boolean {
  if (bytes.length === 0) return true;
  for (const byte of bytes) if (byte !== 0) return false;
  return true;
}

function keysDir(dataRoot: string): string {
  return join(dataRoot, "keys");
}

function keyFilePath(dataRoot: string, issuanceId: string): string {
  return join(keysDir(dataRoot), `${issuanceId}.key`);
}

function writeFileAtomic(path: string, data: Uint8Array, mode: number): void {
  const dir = dirname(path);
  mkdirSync(dir, { recursive: true });
  const temp = join(dir, `.${basename(path)}.${randomSuffix()}.tmp`);
  writeFileSync(temp, data, { mode });
  try {
    // POSIX permissions; best effort on platforms that ignore mode bits (win32).
    chmodSync(temp, mode);
  } catch {
    // ignore
  }
  renameSync(temp, path);
}

function listKeyFiles(dir: string): string[] {
  try {
    return readdirSync(dir).filter((name) => name.endsWith(".key"));
  } catch (error) {
    if (errorCode(error) === "ENOENT") return [];
    throw error;
  }
}

function sha256Hex(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

/** Read the set of issuance ids out of a serialized SQLite snapshot. */
function issuanceIdsFromSnapshot(snapshot: Uint8Array): Set<string> {
  const dir = mkdtempSync(join(tmpdir(), "hbs-restore-"));
  const path = join(dir, "snapshot.sqlite");
  writeFileSync(path, snapshot);
  const db = new Database(path);
  try {
    const rows = db.query("SELECT id FROM issuances").all() as { id: string }[];
    return new Set(rows.map((row) => row.id));
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Generate one fresh raw X25519 keypair. Never derived or reused. */
export function keygen(): { publicKey: Uint8Array; privateKey: Uint8Array } {
  const pair = generateKeyPairSync("x25519");
  const pubJwk = pair.publicKey.export({ format: "jwk" }) as { x?: string };
  const privJwk = pair.privateKey.export({ format: "jwk" }) as { d?: string };
  if (!pubJwk.x || !privJwk.d) {
    throw new KeyLifecycleError("failed to export x25519 key material");
  }
  return {
    publicKey: new Uint8Array(Buffer.from(pubJwk.x, "base64url")),
    privateKey: new Uint8Array(Buffer.from(privJwk.d, "base64url")),
  };
}

export class KeyLifecycle {
  private readonly db: Database;
  private readonly dataRoot: string;
  private readonly purgePolicy?: (issuanceId: string) => PurgePolicyResult;

  constructor(db: Database, opts: KeyLifecycleOptions) {
    this.db = db;
    this.dataRoot = opts.dataRoot;
    this.purgePolicy = opts.purgePolicy;
  }

  /** Persist a keypair: raw private key on disk (0600, atomic) plus a DB mapping.
   *  Rejects nil/duplicate public keys and rolls back the file if the insert fails. */
  saveKey(issuanceId: string, privateKey: Uint8Array, publicKey: Uint8Array): void {
    if (isNil(publicKey)) throw new KeyLifecycleError("refusing to store a nil public key");
    if (isNil(privateKey)) throw new KeyLifecycleError("refusing to store a nil private key");

    const encoded = Buffer.from(publicKey).toString("base64");
    const duplicate = this.db
      .query("SELECT 1 FROM keys WHERE public_key = ?")
      .get(encoded);
    if (duplicate) {
      throw new KeyLifecycleError("duplicate public key is already mapped to an issuance");
    }

    const path = keyFilePath(this.dataRoot, issuanceId);
    writeFileAtomic(path, privateKey, KEY_FILE_MODE);
    try {
      this.db.query(
        "INSERT INTO keys (issuance_id, public_key, private_key_path, created_at) VALUES (?, ?, ?, ?)",
      ).run(issuanceId, encoded, path, new Date().toISOString());
    } catch (error) {
      // No orphan file when the mapping insert rolls back (e.g. FK failure).
      rmSync(path, { force: true });
      throw error;
    }
  }

  /** Loads a private key only through the issuance -> key mapping. */
  loadPriv(issuanceId: string): Uint8Array {
    const row = this.db
      .query("SELECT private_key_path FROM keys WHERE issuance_id = ?")
      .get(issuanceId) as { private_key_path: string } | null;
    if (!row) {
      throw new KeyLifecycleError(`no key mapping for issuance ${issuanceId}`);
    }
    return new Uint8Array(readFileSync(row.private_key_path));
  }

  /** Throws for missing or revoked issuances; used to gate ingest and download. */
  assertIssuanceUsable(issuanceId: string, purpose: "ingest" | "download"): void {
    void purpose;
    const row = this.db
      .query("SELECT revoked_at FROM issuances WHERE id = ?")
      .get(issuanceId) as { revoked_at: string | null } | null;
    if (!row || row.revoked_at !== null) {
      throw new KeyLifecycleError(`issuance ${issuanceId} is revoked or unknown`);
    }
  }

  /** Marks an issuance revoked. Retains key file, artifact, and mapping; audits. */
  revokeIssuance(issuanceId: string, opts: { actor: string; reason: string }): void {
    const revokedAt = new Date().toISOString();
    this.db.query(
      "UPDATE issuances SET revoked_at = ?, revoked_reason = ?, revoked_by = ? WHERE id = ?",
    ).run(revokedAt, opts.reason, opts.actor, issuanceId);
    this.audit(opts.actor, "issuance.revoked", issuanceId, {
      issuanceId,
      reason: opts.reason,
      revokedAt,
    });
  }

  /** Irreversible super-admin purge. Deletes key row/file and the issuance, then
   *  writes redacted audit metadata. */
  purgeIssuance(
    issuanceId: string,
    opts: { actor: string; role: string; typedExtractorId: string; confirmIrreversible: boolean },
  ): void {
    if (opts.role !== "super_admin") {
      throw new KeyLifecycleError("purging an issuance requires the super_admin role");
    }
    if (opts.confirmIrreversible !== true) {
      throw new KeyLifecycleError("irreversible confirmation is required to purge");
    }
    const row = this.db
      .query("SELECT extractor_id FROM issuances WHERE id = ?")
      .get(issuanceId) as IssuancePurgeRow | null;
    if (!row) {
      throw new KeyLifecycleError(`issuance ${issuanceId} not found`);
    }
    if (opts.typedExtractorId !== row.extractor_id) {
      throw new KeyLifecycleError(
        "confirmation failed: typed extractor id does not match the issuance",
      );
    }
    if (this.purgePolicy) {
      const policy = this.purgePolicy(issuanceId);
      if (!policy.retentionSatisfied) {
        throw new KeyLifecycleError("retention requirements are not satisfied");
      }
      if (policy.legalHold) {
        throw new KeyLifecycleError("issuance is under legal hold");
      }
    }

    const path = keyFilePath(this.dataRoot, issuanceId);
    this.db.transaction(() => {
      this.db.query("DELETE FROM keys WHERE issuance_id = ?").run(issuanceId);
      this.db.query("DELETE FROM issuances WHERE id = ?").run(issuanceId);
    })();
    rmSync(path, { force: true });
    this.audit(opts.actor, "issuance.purged", issuanceId, {
      extractorId: opts.typedExtractorId,
      irreversible: true,
    });
  }

  private audit(actor: string, action: string, resource: string, details: unknown): void {
    this.db.query(
      "INSERT INTO audit_log (actor, actor_ip, action, resource, details, created_at) VALUES (?, ?, ?, ?, ?, ?)",
    ).run(actor, null, action, resource, JSON.stringify(details), new Date().toISOString());
  }
}

/** Authenticated, passphrase-encrypted snapshot of the SQLite DB plus key files. */
export function createEncryptedBackup(
  db: Database,
  passphrase: string,
  opts: { dataRoot: string },
): Uint8Array {
  const dir = keysDir(opts.dataRoot);
  const issuanceIds = new Set(
    (db.query("SELECT id FROM issuances").all() as { id: string }[]).map((row) => row.id),
  );

  const entries: BackupKeysEntry[] = [];
  for (const issuanceId of issuanceIds) {
    let bytes: Uint8Array;
    try {
      bytes = new Uint8Array(readFileSync(keyFilePath(opts.dataRoot, issuanceId)));
    } catch {
      throw new KeyLifecycleError(`missing key file for issuance ${issuanceId}`);
    }
    entries.push({ issuanceId, privateKey: Buffer.from(bytes).toString("base64") });
  }
  // Strict one-to-one: no key file may exist without a matching issuance.
  for (const name of listKeyFiles(dir)) {
    const stem = name.slice(0, -".key".length);
    if (!issuanceIds.has(stem)) {
      throw new KeyLifecycleError(`key file ${name} does not map to any issuance`);
    }
  }

  const databaseBytes = new Uint8Array(db.serialize());
  const payload: BackupPayload = {
    database: Buffer.from(databaseBytes).toString("base64"),
    keys: entries,
  };
  const plaintext = Buffer.from(JSON.stringify(payload), "utf8");

  const salt = randomBytes(16);
  const nonce = randomBytes(NONCE_BYTES);
  const key = scryptSync(passphrase, salt, RAW_KEY_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);

  const envelope: BackupEnvelope = {
    version: BACKUP_VERSION,
    kdf: "scrypt",
    salt: salt.toString("base64"),
    nonce: nonce.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    digest: sha256Hex(plaintext),
  };
  return new Uint8Array(Buffer.from(JSON.stringify(envelope), "utf8"));
}

/** Verifies and decrypts a backup, then atomically restores key files and DB.
 *  Nothing is replaced until every check has passed. */
export function restoreEncryptedBackup(
  archive: Uint8Array,
  passphrase: string,
  opts: { dataRoot: string; databasePath: string },
): void {
  let envelope: BackupEnvelope;
  try {
    envelope = JSON.parse(Buffer.from(archive).toString("utf8")) as BackupEnvelope;
  } catch {
    throw new KeyLifecycleError("backup archive is not valid JSON");
  }
  if (!envelope || envelope.version !== BACKUP_VERSION) {
    throw new KeyLifecycleError(`unsupported backup version: ${envelope?.version}`);
  }
  if (envelope.kdf !== "scrypt") {
    throw new KeyLifecycleError(`unsupported backup KDF: ${envelope.kdf}`);
  }

  const salt = Buffer.from(envelope.salt, "base64");
  const nonce = Buffer.from(envelope.nonce, "base64");
  const ciphertext = Buffer.from(envelope.ciphertext, "base64");
  if (nonce.length !== NONCE_BYTES || ciphertext.length < GCM_TAG_BYTES) {
    throw new KeyLifecycleError("backup archive is malformed");
  }

  const key = scryptSync(passphrase, salt, RAW_KEY_BYTES);
  const tag = ciphertext.subarray(ciphertext.length - GCM_TAG_BYTES);
  const data = ciphertext.subarray(0, ciphertext.length - GCM_TAG_BYTES);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  decipher.setAuthTag(tag);

  let plaintext: Buffer;
  try {
    plaintext = Buffer.concat([decipher.update(data), decipher.final()]);
  } catch {
    throw new KeyLifecycleError(
      "backup authentication failed: wrong passphrase or tampered archive",
    );
  }
  if (sha256Hex(plaintext) !== envelope.digest) {
    throw new KeyLifecycleError("backup digest mismatch: archive is corrupted");
  }

  let payload: BackupPayload;
  try {
    payload = JSON.parse(plaintext.toString("utf8")) as BackupPayload;
  } catch {
    throw new KeyLifecycleError("backup payload is not valid JSON");
  }
  if (!payload || typeof payload.database !== "string" || !Array.isArray(payload.keys)) {
    throw new KeyLifecycleError("backup payload is malformed");
  }

  const databaseBytes = new Uint8Array(Buffer.from(payload.database, "base64"));
  const keyFiles = new Map<string, Uint8Array>();
  for (const entry of payload.keys) {
    if (!entry || typeof entry.issuanceId !== "string" || typeof entry.privateKey !== "string") {
      throw new KeyLifecycleError("backup key entry is malformed");
    }
    if (keyFiles.has(entry.issuanceId)) {
      throw new KeyLifecycleError(`duplicate backup key for issuance ${entry.issuanceId}`);
    }
    const privateKey = new Uint8Array(Buffer.from(entry.privateKey, "base64"));
    if (privateKey.length !== RAW_KEY_BYTES || isNil(privateKey)) {
      throw new KeyLifecycleError(`invalid backup key material for issuance ${entry.issuanceId}`);
    }
    keyFiles.set(entry.issuanceId, privateKey);
  }

  const issuanceIds = issuanceIdsFromSnapshot(databaseBytes);
  if (issuanceIds.size !== keyFiles.size) {
    throw new KeyLifecycleError("backup key set does not match database issuances");
  }
  for (const issuanceId of issuanceIds) {
    if (!keyFiles.has(issuanceId)) {
      throw new KeyLifecycleError(`backup is missing a key for issuance ${issuanceId}`);
    }
  }
  for (const issuanceId of keyFiles.keys()) {
    if (!issuanceIds.has(issuanceId)) {
      throw new KeyLifecycleError(`backup has a key with no matching issuance ${issuanceId}`);
    }
  }

  // All validation passed; stage the replacements.
  for (const [issuanceId, privateKey] of keyFiles) {
    writeFileAtomic(keyFilePath(opts.dataRoot, issuanceId), privateKey, KEY_FILE_MODE);
  }
  writeFileAtomic(opts.databasePath, databaseBytes, KEY_FILE_MODE);
}
