// Task 48 unified ingest pipeline tests.
//
// Envelopes and issuances are built in-test from extractor-produced fixture
// data (`fixtures/crypto-vectors.json`) and a minimal report JSON that mirrors
// the real serialized extractor shape (nested `scan`/`metadata`, camelCase
// fields, `DegradedPartial`/`NotApplicable` enum variant names).

import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { Database } from "bun:sqlite";
import {
  createCipheriv,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
} from "node:crypto";
import { zstdCompressSync } from "node:zlib";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openDb, runMigrations } from "./db";
import { KeyLifecycle, keygen } from "./keys";
import { SLOT_MAGIC, createArtifact, patch } from "./patcher";
import { hashCampaignToken } from "./campaigns";
import {
  REJECTION_CODES,
  configureIngest,
  ingestBatch,
  resetIngest,
  validateAndIngestEnvelope,
  type IngestResult,
} from "./ingest";
import { computeCoverage, computeRiskScore, computeSummary } from "./metrics";
import { REPORT_ARRIVED_EVENT, reportEvents, type SseEvent } from "./sse";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const vectors = JSON.parse(
  readFileSync(join(import.meta.dir, "..", "..", "fixtures", "crypto-vectors.json"), "utf8"),
) as any[];

// Bun's node:crypto (1.4.x) does not expose ChaCha20-Poly1305, so the
// end-to-end fixtures use the suite-1 (AES-256-GCM) vector. Both are
// extractor-produced; only the cipher primitive differs.
const basic = vectors.find((vector) => vector.name === "suite1-basic");
if (!basic) throw new Error("crypto-vectors.json is missing suite1-basic");

const PKCS8_X25519_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const SPKI_X25519_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

function rawPrivKey(priv: Buffer) {
  return createPrivateKey({
    key: Buffer.concat([PKCS8_X25519_PREFIX, priv]),
    format: "der",
    type: "pkcs8",
  });
}

function rawPubKey(pub: Buffer) {
  return createPublicKey({
    key: Buffer.concat([SPKI_X25519_PREFIX, pub]),
    format: "der",
    type: "spki",
  });
}

function sharedSecret(priv: Buffer, pub: Buffer): Buffer {
  return Buffer.from(
    diffieHellman({ privateKey: rawPrivKey(priv), publicKey: rawPubKey(pub) }),
  );
}

function deriveKey(shared: Buffer, salt: Buffer, info: Buffer): Buffer {
  return Buffer.from(hkdfSync("sha256", shared, salt, info, 32));
}

function u16le(value: number): Buffer {
  const buffer = Buffer.alloc(2);
  buffer.writeUInt16LE(value, 0);
  return buffer;
}

function u64le(value: number): Buffer {
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64LE(BigInt(value), 0);
  return buffer;
}

function uuidHex(bytes: Buffer): string {
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

function ephemeral(): { pub: Buffer; priv: Buffer } {
  const pair = generateKeyPairSync("x25519");
  const pub = Buffer.from((pair.publicKey.export({ format: "jwk" }) as { x: string }).x, "base64url");
  const priv = Buffer.from((pair.privateKey.export({ format: "jwk" }) as { d: string }).d, "base64url");
  return { pub, priv };
}

type SealOptions = {
  recipientPub: Buffer;
  keyId: number;
  extractorId: Buffer;
  suite?: 0 | 1;
  scanId?: Buffer;
};

function sealV2(payload: Buffer, options: SealOptions): Uint8Array {
  const suite = options.suite ?? 1;
  const scanId = options.scanId ?? randomBytes(16);
  const eph = ephemeral();
  const plaintext = zstdCompressSync(payload);
  const salt = Buffer.concat([scanId, eph.pub]);
  const info = Buffer.concat([
    Buffer.from("HBS-report-v2", "ascii"),
    Buffer.from([suite]),
    u16le(options.keyId),
    options.extractorId,
  ]);
  const key = deriveKey(sharedSecret(eph.priv, options.recipientPub), salt, info);
  const nonce = randomBytes(12);

  const header = Buffer.alloc(93);
  header.write("HBS2", 0, "ascii");
  header.writeUInt16LE(2, 4);
  header[6] = suite;
  header.writeUInt16LE(options.keyId, 7);
  options.extractorId.copy(header, 9);
  scanId.copy(header, 25);
  eph.pub.copy(header, 41);
  nonce.copy(header, 73);
  u64le(plaintext.length + 16).copy(header, 85);

  // `createCipheriv` typings only model known GCM algorithms; the union of
  // suite ciphers defeats overload resolution, so call it dynamically.
  const cipher = (createCipheriv as any)(
    suite === 0 ? "chacha20-poly1305" : "aes-256-gcm",
    key,
    nonce,
    { authTagLength: 16 },
  );
  cipher.setAAD(header);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  return new Uint8Array(Buffer.concat([header, ciphertext]));
}

function sealV1(
  payload: Buffer,
  options: { recipientPub: Buffer; keyId: number; suite?: 0 | 1; scanId?: Buffer },
): Uint8Array {
  const suite = options.suite ?? 1;
  const scanId = options.scanId ?? randomBytes(16);
  const eph = ephemeral();
  const plaintext = zstdCompressSync(payload);
  const salt = Buffer.concat([scanId, eph.pub]);
  const info = Buffer.concat([
    Buffer.from("HBS-report-v1", "ascii"),
    Buffer.from([suite]),
    u16le(options.keyId),
  ]);
  const key = deriveKey(sharedSecret(eph.priv, options.recipientPub), salt, info);
  const nonce = randomBytes(12);

  const header = Buffer.alloc(77);
  header.write("HBS1", 0, "ascii");
  header.writeUInt16LE(1, 4);
  header[6] = suite;
  header.writeUInt16LE(options.keyId, 7);
  scanId.copy(header, 9);
  eph.pub.copy(header, 25);
  nonce.copy(header, 57);
  u64le(plaintext.length + 16).copy(header, 69);

  const cipher = (createCipheriv as any)(
    suite === 0 ? "chacha20-poly1305" : "aes-256-gcm",
    key,
    nonce,
    { authTagLength: 16 },
  );
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  return new Uint8Array(Buffer.concat([header, ciphertext]));
}

// ---------------------------------------------------------------------------
// Report shape (mirrors extractor/src/model.rs + report.rs serialization)
// ---------------------------------------------------------------------------

function result(id: string, status: string, severity: string): Record<string, unknown> {
  return {
    id,
    title: `check ${id}`,
    status,
    severity,
    category: "Test",
    description: "description",
    impact: "impact",
    recommendation: "recommendation",
    references: ["CIS-1.1"],
    evidence: "EVIDENCE_SENTINEL",
    location: "/etc/example.conf",
    repro: "cat /etc/example.conf",
    degradedReason: null,
    fallbackLog: [{ source: "/etc/example.conf", outcome: "read" }],
    evidenceBlocks: [],
    runContext: { user: "root", uid: 0, elevated: false },
    durationMs: 3,
  };
}

function defaultResults(): Record<string, unknown>[] {
  return [
    result("LIN-001", "NonCompliant", "Critical"),
    result("LIN-002", "Compliant", "High"),
    result("LIN-003", "NonCompliant", "Medium"),
  ];
}

type MakeReportOptions = {
  extractorId: Buffer;
  campaignId: string;
  keyId: number;
  schemaVersion?: number;
  machineId?: string;
  hostname?: string;
  results?: Record<string, unknown>[];
  summary?: Record<string, unknown>;
  scan?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
};

function makeReport(options: MakeReportOptions): Record<string, unknown> {
  const machineId = options.machineId ?? "machine-aaaa";
  const hostname = options.hostname ?? "host-alpha";
  return {
    schemaVersion: options.schemaVersion ?? 1,
    scan: {
      peakRssKb: 2048,
      extractorId: uuidHex(options.extractorId),
      campaignId: options.campaignId,
      keyId: options.keyId,
      machineId,
      hostname,
      platform: "Linux",
      osName: "Ubuntu",
      osVersion: "22.04",
      arch: "x86_64",
      privileged: false,
      extractorVersion: "0.1.0",
      privilege: "degraded",
      elevationStatus: "not-needed",
      privilegeRequested: false,
      privilegeGranted: false,
      privilegeRefused: false,
      startedUnix: Math.floor(Date.now() / 1000),
      durationMs: 1234,
      catalogFingerprint: "fingerprint-abc",
      ...options.scan,
    },
    metadata: {
      hostname,
      machine_id: machineId,
      os_name: "Ubuntu",
      arch: "x86_64",
      ...options.metadata,
    },
    results: options.results ?? defaultResults(),
    summary: options.summary ?? {
      compliant: 999,
      nonCompliant: 999,
      notApplicable: 0,
      error: 0,
      degraded: 0,
      informational: 0,
    },
    selfAudit: { commands: ["uname -a"], filesRead: ["/etc/hostname"] },
  };
}

// ---------------------------------------------------------------------------
// DB helpers
// ---------------------------------------------------------------------------

let db: Database;
let dataRoot: string;

function seedCampaign(): void {
  db.query(
    "INSERT INTO campaigns (id, name, created_at, updated_at) VALUES (1, 'Camp', '2026-01-01', '2026-01-01')",
  ).run();
  db.query(
    "INSERT INTO locations (id, campaign_id, name, created_at, updated_at) VALUES (1, 1, 'HQ', '2026-01-01', '2026-01-01')",
  ).run();
}

function addLocation(id: number, name: string): void {
  db.query(
    "INSERT INTO locations (id, campaign_id, name, created_at, updated_at) VALUES (?, 1, ?, '2026-01-01', '2026-01-01')",
  ).run(id, name);
}

function ensureTokenTable(): void {
  db.run(`CREATE TABLE IF NOT EXISTS campaign_tokens (
    campaign_id INTEGER NOT NULL REFERENCES campaigns(id),
    kind TEXT NOT NULL CHECK (kind IN ('download','push')),
    token_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (campaign_id, kind)
  )`);
}

function setPushToken(token: string): void {
  ensureTokenTable();
  db.query(
    "INSERT INTO campaign_tokens (campaign_id, kind, token_hash, created_at) VALUES (1, 'push', ?, '2026-01-01')",
  ).run(hashCampaignToken(token));
}

function insertIssuance(options: {
  id: string;
  extractorId: string;
  keyId: string;
  campaignId?: number;
  locationId?: number;
  artifactPath?: string | null;
  revokedAt?: string | null;
  legacy?: boolean;
}): void {
  db.query(
    `INSERT INTO issuances
       (id, extractor_id, campaign_id, location_id, key_id, artifact_path, is_legacy_v1, revoked_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, '2026-01-01')`,
  ).run(
    options.id,
    options.extractorId,
    options.campaignId ?? 1,
    options.locationId ?? 1,
    options.keyId,
    options.artifactPath ?? null,
    options.legacy ? 1 : 0,
    options.revokedAt ?? null,
  );
}

function makeArtifact(
  issuanceId: string,
  options: { keyId: number; campaignId: Buffer; extractorId: Buffer; publicKey: Buffer },
): string {
  const template = new Uint8Array(1024);
  template.set(SLOT_MAGIC, 0);
  template.fill(0xaa, 8, 480);
  const now = Math.floor(Date.now() / 1000);
  const patched = patch(template, {
    keyId: options.keyId,
    campaignId: options.campaignId,
    extractorId: options.extractorId,
    publicKey: options.publicKey,
    issuedAt: now - 1000,
    expiry: now + 100_000,
  });
  return createArtifact(patched.bytes, issuanceId, { dataRoot }).path;
}

function addIssuance(options: {
  id: string;
  extractorIdHex: string;
  keyId: number;
  keypair: { publicKey: Uint8Array; privateKey: Uint8Array };
  campaignId?: number;
  locationId?: number;
  legacy?: boolean;
  revokedAt?: string | null;
  artifact?: { campaignUuid: Buffer } | null;
}): string | null {
  let artifactPath: string | null = null;
  if (options.artifact) {
    artifactPath = makeArtifact(options.id, {
      keyId: options.keyId,
      campaignId: options.artifact.campaignUuid,
      extractorId: Buffer.from(options.extractorIdHex, "hex"),
      publicKey: Buffer.from(options.keypair.publicKey),
    });
  }
  insertIssuance({
    id: options.id,
    extractorId: options.extractorIdHex,
    keyId: String(options.keyId),
    campaignId: options.campaignId,
    locationId: options.locationId,
    artifactPath,
    legacy: options.legacy,
    revokedAt: options.revokedAt,
  });
  new KeyLifecycle(db, { dataRoot }).saveKey(
    options.id,
    options.keypair.privateKey,
    options.keypair.publicKey,
  );
  return artifactPath;
}

type Issuance = {
  id: string;
  extractorId: Buffer;
  extractorIdHex: string;
  keyId: number;
  keypair: { publicKey: Uint8Array; privateKey: Uint8Array };
  campaignUuid: Buffer;
  campaignUuidStr: string;
};

function standardV2(options: { id?: string; locationId?: number } = {}): Issuance {
  const extractorId = randomBytes(16);
  const extractorIdHex = extractorId.toString("hex");
  const keyId = 7;
  const keypair = keygen();
  const campaignUuid = randomBytes(16);
  const id = options.id ?? `iss-${randomBytes(4).toString("hex")}`;
  addIssuance({
    id,
    extractorIdHex,
    keyId,
    keypair,
    locationId: options.locationId,
    artifact: { campaignUuid },
  });
  return {
    id,
    extractorId,
    extractorIdHex,
    keyId,
    keypair,
    campaignUuid,
    campaignUuidStr: uuidHex(campaignUuid),
  };
}

function sealFor(
  issuance: Issuance,
  reportOverrides: Partial<MakeReportOptions> = {},
  scanId?: Buffer,
  suite: 0 | 1 = 1,
): Uint8Array {
  const report = makeReport({
    extractorId: issuance.extractorId,
    campaignId: issuance.campaignUuidStr,
    keyId: issuance.keyId,
    ...reportOverrides,
  });
  return sealV2(Buffer.from(JSON.stringify(report)), {
    recipientPub: Buffer.from(issuance.keypair.publicKey),
    keyId: issuance.keyId,
    extractorId: issuance.extractorId,
    suite,
    scanId,
  });
}

function session(): { kind: "session" } {
  return { kind: "session" };
}

function rowCount(table: string): number {
  return (db.query(`SELECT COUNT(*) AS count FROM ${table}`).get() as { count: number }).count;
}

beforeEach(() => {
  db = openDb(":memory:");
  runMigrations(db);
  dataRoot = mkdtempSync(join(tmpdir(), "hbs-ingest-"));
  seedCampaign();
  configureIngest({ db, dataRoot, bus: reportEvents });
});

afterEach(() => {
  resetIngest();
  reportEvents.clear();
  rmSync(dataRoot, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// Pure metrics (hand-computed)
// ---------------------------------------------------------------------------

describe("metrics", () => {
  it("computes summary counts exactly like the extractor", () => {
    const results = [
      result("A", "Compliant", "High"),
      result("B", "NonCompliant", "Critical"),
      result("C", "NotApplicable", "Low"),
      result("D", "Error", "Medium"),
      result("E", "DegradedPartial", "High"),
      result("F", "Compliant", "Informational"),
    ];
    expect(computeSummary(results)).toEqual({
      compliant: 2,
      nonCompliant: 1,
      notApplicable: 1,
      error: 1,
      degraded: 1,
      informational: 1,
    });
  });

  it("computes weighted risk excluding N/A and Info", () => {
    const results = [
      result("A", "NonCompliant", "Critical"), // 10 failed / 10 applicable
      result("B", "Compliant", "High"), // 6 applicable
      result("C", "NonCompliant", "Medium"), // 3 failed / 3 applicable
      result("D", "Compliant", "Low"), // 1 applicable
      result("E", "NonCompliant", "Informational"), // weight 0
      result("F", "NotApplicable", "High"), // excluded
      result("G", "Error", "Medium"), // 3 applicable, not failed
      result("H", "DegradedPartial", "High"), // 6 applicable, not failed
    ];
    // numerator 13, denominator 29
    expect(computeRiskScore(results)).toBeCloseTo(100 * (1 - 13 / 29), 6);
  });

  it("returns 100 for an empty/weightless scope", () => {
    expect(computeRiskScore([result("A", "NotApplicable", "Critical")])).toBe(100);
    expect(computeRiskScore([])).toBe(100);
  });

  it("removes accepted_risk/false_positive from numerator but keeps denominator", () => {
    const results = [
      result("A", "NonCompliant", "Critical"), // 10
      result("B", "Compliant", "High"), // 6
    ];
    const open = computeRiskScore(results);
    expect(open).toBeCloseTo(100 * (1 - 10 / 16), 6);
    const accepted = computeRiskScore(results, (id) => (id === "A" ? "accepted_risk" : undefined));
    expect(accepted).toBe(100); // 0 failed / 16 applicable
    const falsePositive = computeRiskScore(results, (id) => (id === "A" ? "false_positive" : undefined));
    expect(falsePositive).toBe(100);
  });

  it("computes coverage as decided applicable over applicable", () => {
    const results = [
      result("A", "Compliant", "High"),
      result("B", "NonCompliant", "High"),
      result("C", "NotApplicable", "High"),
      result("D", "Error", "High"),
      result("E", "DegradedPartial", "High"),
    ];
    // applicable 4, decided 2
    expect(computeCoverage(results)).toBeCloseTo(50, 6);
  });
});

// ---------------------------------------------------------------------------
// Bounds and schema
// ---------------------------------------------------------------------------

describe("ingest bounds and schema", () => {
  it("rejects an envelope over the 16 MiB limit before parsing", async () => {
    const oversized = new Uint8Array(16 * 1024 * 1024 + 1);
    const result = await validateAndIngestEnvelope(oversized, "upload", session());
    expect(result).toEqual({ ok: false, code: REJECTION_CODES.TOO_LARGE });
  });

  it("rejects trailing bytes after the ciphertext", async () => {
    const issuance = standardV2();
    const valid = sealFor(issuance);
    const trailing = new Uint8Array(valid.length + 1);
    trailing.set(valid);
    trailing[valid.length] = 0;
    const result = await validateAndIngestEnvelope(trailing, "upload", session());
    expect(result).toEqual({ ok: false, code: REJECTION_CODES.TRAILING_BYTES });
  });

  it("rejects more than 1000 results", async () => {
    const issuance = standardV2();
    const results = Array.from({ length: 1001 }, (_, i) =>
      result(`LIN-${String(i).padStart(4, "0")}`, "Compliant", "Low"),
    );
    const outcome = await validateAndIngestEnvelope(
      sealFor(issuance, { results }),
      "upload",
      session(),
    );
    expect(outcome).toEqual({ ok: false, code: REJECTION_CODES.RESULTS_TOO_MANY });
  });

  it("rejects JSON nesting deeper than 32", async () => {
    const issuance = standardV2();
    let nested: unknown = 0;
    for (let i = 0; i < 40; i += 1) nested = [nested];
    const result = await validateAndIngestEnvelope(
      sealFor(issuance, { scan: { extra: nested } }),
      "upload",
      session(),
    );
    expect(result).toEqual({ ok: false, code: REJECTION_CODES.JSON_DEPTH_EXCEEDED });
  });

  it("rejects a string longer than 1 MiB", async () => {
    const issuance = standardV2();
    const result = await validateAndIngestEnvelope(
      sealFor(issuance, { scan: { hostname: "a".repeat(1024 * 1024 + 1) } }),
      "upload",
      session(),
    );
    expect(result).toEqual({ ok: false, code: REJECTION_CODES.STRING_TOO_LONG });
  });

  it("rejects an array longer than 10,000 elements", async () => {
    const issuance = standardV2();
    const result = await validateAndIngestEnvelope(
      sealFor(issuance, { scan: { extra: new Array(10_001).fill("x") } }),
      "upload",
      session(),
    );
    expect(result).toEqual({ ok: false, code: REJECTION_CODES.ARRAY_TOO_LONG });
  });

  it("rejects malformed JSON with SCHEMA_INVALID", async () => {
    const issuance = standardV2();
    const bytes = sealV2(Buffer.from("not valid json"), {
      recipientPub: Buffer.from(issuance.keypair.publicKey),
      keyId: issuance.keyId,
      extractorId: issuance.extractorId,
    });
    const result = await validateAndIngestEnvelope(bytes, "upload", session());
    expect(result).toEqual({ ok: false, code: REJECTION_CODES.SCHEMA_INVALID });
  });

  it("rejects a future schema version", async () => {
    const issuance = standardV2();
    const result = await validateAndIngestEnvelope(
      sealFor(issuance, { schemaVersion: 2 }),
      "upload",
      session(),
    );
    expect(result).toEqual({ ok: false, code: REJECTION_CODES.SCHEMA_VERSION_UNSUPPORTED });
  });

  it("rejects duplicate check IDs", async () => {
    const issuance = standardV2();
    const results = [
      result("LIN-001", "Compliant", "Low"),
      result("LIN-001", "NonCompliant", "High"),
    ];
    const outcome = await validateAndIngestEnvelope(
      sealFor(issuance, { results }),
      "upload",
      session(),
    );
    expect(outcome).toEqual({ ok: false, code: REJECTION_CODES.DUPLICATE_CHECK_ID });
  });

  it("rejects a whitespace-only machine id", async () => {
    const issuance = standardV2();
    const result = await validateAndIngestEnvelope(
      sealFor(issuance, { machineId: "   " }),
      "upload",
      session(),
    );
    expect(result).toEqual({ ok: false, code: REJECTION_CODES.EMPTY_MACHINE_ID });
  });

  it("rejects an empty hostname", async () => {
    const issuance = standardV2();
    const result = await validateAndIngestEnvelope(
      sealFor(issuance, { hostname: "  " }),
      "upload",
      session(),
    );
    expect(result).toEqual({ ok: false, code: REJECTION_CODES.EMPTY_HOSTNAME });
  });

  it("leaves no host/report/host_location rows on rejection", async () => {
    const before = {
      hosts: rowCount("hosts"),
      reports: rowCount("reports"),
      hostLocations: rowCount("host_locations"),
    };
    const result = await validateAndIngestEnvelope(new Uint8Array([1, 2, 3]), "upload", session());
    expect(result.ok).toBe(false);
    expect(rowCount("hosts")).toBe(before.hosts);
    expect(rowCount("reports")).toBe(before.reports);
    expect(rowCount("host_locations")).toBe(before.hostLocations);
    const events = db.query("SELECT accepted FROM ingest_events").all() as { accepted: number }[];
    expect(events.some((event) => event.accepted === 0)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Identity, authentication, resolution
// ---------------------------------------------------------------------------

describe("ingest identity and authentication", () => {
  it("ingests a fixture-keyed v2 envelope and derives routing from the issuance", async () => {
    const campaignUuid = randomBytes(16);
    addIssuance({
      id: "iss-fixture",
      extractorIdHex: basic.extractorIdHex,
      keyId: basic.keyId,
      keypair: {
        publicKey: Buffer.from(basic.recipientPubHex, "hex"),
        privateKey: Buffer.from(basic.recipientPrivHex, "hex"),
      },
      artifact: { campaignUuid },
    });
    const report = makeReport({
      extractorId: Buffer.from(basic.extractorIdHex, "hex"),
      campaignId: uuidHex(campaignUuid),
      keyId: basic.keyId,
      machineId: "machine-fixture",
      hostname: "vec-host-01",
    });
    const bytes = sealV2(Buffer.from(JSON.stringify(report)), {
      recipientPub: Buffer.from(basic.recipientPubHex, "hex"),
      keyId: basic.keyId,
      extractorId: Buffer.from(basic.extractorIdHex, "hex"),
      suite: basic.suite as 0 | 1,
    });

    const result = await validateAndIngestEnvelope(bytes, "upload", session());
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.duplicate).toBe(false);
    expect(result.campaignId).toBe(1);
    expect(result.locationId).toBe(1);
    expect(result.hostId).toBeGreaterThan(0);
    expect(result.links).toEqual({
      campaign: "/api/campaigns/1",
      location: "/api/campaigns/1/locations/1",
      host: `/api/hosts/${result.hostId}`,
      report: `/api/reports/${result.reportId}`,
    });
    expect(rowCount("hosts")).toBe(1);
    expect(rowCount("host_locations")).toBe(1);
    expect(rowCount("reports")).toBe(1);
    const stored = db.query("SELECT * FROM reports WHERE id = ?").get(result.reportId) as any;
    expect(stored.campaign_id).toBe(1);
    expect(stored.location_id).toBe(1);
    expect(stored.issuance_id).toBe("iss-fixture");
  });

  it("returns the original report idempotently on duplicate replay", async () => {
    const issuance = standardV2();
    const bytes = sealFor(issuance);
    const first = await validateAndIngestEnvelope(bytes, "upload", session());
    const second = await validateAndIngestEnvelope(bytes, "upload", session());
    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    if (!first.ok || !second.ok) return;
    expect(second.duplicate).toBe(true);
    expect(second.reportId).toBe(first.reportId);
    expect(second.links).toEqual(first.links);
    expect(rowCount("reports")).toBe(1);
  });

  it("rejects a v2 envelope from an unknown extractor", async () => {
    const extractorId = randomBytes(16);
    const keypair = keygen();
    const report = makeReport({
      extractorId,
      campaignId: uuidHex(randomBytes(16)),
      keyId: 7,
      machineId: "m",
      hostname: "h",
    });
    const bytes = sealV2(Buffer.from(JSON.stringify(report)), {
      recipientPub: Buffer.from(keypair.publicKey),
      keyId: 7,
      extractorId,
    });
    const result = await validateAndIngestEnvelope(bytes, "upload", session());
    expect(result).toEqual({ ok: false, code: REJECTION_CODES.UNKNOWN_ISSUANCE });
  });

  it("rejects a revoked v2 issuance", async () => {
    const issuance = standardV2();
    db.query("UPDATE issuances SET revoked_at = '2026-02-01' WHERE id = ?").run(issuance.id);
    const result = await validateAndIngestEnvelope(sealFor(issuance), "upload", session());
    expect(result).toEqual({ ok: false, code: REJECTION_CODES.REVOKED_ISSUANCE });
  });

  it("rejects a v2 header key id that disagrees with the issuance", async () => {
    const issuance = standardV2();
    const wrongKeyId = issuance.keyId + 1;
    const report = makeReport({
      extractorId: issuance.extractorId,
      campaignId: issuance.campaignUuidStr,
      keyId: wrongKeyId,
      machineId: "m",
      hostname: "h",
    });
    const bytes = sealV2(Buffer.from(JSON.stringify(report)), {
      recipientPub: Buffer.from(issuance.keypair.publicKey),
      keyId: wrongKeyId,
      extractorId: issuance.extractorId,
    });
    const result = await validateAndIngestEnvelope(bytes, "upload", session());
    expect(result).toEqual({ ok: false, code: REJECTION_CODES.KEY_ID_MISMATCH });
  });

  it("rejects a v2 inner extractor id that disagrees with the header", async () => {
    const issuance = standardV2();
    const result = await validateAndIngestEnvelope(
      sealFor(issuance, { extractorId: randomBytes(16) }),
      "upload",
      session(),
    );
    expect(result).toEqual({ ok: false, code: REJECTION_CODES.INNER_IDENTITY_MISMATCH });
  });

  it("rejects a v2 inner campaign id that disagrees with the issuance", async () => {
    const issuance = standardV2();
    const result = await validateAndIngestEnvelope(
      sealFor(issuance, { campaignId: uuidHex(randomBytes(16)) }),
      "upload",
      session(),
    );
    expect(result).toEqual({ ok: false, code: REJECTION_CODES.INNER_IDENTITY_MISMATCH });
  });

  it("ingests a valid legacy v1 envelope and verifies inner identity", async () => {
    const pair = keygen();
    const extractorId = randomBytes(16);
    addIssuance({
      id: "iss-v1-valid",
      extractorIdHex: extractorId.toString("hex"),
      keyId: 7,
      keypair: pair,
      legacy: true,
    });
    const report = makeReport({
      extractorId,
      campaignId: "1",
      keyId: 7,
      machineId: "machine-v1",
      hostname: "v1-host",
    });
    const bytes = sealV1(Buffer.from(JSON.stringify(report)), {
      recipientPub: Buffer.from(pair.publicKey),
      keyId: 7,
    });
    const result = await validateAndIngestEnvelope(bytes, "upload", session());
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.campaignId).toBe(1);
    expect(rowCount("reports")).toBe(1);
  });

  it("rejects an ambiguous legacy v1 key id", async () => {
    const extractorId = randomBytes(16);
    addIssuance({
      id: "iss-v1-a",
      extractorIdHex: extractorId.toString("hex"),
      keyId: 7,
      keypair: keygen(),
      legacy: true,
    });
    insertIssuance({
      id: "iss-v1-b",
      extractorId: randomBytes(16).toString("hex"),
      keyId: "07",
      legacy: true,
    });
    const bytes = sealV1(Buffer.from("{}"), {
      recipientPub: Buffer.from(keygen().publicKey),
      keyId: 7,
    });
    const result = await validateAndIngestEnvelope(bytes, "upload", session());
    expect(result).toEqual({ ok: false, code: REJECTION_CODES.AMBIGUOUS_V1_KEY });
  });

  it("rejects a revoked legacy v1 issuance", async () => {
    addIssuance({
      id: "iss-v1-revoked",
      extractorIdHex: randomBytes(16).toString("hex"),
      keyId: 7,
      keypair: keygen(),
      legacy: true,
      revokedAt: "2026-02-01",
    });
    const bytes = sealV1(Buffer.from("{}"), {
      recipientPub: Buffer.from(keygen().publicKey),
      keyId: 7,
    });
    const result = await validateAndIngestEnvelope(bytes, "upload", session());
    expect(result).toEqual({ ok: false, code: REJECTION_CODES.REVOKED_ISSUANCE });
  });

  it("rejects a v1 inner extractor id mismatch after decryption", async () => {
    const pair = keygen();
    const extractorId = randomBytes(16);
    addIssuance({
      id: "iss-v1-mismatch",
      extractorIdHex: extractorId.toString("hex"),
      keyId: 7,
      keypair: pair,
      legacy: true,
    });
    const report = makeReport({
      extractorId: randomBytes(16),
      campaignId: "1",
      keyId: 7,
      machineId: "m",
      hostname: "h",
    });
    const bytes = sealV1(Buffer.from(JSON.stringify(report)), {
      recipientPub: Buffer.from(pair.publicKey),
      keyId: 7,
    });
    const result = await validateAndIngestEnvelope(bytes, "upload", session());
    expect(result).toEqual({ ok: false, code: REJECTION_CODES.INNER_IDENTITY_MISMATCH });
  });

  it("accepts a push with the correct token", async () => {
    const issuance = standardV2();
    setPushToken("push-secret-token");
    const result = await validateAndIngestEnvelope(sealFor(issuance), "push", {
      kind: "push",
      token: "push-secret-token",
    });
    expect(result.ok).toBe(true);
  });

  it("rejects a push with a missing token", async () => {
    const issuance = standardV2();
    setPushToken("push-secret-token");
    const result = await validateAndIngestEnvelope(sealFor(issuance), "push", {
      kind: "push",
      token: "",
    });
    expect(result).toEqual({ ok: false, code: REJECTION_CODES.MISSING_PUSH_TOKEN });
  });

  it("rejects a push with a wrong token", async () => {
    const issuance = standardV2();
    setPushToken("push-secret-token");
    const result = await validateAndIngestEnvelope(sealFor(issuance), "push", {
      kind: "push",
      token: "wrong-token",
    });
    expect(result).toEqual({ ok: false, code: REJECTION_CODES.INVALID_PUSH_TOKEN });
  });

  it("rejects upload with push auth and push with session auth", async () => {
    const upload = await validateAndIngestEnvelope(new Uint8Array(0), "upload", {
      kind: "push",
      token: "x",
    });
    expect(upload).toEqual({ ok: false, code: REJECTION_CODES.AUTH_REQUIRED });
    const push = await validateAndIngestEnvelope(new Uint8Array(0), "push", session());
    expect(push).toEqual({ ok: false, code: REJECTION_CODES.AUTH_REQUIRED });
  });
});

// ---------------------------------------------------------------------------
// Routing, hosts, batches
// ---------------------------------------------------------------------------

describe("ingest routing and host identity", () => {
  it("preserves the host id across a hostname rename", async () => {
    const issuance = standardV2();
    const first = await validateAndIngestEnvelope(
      sealFor(issuance, { machineId: "machine-rename", hostname: "alpha" }),
      "upload",
      session(),
    );
    expect(first.ok).toBe(true);
    const second = await validateAndIngestEnvelope(
      sealFor(issuance, { machineId: "machine-rename", hostname: "beta" }),
      "upload",
      session(),
    );
    expect(second.ok).toBe(true);
    if (!first.ok || !second.ok) return;
    expect(second.hostId).toBe(first.hostId);
    expect(rowCount("hosts")).toBe(1);
    const host = db.query("SELECT hostname FROM hosts WHERE id = ?").get(first.hostId) as {
      hostname: string;
    };
    expect(host.hostname).toBe("beta");
  });

  it("keeps identical hostnames with different machine ids distinct", async () => {
    const issuance = standardV2();
    const first = await validateAndIngestEnvelope(
      sealFor(issuance, { machineId: "machine-a", hostname: "web" }),
      "upload",
      session(),
    );
    const second = await validateAndIngestEnvelope(
      sealFor(issuance, { machineId: "machine-b", hostname: "web" }),
      "upload",
      session(),
    );
    expect(first.ok && second.ok).toBe(true);
    if (!first.ok || !second.ok) return;
    expect(first.hostId).not.toBe(second.hostId);
    expect(rowCount("hosts")).toBe(2);
  });

  it("maps one machine to multiple locations without duplicating the host", async () => {
    addLocation(2, "Branch");
    const first = standardV2({ locationId: 1 });
    const second = standardV2({ locationId: 2 });
    const a = await validateAndIngestEnvelope(
      sealFor(first, { machineId: "machine-shared", hostname: "shared" }),
      "upload",
      session(),
    );
    const b = await validateAndIngestEnvelope(
      sealFor(second, { machineId: "machine-shared", hostname: "shared" }),
      "upload",
      session(),
    );
    expect(a.ok && b.ok).toBe(true);
    if (!a.ok || !b.ok) return;
    expect(a.hostId).toBe(b.hostId);
    expect(rowCount("hosts")).toBe(1);
    const locations = db
      .query("SELECT location_id FROM host_locations WHERE host_id = ? ORDER BY location_id")
      .all(a.hostId) as { location_id: number }[];
    expect(locations.map((row) => row.location_id)).toEqual([1, 2]);
  });

  it("isolates a bad file from a valid sibling in a batch", async () => {
    const issuance = standardV2();
    const results = await ingestBatch(
      [
        { name: "good.hbs", bytes: sealFor(issuance) },
        { name: "bad.hbs", bytes: new Uint8Array([1, 2, 3]) },
      ],
      session(),
    );
    expect(results).toHaveLength(2);
    expect(results[0].name).toBe("good.hbs");
    expect(results[0].result.ok).toBe(true);
    expect(results[1].name).toBe("bad.hbs");
    expect(results[1].result.ok).toBe(false);
    expect(rowCount("reports")).toBe(1);
  });

  it("rejects an oversized batch without processing any file", async () => {
    const issuance = standardV2();
    const files = Array.from({ length: 33 }, (_, i) => ({
      name: `f${i}.hbs`,
      bytes: i === 0 ? sealFor(issuance) : new Uint8Array([1, 2, 3]),
    }));
    const results = await ingestBatch(files, session());
    expect(results.every((entry) => entry.result.ok === false)).toBe(true);
    expect(results[0].result).toEqual({ ok: false, code: REJECTION_CODES.BATCH_TOO_LARGE });
    expect(rowCount("reports")).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Server-authoritative metrics + audit trail
// ---------------------------------------------------------------------------

describe("ingest server-authoritative metrics and audit", () => {
  it("recomputes tampered aggregates from raw results", async () => {
    const issuance = standardV2();
    const bytes = sealFor(issuance, {
      summary: {
        compliant: 999,
        nonCompliant: 999,
        notApplicable: 999,
        error: 999,
        degraded: 999,
        informational: 999,
      },
    });
    const result = await validateAndIngestEnvelope(bytes, "upload", session());
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const stored = db.query("SELECT * FROM reports WHERE id = ?").get(result.reportId) as any;
    expect(JSON.parse(stored.summary_json)).toEqual(
      computeSummary(defaultResults() as any),
    );
    expect(stored.score).toBeCloseTo(computeRiskScore(defaultResults() as any), 6);
    expect(stored.coverage).toBeCloseTo(computeCoverage(defaultResults() as any), 6);
    expect(JSON.parse(stored.summary_json).compliant).toBe(1);
  });

  it("stores validated report JSON and envelope bytes", async () => {
    const issuance = standardV2();
    const bytes = sealFor(issuance);
    const result = await validateAndIngestEnvelope(bytes, "upload", session());
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const stored = db.query("SELECT report_json, envelope, via, bytes FROM reports WHERE id = ?").get(
      result.reportId,
    ) as { report_json: string; envelope: Uint8Array; via: string; bytes: number };
    const parsed = JSON.parse(stored.report_json);
    expect(parsed.schemaVersion).toBe(1);
    expect(parsed.results).toHaveLength(3);
    expect(stored.via).toBe("upload");
    expect(stored.bytes).toBe(bytes.length);
    expect(new Uint8Array(stored.envelope).length).toBe(bytes.length);
  });

  it("never records evidence or secrets in ingest_events", async () => {
    const issuance = standardV2();
    setPushToken("push-secret-token");
    await validateAndIngestEnvelope(sealFor(issuance), "push", {
      kind: "push",
      token: "push-secret-token",
    });
    await validateAndIngestEnvelope(sealFor(issuance), "push", {
      kind: "push",
      token: "wrong-token",
    });
    const events = db.query("SELECT * FROM ingest_events").all() as Record<string, unknown>[];
    expect(events.length).toBeGreaterThan(0);
    for (const event of events) {
      const serialized = JSON.stringify(event);
      expect(serialized).not.toContain("EVIDENCE_SENTINEL");
      expect(serialized).not.toContain("push-secret-token");
      expect(serialized).not.toContain("wrong-token");
    }
  });

  it("emits report-arrived only after a committed new report", async () => {
    const issuance = standardV2();
    const events: SseEvent[] = [];
    const unsubscribe = reportEvents.subscribe((event) => events.push(event));

    const rejected = await validateAndIngestEnvelope(new Uint8Array([1, 2, 3]), "upload", session());
    expect(rejected.ok).toBe(false);
    expect(events).toHaveLength(0);

    const first = await validateAndIngestEnvelope(sealFor(issuance), "upload", session());
    expect(first.ok).toBe(true);
    expect(events).toHaveLength(1);
    expect(events[0].event).toBe(REPORT_ARRIVED_EVENT);
    const payload = events[0].data as { links: Record<string, string>; reportId: number };
    expect(payload.reportId).toBe((first as { reportId: number }).reportId);
    expect(Object.keys(payload.links).sort()).toEqual(["campaign", "host", "location", "report"]);
    expect(JSON.stringify(payload)).not.toContain("EVIDENCE_SENTINEL");

    unsubscribe();
  });
});
