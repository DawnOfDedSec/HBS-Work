import { createHash } from "node:crypto";
import { mkdirSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";

// Binary keyslot patcher. Contract: spec §4.6 and plan Task 45. The exact
// 512-byte layout is shared with the Rust extractor (`extractor/src/keyslot.rs`)
// and verified by cross-language fixtures.

export const SLOT_MAGIC = Buffer.from("HBSKSLOT", "ascii");
export const SLOT_LEN = 512;

export const ID_LEN = 16;
export const PUB_LEN = 32;

export type PatcherErrorCode =
  | "NO_SLOT"
  | "MULTIPLE_SLOTS"
  | "TRUNCATED_SLOT"
  | "NOT_PLACEHOLDER"
  | "BAD_KEY_ID"
  | "BAD_ID_LEN"
  | "BAD_PUB_LEN"
  | "NIL_ID"
  | "NIL_PUB"
  | "BAD_TIMESTAMPS"
  | "UNSUPPORTED_VERSION"
  | "NONZERO_FLAGS"
  | "NONZERO_RESERVED"
  | "BAD_MAGIC"
  | "CHECKSUM_MISMATCH";

export class PatcherError extends Error {
  readonly code: PatcherErrorCode;

  constructor(code: PatcherErrorCode, message: string) {
    super(message);
    this.name = "PatcherError";
    this.code = code;
  }
}

export type SlotFields = {
  slotVersion: number;
  flags: number;
  keyId: number;
  campaignId: Uint8Array;
  extractorId: Uint8Array;
  expiryUnix: number;
  issuedAtUnix: number;
  recipientPub: Uint8Array;
};

export type PatchInput = {
  keyId: number;
  campaignId: Uint8Array;
  extractorId: Uint8Array;
  publicKey: Uint8Array;
  issuedAt: number;
  expiry: number;
};

export type Artifact = { path: string; sha256: string; size: number };

function matchesMagic(bytes: Uint8Array, offset: number): boolean {
  for (let i = 0; i < SLOT_MAGIC.length; i++) {
    if (bytes[offset + i] !== SLOT_MAGIC[i]) return false;
  }
  return true;
}

function allZero(bytes: Uint8Array): boolean {
  for (const b of bytes) if (b !== 0) return false;
  return true;
}

export function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function sha256Bytes(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(bytes).digest());
}

function readU16LE(bytes: Uint8Array, offset: number): number {
  return bytes[offset] | (bytes[offset + 1] << 8);
}

function writeU16LE(bytes: Uint8Array, offset: number, value: number): void {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >>> 8) & 0xff;
}

function readU64LE(bytes: Uint8Array, offset: number): bigint {
  let value = 0n;
  for (let i = 7; i >= 0; i--) {
    value = (value << 8n) | BigInt(bytes[offset + i]);
  }
  return value;
}

function writeU64LE(bytes: Uint8Array, offset: number, value: number): void {
  let v = BigInt(value);
  for (let i = 0; i < 8; i++) {
    bytes[offset + i] = Number(v & 0xffn);
    v >>= 8n;
  }
}

/**
 * Locate the single pristine placeholder slot. The magic literal also appears
 * in program code, so occurrences without a full 512-byte region or without a
 * zero checksum are not placeholders. Rejects absent, duplicated, truncated,
 * or already-patched slots so a binary is never patched twice.
 */
export function findOnlySlot(bytes: Uint8Array): number {
  const placeholders: number[] = [];
  let sawTruncated = false;
  let sawPatched = false;

  for (let i = 0; i + SLOT_MAGIC.length <= bytes.length; i++) {
    if (!matchesMagic(bytes, i)) continue;
    if (i + SLOT_LEN > bytes.length) {
      sawTruncated = true;
      continue;
    }
    if (allZero(bytes.subarray(i + 480, i + 512))) placeholders.push(i);
    else sawPatched = true;
  }

  if (placeholders.length > 1) {
    throw new PatcherError("MULTIPLE_SLOTS", "multiple keyslot placeholders found");
  }
  if (placeholders.length === 1) return placeholders[0]!;
  if (sawTruncated) throw new PatcherError("TRUNCATED_SLOT", "keyslot placeholder is truncated");
  if (sawPatched) throw new PatcherError("NOT_PLACEHOLDER", "keyslot already patched (checksum present)");
  throw new PatcherError("NO_SLOT", "keyslot placeholder not found");
}

/**
 * Patch a copy of `template` with the issuance fields and recompute the
 * checksum over bytes 0..480. The template is never mutated.
 */
export function patch(template: Uint8Array, input: PatchInput): { bytes: Uint8Array; sha256: string } {
  const offset = findOnlySlot(template);

  if (!Number.isInteger(input.keyId) || input.keyId < 0 || input.keyId > 0xffff) {
    throw new PatcherError("BAD_KEY_ID", `key id must be a u16 (got ${input.keyId})`);
  }
  if (input.campaignId.length !== ID_LEN || input.extractorId.length !== ID_LEN) {
    throw new PatcherError("BAD_ID_LEN", "campaignId and extractorId must be 16 bytes");
  }
  if (input.publicKey.length !== PUB_LEN) {
    throw new PatcherError("BAD_PUB_LEN", "public key must be 32 bytes");
  }
  if (allZero(input.campaignId)) throw new PatcherError("NIL_ID", "campaignId is nil");
  if (allZero(input.extractorId)) throw new PatcherError("NIL_ID", "extractorId is nil");
  if (allZero(input.publicKey)) throw new PatcherError("NIL_PUB", "public key is nil");
  if (!(input.issuedAt < input.expiry)) {
    throw new PatcherError("BAD_TIMESTAMPS", "issuedAt must be before expiry");
  }

  const bytes = new Uint8Array(template); // copy
  writeU16LE(bytes, offset + 8, 1); // slot version
  writeU16LE(bytes, offset + 10, 0); // flags
  writeU16LE(bytes, offset + 12, input.keyId);
  writeU16LE(bytes, offset + 14, 0); // reserved u16
  bytes.set(input.campaignId, offset + 16);
  bytes.set(input.extractorId, offset + 32);
  writeU64LE(bytes, offset + 48, input.expiry);
  writeU64LE(bytes, offset + 56, input.issuedAt);
  bytes.set(input.publicKey, offset + 64);
  bytes.fill(0, offset + 96, offset + 480); // reserved pad
  const checksum = sha256Bytes(bytes.subarray(offset, offset + 480));
  bytes.set(checksum, offset + 480);

  return { bytes, sha256: sha256Hex(bytes) };
}

/**
 * Strictly parse a slot at `offset`, mirroring the Rust extractor's
 * validation order. Throws PatcherError with a stable code.
 */
export function readSlot(bytes: Uint8Array, offset = 0): SlotFields {
  if (offset + SLOT_LEN > bytes.length) {
    throw new PatcherError("TRUNCATED_SLOT", "keyslot is truncated");
  }
  if (!matchesMagic(bytes, offset)) {
    throw new PatcherError("BAD_MAGIC", "keyslot magic mismatch");
  }
  const expected = bytes.subarray(offset + 480, offset + 512);
  if (allZero(expected)) {
    throw new PatcherError("NOT_PLACEHOLDER", "binary not issued (placeholder keyslot)");
  }
  const slotVersion = readU16LE(bytes, offset + 8);
  if (slotVersion !== 1) {
    throw new PatcherError("UNSUPPORTED_VERSION", `unsupported keyslot version ${slotVersion}`);
  }
  const flags = readU16LE(bytes, offset + 10);
  if (flags !== 0) throw new PatcherError("NONZERO_FLAGS", `keyslot flags must be zero (got ${flags})`);
  if (readU16LE(bytes, offset + 14) !== 0) {
    throw new PatcherError("NONZERO_RESERVED", "keyslot reserved field must be zero");
  }
  if (!allZero(bytes.subarray(offset + 96, offset + 480))) {
    throw new PatcherError("NONZERO_RESERVED", "keyslot reserved pad must be zero");
  }
  const campaignId = bytes.slice(offset + 16, offset + 32);
  const extractorId = bytes.slice(offset + 32, offset + 48);
  const recipientPub = bytes.slice(offset + 64, offset + 96);
  if (allZero(campaignId)) throw new PatcherError("NIL_ID", "keyslot campaignId is nil");
  if (allZero(extractorId)) throw new PatcherError("NIL_ID", "keyslot extractorId is nil");
  if (allZero(recipientPub)) throw new PatcherError("NIL_PUB", "keyslot public key is nil");
  const expiryUnix = Number(readU64LE(bytes, offset + 48));
  const issuedAtUnix = Number(readU64LE(bytes, offset + 56));
  if (!(issuedAtUnix < expiryUnix)) {
    throw new PatcherError("BAD_TIMESTAMPS", "keyslot issuedAt must be before expiry");
  }
  const actual = sha256Bytes(bytes.subarray(offset, offset + 480));
  for (let i = 0; i < 32; i++) {
    if (actual[i] !== expected[i]) {
      throw new PatcherError("CHECKSUM_MISMATCH", "keyslot checksum mismatch (corrupted)");
    }
  }
  return {
    slotVersion,
    flags,
    keyId: readU16LE(bytes, offset + 12),
    campaignId,
    extractorId,
    expiryUnix,
    issuedAtUnix,
    recipientPub,
  };
}

/** Atomically persist patched bytes as an immutable issuance artifact. */
export function createArtifact(
  patched: Uint8Array,
  issuanceId: string,
  opts: { dataRoot: string },
): Artifact {
  if (!/^[A-Za-z0-9._-]+$/.test(issuanceId)) {
    throw new PatcherError("NIL_ID", "issuanceId contains unsafe path characters");
  }
  const dir = join(opts.dataRoot, "binaries");
  mkdirSync(dir, { recursive: true });
  const path = join(dir, issuanceId);
  const tmp = `${path}.tmp-${process.pid}-${Date.now()}`;
  writeFileSync(tmp, patched);
  renameSync(tmp, path);
  return { path, sha256: sha256Hex(patched), size: patched.length };
}
