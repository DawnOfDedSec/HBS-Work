// Bounded sealed-report envelope parser/decryptor (Task 44).
//
// Byte formats are pinned by the plan's Global Constraints and by the
// authoritative Rust implementation in `extractor/src/crypto.rs`:
//
//   v2 (magic HBS2, 93-byte header, header is AEAD AAD):
//     0   magic "HBS2"
//     4   version u16 LE (=2)
//     6   suite u8 (0 = ChaCha20-Poly1305, 1 = AES-256-GCM)
//     7   key_id u16 LE
//     9   extractor_id 16 bytes
//     25  scan_id 16 bytes
//     41  ephemeral public key 32 bytes
//     73  nonce 12 bytes
//     85  ciphertext length u64 LE (includes 16-byte AEAD tag)
//     93  ciphertext || tag
//
//   v1 (magic HBS1, 77-byte header, empty AAD):
//     0   magic "HBS1"
//     4   version u16 LE (=1)
//     6   suite u8
//     7   key_id u16 LE
//     9   scan_id 16 bytes
//     25  ephemeral public key 32 bytes
//     57  nonce 12 bytes
//     69  ciphertext length u64 LE
//     77  ciphertext || tag
//
// HKDF-SHA256 derives the 32-byte AEAD key:
//   ikm  = X25519(recipient_priv, ephemeral_pub)
//   salt = scan_id || ephemeral_pub
//   info = "HBS-report-v2" || suite_u8 || key_id_u16_le || extractor_id   (v2)
//          "HBS-report-v1" || suite_u8 || key_id_u16_le                  (v1)
//
// Plaintext is zstd-compressed report JSON. Decompression is bounded so a
// malicious frame can never allocate past the configured limit.

import {
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  hkdfSync,
} from "node:crypto";
import { zstdDecompressSync } from "node:zlib";

export type ParsedEnvelopeV2 = {
  version: 2;
  suite: 0 | 1;
  keyId: number;
  extractorId: Uint8Array;
  scanId: Uint8Array;
  ephemeralPub: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  aad: Uint8Array;
};

export type ParsedEnvelopeV1 = {
  version: 1;
  suite: 0 | 1;
  keyId: number;
  scanId: Uint8Array;
  ephemeralPub: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
};

export type ParsedEnvelope = ParsedEnvelopeV2 | ParsedEnvelopeV1;

export type IngestLimits = {
  maxEnvelopeBytes: number;
  maxDecompressedBytes: number;
};

export const DEFAULT_INGEST_LIMITS: IngestLimits = {
  maxEnvelopeBytes: 16 * 1024 * 1024,
  maxDecompressedBytes: 64 * 1024 * 1024,
};

/** Stable rejection codes. Crypto internals never appear in messages. */
export const ENVELOPE_ERROR_CODES = {
  TOO_LARGE: "ENVELOPE_TOO_LARGE",
  TOO_SHORT: "ENVELOPE_TOO_SHORT",
  BAD_MAGIC: "BAD_MAGIC",
  BAD_VERSION: "BAD_VERSION",
  BAD_SUITE: "BAD_SUITE",
  CIPHERTEXT_LENGTH_OVERFLOW: "CIPHERTEXT_LENGTH_OVERFLOW",
  CIPHERTEXT_TRUNCATED: "CIPHERTEXT_TRUNCATED",
  TRAILING_BYTES: "TRAILING_BYTES",
  NIL_ROUTING_FIELD: "NIL_ROUTING_FIELD",
  INVALID_PRIVATE_KEY: "INVALID_PRIVATE_KEY",
  DECRYPTION_FAILED: "DECRYPTION_FAILED",
  DECOMPRESSION_FAILED: "DECOMPRESSION_FAILED",
  DECOMPRESSED_TOO_LARGE: "DECOMPRESSED_TOO_LARGE",
  V1_UNSEAL_UNSUPPORTED: "V1_UNSEAL_UNSUPPORTED",
} as const;

export type EnvelopeErrorCode =
  (typeof ENVELOPE_ERROR_CODES)[keyof typeof ENVELOPE_ERROR_CODES];

export class EnvelopeError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "EnvelopeError";
    this.code = code;
  }
}

const MAGIC_V2 = [0x48, 0x42, 0x53, 0x32]; // "HBS2"
const MAGIC_V1 = [0x48, 0x42, 0x53, 0x31]; // "HBS1"
const HEADER_LEN_V2 = 93;
const HEADER_LEN_V1 = 77;
const EXTRACTOR_ID_LEN = 16;
const SCAN_ID_LEN = 16;
const EPH_PUB_LEN = 32;
const NONCE_LEN = 12;
const TAG_LEN = 16;

// Raw-key DER prefixes for X25519 KeyObject construction (RFC 8410).
const PKCS8_X25519_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const SPKI_X25519_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

function reject(code: string, message: string): never {
  throw new EnvelopeError(code, message);
}

function readU16LE(bytes: Uint8Array, offset: number): number {
  return bytes[offset] | (bytes[offset + 1] << 8);
}

function readU64LE(bytes: Uint8Array, offset: number): bigint {
  let value = 0n;
  for (let i = 7; i >= 0; i -= 1) {
    value = (value << 8n) | BigInt(bytes[offset + i]);
  }
  return value;
}

function isAllZero(bytes: Uint8Array): boolean {
  for (const byte of bytes) if (byte !== 0) return false;
  return true;
}

function matchesMagic(bytes: Uint8Array, magic: readonly number[]): boolean {
  for (let i = 0; i < magic.length; i += 1) if (bytes[i] !== magic[i]) return false;
  return true;
}

function resolveLimits(limits?: Partial<IngestLimits>): IngestLimits {
  return { ...DEFAULT_INGEST_LIMITS, ...limits };
}

/**
 * Parse and validate an envelope header, enforcing the configured envelope
 * size limit and exact ciphertext length. Never decrypts.
 */
export function parseEnvelope(bytes: Uint8Array, limits?: Partial<IngestLimits>): ParsedEnvelope {
  const { maxEnvelopeBytes } = resolveLimits(limits);
  if (bytes.length > maxEnvelopeBytes) {
    reject(
      ENVELOPE_ERROR_CODES.TOO_LARGE,
      `envelope exceeds ${maxEnvelopeBytes} byte limit`,
    );
  }
  if (bytes.length < MAGIC_V2.length) {
    reject(ENVELOPE_ERROR_CODES.TOO_SHORT, "envelope shorter than magic");
  }

  if (matchesMagic(bytes, MAGIC_V2)) return parseV2(bytes);
  if (matchesMagic(bytes, MAGIC_V1)) return parseV1(bytes);
  reject(ENVELOPE_ERROR_CODES.BAD_MAGIC, "unrecognized envelope magic");
}

function parseV2(bytes: Uint8Array): ParsedEnvelopeV2 {
  if (bytes.length < HEADER_LEN_V2) {
    reject(ENVELOPE_ERROR_CODES.TOO_SHORT, `v2 envelope shorter than ${HEADER_LEN_V2}-byte header`);
  }
  const version = readU16LE(bytes, 4);
  if (version !== 2) reject(ENVELOPE_ERROR_CODES.BAD_VERSION, "v2 magic with wrong version");
  const suite = bytes[6];
  if (suite !== 0 && suite !== 1) reject(ENVELOPE_ERROR_CODES.BAD_SUITE, "unsupported suite");

  const keyId = readU16LE(bytes, 7);
  const extractorId = bytes.slice(9, 9 + EXTRACTOR_ID_LEN);
  const scanId = bytes.slice(25, 25 + SCAN_ID_LEN);
  const ephemeralPub = bytes.slice(41, 41 + EPH_PUB_LEN);
  const nonce = bytes.slice(73, 73 + NONCE_LEN);
  const ciphertext = extractCiphertext(bytes, HEADER_LEN_V2, 85);

  if (isAllZero(extractorId)) {
    reject(ENVELOPE_ERROR_CODES.NIL_ROUTING_FIELD, "extractor id is all zero");
  }
  if (isAllZero(scanId)) {
    reject(ENVELOPE_ERROR_CODES.NIL_ROUTING_FIELD, "scan id is all zero");
  }

  return {
    version: 2,
    suite,
    keyId,
    extractorId,
    scanId,
    ephemeralPub,
    nonce,
    ciphertext,
    aad: bytes.slice(0, HEADER_LEN_V2),
  };
}

function parseV1(bytes: Uint8Array): ParsedEnvelopeV1 {
  if (bytes.length < HEADER_LEN_V1) {
    reject(ENVELOPE_ERROR_CODES.TOO_SHORT, `v1 envelope shorter than ${HEADER_LEN_V1}-byte header`);
  }
  const version = readU16LE(bytes, 4);
  if (version !== 1) reject(ENVELOPE_ERROR_CODES.BAD_VERSION, "v1 magic with wrong version");
  const suite = bytes[6];
  if (suite !== 0 && suite !== 1) reject(ENVELOPE_ERROR_CODES.BAD_SUITE, "unsupported suite");

  const keyId = readU16LE(bytes, 7);
  const scanId = bytes.slice(9, 9 + SCAN_ID_LEN);
  const ephemeralPub = bytes.slice(25, 25 + EPH_PUB_LEN);
  const nonce = bytes.slice(57, 57 + NONCE_LEN);
  const ciphertext = extractCiphertext(bytes, HEADER_LEN_V1, 69);

  if (isAllZero(scanId)) {
    reject(ENVELOPE_ERROR_CODES.NIL_ROUTING_FIELD, "scan id is all zero");
  }

  return { version: 1, suite, keyId, scanId, ephemeralPub, nonce, ciphertext };
}

function extractCiphertext(
  bytes: Uint8Array,
  headerLen: number,
  lengthOffset: number,
): Uint8Array {
  const declared = readU64LE(bytes, lengthOffset);
  const remaining = BigInt(bytes.length - headerLen);
  if (declared > BigInt(Number.MAX_SAFE_INTEGER)) {
    reject(
      ENVELOPE_ERROR_CODES.CIPHERTEXT_LENGTH_OVERFLOW,
      "declared ciphertext length overflows",
    );
  }
  if (declared > remaining) {
    reject(
      ENVELOPE_ERROR_CODES.CIPHERTEXT_TRUNCATED,
      "ciphertext shorter than declared length",
    );
  }
  if (declared < remaining) {
    reject(ENVELOPE_ERROR_CODES.TRAILING_BYTES, "trailing bytes after ciphertext");
  }
  return bytes.slice(headerLen, bytes.length);
}

/** Build a raw 32-byte X25519 private-key KeyObject. */
function privateKeyObject(privRaw: Uint8Array) {
  const der = Buffer.concat([PKCS8_X25519_PREFIX, Buffer.from(privRaw)]);
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

/** Build a raw 32-byte X25519 public-key KeyObject. */
function publicKeyObject(pubRaw: Uint8Array) {
  const der = Buffer.concat([SPKI_X25519_PREFIX, Buffer.from(pubRaw)]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

function deriveSharedSecret(privRaw: Uint8Array, ephemeralPub: Uint8Array): Uint8Array {
  const shared = diffieHellman({
    privateKey: privateKeyObject(privRaw),
    publicKey: publicKeyObject(ephemeralPub),
  });
  return new Uint8Array(shared);
}

function deriveAeadKey(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
): Buffer {
  return Buffer.from(hkdfSync("sha256", ikm, salt, info, 32));
}

function v2Info(suite: 0 | 1, keyId: number, extractorId: Uint8Array): Buffer {
  const info = Buffer.alloc(13 + 3 + EXTRACTOR_ID_LEN);
  info.write("HBS-report-v2", 0, "ascii");
  info[13] = suite;
  info.writeUInt16LE(keyId, 14);
  Buffer.from(extractorId).copy(info, 16);
  return info;
}

function v1Info(suite: 0 | 1, keyId: number): Buffer {
  const info = Buffer.alloc(13 + 3);
  info.write("HBS-report-v1", 0, "ascii");
  info[13] = suite;
  info.writeUInt16LE(keyId, 14);
  return info;
}

// --- ChaCha20-Poly1305 (RFC 8439) ---------------------------------------
//
// Bun's node:crypto does not expose ChaCha20-Poly1305, so suite 0 is
// implemented here with no external dependency. AES-256-GCM (suite 1) uses
// node:crypto.

const SIGMA = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

function rotl32(value: number, shift: number): number {
  return ((value << shift) | (value >>> (32 - shift))) >>> 0;
}

function readU32LE(bytes: Uint8Array, offset: number): number {
  return (
    (bytes[offset] |
      (bytes[offset + 1] << 8) |
      (bytes[offset + 2] << 16) |
      (bytes[offset + 3] << 24)) >>>
    0
  );
}

function writeU32LE(bytes: Uint8Array, offset: number, value: number): void {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >>> 8) & 0xff;
  bytes[offset + 2] = (value >>> 16) & 0xff;
  bytes[offset + 3] = (value >>> 24) & 0xff;
}

function quarterRound(x: Uint32Array, a: number, b: number, c: number, d: number): void {
  x[a] = (x[a] + x[b]) >>> 0;
  x[d] = rotl32(x[d] ^ x[a], 16);
  x[c] = (x[c] + x[d]) >>> 0;
  x[b] = rotl32(x[b] ^ x[c], 12);
  x[a] = (x[a] + x[b]) >>> 0;
  x[d] = rotl32(x[d] ^ x[a], 8);
  x[c] = (x[c] + x[d]) >>> 0;
  x[b] = rotl32(x[b] ^ x[c], 7);
}

function chacha20Block(key: Uint8Array, counter: number, nonce: Uint8Array): Uint8Array {
  const state = new Uint32Array(16);
  state[0] = SIGMA[0];
  state[1] = SIGMA[1];
  state[2] = SIGMA[2];
  state[3] = SIGMA[3];
  for (let i = 0; i < 8; i += 1) state[4 + i] = readU32LE(key, i * 4);
  state[12] = counter >>> 0;
  state[13] = readU32LE(nonce, 0);
  state[14] = readU32LE(nonce, 4);
  state[15] = readU32LE(nonce, 8);

  const working = state.slice();
  for (let round = 0; round < 10; round += 1) {
    quarterRound(working, 0, 4, 8, 12);
    quarterRound(working, 1, 5, 9, 13);
    quarterRound(working, 2, 6, 10, 14);
    quarterRound(working, 3, 7, 11, 15);
    quarterRound(working, 0, 5, 10, 15);
    quarterRound(working, 1, 6, 11, 12);
    quarterRound(working, 2, 7, 8, 13);
    quarterRound(working, 3, 4, 9, 14);
  }

  const out = new Uint8Array(64);
  for (let i = 0; i < 16; i += 1) {
    writeU32LE(out, i * 4, (working[i] + state[i]) >>> 0);
  }
  return out;
}

function chacha20Xor(key: Uint8Array, nonce: Uint8Array, data: Uint8Array): Uint8Array {
  const out = new Uint8Array(data.length);
  let counter = 1;
  for (let offset = 0; offset < data.length; offset += 64) {
    const block = chacha20Block(key, counter, nonce);
    counter += 1;
    const count = Math.min(64, data.length - offset);
    for (let i = 0; i < count; i += 1) out[offset + i] = data[offset + i] ^ block[i];
  }
  return out;
}

function leToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) value = (value << 8n) | BigInt(bytes[i]);
  return value;
}

function bigIntToLe(value: bigint, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let remaining = value;
  for (let i = 0; i < length; i += 1) {
    out[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return out;
}

const POLY1305_MODULUS = (1n << 130n) - 5n;
const POLY1305_R_MASK = 0x0ffffffc0ffffffc0ffffffc0fffffffn;

function poly1305Mac(message: Uint8Array, key: Uint8Array): Uint8Array {
  const r = leToBigInt(key.subarray(0, 16)) & POLY1305_R_MASK;
  const s = leToBigInt(key.subarray(16, 32));
  let accumulator = 0n;
  for (let offset = 0; offset < message.length; offset += 16) {
    const chunk = message.subarray(offset, Math.min(offset + 16, message.length));
    const block = new Uint8Array(chunk.length + 1);
    block.set(chunk);
    block[chunk.length] = 1;
    accumulator = ((accumulator + leToBigInt(block)) * r) % POLY1305_MODULUS;
  }
  return bigIntToLe((accumulator + s) & ((1n << 128n) - 1n), 16);
}

function pad16Length(length: number): number {
  return length % 16 === 0 ? 0 : 16 - (length % 16);
}

function poly1305Input(aad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  const aadPad = pad16Length(aad.length);
  const ctPad = pad16Length(ciphertext.length);
  const out = new Uint8Array(aad.length + aadPad + ciphertext.length + ctPad + 16);
  let offset = 0;
  out.set(aad, offset);
  offset += aad.length + aadPad;
  out.set(ciphertext, offset);
  offset += ciphertext.length + ctPad;
  out.set(bigIntToLe(BigInt(aad.length), 8), offset);
  offset += 8;
  out.set(bigIntToLe(BigInt(ciphertext.length), 8), offset);
  return out;
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

function chacha20Poly1305Decrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  if (ciphertext.length < TAG_LEN) {
    reject(ENVELOPE_ERROR_CODES.DECRYPTION_FAILED, "ciphertext too short to authenticate");
  }
  const body = ciphertext.subarray(0, ciphertext.length - TAG_LEN);
  const tag = ciphertext.subarray(ciphertext.length - TAG_LEN);
  const polyKey = chacha20Block(key, 0, nonce).subarray(0, 32);
  const expected = poly1305Mac(poly1305Input(aad, body), polyKey);
  if (!constantTimeEqual(expected, tag)) {
    reject(ENVELOPE_ERROR_CODES.DECRYPTION_FAILED, "authentication failed");
  }
  return chacha20Xor(key, nonce, body);
}

function decryptAead(
  suite: 0 | 1,
  key: Buffer,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  if (suite === 0) {
    return chacha20Poly1305Decrypt(key, nonce, ciphertext, aad);
  }
  if (ciphertext.length < TAG_LEN) {
    reject(ENVELOPE_ERROR_CODES.DECRYPTION_FAILED, "ciphertext too short to authenticate");
  }
  const body = ciphertext.subarray(0, ciphertext.length - TAG_LEN);
  const tag = ciphertext.subarray(ciphertext.length - TAG_LEN);
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, nonce, { authTagLength: TAG_LEN });
    if (aad.length > 0) decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    return new Uint8Array(Buffer.concat([decipher.update(body), decipher.final()]));
  } catch {
    reject(ENVELOPE_ERROR_CODES.DECRYPTION_FAILED, "authentication failed");
  }
}

function boundedZstdDecompress(compressed: Uint8Array, maxDecompressedBytes: number): Uint8Array {
  try {
    const out = zstdDecompressSync(compressed, { maxOutputLength: maxDecompressedBytes });
    if (out.length > maxDecompressedBytes) {
      reject(
        ENVELOPE_ERROR_CODES.DECOMPRESSED_TOO_LARGE,
        `decompressed payload exceeds ${maxDecompressedBytes} byte limit`,
      );
    }
    return new Uint8Array(out);
  } catch (error) {
    if (error instanceof EnvelopeError) throw error;
    const code = (error as { code?: string }).code;
    if (code === "ERR_BUFFER_TOO_LARGE") {
      reject(
        ENVELOPE_ERROR_CODES.DECOMPRESSED_TOO_LARGE,
        `decompressed payload exceeds ${maxDecompressedBytes} byte limit`,
      );
    }
    reject(ENVELOPE_ERROR_CODES.DECOMPRESSION_FAILED, "malformed compressed payload");
  }
}

/**
 * Decrypt and bounded-decompress a parsed envelope. Returns the raw report
 * JSON bytes. v1 is supported for migration ingest only; the dashboard never
 * issues v1.
 */
export function unsealEnvelope(
  parsed: ParsedEnvelope,
  privRaw: Uint8Array,
  limits?: Partial<IngestLimits>,
): Uint8Array {
  const { maxDecompressedBytes } = resolveLimits(limits);
  if (privRaw.length !== 32) {
    reject(ENVELOPE_ERROR_CODES.INVALID_PRIVATE_KEY, "private key must be 32 raw bytes");
  }

  const ikm = deriveSharedSecret(privRaw, parsed.ephemeralPub);
  const salt = Buffer.concat([Buffer.from(parsed.scanId), Buffer.from(parsed.ephemeralPub)]);

  if (parsed.version === 2) {
    const key = deriveAeadKey(ikm, salt, v2Info(parsed.suite, parsed.keyId, parsed.extractorId));
    const compressed = decryptAead(parsed.suite, key, parsed.nonce, parsed.ciphertext, parsed.aad);
    return boundedZstdDecompress(compressed, maxDecompressedBytes);
  }

  const key = deriveAeadKey(ikm, salt, v1Info(parsed.suite, parsed.keyId));
  const compressed = decryptAead(parsed.suite, key, parsed.nonce, parsed.ciphertext, new Uint8Array(0));
  return boundedZstdDecompress(compressed, maxDecompressedBytes);
}
