// Task 44 - bounded envelope parser/decryptor tests.
//
// Consumes the independent cross-language vectors in
// `fixtures/crypto-vectors.json` (Task 15). Mutations assert stable
// rejection codes and that error text never leaks raw key material.

import { describe, expect, it } from "bun:test";
import { createCipheriv, createPrivateKey, createPublicKey, createHash, diffieHellman, hkdfSync } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { zstdCompressSync } from "node:zlib";
import {
  ENVELOPE_ERROR_CODES,
  EnvelopeError,
  parseEnvelope,
  unsealEnvelope,
  type ParsedEnvelope,
} from "./envelope";

const FIXTURES_DIR = join(import.meta.dir, "..", "..", "fixtures");

type Vector = {
  name: string;
  suite: 0 | 1;
  keyId: number;
  extractorIdHex: string;
  recipientPrivHex: string;
  recipientPubHex: string;
  plaintextHex: string | null;
  envelopeHex: string | null;
  envelopeLen: number;
  envelopeSha256: string;
  plaintextSha256: string;
  large: boolean;
};

const VECTORS: Vector[] = JSON.parse(
  readFileSync(join(FIXTURES_DIR, "crypto-vectors.json"), "utf8"),
) as Vector[];

const V2_VECTORS = VECTORS.filter((v) => v.envelopeHex !== null);
const LARGE_FIXTURE = join(FIXTURES_DIR, "vector-suite0-large-1mb.hbs");

// --- byte helpers -------------------------------------------------------

function bytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, "hex"));
}

function hex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex");
}

function sha256Hex(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function writeU64LE(target: Uint8Array, offset: number, value: bigint): void {
  new DataView(target.buffer, target.byteOffset, target.byteLength).setBigUint64(offset, value, true);
}

function errorCode(fn: () => unknown): string {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(EnvelopeError);
    return (error as EnvelopeError).code;
  }
  throw new Error("expected function to throw");
}

const PKCS8_X25519_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const SPKI_X25519_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

function rawPublicKey(privRaw: Uint8Array): Uint8Array {
  const der = Buffer.concat([PKCS8_X25519_PREFIX, Buffer.from(privRaw)]);
  const key = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  return new Uint8Array(createPublicKey(key).export({ format: "der", type: "spki" }).subarray(-32));
}

function sharedSecret(privRaw: Uint8Array, pubRaw: Uint8Array): Uint8Array {
  return new Uint8Array(
    diffieHellman({
      privateKey: createPrivateKey({
        key: Buffer.concat([PKCS8_X25519_PREFIX, Buffer.from(privRaw)]),
        format: "der",
        type: "pkcs8",
      }),
      publicKey: createPublicKey({
        key: Buffer.concat([SPKI_X25519_PREFIX, Buffer.from(pubRaw)]),
        format: "der",
        type: "spki",
      }),
    }),
  );
}

/**
 * Craft a v2 suite-1 (AES-256-GCM) envelope. Bun's node:crypto cannot
 * encrypt ChaCha20-Poly1305, so crafted vectors use the AES suite; the real
 * ChaCha vectors come from the Rust fixtures.
 */
function sealV2Suite1(options: {
  plaintext: Uint8Array;
  recipientPubRaw: Uint8Array;
  extractorId: Uint8Array;
  keyId: number;
  scanId?: Uint8Array;
  nonce?: Uint8Array;
  ephemeralPrivRaw?: Uint8Array;
  compress?: boolean;
}): Uint8Array {
  const scanId = options.scanId ?? new Uint8Array(16).fill(0x11);
  const nonce = options.nonce ?? new Uint8Array(12).fill(0x22);
  const ephPriv = options.ephemeralPrivRaw ?? new Uint8Array(32).fill(0x55);
  const ephPub = rawPublicKey(ephPriv);
  const ikm = sharedSecret(ephPriv, options.recipientPubRaw);
  const salt = Buffer.concat([Buffer.from(scanId), Buffer.from(ephPub)]);
  const info = Buffer.concat([
    Buffer.from("HBS-report-v2", "ascii"),
    Buffer.from([1]),
    Buffer.from([options.keyId & 0xff, (options.keyId >> 8) & 0xff]),
    Buffer.from(options.extractorId),
  ]);
  const key = Buffer.from(hkdfSync("sha256", ikm, salt, info, 32));
  const compressed =
    options.compress === false
      ? Buffer.from(options.plaintext)
      : zstdCompressSync(Buffer.from(options.plaintext));
  const ciphertextLength = compressed.length + 16;

  const header = Buffer.alloc(93);
  header.write("HBS2", 0, "ascii");
  header.writeUInt16LE(2, 4);
  header[6] = 1;
  header.writeUInt16LE(options.keyId, 7);
  Buffer.from(options.extractorId).copy(header, 9);
  Buffer.from(scanId).copy(header, 25);
  Buffer.from(ephPub).copy(header, 41);
  Buffer.from(nonce).copy(header, 73);
  header.writeBigUInt64LE(BigInt(ciphertextLength), 85);

  const cipher = createCipheriv("aes-256-gcm", key, nonce, { authTagLength: 16 });
  cipher.setAAD(header);
  const ciphertext = Buffer.concat([cipher.update(compressed), cipher.final(), cipher.getAuthTag()]);
  return new Uint8Array(Buffer.concat([header, ciphertext]));
}

// Deterministic legacy v1 vector generated from the pre-v2 Rust layout
// (`extractor/src/crypto.rs` at HEAD): 77-byte header, empty AAD,
// HKDF info "HBS-report-v1" || suite || key_id_le.
const V1_ENVELOPE_HEX =
  "4842533101000105001112131415161718191a1b1c1d1e1f2038ab664bd86f77d7e66bdd9ae0792913a94fd8b33a1260027e4b46c1f4884c67000102030405060708090a0b3200000000000000c9d1599167ce9358b055629ba5620257b80d42c42c1e7214dd7c72fb25c3cbd38bd1d926a5b038a2eff7bdbee1c9985ea675";
const V1_PLAINTEXT_HEX = "7b22736368656d6156657273696f6e223a312c2276223a317d";
const V1_RECIPIENT_PRIV_HEX = "41".repeat(32);

// --- fixture vectors ----------------------------------------------------

describe("v2 fixture vectors", () => {
  for (const vector of V2_VECTORS) {
    it(`parses and unseals ${vector.name}`, () => {
      const envelope = bytes(vector.envelopeHex!);
      expect(envelope.length).toBe(vector.envelopeLen);
      expect(sha256Hex(envelope)).toBe(vector.envelopeSha256);

      const parsed = parseEnvelope(envelope) as Extract<ParsedEnvelope, { version: 2 }>;
      expect(parsed.version).toBe(2);
      expect(parsed.suite).toBe(vector.suite);
      expect(parsed.keyId).toBe(vector.keyId);
      expect(hex(parsed.extractorId)).toBe(vector.extractorIdHex);
      expect(parsed.scanId.length).toBe(16);
      expect(parsed.ephemeralPub.length).toBe(32);
      expect(parsed.nonce.length).toBe(12);
      expect(parsed.ciphertext.length).toBe(vector.envelopeLen - 93);
      expect(parsed.aad.length).toBe(93);
      expect(hex(parsed.aad)).toBe(vector.envelopeHex!.slice(0, 186));

      const plaintext = unsealEnvelope(parsed, bytes(vector.recipientPrivHex));
      expect(hex(plaintext)).toBe(vector.plaintextHex!);
      expect(sha256Hex(plaintext)).toBe(vector.plaintextSha256);
    });
  }

  it("decrypts the large 1 MiB fixture with bounded decompression", () => {
    expect(existsSync(LARGE_FIXTURE)).toBe(true);
    const envelope = new Uint8Array(readFileSync(LARGE_FIXTURE));
    const vector = VECTORS.find((v) => v.large)!;
    expect(envelope.length).toBe(vector.envelopeLen);
    expect(sha256Hex(envelope)).toBe(vector.envelopeSha256);

    const parsed = parseEnvelope(envelope) as Extract<ParsedEnvelope, { version: 2 }>;
    const plaintext = unsealEnvelope(parsed, bytes(vector.recipientPrivHex));
    expect(plaintext.length).toBe(1024 * 1024);
    expect(sha256Hex(plaintext)).toBe(vector.plaintextSha256);
  });
});

describe("legacy v1 ingest", () => {
  it("parses the 77-byte v1 layout and unseals", () => {
    const parsed = parseEnvelope(bytes(V1_ENVELOPE_HEX)) as Extract<
      ParsedEnvelope,
      { version: 1 }
    >;
    expect(parsed.version).toBe(1);
    expect(parsed.suite).toBe(1);
    expect(parsed.keyId).toBe(5);
    expect(parsed.scanId.length).toBe(16);
    expect(parsed.ephemeralPub.length).toBe(32);
    expect(parsed.nonce.length).toBe(12);

    const plaintext = unsealEnvelope(parsed, bytes(V1_RECIPIENT_PRIV_HEX));
    expect(hex(plaintext)).toBe(V1_PLAINTEXT_HEX);
  });

  it("rejects a v1 envelope with wrong version", () => {
    const envelope = bytes(V1_ENVELOPE_HEX);
    envelope[4] = 2;
    expect(errorCode(() => parseEnvelope(envelope))).toBe(ENVELOPE_ERROR_CODES.BAD_VERSION);
  });
});

// --- bounds and mutation table -----------------------------------------

describe("bounds and mutation table", () => {
  const vector = V2_VECTORS[0];
  const envelope = bytes(vector.envelopeHex!);
  const priv = bytes(vector.recipientPrivHex);
  const parsed = parseEnvelope(envelope);

  it("rejects truncation at every header boundary and just past it", () => {
    for (let length = 0; length <= 94; length += 1) {
      const truncated = envelope.slice(0, length);
      const code = errorCode(() => parseEnvelope(truncated));
      expect(typeof code).toBe("string");
      if (length < 93) expect(code).toBe(ENVELOPE_ERROR_CODES.TOO_SHORT);
      else expect(code).toBe(ENVELOPE_ERROR_CODES.CIPHERTEXT_TRUNCATED);
    }
  });

  it("rejects a header shorter than the magic", () => {
    expect(errorCode(() => parseEnvelope(new Uint8Array(0)))).toBe(ENVELOPE_ERROR_CODES.TOO_SHORT);
    expect(errorCode(() => parseEnvelope(new Uint8Array([0x48, 0x42, 0x53])))).toBe(
      ENVELOPE_ERROR_CODES.TOO_SHORT,
    );
  });

  it("rejects bad magic", () => {
    const mutated = envelope.slice();
    mutated[0] = 0x58;
    expect(errorCode(() => parseEnvelope(mutated))).toBe(ENVELOPE_ERROR_CODES.BAD_MAGIC);
    expect(errorCode(() => parseEnvelope(new Uint8Array(200).fill(7)))).toBe(
      ENVELOPE_ERROR_CODES.BAD_MAGIC,
    );
  });

  it("rejects bad version", () => {
    const mutated = envelope.slice();
    mutated[4] = 3;
    expect(errorCode(() => parseEnvelope(mutated))).toBe(ENVELOPE_ERROR_CODES.BAD_VERSION);
  });

  it("rejects bad suite", () => {
    const mutated = envelope.slice();
    mutated[6] = 2;
    expect(errorCode(() => parseEnvelope(mutated))).toBe(ENVELOPE_ERROR_CODES.BAD_SUITE);
    mutated[6] = 0xff;
    expect(errorCode(() => parseEnvelope(mutated))).toBe(ENVELOPE_ERROR_CODES.BAD_SUITE);
  });

  it("rejects a declared length smaller than the remaining bytes", () => {
    const mutated = envelope.slice();
    writeU64LE(mutated, 85, BigInt(vector.envelopeLen - 93 - 1));
    expect(errorCode(() => parseEnvelope(mutated))).toBe(ENVELOPE_ERROR_CODES.TRAILING_BYTES);
  });

  it("rejects a declared length larger than the remaining bytes", () => {
    const mutated = envelope.slice();
    writeU64LE(mutated, 85, BigInt(vector.envelopeLen - 93 + 1));
    expect(errorCode(() => parseEnvelope(mutated))).toBe(ENVELOPE_ERROR_CODES.CIPHERTEXT_TRUNCATED);
  });

  it("rejects an overflowing declared length", () => {
    const mutated = envelope.slice();
    writeU64LE(mutated, 85, 0xffffffffffffffffn);
    expect(errorCode(() => parseEnvelope(mutated))).toBe(
      ENVELOPE_ERROR_CODES.CIPHERTEXT_LENGTH_OVERFLOW,
    );
  });

  it("rejects trailing bytes", () => {
    const mutated = new Uint8Array(envelope.length + 1);
    mutated.set(envelope);
    expect(errorCode(() => parseEnvelope(mutated))).toBe(ENVELOPE_ERROR_CODES.TRAILING_BYTES);
  });

  it("rejects all-zero routing fields", () => {
    const zeroExtractor = envelope.slice();
    zeroExtractor.fill(0, 9, 25);
    expect(errorCode(() => parseEnvelope(zeroExtractor))).toBe(ENVELOPE_ERROR_CODES.NIL_ROUTING_FIELD);

    const zeroScan = envelope.slice();
    zeroScan.fill(0, 25, 41);
    expect(errorCode(() => parseEnvelope(zeroScan))).toBe(ENVELOPE_ERROR_CODES.NIL_ROUTING_FIELD);
  });

  it("fails to unseal after header bit flips in routing fields", () => {
    for (const offset of [6, 7, 8, 9, 20, 24]) {
      const mutated = envelope.slice();
      mutated[offset] ^= 0x01;
      // suite flip must stay a valid suite (0 <-> 1)
      if (offset === 6 && mutated[6] > 1) mutated[6] = mutated[6] === 0 ? 1 : 0;
      const reparsed = parseEnvelope(mutated);
      expect(errorCode(() => unsealEnvelope(reparsed, priv))).toBe(
        ENVELOPE_ERROR_CODES.DECRYPTION_FAILED,
      );
    }
  });

  it("fails to unseal after a ciphertext bit flip", () => {
    const mutated = envelope.slice();
    mutated[100] ^= 0x01;
    expect(errorCode(() => unsealEnvelope(parseEnvelope(mutated), priv))).toBe(
      ENVELOPE_ERROR_CODES.DECRYPTION_FAILED,
    );
  });

  it("fails to unseal after a tag bit flip", () => {
    const mutated = envelope.slice();
    mutated[mutated.length - 1] ^= 0x01;
    expect(errorCode(() => unsealEnvelope(parseEnvelope(mutated), priv))).toBe(
      ENVELOPE_ERROR_CODES.DECRYPTION_FAILED,
    );
  });

  it("rejects an envelope over the configured size limit", () => {
    const oversized = new Uint8Array(101);
    oversized.set([0x48, 0x42, 0x53, 0x32]);
    expect(errorCode(() => parseEnvelope(oversized, { maxEnvelopeBytes: 100 }))).toBe(
      ENVELOPE_ERROR_CODES.TOO_LARGE,
    );
  });

  it("rejects a malformed zstd payload", () => {
    const recipientPub = bytes(vector.recipientPubHex);
    const crafted = sealV2Suite1({
      plaintext: new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03]),
      recipientPubRaw: recipientPub,
      extractorId: bytes(vector.extractorIdHex),
      keyId: vector.keyId,
      compress: false,
    });
    const craftedParsed = parseEnvelope(crafted);
    expect(errorCode(() => unsealEnvelope(craftedParsed, priv))).toBe(
      ENVELOPE_ERROR_CODES.DECOMPRESSION_FAILED,
    );
  });

  it("rejects decompressed output over the limit against a real fixture", () => {
    expect(
      errorCode(() => unsealEnvelope(parsed, priv, { maxDecompressedBytes: 4 })),
    ).toBe(ENVELOPE_ERROR_CODES.DECOMPRESSED_TOO_LARGE);
  });

  it("rejects a compression bomb before allocating the claimed output", () => {
    const recipientPub = bytes(vector.recipientPubHex);
    const bomb = sealV2Suite1({
      plaintext: new Uint8Array(4 * 1024 * 1024).fill(0x78),
      recipientPubRaw: recipientPub,
      extractorId: bytes(vector.extractorIdHex),
      keyId: vector.keyId,
    });
    expect(
      errorCode(() => unsealEnvelope(parseEnvelope(bomb), priv, { maxDecompressedBytes: 1024 })),
    ).toBe(ENVELOPE_ERROR_CODES.DECOMPRESSED_TOO_LARGE);
  });

  it("rejects an invalid private key length", () => {
    expect(errorCode(() => unsealEnvelope(parsed, new Uint8Array(31)))).toBe(
      ENVELOPE_ERROR_CODES.INVALID_PRIVATE_KEY,
    );
  });

  it("never leaks raw key material in error text", () => {
    const wrongPriv = new Uint8Array(32).fill(0x9c);
    let message = "";
    try {
      unsealEnvelope(parsed, wrongPriv);
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message.length).toBeGreaterThan(0);
    expect(message).not.toContain(hex(wrongPriv));
    expect(message).not.toContain(vector.recipientPrivHex);
    expect(message).not.toContain(vector.recipientPubHex);
    expect(message).not.toContain(hex(parsed.ephemeralPub));
  });
});
