import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { EnvelopeError, parseEnvelope, unsealEnvelope } from "./envelope";

// Immutable legacy v1 (HBS1) vectors generated once by
// `extractor/examples/gen_v1_vectors.rs`. The dashboard only ingests v1 for
// migration; it never issues it.

type LegacyVector = {
  name: string;
  suite: 0 | 1;
  keyId: number;
  recipientPrivHex: string;
  recipientPubHex: string;
  ephemeralPrivHex: string;
  plaintextHex: string;
  envelopeHex: string;
};

const vectors: LegacyVector[] = JSON.parse(
  readFileSync(new URL("../../fixtures/legacy-v1-vectors.json", import.meta.url), "utf8"),
);

describe("legacy v1 ingest", () => {
  for (const vector of vectors) {
    it(`parses and unseals ${vector.name}`, () => {
      const bytes = new Uint8Array(Buffer.from(vector.envelopeHex, "hex"));
      const parsed = parseEnvelope(bytes);
      expect(parsed.version).toBe(1);
      expect(parsed.suite).toBe(vector.suite);
      expect(parsed.keyId).toBe(vector.keyId);
      expect(parsed.ephemeralPub).toHaveLength(32);
      expect(parsed.nonce).toHaveLength(12);

      const priv = new Uint8Array(Buffer.from(vector.recipientPrivHex, "hex"));
      const plaintext = unsealEnvelope(parsed, priv);
      expect(Buffer.from(plaintext).toString("hex")).toBe(vector.plaintextHex);
    });
  }

  it("rejects a tampered v1 ciphertext with a stable code", () => {
    const bytes = new Uint8Array(Buffer.from(vectors[0]!.envelopeHex, "hex"));
    bytes[bytes.length - 1] ^= 0xff;
    const parsed = parseEnvelope(bytes);
    const priv = new Uint8Array(Buffer.from(vectors[0]!.recipientPrivHex, "hex"));
    let code = "";
    try {
      unsealEnvelope(parsed, priv);
    } catch (error) {
      code = error instanceof EnvelopeError ? error.code : "not-envelope-error";
    }
    expect(code).not.toBe("");
    expect(code).not.toBe("not-envelope-error");
  });

  it("rejects a truncated v1 header before decryption", () => {
    const bytes = new Uint8Array(Buffer.from(vectors[0]!.envelopeHex, "hex")).subarray(0, 40);
    expect(() => parseEnvelope(bytes)).toThrow(EnvelopeError);
  });
});
