import { afterEach, describe, expect, it } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  PatcherError,
  SLOT_LEN,
  SLOT_MAGIC,
  createArtifact,
  findOnlySlot,
  patch,
  readSlot,
} from "./patcher";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function dataRoot(): string {
  const value = mkdtempSync(join(tmpdir(), "hbs-patcher-"));
  roots.push(value);
  return value;
}

/** Independent placeholder builder mirroring the Rust `KEY_SLOT_PLACEHOLDER`. */
function placeholder(): Uint8Array {
  const slot = new Uint8Array(SLOT_LEN).fill(0xaa);
  slot.set(SLOT_MAGIC, 0);
  slot.fill(0, 480, 512);
  return slot;
}

function fakeBinary(prefix = 1024, suffix = 64): Uint8Array {
  const bin = new Uint8Array(prefix + SLOT_LEN + suffix);
  bin.set(placeholder(), prefix);
  return bin;
}

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function u16le(value: number): Uint8Array {
  return Uint8Array.from([value & 0xff, (value >>> 8) & 0xff]);
}

function u64le(value: number): Uint8Array {
  const out = new Uint8Array(8);
  let v = BigInt(value);
  for (let i = 0; i < 8; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

const CAMPAIGN = Uint8Array.from({ length: 16 }, (_, i) => 0xa0 + i);
const EXTRACTOR = Uint8Array.from({ length: 16 }, (_, i) => 0xb0 + i);
const PUB = Uint8Array.from({ length: 32 }, (_, i) => 0xc0 + i);

describe("patcher findOnlySlot", () => {
  it("locates exactly one pristine placeholder", () => {
    const bin = fakeBinary();
    expect(findOnlySlot(bin)).toBe(1024);
  });

  it("rejects absent, duplicate, truncated, and already-patched slots", () => {
    expect(() => findOnlySlot(new Uint8Array(256))).toThrowCode("NO_SLOT");

    const two = new Uint8Array(1024 + SLOT_LEN * 2);
    two.set(placeholder(), 1024);
    two.set(placeholder(), 1024 + SLOT_LEN);
    expect(() => findOnlySlot(two)).toThrowCode("MULTIPLE_SLOTS");

    const truncated = new Uint8Array(1024 + 200);
    truncated.set(SLOT_MAGIC, 1024);
    truncated.fill(0, 1024 + 8);
    expect(() => findOnlySlot(truncated)).toThrowCode("TRUNCATED_SLOT");

    const patched = fakeBinary();
    patched[1024 + 480] = 1; // non-zero checksum => already issued
    expect(() => findOnlySlot(patched)).toThrowCode("NOT_PLACEHOLDER");
  });
});

describe("patcher patch", () => {
  const input = {
    keyId: 7,
    campaignId: CAMPAIGN,
    extractorId: EXTRACTOR,
    publicKey: PUB,
    issuedAt: 1_700_000_000,
    expiry: 4_102_444_800,
  };

  it("writes the exact spec layout and checksum without mutating the template", () => {
    const template = fakeBinary();
    const before = Buffer.from(template).toString("hex");
    const { bytes, sha256 } = patch(template, input);
    const off = 1024;

    expect(Buffer.from(template).toString("hex")).toBe(before);
    expect(hex(bytes.subarray(off, off + 8))).toBe(hex(SLOT_MAGIC));
    expect(readU16(bytes, off + 8)).toBe(1);
    expect(readU16(bytes, off + 10)).toBe(0);
    expect(readU16(bytes, off + 12)).toBe(7);
    expect(readU16(bytes, off + 14)).toBe(0);
    expect(hex(bytes.subarray(off + 16, off + 32))).toBe(hex(CAMPAIGN));
    expect(hex(bytes.subarray(off + 32, off + 48))).toBe(hex(EXTRACTOR));
    expect(bytes.subarray(off + 48, off + 56)).toEqual(u64le(input.expiry));
    expect(bytes.subarray(off + 56, off + 64)).toEqual(u64le(input.issuedAt));
    expect(hex(bytes.subarray(off + 64, off + 96))).toBe(hex(PUB));
    expect(bytes.subarray(off + 96, off + 480).every((b) => b === 0)).toBeTrue();

    const expectedChecksum = createHash("sha256").update(bytes.subarray(off, off + 480)).digest();
    expect(Buffer.from(bytes.subarray(off + 480, off + 512))).toEqual(expectedChecksum);
    expect(sha256).toBe(createHash("sha256").update(bytes).digest("hex"));
  });

  it("round-trips through the strict parser", () => {
    const { bytes } = patch(fakeBinary(), input);
    const slot = readSlot(bytes, 1024);
    expect(slot.keyId).toBe(7);
    expect(slot.slotVersion).toBe(1);
    expect(slot.flags).toBe(0);
    expect(hex(slot.campaignId)).toBe(hex(CAMPAIGN));
    expect(hex(slot.extractorId)).toBe(hex(EXTRACTOR));
    expect(hex(slot.recipientPub)).toBe(hex(PUB));
    expect(slot.issuedAtUnix).toBe(input.issuedAt);
    expect(slot.expiryUnix).toBe(input.expiry);
  });

  it("validates ids, key, and timestamp ordering", () => {
    const cases: Array<[string, Partial<typeof input>]> = [
      ["NIL_ID", { campaignId: new Uint8Array(16) }],
      ["NIL_ID", { extractorId: new Uint8Array(16) }],
      ["NIL_PUB", { publicKey: new Uint8Array(32) }],
      ["BAD_ID_LEN", { campaignId: new Uint8Array(15) }],
      ["BAD_PUB_LEN", { publicKey: new Uint8Array(31) }],
      ["BAD_KEY_ID", { keyId: 70000 }],
      ["BAD_TIMESTAMPS", { issuedAt: 100, expiry: 100 }],
    ];
    for (const [code, override] of cases) {
      expect(() => patch(fakeBinary(), { ...input, ...override })).toThrowCode(code);
    }
  });

  it("refuses to patch an already-patched binary a second time", () => {
    const { bytes } = patch(fakeBinary(), input);
    expect(() => patch(bytes, input)).toThrowCode("NOT_PLACEHOLDER");
  });
});

describe("patcher readSlot strictness", () => {
  const input = {
    keyId: 1,
    campaignId: CAMPAIGN,
    extractorId: EXTRACTOR,
    publicKey: PUB,
    issuedAt: 1,
    expiry: 2,
  };

  it("rejects version, flags, reserved, and checksum tampering", () => {
    const base = patch(fakeBinary(), input).bytes;
    const off = 1024;

    const badVersion = new Uint8Array(base);
    badVersion.set(u16le(2), off + 8);
    expect(() => readSlot(badVersion, off)).toThrowCode("UNSUPPORTED_VERSION");

    const badFlags = new Uint8Array(base);
    badFlags.set(u16le(1), off + 10);
    expect(() => readSlot(badFlags, off)).toThrowCode("NONZERO_FLAGS");

    const badReserved = new Uint8Array(base);
    badReserved.set(u16le(1), off + 14);
    expect(() => readSlot(badReserved, off)).toThrowCode("NONZERO_RESERVED");

    const badPad = new Uint8Array(base);
    badPad[off + 200] = 1;
    expect(() => readSlot(badPad, off)).toThrowCode("NONZERO_RESERVED");

    const badChecksum = new Uint8Array(base);
    badChecksum[off + 64] ^= 0xff;
    expect(() => readSlot(badChecksum, off)).toThrowCode("CHECKSUM_MISMATCH");
  });
});

describe("patcher createArtifact", () => {
  it("atomically stores immutable bytes with hash and size", () => {
    const root = dataRoot();
    const { bytes, sha256 } = patch(fakeBinary(), {
      keyId: 3,
      campaignId: CAMPAIGN,
      extractorId: EXTRACTOR,
      publicKey: PUB,
      issuedAt: 1,
      expiry: 2,
    });
    const artifact = createArtifact(bytes, "iss-abc", { dataRoot: root });
    expect(artifact.size).toBe(bytes.length);
    expect(artifact.sha256).toBe(sha256);
    expect(readFileSync(artifact.path)).toEqual(Buffer.from(bytes));
    expect(() => createArtifact(bytes, "../escape", { dataRoot: root })).toThrowCode("NIL_ID");
  });
});

function readU16(bytes: Uint8Array, offset: number): number {
  return bytes[offset] | (bytes[offset + 1] << 8);
}

declare module "bun:test" {
  interface Matchers<T> {
    toThrowCode(code: string): void;
  }
}

expect.extend({
  toThrowCode(received: () => unknown, code: string) {
    try {
      received();
      return { pass: false, message: () => `expected throw with code ${code}, but nothing was thrown` };
    } catch (error) {
      const actual = error instanceof PatcherError ? error.code : `non-PatcherError: ${(error as Error).message}`;
      return {
        pass: actual === code,
        message: () => `expected code ${code}, got ${actual}`,
      };
    }
  },
} as never);
