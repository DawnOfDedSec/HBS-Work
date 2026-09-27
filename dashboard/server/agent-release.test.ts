// Tests for the GitHub Releases agent-template fetch: cache-first behavior,
// asset matching per platform, checksum verification (pass + mismatch
// refusal), and air-gap mode.

import { createHash } from "node:crypto";
import { afterEach, describe, expect, it } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { ensureAgentTemplate, type ReleaseFetchOptions } from "./agent-release";

const BINARY = Buffer.from("fake-extractor-binary-\0-with-bytes", "utf8");
const BINARY_SHA = createHash("sha256").update(BINARY).digest("hex");

function stubFetch(handler: (url: string) => { status?: number; body?: Uint8Array | string; contentType?: string }) {
  return (async (url: string) => {
    const result = handler(String(url));
    const body = typeof result.body === "string" ? new TextEncoder().encode(result.body) : result.body ?? new Uint8Array();
    return new Response(body as unknown as BodyInit, {
      status: result.status ?? 200,
      headers: { "content-type": result.contentType ?? "application/octet-stream" },
    });
  }) as unknown as typeof fetch;
}

function releasePayload(): { status?: number; body: Uint8Array; contentType?: string } {
  const release = {
    assets: [
      { name: "hbs-extractor-v9-x86_64-pc-windows-msvc.exe", browser_download_url: "https://test/bin/exe", size: BINARY.length },
      { name: "hbs-extractor-v9-x86_64-unknown-linux-musl", browser_download_url: "https://test/bin/lin", size: BINARY.length },
      { name: "SHA256SUMS", browser_download_url: "https://test/bin/SHA256SUMS", size: 200 },
    ],
  };
  return { status: 200, body: new TextEncoder().encode(JSON.stringify(release)), contentType: "application/json" };
}

function sumsPayload(): { status?: number; body: Uint8Array; contentType?: string } {
  return { status: 200, body: new TextEncoder().encode(`${BINARY_SHA}  hbs-extractor-v9-x86_64-unknown-linux-musl\n`) };
}

function happyFetch(url: string) {
  if (url.includes("releases/latest")) return releasePayload();
  if (url.endsWith("SHA256SUMS")) return sumsPayload();
  return { status: 200, body: BINARY };
}

function makeOptions(outputDir: string, fetchImpl: typeof fetch, disabled = false): ReleaseFetchOptions {
  return { outputDir, fetchImpl, disabled };
}

let dir: string;
afterEach(() => {
  if (dir) rmSync(dir, { recursive: true, force: true });
});

describe("agent template release fetch", () => {
  it("downloads, verifies, caches, and reuses the cached template", async () => {
    dir = mkdtempSync(join(tmpdir(), "hbs-agent-"));
    let downloads = 0;
    const fetchImpl = stubFetch((url) => {
      if (!url.includes("releases/latest") && !url.includes("SHA256SUMS")) downloads += 1;
      return happyFetch(url);
    });

    const first = await ensureAgentTemplate("linux-amd64", makeOptions(dir, fetchImpl), fetchImpl);
    expect(first.source).toBe("release");
    expect(first.sha256).toBe(BINARY_SHA);
    expect(readFileSync(join(dir, "linux-amd64"))).toEqual(BINARY);

    const second = await ensureAgentTemplate("linux-amd64", makeOptions(dir, fetchImpl), fetchImpl);
    expect(second.source).toBe("cache");
    expect(downloads).toBe(1); // only the binary; cached on the second call
  });

  it("refuses a binary whose checksum does not match SHA256SUMS", async () => {
    dir = mkdtempSync(join(tmpdir(), "hbs-agent-"));
    const bad = stubFetch((url) => {
      if (url.includes("releases/latest")) return releasePayload();
      if (url.endsWith("SHA256SUMS")) return sumsPayload();
      return { status: 200, body: new TextEncoder().encode("tampered") };
    });
    await expect(ensureAgentTemplate("linux-amd64", makeOptions(dir, bad), bad)).rejects.toThrow(/checksum mismatch/);
    expect(existsSync(join(dir, "linux-amd64"))).toBe(false);
  });

  it("errors clearly when the release has no asset for the platform", async () => {
    dir = mkdtempSync(join(tmpdir(), "hbs-agent-"));
    const none = stubFetch((url) => {
      const payload = releasePayload();
      if (url.includes("releases/latest")) {
        const release = JSON.parse(new TextDecoder().decode(payload.body)) as { assets: Array<{ name: string }> };
        release.assets = release.assets.filter((asset) => !asset.name.includes("musl"));
        return { status: 200, body: new TextEncoder().encode(JSON.stringify(release)), contentType: "application/json" };
      }
      return sumsPayload();
    });
    await expect(ensureAgentTemplate("linux-arm64", makeOptions(dir, none), none)).rejects.toThrow(/no extractor asset/);
  });

  it("air-gap mode fails without any network call", async () => {
    dir = mkdtempSync(join(tmpdir(), "hbs-agent-"));
    let called = 0;
    const counting = stubFetch(() => {
      called += 1;
      return happyFetch("x");
    });
    await expect(ensureAgentTemplate("linux-amd64", makeOptions(dir, counting, true), counting)).rejects.toThrow(/disabled/);
    expect(called).toBe(0);
  });
});
