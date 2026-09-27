// Agent template fetch from GitHub Releases: when no local template exists in
// `dashboard/binaries/<platform>`, the prebuilt extractor from the project's
// latest release is downloaded, checksum-verified against SHA256SUMS, and
// cached as the issuance template. The per-issuance keyslot patching (which
// embeds the report-encryption keypair) happens afterwards in issuances.ts -
// private key material never enters this module.

import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";

export type AgentPlatform = "windows-amd64" | "linux-amd64" | "linux-arm64";

export type ReleaseFetchOptions = {
  /** GitHub API URL for the release to use. Default: latest release of the project repo. */
  releaseApiUrl?: string;
  /** Base for release asset downloads. Derived from releaseApiUrl when unset. */
  assetBaseUrl?: string;
  /** Cache/output directory. Default: dashboard/binaries. */
  outputDir?: string;
  /** Disable network fetch (air-gapped installs). */
  disabled?: boolean;
  fetchImpl?: typeof fetch;
};

export type ReleaseFetchResult = {
  source: "cache" | "release";
  template: Uint8Array;
  assetName: string;
  sha256: string;
};

const RELEASE_ASSET_TARGETS: Record<AgentPlatform, { target: string; ext: string }> = {
  "windows-amd64": { target: "x86_64-pc-windows-msvc", ext: ".exe" },
  "linux-amd64": { target: "x86_64-unknown-linux-musl", ext: "" },
  "linux-arm64": { target: "aarch64-unknown-linux-musl", ext: "" },
};

export function defaultReleaseApiUrl(): string {
  return process.env.HBS_AGENT_RELEASE_URL ?? "https://api.github.com/repos/PotenFYR-Studios/HBS-Tool/releases/latest";
}

function cachePath(outputDir: string, platform: AgentPlatform): string {
  return join(resolve(outputDir), platform);
}

function isPlatform(value: unknown): value is AgentPlatform {
  return value === "windows-amd64" || value === "linux-amd64" || value === "linux-arm64";
}

/** SHA-256 (hex) via WebCrypto - available in Bun without extra deps. */
async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes as unknown as ArrayBuffer);
  return Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export type ReleaseAsset = { name: string; url: string; size: number };

/** List release assets for the configured release, tolerating rate limits. */
export async function fetchReleaseAssets(opts: ReleaseFetchOptions = {}, fetchImpl: typeof fetch = fetch): Promise<ReleaseAsset[]> {
  const apiUrl = opts.releaseApiUrl ?? defaultReleaseApiUrl();
  const response = await fetchImpl(apiUrl, { headers: { "user-agent": "HBS-Dashboard", accept: "application/vnd.github+json" } });
  if (!response.ok) {
    throw new Error(`release lookup failed (HTTP ${response.status})`);
  }
  const release = (await response.json()) as { assets?: Array<{ name: string; browser_download_url: string; size: number }> };
  return (release.assets ?? []).map((asset) => ({ name: asset.name, url: asset.browser_download_url, size: asset.size }));
}

function pickAgentAsset(assets: ReleaseAsset[], platform: AgentPlatform): ReleaseAsset | null {
  const { target, ext } = RELEASE_ASSET_TARGETS[platform];
  const re = new RegExp(`^hbs-extractor-\\S+-${target.replace(/[+]/g, "\\+")}${ext}$`, "i");
  return assets.find((asset) => re.test(asset.name)) ?? null;
}

async function expectedSha256(assets: ReleaseAsset[], assetName: string, fetchImpl: typeof fetch): Promise<string | null> {
  const sums = assets.find((asset) => asset.name === "SHA256SUMS");
  if (!sums) return null;
  const response = await fetchImpl(sums.url, { headers: { "user-agent": "HBS-Dashboard" } });
  if (!response.ok) return null;
  const text = await response.text();
  for (const line of text.split(/\r?\n/)) {
    const match = /^([0-9a-f]{64})\s+\*?(.+)$/i.exec(line.trim());
    if (match && match[2] === assetName) return match[1].toLowerCase();
  }
  return null;
}

/**
 * Return the agent template for `platform`: cached file when present,
 * otherwise download + checksum-verify from GitHub Releases and cache it.
 * Throws with an actionable message when nothing is available.
 */
export async function ensureAgentTemplate(
  platform: AgentPlatform,
  opts: ReleaseFetchOptions = {},
  fetchImpl: typeof fetch = fetch,
): Promise<ReleaseFetchResult> {
  if (!isPlatform(platform)) throw new Error(`unsupported platform '${String(platform)}'`);
  const outputDir = opts.outputDir ?? resolve(import.meta.dir, "..", "binaries");
  const cached = cachePath(outputDir, platform);
  if (existsSync(cached)) {
    return { source: "cache", template: new Uint8Array(readFileSync(cached)), assetName: cached, sha256: "" };
  }
  if (opts.disabled || process.env.HBS_AGENT_RELEASE_DISABLE === "1") {
    throw new Error(
      `no local template at ${cached} and release fetch is disabled; ` +
        "place a dashboard/binaries/<platform> template manually or re-enable release fetch",
    );
  }

  const assets = await fetchReleaseAssets(opts, fetchImpl);
  const asset = pickAgentAsset(assets, platform);
  if (!asset) {
    throw new Error(`no extractor asset for ${platform} in the release (looked for hbs-extractor-*-${RELEASE_ASSET_TARGETS[platform].target}${RELEASE_ASSET_TARGETS[platform].ext})`);
  }
  const response = await fetchImpl(asset.url, { headers: { "user-agent": "HBS-Dashboard" } });
  if (!response.ok) throw new Error(`asset download failed (HTTP ${response.status})`);
  const bytes = new Uint8Array(await response.arrayBuffer());

  const expected = await expectedSha256(assets, asset.name, fetchImpl);
  if (expected) {
    const actual = await sha256Hex(bytes);
    if (actual !== expected) {
      throw new Error(`checksum mismatch for ${asset.name}: expected ${expected}, got ${actual} - refusing the binary`);
    }
  }

  mkdirSync(outputDir, { recursive: true });
  writeFileSync(cached, bytes);
  return { source: "release", template: bytes, assetName: asset.name, sha256: expected ?? "unverified" };
}

/** Sync read used by listing paths: cache only, no network. */
export function cachedAgentTemplate(outputDir: string | undefined, platform: AgentPlatform): Uint8Array | null {
  const cached = cachePath(outputDir ?? resolve(import.meta.dir, "..", "binaries"), platform);
  if (!existsSync(cached)) return null;
  return new Uint8Array(readFileSync(cached));
}
