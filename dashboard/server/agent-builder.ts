// On-demand agent template builder: fetches the extractor source (from the
// local repo checkout or a GitHub clone) and runs `cargo build --release` to
// produce `binaries/<platform>` for the issuance pipeline.
//
// Native builds only: the host toolchain must match the requested platform
// (windows-amd64 on Windows, linux-amd64 on Linux). Cross targets belong to
// the CI release workflow. All external commands go through an injectable
// runner so tests never touch git/cargo.

import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, rmSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

export type AgentPlatform = "windows-amd64" | "linux-amd64" | "linux-arm64";

export type BuildOptions = {
  platform: AgentPlatform;
  /** Source checkout to build. Defaults to the sibling `extractor/` folder. */
  sourcePath?: string;
  /** GitHub URL to clone into a cached workspace when no local checkout exists. */
  repoUrl?: string;
  /** Branch/tag to check out when cloning. Default: the remote default branch. */
  ref?: string;
  /** Where the finished template is written. Default: dashboard/binaries. */
  outputDir?: string;
  /** Workspace for clones and build artifacts. Default: server/data/agent-builds. */
  workDir?: string;
  buildTimeoutMs?: number;
  runner?: RunnerLike;
};

export type RunnerLike = (
  binary: string,
  args: string[],
  options: { cwd?: string; timeoutMs?: number },
) => { status: number | null; stdout: string; stderr: string };

export type BuildResult = {
  ok: boolean;
  templatePath?: string;
  cloned?: boolean;
  seconds: number;
  error?: string;
};

export const DEFAULT_REPO_URL = "https://github.com/PotenFYR-Studios/HBS-Tool.git";

const BUILD_LOCKS = new Map<string, Promise<BuildResult>>();

function defaultRunner(binary: string, args: string[], options: { cwd?: string; timeoutMs?: number }) {
  const result = spawnSync(binary, args, {
    cwd: options.cwd,
    timeout: options.timeoutMs,
    encoding: "utf8",
    windowsHide: true,
  });
  return { status: result.status, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
}

function runOrFail(
  runner: RunnerLike,
  binary: string,
  args: string[],
  cwd: string | undefined,
  timeoutMs: number,
  failureLabel: string,
): void {
  const result = runner(binary, args, { cwd, timeoutMs });
  if (result.status !== 0) {
    const detail = (result.stderr || result.stdout || `exit ${result.status}`).trim().slice(-400);
    throw new Error(`${failureLabel}: ${detail}`);
  }
}

/** Host platform → buildable agent target; null when the host cannot build it. */
export function hostPlatformFor(platform: AgentPlatform): AgentPlatform | null {
  if (process.platform === "win32") return platform === "windows-amd64" ? platform : null;
  if (process.platform === "linux") {
    const hostArm = process.arch === "arm64";
    return hostArm ? (platform === "linux-arm64" ? platform : null) : platform === "linux-amd64" ? platform : null;
  }
  return null;
}

function binaryName(platform: AgentPlatform): string {
  return platform === "windows-amd64" ? "hbs-extractor.exe" : "hbs-extractor";
}

function defaultSourcePath(): string | null {
  // The dashboard normally runs inside the repo clone - the extractor source
  // is the sibling folder. Also honor an explicit env override.
  const candidates = [
    process.env.HBS_AGENT_SOURCE_PATH,
    resolve(import.meta.dir, "..", "..", "..", "extractor"),
    resolve(process.cwd(), "..", "extractor"),
  ].filter((entry): entry is string => Boolean(entry));
  for (const candidate of candidates) {
    if (existsSync(join(candidate, "Cargo.toml"))) return resolve(candidate);
  }
  return null;
}

/**
 * Build (or reuse) the agent template for `platform`. Serialized per platform:
 * concurrent callers await the same in-flight build.
 */
export function buildAgentTemplate(options: BuildOptions): Promise<BuildResult> {
  const key = options.platform;
  const inFlight = BUILD_LOCKS.get(key);
  if (inFlight) return inFlight;
  const promise = buildOnce(options).finally(() => BUILD_LOCKS.delete(key));
  BUILD_LOCKS.set(key, promise);
  return promise;
}

async function buildOnce(options: BuildOptions): Promise<BuildResult> {
  const started = Date.now();
  try {
    const host = hostPlatformFor(options.platform);
    if (host === null) {
      throw new Error(
        `native build for '${options.platform}' is not possible on this host (${process.platform}/${process.arch}); use the CI release workflow`,
      );
    }
    const runner = options.runner ?? defaultRunner;
    const timeoutMs = options.buildTimeoutMs ?? 15 * 60_000;
    const outputDir = options.outputDir ?? resolve(import.meta.dir, "..", "binaries");
    const workDir = options.workDir ?? join(resolve(import.meta.dir, "..", "data"), "agent-builds");
    mkdirSync(outputDir, { recursive: true });
    mkdirSync(workDir, { recursive: true });

    let sourcePath = options.sourcePath ?? defaultSourcePath();
    let cloned = false;
    if (!sourcePath) {
      const repoUrl = options.repoUrl ?? process.env.HBS_AGENT_REPO_URL ?? DEFAULT_REPO_URL;
      const ref = options.ref ?? process.env.HBS_AGENT_REF;
      const cacheDir = join(workDir, "agent-src");
      if (existsSync(join(cacheDir, ".git"))) {
        runOrFail(runner, "git", ["fetch", "--all", "--tags"], cacheDir, 120_000, "git fetch failed");
      } else {
        rmSync(cacheDir, { force: true, recursive: true });
        mkdirSync(join(workDir), { recursive: true });
        runOrFail(runner, "git", ["clone", repoUrl, cacheDir], undefined, 300_000, "git clone failed");
        cloned = true;
      }
      if (ref) runOrFail(runner, "git", ["checkout", ref], cacheDir, 60_000, "git checkout failed");
      sourcePath = join(cacheDir, "extractor");
      if (!existsSync(join(sourcePath, "Cargo.toml"))) {
        throw new Error("cloned repository does not contain extractor/Cargo.toml");
      }
    } else {
      sourcePath = resolve(sourcePath);
      if (!existsSync(join(sourcePath, "Cargo.toml"))) {
        throw new Error(`no extractor source at ${sourcePath}`);
      }
    }

    runOrFail(runner, "cargo", ["build", "--release"], sourcePath, timeoutMs, "cargo build failed");

    const builtPath = join(sourcePath, "target", "release", binaryName(options.platform));
    if (!existsSync(builtPath)) throw new Error(`cargo build finished but ${builtPath} is missing`);
    if (statSync(builtPath).size < 1024) throw new Error("built binary is implausibly small");

    const templatePath = join(outputDir, options.platform);
    copyFileSync(builtPath, templatePath);
    return { ok: true, templatePath, cloned, seconds: (Date.now() - started) / 1000 };
  } catch (error) {
    return { ok: false, seconds: (Date.now() - started) / 1000, error: (error as Error).message };
  }
}

/** Status probe used by the admin UI before attempting a build. */
export function templateStatus(outputDir: string | undefined, platform: AgentPlatform): { present: boolean; path: string; size: number | null; builtAt: string | null } {
  const dir = outputDir ?? resolve(import.meta.dir, "..", "binaries");
  const path = join(dir, platform);
  if (!existsSync(path)) return { present: false, path, size: null, builtAt: null };
  const stats = statSync(path);
  return { present: true, path, size: stats.size, builtAt: stats.mtime.toISOString() };
}

/** CLI entry: `bun server/agent-builder.ts <platform>` - builds and prints the path. */
if (import.meta.main) {
  const platform = process.argv[2] as AgentPlatform | undefined;
  if (!platform || !["windows-amd64", "linux-amd64", "linux-arm64"].includes(platform)) {
    console.error("usage: bun server/agent-builder.ts <windows-amd64|linux-amd64|linux-arm64>");
    process.exit(2);
  }
  const result = await buildAgentTemplate({ platform });
  if (result.ok) {
    console.log(`template ready: ${result.templatePath} (${result.seconds.toFixed(1)}s${result.cloned ? ", freshly cloned" : ""})`);
  } else {
    console.error(`build failed: ${result.error}`);
    process.exit(3);
  }
}
