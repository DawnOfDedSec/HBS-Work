// Windows-container host sweep (mirror of the Linux sweep):
//   dashboard hosted on this host -> containers DOWNLOAD the windows-amd64
//   extractor -> run it -> PUSH the sealed report back -> assert ingestion.
//
// Preconditions (Windows containers require elevation once):
//   Enable-WindowsOptionalFeature -Online -FeatureName Containers -All     (elevated)
//   Enable Hyper-V (or WSL2 backend already provides it)
//   & "$Env:ProgramFiles\Docker\Docker\DockerCli.exe" -SwitchWindowsEngine
// and a statically linked windows binary:
//   cd extractor && $env:RUSTFLAGS='-C target-feature=+crt-static'
//   cargo build --target x86_64-pc-windows-msvc
//
// Run: cd dashboard && bun run ../scripts/docker-e2e-hosts-windows.ts

import { closeSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const repo = resolve(import.meta.dir, "..");
const dashboardDir = join(repo, "dashboard");
const PORT = Number(process.env.HBS_E2E_PORT ?? (20000 + Math.floor(Math.random() * 20000)));
const BASE = `http://127.0.0.1:${PORT}`;
// Windows containers cannot resolve host.docker.internal; use the host IP that
// the container's NAT network can reach (resolved after the engine check).
let DOCKER_BASE = `http://172.22.224.1:${PORT}`;
const ISOLATION = process.env.HBS_WINDOWS_ISOLATION ?? "hyperv";
const work = mkdtempSync(join(tmpdir(), "hbs-win-hosts-"));
const outDir = join(work, "out");
const binDir = join(dashboardDir, "binaries");
mkdirSync(outDir, { recursive: true });
mkdirSync(binDir, { recursive: true });

// Server Core images include the OS tools the checks use (reg.exe, netsh,
// wevtutil, PowerShell). nanoserver is intentionally excluded: it is too
// minimal and the extractor exits 0xC0000135 (STATUS_DLL_NOT_FOUND) there.
const IMAGES = (process.env.HBS_WINDOWS_IMAGES ??
  "mcr.microsoft.com/windows/servercore:ltsc2019,mcr.microsoft.com/windows/servercore:ltsc2022,mcr.microsoft.com/windows/servercore:ltsc2025")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const failures: string[] = [];
function check(condition: unknown, label: string): void {
  if (condition) console.log(`ok   - ${label}`);
  else {
    failures.push(label);
    console.error(`FAIL - ${label}`);
  }
}

// --- engine must be Windows containers ---
function dockerOsType(): string {
  return Bun.spawnSync(["docker", "info", "--format", "{{.OSType}}"]).stdout.toString().trim();
}
if (dockerOsType() !== "windows") {
  console.error(`Docker engine is in '${dockerOsType()}' mode, not Windows containers.`);
  console.error("Enable it once (elevated), then re-run this script:");
  console.error("  Enable-WindowsOptionalFeature -Online -FeatureName Containers -All");
  console.error("  & \"$Env:ProgramFiles\\Docker\\Docker\\DockerCli.exe\" -SwitchWindowsEngine");
  console.error("If Hyper-V isolation is unavailable use HBS_WINDOWS_ISOLATION=process on a matching host.");
  process.exit(2);
}

// A Windows container reaches the host via the NAT gateway (not host.docker.internal).
{
  const gateway = Bun.spawnSync([
    "docker", "network", "inspect", "nat", "--format", "{{(index .IPAM.Config 0).Gateway}}",
  ]).stdout.toString().trim();
  if (/^\d+\.\d+\.\d+\.\d+$/.test(gateway)) DOCKER_BASE = `http://${gateway}:${PORT}`;
  console.log(`windows containers will reach the dashboard at ${DOCKER_BASE}`);
}

const template = join(repo, "extractor", "target", "x86_64-pc-windows-msvc", "debug", "hbs-extractor.exe");
if (!existsSync(template)) {
  console.error("missing static windows binary; build it with:");
  console.error("  cd extractor && $env:RUSTFLAGS='-C target-feature=+crt-static'; cargo build --target x86_64-pc-windows-msvc");
  process.exit(2);
}
copyFileSync(template, join(binDir, "windows-amd64"));

const dashLogFd = openSync(join(work, "dashboard.log"), "w");
const server = Bun.spawn(["bun", "server/index.ts"], {
  cwd: dashboardDir,
  env: {
    ...process.env,
    HOST: "0.0.0.0",
    PORT: String(PORT),
    HBS_DB_PATH: join(work, "hosts.sqlite"),
    HBS_DATA_ROOT: join(work, "data"),
    HBS_BOOTSTRAP_ADMIN: "false",
  },
  stdout: dashLogFd,
  stderr: dashLogFd,
});

let cookie = "";
async function api(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  if (cookie) headers.set("cookie", cookie);
  const res = await fetch(`${BASE}${path}`, { ...init, headers });
  const setCookie = res.headers.get("set-cookie");
  if (setCookie) cookie = setCookie.split(";")[0]!;
  return res;
}

async function waitForDashboard(): Promise<boolean> {
  for (let i = 0; i < 60; i += 1) {
    try {
      if ((await fetch(`${BASE}/api/health`)).ok) return true;
    } catch {
      // not up yet
    }
    await Bun.sleep(500);
  }
  return false;
}

let validated = 0;
try {
  check(await waitForDashboard(), `dashboard hosted on ${BASE}`);

  await api("/api/auth/setup", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username: "admin", password: "correct horse battery staple" }),
  });
  const created = await api("/api/campaigns", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ name: "Windows container sweep", locations: [{ name: "Fleet" }] }),
  });
  const campaign = (await created.json()) as Record<string, any>;
  const campaignId = campaign.id as number;
  const locationId = (campaign.locations ?? [])[0]?.id as number;
  const downloadToken = campaign.downloadToken as string;
  const pushToken = campaign.pushToken as string;
  check(created.status === 201, "campaign + location created");

  const issued = await api(`/api/campaigns/${campaignId}/locations/${locationId}/issuances`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ platform: "windows-amd64" }),
  });
  const issuance = (await issued.json()) as Record<string, any>;
  check(issued.status === 201, "windows-amd64 extractor issued");

  for (const image of IMAGES) {
    const tag = image.replace(/[:/.]/g, "_");
    const containerOut = join(outDir, tag);
    mkdirSync(containerOut, { recursive: true });
    writeFileSync(join(containerOut, "token"), pushToken);

    // cmd script (curl.exe ships in servercore and nanoserver; PowerShell in servercore).
    writeFileSync(
      join(containerOut, "run.cmd"),
      [
        "@echo off",
        "setlocal",
        `if exist "%SystemRoot%\\System32\\curl.exe" (`,
        `  echo URL=%HBS_URL% ISS=%HBS_ISSUANCE%`,
        `  "%SystemRoot%\\System32\\curl.exe" -fsSL "%HBS_URL%/api/issuances/%HBS_ISSUANCE%/download?token=%HBS_DOWNLOAD_TOKEN%" -o C:\\hbs.exe`,
        `  echo CURL_EXIT=%errorlevel%`,
        ") else (",
        `  powershell -NoProfile -Command "Invoke-WebRequest -UseBasicParsing -Uri '%HBS_URL%/api/issuances/%HBS_ISSUANCE%/download?token=%HBS_DOWNLOAD_TOKEN%' -OutFile 'C:\\hbs.exe'"`,
        ")",
        "if not exist C:\\hbs.exe ( echo DOWNLOAD_FAILED & exit /b 9 )",
        `C:\\hbs.exe --no-elevate --no-pause --push "%HBS_URL%/api/ingest" --push-token-file C:\\out\\token --out C:\\out\\report.hbs`,
        "echo EXIT=%errorlevel%",
      ].join("\r\n"),
    );

    console.log(`\n=== ${image} (isolation ${ISOLATION}) ===`);
    const run = Bun.spawnSync(
      [
        "docker", "run", "--rm",
        `--isolation=${ISOLATION}`,
        "-v", `${containerOut}:C:\\out`,
        "-e", `HBS_URL=${DOCKER_BASE}`,
        "-e", `HBS_ISSUANCE=${issuance.id}`,
        "-e", `HBS_DOWNLOAD_TOKEN=${downloadToken}`,
        image,
        "cmd", "/c", "C:\\out\\run.cmd",
      ],
      { stdout: "pipe", stderr: "pipe" },
    );

    const log = `${run.stdout.toString()}${run.stderr.toString()}`;
    writeFileSync(join(containerOut, "run.log"), log);
    const reportPath = join(containerOut, "report.hbs");
    const sealed = existsSync(reportPath) ? readFileSync(reportPath) : Buffer.alloc(0);
    const exitLine = /EXIT=(\d+)/.exec(log);
    const containerExit = exitLine ? Number(exitLine[1]) : run.exitCode;

    check(containerExit === 0, `${image}: extractor exited 0`);
    check(sealed.subarray(0, 4).toString("ascii") === "HBS2", `${image}: sealed HBS2 report (${sealed.length} bytes)`);
    if (containerExit === 0) validated += 1;
    console.log(log.split("\r\n").slice(-8).join("\n"));
  }

  const hosts = (await (await api("/api/hosts")).json()) as { hosts?: unknown[] };
  check((hosts.hosts?.length ?? 0) >= 1, `dashboard routed ${hosts.hosts?.length ?? 0} Windows hosts`);
} finally {
  for (let i = 0; i < 5 && server.exitCode === null; i += 1) {
    server.kill();
    await Bun.sleep(200);
  }
  await server.exited.catch(() => {});
  try {
    closeSync(dashLogFd);
  } catch {
    // already closed
  }
}

console.log(`\nartifacts: ${outDir}`);
if (failures.length > 0) {
  console.error(`${failures.length} failure(s):`);
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
}
console.log(`WINDOWS CONTAINER SWEEP PASS: ${validated} image(s) validated`);
process.exit(0);
