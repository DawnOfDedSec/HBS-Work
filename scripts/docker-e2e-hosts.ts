// Full real-world host sweep:
//   1. host the dashboard on this Windows machine (0.0.0.0:PORT);
//   2. create a campaign/location/issuance and build a patched linux-amd64 extractor;
//   3. for a matrix of distro versions, start a container that DOWNLOADS the
//      extractor FROM the dashboard, runs it, and PUSHES the sealed report back;
//   4. also exercise the offline + multipart-upload path;
//   5. assert the dashboard ingested every report (hosts/findings) and print the
//      extractor logs + per-host testcase summary.
//
// Run: cd dashboard && bun run ../scripts/docker-e2e-hosts.ts
// Needs: Docker Desktop, and a built musl binary (cargo zigbuild; the script builds it if missing).

import { closeSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, openSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const repo = resolve(import.meta.dir, "..");
const dashboardDir = join(repo, "dashboard");
const PORT = Number(process.env.HBS_E2E_PORT ?? (20000 + Math.floor(Math.random() * 20000)));
const BASE = `http://127.0.0.1:${PORT}`;
const DOCKER_BASE = `http://host.docker.internal:${PORT}`;
const work = mkdtempSync(join(tmpdir(), "hbs-hosts-"));
const outDir = join(work, "out");
const binDir = join(dashboardDir, "binaries");
mkdirSync(outDir, { recursive: true });
mkdirSync(binDir, { recursive: true });

const IMAGES = (process.env.HBS_DOCKER_IMAGES ??
  "ubuntu:20.04,ubuntu:22.04,ubuntu:24.04,debian:11,debian:12,alpine:3.18,alpine:3.20,rockylinux:8,rockylinux:9,amazonlinux:2,amazonlinux:2023,opensuse/leap:15.5,archlinux:latest")
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

// --- 0. ensure the static musl binary exists, and publish it as the template ---
const musl = join(repo, "extractor", "target", "x86_64-unknown-linux-musl", "debug", "hbs-extractor");
if (!existsSync(musl)) {
  console.log("building linux-musl extractor ...");
  const cargoPath = "/c/Users/jonmori/.cargo/bin";
  const build = Bun.spawnSync(
    ["cargo", "zigbuild", "--target", "x86_64-unknown-linux-musl"],
    { cwd: join(repo, "extractor"), env: { ...process.env, PATH: `${cargoPath}:${process.env.PATH}` }, stdout: "inherit", stderr: "inherit" },
  );
  if (build.exitCode !== 0) {
    console.error("musl build failed; run scripts/docker-test/run.sh first");
    process.exit(2);
  }
}
copyFileSync(musl, join(binDir, "linux-amd64"));

// --- 1. host the dashboard on 0.0.0.0 ---
const dbPath = join(work, "hosts.sqlite");
const dataRoot = join(work, "data");
const dashLogFd = openSync(join(work, "dashboard.log"), "w");
const server = Bun.spawn(["bun", "server/index.ts"], {
  cwd: dashboardDir,
  env: { ...process.env, HOST: "0.0.0.0", PORT: String(PORT), HBS_DB_PATH: dbPath, HBS_DATA_ROOT: dataRoot, HBS_BOOTSTRAP_ADMIN: "false" },
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
      const res = await fetch(`${BASE}/api/health`);
      if (res.ok) return true;
    } catch {
      // not up yet
    }
    await Bun.sleep(500);
  }
  return false;
}

async function shutdown(): Promise<void> {
  for (let i = 0; i < 5 && server.exitCode === null; i += 1) {
    server.kill();
    await Bun.sleep(200);
  }
  await server.exited.catch(() => {});
}

let scenarios: string[] = [];
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
    body: JSON.stringify({ name: "Docker host sweep", locations: [{ name: "Fleet" }] }),
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
    body: JSON.stringify({ platform: "linux-amd64" }),
  });
  const issuance = (await issued.json()) as Record<string, any>;
  check(issued.status === 201 && typeof issuance.id === "string", "linux-amd64 extractor issued");
  console.log(`     extractor id ${issuance.id}, sha256 ${String(issuance.artifactSha256).slice(0, 16)}…`);

  // Host-side download sanity (proves the dashboard serves the artifact).
  const hostDownload = await fetch(
    `${BASE}/api/issuances/${issuance.id}/download?token=${encodeURIComponent(downloadToken)}`,
  );
  check(hostDownload.status === 200, "extractor downloadable from the dashboard (token auth)");

  // --- 2. container sweep ---
  for (const image of IMAGES) {
    const tag = image.replace(/[:/]/g, "_");
    const containerOut = join(outDir, tag);
    mkdirSync(containerOut, { recursive: true });

    // Alternate push vs upload-only to exercise both arrival paths.
    const viaUpload = scenarios.length % 2 === 1;
    const pushArg = viaUpload ? "" : `--push ${DOCKER_BASE}/api/ingest --push-token-file /tmp/token`;

    const script = `
      set +e
      if command -v curl >/dev/null 2>&1; then DL="curl -fsSL";
      elif command -v wget >/dev/null 2>&1; then DL="wget -q -O -";
      else
        export DEBIAN_FRONTEND=noninteractive
        if command -v apt-get >/dev/null 2>&1; then apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq curl >/dev/null 2>&1;
        elif command -v dnf >/dev/null 2>&1; then dnf install -y -q curl >/dev/null 2>&1;
        elif command -v yum >/dev/null 2>&1; then yum install -y -q curl >/dev/null 2>&1;
        elif command -v apk >/dev/null 2>&1; then apk add --no-cache curl >/dev/null 2>&1;
        elif command -v zypper >/dev/null 2>&1; then zypper -n install curl >/dev/null 2>&1;
        elif command -v pacman >/dev/null 2>&1; then pacman -Sy --noconfirm curl >/dev/null 2>&1;
        fi
        command -v curl >/dev/null 2>&1 && DL="curl -fsSL" || DL=""
      fi
      URL="$HBS_URL/api/issuances/$HBS_ISSUANCE/download?token=$HBS_DOWNLOAD_TOKEN"
      if [ -n "$DL" ]; then
        $DL "$URL" > /tmp/hbs 2>/tmp/dl.err
      elif command -v bash >/dev/null 2>&1 && [ -f /http-get.sh ]; then
        bash /http-get.sh "$URL" > /tmp/hbs 2>/tmp/dl.err
      else
        echo "DOWNLOAD_FAILED: no downloader" >&2; exit 9
      fi
      [ -s /tmp/hbs ] || { echo "DOWNLOAD_FAILED"; cat /tmp/dl.err; exit 9; }
      chmod +x /tmp/hbs
      printf '%s' "$PUSH_TOKEN_VALUE" > /tmp/token
      echo "=== downloaded $(wc -c < /tmp/hbs) bytes ==="
      /tmp/hbs --no-elevate --no-pause ${pushArg} --out /out/report.hbs
      echo "EXIT=$?"
    `;

    console.log(`\n=== ${image} (${viaUpload ? "offline + upload" : "push"}) ===`);
    const run = Bun.spawnSync(
      [
        "docker", "run", "--rm",
        "--add-host", "host.docker.internal:host-gateway",
        "-v", `${containerOut}:/out`,
        "-v", `${join(repo, "scripts", "docker-test", "http-get-bash.sh")}:/http-get.sh:ro`,
        "-e", `HBS_URL=${DOCKER_BASE}`,
        "-e", `HBS_ISSUANCE=${issuance.id}`,
        "-e", `HBS_DOWNLOAD_TOKEN=${downloadToken}`,
        "-e", `PUSH_TOKEN_VALUE=${pushToken}`,
        image,
        "sh", "-c", script,
      ],
      { stdout: "pipe", stderr: "pipe" },
    );

    const log = `${run.stdout.toString()}${run.stderr.toString()}`;
    writeFileSync(join(containerOut, "run.log"), log);
    const reportPath = join(containerOut, "report.hbs");
    const sealed = existsSync(reportPath) ? readFileSync(reportPath) : Buffer.alloc(0);
    const exitLine = /EXIT=(\d+)/.exec(log);
    const containerExit = exitLine ? Number(exitLine[1]) : run.exitCode;
    const downloaded = /downloaded (\d+) bytes/.exec(log);

    check(downloaded !== null, `${image}: downloaded extractor from the dashboard`);
    check(containerExit === 0, `${image}: extractor exited 0`);
    check(sealed.subarray(0, 4).toString("ascii") === "HBS2", `${image}: sealed HBS2 report (${sealed.length} bytes)`);

    if (viaUpload && sealed.length > 0) {
      const form = new FormData();
      form.set("files", new Blob([new Uint8Array(sealed)]), `${tag}.hbs`);
      const uploaded = await api("/api/reports/upload", { method: "POST", body: form });
      const body = (await uploaded.json()) as { results?: { result?: { ok?: boolean } }[] };
      check(uploaded.status === 200 && body.results?.[0]?.result?.ok === true, `${image}: multipart upload accepted`);
    }
    scenarios.push(image);
    // keep only the last chunk of console output
    console.log(log.split("\n").slice(-6).join("\n"));
  }

  // --- 3. assert the dashboard saw the results ---
  const hosts = (await (await api("/api/hosts")).json()) as { hosts?: unknown[] };
  check((hosts.hosts?.length ?? 0) >= IMAGES.length - 1, `dashboard routed ${hosts.hosts?.length} distinct hosts`);
  const findings = (await (await api("/api/findings")).json()) as { results?: unknown[]; total?: number };
  check((findings.total ?? findings.results?.length ?? 0) > 0, "dashboard exposes ingested findings");

  const reports = (await (await api("/api/reports")).json()) as unknown;
  console.log(`\ndashboard reports payload: ${JSON.stringify(reports).slice(0, 200)}…`);
} finally {
  await shutdown();
  try {
    closeSync(dashLogFd);
  } catch {
    // already closed
  }
}

console.log(`\nartifacts: ${outDir}`);
for (const image of IMAGES) {
  const tag = image.replace(/[:/]/g, "_");
  const logPath = join(outDir, tag, "run.log");
  if (!existsSync(logPath)) continue;
  const lines = readFileSync(logPath, "utf8").split("\n");
  console.log(`\n----- ${image} extractor log (tail) -----`);
  console.log(lines.slice(-12).join("\n"));
}

if (failures.length > 0) {
  console.error(`\n${failures.length} failure(s):`);
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
}
console.log(`\nDOCKER HOST SWEEP PASS: ${IMAGES.length} distro versions validated against the hosted dashboard`);
process.exit(0);
