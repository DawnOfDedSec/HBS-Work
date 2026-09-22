// Task 60 end-to-end loop (Windows/local, in-process HTTP):
//   dashboard issues a patched extractor  ->  run it offline  ->  sealed HBS2
//   ->  push with the campaign token  ->  ingest + host routing + exports.
//
// Run: cd dashboard && bun run ../scripts/e2e-loop.ts
// Requires the extractor debug binary: (cd extractor && cargo build).

import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const repo = resolve(import.meta.dir, "..");
const work = mkdtempSync(join(tmpdir(), "hbs-e2e-"));

process.env.HBS_DB_PATH = join(work, "e2e.sqlite");
process.env.HBS_DATA_ROOT = join(work, "data");
mkdirSync(process.env.HBS_DATA_ROOT, { recursive: true });

const binaries = join(repo, "dashboard", "binaries");
mkdirSync(binaries, { recursive: true });
const template = join(binaries, "windows-amd64");
copyFileSync(join(repo, "extractor", "target", "debug", "hbs-extractor.exe"), template);

const { app } = await import(join(repo, "dashboard", "server", "index.ts"));

let cookie = "";
async function req(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  if (cookie) headers.set("cookie", cookie);
  const response = await app.request(path, { ...init, headers });
  const setCookie = response.headers.get("set-cookie");
  if (setCookie) cookie = setCookie.split(";")[0]!;
  return response;
}

function dataId(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) ? value : null;
}

let failures = 0;
function check(condition: unknown, label: string): void {
  if (condition) console.log(`ok   - ${label}`);
  else {
    failures += 1;
    console.error(`FAIL - ${label}`);
  }
}

const health = await req("/api/health");
check(health.status === 200, "health route");

const setup = await req("/api/auth/setup", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ username: "admin", password: "correct horse battery staple" }),
});
check(setup.status === 201, "first-run setup creates super_admin");

const created = await req("/api/campaigns", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ name: "E2E Campaign", client: "Acme", locations: [{ name: "Lab" }] }),
});
check(created.status === 201, "create campaign with first location");
const campaign = (await created.json()) as Record<string, any>;
const campaignId = dataId(campaign.id);
const locationId = dataId((campaign.locations ?? [])[0]?.id);
const pushToken = campaign.pushToken as string | undefined;
check(campaignId !== null && locationId !== null, "campaign and location ids");
check(typeof pushToken === "string" && pushToken.length > 0, "campaign push token returned once");

const issued = await req(`/api/campaigns/${campaignId}/locations/${locationId}/issuances`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ platform: "windows-amd64" }),
});
check(issued.status === 201, "issue extractor (patched artifact + keypair)");
const issuedText = await issued.text();
if (issued.status !== 201) console.error("issuance error:", issuedText.slice(0, 600));
const issuance = (issuedText ? JSON.parse(issuedText) : {}) as Record<string, any>;
const issuanceId = issuance.id as string;
check(typeof issuanceId === "string" && issuanceId.length > 0, "issuance id");
check(typeof issuance.artifactSha256 === "string" && issuance.artifactSha256.length === 64, "artifact sha256 recorded");

const download = await req(`/api/issuances/${issuanceId}/download`);
check(download.status === 200, "download the exact patched artifact");
check(download.headers.get("x-hbs-sha256") === issuance.artifactSha256, "download hash matches issuance metadata");
const exePath = join(work, "issued-extractor.exe");
writeFileSync(exePath, new Uint8Array(await download.arrayBuffer()));

const reportPath = join(work, "report.hbs");
const run = Bun.spawnSync(
  [exePath, "--no-elevate", "--no-pause", "--quiet", "--out", reportPath],
  { stdout: "pipe", stderr: "pipe" },
);
if (run.exitCode !== 0) console.error(run.stderr.toString().slice(0, 500));
check(run.exitCode === 0, "issued extractor runs offline and seals a report");

const sealed = readFileSync(reportPath);
check(sealed.subarray(0, 4).toString("ascii") === "HBS2", "sealed report is an HBS2 v2 envelope");

const pushed = await req("/api/ingest", {
  method: "POST",
  headers: { "content-type": "application/octet-stream", authorization: `Bearer ${pushToken}` },
  body: new Uint8Array(sealed),
});
const ingestBody = (await pushed.json()) as Record<string, any>;
if (!(pushed.status === 200 && ingestBody.ok === true)) console.error("ingest rejected:", pushed.status, JSON.stringify(ingestBody));
check(pushed.status === 200 && ingestBody.ok === true, "push ingest accepted");
const reportId = dataId(ingestBody.reportId);

const replay = await req("/api/ingest", {
  method: "POST",
  headers: { "content-type": "application/octet-stream", authorization: `Bearer ${pushToken}` },
  body: new Uint8Array(sealed),
});
const replayBody = (await replay.json()) as Record<string, any>;
check(replayBody.ok === true && replayBody.duplicate === true, "duplicate replay is idempotent");

const hosts = (await (await req("/api/hosts")).json()) as Record<string, any>;
check((hosts.hosts ?? []).length >= 1, "host auto-routed by machine id");

const report = await req(`/api/reports/${reportId}`);
check(report.status === 200, "report detail available");

const findings = (await (await req("/api/findings")).json()) as Record<string, any>;
check((findings.results ?? []).length > 0, "findings populated");

const csv = await req(`/api/export/report/${reportId}?format=csv`);
check(csv.status === 200 && (await csv.text()).length > 0, "CSV export");
const xlsx = await req(`/api/export/report/${reportId}?format=xlsx`);
check(xlsx.status === 200, "XLSX export");
const pdf = await req(`/api/export/report/${reportId}?format=pdf&template=technical`);
check(pdf.status === 200, "techniCal PDF export");

console.log(failures === 0 ? `\nE2E PASS (workdir ${work})` : `\nE2E FAILED: ${failures} checks`);
process.exit(failures === 0 ? 0 : 1);
