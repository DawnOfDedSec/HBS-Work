// Linux end-to-end loop, run for real inside a container:
//   dashboard issues a patched musl extractor  ->  run it in Debian 12 offline
//   ->  sealed HBS2 report  ->  push with the campaign token  ->  ingest,
//   routing, and exports validated.
//
// Run: cd dashboard && bun run ../scripts/e2e-linux.ts
// Needs: (cd extractor && cargo zigbuild --target x86_64-unknown-linux-musl) and Docker.

import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const repo = resolve(import.meta.dir, "..");
const work = mkdtempSync(join(tmpdir(), "hbs-e2e-linux-"));
process.env.HBS_DB_PATH = join(work, "e2e.sqlite");
process.env.HBS_DATA_ROOT = join(work, "data");
mkdirSync(process.env.HBS_DATA_ROOT, { recursive: true });

const binaries = join(repo, "dashboard", "binaries");
mkdirSync(binaries, { recursive: true });
const musl = join(repo, "extractor", "target", "x86_64-unknown-linux-musl", "debug", "hbs-extractor");
copyFileSync(musl, join(binaries, "linux-amd64"));

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

let failures = 0;
function check(condition: unknown, label: string): void {
  if (condition) console.log(`ok   - ${label}`);
  else {
    failures += 1;
    console.error(`FAIL - ${label}`);
  }
}

await req("/api/auth/setup", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ username: "admin", password: "correct horse battery staple" }),
});

const created = await req("/api/campaigns", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ name: "Linux E2E", locations: [{ name: "DC" }] }),
});
const campaign = (await created.json()) as Record<string, any>;
const campaignId = campaign.id as number;
const locationId = (campaign.locations ?? [])[0]?.id as number;
const pushToken = campaign.pushToken as string;
check(created.status === 201 && Number.isInteger(campaignId) && Number.isInteger(locationId), "campaign + location created");

const issued = await req(`/api/campaigns/${campaignId}/locations/${locationId}/issuances`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ platform: "linux-amd64" }),
});
const issuance = (await issued.json()) as Record<string, any>;
check(issued.status === 201 && typeof issuance.id === "string", "linux-amd64 extractor issued");

const download = await req(`/api/issuances/${issuance.id}/download`);
const issuedBin = join(work, "issued-musl.bin");
writeFileSync(issuedBin, new Uint8Array(await download.arrayBuffer()));
check(download.status === 200, "patched musl binary downloaded");

const outDir = join(work, "out");
mkdirSync(outDir, { recursive: true });
const run = Bun.spawnSync(
  [
    "docker", "run", "--rm",
    "-v", `${issuedBin}:/issued-hbs:ro`,
    "-v", `${outDir}:/out`,
    "--user", "0:0",
    "debian:12",
    "sh", "-c", "cp /issued-hbs /tmp/h && chmod +x /tmp/h && /tmp/h --no-elevate --no-pause --quiet --out /out/report.hbs",
  ],
  { stdout: "pipe", stderr: "pipe" },
);
if (run.exitCode !== 0) console.error(run.stderr.toString().slice(0, 600));
check(run.exitCode === 0, "issued musl extractor runs in debian:12 and seals a report");

const sealed = readFileSync(join(outDir, "report.hbs"));
check(sealed.subarray(0, 4).toString("ascii") === "HBS2", "sealed report is HBS2 v2");

// Confidentiality: only the dashboard key may open the report, and the issued
// binary must never carry the dashboard's private key.
try {
  const { parseEnvelope, unsealEnvelope } = await import(join(repo, "dashboard", "server", "envelope.ts"));
  const parsedEnv = parseEnvelope(new Uint8Array(sealed));
  let openedWithWrongKey = false;
  try {
    unsealEnvelope(parsedEnv, new Uint8Array(32).fill(0x5a));
    openedWithWrongKey = true;
  } catch {
    // expected
  }
  check(!openedWithWrongKey, "sealed report rejects a wrong key (confidentiality)");

  const priv = new Uint8Array(readFileSync(join(process.env.HBS_DATA_ROOT!, "keys", `${issuance.id}.key`)));
  check(!Buffer.from(sealed).includes(priv), "dashboard private key is absent from the sealed report");
  check(!Buffer.from(readFileSync(issuedBin)).includes(priv), "dashboard private key is absent from the issued binary");
} catch (error) {
  check(false, `confidentiality checks errored: ${(error as Error).message}`);
}

const pushed = await req("/api/ingest", {
  method: "POST",
  headers: { "content-type": "application/octet-stream", authorization: `Bearer ${pushToken}` },
  body: new Uint8Array(sealed),
});
const ingest = (await pushed.json()) as Record<string, any>;
if (!(pushed.status === 200 && ingest.ok === true)) console.error("ingest rejected:", pushed.status, JSON.stringify(ingest));
check(pushed.status === 200 && ingest.ok === true, "Linux container report ingested by push");

const reportId = ingest.reportId as number;
const report = await req(`/api/reports/${reportId}`);
const reportBody = (await report.json()) as Record<string, any>;
check(report.status === 200, "report detail available");
check(typeof reportBody.hostname === "string" && reportBody.hostname.length > 0, "report has hostname");
const hostMachineId = reportBody.machineId ?? reportBody.serialized?.machineId;
check(hostMachineId === undefined || (typeof hostMachineId === "string" && hostMachineId.length > 0), "report has machine id");

const hosts = (await (await req("/api/hosts")).json()) as Record<string, any>;
check((hosts.hosts ?? []).length >= 1, "container host auto-routed");

const csv = await req(`/api/export/report/${reportId}?format=csv`);
check(csv.status === 200 && (await csv.text()).length > 0, "CSV export");

console.log(failures === 0 ? `\nLINUX E2E PASS (workdir ${work})` : `\nLINUX E2E FAILED: ${failures} checks`);
process.exit(failures === 0 ? 0 : 1);
