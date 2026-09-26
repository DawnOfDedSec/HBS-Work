// Network configuration poller: pulls running configs from network devices
// over the system OpenSSH client and uploads them for review.
//
//   bun tools/network-poller.ts --devices devices.json [--dry-run] [--interval 900]
//
// Devices file:
// {
//   "campaignId": 1,
//   "locationId": 2,
//   "devices": [
//     { "name": "core-sw", "host": "10.0.0.5", "vendor": "cisco-ios",
//       "username": "netops", "port": 22 }
//   ]
// }
//
// Credentials come from the environment (never the devices file):
//   HBS_POLLER_URL / HBS_POLLER_USERNAME / HBS_POLLER_PASSWORD  dashboard + login
//   HBS_POLLER_KEY                                              SSH private key path
//
// No new dependencies: SSH is delegated to the system `ssh` binary
// (key-based, BatchMode) and HTTP to global fetch.

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";

export type DeviceSpec = {
  name: string;
  host: string;
  vendor: string;
  username: string;
  port: number;
  /** Optional override; defaults to the vendor's running-config command. */
  command?: string;
};

export type DevicesFile = {
  campaignId: number;
  locationId: number;
  devices: DeviceSpec[];
};

export type PollerOptions = {
  dashboardUrl: string;
  username: string;
  password: string;
  /** SSH private key passed via -i; omit to rely on the agent/default keys. */
  keyPath?: string;
  sshBinary?: string;
  connectTimeoutSeconds?: number;
};

type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;
type RunnerLike = (binary: string, args: string[], timeoutMs: number) => { status: number | null; stdout: string; stderr: string };

/** Vendor-specific command that dumps the full running configuration. */
export function commandFor(vendor: string): string {
  switch (vendor) {
    case "cisco-ios":
    case "cisco-nxos":
    case "cisco-wlc-iosxe":
    case "aruba-switch":
    case "arubaos":
      return "show running-config";
    case "cisco-asa":
      return "show running-config";
    case "juniper-junos":
      return "show configuration | display set";
    case "palo-alto":
      return "show config running";
    case "fortinet":
      return "show full-configuration";
    case "ubiquiti":
      return "show configuration commands";
    case "f5":
      return "tmsh list sys config";
    case "sonicwall":
      return "show config";
    case "cisco-wlc":
      return "show run-config";
    default:
      return "show running-config";
  }
}

function positiveInt(value: unknown): number | null {
  const parsed = typeof value === "number" ? value : Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
}

/** Parse and validate a devices file. Throws with a readable message. */
export function parseDevicesFile(rawText: string): DevicesFile {
  // Windows-authored files often carry a UTF-8 BOM.
  const text = rawText.replace(/^\uFEFF/, "");
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("devices file is not valid JSON");
  }
  if (!parsed || typeof parsed !== "object") throw new Error("devices file must be a JSON object");
  const doc = parsed as Record<string, unknown>;
  const campaignId = positiveInt(doc.campaignId);
  const locationId = positiveInt(doc.locationId);
  if (!campaignId) throw new Error("devices file requires a positive integer campaignId");
  if (!locationId) throw new Error("devices file requires a positive integer locationId");
  if (!Array.isArray(doc.devices)) throw new Error("devices file requires a devices array");

  const devices: DeviceSpec[] = doc.devices.map((entry, index) => {
    if (!entry || typeof entry !== "object") throw new Error(`device ${index} must be an object`);
    const spec = entry as Record<string, unknown>;
    const name = typeof spec.name === "string" && spec.name.trim() ? spec.name.trim() : "";
    const host = typeof spec.host === "string" && spec.host.trim() ? spec.host.trim() : "";
    if (!name) throw new Error(`device ${index} requires a name`);
    if (!host) throw new Error(`device ${name} requires a host`);
    const port = spec.port === undefined ? 22 : positiveInt(spec.port);
    if (!port) throw new Error(`device ${name} port must be a positive integer`);
    return {
      name,
      host,
      vendor: typeof spec.vendor === "string" && spec.vendor.trim() ? spec.vendor.trim() : "generic",
      username: typeof spec.username === "string" && spec.username.trim() ? spec.username.trim() : "netops",
      port,
      command: typeof spec.command === "string" && spec.command.trim() ? spec.command.trim() : undefined,
    };
  });
  if (devices.length === 0) throw new Error("devices file lists no devices");
  const names = new Set<string>();
  for (const device of devices) {
    if (names.has(device.name)) throw new Error(`duplicate device name ${device.name}`);
    names.add(device.name);
  }
  return { campaignId, locationId, devices };
}

/** argv for the system ssh client: non-interactive, host-key accepting. */
export function buildSshArgs(device: DeviceSpec, command: string, keyPath?: string, timeoutSeconds = 15): string[] {
  const args = [
    "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=accept-new",
    "-o", `ConnectTimeout=${timeoutSeconds}`,
    "-p", String(device.port),
  ];
  if (keyPath) args.push("-i", keyPath);
  args.push(`${device.username}@${device.host}`, command);
  return args;
}

export function defaultRunner(binary: string, args: string[], timeoutMs: number): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync(binary, args, { encoding: "utf8", timeout: timeoutMs, windowsHide: true });
  return { status: result.status, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
}

/** Pull one configuration; stderr is never echoed (may contain banners). */
export function pullConfig(device: DeviceSpec, options: PollerOptions, runner: RunnerLike = pollerRunner): string {
  const command = device.command ?? commandFor(device.vendor);
  const args = buildSshArgs(device, command, options.keyPath, options.connectTimeoutSeconds ?? 15);
  const result = runner(options.sshBinary ?? "ssh", args, (options.connectTimeoutSeconds ?? 15) * 2000 + 5000);
  if (result.status !== 0 || result.stdout.trim().length === 0) {
    throw new Error(`ssh ${device.username}@${device.host} failed (exit ${result.status})`);
  }
  return result.stdout;
}

async function login(options: PollerOptions, fetchImpl: FetchLike): Promise<string> {
  const response = await fetchImpl(`${options.dashboardUrl}/api/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username: options.username, password: options.password }),
  });
  if (!response.ok) throw new Error(`dashboard login failed (HTTP ${response.status})`);
  const cookie = (response.headers.get("set-cookie") ?? "").split(";")[0];
  if (!cookie) throw new Error("dashboard login returned no session cookie");
  return cookie;
}

export async function uploadConfig(
  options: PollerOptions,
  cookie: string,
  devicesFile: DevicesFile,
  device: DeviceSpec,
  config: string,
  fetchImpl: FetchLike,
): Promise<{ ok: boolean; duplicate?: boolean; reportId?: number; score?: number }> {
  const form = new FormData();
  form.append("campaignId", String(devicesFile.campaignId));
  form.append("locationId", String(devicesFile.locationId));
  form.append("files", new File([config], `${device.name}.cfg`));
  const response = await fetchImpl(`${options.dashboardUrl}/api/network/upload`, {
    method: "POST",
    body: form,
    headers: { cookie },
  });
  const body = (await response.json().catch(() => null)) as { results?: Array<{ result: { ok: boolean; duplicate?: boolean; reportId?: number; score?: number } }> } | null;
  const result = body?.results?.[0]?.result;
  if (!response.ok || !result?.ok) {
    throw new Error(`upload of ${device.name} rejected (HTTP ${response.status})`);
  }
  return result;
}

/** Pull + upload every device; one failed device never blocks the rest. */
export async function poll(
  devicesFile: DevicesFile,
  options: PollerOptions,
  fetchImpl: FetchLike = fetch,
  runner: RunnerLike = pollerRunner,
): Promise<{ uploaded: number; duplicates: number; failed: Array<{ name: string; error: string }> }> {
  const cookie = await login(options, fetchImpl);
  const outcome = { uploaded: 0, duplicates: 0, failed: [] as Array<{ name: string; error: string }> };
  for (const device of devicesFile.devices) {
    try {
      const config = pullConfig(device, options, runner);
      const result = await uploadConfig(options, cookie, devicesFile, device, config, fetchImpl);
      if (result.duplicate) outcome.duplicates += 1;
      else outcome.uploaded += 1;
    } catch (error) {
      outcome.failed.push({ name: device.name, error: (error as Error).message });
    }
  }
  return outcome;
}

/** Indirection so tests can stub the SSH runner without module mocking. */
let pollerRunner: RunnerLike = defaultRunner;

function readEnvOptions(): PollerOptions {
  const dashboardUrl = (process.env.HBS_POLLER_URL ?? "http://127.0.0.1:3000").replace(/\/+$/, "");
  const username = process.env.HBS_POLLER_USERNAME ?? "";
  const password = process.env.HBS_POLLER_PASSWORD ?? "";
  if (!username || !password) {
    console.error("network-poller: set HBS_POLLER_USERNAME and HBS_POLLER_PASSWORD");
    process.exit(2);
  }
  return {
    dashboardUrl,
    username,
    password,
    keyPath: process.env.HBS_POLLER_KEY || undefined,
    sshBinary: process.env.HBS_POLLER_SSH || undefined,
    connectTimeoutSeconds: Number(process.env.HBS_POLLER_TIMEOUT ?? 15) || 15,
  };
}

function argValue(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

if (import.meta.main) {
  const devicesPath = argValue("--devices") ?? "devices.json";
  const interval = Number(argValue("--interval") ?? 0);
  const dryRun = process.argv.includes("--dry-run");
  let devicesFile: DevicesFile;
  try {
    devicesFile = parseDevicesFile(readFileSync(devicesPath, "utf8"));
  } catch (error) {
    console.error(`network-poller: ${(error as Error).message}`);
    process.exit(2);
  }

  if (dryRun) {
    for (const device of devicesFile.devices) {
      const command = device.command ?? commandFor(device.vendor);
      console.log(`${device.name}: ssh ${buildSshArgs(device, command).join(" ")}`);
    }
    process.exit(0);
  }

  const options = readEnvOptions();
  const runOnce = async (): Promise<void> => {
    const started = Date.now();
    const outcome = await poll(devicesFile, options);
    console.log(
      `network-poller: ${outcome.uploaded} uploaded, ${outcome.duplicates} duplicates, ${outcome.failed.length} failed in ${Date.now() - started}ms`,
    );
    for (const failure of outcome.failed) console.error(`network-poller: ${failure.name}: ${failure.error}`);
  };

  if (interval > 0) {
    void (async () => {
      for (;;) {
        await runOnce().catch((error) => console.error(`network-poller: ${(error as Error).message}`));
        await new Promise((resolve) => setTimeout(resolve, interval * 1000));
      }
    })();
  } else {
    void runOnce().catch((error) => {
      console.error(`network-poller: ${(error as Error).message}`);
      process.exit(3);
    });
  }
}
