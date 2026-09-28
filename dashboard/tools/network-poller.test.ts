// Tests for the network config poller: devices-file validation, vendor
// command mapping, SSH argv construction, and the poll loop against stubs
// (no real SSH or dashboard).

import { describe, expect, it } from "bun:test";
import {
  buildSshArgs,
  commandFor,
  parseDevicesFile,
  poll,
  pullConfig,
  type DevicesFile,
  type PollerOptions,
} from "./network-poller";

const VALID_JSON = JSON.stringify({
  campaignId: 1,
  locationId: 2,
  devices: [
    { name: "core-sw", host: "10.0.0.5", vendor: "cisco-ios", username: "netops" },
    { name: "edge-fw", host: "10.0.0.1", vendor: "fortinet", port: 2222 },
  ],
});

const OPTIONS: PollerOptions = {
  dashboardUrl: "http://dashboard.test",
  username: "poller",
  password: "poller-passphrase-123",
};

describe("devices file parsing", () => {
  it("accepts a valid file and applies defaults", () => {
    const parsed = parseDevicesFile(VALID_JSON);
    expect(parsed.campaignId).toBe(1);
    expect(parsed.locationId).toBe(2);
    expect(parsed.devices).toHaveLength(2);
    expect(parsed.devices[0].port).toBe(22);
    expect(parsed.devices[0].vendor).toBe("cisco-ios");
    expect(parsed.devices[1].port).toBe(2222);
  });

  it("rejects malformed files with readable errors", () => {
    expect(() => parseDevicesFile("not json")).toThrow("not valid JSON");
    expect(() => parseDevicesFile("{}")).toThrow("campaignId");
    expect(() => parseDevicesFile(JSON.stringify({ campaignId: 1, locationId: 2, devices: [] }))).toThrow("lists no devices");
    expect(() =>
      parseDevicesFile(JSON.stringify({ campaignId: 1, locationId: 2, devices: [{ name: "a", host: "x" }, { name: "a", host: "y" }] })),
    ).toThrow("duplicate device name");
    expect(() =>
      parseDevicesFile(JSON.stringify({ campaignId: 1, locationId: 2, devices: [{ host: "x" }] })),
    ).toThrow("requires a name");
  });
});

describe("vendor command mapping", () => {
  it("maps each supported vendor to its running-config command", () => {
    expect(commandFor("cisco-ios")).toBe("show running-config");
    expect(commandFor("juniper-junos")).toBe("show configuration | display set");
    expect(commandFor("palo-alto")).toBe("show config running");
    expect(commandFor("fortinet")).toBe("show full-configuration");
    expect(commandFor("f5")).toBe("tmsh list sys config");
    expect(commandFor("unknown-thing")).toBe("show running-config");
  });
});

describe("ssh argv construction", () => {
  it("builds a non-interactive argv with key and port", () => {
    const args = buildSshArgs(
      { name: "sw", host: "10.0.0.5", vendor: "cisco-ios", username: "netops", port: 2222 },
      "show running-config",
      "/keys/poller.key",
      9,
    );
    expect(args).toEqual([
      "-o", "BatchMode=yes",
      "-o", "StrictHostKeyChecking=accept-new",
      "-o", "ConnectTimeout=9",
      "-p", "2222",
      "-i", "/keys/poller.key",
      "netops@10.0.0.5",
      "show running-config",
    ]);
  });
});

describe("pull and poll loop", () => {
  it("returns the pulled config from the runner", () => {
    const devices: DevicesFile = parseDevicesFile(VALID_JSON);
    const config = pullConfig(devices.devices[0], OPTIONS, () => ({ status: 0, stdout: "hostname CORE-SW\n", stderr: "" }));
    expect(config).toContain("hostname CORE-SW");
  });

  it("throws when ssh fails or returns nothing", () => {
    const devices: DevicesFile = parseDevicesFile(VALID_JSON);
    expect(() => pullConfig(devices.devices[0], OPTIONS, () => ({ status: 255, stdout: "", stderr: "denied" }))).toThrow("failed");
    expect(() => pullConfig(devices.devices[0], OPTIONS, () => ({ status: 0, stdout: "  ", stderr: "" }))).toThrow("failed");
  });

  it("logs in once, uploads every device, and isolates per-device failures", async () => {
    const devices: DevicesFile = parseDevicesFile(VALID_JSON);
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const fetchImpl = (async (url: string, init?: RequestInit) => {
      calls.push({ url, init });
      if (url.endsWith("/api/auth/login")) {
        return new Response("{}", {
          status: 200,
          headers: { "set-cookie": "hbs_session=abc; Path=/; HttpOnly" },
        });
      }
      const isSecond = calls.filter((call) => call.url.includes("/api/network/upload")).length === 2;
      return new Response(
        JSON.stringify({
          results: [{ name: "x", result: isSecond ? { ok: false, code: "INVALID_BODY", error: "nope" } : { ok: true, duplicate: true, reportId: 9 } }],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }) as unknown as typeof fetch;
    const runner = (() => ({ status: 0, stdout: "hostname X\nend\n", stderr: "" })) as never;

    const outcome = await poll(devices, OPTIONS, fetchImpl, runner);
    expect(outcome.duplicates).toBe(1);
    expect(outcome.uploaded).toBe(0);
    expect(outcome.failed).toHaveLength(1);
    expect(outcome.failed[0].name).toBe("edge-fw");
    // one login + two uploads
    expect(calls.filter((call) => call.url.includes("/api/auth/login"))).toHaveLength(1);
    expect(calls.filter((call) => call.url.includes("/api/network/upload"))).toHaveLength(2);
    // the session cookie flows to the upload
    expect(calls[1].init?.headers).toEqual({ cookie: "hbs_session=abc" });
  });
});
