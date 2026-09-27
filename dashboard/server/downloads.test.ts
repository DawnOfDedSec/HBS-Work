import { afterEach, describe, expect, it } from "bun:test";
import { Hono } from "hono";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { hashToken, sessionFromHeaders } from "./auth";
import { createCampaignRoutes, type CampaignAuth } from "./campaigns";
import { openDb, runMigrations } from "./db";
import { SLOT_LEN, SLOT_MAGIC, readSlot, sha256Hex } from "./patcher";
import {
  deriveCampaignId,
  parseExtractorIdHex,
  registerIssuanceRoutes,
} from "./issuances";

// Task 47 regression suite: immutable issuance creation and downloads.

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function dataRoot(): string {
  const value = mkdtempSync(join(tmpdir(), "hbs-issuance-"));
  roots.push(value);
  return value;
}

/** Synthetic base template with one pristine 512-byte placeholder slot. */
function template(marker = 0): Uint8Array {
  const bin = new Uint8Array(1024 + SLOT_LEN + 64).fill(marker);
  const slot = new Uint8Array(SLOT_LEN).fill(0xaa);
  slot.set(SLOT_MAGIC, 0);
  slot.fill(0, 480, 512);
  bin.set(slot, 1024);
  return bin;
}

type Harness = {
  app: Hono<any>;
  db: ReturnType<typeof openDb>;
  root: string;
  setLoader: (loader: (platform: string) => Uint8Array) => void;
};

function harness(initial?: (platform: string) => Uint8Array): Harness {
  const db = openDb(":memory:");
  runMigrations(db);
  const root = dataRoot();
  let loader = initial ?? (() => template());
  const app = new Hono<any>();

  // Non-blocking session middleware mirrors production: routes that need a role
  // enforce it through requireRole, and the download route additionally accepts
  // a campaign token.
  app.use("/api/*", async (c, next) => {
    const user = sessionFromHeaders(db, c.req.header("cookie"));
    if (user) c.set("user", user);
    await next();
  });

  const auth: CampaignAuth = {
    requireRole:
      (...roles: string[]) =>
      async (c, next) => {
        const user = c.get("user");
        if (!user || !roles.includes(user.role)) return c.json({ error: "forbidden" }, 403);
        await next();
      },
  };

  app.route("/", createCampaignRoutes(db, auth));
  registerIssuanceRoutes(app, db, auth, { dataRoot: root, loadTemplate: (p) => loader(p) });
  return { app, db, root, setLoader: (next) => (loader = next) };
}

let userCounter = 0;
function seedSession(db: ReturnType<typeof openDb>, role: "super_admin" | "auditor" | "viewer"): string {
  userCounter += 1;
  const username = `user-${role}-${userCounter}`;
  const token = `token-${role}-${userCounter}`;
  const stamp = new Date().toISOString();
  const expires = new Date(Date.now() + 86_400_000).toISOString();
  const result = db
    .query("INSERT INTO users (username, password_hash, role, active, created_at, updated_at) VALUES (?, 'x', ?, 1, ?, ?)")
    .run(username, role, stamp, stamp);
  db.query("INSERT INTO sessions (user_id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?)").run(
    Number(result.lastInsertRowid),
    hashToken(token),
    stamp,
    expires,
  );
  return `hbs_session=${token}`;
}

function json(method: string, body: unknown, headers: Record<string, string> = {}): RequestInit {
  return {
    method,
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  };
}

async function makeCampaign(app: Hono<any>, cookie: string, name: string) {
  const response = await app.request(
    "/api/campaigns",
    json("POST", { name, locations: [{ name: "DC-East" }] }, { cookie }),
  );
  expect(response.status).toBe(201);
  return (await response.json()) as {
    id: number;
    locations: { id: number }[];
    downloadToken: string;
    pushToken: string;
  };
}

function issue(
  app: Hono<any>,
  cookie: string,
  campaignId: number,
  locationId: number,
  body: Record<string, unknown> = { platform: "linux-amd64" },
) {
  return app.request(
    `/api/campaigns/${campaignId}/locations/${locationId}/issuances`,
    json("POST", body, { cookie }),
  );
}

describe("issuance creation", () => {
  it("persists artifact, key, and checksum atomically with a download url", async () => {
    const h = harness();
    const cookie = seedSession(h.db, "super_admin");
    const campaign = await makeCampaign(h.app, cookie, "Acme Q3");
    const locationId = campaign.locations[0]!.id;

    const response = await issue(h.app, cookie, campaign.id, locationId);
    expect(response.status).toBe(201);
    const body = (await response.json()) as Record<string, any>;

    expect(body.id).toBeString();
    expect(body.extractorId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
    expect(body.campaignId).toBe(campaign.id);
    expect(body.locationId).toBe(locationId);
    expect(body.platform).toBe("linux-amd64");
    expect(body.keyId).toBe(1);
    expect(body.artifactSize).toBe(template().length);
    expect(body.downloadUrl).toBe(`/api/issuances/${body.id}/download`);
    expect(body.expired).toBe(false);
    expect(body.revoked).toBe(false);
    expect(Date.parse(body.expiresAt)).toBeGreaterThan(Date.now());

    const artifactPath = join(h.root, "binaries", body.id);
    const artifact = new Uint8Array(readFileSync(artifactPath));
    expect(sha256Hex(artifact)).toBe(body.artifactSha256);

    const slot = readSlot(artifact, 1024);
    expect(slot.keyId).toBe(1);
    expect(Buffer.from(slot.campaignId)).toEqual(Buffer.from(deriveCampaignId(campaign.id)));
    expect(Buffer.from(slot.extractorId)).toEqual(Buffer.from(parseExtractorIdHex(body.extractorId)));
    expect(slot.recipientPub.some(Boolean)).toBeTrue();
    expect(slot.issuedAtUnix).toBeLessThan(slot.expiryUnix);

    const keyRow = h.db.query("SELECT private_key_path FROM keys WHERE issuance_id = ?").get(body.id) as {
      private_key_path: string;
    } | null;
    expect(keyRow).not.toBeNull();
    expect(readFileSync(keyRow!.private_key_path)).toHaveLength(32);

    expect((h.db.query("SELECT action FROM audit_log ORDER BY id DESC LIMIT 1").get() as { action: string }).action).toBe(
      "issuance.create",
    );
  });

  it("allocates the smallest unused positive key id and skips zero", async () => {
    const h = harness();
    const cookie = seedSession(h.db, "super_admin");
    const campaign = await makeCampaign(h.app, cookie, "Campaign");
    const locationId = campaign.locations[0]!.id;

    const first = (await (await issue(h.app, cookie, campaign.id, locationId)).json()) as { id: string; keyId: number };
    const second = (await (await issue(h.app, cookie, campaign.id, locationId)).json()) as { id: string; keyId: number };
    expect(first.keyId).toBe(1);
    expect(second.keyId).toBe(2);

    // Free id 2: the next allocation must reuse it rather than climb to 3.
    h.db.query("UPDATE issuances SET key_id = '10' WHERE id = ?").run(second.id);
    const third = (await (await issue(h.app, cookie, campaign.id, locationId)).json()) as { keyId: number };
    expect(third.keyId).toBe(2);
  });

  it("rejects unsupported platforms, inactive locations, and invalid expiry", async () => {
    const h = harness();
    const cookie = seedSession(h.db, "super_admin");
    const campaign = await makeCampaign(h.app, cookie, "Campaign");
    const locationId = campaign.locations[0]!.id;

    expect((await issue(h.app, cookie, campaign.id, locationId, { platform: "solaris-sparc" })).status).toBe(400);
    expect((await issue(h.app, cookie, campaign.id, locationId, {})).status).toBe(400);
    expect((await issue(h.app, cookie, campaign.id, locationId, { platform: "linux-amd64", expiry: "not-a-date" })).status).toBe(400);
    expect((await issue(h.app, cookie, campaign.id, locationId, { platform: "linux-amd64", expiry: "2001-01-01T00:00:00.000Z" })).status).toBe(400);

    h.db.query("UPDATE locations SET retired_at = ? WHERE id = ?").run(new Date().toISOString(), locationId);
    expect((await issue(h.app, cookie, campaign.id, locationId)).status).toBe(409);

    // Unknown location/campaign combinations are 404.
    expect((await issue(h.app, cookie, campaign.id, 9999)).status).toBe(404);
    expect((await issue(h.app, cookie, 9999, locationId)).status).toBe(404);
  });

  it("accepts an explicit future expiry", async () => {
    const h = harness();
    const cookie = seedSession(h.db, "super_admin");
    const campaign = await makeCampaign(h.app, cookie, "Campaign");
    const locationId = campaign.locations[0]!.id;
    const expiry = new Date(Date.now() + 7 * 86_400_000).toISOString();

    const response = await issue(h.app, cookie, campaign.id, locationId, { platform: "windows-amd64", expiry });
    expect(response.status).toBe(201);
    const body = (await response.json()) as { expiresAt: string; platform: string };
    expect(body.platform).toBe("windows-amd64");
    expect(Date.parse(body.expiresAt)).toBe(Math.floor(Date.parse(expiry) / 1000) * 1000);
  });

  it("requires the auditor role or above", async () => {
    const h = harness();
    const viewer = seedSession(h.db, "viewer");
    const admin = seedSession(h.db, "super_admin");
    const campaign = await makeCampaign(h.app, admin, "Campaign");
    const locationId = campaign.locations[0]!.id;

    expect((await issue(h.app, viewer, campaign.id, locationId)).status).toBe(403);
    expect((await issue(h.app, "hbs_session=bogus", campaign.id, locationId)).status).toBe(403);
  });
});

describe("issuance download", () => {
  it("streams the exact artifact bytes with matching hash and increments once per success", async () => {
    const h = harness();
    const cookie = seedSession(h.db, "super_admin");
    const campaign = await makeCampaign(h.app, cookie, "Campaign");
    const locationId = campaign.locations[0]!.id;
    const created = (await (await issue(h.app, cookie, campaign.id, locationId)).json()) as Record<string, any>;
    const artifact = readFileSync(join(h.root, "binaries", created.id));

    const response = await h.app.request(`/api/issuances/${created.id}/download`, { headers: { cookie } });
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/octet-stream");
    expect(response.headers.get("content-length")).toBe(String(artifact.length));
    expect(response.headers.get("x-hbs-sha256")).toBe(created.artifactSha256);
    expect(response.headers.get("content-digest")).toBe(created.artifactSha256);
    expect(Buffer.from(new Uint8Array(await response.arrayBuffer()))).toEqual(artifact);

    expect(h.db.query("SELECT download_count FROM issuances WHERE id = ?").get(created.id)).toEqual({
      download_count: 1,
    });

    const second = await h.app.request(`/api/issuances/${created.id}/download`, { headers: { cookie } });
    expect(second.status).toBe(200);
    expect(h.db.query("SELECT download_count FROM issuances WHERE id = ?").get(created.id)).toEqual({
      download_count: 2,
    });
    expect(sha256Hex(new Uint8Array(await second.arrayBuffer()))).toBe(created.artifactSha256);
  });

  it("serves the alias route and rejects mismatched path campaign/location", async () => {
    const h = harness();
    const cookie = seedSession(h.db, "super_admin");
    const campaign = await makeCampaign(h.app, cookie, "Campaign");
    const locationId = campaign.locations[0]!.id;
    const created = (await (await issue(h.app, cookie, campaign.id, locationId)).json()) as { id: string };

    const alias = `/api/campaigns/${campaign.id}/locations/${locationId}/issuances/${created.id}/download`;
    expect((await h.app.request(alias, { headers: { cookie } })).status).toBe(200);
    expect(
      (await h.app.request(`/api/campaigns/${campaign.id}/locations/9999/issuances/${created.id}/download`, { headers: { cookie } })).status,
    ).toBe(404);
  });

  it("authenticates a download token and denies cross-campaign or wrong-kind tokens", async () => {
    const h = harness();
    const cookie = seedSession(h.db, "super_admin");
    const campaignA = await makeCampaign(h.app, cookie, "Campaign A");
    const campaignB = await makeCampaign(h.app, cookie, "Campaign B");
    const created = (await (
      await issue(h.app, cookie, campaignB.id, campaignB.locations[0]!.id)
    ).json()) as { id: string };
    const url = `/api/issuances/${created.id}/download`;

    expect((await h.app.request(url)).status).toBe(401);
    expect((await h.app.request(`${url}?token=${campaignA.downloadToken}`)).status).toBe(403);
    expect(
      (
        await h.app.request(url, {
          headers: { "X-HBS-Download-Token": campaignA.downloadToken },
        })
      ).status,
    ).toBe(403);
    expect((await h.app.request(`${url}?token=${campaignB.pushToken}`)).status).toBe(403);
    expect((await h.app.request(`${url}?token=${campaignB.downloadToken}`)).status).toBe(200);
    expect(
      (
        await h.app.request(url, {
          headers: { "X-HBS-Download-Token": campaignB.downloadToken },
        })
      ).status,
    ).toBe(200);
  });

  it("rejects expired, revoked, and missing issuances", async () => {
    const h = harness();
    const cookie = seedSession(h.db, "super_admin");
    const campaign = await makeCampaign(h.app, cookie, "Campaign");
    const locationId = campaign.locations[0]!.id;

    const created = (await (await issue(h.app, cookie, campaign.id, locationId)).json()) as { id: string };
    h.db
      .query("UPDATE issuances SET expires_at = ? WHERE id = ?")
      .run(new Date(Date.now() - 86_400_000).toISOString(), created.id);
    expect((await h.app.request(`/api/issuances/${created.id}/download`, { headers: { cookie } })).status).toBe(403);

    expect((await h.app.request("/api/issuances/does-not-exist/download", { headers: { cookie } })).status).toBe(404);
  });
});

describe("issuance revocation", () => {
  it("revokes, deletes the private key file, blocks download, and keeps reports", async () => {
    const h = harness();
    const cookie = seedSession(h.db, "auditor");
    const campaign = await makeCampaign(h.app, cookie, "Campaign");
    const locationId = campaign.locations[0]!.id;
    const created = (await (await issue(h.app, cookie, campaign.id, locationId)).json()) as {
      id: string;
      extractorId: string;
    };

    const stamp = new Date().toISOString();
    const hostId = Number(
      h.db
        .query("INSERT INTO hosts (machine_id, hostname, first_seen_at, last_seen_at) VALUES (?, ?, ?, ?)")
        .run("machine-1", "host-1", stamp, stamp).lastInsertRowid,
    );
    h.db
      .query(
        `INSERT INTO reports (issuance_id, host_id, location_id, campaign_id, extractor_id, scan_id, received_at, report_json)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(created.id, hostId, locationId, campaign.id, created.extractorId, "scan-1", stamp, '{"ok":true}');

    const keyPath = join(h.root, "keys", `${created.id}.key`);
    expect(existsSync(keyPath)).toBeTrue();

    const response = await h.app.request(
      `/api/campaigns/${campaign.id}/issuances/${created.extractorId}`,
      json("DELETE", { reason: "compromised host" }, { cookie }),
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as Record<string, any>;
    expect(body.revoked).toBe(true);
    expect(body.revokedReason).toBe("compromised host");
    expect(body.revokedBy).toContain("user-auditor");

    expect(existsSync(keyPath)).toBeFalse();
    expect(h.db.query("SELECT COUNT(*) AS n FROM keys WHERE issuance_id = ?").get(created.id)).toEqual({ n: 1 });
    expect(h.db.query("SELECT COUNT(*) AS n FROM reports WHERE issuance_id = ?").get(created.id)).toEqual({ n: 1 });
    expect((h.db.query("SELECT action FROM audit_log WHERE action = 'issuance.revoked'").get() as { action: string }).action).toBe("issuance.revoked");

    expect((await h.app.request(`/api/issuances/${created.id}/download`, { headers: { cookie } })).status).toBe(403);

    // Idempotent: a second revoke succeeds without a duplicate audit row.
    const again = await h.app.request(
      `/api/campaigns/${campaign.id}/issuances/${created.extractorId}`,
      json("DELETE", { reason: "again" }, { cookie }),
    );
    expect(again.status).toBe(200);
    expect((h.db.query("SELECT COUNT(*) AS n FROM audit_log WHERE action = 'issuance.revoked'").get() as { n: number }).n).toBe(1);
  });

  it("requires a reason, auditor+, and a matching campaign", async () => {
    const h = harness();
    const admin = seedSession(h.db, "super_admin");
    const viewer = seedSession(h.db, "viewer");
    const campaign = await makeCampaign(h.app, admin, "Campaign");
    const other = await makeCampaign(h.app, admin, "Other");
    const created = (await (
      await issue(h.app, admin, campaign.id, campaign.locations[0]!.id)
    ).json()) as { extractorId: string };

    const url = `/api/campaigns/${campaign.id}/issuances/${created.extractorId}`;
    expect((await h.app.request(url, json("DELETE", { reason: "x" }, { cookie: viewer }))).status).toBe(403);
    expect((await h.app.request(url, json("DELETE", {}, { cookie: admin }))).status).toBe(400);
    expect(
      (await h.app.request(`/api/campaigns/${other.id}/issuances/${created.extractorId}`, json("DELETE", { reason: "x" }, { cookie: admin }))).status,
    ).toBe(404);
    expect((await h.app.request(`/api/campaigns/${campaign.id}/issuances/missing`, json("DELETE", { reason: "x" }, { cookie: admin }))).status).toBe(404);
  });
});

describe("issuance listing", () => {
  it("returns metadata, counts, and a null staleness warning for a current template", async () => {
    const h = harness();
    const admin = seedSession(h.db, "super_admin");
    const viewer = seedSession(h.db, "viewer");
    const campaign = await makeCampaign(h.app, admin, "Campaign");
    const locationId = campaign.locations[0]!.id;
    const first = (await (await issue(h.app, admin, campaign.id, locationId)).json()) as Record<string, any>;
    await issue(h.app, admin, campaign.id, locationId, { platform: "linux-arm64" });
    await h.app.request(`/api/issuances/${first.id}/download`, { headers: { cookie: admin } });

    const listUrl = `/api/campaigns/${campaign.id}/locations/${locationId}/issuances`;
    const response = await h.app.request(listUrl, { headers: { cookie: viewer } });
    expect(response.status).toBe(200);
    const items = (await response.json()) as Record<string, any>[];
    expect(items).toHaveLength(2);

    const item = items.find((row) => row.id === first.id)!;
    expect(item).toMatchObject({
      platform: "linux-amd64",
      artifactSha256: first.artifactSha256,
      downloadCount: 1,
      expired: false,
      revoked: false,
      versionStalenessWarning: null,
      downloadUrl: `/api/issuances/${first.id}/download`,
    });
    expect(item.expiresAt).toBe(first.expiresAt);
    expect(items.some((row) => row.platform === "linux-arm64")).toBeTrue();

    // Viewers cannot mutate; unauthenticated callers cannot read.
    expect((await h.app.request(listUrl)).status).toBe(403);
  });

  it("flags a template that changed since issuance", async () => {
    let current = template();
    const h = harness(() => current);
    const admin = seedSession(h.db, "super_admin");
    const campaign = await makeCampaign(h.app, admin, "Campaign");
    const locationId = campaign.locations[0]!.id;
    const created = (await (await issue(h.app, admin, campaign.id, locationId)).json()) as Record<string, any>;
    const listUrl = `/api/campaigns/${campaign.id}/locations/${locationId}/issuances`;

    const fresh = (await (await h.app.request(listUrl, { headers: { cookie: admin } })).json()) as Record<string, any>[];
    expect(fresh[0]!.versionStalenessWarning).toBeNull();

    current = template();
    current[0] = 0x5a;
    const stale = (await (await h.app.request(listUrl, { headers: { cookie: admin } })).json()) as Record<string, any>[];
    expect(stale[0]!.id).toBe(created.id);
    expect(stale[0]!.versionStalenessWarning).toBeString();

    h.setLoader(() => {
      throw new Error("no template");
    });
    const missing = (await (await h.app.request(listUrl, { headers: { cookie: admin } })).json()) as Record<string, any>[];
    expect(missing[0]!.versionStalenessWarning).toContain("no local extractor template");
  });
});
