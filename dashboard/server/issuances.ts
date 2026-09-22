import type { Database } from "bun:sqlite";
import type { Hono } from "hono";
import { randomBytes, randomUUID } from "node:crypto";
import { readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { KeyLifecycle, keygen } from "./keys";
import { requireIssuableLocation } from "./locations";
import { SLOT_LEN, SLOT_MAGIC, createArtifact, patch } from "./patcher";
import type { CampaignAuth } from "./campaigns";
import { isExpired, registerDownloadRoutes, type IssuanceRow } from "./downloads";

// Issuance creation, listing, and revocation. Contract: spec §6.2 and plan Task 47.
//
// Campaign -> Location -> Issuance -> Host/Report. Each issuance has a unique
// random extractor id and an independent X25519 keypair. The patched artifact is
// written once and never regenerated; downloads stream those exact bytes.

/**
 * Supported extractor targets. This is a documented allowlist: issuing for an
 * unknown platform fails with 400 instead of writing an artifact no build can
 * satisfy. Extend alongside `scripts/build-all.sh`.
 */
export const PLATFORMS = ["linux-amd64", "linux-arm64", "windows-amd64"] as const;
export type Platform = (typeof PLATFORMS)[number];

export const DEFAULT_EXPIRY_DAYS = 90;

export type IssuanceRouteOptions = {
  /** Root for `binaries/` and `keys/`. Default: HBS_DATA_ROOT or "server/data". */
  dataRoot?: string;
  /** Base template loader; tests inject a synthetic binary with one placeholder slot. */
  loadTemplate?: (platform: string) => Uint8Array;
};

export function isSupportedPlatform(value: unknown): value is Platform {
  return typeof value === "string" && (PLATFORMS as readonly string[]).includes(value);
}

/**
 * Deterministic 16-byte campaign id for the keyslot: the 64-bit id is written
 * big-endian into bytes 8..16, bytes 0..8 are zero padding. The result is never
 * all-zero for a valid positive campaign id, satisfying the nil-id guard.
 */
export function deriveCampaignId(campaignId: number): Uint8Array {
  if (!Number.isSafeInteger(campaignId) || campaignId <= 0) {
    throw new Error("campaign id must be a positive integer");
  }
  const out = new Uint8Array(16);
  let value = BigInt(campaignId);
  for (let i = 15; i >= 8; i--) {
    out[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return out;
}

/**
 * Smallest positive u16 key id not already used by any issuance (legacy v1
 * records included, so the value is globally unique). 0 is never allocated.
 */
export function allocateKeyId(db: Database): number {
  const used = new Set(
    (db.query("SELECT key_id FROM issuances").all() as { key_id: string }[])
      .map((row) => Number(row.key_id))
      .filter((value) => Number.isInteger(value)),
  );
  for (let candidate = 1; candidate <= 0xffff; candidate++) {
    if (!used.has(candidate)) return candidate;
  }
  throw new Error("no free key id remains in the u16 space");
}

/** Format 16 random bytes as a canonical UUID-style hex string. */
export function formatExtractorId(bytes: Uint8Array): string {
  if (bytes.length !== 16) throw new Error("extractor id must be 16 bytes");
  const hex = Buffer.from(bytes).toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function parseExtractorIdHex(uuid: string): Uint8Array {
  const hex = uuid.replace(/-/g, "");
  if (!/^[0-9a-f]{32}$/i.test(hex)) throw new Error("invalid extractor id");
  return new Uint8Array(Buffer.from(hex, "hex"));
}

function defaultLoadTemplate(platform: string): Uint8Array {
  const path = join(import.meta.dir, "..", "binaries", platform);
  try {
    return new Uint8Array(readFileSync(path));
  } catch {
    throw new Error(
      `extractor template for platform '${platform}' not found at ${path}; ` +
        "build dashboard/binaries/<platform> or pass opts.loadTemplate",
    );
  }
}

function numId(value: string | undefined): number | null {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
}

function nowIso(): string {
  return new Date().toISOString();
}

function actor(c: any): string {
  const user = c.get("user");
  return user?.username ?? user?.id?.toString() ?? c.get("actor") ?? "unknown";
}

function audit(db: Database, c: any, action: string, resource: string, details: object): void {
  db.query(`INSERT INTO audit_log (actor, actor_ip, action, resource, details, created_at)
    VALUES (?, ?, ?, ?, ?, ?)`).run(
    actor(c),
    c.req.header("x-forwarded-for") ?? null,
    action,
    resource,
    JSON.stringify(details),
    nowIso(),
  );
}

/** `campaign_tokens` is normally created by Task 46; create it defensively so
 *  download-token verification works when only issuance routes are mounted. */
function prepareTables(db: Database): void {
  db.run(`CREATE TABLE IF NOT EXISTS campaign_tokens (
    campaign_id INTEGER NOT NULL REFERENCES campaigns(id),
    kind TEXT NOT NULL CHECK (kind IN ('download','push')),
    token_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (campaign_id, kind)
  )`);
}

/** Offset of the single slot magic in `bytes`, or null when absent/ambiguous. */
function locateSlot(bytes: Uint8Array): number | null {
  let found: number | null = null;
  for (let i = 0; i + SLOT_MAGIC.length <= bytes.length; i++) {
    let match = true;
    for (let j = 0; j < SLOT_MAGIC.length; j++) {
      if (bytes[i + j] !== SLOT_MAGIC[j]) {
        match = false;
        break;
      }
    }
    if (!match) continue;
    if (found !== null) return null;
    found = i;
  }
  return found;
}

/**
 * True when the artifact was produced from the current template: same length,
 * same slot offset, and identical bytes everywhere outside the 512-byte slot.
 */
function templateMatchesArtifact(template: Uint8Array, artifact: Uint8Array): boolean {
  if (template.length !== artifact.length) return false;
  const templateSlot = locateSlot(template);
  const artifactSlot = locateSlot(artifact);
  if (templateSlot === null || artifactSlot === null || templateSlot !== artifactSlot) return false;
  for (let i = 0; i < template.length; i++) {
    if (i >= templateSlot && i < templateSlot + SLOT_LEN) continue;
    if (template[i] !== artifact[i]) return false;
  }
  return true;
}

type SerializeExtra = { versionStalenessWarning: string | null };

function serializeIssuance(row: IssuanceRow, extra: SerializeExtra) {
  return {
    id: row.id,
    extractorId: row.extractor_id,
    campaignId: row.campaign_id,
    locationId: row.location_id,
    platform: row.platform,
    keyId: Number(row.key_id),
    artifactSha256: row.artifact_hash,
    artifactSize: row.artifact_size,
    downloadCount: row.download_count,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    expired: isExpired(row),
    revoked: row.revoked_at !== null,
    revokedAt: row.revoked_at,
    revokedReason: row.revoked_reason,
    revokedBy: row.revoked_by,
    downloadUrl: `/api/issuances/${row.id}/download`,
    versionStalenessWarning: extra.versionStalenessWarning,
  };
}

export function registerIssuanceRoutes(
  app: Hono<any>,
  db: Database,
  auth: CampaignAuth,
  opts: IssuanceRouteOptions = {},
): void {
  prepareTables(db);
  const dataRoot = opts.dataRoot ?? process.env.HBS_DATA_ROOT ?? "server/data";
  const loadTemplate = opts.loadTemplate ?? defaultLoadTemplate;

  app.post(
    "/api/campaigns/:id/locations/:loc/issuances",
    auth.requireRole("super_admin", "auditor"),
    async (c) => {
      const campaignId = numId(c.req.param("id"));
      const locationId = numId(c.req.param("loc"));
      if (!campaignId || !locationId) return c.json({ error: "location not found" }, 404);
      const location = db
        .query("SELECT 1 FROM locations WHERE id = ? AND campaign_id = ?")
        .get(locationId, campaignId);
      if (!location) return c.json({ error: "location not found" }, 404);
      try {
        requireIssuableLocation(db, campaignId, locationId);
      } catch {
        return c.json({ error: "campaign or location is not active" }, 409);
      }

      let body: any;
      try {
        body = await c.req.json();
      } catch {
        return c.json({ error: "invalid JSON" }, 400);
      }
      if (!isSupportedPlatform(body?.platform)) {
        return c.json(
          { error: `unsupported platform; expected one of: ${PLATFORMS.join(", ")}` },
          400,
        );
      }
      const platform = body.platform;

      const issuedAt = Math.floor(Date.now() / 1000);
      let expiryUnix: number;
      let expiresAt: string;
      if (body.expiry === undefined || body.expiry === null) {
        expiryUnix = issuedAt + DEFAULT_EXPIRY_DAYS * 86_400;
        expiresAt = new Date(expiryUnix * 1000).toISOString();
      } else {
        const parsed =
          typeof body.expiry === "number" ? body.expiry * 1000 : Date.parse(String(body.expiry));
        if (!Number.isFinite(parsed)) return c.json({ error: "expiry must be an ISO date" }, 400);
        expiryUnix = Math.floor(parsed / 1000);
        if (!(issuedAt < expiryUnix)) {
          return c.json({ error: "expiry must be in the future" }, 400);
        }
        expiresAt = new Date(expiryUnix * 1000).toISOString();
      }

      let keyId: number;
      try {
        keyId = allocateKeyId(db);
      } catch (error) {
        return c.json({ error: (error as Error).message }, 409);
      }
      const extractorBytes = randomBytes(16);
      const extractorId = formatExtractorId(extractorBytes);
      const issuanceId = randomUUID();
      const pair = keygen();

      let template: Uint8Array;
      try {
        template = loadTemplate(platform);
      } catch (error) {
        return c.json({ error: (error as Error).message }, 500);
      }

      let patched: Uint8Array;
      let artifact: { path: string; sha256: string; size: number };
      try {
        const result = patch(template, {
          keyId,
          campaignId: deriveCampaignId(campaignId),
          extractorId: extractorBytes,
          publicKey: pair.publicKey,
          issuedAt,
          expiry: expiryUnix,
        });
        patched = result.bytes;
        artifact = createArtifact(patched, issuanceId, { dataRoot });
      } catch (error) {
        return c.json({ error: (error as Error).message }, 400);
      }

      const createdAt = nowIso();
      const lifecycle = new KeyLifecycle(db, { dataRoot });
      const keyPath = join(dataRoot, "keys", `${issuanceId}.key`);

      // One transaction stores the issuance row and the key mapping. Any
      // failure removes both files so no orphan artifact/key survives rollback.
      db.run("BEGIN");
      try {
        db.query(`INSERT INTO issuances
          (id, extractor_id, campaign_id, location_id, key_id, platform, artifact_path,
           artifact_hash, artifact_size, expires_at, created_at, download_count, is_legacy_v1)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0)`).run(
          issuanceId,
          extractorId,
          campaignId,
          locationId,
          String(keyId),
          platform,
          artifact.path,
          artifact.sha256,
          artifact.size,
          expiresAt,
          createdAt,
        );
        lifecycle.saveKey(issuanceId, pair.privateKey, pair.publicKey);
        db.run("COMMIT");
      } catch (error) {
        db.run("ROLLBACK");
        rmSync(artifact.path, { force: true });
        rmSync(keyPath, { force: true });
        const message = (error as Error).message;
        if (message.includes("retired")) {
          return c.json({ error: "cannot issue for a retired location" }, 409);
        }
        throw error;
      }

      audit(db, c, "issuance.create", `issuance:${issuanceId}`, {
        extractorId,
        platform,
        keyId,
        expiresAt,
      });

      const row = db.query("SELECT * FROM issuances WHERE id = ?").get(issuanceId) as IssuanceRow;
      return c.json(serializeIssuance(row, { versionStalenessWarning: null }), 201);
    },
  );

  app.get(
    "/api/campaigns/:id/locations/:loc/issuances",
    auth.requireRole("super_admin", "auditor", "viewer"),
    (c) => {
      const campaignId = numId(c.req.param("id"));
      const locationId = numId(c.req.param("loc"));
      if (!campaignId || !locationId) return c.json({ error: "location not found" }, 404);
      const location = db
        .query("SELECT 1 FROM locations WHERE id = ? AND campaign_id = ?")
        .get(locationId, campaignId);
      if (!location) return c.json({ error: "location not found" }, 404);

      const rows = db
        .query("SELECT * FROM issuances WHERE campaign_id = ? AND location_id = ? ORDER BY created_at, id")
        .all(campaignId, locationId) as IssuanceRow[];

      // Compare each artifact against the currently available template so the
      // listing never claims a stale extractor is current. Templates are cached
      // per platform within one request.
      const templates = new Map<string, Uint8Array | null>();
      const warningFor = (row: IssuanceRow): string | null => {
        const platform = row.platform ?? "";
        let template = templates.get(platform);
        if (template === undefined) {
          try {
            template = loadTemplate(platform);
          } catch {
            template = null;
          }
          templates.set(platform, template);
        }
        if (template === null) return `extractor template for '${platform}' is unavailable`;
        if (!row.artifact_path) return "artifact path is not recorded";
        let artifact: Uint8Array;
        try {
          artifact = new Uint8Array(readFileSync(row.artifact_path));
        } catch {
          return "stored artifact is missing";
        }
        return templateMatchesArtifact(template, artifact)
          ? null
          : "extractor template has changed since this issuance was created";
      };

      return c.json(rows.map((row) => serializeIssuance(row, { versionStalenessWarning: warningFor(row) })));
    },
  );

  app.delete(
    "/api/campaigns/:id/issuances/:extractor_id",
    auth.requireRole("super_admin", "auditor"),
    async (c) => {
      const campaignId = numId(c.req.param("id"));
      if (!campaignId) return c.json({ error: "issuance not found" }, 404);
      const row = db
        .query("SELECT * FROM issuances WHERE campaign_id = ? AND extractor_id = ?")
        .get(campaignId, c.req.param("extractor_id")) as IssuanceRow | null;
      if (!row) return c.json({ error: "issuance not found" }, 404);

      let body: any = {};
      try {
        body = await c.req.json();
      } catch {
        // A reason is still required below.
      }
      const reason = typeof body?.reason === "string" ? body.reason.trim() : "";
      if (!reason) return c.json({ error: "reason is required" }, 400);

      if (row.revoked_at) {
        return c.json(serializeIssuance(row, { versionStalenessWarning: null }));
      }

      const revokedAt = nowIso();
      const revokedBy = actor(c);
      db.query(
        "UPDATE issuances SET revoked_at = ?, revoked_reason = ?, revoked_by = ? WHERE id = ?",
      ).run(revokedAt, reason, revokedBy, row.id);

      // Delete the private-key file but retain the key mapping, artifact, and
      // report rows: past reports stay queryable, future ingest/download stop.
      const keyRow = db
        .query("SELECT private_key_path FROM keys WHERE issuance_id = ?")
        .get(row.id) as { private_key_path: string } | null;
      if (keyRow) rmSync(keyRow.private_key_path, { force: true });

      audit(db, c, "issuance.revoked", `issuance:${row.id}`, {
        extractorId: row.extractor_id,
        reason,
        revokedAt,
      });

      const updated = db.query("SELECT * FROM issuances WHERE id = ?").get(row.id) as IssuanceRow;
      return c.json(serializeIssuance(updated, { versionStalenessWarning: null }));
    },
  );

  registerDownloadRoutes(app, db);
}

// Re-exported for callers that need to rebuild keyslot bytes from a listing.
export { parseExtractorIdHex };
