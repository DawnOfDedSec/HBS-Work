import type { Database } from "bun:sqlite";
import type { Hono } from "hono";
import { readFileSync } from "node:fs";
import { sessionFromHeaders } from "./auth";
import { verifyCampaignToken } from "./campaigns";

// Immutable issuance download endpoints. Contract: spec §6.2.2 and plan Task 47.
//
// GET /api/issuances/:id/download
// GET /api/campaigns/:id/locations/:loc/issuances/:issuance_id/download  (alias)
//
// The stored artifact is the exact byte sequence created at issuance time; the
// download path never re-patches or regenerates identity. Authentication is
// satisfied by EITHER a valid dashboard session cookie (viewer and above) OR a
// campaign `download` token supplied as `?token=` or `X-HBS-Download-Token`.

export type IssuanceRow = {
  id: string;
  extractor_id: string;
  campaign_id: number;
  location_id: number;
  key_id: string;
  platform: string | null;
  artifact_path: string | null;
  artifact_hash: string | null;
  artifact_size: number | null;
  expires_at: string | null;
  created_at: string;
  download_count: number;
  revoked_at: string | null;
  revoked_reason: string | null;
  revoked_by: string | null;
  is_legacy_v1: number;
};

export function isExpired(row: IssuanceRow, now: number = Date.now()): boolean {
  if (!row.expires_at) return false;
  const at = Date.parse(row.expires_at);
  return Number.isFinite(at) && at <= now;
}

/** Look up by primary key first, then by the unique extractor id. */
export function findIssuance(db: Database, reference: string): IssuanceRow | null {
  const row = db.query("SELECT * FROM issuances WHERE id = ?").get(reference) as IssuanceRow | null;
  if (row) return row;
  return db.query("SELECT * FROM issuances WHERE extractor_id = ?").get(reference) as IssuanceRow | null;
}

/**
 * Shared handler: authorise, verify active/unexpired/unrevoked, stream the
 * exact stored bytes with the persisted artifact hash, and increment the
 * download count exactly once.
 */
function serveDownload(c: any, db: Database, row: IssuanceRow) {
  const sessionUser = sessionFromHeaders(db, c.req.header("cookie"));
  if (!sessionUser) {
    const raw = c.req.query("token") ?? c.req.header("X-HBS-Download-Token");
    if (!raw) return c.json({ error: "authentication required" }, 401);
    if (!verifyCampaignToken(db, row.campaign_id, "download", raw)) {
      return c.json({ error: "forbidden" }, 403);
    }
  }

  if (row.revoked_at) return c.json({ error: "issuance is revoked" }, 403);
  if (isExpired(row)) return c.json({ error: "issuance is expired" }, 403);
  if (!row.artifact_path) return c.json({ error: "artifact unavailable" }, 404);

  let bytes: Uint8Array;
  try {
    bytes = new Uint8Array(readFileSync(row.artifact_path));
  } catch {
    return c.json({ error: "artifact unavailable" }, 404);
  }

  const hash = row.artifact_hash ?? "";
  // Exactly one increment per successful download; this is the only mutation.
  db.query("UPDATE issuances SET download_count = download_count + 1 WHERE id = ?").run(row.id);

  return c.body(bytes, 200, {
    "content-type": "application/octet-stream",
    "content-length": String(bytes.length),
    // Both headers carry the persisted hex SHA-256 of the stored artifact.
    "content-digest": hash,
    "x-hbs-sha256": hash,
    "content-disposition": `attachment; filename="${row.id}"`,
  });
}

export function registerDownloadRoutes(app: Hono<any>, db: Database): void {
  app.get("/api/issuances/:id/download", (c) => {
    const row = findIssuance(db, c.req.param("id"));
    if (!row) return c.json({ error: "issuance not found" }, 404);
    return serveDownload(c, db, row);
  });

  app.get("/api/campaigns/:id/locations/:loc/issuances/:issuance_id/download", (c) => {
    const campaignId = Number(c.req.param("id"));
    const locationId = Number(c.req.param("loc"));
    const row = findIssuance(db, c.req.param("issuance_id"));
    if (!row) return c.json({ error: "issuance not found" }, 404);
    if (row.campaign_id !== campaignId || row.location_id !== locationId) {
      return c.json({ error: "issuance not found" }, 404);
    }
    return serveDownload(c, db, row);
  });
}
