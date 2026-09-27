// Host identity and location mapping (Task 48).
//
// Host identity is keyed by normalized stable `machine_id` (spec §6.3):
//   * hostname is mutable display metadata - a rename updates the existing
//     host row, never creates a duplicate;
//   * distinct machine IDs stay distinct even when hostnames collide;
//   * `host_locations` records every campaign/location a machine has been
//     seen in without losing history.
//
// These helpers only run SQL. The caller owns the enclosing transaction.

import type { Database } from "bun:sqlite";

export type HostRow = {
  id: number;
  machine_id: string;
  hostname: string | null;
  platform: string | null;
  os: string | null;
  arch: string | null;
  first_seen_at: string;
  last_seen_at: string;
};

export type UpsertHostInput = {
  machineId: string;
  hostname: string;
  platform?: string | null;
  os?: string | null;
  arch?: string | null;
  seenAt: string;
};

export type UpsertHostResult = {
  hostId: number;
  created: boolean;
};

const MAX_IDENTIFIER_LENGTH = 512;

/**
 * Normalize a machine ID: trim, reject empty, lowercase (machine IDs are
 * case-insensitive opaque identifiers). Returns null when unusable.
 */
export function normalizeMachineId(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim().toLowerCase();
  if (!trimmed) return null;
  if (trimmed.length > MAX_IDENTIFIER_LENGTH) return null;
  return trimmed;
}

/** Normalize a hostname: trim and reject empty. Case is preserved for display. */
export function normalizeHostname(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (trimmed.length > MAX_IDENTIFIER_LENGTH) return null;
  return trimmed;
}

/** Stable display identity from the SDD ledger: hostname + ":" + machine_id[0..8]. */
export function displayId(hostname: string, machineId: string): string {
  return `${hostname}:${machineId.slice(0, 8)}`;
}

/**
 * Insert or update a host by machine_id. A rename updates hostname/last_seen
 * only; first_seen_at and the machine_id key are never rewritten.
 */
export function upsertHost(db: Database, input: UpsertHostInput): UpsertHostResult {
  const existing = db
    .query("SELECT id FROM hosts WHERE machine_id = ?")
    .get(input.machineId) as { id: number } | null;

  if (existing) {
    db.query(
      `UPDATE hosts
         SET hostname = ?,
             last_seen_at = ?,
             platform = COALESCE(?, platform),
             os = COALESCE(?, os),
             arch = COALESCE(?, arch)
       WHERE id = ?`,
    ).run(
      input.hostname,
      input.seenAt,
      input.platform ?? null,
      input.os ?? null,
      input.arch ?? null,
      existing.id,
    );
    return { hostId: existing.id, created: false };
  }

  const inserted = db
    .query(
      `INSERT INTO hosts (machine_id, hostname, platform, os, arch, first_seen_at, last_seen_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(
      input.machineId,
      input.hostname,
      input.platform ?? null,
      input.os ?? null,
      input.arch ?? null,
      input.seenAt,
      input.seenAt,
    );
  return { hostId: Number(inserted.lastInsertRowid), created: true };
}

/** Record/refresh a host's presence at one location. */
export function upsertHostLocation(
  db: Database,
  hostId: number,
  locationId: number,
  seenAt: string,
): void {
  db.query(
    `INSERT INTO host_locations (host_id, location_id, first_seen_at, last_seen_at)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(host_id, location_id)
     DO UPDATE SET last_seen_at = excluded.last_seen_at`,
  ).run(hostId, locationId, seenAt, seenAt);
}
