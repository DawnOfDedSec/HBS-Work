// Redacted diagnostic bundle route (Task 49).
//
// `GET /api/diagnostic` is super-admin only. The bundle is assembled in
// `reports.ts` from IDs, counts, timings, and enum values only — never from
// `reports.envelope` or `reports.report_json`, and never from any evidence
// block, evidence string, justification, or credential. This module only owns
// the route shape and the super-admin gate.

import type { Database } from "bun:sqlite";
import { Hono, type MiddlewareHandler } from "hono";
import { parseQuery, type NormalizedQuery } from "./query";

export type DiagnosticAuth = {
  requireRole: (...roles: string[]) => MiddlewareHandler;
};

export type DiagnosticDeps = {
  buildBundle: (db: Database, query: NormalizedQuery) => unknown;
};

export function registerDiagnosticRoutes(
  app: Hono<any>,
  db: Database,
  auth: DiagnosticAuth,
  deps: DiagnosticDeps,
): void {
  app.get("/api/diagnostic", auth.requireRole("super_admin"), (c) => {
    const search = new URL(c.req.url).search;
    const parsed = parseQuery(search);
    if (!parsed.ok) return c.json({ error: parsed.message, code: parsed.code }, 400);
    return c.json({ diagnostic: deps.buildBundle(db, parsed.query) });
  });
}
