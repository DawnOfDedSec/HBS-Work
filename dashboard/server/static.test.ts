import { describe, expect, it } from "bun:test";
import { existsSync } from "node:fs";
import { join } from "node:path";

// Set before importing the server: index.ts opens its database at module load.
process.env.HBS_DB_PATH = ":memory:";
const { app } = await import("./index");

/**
 * Guards the production static-file routes.
 *
 * The regression this exists for: the built SPA block served only /assets/*,
 * so /fonts/*.woff2 fell through to the SPA fallback and returned the HTML
 * shell. Nothing failed - the console just rendered in the OS default face in
 * production, while `bun run dev` (where Vite serves public/ itself) looked
 * right. A font that 200s with text/html is the signature.
 *
 * The static block is only mounted when dist/index.html exists, so these skip
 * on a clean checkout that has not been built.
 */
const built = existsSync(join(import.meta.dir, "..", "dist", "index.html"));
const FONTS = ["inter-latin-var.woff2", "jbmono-latin-var.woff2"];

describe("built SPA static assets", () => {
  for (const file of FONTS) {
    it.skipIf(!built)(`serves /fonts/${file} as a font, not the SPA shell`, async () => {
      const res = await app.request(`/fonts/${file}`);
      expect(res.status).toBe(200);
      expect(res.headers.get("content-type") ?? "").not.toContain("text/html");
      const body = new Uint8Array(await res.arrayBuffer());
      expect(String.fromCharCode(...body.subarray(0, 4))).toBe("wOF2");
    });
  }

  it.skipIf(!built)("still hands /api/* to the API instead of the shell", async () => {
    const res = await app.request("/api/definitely-not-a-route");
    expect(res.headers.get("content-type") ?? "").not.toContain("text/html");
  });
});
