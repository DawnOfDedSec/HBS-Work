/**
 * Embedded SPA assets for standalone (`bun build --compile`) server builds.
 *
 * tools/embed-dist.ts regenerates dist.embedded.generated.ts after every
 * `bun run build`. Repo checkouts without a build keep a missing module: the
 * dynamic import then fails and every lookup falls back to disk (dev mode
 * serves dist/ from disk, or Vite serves public/ itself).
 */
import { join } from "node:path";

export interface EmbeddedFile {
  body: ArrayBuffer;
  contentType: string;
}

let EMBEDDED: Record<string, string> = {};
try {
  const mod = await import("./dist.embedded.generated");
  EMBEDDED = mod.EMBEDDED_DIST ?? {};
} catch {
  // No generated module (repo checkout): disk serving stays in charge.
}

const cache = new Map<string, EmbeddedFile | null>();

const MIME: Record<string, string> = {
  html: "text/html; charset=utf-8",
  js: "text/javascript; charset=utf-8",
  mjs: "text/javascript; charset=utf-8",
  css: "text/css; charset=utf-8",
  json: "application/json; charset=utf-8",
  txt: "text/plain; charset=utf-8",
  svg: "image/svg+xml",
  png: "image/png",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  gif: "image/gif",
  ico: "image/x-icon",
  webp: "image/webp",
  woff: "font/woff",
  woff2: "font/woff2",
  ttf: "font/ttf",
  otf: "font/otf",
  eot: "application/vnd.ms-fontobject",
  webmanifest: "application/manifest+json",
  map: "application/json; charset=utf-8",
  wasm: "application/wasm",
};

function contentTypeFor(path: string): string {
  const ext = path.slice(path.lastIndexOf(".") + 1).toLowerCase();
  return MIME[ext] ?? "application/octet-stream";
}

export function hasEmbeddedDist(): boolean {
  return Object.keys(EMBEDDED).length > 0;
}

/** Decode once, then cache: cold lookups pay one base64 decode. */
export function embeddedFile(path: string): EmbeddedFile | null {
  const key = path.split("\\").join("/").replace(/^\/+/, "");
  if (cache.has(key)) return cache.get(key)!;
  let result: EmbeddedFile | null = null;
  const b64 = EMBEDDED[key];
  if (b64 !== undefined) {
    const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    // Exact-size ArrayBuffer: valid BodyInit for new Response(...).
    result = { body: bytes.buffer as ArrayBuffer, contentType: contentTypeFor(key) };
  }
  cache.set(key, result);
  return result;
}

/**
 * Absolute paths that exist in the embedded bundle, e.g. "index.html".
 * Exported so the server can compute CSP hashes without touching disk.
 */
export function embeddedIndexHtml(): string | null {
  const file = embeddedFile("index.html");
  if (!file) return null;
  return new TextDecoder().decode(file.body);
}

export const distIndexHtmlPath = join(import.meta.dir, "..", "dist", "index.html");
