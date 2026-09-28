// Type shim for the module that tools/embed-dist.ts generates after `bun run build`.
// Gitignored as a .ts file; present as a .d.ts so `bunx tsc --noEmit` passes on a
// fresh checkout (dynamic import type-checks, Bun's bundler still embeds the real one).
export declare const EMBEDDED_DIST: Record<string, string>;

