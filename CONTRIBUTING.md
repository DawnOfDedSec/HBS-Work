# Contributing to HBS Tool

Thanks for your interest in contributing! This file covers everything you need to build, test, and submit changes.

## Project Overview

| | |
|---|---|
| Extractor | Rust (stable), single static binary, zero runtime dependencies |
| Dashboard | Bun + Hono backend, Vite + React SPA, SQLite |
| Platforms | Linux (musl, amd64/arm64) and Windows (amd64, arm64/armv7 stretch) |
| Docs site | `docs/` — Vite + React + TypeScript, built with Bun, deployed to GitHub Pages |

The two sides share two exact byte formats (the `.hbs` sealed-report envelope and
the binary keyslot) implemented identically in Rust and TypeScript, with
cross-language vectors in `fixtures/`. If you touch either format, both
implementations and the fixtures must change in the same PR.

## Prerequisites

- **Rust stable** (`rustup`) — the extractor; `rust-toolchain.toml` pins the version
- **Bun 1.1+** — the dashboard and the docs site
- Optional: `cargo-zigbuild` (cross-compilation), Docker (distro/container sweeps), Playwright browsers (E2E)

## Building

```bash
# extractor
cd extractor
cargo build               # debug (includes the hidden --dev-insecure-key)
cargo build --release     # LTO, stripped, panic=abort, opt-level=z

# dashboard
cd dashboard
bun install
bun run build             # emits dist/ (the API server serves the SPA too)
bun server/index.ts       # http://127.0.0.1:3000
```

## Testing Your Changes

```bash
cd extractor && cargo test            # unit + integration + catalog audit
cd dashboard && bun test              # backend + frontend unit suite
cd dashboard && bunx tsc --noEmit     # strict TypeScript
cd dashboard && bunx playwright test  # browser E2E (gated by HBS_E2E=1)
```

For behavioral changes to the extractor, prefer the sealed smoke scan:

```bash
cd extractor
./target/debug/hbs-extractor --no-elevate --no-pause --quiet \
  --dev-insecure-key "$(printf 'ab%.0s' {1..32})" --out smoke.hbs
```

The report must start with the `HBS2` magic and be the only file written.

## Documentation

The docs site lives in `docs/` (Vite + React + TypeScript, built with Bun):

```bash
cd docs
bun install
bun run build   # outputs to docs/dist
```

Preview the built site locally:

```bash
bun run preview
```

If your change affects flags, exit codes, env vars, the report format, the
testcase catalog, or the dashboard API, update the matching section under
`docs/src/` **and** the README in the same PR. The docs must reflect **real**
behavior, never aspirational behavior.

## Pull Requests

1. Fork the repo and create your branch from `main`
2. Keep PRs focused: one fix or feature per PR
3. Use [conventional commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `refactor:`, `chore:`)

**Checklist before opening:**

- [ ] `cargo test` passes for extractor changes
- [ ] `bun test` and `bunx tsc --noEmit` pass for dashboard changes
- [ ] Docs (`docs/`) and README updated if behavior, flags, formats, or the catalog changed
- [ ] Both sides of any wire-format change updated (+ `fixtures/` vectors)
- [ ] The extractor's guarantees hold: strictly read-only, single file written, no network unless `--push`
- [ ] No secrets, keys, tokens, or real host data committed

## CI

- **`validate.yml`**: Linux + Windows build/tests/sealed smoke scan and the dashboard suite on every push and PR
- **`release.yml`**: after `validate` succeeds on `main` — builds the target matrix, emits `SHA256SUMS`/`manifest.json`, publishes the release
- **`docs-pages.yml`**: builds the docs site; pushes to `main` deploy it to GitHub Pages

## Reporting Issues

Use the [issue tracker](https://github.com/PotenFYR-Studios/HBS-Tool/issues). For security vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
