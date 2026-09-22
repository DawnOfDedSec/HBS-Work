# HBS — Host Baseline Security Review Platform

Two-part, offline-first configuration-security review platform:

- **Extractor** (Rust): a single, strictly read-only binary that runs on the target
  host, evaluates ~325 hardening testcases, and writes a **sealed report**
  (`.hbs`, `HBS2` v2 envelope) that only the issuing dashboard can open.
- **Dashboard** (Bun + Hono + React): issues one extractor per campaign/location,
  receives sealed reports by upload or optional `--push`, decrypts and verifies
  them, routes hosts automatically, and renders filterable enterprise reports
  with exports.

The design spec and implementation plan live under
`docs/superpowers/`; the execution ledger lives under `.superpowers/sdd/`.

## Repository layout

```
extractor/           Rust crate (lib + `hbs-extractor` binary)
dashboard/           Bun/Hono backend (`server/`) + Vite/React SPA (`src/`)
fixtures/            Cross-language crypto/keyslot vectors
scripts/             Cross-compilation and Docker validation harnesses
docs/superpowers/    Design spec and implementation plan
```

## Extractor

### Build

```bash
cd extractor
cargo build --release
```

Required targets: `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`,
`x86_64-pc-windows-msvc`. Cross-compilation uses `cargo-zigbuild`
(`scripts/build-all.sh`); release builds are static musl / MSVC, LTO, stripped,
`panic = "abort"`, with a < 10 MiB size gate.

### Run

```
hbs-extractor [OPTIONS]

  --list-checks                  List every registered testcase and exit
  --only <IDS>                   Run only these check IDs (comma-separated)
  --category <NAME>              Run only this category
  --min-severity <LEVEL>         Skip checks below this severity
  --out <PATH>                   Output path for the sealed report
  --push <URL>                   Also push the sealed report to this dashboard
  --push-token-file <PATH>       Read-only file containing the push token
  --elevate                      Request one explicit consent prompt for admin-only checks
  --no-elevate                   Never request elevation
  --no-pause                     Do not pause at the end (scripted runs)
  --quiet                        Suppress progress output
```

A dashboard-issued extractor carries a 512-byte keyslot with the issuance's
public key and IDs. An unissued (placeholder) or expired binary exits before
scanning. The keyslot checksum detects corruption; it is **not** a trust anchor.
By default the sealed report is written **in the same directory as the extractor
binary** (never the current working directory); `--out <path>` overrides it.
Windows system locations are resolved from the environment (`SystemRoot`,
`SystemDrive`, `ProgramFiles`, `ProgramData`), never assumed to be on `C:`.

### Offline by default

Without `--push`, the extractor opens **zero sockets, performs no DNS, and makes
no network call** — local scanning and sealing work fully air-gapped. Hostname
and FQDN are derived from local files only, and the command allowlist rejects
DNS/remote-target tools and arguments (e.g. `hostname -f`, `getent hosts`,
`showmount`, `-ComputerName`, `/node:`, UNC paths) **before** anything is
spawned; the container matrix is run with `--network none` to prove it. When
`--push` is supplied, the report is sealed and written locally **first**; only
then is it sent. A push failure never deletes the local report. Network policy:
connect 5 s, transfer 15 s, at most 2 retries on transient failures.

The push token is sourced **only** from `HBS_PUSH_TOKEN` or
`--push-token-file`. Supplying both is an error. The token never appears in
`argv`, the URL, logs, the self-audit, the report, or the keyslot.

### Least privilege

Scans always start unprivileged. Admin-only checks run only under an explicit
`--elevate` (one consent prompt on Windows; Linux never invokes `sudo` and
prints re-run guidance instead). Declined elevation does not abort the scan:
remaining checks use read-only fallbacks and unresolved results become
`DegradedPartial`. The report records requested/granted/refused/not-needed.

### Strict read-only guarantee

Target files, registry keys, and APIs are queried read-only. Only query-only
allowlisted commands run; `secedit /export`, temp-file exports, redirects, and
every state-changing or network-capable probe are forbidden. The **only** write
on the target host is the requested sealed `.hbs` report. Every attempted file
read and command is recorded before it happens, redacted, and included in the
report's self-audit (including denied, missing, failed, and timed-out attempts).

### Evidence and result semantics

Every result has a status (`Compliant`, `NonCompliant`, `NotApplicable`,
`DegradedPartial`, `Error`) and a severity (`Critical` 10, `High` 6, `Medium` 3,
`Low` 1, `Informational` 0). Checks try ordered read-only sources and stop at
authoritative evidence; exhausted, denied, or malformed sources produce
`DegradedPartial`, never a false pass. `Error` is reserved for internal
invariants or corrupted input. Locatable non-compliant findings attach a
pinpoint evidence block (redacted path, 1-based line/column, a ±3-line context
window with the offending line identified, optional file metadata).

### Sealed report (`.hbs` v2)

93-byte little-endian header — `HBS2`, version 2, suite, key id, 16-byte
`extractor_id`, 16-byte `scan_id`, 32-byte ephemeral X25519 public key, 12-byte
nonce, u64 ciphertext length — followed by
`AEAD(zstd(report JSON))`. The entire header is AEAD additional authenticated
data, so tampering with routing fields fails authentication. Keys come from
`X25519 + HKDF-SHA256` with
`info = "HBS-report-v2" || suite || key_id_le || extractor_id`. Suite 0 is
ChaCha20-Poly1305; suite 1 is AES-256-GCM. The dashboard retains a bounded
legacy `HBS1` ingest path for migration only and never issues v1.

The report is the **single** artifact and is self-diagnosing: alongside every
testcase it embeds a structured, redacted audit trail (`selfAudit.attempts` —
each file read, command, registry, or API query with status, exit code, bytes,
duration, cache flag, and the evidence reference it produced), a `diagnostics`
block (environment/hypervisor, catalog fingerprint, privilege, peak RSS, phase
durations, and a per-check `missingData` explanation with exhausted sources),
and a bounded human-readable `log`. Decrypting one `.hbs` shows the findings
**and** exactly why any value is missing.

### Honest security statement

Sealed reports provide confidentiality and integrity under modern, audited
cryptography, **assuming** the dashboard's private keys stay protected, the OS
RNG is sound, and endpoint memory is secure. We make no “unbreakable” claim.
The extractor binary contains only a **public** key and cannot decrypt anything;
it cannot be encrypted while executable, so its logic remains
reverse-engineerable despite stripping and obfuscation.

### Resource budgets

| Metric | Budget |
|---|---|
| Peak RSS | < 200 MB (typically 20–40 MB) |
| Binary size | < 10 MB (CI gate) |
| CPU | < 0.5 core sustained, ≤ 2 workers, 2–5 s command timeouts |
| Target disk writes | exactly 1 (the sealed report) |

## Dashboard

```bash
cd dashboard
bun install
bun run dev        # binds 127.0.0.1:3000 by default
```

**First run.** If no users exist, the server creates a `super_admin` and prints
its credentials once in the CLI (a random 20-character password). Sign in and
change it. Disable with `HBS_BOOTSTRAP_ADMIN=false` (then use the `/setup`
wizard); override with `HBS_ADMIN_USERNAME` / `HBS_ADMIN_PASSWORD`.

Configuration: `PORT`, `HOST`, `HBS_DB_PATH`, `HBS_DATA_ROOT`, and optional TLS
via `--tls-cert <path> --tls-key <path>` or `HBS_TLS_CERT` / `HBS_TLS_KEY`
(the certificate SHA-256 fingerprint is printed at startup). Private keys are
stored per issuance with mode `0600`; the server binds to localhost by default.

**Hosting on the network:**

```bash
bun server/index.ts                 # 127.0.0.1:3000 (localhost only, default)
bun server/index.ts --host 10.0.0.5 # one interface
bun server/index.ts --host          # ALL interfaces (0.0.0.0) — prints reachable URLs
bun server/index.ts --host --port 8443 --tls-cert cert.pem --tls-key key.pem
```

Bare `--host` prints the interface URLs it is reachable on and a warning when
TLS is not configured (session cookies are unencrypted over plain HTTP). CLI
flags take precedence over `HOST`/`PORT`.

For development, `bun run dev` serves the Vite SPA and proxies `/api`. For a
single-host deployment, `bun run build` emits `dashboard/dist` and the API
server serves it at `/` (with SPA deep-link fallback), so one process serves
both the console and the API.

### Hierarchy and routing

`Campaign → Location → Issuance → Host/Report`. Each issuance has a unique
random `extractor_id` and an independent X25519 keypair; the download route
streams the exact patched artifact written at creation time and verifies its
SHA-256. Campaign and location are derived **only** from the authenticated
issuance — never from request fields or report JSON. Hosts are keyed by a
normalized machine ID, with `host_locations` preserving history across
locations. Replays of `(extractor_id, scan_id)` are idempotent.

### Tests

```bash
cd extractor && cargo test        # Rust unit/integration suite
cd dashboard && bun test          # Bun backend + frontend unit suite
cd dashboard && bunx tsc --noEmit # strict TypeScript check
```

### Real-world validation

```bash
# Linux: static musl extractor inside real distros, root and non-root
bash scripts/docker-test/run.sh
bun run scripts/docker-test/validate-reports.ts   # decrypt + assert every sealed report

# Host sweep: host the dashboard and have 13 distro versions download the
# extractor from it, run it, and push/upload results (with extractor logs)
cd dashboard && bun run ../scripts/docker-e2e-hosts.ts

# Linux end-to-end: issue a musl extractor, run it in debian:12, push to the dashboard
cd dashboard && bun run ../scripts/e2e-linux.ts

# Windows: native scans (full, filtered, category, list) + issued-extractor loop
bun run scripts/windows-validate.ts
cd dashboard && bun run ../scripts/e2e-loop.ts
```

Docker Desktop here runs Linux containers, so Windows is validated natively on
a real Windows host. Windows-container mode (servercore/nanoserver LTSC sweep,
`scripts/docker-e2e-hosts-windows.ts`) requires the enabled `Containers`
Windows feature and a Docker Desktop install that permits Windows containers.

## Status and limitations

The platform is functionally complete end to end: a dashboard-issued extractor
scans offline, seals a v2 report, pushes or uploads it, and the dashboard
decrypts, routes, and exports it (verified by `scripts/e2e-loop.ts`).

Known limitations at this revision:

- Windows 10/11/Server 2016–2025 have not been exercised on real runners; the
  catalog-wide audit (`extractor/tests/catalog.rs`) covers Linux and Windows
  behavior with injected, offline contexts.
- Evidence blocks use the `{path, line, col, context[], targetIndex}` wire
  format, and the UI derives the ±3-line window from it. The spec's fully
  discriminated block (`sourceType/offendingValue/contextBefore/contextAfter`)
  is a documented future refinement, not implemented across the catalog.
- Browser end-to-end specs under `dashboard/tests/` are driven by
  `bunx playwright test` and gated behind `HBS_E2E=1`; `bun test` intentionally
  ignores `tests/**` (see `dashboard/bunfig.toml`).
- Backup restore validates and stages a replacement database; the operator
  swaps the file and restarts the server rather than hot-swapping live state.

The dashboard makes no outbound network calls; there is no telemetry and no
auto-update. See `.superpowers/sdd/2026-09-21-hbs-platform/progress.md` for the
full execution ledger.
