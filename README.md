# HBS — Host Baseline Security Review Platform

An offline-first, strictly read-only configuration-security review platform for
enterprise servers, with a sealed-report security model.

- **Extractor** (Rust, single static binary) — runs on a target host, evaluates
  **368 hardening testcases**, and writes a **sealed report** (`.hbs`, `HBS2` v2)
  that only the issuing dashboard can decrypt. It is air-gapped by default.
- **Dashboard** (Bun + Hono + React) — issues one patched extractor per
  campaign/location, receives sealed reports by file **upload** or optional
  **`--push`**, decrypts/verifies them, routes hosts automatically, and presents
  findings, remediation, telemetry, standards, and exports.

It is built for four audiences: **security leadership** (executive one-pager),
**system administrators** (actionable remediation), **cyber analysts**
(pivots, evidence, diffing, telemetry), and **upper management** (board-ready
reporting and printable deliverables).

> **Design/plan:** `docs/superpowers/specs/` and `docs/superpowers/plans/`.
> **Execution ledger:** `.superpowers/sdd/`.

---

## Table of contents

1. [Architecture](#architecture)
2. [Platform support](#platform-support)
3. [Quick start](#quick-start)
4. [Extractor reference](#extractor-reference)
5. [Dashboard reference](#dashboard-reference)
6. [Report format & security model](#report-format--security-model)
7. [Testcase catalog](#testcase-catalog)
8. [Validation & testing](#validation--testing)
9. [CI/CD & releases](#cicd--releases)
10. [Resource budgets](#resource-budgets)
11. [Honest security statement](#honest-security-statement)
12. [Limitations & roadmap](#limitations--roadmap)
13. [Troubleshooting / FAQ](#troubleshooting--faq)
14. [Glossary](#glossary)
15. [Repository layout](#repository-layout)

---

## Architecture

```
Campaign ──► Location ──► Issuance ──► Host / Report
                             │
   dashboard patches a per-issuance X25519 public key into the extractor keyslot
                             │
        ┌────────────────────▼─────────────────────┐
        │  TARGET HOST (read-only scan, no network) │
        │  hbs-extractor  ──►  hbs-report-*.hbs     │
        └────────────────────┬─────────────────────┘
                             │  (A) operator uploads the file
                             │  (B) optional --push with a campaign token
                     ┌───────▼────────┐
                     │   Dashboard     │  decrypt → verify → route by machine-id
                     │  SQLite + SPA   │  findings • remediation • telemetry • exports
                     └────────────────┘
```

The two sides share two exact byte formats, defined once and implemented
identically in Rust and TypeScript: the **sealed-report envelope** and the
**binary keyslot**.

---

## Platform support

| Target | Arch | Status |
|---|---|---|
| `x86_64-unknown-linux-musl` | amd64 Linux | Required (fully static musl) |
| `aarch64-unknown-linux-musl` | arm64 Linux | Required |
| `x86_64-pc-windows-msvc` | amd64 Windows | Required (static CRT for containers) |
| `aarch64-pc-windows-msvc` | arm64 Windows | Stretch |
| `armv7-unknown-linux-musleabihf` | 32-bit armv7 Linux | Stretch |

- **Linux families:** Debian/Ubuntu, RHEL/CentOS/Rocky/Alma, SUSE, Arch, Alpine,
  Amazon Linux — kernel ≥ 3.10. Tested across 13 distro versions.
- **Windows:** 10/11 and Server 2016–2025. Tested on Windows 11 natively and
  Server Core LTSC 2019/2022/2025 in containers.
- **Environments:** bare metal, VM, container, and WSL are detected; controls
  that cannot exist in a container (Secure Boot, TPM, bootloader, kernel
  modules, host firewall, separate-partition layout) report `NotApplicable`
  with a reason instead of failing.
- Other OSes (macOS, BSD, Solaris/AIX) and non-x86/arm architectures are not
  targeted.

---

## Quick start

### 1. Dashboard (hosted on your machine)

```bash
cd dashboard
bun install
bun run build                 # emits dist/ (the API server serves the SPA too)
bun server/index.ts           # http://127.0.0.1:3000
```

On first launch (no users) the server **prints superuser credentials once** in
the CLI. Sign in and change the password.

### 2. Create campaign → location → issuance

In the UI: **Campaigns → New campaign** (adds the first location), then
**Locations → Generate extractor**. Or via API:

```bash
# after signing in, the browser holds the session cookie
POST /api/campaigns                         { "name":"Acme Q3", "locations":[{"name":"DC-East"}] }
POST /api/campaigns/:id/locations/:loc/issuances   { "platform":"linux-amd64" }
GET  /api/issuances/:id/download?token=<downloadToken>
```

### 3. Run the extractor on the target (offline)

```bash
# Linux (amd64), unprivileged; report lands beside the binary
./hbs-extractor --no-elevate --quiet

# Windows (PowerShell/cmd)
hbs-extractor.exe --no-elevate --quiet
```

### 4. Deliver the report — pick one

```bash
# (A) Upload in the dashboard
#     Campaign → Locations & Hosts → drag the .hbs into the drop zone

# (B) Optional push from the extractor (only then does it use the network)
HBS_PUSH_TOKEN=<campaignPushToken> ./hbs-extractor \
  --no-elevate --quiet --push https://dashboard.example/api/ingest
# or, without an env var:
./hbs-extractor --push https://dashboard.example/api/ingest \
  --push-token-file /etc/hbs/push.token
```

The dashboard derives **campaign and location solely from the issuance**, keys
the host by machine ID, and (for a subsequent scan) auto-resolves previously
open findings that now pass.

---

## Extractor reference

### Build

```bash
cd extractor
cargo build               # debug (includes the hidden --dev-insecure-key)
cargo build --release     # LTO, stripped, panic=abort, opt-level=z
```

Cross-compilation (`scripts/build-all.sh`, `cargo-zigbuild`):

```bash
cargo zigbuild --release --target x86_64-unknown-linux-musl
cargo zigbuild --release --target aarch64-unknown-linux-musl
# Windows (static CRT so it runs in clean images):
RUSTFLAGS='-C target-feature=+crt-static' cargo build --release --target x86_64-pc-windows-msvc
```

### Command-line flags

| Flag | Meaning |
|---|---|
| `--list-checks` | Print every registered testcase (id, severity, category, title) and exit |
| `--only <IDS>` | Run only these check IDs (comma-separated) |
| `--category <NAME>` | Run only one category (e.g. `SSH`, `Account Policy`, `Server Config`) |
| `--min-severity <LEVEL>` | Skip checks below `critical\|high\|medium\|low\|informational` |
| `--out <PATH>` | Report path. **Default: beside the extractor binary**, never the CWD |
| `--push <URL>` | Also POST the sealed report to a dashboard (`http(s)://…/api/ingest`) |
| `--push-token-file <PATH>` | Read-only file with the push token (mutually exclusive with `HBS_PUSH_TOKEN`) |
| `--elevate` | Ask once for elevation to run admin-only checks (Windows UAC; Linux guidance) |
| `--no-elevate` | Never request elevation |
| `--no-pause` | Do not pause at the end (scripted/CI runs) |
| `--quiet` | Suppress progress output (machine-readable lines) |

Hidden/internal: `--elevated-child` (relaunch guard) and, **debug builds only**,
`--dev-insecure-key <64-hex>` (testing without a dashboard-issued keyslot; never
present in release builds).

### Environment variables

| Variable | Effect |
|---|---|
| `HBS_PUSH_TOKEN` | Push token (only read when `--push` is used) |

Supplying both `HBS_PUSH_TOKEN` and `--push-token-file` is an error. The token
never appears in `argv`, the URL, logs, the self-audit, the report, or the
keyslot.

### Output & exit codes

- **Output:** one sealed `.hbs` file, written **next to the extractor binary** by
  default, or to `--out`. It is the only file written on the target.
- `0` success · `2` unissued/placeholder or expired keyslot · `3` no checks
  matched the filters, sealing/write failure, or push-token configuration error.
  A **network push failure does not fail the scan** — the local report is kept
  and the summary shows a push-failed status.

### Scenario guide

| Scenario | Command |
|---|---|
| Linux, non-root, offline | `./hbs-extractor --no-elevate --quiet` |
| Linux, elevated (root) | `sudo ./hbs-extractor --no-elevate --quiet` (already privileged) |
| Linux, ask for elevation | `./hbs-extractor --elevate` (prints re-run guidance; never invokes `sudo`) |
| Linux, filtered + custom output | `./hbs-extractor --only LIN-SSH-001,LIN-NET-004 --out /tmp/scan.hbs` |
| Windows, standard user | `hbs-extractor.exe --no-elevate --quiet` |
| Windows, admin-only checks | `hbs-extractor.exe --elevate` (one UAC prompt; denial still completes) |
| Windows, scripted / CI | `hbs-extractor.exe --no-elevate --no-pause --quiet` |
| Air-gapped push | `HBS_PUSH_TOKEN=… ./hbs-extractor --push https://…/api/ingest` |
| Collect-and-upload | run with no `--push`, then upload the `.hbs` in the dashboard |
| VM / container | identical flags; host-only controls become `NotApplicable` |
| Inventory only | `./hbs-extractor --list-checks` |

### Least privilege

Scans **always start unprivileged**. Admin-only checks run only under an
explicit `--elevate` (a single Windows UAC consent; Linux never invokes `sudo`).
Declined/cancelled elevation does not abort: remaining checks use read-only
fallbacks and unresolved results become `DegradedPartial`. The report records
`privilegeRequested/Granted/Refused/not-needed` and per-check run context.

### Strict read-only guarantee

Only query-style, allowlisted commands run; `secedit /export`, temp-file
exports, redirects, shell interpreters, and state-changing or network-capable
probes are rejected **before spawn**. DNS/remote forms are refused
(`hostname -f`, `getent hosts`, `showmount`, `-ComputerName`, `/node:`, UNC
paths). The single write on the target is the sealed report. Every attempted
read/command is recorded before it happens and included in the report.

---

## Dashboard reference

### Install & run

```bash
cd dashboard
bun install
bun run dev                  # Vite dev server (SPA) + proxies /api to :3000
# production single-process:
bun run build && bun server/index.ts
```

### First run & users

- If no users exist, the server creates a `super_admin` and **prints its
  credentials once in the CLI** (random 20-char password).
  - Disable with `HBS_BOOTSTRAP_ADMIN=false` → use the `/setup` wizard instead.
  - Override with `HBS_ADMIN_USERNAME` / `HBS_ADMIN_PASSWORD`.
- Roles: `super_admin` (all, incl. users/keys/backup/diagnostic), `auditor`
  (campaigns, issuances, ingest, treatment, exports), `viewer` (read-only).

### Hosting & configuration

| HTTP flag | Env | Meaning |
|---|---|---|
| `--host` | `HOST` | Bare `--host` binds **all interfaces** (`0.0.0.0`) and prints reachable URLs; `--host <addr>` binds one; default `127.0.0.1` |
| `--port <n>` | `PORT` | Listen port (default `3000`) |
| `--tls-cert <p>` / `--tls-key <p>` | `HBS_TLS_CERT` / `HBS_TLS_KEY` | Enable TLS (fingerprint printed at startup) |
| `--help` | — | Usage |
| — | `HBS_DB_PATH` | SQLite path (default `server/data/hbs.sqlite`) |
| — | `HBS_DATA_ROOT` | Keys/artifacts root (default `server/data`) |

CLI flags take precedence over env. Binding to a non-loopback address prints the
interface URLs and a warning when TLS is not configured.

### Workflow

1. **Campaign + location** (creation can include the first location atomically).
2. **Issuance** — a unique random `extractor_id` and independent X25519 keypair;
   the dashboard patches the binary and stores the immutable artifact + SHA-256.
3. **Download** — token or session authenticated; streams the exact stored bytes
   and verifies the hash. Revoked/expired issuances are refused.
4. **Scan** — air-gapped by default, or `--push`.
5. **Ingest** — unified pipeline: bounds → issuance resolution → token auth →
   AEAD decrypt + bounded decompress → schema/identity cross-binding →
   dedupe `(extractor_id, scan_id)` → server-authoritative metrics → one
   transaction → SSE `report-arrived`.
6. **Triage** — treatment workflow with audit history; owners, due dates,
   justifications.
7. **Export** — Excel, CSV, PDF (executive + technical), Word, diagnostic bundle.

### Console pages

| Page | Audience | What it does |
|---|---|---|
| **Executive Summary** | management | Board one-pager, risk gauge, top risks, plain-language narrative, **presentation mode**, **print/Save as PDF** |
| **Overview** | all | KPI tiles with drill-down, risk trend, severity donut, top failing checks, freshness banner |
| **Campaigns** | all | Campaign workspace, scope selector (latest / report / date range) |
| **Locations & Hosts** | sysadmin | Location cards, host inventory, download snippets, batch **drop-zone upload** |
| **Findings** | analyst | Filters (URL-canonical), By Host / By Check pivots, density toggle, saved views |
| **Remediation** | sysadmin | Failing checks grouped into action items with copyable fix commands + exports |
| **Telemetry** | analyst | Scan/ingest percentiles, coverage trend, adoption bars, freshness/SLA |
| **Standards** | analyst/auditor | CIS / NIST 800-53 / ISO 27001 / PCI-DSS coverage matrix |
| **Treatment** | auditor | State board (open/accepted_risk/false_positive/remediated) with history |
| **Admin** | super_admin | Users, issuance keys, retention, audit log, encrypted backup/restore |

Cross-cutting: command palette (`Ctrl/⌘-K`), live SSE activity + notifications,
light/dark theme, table twins for every chart, and a print stylesheet.

### Key API endpoints

```
GET    /api/health
POST   /api/auth/setup | /api/auth/login | /api/auth/logout        GET /api/auth/status
GET    /api/campaigns      POST /api/campaigns
GET    /api/campaigns/:id/locations    POST/PATCH /api/campaigns/:id/locations[/:loc]
POST   /api/campaigns/:id/locations/:loc/issuances   GET (list)
GET    /api/issuances/:id/download?token=…   DELETE /api/campaigns/:id/issuances/:extractorId
POST   /api/ingest            (extractor push; Bearer push token)
POST   /api/reports/upload    (multipart batch, ≤32 files; session)
GET    /api/events            (SSE report-arrived)
GET    /api/overview | /api/campaigns/:id/summary | /api/metrics/{severity,category,risk}
GET    /api/findings | /api/reports | /api/reports/:id | /api/reports/:id/diff/:other
GET    /api/hosts | /api/hosts/:id | /api/checks/:checkId
GET    /api/remediation | /api/telemetry | /api/standards | /api/treatment
POST   /api/reports/:id/findings/:checkId/treatment
GET/POST/PATCH/DELETE /api/saved-views
GET    /api/admin/audit | /api/reports/:id/findings/:checkId/history
POST   /api/admin/backup | /api/admin/backup/restore
GET    /api/export/report/:id?format=xlsx|csv|pdf|docx[&template=executive|technical]
GET    /api/export/campaign/:id?format=…      GET /api/export/diagnostic?format=json|csv
```

---

## Report format & security model

### `.hbs` v2 envelope (93-byte header, little-endian)

```
0   4   magic "HBS2"
4   2   version (u16 = 2)
6   1   suite (0 = X25519+HKDF-SHA256+ChaCha20-Poly1305, 1 = …+AES-256-GCM)
7   2   key_id (u16)
9   16  extractor_id
25  16  scan_id
41  32  ephemeral X25519 public key
73  12  nonce
85  8   ciphertext length (u64)
93  ..  AEAD(zstd(report JSON)) + 16-byte tag
```

- The **entire header is AEAD AAD** → tampering with routing fails authentication.
- `key = HKDF-SHA256(X25519(eph, recipient), salt = scan_id||eph_pub,
  info = "HBS-report-v2"||suite||key_id_le||extractor_id)`.
- The dashboard keeps a bounded **`HBS1` ingest** path for migration only and
  never issues v1.

### Keyslot (512 bytes, patched per issuance)

Magic `HBSKSLOT`, version, flags, key id, campaign/extractor IDs, issued/expiry
timestamps, 32-byte recipient public key, zero pad, SHA-256 checksum. Strict
validation rejects absent/duplicate slots, nonzero flags/reserved/pad, nil IDs
or key, and `issued_at >= expiry`. **The checksum detects corruption, not trust.**

### Self-diagnosing report

The single sealed file carries **both results and logs**:

- `results[]` — status, severity, evidence, location, repro, impact,
  recommendation, references, `fallbackLog`, `evidenceBlocks`, `runContext`.
- `selfAudit.attempts[]` — every file read / command / registry / API query with
  `kind`, redacted `source`, `status` (`ok|missing|denied|timeout|rejected|
  nonzero|malformed|cached|error`), `exitCode`, `bytes`, `durationMs`,
  `cached`, and `evidenceRef` linking a finding to the log line that produced it.
- `diagnostics` — environment/hypervisor, catalog fingerprint, privilege, peak
  RSS, phase durations, `missingData` (per degraded/NA/error check with
  exhausted sources), metadata attempts, and a bounded human-readable `log`.

All strings are redacted and size-bounded before sealing.

---

## Testcase catalog

**368 testcases** — Linux `LIN-*` (165), Windows `WIN-*` (153), and shared
`GEN-*` (50). Checks are applicability-gated, not duplicated: a Linux host runs
~215, a Windows host ~200; the union is 368.

| Family | Count | Coverage |
|---|---|---|
| `LIN-FS` | 15 | Partitions (`/tmp`, `/var`, `/home`, …), mount options, bootloader perms, core dumps |
| `LIN-SV` | 10 | Legacy/inetd services, telnet/rsh/tftp clients absent, MTA posture |
| `LIN-NET` | 20 | IP forwarding, ICMP, rp_filter, redirects, syncookies, IPv6 |
| `LIN-FW` | 5 | firewalld/ufw/nftables/iptables default-deny |
| `LIN-LOG` | 14 | rsyslog/journald config, permissions, rotation, remote forwarding |
| `LIN-AU` | 12 | auditd rules, immutability, retention |
| `LIN-SSH` | 15 | sshd: root login, ciphers/MACs/KEX, auth limits, forwarding |
| `LIN-PAM` | 14 | pwquality, faillock, pwhistory, password ageing, sudo policy |
| `LIN-USER` | 20 | passwd/shadow/group perms, UID 0 uniqueness, umask, home perms |
| `LIN-TH` | 40 | Kernel attack surface (eBPF, userns, io_uring, kptr/dmesg, lockdown), persistence hunting, containers/EOL/currency |
| `WIN-ACC` | 14 | Account policy (length/age/history/lockout, LSA restrictions, admins) |
| `WIN-AU` | 10 | Audit subcategories via `auditpol /get` (never `secedit /export`) |
| `WIN-SEC` | 22 | UAC, LM/NTLM, SMB signing, screen lock, legal notice, SMBv1 |
| `WIN-UR` | 16 | User rights via read-only LSA policy APIs |
| `WIN-EVT` | 6 | Event log sizes/retention/permissions |
| `WIN-DEF` | 10 | Defender AV + ASR + update posture |
| `WIN-SVC` | 20 | Legacy/unnecessary services (Telnet, TFTP, RemoteRegistry, Spooler, …) |
| `WIN-REG` | 10 | Registry/filesystem ACLs, Run keys, unquoted service paths |
| `WIN-NET` | 18 | Firewall profiles, LLMNR/mDNS, RDP, WinRM, LDAP signing, NTLM |
| `WIN-TH` | 27 | Credential protection (LSA PPL, Credential Guard, HVCI, WDigest), ASR, persistence (IFEO, WMI, tasks, netsh), EOL/LAPS |
| `GEN-INV` | 25 | Inventory: ports, packages, users, tasks, shares, patch, TPM/Secure Boot, EDR/backup, identity |
| `GEN-SRV` | 24 | Server config review: time sync, DNS redundancy, updates, backup, log forwarding, pending reboot, certs, firewall, management bindings, sudo/UAC, free space, swap, LDAP/Kerberos |

There is also one internal self-test (`GEN-TOY-001`), which is why the `GEN`
family totals 50 (25 + 24 + 1). `--list-checks` prints the full set; every check
has an ordered fallback chain and degrades (never false-passes, never `Error`)
when evidence is unavailable.

---

## Validation & testing

### Unit / integration

```bash
cd extractor && cargo test              # Rust suite (unit + integration + catalog audit)
cd dashboard && bun test                # Bun backend + frontend unit suite
cd dashboard && bunx tsc --noEmit       # strict TypeScript
cd dashboard && bunx playwright test    # browser E2E (gated by HBS_E2E=1)
```

### Real-world matrices

```bash
# Linux: static musl extractor inside real distros, root + non-root, --network none
bash scripts/docker-test/run.sh
bun run scripts/docker-test/validate-reports.ts   # decrypt + assert every sealed report

# Linux end-to-end: issue a musl extractor, run it in debian:12, push to dashboard
cd dashboard && bun run ../scripts/e2e-linux.ts

# Windows: Server Core LTSC 2019/2022/2025 via the Docker WINDOWS engine
cd dashboard && bun run ../scripts/docker-e2e-hosts-windows.ts

# Windows native (optional): scans + issued-extractor loop
bun run scripts/windows-validate.ts
cd dashboard && bun run ../scripts/e2e-loop.ts
```

| Script | Purpose |
|---|---|
| `scripts/build-all.sh` | Cross-compile the target matrix (+ size gate) |
| `scripts/docker-test/run.sh` | 13-distro Linux sweep, root/non-root, `--network none` |
| `scripts/docker-test/validate-reports.ts` | Decrypt every report; assert content + logs |
| `scripts/docker-test/http-get-bash.sh` | Dependency-free downloader for minimal images |
| `scripts/docker-e2e-hosts.ts` | Dashboard-hosted Linux sweep (download → run → push/upload) |
| `scripts/docker-e2e-hosts-windows.ts` | Same for Windows Server Core containers |
| `scripts/e2e-linux.ts` | Issue → run in `debian:12` → push → assert routing/exports |
| `scripts/e2e-loop.ts` | Windows issued-extractor loop (incl. confidentiality assertions) |
| `scripts/windows-validate.ts` | Native Windows scan matrix (full/filtered/category/list) |
| `scripts/check-spa.ts` | SPA serving smoke (root, deep link, assets, API) |
| `scripts/check-bootstrap.ts` | First-run CLI credential bootstrap |

### Docker engine switching (for the local container sweeps)

```powershell
& "$Env:ProgramFiles\Docker\Docker\DockerCli.exe" -SwitchLinuxEngine   # Linux sweep
& "$Env:ProgramFiles\Docker\Docker\DockerCli.exe" -SwitchWindowsEngine # Windows sweep
```

---

## CI/CD & releases

- **`.github/workflows/validate.yml`** (push/PR/manual)
  - Linux: `ubuntu-22.04`, `ubuntu-24.04` — build, tests, sealed smoke scan, artifacts.
  - Windows: `windows-2022`, `windows-2025` (+ `windows-2019`, `windows-11-arm` tolerated) — build, tests, sealed scan.
  - Dashboard: `bun test`, `tsc`, `vite build`.
- **`.github/workflows/release.yml`** (runs only after `validate` succeeds on main)
  - Builds all targets + the dashboard bundle, emits `SHA256SUMS` and `manifest.json`.
  - Publishes a release tagged `v<version>` from `extractor/Cargo.toml`:
    - **new version** → creates the release with the changelog (commits since the previous tag);
    - **same version** → overwrites the assets and **appends** the new changelog to the existing notes.

---

## Resource budgets

| Metric | Budget | Enforced by |
|---|---|---|
| Peak RSS | < 200 MB (typically 20–40 MB) | bounded 1 MiB reads, streaming JSON |
| Binary size | < 10 MB (expected 5–8 MB) | static musl, `opt-level=z`, LTO, strip, CI gate |
| CPU | < 0.5 core sustained | sequential checks, ≤ 2 workers, 2–5 s command timeouts, lowered priority |
| Target disk writes | exactly 1 | sealed report only; no temp exports |

---

## Honest security statement

Sealed reports provide confidentiality and integrity under modern, audited
cryptography (X25519, HKDF-SHA256, ChaCha20-Poly1305 or AES-256-GCM) **assuming**
the dashboard's private keys stay protected, the OS RNG is sound, and endpoint
memory is secure. We make no "unbreakable" claim. The extractor binary contains
only a **public** key and cannot decrypt anything; a binary cannot be encrypted
while still executable, so its logic remains reverse-engineerable despite
stripping and obfuscation.

---

## Limitations & roadmap

- **Other OSes/architectures** (macOS, BSD, Solaris/AIX; s390x/ppc64/riscv) are
  out of scope. armv7/arm64 Windows are build targets validated opportunistically.
- **Evidence blocks** currently use `{path, line, col, context[], targetIndex}`;
  the UI derives the ±3-line window. A fully discriminated wire block
  (`sourceType/offendingValue/contextBefore/contextAfter`) is a possible future
  refinement.
- **Backup restore** validates and stages a replacement database; the operator
  swaps the file and restarts rather than hot-swapping live state.
- Planned: ATT&CK coverage view, SLA/ownership board, attack-surface inventory
  with deltas, chart exports, API tokens for CI uploads.

---

## Troubleshooting / FAQ

**`/` returns 404.** Run `bun run build` (emits `dist/`) then `bun server/index.ts`;
the API server serves the SPA. In development use `bun run dev`.

**`unissued or placeholder keyslot` (exit 2).** The binary was not issued by a
dashboard. Download it from an issuance, or (debug only) use `--dev-insecure-key`.

**`extractor expired` (exit 2).** The issuance passed its expiry — create a new
issuance.

**Push fails but the scan succeeded.** The local report is kept; upload it
manually. Tokens come only from `HBS_PUSH_TOKEN` or `--push-token-file`.

**A check shows `DegradedPartial`.** Every fallback was unavailable/denied. The
report's `missingData` lists the exhausted sources — that is expected on hosts
missing a tool or in containers where a control cannot exist (which instead
reports `NotApplicable`).

**Where is the report?** Next to the extractor binary unless `--out` is given.

**Windows containers.** Docker Desktop must be a machine-wide install with the
`Containers`/Hyper-V features enabled; then
`DockerCli.exe -SwitchWindowsEngine`. `nanoserver` is too minimal — use
`servercore`.

---

## Glossary

| Term | Meaning |
|---|---|
| Campaign / Location / Issuance | Audit engagement → site → one patched extractor artifact |
| Keyslot | 512-byte header in the binary carrying the issuance's public key and IDs |
| Sealed report (`.hbs`) | AEAD envelope containing the report JSON, audit log, and diagnostics |
| Evidence depth | `AuthoritativePrimary`, `AuthoritativeFallback`, `DegradedPartial` |
| Status | `Compliant`, `NonCompliant`, `NotApplicable`, `DegradedPartial`, `Error` |
| Severity | `Critical` 10, `High` 6, `Medium` 3, `Low` 1, `Informational` 0 |
| Machine ID | Stable host identity (`/etc/machine-id`, `MachineGuid`, or a documented fallback) |

---

## Repository layout

```
extractor/           Rust crate (lib + `hbs-extractor` binary)
  src/checks/        LIN-*, WIN-*, GEN-INV, GEN-SRV modules + registry
  src/{crypto,keyslot,model,report,context,evidence,metadata,platform}.rs
dashboard/           Bun + Hono backend (`server/`) + Vite/React SPA (`src/`)
fixtures/            Cross-language crypto/keyslot vectors
scripts/             Build + validation harnesses (see table above)
.github/workflows/   validate.yml, release.yml
docs/superpowers/    Design spec and implementation plan
```
