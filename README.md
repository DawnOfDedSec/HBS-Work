<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:8b5cf6,50:ec4899,100:f97316&height=220&section=header&text=hbs-tool&fontSize=52&fontColor=ffffff&fontAlignY=34&desc=Sealed%20reports%20%C2%B7%20Read-only%20scans%20%C2%B7%20368%20hardening%20testcases&descSize=18&descAlignY=55&animation=twinkling" width="100%" alt="hbs-tool banner"/>

[![Release](https://img.shields.io/github/v/release/PotenFYR-Studios/HBS-Tool?style=for-the-badge&logo=github&logoColor=white&labelColor=1c1e26&color=8b5cf6)](https://github.com/PotenFYR-Studios/HBS-Tool/releases)
[![Docs](https://img.shields.io/badge/docs-hbs--tool.docs.potenfyr.in-8b5cf6?style=for-the-badge&logo=googlechrome&logoColor=white&labelColor=1c1e26)](https://hbs-tool.docs.potenfyr.in)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-ec4899?style=for-the-badge&logo=linux&logoColor=white&labelColor=1c1e26)](#platform-support)
[![Discord](https://img.shields.io/badge/Discord-Join%20us-5865F2?style=for-the-badge&logo=discord&logoColor=white&labelColor=1c1e26)](https://discord.com/invite/zUaN2FPBec)
[![GitHub](https://img.shields.io/badge/GitHub-PotenFYR--Studios-181717?style=for-the-badge&logo=github&logoColor=white&labelColor=1c1e26)](https://github.com/PotenFYR-Studios/HBS-Tool)
[![View](https://komarev.com/ghpvc/?username=PotenFYR-Studios-HBS-Tool&color=ec4899&style=for-the-badge&label=VIEW&labelColor=1c1e26)](https://github.com/PotenFYR-Studios/HBS-Tool)

[![CI](https://img.shields.io/github/actions/workflow/status/PotenFYR-Studios/HBS-Tool/validate.yml?branch=main&style=flat-square&logo=githubactions&label=CI&color=2ea043&labelColor=1c1e26)](https://github.com/PotenFYR-Studios/HBS-Tool/actions/workflows/validate.yml)
[![testcases](https://img.shields.io/badge/hardening-368%20testcases-8b5cf6?style=flat-square&labelColor=1c1e26)](#testcase-catalog)
[![network](https://img.shields.io/badge/target%20network-air--gapped%20by%20default-2ea043?style=flat-square&labelColor=1c1e26)](#report-format--security-model)

[![Typing SVG](https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=20&pause=1200&color=8B5CF6&center=true&vCenter=true&width=800&lines=Offline-first+host+baseline+security+reviews;Strictly+read-only+scans+%C2%B7+sealed+reports;368+hardening+testcases+across+Linux+%26+Windows;Executive+one-pagers+to+raw+evidence+pivots)](https://github.com/PotenFYR-Studios/HBS-Tool)

**HBS** - an offline-first, strictly read-only configuration-security review platform for enterprise servers, with a sealed-report security model.

[Docs](https://hbs-tool.docs.potenfyr.in) · [Getting started](https://hbs-tool.docs.potenfyr.in/docs/getting-started) · [Releases](https://github.com/PotenFYR-Studios/HBS-Tool/releases) · [Issues](https://github.com/PotenFYR-Studios/HBS-Tool/issues)

</div>

---

## Why HBS

Auditing a fleet of enterprise servers with screen shots, spreadsheets and SSH one-liners is slow, inconsistent and leaks data at every step. HBS does it in two sealed halves:

- **Extractor** (Rust, single static binary) - runs on a target host, evaluates
  **368 hardening testcases**, and writes a **sealed report** (`.hbs`, `HBS2` v2)
  that only the issuing dashboard can decrypt. It is air-gapped by default.
- **Dashboard** (Bun + Hono + React) - issues one patched extractor per
  campaign/location, receives sealed reports by file **upload** or optional
  **`--push`**, decrypts/verifies them, routes hosts automatically, and presents
  findings, remediation, telemetry, standards, and exports.

It is built for four audiences: **security leadership** (executive one-pager),
**system administrators** (actionable remediation), **cyber analysts**
(pivots, evidence, diffing, telemetry), and **upper management** (board-ready
reporting and printable deliverables).

> The full documentation lives at **[hbs-tool.docs.potenfyr.in](https://hbs-tool.docs.potenfyr.in)**:
> [getting started](https://hbs-tool.docs.potenfyr.in/docs/getting-started),
> the [extractor reference](https://hbs-tool.docs.potenfyr.in/docs/extractor) and
> the [security model](https://hbs-tool.docs.potenfyr.in/docs/security-model).
> This README mirrors the same content.

## Table of contents

1. [Architecture](#architecture)
2. [Platform support](#platform-support)
3. [Getting started](#getting-started)
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

**Extractor** (scan agent, ships per target host):

| Target | Arch | Status |
|---|---|---|
| `x86_64-unknown-linux-musl` | amd64 Linux | Required (fully static musl) |
| `aarch64-unknown-linux-musl` | arm64 Linux | Required |
| `x86_64-pc-windows-msvc` | amd64 Windows | Required (static CRT for containers) |
| `aarch64-pc-windows-msvc` | arm64 Windows | Stretch |
| `armv7-unknown-linux-musleabihf` | 32-bit armv7 Linux | Stretch |

**Console** (dashboard engine + desktop app, ships per dashboard host - zero
runtime prerequisites on every one of them):

| Component | Platforms |
|---|---|
| `hbs-server` engine | linux x64 + arm64 (glibc and musl), macOS Intel + Apple Silicon, Windows x64 (arm64 under emulation) |
| HBS Console desktop app | Windows x64 (NSIS/MSI), Linux x64 + arm64 (deb/rpm, AppImage on x64), macOS universal `.dmg` (Intel + Apple Silicon) |

- **Linux families:** Debian/Ubuntu, RHEL/CentOS/Rocky/Alma, SUSE, Arch, Alpine,
  Amazon Linux - kernel ≥ 3.10. Tested across 13 distro versions.
- **Windows:** 10/11 and Server 2016–2025. Tested on Windows 11 natively and
  Server Core LTSC 2019/2022/2025 in containers.
- **Environments:** bare metal, VM, container, and WSL are detected; controls
  that cannot exist in a container (Secure Boot, TPM, bootloader, kernel
  modules, host firewall, separate-partition layout) report `NotApplicable`
  with a reason instead of failing.
- Other OSes (BSD, Solaris/AIX) are not targeted for the console; the
  extractor's musl builds cover most exotic Linux targets.

---

## Getting started

Everything below uses the web console. A normal user only needs the two install
commands, a browser, and the extractor binary the dashboard hands them. No
command-line knowledge is required beyond copy-paste.

### 1. Install and open the dashboard

The dashboard runs on the machine you manage scans from (your workstation or a
server). It stores all data locally; nothing leaves your network.

**Zero prerequisites.** The console engine ships as a single prebuilt native
binary per OS and architecture - you do not need Bun, Node, Rust, a compiler
or admin rights. The installer downloads the right asset from the project's
GitHub releases, verifies its SHA-256 checksum, and wires everything in:
Start-menu entry, desktop shortcut, tray icon, launch-at-login.

```bash
# Linux / macOS - interactive setup wizard (arrow keys), or pipe it in CI
curl -fsSL https://raw.githubusercontent.com/PotenFYR-Studios/HBS-Tool/main/scripts/install.sh | bash

# Windows (PowerShell) - the same wizard
irm https://raw.githubusercontent.com/PotenFYR-Studios/HBS-Tool/main/scripts/install.ps1 | iex
```

The wizard asks **what to install** first (arrow keys / number keys, Enter
accepts the suggestion):

1. **Full install** (recommended) - console engine + tray + shortcuts + the
   HBS Console desktop app.
2. **Dashboard only** - the web console + tray; no desktop app.
3. **Desktop app only** - the native app plus its engine; the app owns the
   tray and shortcuts.

Every question also has a flag (`--mode full|dashboard|desktop` /
`-Mode`), so the same installer runs unattended with `-y` / `-Yes`.

Both scripts print the console address when done. By default it is:

- **http://127.0.0.1:3000** on the machine running the dashboard. To reach it
  from your laptop instead of the server console, start it with `--host` (or
  set `HOST`) and open `http://<dashboard-ip>:3000` from any browser on the
  same network. Add TLS with `--tls-cert` / `--tls-key` for anything beyond
  your LAN.

**First sign-in:** nothing is pre-created - no generated password to copy. Open
the console and its first-run wizard (Welcome → Administrator → Finish) asks you
to choose the superuser username and password, then signs you in. That account
can invite `auditor` and `viewer` users; you never need the terminal again. The
desktop app shows the same wizard, and opens it automatically on a fresh
install. Unattended installs can create the account from the environment
instead: `HBS_BOOTSTRAP_ADMIN=true` with `HBS_ADMIN_USERNAME` /
`HBS_ADMIN_PASSWORD`.

#### What the installer asks

Interactive runs show a short wizard (Enter accepts the suggested value) and
every answer has a flag, so unattended installs stay possible:

| Question | Default | Flags (sh / ps1) |
|---|---|---|
| What to install (full / dashboard / desktop app) | full | `--mode` / `-Mode` |
| Install location | `~/.hbs` / `%LOCALAPPDATA%\HBS` | `--dir` / `-InstallDir` |
| Dashboard port | `3000` | `--port` / `-Port` |
| Create a desktop shortcut | yes (except desktop mode) | `--desktop-icon` / `--no-desktop-icon` |
| Start HBS automatically at login | yes | `--autostart` / `--no-autostart` |
| Install the tray icon | yes (except desktop mode) | `--tray` / `--no-tray` |
| Install the HBS Console desktop app | yes (except dashboard mode) | `--desktop-app` / `--no-desktop-app` |
| Start it now | yes | `--no-start` / `-NoStart` |

Other useful flags: `--tag vX.Y.Z` pins a release, `--from-source` builds from
a git checkout instead (the only path that needs Bun), and `--uninstall` /
`-Uninstall` removes everything (`--purge` also deletes the data). Uninstall
from the console with `hbs uninstall`, or on Windows through
**Settings → Apps → HBS Console (dashboard)**, like any other program.

#### Desktop app & tray

Every install mode leaves HBS installed like a real application: an
application-menu / Start-menu entry, a desktop icon (asked in the wizard), a
tray icon and launch-at-login (both optional).

- **HBS Console** (Tauri 2 shell, `desktop/`) opens the dashboard in a native
  window and keeps a tray / menu-bar icon with: open console, open in browser,
  start, stop, restart, view logs, open data folder, update, launch-at-login
  and quit (with or without stopping the server).
- Closing the window keeps HBS in the tray; **Quit** leaves the server
  running, **Quit and stop server** stops it.
- It ships as a real installer per platform: NSIS/MSI on Windows, `.deb`,
  `.rpm` and `.AppImage` on Linux (x64 and arm64), and one universal `.dmg`
  for both Intel and Apple Silicon Macs - all published as release assets by
  the `release` workflow.
- No Electron: ~10 MB, uses the OS webview, and the same dashboard is still
  reachable at `http://127.0.0.1:3000` from any browser on the machine.
- Install it later any time with `hbs install-app`.

Dashboard-only mode still gets a tray (Windows: a native PowerShell tray,
Linux: `yad` based, macOS: `hbs app` + the menu-bar helper) and the same
`hbs start|stop|restart|logs` controls.

Prefer not to install anything yet? From a source clone:

```bash
cd dashboard
bun install
bun run build                 # emits dist/ (the API server serves the SPA too)
bun server/index.ts           # http://127.0.0.1:3000
```

### 2. Create a campaign and generate an extractor

Think of it as three levels: **Campaign** (the review, e.g. "Acme Q3") →
**Location** (a site, e.g. "DC-East") → **Issuance** (one extractor binary,
locked to that campaign/location and expiring on its own).

1. Sign in and open **Campaigns**.
2. Click **New campaign**, give it a name, and add your first location.
3. Open the campaign, go to **Locations & Hosts**, and click
   **Generate extractor**.
4. Pick the platform of the machines you will scan (`linux-amd64` or
   `windows-amd64` cover most fleets) and download the file. The dashboard
   locks the binary to this issuance automatically: it carries its own
   encryption key, so reports can only be opened by this dashboard.

The same steps are available via the REST API if you want automation:

```bash
POST /api/campaigns                         { "name":"Acme Q3", "locations":[{"name":"DC-East"}] }
POST /api/campaigns/:id/locations/:loc/issuances   { "platform":"linux-amd64" }
GET  /api/issuances/:id/download?token=<downloadToken>
```

### 3. Scan a server (offline, read-only)

Copy the downloaded extractor to the target server any way you already use
(SCP, USB stick, network share). Then run it there:

```bash
# Linux (amd64), unprivileged; report lands beside the binary
./hbs-extractor --no-elevate --quiet

# Windows (PowerShell/cmd)
hbs-extractor.exe --no-elevate --quiet
```

That's the whole scan: strictly read-only, no internet access, and exactly one
file written (`hbs-report-*.hbs`). On Windows you can also just double-click
the `.exe`: it runs the scan in a console window and waits at the end so you
can read the summary. Admin-only checks are skipped unless you run
`hbs-extractor.exe --elevate` from a terminal and accept the one UAC prompt
(declining is safe: those checks degrade gracefully).

### 4. Get the report into the dashboard

Pick whichever fits your network rules:

- **Manual upload (default):** copy the `.hbs` file back, then in the console
  open **Campaigns → your campaign → Locations & Hosts** and drag the file
  into the drop zone. Batch uploads (up to 32 files) are supported.
- **Direct push (optional):** let the extractor deliver it itself. This is the
  only situation in which the extractor touches the network. Copy the push
  token from the issuance page in the console, then:

  ```bash
  HBS_PUSH_TOKEN=<token-from-console> ./hbs-extractor \
    --no-elevate --quiet --push https://<dashboard-host>:3000/api/ingest
  ```

The host appears in the dashboard immediately (live notification, no refresh
needed). Campaign and location are derived from the issuance, so nothing needs
to be typed or matched by hand. Scanning the same server again auto-resolves
findings that now pass.

### 5. Read the results

Where to look, by role:

| You are... | Open... | You get... |
|---|---|---|
| Management | **Executive Summary** | One-page risk overview, plain-language narrative, print/PDF for the board |
| Sysadmin | **Remediation** | Every failing check grouped into fix actions with copyable commands |
| Analyst | **Findings** | Filter/pivot by host or check, open evidence, diff hosts against each other |
| Auditor | **Standards** | CIS / NIST 800-53 / ISO 27001 / PCI-DSS coverage matrix, **Treatment** board for accepted risks |

Every page supports light/dark theme, CSV/Excel/PDF/Word export, and the
`Ctrl/⌘-K` command palette for jumping anywhere. Full details for each page:
[Dashboard reference](#dashboard-reference).

### 6. Keeping it running

The installers register a background service (systemd user unit on Linux,
LaunchAgent on macOS, tray icon + startup shortcut on Windows), so the console
comes back after reboot. To update later: `hbs update` (downloads the latest
release in place) or re-run the same install command - all data is kept.
Uninstall with `--uninstall` (`--purge` to also wipe data). Manual start/stop:
`hbs start`, `hbs stop`, `hbs status` (Linux/macOS) or the tray icon menu
(Windows).

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
  A **network push failure does not fail the scan** - the local report is kept
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

- No account is created for you: the console opens its first-run wizard
  (Welcome → Administrator → Finish) where you choose the superuser username and
  password. The desktop app opens the same wizard on a fresh install.
  - Unattended installs: `HBS_BOOTSTRAP_ADMIN=true` creates a `super_admin` from
    `HBS_ADMIN_USERNAME` / `HBS_ADMIN_PASSWORD` (otherwise a random 20-char
    password) and prints it once in the CLI.
- Roles: `super_admin` (all, incl. users/keys/backup/diagnostic), `auditor`
  (campaigns, issuances, ingest, treatment, exports), `viewer` (read-only).

### Hosting & configuration

| HTTP flag | Env | Meaning |
|---|---|---|
| `--host` | `HOST` | Bare `--host` binds **all interfaces** (`0.0.0.0`) and prints reachable URLs; `--host <addr>` binds one; default `127.0.0.1` |
| `--port <n>` | `PORT` | Listen port (default `3000`) |
| `--tls-cert <p>` / `--tls-key <p>` | `HBS_TLS_CERT` / `HBS_TLS_KEY` | Enable TLS (fingerprint printed at startup) |
| `--help` | - | Usage |
| - | `HBS_DB_PATH` | SQLite path (default `server/data/hbs.sqlite`) |
| - | `HBS_DATA_ROOT` | Keys/artifacts root (default `server/data`) |

CLI flags take precedence over env. Binding to a non-loopback address prints the
interface URLs and a warning when TLS is not configured.

### Workflow

1. **Campaign + location** (creation can include the first location atomically).
2. **Issuance** - a unique random `extractor_id` and independent X25519 keypair;
   the dashboard patches the binary and stores the immutable artifact + SHA-256.
3. **Download** - token or session authenticated; streams the exact stored bytes
   and verifies the hash. Revoked/expired issuances are refused.
4. **Scan** - air-gapped by default, or `--push`.
5. **Ingest** - unified pipeline: bounds → issuance resolution → token auth →
   AEAD decrypt + bounded decompress → schema/identity cross-binding →
   dedupe `(extractor_id, scan_id)` → server-authoritative metrics → one
   transaction → SSE `report-arrived`.
6. **Triage** - treatment workflow with audit history; owners, due dates,
   justifications.
7. **Export** - Excel, CSV, PDF (executive + technical), Word, diagnostic bundle.

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

- `results[]` - status, severity, evidence, location, repro, impact,
  recommendation, references, `fallbackLog`, `evidenceBlocks`, `runContext`.
- `selfAudit.attempts[]` - every file read / command / registry / API query with
  `kind`, redacted `source`, `status` (`ok|missing|denied|timeout|rejected|
  nonzero|malformed|cached|error`), `exitCode`, `bytes`, `durationMs`,
  `cached`, and `evidenceRef` linking a finding to the log line that produced it.
- `diagnostics` - environment/hypervisor, catalog fingerprint, privilege, peak
  RSS, phase durations, `missingData` (per degraded/NA/error check with
  exhausted sources), metadata attempts, and a bounded human-readable `log`.

All strings are redacted and size-bounded before sealing.

---

## Testcase catalog

**368 testcases** - Linux `LIN-*` (165), Windows `WIN-*` (153), and shared
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
  - Linux: `ubuntu-22.04`, `ubuntu-24.04` - build, tests, sealed smoke scan, artifacts.
  - Windows: `windows-2022`, `windows-2025` (+ `windows-2019`, `windows-11-arm` tolerated) - build, tests, sealed scan.
  - Dashboard: `bun test`, `tsc`, `vite build`.
- **`.github/workflows/release.yml`** (runs only after `validate` succeeds on main)
  - Builds all targets + the dashboard bundle, emits `SHA256SUMS` and `manifest.json`.
  - Publishes a release tagged `v<version>` from `extractor/Cargo.toml`:
    - **new version** → creates the release with the changelog (commits since the previous tag);
    - **same version** → overwrites the assets and **appends** the new changelog to the existing notes.
- **`.github/workflows/docs-pages.yml`** - builds `docs/` and publishes it to
  GitHub Pages at **[hbs-tool.docs.potenfyr.in](https://hbs-tool.docs.potenfyr.in)**.

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
while still executable, so its logic remains reverse-engineerable even though
release builds are stripped. HBS deliberately ships no packer and no string
obfuscation: that keeps endpoint security products from scoring the binary as
malicious, and it costs nothing because the logic is public anyway.

### Hardening you can rely on

- **Credential storage** - passwords are Argon2id hashes (64 MiB, 3 passes,
  per-hash random salt) peppered with a secret kept outside the database, so a
  leaked database alone verifies and cracks nothing. Session tokens are stored
  hashed; cookies are `HttpOnly`, `SameSite=Lax`, `Secure` under TLS.
  See [SECURITY.md](SECURITY.md#credential-storage).
- **First-run setup** - no account and no password is generated or printed for
  you. The console's setup wizard creates the first administrator, and the same
  password policy is enforced server-side. Unattended installs opt in
  explicitly with `HBS_BOOTSTRAP_ADMIN=true`.
- **Endpoint security** - read-only scans, no admin rights, no injection, no
  credential or LSASS access, no packet capture, no kernel components, no
  obfuscation, no silent updates. Allowlisting recipes for Defender, Defender
  for Endpoint, CrowdStrike, SentinelOne, Cortex XDR, Sophos, Gatekeeper and
  SELinux/AppArmor are in
  [docs/security/edr-compatibility.md](docs/security/edr-compatibility.md).
- **Browser hardening** - strict Content-Security-Policy (the single inline
  theme-guard script is allowed by hash), `no-store` on every API response,
  cross-origin write rejection, and login rate limiting.

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

**`extractor expired` (exit 2).** The issuance passed its expiry - create a new
issuance.

**Push fails but the scan succeeded.** The local report is kept; upload it
manually. Tokens come only from `HBS_PUSH_TOKEN` or `--push-token-file`.

**No tray icon on Linux.** The tray helper needs `yad` (`sudo apt install yad`)
and a notification-area aware desktop (GNOME needs the AppIndicator extension,
KDE, XFCE and Cinnamon work out of the box). The optional desktop app ships its
own tray and needs no `yad`.

**`hbs app` opens the browser instead of the desktop app.** The Tauri bundle
was not installed (it is optional). `install-desktop.sh` /`install-desktop.ps1`
installs it from the latest release; on machines without a bundle for that
platform use `--from-source` / `-FromSource` (needs Rust + Bun).

**macOS: "HBS Console is damaged" after installing the desktop app.** Release
builds are ad-hoc signed, not notarised: right-click the app → **Open**, or run
`xattr -dr com.apple.quarantine "/Applications/HBS Console.app"`. The
installer already does this for the `.dmg` it installs.

**How do I uninstall completely?** `hbs uninstall` (keeps your reports) or
`hbs uninstall --purge` / `hbs.ps1 uninstall -Purge` (deletes the data too).
Windows also lists **HBS Console** in **Settings → Apps**.

**A check shows `DegradedPartial`.** Every fallback was unavailable/denied. The
report's `missingData` lists the exhausted sources - that is expected on hosts
missing a tool or in containers where a control cannot exist (which instead
reports `NotApplicable`).

**Where is the report?** Next to the extractor binary unless `--out` is given.

**Windows containers.** Docker Desktop must be a machine-wide install with the
`Containers`/Hyper-V features enabled; then
`DockerCli.exe -SwitchWindowsEngine`. `nanoserver` is too minimal - use
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
desktop/             HBS Console desktop app (Tauri 2 shell: tray, window, icons)
fixtures/            Cross-language crypto/keyslot vectors
scripts/             Build + validation harnesses, and the installers:
  install.sh|ps1       interactive setup wizard (service, tray, shortcuts, uninstall)
  install-desktop.*    optional Tauri desktop app (release bundle or from source)
  uninstall.ps1        standalone Windows uninstaller (Settings > Apps entry)
  hbs|hbs.ps1          control CLI: start|stop|restart|status|logs|open|app|tray|autostart|update|uninstall
  tray-windows.ps1 / tray-linux.sh / tray-macos.sh
docs/                Documentation site (GitHub Pages, hbs-tool.docs.potenfyr.in)
.github/workflows/   validate.yml, release.yml (incl. desktop bundles), docs-pages.yml
```

## Docs & links

- [Documentation site](https://hbs-tool.docs.potenfyr.in) (this repo's `docs/`, deployed via GitHub Pages)
- [Releases](https://github.com/PotenFYR-Studios/HBS-Tool/releases) - installers, extractor binaries, `SHA256SUMS`, `manifest.json`
- [Issues](https://github.com/PotenFYR-Studios/HBS-Tool/issues)
- [License](LICENSE) - Apache-2.0 with the Commons Clause · [Notice](NOTICE.md)
- [PotenFYR Studios](https://github.com/PotenFYR-Studios) | [Website](https://potenfyr.in) | [Discord](https://discord.com/invite/zUaN2FPBec)

## License

Licensed under the **Apache License 2.0 with the Commons Clause**: free to fork, modify, use, and build around; not to be sold as a product. See [LICENSE](LICENSE); the LICENSE file is authoritative. Referenced standards (CIS, NIST 800-53, ISO 27001, PCI-DSS) and all product names are the property of their respective owners; see [NOTICE.md](NOTICE.md).

## Contributing

PRs welcome; see [CONTRIBUTING.md](CONTRIBUTING.md) for setup, commands and conventions.
Found a vulnerability? Please report privately: see [SECURITY.md](SECURITY.md).

<a href="https://github.com/PotenFYR-Studios/HBS-Tool/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=PotenFYR-Studios/HBS-Tool" alt="hbs-tool contributors" />
</a>
<a href="https://github.com/PotenFYR-Studios/HBS-Tool/stargazers">
  <img src="https://img.shields.io/github/stars/PotenFYR-Studios/HBS-Tool?style=social&label=Stars" alt="Live star count" />
</a>
<a href="https://github.com/PotenFYR-Studios/HBS-Tool/network/members">
  <img src="https://img.shields.io/github/forks/PotenFYR-Studios/HBS-Tool?style=social&label=Forks" alt="Live fork count" />
</a>

---

## ⭐ Star History

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=potenfyr-studios/authcore,potenfyr-studios/statfyr,potenfyr-studios/discord-botlists,potenfyr-studios/shell-eggs,potenfyr-studios/prog-language-eggs,potenfyr-studios/minecraft-eggs,potenfyr-studios/database-eggs,potenfyr-studios/apicordon,potenfyr-studios/ojaj,potenfyr-studios/fyrwall,potenfyr-studios/echoingdeaths,potenfyr-studios/hbs-tool&type=Date&theme=dark" />
  <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=potenfyr-studios/authcore,potenfyr-studios/statfyr,potenfyr-studios/discord-botlists,potenfyr-studios/shell-eggs,potenfyr-studios/prog-language-eggs,potenfyr-studios/minecraft-eggs,potenfyr-studios/database-eggs,potenfyr-studios/apicordon,potenfyr-studios/ojaj,potenfyr-studios/fyrwall,potenfyr-studios/echoingdeaths,potenfyr-studios/hbs-tool&type=Date" />
  <img alt="Star history chart for all PotenFYR Studios public repositories" src="https://api.star-history.com/svg?repos=potenfyr-studios/authcore,potenfyr-studios/statfyr,potenfyr-studios/discord-botlists,potenfyr-studios/shell-eggs,potenfyr-studios/prog-language-eggs,potenfyr-studios/minecraft-eggs,potenfyr-studios/database-eggs,potenfyr-studios/apicordon,potenfyr-studios/ojaj,potenfyr-studios/fyrwall,potenfyr-studios/echoingdeaths,potenfyr-studios/hbs-tool&type=Date" width="80%" />
</picture>

Every public PotenFYR Studios repository on one live chart, served by [star-history.com](https://star-history.com).

---

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/PotenFYR-Studios/FYRwall/output/github-snake-dark.svg" />
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/PotenFYR-Studios/FYRwall/output/github-snake.svg" />
  <img alt="Contribution snake animation" src="https://raw.githubusercontent.com/PotenFYR-Studios/FYRwall/output/github-snake.svg" width="100%" />
</picture>

---

<!-- markdownlint-disable -->

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:f97316,50:ec4899,100:8b5cf6&height=120&section=footer&text=Made%20with%20%E2%9D%A4%EF%B8%8F%20by%20PotenFYR%20Studios&fontSize=22&fontColor=ffffff&animation=twinkling" width="100%" alt="footer"/>

</div>

<!-- markdownlint-enable -->
