# Endpoint security: HBS next to EDR, XDR, antivirus and Defender

For the team that maintains the allowlists. HBS is a security tool that reads
its own host, so the interesting question is not "is it malicious" but "what
exactly does it touch, and which heuristics will fire". This page answers both,
then gives per-platform allowlisting recipes.

Everything below was taken from the code, not from intent:
`extractor/src/` (the scanner), `dashboard/` (the console) and `scripts/`
(the installers). If the code ever does more than this page claims, that is a
security bug - see [SECURITY.md](../../SECURITY.md).

## 1. What HBS is, in two sentences

`hbs-extractor` runs on a host you own, collects read-only posture evidence, and
writes **one** sealed, encrypted report file (or POSTs it to the dashboard you
configure). The dashboard is a local web console - a Bun server on `127.0.0.1`
by default, with a SQLite database - that stores and reviews those reports.

## 2. Verified behaviour (and why an engine may still flag it)

| Component | What it actually does | Detector that may fire |
|---|---|---|
| `hbs-extractor` | Spawns standard read-only system tools through one helper (`evidence.rs`): `stdin` closed, `stdout` captured, `stderr` discarded, hard timeout, `CREATE_NO_WINDOW` on Windows | "Unsigned binary spawning system utilities" (behavioural/ML) |
| `hbs-extractor` | Reads files, `/proc`, `/sys`, the Windows registry (read-only APIs) | Low risk; file-read volume can look like staging |
| `hbs-extractor` | Enumerates local accounts and services (`NetAPI`, SCM query) | "Account enumeration" heuristics |
| `hbs-extractor` | Calls `OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY)` to report whether it is elevated - it never opens another process | Usually none; it is a self-query |
| `hbs-extractor` | Writes exactly one file: the report envelope (`std::fs::write`) at the path you pass | None |
| `hbs-extractor` | Network: a single HTTPS POST of the sealed report to your dashboard URL (`push.rs`, `ureq`). No listener, no port scan, no DNS beaconing, no telemetry | "Outbound POST from a tool" - expected |
| Dashboard (`dashboard/server`) | Bun HTTP server, SQLite, files under the data root; no shell execution | None typical |
| Installer | Writes app/data files, a user service (systemd user unit `hbs` / launchd `net.hbs.dashboard`) **or** a Startup shortcut, an HKCU "Apps & features" entry, and a CLI on `PATH` | "Persistence" heuristics - see §3 |
| Tray helper (Windows) | PowerShell + WinForms notification icon | Script-based tray apps are scored higher by some engines; the desktop app replaces it |
| `hbs-console` (Tauri 2 app) | WebView2 host + tray icon; unsigned unless you sign the build | Windows SmartScreen warning on an unsigned installer |

## 3. What HBS deliberately does not do

These are design guarantees, each visible in code:

- **No process injection** - no `WriteProcessMemory`, `CreateRemoteThread`,
  `VirtualAllocEx`, hooks, or thread hijacking.
- **No credential access** - nothing reads LSASS, browser stores, keyrings, or
  DPAPI blobs. Passwords that exist are the console's own administrator hashes.
- **No packet capture** - the network review parses configuration files you
  upload; the extractor opens no raw sockets.
- **No kernel components** - no driver, no filter, no SELinux policy module.
- **No exploit code and no remote command execution** - the dashboard sends no
  commands back to hosts; ingest is one-way.
- **No self-update** - updates are explicit (`hbs update`, `git pull`, or a new
  release), never silent.
- **No elevation** - everything runs as your user. Checks that need more access
  report `degraded`, they do not try to escalate.
- **No obfuscation** - no packers, no encrypted payloads, no string obfuscation
  (an unused obfuscation crate was removed for exactly this reason). Sources are
  public; release artifacts are reproducible by the CI workflow.

Install-time footprint, for change-management records:

| What | Where | Removed by |
|---|---|---|
| Application files | `<install>\app`, `~/.hbs/app` | `hbs uninstall`, Settings > Apps |
| Data (database, reports, keys) | `<install>\data`, `~/.hbs/data` | only `--purge` / `-Purge` |
| Start-at-login | Startup shortcut (Windows) or systemd user unit / launchd agent | `hbs autostart off`, uninstall |
| Uninstall entry | `HKCU\...\Uninstall\HBSConsole` | uninstall |
| CLI on PATH | user `PATH` entry, `~/.local/bin/hbs` | uninstall |

## 4. Allowlisting

Prefer **hash indicators** over broad path exclusions, and exclude the install
dir - never a whole drive or the system directories.

### Windows Defender / Microsoft Defender for Endpoint

```powershell
# Path exclusions (run as administrator) - pin to the two directories HBS uses
Add-MpPreference -ExclusionPath "$env:LOCALAPPDATA\HBS"
Add-MpPreference -ExclusionPath "$env:LOCALAPPDATA\HBS\data"   # optional: report staging

# If you scan on demand, keep the real-time exclusion narrow and verify it:
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
```

- Intune / Defender for Endpoint: create a *custom indicator* of type
  **Allow** on the `hbs-extractor.exe` file hash (SHA-256 from
  `SHA256SUMS`), which is scoped to your tenant and audit-logged.
- ASR rules (`Block executable files from running unless they meet a prevalence,
  age, or trusted list criterion`) will flag the freshly built binary; the hash
  allowance above is the correct fix, not disabling the rule.
- SmartScreen on the optional NSIS installer: sign the bundle (`signtool`) in
  your own release pipeline, or install per-user and confirm once.

### CrowdStrike Falcon, SentinelOne, Cortex XDR, Sophos, Trellix

Create an allowlist entry keyed on the SHA-256 of `hbs-extractor.exe` /
`hbs-console` (and, if your console supports it, the publisher for signed
builds). Expect an ML "suspicious" verdict on first execution of an unsigned
build that enumerates services and spawns `netstat`; the file hash is what turns
that into a stable allowance. Report the false positive upstream as well - it
improves the vendor's model for every scanner author.

### macOS

```bash
xattr -dr com.apple.quarantine "/Applications/HBS Console.app"   # unsigned release
```

Release builds are ad-hoc signed. For fleets, notarise your own build
(`codesign` + `notarytool`) and distribute that. The extractor is a plain
command-line binary - no entitlements, no `com.apple.security.*` requests.

### Linux

The extractor needs read access to `/etc`, `/proc`, `/sys` and package metadata.
It runs unprivileged; several checks report `degraded` without `root`. No
capabilities, setuid bits, or SELinux types are required:

- SELinux: no module needed; if you confine services with `semanage`, give the
  unit `unconfined_service_t` or a policy that allows read on `/etc`, `/proc`.
- AppArmor: no profile ships; a `complain` profile is enough to observe.

## 5. Verify what you are allowing

Every release publishes `SHA256SUMS` plus a `manifest.json` that lists each
artifact and its digest:

```bash
sha256sum --check SHA256SUMS
# or, per artifact
sha256sum hbs-extractor-linux-x86_64
```

Use those digests as the allowlist key, and re-key on each release. The binaries
are built by `.github/workflows/release.yml` from the tagged commit - the
workflow file is the build recipe.

## 6. Reporting a false positive or a behaviour gap

Open an issue with: the product and version of your endpoint agent, the exact
artifact (or digest) that was flagged, the verbatim detection name, and the
event telemetry if you can share it. Behaviour that contradicts §3 is a
security report - please use the private channel in
[SECURITY.md](../../SECURITY.md).
