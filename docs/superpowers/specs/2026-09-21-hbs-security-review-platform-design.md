# HBS — Host Baseline Security Review Platform: Design Spec

Date: 2026-09-21
Status: Approved design, pending implementation plan
Repo: `d:\Github-Repo\HBS-Work`

## 1. Purpose

A two-part configuration-security review platform for servers:

- **Extractor** (Rust): a single-file, read-only scanner run on the target host
  (any Linux distro or Windows version, amd64/arm64). It collects a detailed
  system fingerprint and evaluates **~325 hardening testcases** (CIS-benchmark
  based, plus a threat-informed layer covering recent attack patterns not yet
  in the standards, plus informational inventory), then writes a **sealed
  report** that only the issuing dashboard can decrypt.
- **Dashboard/Processor** (Bun + Hono + Vite/React/TypeScript): creates
  **campaigns**, issues per-campaign extractors for download (UI or direct
  link), receives sealed reports via upload or `--push`, decrypts them, and
  presents findings with severity filtering, diffing, and Excel/CSV/PDF/Word
  export.

### Non-goals

- No active exploitation, no network scanning of other hosts, no changes to
  the target system. Read-only by construction.
- No agent/daemon/persistence: the extractor runs once and exits.

## 2. Glossary

| Term | Meaning |
|---|---|
| Extractor | The Rust scanner binary issued per campaign location |
| Dashboard | Bun server + React SPA that the auditor runs |
| Campaign | One engagement: client, scope, own keypair, own scan token, expiry — unlimited hosts |
| Location | A site/environment inside a campaign (e.g. "Mumbai DC", "DR site"); extractors are issued and reports are organized per location |
| Extractor issuance | One patched binary downloaded for a location; carries a unique `extractor_id` for automatic report routing |
| Machine ID | Stable host identity collected read-only (`/etc/machine-id`, Windows `MachineGuid`) — survives hostname changes |
| Sealed report (`.hbs`) | Encrypted report envelope produced by the extractor |
| Keyslot | Fixed-size placeholder inside the extractor binary that the dashboard patches with the campaign public key + metadata |
| Fallback chain | Ordered alternative evidence sources per testcase; walked until one yields evidence |

## 3. Architecture

Monorepo:

```
HBS-Work/
├── extractor/               # Cargo workspace — the scanner
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs          # CLI args, privilege handling, orchestration
│       ├── cli/             # terminal UX (progress, colors, non-TTY mode)
│       ├── metadata.rs      # system fingerprint
│       ├── engine/          # registry macro, runner, result model
│       ├── checks/
│       │   ├── linux/       # ~110 testcases, one module per CIS section
│       │   ├── windows/     # ~110 testcases, same structure
│       │   └── shared/      # ~15 informational inventory checks
│       ├── crypto.rs        # X25519 + HKDF + ChaCha20-Poly1305 envelope
│       ├── keyslot.rs       # reads its own patched slot (pubkey, campaign, expiry)
│       └── platform.rs      # arch/distro detection, read-only helpers, priority
├── dashboard/
│   ├── server/              # Bun + Hono: auth, campaigns, patcher, ingest, store, exports
│   ├── src/                 # Vite + React + TS SPA
│   └── package.json
├── scripts/
│   ├── build-all.sh         # cargo-zigbuild matrix → dashboard binaries dir
│   └── docker-test/         # Linux validation matrix
├── docs/
└── README.md
```

### Build & platform matrix

| Target | Covers | Status |
|---|---|---|
| `x86_64-unknown-linux-musl` | any Linux distro, amd64 (fully static) | required |
| `aarch64-unknown-linux-musl` | ARM64 Linux (Graviton, Ampere, Pi) | required |
| `x86_64-pc-windows-msvc` | Windows Server 2016–2025, Win 10/11 | required |
| `aarch64-pc-windows-msvc` | Windows ARM64 | stretch |
| `armv7-unknown-linux-musleabihf` | 32-bit ARM Linux | stretch |

Cross-compiled from the Windows dev machine with `cargo-zigbuild`. Static
musl ⇒ no glibc floor, no DLLs, no installer. Distro behavior differences are
handled at runtime (detection + fallback chains), never by separate builds.

## 4. Extractor

### 4.1 CLI / terminal UX

Identical experience on every OS/arch. Built with `indicatif` + `console`
(ANSI/VirtualTerminal enabled programmatically for classic conhost):

- Banner panel: version, target host, OS, detected privilege level.
- Metadata phase, then per-check streaming lines under an overall progress
  bar: check ID, short title, status icon (✓ compliant / ✗ failed / ⚠
  degraded / – N/A / ! error), severity tag for failures.
- Live counters row (Critical/High/Medium/Low/Info/Errors).
- Closing summary + sealed report path + push status if `--push` used.
- **Non-TTY mode**: when stdout is piped/redirected or `--quiet`, emit plain
  one-line-per-check text; no cursor control, CI-friendly.
- **Windows double-click**: console-subsystem binary opens its own window and
  pauses at the end when launched interactively; `--no-pause` for scripts.
- Flags: `--list-checks`, `--only <ids>`, `--category <name>`,
  `--min-severity <level>`, `--out <path>`, `--push <url>`, `--no-elevate`,
  `--no-pause`, `--quiet`. Polished `--help`.

### 4.2 Privilege model (never fails, only degrades)

- **Windows**: on start, checks token elevation via Win32
  (`OpenProcessToken` → `TokenElevation`). If not elevated and `--no-elevate`
  was not given, relaunches itself via `ShellExecuteW` with the `runas` verb
  (standard UAC prompt, no bypass); the child runs with `--elevated-child` so
  it never re-prompts. If the user declines, the scan continues
  unprivileged; checks that lost depth are marked `Degraded` with the reason.
- **Linux**: runs as a normal user; root-only evidence sources use
  non-root-visible fallbacks (`getent`, world-readable metadata, permission
  bits) and are marked degraded where applicable. `sudo` is never required
  and never invoked silently.
- Privilege level at runtime is recorded in the report.

### 4.3 Engine & result model

Every testcase is a struct registered by a macro into a compile-time catalog
(stable ordering, no runtime parsing). Runner caches shared context (parsed
`/etc/passwd`, registry snapshots, distro info) once.

Testcase definition fields:

| Field | Content |
|---|---|
| `id` | Stable, section-prefixed: `LIN-SU-014`, `WIN-AU-003`, `GEN-INV-002` |
| `title`, `description` | What the test is and does |
| `severity` | Critical / High / Medium / Low / Informational |
| `references` | CIS section + ISO 27001 / NIST 800-53 / PCI-DSS mappings where they exist |
| `category` | CIS section grouping |
| `applicability` | OS version / distro-family constraints |
| `fallbacks` | Ordered evidence sources for this check |

Per-run result fields:

| Field | Content |
|---|---|
| `status` | Compliant / NonCompliant / NotApplicable / Error / Degraded-partial |
| `evidence` | Exact values found: file excerpts, command output, parsed values |
| `location` | File path / registry key / command source |
| `repro` | Steps to reproduce the check manually |
| `impact`, `recommendation` | Why it matters; how to fix |
| `fallback_log` | Every fallback attempted, in order, with per-attempt outcome |
| `duration_ms` | Per-check timing |

Failure containment: each check runs under `catch_unwind` + `Result`; any
panic/IO error becomes an `Error` result documenting all attempts. The scan
never aborts. Path-missing and permission-denied are surfaced explicitly in
the fallback log, with what the other fallbacks showed.

### 4.4 Read-only guarantee

- All file helpers open read-only.
- External commands come from an internal allowlist of query-style commands
  (e.g. `auditpol /get:*`, `secedit /export` to stdout only, `ss -tulpn`,
  `systeminfo`); no command writes to the system.
- The only write anywhere is the sealed report (to CWD or `--out`).
- Every command executed and file read is recorded in the report's
  self-audit section (blue-team transparency).

### 4.5 Sealed report format (`.hbs` v1)

Little-endian unless noted:

```
Offset  Size  Field
0       4     Magic "HBS1"
4       2     format version (u16 = 1)
6       1     cipher suite (0 = X25519+HKDF-SHA256+ChaCha20-Poly1305,
              1 = X25519+HKDF-SHA256+AES-256-GCM)
7       2     key id (u16, campaign key version)
9       16    scan id (random)
25      32    ephemeral X25519 public key
57      12    nonce
69      8     ciphertext length (u64)
77      ..    ciphertext = AEAD(zstd-compressed JSON report), tag appended
```

- Key schedule: `ikm = X25519(ephemeral_secret, recipient_pub)`;
  `salt = scan_id || ephemeral_pub`; `info = "HBS-report-v1" || suite || key_id`;
  HKDF-SHA256 → 32-byte AEAD key.
- Nothing readable outside the ciphertext — hostnames, timestamps, everything
  is inside. The header holds only what is required to parse and decrypt.
- Crates: `x25519-dalek`, `hkdf`, `sha2`, `chacha20poly1305`, `aes-gcm`,
  `zstd`, `serde`/`serde_json`, `getrandom`.

Report JSON is schema-versioned (`schema_version` field) so new testcases
never invalidate old reports. Every report carries a self-identification
block inside the ciphertext: `extractor_id`, machine ID, hostname, FQDN,
platform/arch, scan timestamps, privilege level, extractor version,
command/file self-audit log.

### 4.6 Keyslot (binary patching)

- Fixed 512-byte slot in `.rodata`, emitted via a `#[used]` static whose
  bytes begin with magic `HBSKSLOT`; placeholder build = magic + `0xAA` fill
  + zero checksum. Referenced by code so LTO cannot strip it.
- Patched layout: magic(8) + slot version u16 + flags u16 + key id u16 +
  campaign id (16) + extractor id (16, unique per issued binary) + expiry
  (u64 unix) + issued-at (u64) + recipient public key (32) + zero pad +
  SHA-256 of all preceding bytes.
- Extractor at startup: locates its own executable, scans for the magic,
  validates the checksum. Zero checksum ⇒ "binary not issued by a dashboard"
  hard error. Expired ⇒ refuses to run with a clear message.
- Dashboard patcher (TypeScript) implements the identical layout; patched
  binary's SHA-256 is recomputed and displayed alongside the download.

### 4.7 Hardening profile

Release profile: `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`,
`strip = true`, `opt-level = "z"`. Sensitive string literals are
compile-time obfuscated (const XOR) so a `strings` dump shows nothing
meaningful. Honest limitation, restated: reports are cryptographically
unbreakable; the binary's *logic* is made expensive to reverse, not
impossible (see §8).

### 4.8 Resource budget

| Budget | Commitment | Mechanism |
|---|---|---|
| RAM | < 200 MB (expected ~20–40 MB) | bounded reads (≤ 1 MB per file), streaming serialization, no unbounded buffers |
| Binary | < 10 MB (expected ~5–8 MB) | `opt-level=z`, strip, static musl, no runtime deps |
| CPU | < 0.5 core sustained | max 2 worker threads; per-command timeout 2–5 s (killed); process self-lowers priority (`BelowNormal` on Windows, `nice(10)` on Linux) |
| Disk writes | 1 file | the sealed report only |

### 4.9 Safety properties

- 100% safe Rust except small, documented `unsafe` blocks for Win32 queries.
- All parsed input (config files, command output) is length-capped and
  schema-validated before use.
- Zero telemetry: the extractor contacts nothing unless `--push <url>` is
  explicitly given. Enforced and stated in README.

## 5. Testcase catalog (~325)

Three layers: **standards-based** (CIS core, ~110 per OS), **threat-informed**
(~40 per OS — recent attack patterns and defensive controls not yet required
by the benchmarks), and **shared informational inventory** (~25). Counts are
targets for v1; the template makes adding more trivial.

### Linux (~110, `LIN-*`)

| Section | ~Count | Examples |
|---|---|---|
| Filesystem & partitions | 15 | tmp/dev/shm mounts + nodev/nosuid/noexec, fstab options, bootloader perms, /var, /home separation |
| Legacy services & MTA | 8 | inetd/xinetd disabled, exotic services off |
| Network parameters | 20 | ip_forward, icmp redirects, SYN cookies, rp_filter, log_martians, accept_source_route, ipv6 equivalents |
| Firewall | 5 | firewalld/ufw/nftables/iptables — default-deny verification |
| Logging & auditing | 14 | rsyslog/journald config, auditd rules (identity, logins, time, perms), log file perms, logrotate |
| SSHd | 14 | root login, protocol, ciphers/MACs/Kex, MaxAuthTries, ClientAlive, banner, X11, AllowTcpForwarding |
| PAM & passwords | 14 | pwquality, pam_faillock, history, expiry, hashing algos, sudo timeout, tty tickets |
| System maintenance & users | 20 | /etc/passwd & friends perms, crontab perms, root path, home dirs, umask, default shells, SUID inventory |

### Windows (~110, `WIN-*`)

| Section | ~Count | Examples |
|---|---|---|
| Account policies | 12 | password length/age/history/complexity, lockout duration/threshold |
| Audit policy | 10 | advanced audit (logon, policy change, privilege use, object access…) via `auditpol` |
| Security options | 22 | LANMAN level, SMB signing, UAC sliders, session idle, shutdown rights, guest status, Ctrl+Alt+Del, clear pagefile |
| User rights | 16 | SeDebug, SeTcb, network/remote logon, act-as-system rights |
| Event logs | 6 | sizes, retention, access |
| Defender & updates | 10 | AV enabled/up-to-date, real-time protection, Windows Update config, last-patch age |
| Services | 20 | Telnet/TFTP/RemoteRegistry/PrintSpooler etc. states |
| Registry & FS permissions | 10 | system dir ACLs, registry ACLs on sensitive keys |
| Network hardening | ~10 | firewall profiles, RDP (NLA, encryption level), SMBv1, LDAP signing, mDNS, WPAD, LLMNR |

### Threat-informed Linux (~40, `LIN-TH-*`)

Grounded in current exploitation research: unprivileged user namespaces are
the precondition of most recent kernel LPE chains (nf_tables et al.) and
expand kernel attack surface substantially; io_uring bypasses the normal
syscall path (Google disabled it in production); the xz backdoor
(CVE-2024-3094) rewrote supply-chain expectations.

| Group | ~Count | Checks |
|---|---|---|
| Kernel attack-surface | 12 | `unprivileged_bpf_disabled`, userns restrictions (incl. Ubuntu AppArmor policy), `io_uring_disabled`, `kptr_restrict`/`dmesg_restrict` (KASLR leaks), Yama `ptrace_scope`, `perf_event_paranoid`, `modules_disabled`/kexec, BPF JIT hardening, lockdown mode + Secure Boot, module signature enforcement, protected_hardlinks/symlinks/fifos, `suid_dumpable`/core limits |
| Persistence hunting | 14 | `ld.so.preload` empty/absent; systemd units/timers not owned by any package or with temp-dir ExecStart; udev rule anomalies; rc.local/init.d strays; all five cron locations incl. at-jobs, flagging /tmp, /dev/shm, /proc targets; shell rc tampering for root/users; root `authorized_keys` presence; PAM module substitution; SUID/SGID + file-capability inventory vs package ownership; hidden/duplicate-UID accounts; `NOPASSWD: ALL` sudo grants; OpenSSH version currency (regreSSHion-class CVEs); xz/liblzma version + provenance |
| Container & escape surfaces | 5 | docker group membership; docker/containerd/podman socket perms; privileged daemon flags; `hidepid` on /proc; privileged-container detection where daemon is queryable read-only |
| EOL & currency (supply-chain) | 9 | EOL distro detection; security-patch backlog + update staleness; kernel currency vs distro latest; old/EOL service versions (OpenSSH, nginx, apache); third-party repo surface; package-integrity spot check (rpm -V/debsums, bounded); Secure Boot; signing-key trust surface informational |

### Threat-informed Windows (~40, `WIN-TH-*`)

Grounded in current ransomware tradecraft: credential theft via LSASS,
LOLBAS execution, WMI fileless persistence, vulnerable signed drivers to
bypass PPL, and the ASR rule set that addresses them.

| Group | ~Count | Checks |
|---|---|---|
| Credential protection | 7 | RunAsPPL (LSA protection) enforced; Credential Guard/VBS state; memory integrity (HVCI) + Microsoft vulnerable-driver blocklist (closes known PPL bypasses); WDigest cached logon creds; AutoAdminLogon; stored-credential inventory (cmdkey); LSA security packages tampering |
| Ransomware posture (Defender/ASR) | 7 | full ASR rule-set state with emphasis on WMI-persistence block, LSASS-theft block, vulnerable-driver block, ransomware behavior protection; Controlled Folder Access; tamper protection; engine/signature age; SmartScreen/Smart App Control; WSH/AppLocker/WDAC application-control presence |
| Persistence hunting | 10 | RUN keys + Image File Execution Options debugger hijacks; startup folders (all users); non-Microsoft/odd-path scheduled tasks; services with temp-dir or unquoted binPath; weak service ACLs; WMI permanent event subscriptions; hosts-file anomalies; inbound firewall rules to temp paths; NETSH helper DLLs; Print Spooler state (PrintNightmare-class) |
| Protocol & network abuse | 9 | NTLM restriction/audit level; RPC `RpcAuthnLevelPrivacy`; RDP NLA + restricted-admin + device redirection + minimum TLS; LDAP signing + channel binding; WPAD/LLMNR/mDNS; Schannel TLS 1.0/1.1 disabled + strong-cipher order; WinRM encryption + TrustedHosts scope; SMB encryption; IPv6 attack surface informational |
| EOL & currency | 7 | OS EOL detection (2012r2/2016-era); patch staleness + missing cumulatives; Defender platform currency; LAPS presence (classic + modern); local admin inventory; pending-reboot age; hotfix history coverage |

### Shared informational (~25, `GEN-INV-*`)

Listening ports, installed software inventory, users/groups inventory,
scheduled tasks, autoruns, open shares (Win), patch/last-update age,
virtualization detection, timezone/locale, uptime — plus: EDR/AV agent
presence, backup agent + last-success age, time-sync source & drift, DNS
resolver config, logging/forwarding agent presence, Secure Boot + TPM state,
FIPS mode, audit-subsystem coverage score, sudo/admin group inventory,
effective firewall profile, cloud-agent/cloud-init presence — context
evidence, not pass/fail.

### Research sources for the threat-informed layer

- [Microsoft — Attack surface reduction rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
- [Microsoft — Additional LSA protection (RunAsPPL)](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [itm4n — Do You Really Know About LSA Protection (RunAsPPL)?](https://itm4n.github.io/lsass-runasppl/)
- [Edera — Linux user namespaces: 262% more kernel attack surface](https://edera.dev/blog/linux-user-namespaces-262-more-kernel-attack-surface)
- [Ubuntu — AppArmor restriction of unprivileged user namespaces](https://discourse.ubuntu.com/t/apparmor-restriction-of-unprivileged-user-namespaces/29660)
- [bigiron.cc — Hunting Linux persistence: cron, systemd timers, preload tricks](https://bigiron.cc/hunting-linux-persistence/)
- [Akamai — XZ Utils backdoor (CVE-2024-3094)](https://www.akamai.com/blog/security-research/critical-linux-backdoor-xz-utils-discovered-threat-intelligence)
- [SentinelOne — CVE-2022-24122 unprivileged userns exploitation](https://www.sentinelone.com/blog/lucas-leaks-the-saga-of-a-linux-kernel-exploit-cve-2022-24122/)

## 6. Dashboard

### 6.1 Auth & user management

- **First-run wizard**: with no users in the DB, every route redirects to
  "Create super admin" (username + password). No defaults, no bypass.
  Passwords hashed with argon2id (`Bun.password`).
- **Roles**: `super_admin` (users, keys, everything), `auditor` (campaigns,
  reports, exports, annotations), `viewer` (read-only).
- **Sessions**: HttpOnly cookie, server-side session store in SQLite with
  expiry; login rate-limiting (per-IP + per-user backoff).
- **User management page** (super admin): create/deactivate users, reset
  passwords, role assignment, last-login view.
- Machine endpoints (`/api/ingest`, direct download links) use per-campaign
  tokens, entirely separate from user sessions.

### 6.2 Campaigns, locations & host routing

- **Campaign** fields: name, client/engagement, scope notes, asset tags,
  expiry date. **Unlimited hosts per campaign.**
- **Locations**: a campaign contains one or more locations (name, notes,
  tags — e.g. "Mumbai DC", "DR Pune"). Campaign creation asks for the
  name + first location; more can be added any time.
- **Every issuance gets its own unique X25519 keypair** — no key is ever
  shared between two extractors, even within the same location. Blast
  radius of any key compromise is exactly one issued binary. Each report
  records its `key_id`; the private key is retained (0600 file) so old
  reports keep decrypting; deleting/revoking an issuance deletes its key.
- The dashboard never waits on or polls for extractors: processing is
  purely event-driven — when a sealed report arrives via upload or push,
  the server looks up the `extractor_id`/`key_id`, decrypts, validates,
  computes metrics, routes it, and emits an SSE event.
- Campaigns also own a scan token (hashed at rest) for push auth and a
  download token for direct-link downloads.
- **Extractor issuance is per location**: downloading asks campaign →
  location, then platform. Every issued binary carries a unique
  `extractor_id`; the dashboard records
  `extractor_id → (campaign, location)`.
- **Automatic host routing — no manual machine names, ever**: every sealed
  report self-identifies with `extractor_id`, hostname, and a stable
  machine ID (`/etc/machine-id` on Linux, `MachineGuid` on Windows,
  collected read-only). Hosts are keyed internally by machine ID; the
  display identifier is the human-friendly composite
  **`hostname:machineid`** (first 8 chars of the machine ID) — easy to
  read and unambiguous in lists, charts, and exports. Hostname changes are
  tracked, not duplicated. On upload or push, the dashboard resolves
  `extractor_id → location`, upserts the host, and files the report. A
  single "drop anywhere" upload on the campaign page routes every file
  automatically, including mixed batches from multiple locations.
- Campaign view: location cards → per-location host list (hostname,
  platform, OS version, last scan, score) → host's reports and diffs.
- Expiry embedded in issued extractors; expired binaries refuse to run.
  Dashboard marks expired campaigns.
- Revoking an issuance (or deleting a location) blocks future reports from
  routing and retires that issuance's key.

### 6.3 Backend (Bun + Hono) API surface

```
POST   /api/auth/setup            first-run super admin creation
POST   /api/auth/login|logout
GET    /api/auth/status           {initialized, user, role}
GET/POST/PATCH/DELETE /api/users          super admin only
GET/POST /api/campaigns  ·  PATCH /api/campaigns/{id}
GET    /api/campaigns/{id}/summary       metrics rollup for Summary page
GET/POST/PATCH/DELETE /api/campaigns/{id}/locations
GET    /api/campaigns/{id}/locations/{loc}/downloads    platform cards + sha256 + links
GET    /api/campaigns/{id}/locations/{loc}/download/{platform}?t={token}   patched binary (records issuance)
DELETE /api/campaigns/{id}/issuances/{extractor_id}     revoke an issued extractor
POST   /api/ingest                X-HBS-Token; body = sealed report
POST   /api/reports/upload        multipart sealed report(s), batch OK (session
                                   auth); routed automatically by extractor_id
GET    /api/campaigns/{id}/hosts  auto-populated host inventory per location
GET    /api/reports · /api/reports/{id} · /api/reports/{id}/findings
GET    /api/reports/diff?a=…&b=…
GET    /api/campaigns/{id}/findings/treatment    treatment board (state/assignee filters)
PATCH  /api/findings/{hostId}/{checkId}/state    {state, justification?, assignedTo?, dueDate?}
GET/POST /api/findings/{hostId}/{checkId}/comments
GET    /api/export/{reportId}?format=xlsx|csv|pdf|docx
GET    /api/keys/status                per-issuance key inventory (campaign, location, created, retired)
POST   /api/keys/export                super admin, passphrase-wrapped bundle (campaign-filterable)
GET    /api/events                SSE: live report arrival
```

- Storage: SQLite (`bun:sqlite`) single file — tables include `users`,
  `sessions`, `campaigns`, `locations`, `keys` (one row per issuance,
  never shared), `issuances`
  (`extractor_id → campaign/location`, download count, revoked flag),
  `hosts` (machine ID keyed, auto-populated), `reports`,
  `finding_states` (per host+check treatment, unique on host+check),
  `comments` (per finding thread).
  Private keys as separate 0600 files in `data/keys/`, referenced by id.
- Binds 127.0.0.1 by default; `--host` to expose, optional auto-TLS with
  printed certificate fingerprint for verification. No outbound calls.

### 6.4 Metrics model (what the charts plot)

Defined once, computed server-side, stored with each report:

- **Risk score (0–100, higher = safer)**:
  `score = 100 × (1 − Σ(wᵢ × failedᵢ) / Σ(wᵢ × applicableᵢ))` over
  non-informational checks, weights Critical = 10, High = 6, Medium = 3,
  Low = 1. Findings treated as `accepted_risk` or `false_positive` are
  excluded from the numerator.

### 6.4a Finding treatment workflow (VM-style)

Findings are treated like tickets in a vulnerability-management system.
State is keyed per `(host, check_id)` and persists across re-scans of the
same machine until changed:

| State | Meaning |
|---|---|
| `open` | Default state from a failing check |
| `in_progress` | Remediation assigned/underway (assignee + due date) |
| `mitigated` | Fix claimed, awaiting verification by next scan |
| `resolved` | System-set when a re-scan shows the check Compliant (read-only; records which scan resolved it) |
| `accepted_risk` | Justified acceptance (required justification text + accepter; excluded from risk score) |
| `false_positive` | Marked not-a-finding (excluded from risk score) |

- **Comments thread** per finding: multiple comments (author, timestamp,
  markdown-plain text) — auditor discussion/evidence trail.
- State changes and comments are visible in the finding drawer, the
  technical findings table (state chips), and a campaign **Treatment**
  board (filter by state/assignee/severity; backlog → in-progress →
  resolved flow).
- Roles: `auditor`+ can change states/comment; `viewer` read-only.
- **Coverage %** = decided checks / applicable checks (Errors and
  unreachable fallbacks reduce this — surfaced honestly, never hidden).
- **Host score** = risk score of that host's latest report.
- **Campaign score** = check-weighted mean over host scores.
- **Remediation rate** = fixed / (fixed + regressed) between two
  consecutive reports for the same host (powers Diff and progress bars).
- **Trend** = per-host and campaign score over scan date.

### 6.5 Frontend (Vite + React + TS)

Dark auditor-console theme. Tailwind + shadcn-style components + Magic UI
(animated gradient panels, number-ticker KPIs, smooth page transitions).
Charts (Recharts): every chart is interactive — hover tooltips with exact
values and counts, animated transitions, and **click-through drill-down**
(donut segment → filtered findings table). Color-blind-safe palette,
consistent scales, keyboard-accessible charts, skeleton loaders, SSE-driven
live updates. A strict data-viz design checklist is applied at build time.

**App shell**: persistent sidebar (Overview, Campaigns, Reports, Admin),
breadcrumbs, `Ctrl+K` command palette for quick navigation, responsive
layout.

Pages:

1. **First-run setup** (wizard, when uninitialized)
2. **Login**
3. **Global overview** — KPI tiles (campaigns, hosts, open criticals, avg
   risk), risk trend line, campaign status table
4. **Campaign workspace** (tabbed, per campaign):
   - **Summary** — dual-view toggle:
     - *Executive*: hero animated risk gauge; severity donut (hover for
       counts/percentages, click to drill); compliance-by-category bars;
       hosts × category heat-map; score trend line; Top-10 failing checks;
       remediation progress; auto-generated plain-language callouts
       ("3 urgent actions this week"); coverage banner
     - *Technical*: full findings table with severity/category/status
       filters → detail drawer (evidence, fallback log, repro steps,
       impact, recommendation, references, accepted-risk control); raw
       JSON view
   - **Reports** — auto-updating list (SSE) when pushed reports land
   - **Report detail** — enterprise-scanner conventions (Nessus/Qualys
     pattern), including **two pivots: "By Host"** (this machine's
     findings, severity iconography, check-ID column, state chips) and
     **"By Check"** (one failing check → every affected host across the
     campaign, with host counts and per-host evidence). Finding rows carry
     the check ID (`WIN-AU-003`), severity badge, category, status, and
     first/last-seen timestamps; the detail drawer shows the full field
     set: description, evidence, fallback log, repro steps, impact,
     recommendation, standards references, plus the treatment controls:
     state dropdown, assignee, due date, justification, and the comments
     thread.
     A **telemetry panel** shows scan metadata: duration, privilege level,
     extractor version, coverage %, errors/degraded counts, counts of
     commands executed and files read, arrival path (upload vs push).
     Exec summary, risk score, severity/category filters as described
     above.
   - **Diff** — two reports side-by-side: improved/regressed per finding
   - **Locations & hosts** — location cards (create/rename at any time);
     per-location: download cards per platform (SHA-256, direct link,
     curl/PowerShell snippets), a drop-zone that accepts **batch** report
     uploads routed automatically by `extractor_id`, and the auto-populated
     host list (hostname, platform, OS version, last scan, score) — hosts
     appear as scans land, never typed in by hand
   - **Host detail** — one machine's reports over time, per-scan trend,
     diffs between its own scans
   - **Treatment board** — VM-style workflow: all findings with state
     chips (open / in-progress / mitigated / accepted / false-positive /
     resolved), filter by state, assignee, severity; bulk state changes;
     due-date overdue highlighting
5. **Presentation mode** — "Present" button on Campaign Summary: hides all
   navigation chrome, large typography, section-by-section keyboard
   stepping (←/→), screen-share friendly; the same content exports as the
   branded PDF executive template
6. **Admin: Users & Keys** — role management, key status/rotate/export

### 6.6 Exports

Server-side generation, downloaded as files:

- **Excel (exceljs)**: styled summary sheet + findings sheet(s) grouped by
  severity.
- **CSV**: flat findings table.
- **PDF (pdfkit + table plugin)**: two templates — executive summary
  (charts-as-tables, plain language, matches Presentation mode) and full
  findings with per-host and per-check sections in the enterprise-scanner
  layout (severity iconography, check-ID references, remediation
  priority ordering) — deliverable grade.
- **Word (docx)**: same structure, editable.

If any library is incompatible with Bun, the fallback is client-side
generation with identical output.

## 7. Threat model summary

| Threat | Mitigation |
|---|---|
| Sealed report interception/copy | X22519+AEAD; nothing readable, nothing forgeable |
| Extractor shared/leaked/reverse-engineered | Public key only: encrypt-only. Logic obfuscated, stripped |
| Target host compromised while scanning | Extractor holds no secret; read-only; self-audit log |
| Dashboard key theft | Unique keypair per issuance (never shared), 0600 files, revocation, localhost bind |
| Stale scanners after engagement | Embedded expiry; refuse-to-run |
| Bruteforce of dashboard | argon2id, rate limiting, no default credentials |

## 8. Honest security statement

2²⁵⁶ keyspace: a hypothetical machine testing 10¹⁸ keys/second needs on the
order of 10⁵¹ years — sealed reports are unbreakable by any real computer.
The realistic weak points are key storage and endpoint compromise, which
§7 mitigations address. The extractor binary's *logic* can only be made
expensive to reverse, never impossible. The README will state exactly this.

## 9. Testing & validation

- **Crypto vectors**: shared JSON fixtures; Rust encrypt → Bun decrypt and
  vice versa; tamper-detected (bit-flip) cases must fail.
- **Engine unit tests**: fallback chains against fixture filesystems
  (missing path, permission denied, garbage content); catch_unwind behavior.
- **Keyslot round-trip**: placeholder → patch → extractor validates.
- **Docker matrix**: `ubuntu:24.04`, `debian:12`, `alpine`, `rockylinux/ubi9`
  — root and non-root; assert exit 0, report decrypts, schema validates,
  measure peak RSS (`/usr/bin/time -v`) and binary size against budget.
- **Windows**: full runs on the dev machine, elevated and non-elevated
  (UAC decline) paths.
- **Dashboard**: Bun unit tests (auth, campaigns, patcher, ingest, exports),
  Playwright smoke for all pages, export files verified to open.
- **Resource assertions** in CI/scripts: RSS < 200 MB, size < 10 MB.

## 10. Build phases

1. Extractor core: engine, result model, keyslot, crypto, CLI/UX + crypto
   round-trip tests
2. Linux testcases + Docker validation matrix
3. Windows testcases + local validation
4. Dashboard backend: auth/user mgmt, campaigns, patcher, ingest, store,
   metrics computation
5. Dashboard frontend + Magic UI + interactive charts + SSE live view +
   Campaign Summary (executive/technical) + presentation mode
6. Exports (both PDF templates), diff view, annotations, polish
7. README + docs

## 11. Future extensions (explicitly out of v1)

macOS support, per-check remediation scripts, multi-auditor teams with
assignment workflows, scheduled re-scans via issued links, report signing
for third-party verification.
