# HBS — Host Baseline Security Review Platform: Design Spec

Date: 2026-09-21
Status: Approved design, updated source of truth
Repo: `d:\Github-Repo\HBS-Work`

## 1. Purpose

Two-part configuration-security review platform for enterprise servers:

- **Extractor** (Rust): single-file, strictly read-only scanner executed on target host (Linux distros or Windows versions, amd64/arm64). Collects detailed system fingerprint, evaluates **~325 hardening testcases** (CIS benchmarks, threat-informed attack-surface layer, and shared informational inventory), and writes a **sealed report** (`.hbs` v2 envelope) decryptable only by issuing dashboard.
- **Dashboard/Processor** (Bun + Hono + Vite/React/TypeScript): creates **campaigns**, organizes locations, issues unique single-key extractors for download (UI or direct link), receives sealed reports via batch upload or optional `--push`, decrypts and verifies reports, routes hosts automatically, and presents Nessus-style findings with live filtering, diffing, treatment workflows, and deliverable exports (Excel, CSV, PDF, Word).

### Non-goals (Strict Boundaries)

- Strictly read-only: no active exploitation, no network port scanning, no remote probes, no configuration changes, no temp file exports on target (including `secedit /export`).
- No persistence, no background daemon, no scheduled service, no agent architecture: extractor runs once and terminates.
- Offline by default: zero socket, DNS, or network calls unless `--push <url>` explicitly provided by operator. Local scan and report sealing operate fully air-gapped.
- No auto-update, no cloud dependencies, no external telemetry.

## 2. Glossary

| Term | Meaning |
|---|---|
| Extractor | Standalone Rust scanner binary issued per campaign location |
| Dashboard | Bun server + React SPA run by auditing team on trusted machine |
| Campaign | Top-level audit engagement: client, scope, expiry, scan push token, download token |
| Location | Operational site/environment within campaign (e.g. "DC-East", "PCI-Zone"); soft-retirable |
| Extractor Issuance | Immutable patched binary download artifact with unique random `extractor_id` and dedicated single-use X25519 keypair |
| Machine ID | Stable host identifier collected read-only (`/etc/machine-id` on Linux, `MachineGuid` on Windows) |
| Host Locations | Mapping table allowing identical host to appear across multiple locations or campaigns over time |
| Sealed Report (`.hbs` v2) | Authenticated, encrypted report envelope (magic `HBS2`, version 2, AEAD AAD header, zstd-compressed JSON payload) |
| Keyslot | 512-byte `.rodata` slot in extractor binary patched with recipient public key, campaign/extractor IDs, and integrity checksum |
| Fallback Chain | Ordered list of alternative read-only evidence sources per testcase, executed until authoritative evidence obtained |
| Evidence Depth | Level of evidence obtained: `AuthoritativePrimary`, `AuthoritativeFallback`, or `DegradedPartial` |
| Discriminated Evidence Block | Pinpoint evidence struct (`sourceType`, `source`, `line`, `col`, `contextBefore`, `offendingValue`, `contextAfter`, file metadata, `redacted`) |
| Treatment Workflow | Vulnerability-management state tracking (`open`, `in_progress`, `mitigated`, `accepted_risk`, `false_positive`, `resolved`) |

## 3. Architecture & Monorepo Layout

Monorepo layout:

```
HBS-Work/
├── extractor/               # Cargo workspace — scanner binary & library
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs          # CLI args, two-phase privilege orchestration, runner
│       ├── cli.rs           # Terminal UX (indicatif + console, non-TTY mode)
│       ├── elevate.rs       # Least-privilege handling (UAC / elevation consent)
│       ├── metadata.rs      # System fingerprint (read-only system probes)
│       ├── engine.rs        # Testcase catalog runner, panic containment, fallback log
│       ├── model.rs         # Results, discriminated evidence blocks, report schema
│       ├── context.rs       # ScanContext (read-only caches, audit log, injectors)
│       ├── evidence.rs      # Bounded read-only file/command executors (allowlist)
│       ├── redact.rs        # Secret masking applied prior to serialization
│       ├── checks/
│       │   ├── mod.rs       # Catalog registry, outcome constructors, evidence builder
│       │   ├── linux/       # ~110 CIS testcases + ~40 threat testcases
│       │   ├── windows/     # ~110 CIS testcases + ~40 threat testcases
│       │   └── shared.rs    # ~25 shared informational inventory checks
│       ├── crypto.rs        # Envelope v2 sealing/unsealing, HKDF-SHA256, AEAD AAD
│       ├── keyslot.rs       # 512-byte keyslot parsing, strict validation, checksum
│       └── platform.rs      # Capability detection (distro family, OS, arch, nice)
├── dashboard/
│   ├── server/              # Bun + Hono backend: auth, ingest pipeline, SQLite store
│   │   ├── index.ts         # Server boot, route registration, 127.0.0.1 bind
│   │   ├── db.ts            # SQLite migrations, schema, indexes, audit log
│   │   ├── auth.ts          # Setup wizard, argon2id, sessions, rate-limiting
│   │   ├── keys.ts          # Dedicated per-issuance X25519 key management, 0600 storage
│   │   ├── patcher.ts       # Binary keyslot patcher, strict slot validation
│   │   ├── envelope.ts      # Envelope v2 decryption (AAD) + legacy v1 migration ingest
│   │   ├── ingest.ts        # Unified validateAndIngestEnvelope pipeline (push + upload)
│   │   ├── metrics.ts       # Server-authoritative risk score, coverage, aggregations
│   │   ├── sse.ts           # Server-sent events for real-time report arrival
│   │   └── exports/         # Excel, CSV, PDF, Word report generators
│   ├── src/                 # Vite + React 18 + TypeScript strict SPA
│   └── package.json
├── scripts/
│   ├── build-all.sh         # Cross-compilation matrix with 10 MB budget gate
│   └── docker-test/         # Linux distro validation matrix (root & non-root)
├── docs/                    # Design specs, implementation plans
└── README.md
```

### Capability-Based Platform Matrix

Detection uses capability probes (kernel interfaces, syscall availability, service managers, registry paths) rather than rigid OS-version string assumptions.

| Target | Architecture / OS | Distro / Version Support | Status |
|---|---|---|---|
| `x86_64-unknown-linux-musl` | amd64 Linux | Fully static musl; kernel ≥ 3.10; RHEL/CentOS 7-9, Ubuntu 16.04-24.04, Debian 9-12, Alpine 3.x, SUSE, Arch | Required |
| `aarch64-unknown-linux-musl` | arm64 Linux | Fully static musl; AWS Graviton, Ampere, Raspberry Pi 64-bit | Required |
| `x86_64-pc-windows-msvc` | amd64 Windows | Windows Server 2016, 2019, 2022, 2025; Windows 10, Windows 11 | Required |
| `aarch64-pc-windows-msvc` | arm64 Windows | Windows 11 ARM64, Windows Server on ARM | Stretch |
| `armv7-unknown-linux-musleabihf` | 32-bit armv7 Linux | Embedded / legacy Linux appliances | Stretch |

Cross-compilation runs from dev workstation using `cargo-zigbuild`. Static musl binaries have zero external glibc/musl library dependencies. Unsupported architectures exit cleanly with code 3 without altering target.

## 4. Extractor

### 4.1 CLI / Terminal UX & Push Handling

- Clean terminal output using `indicatif` and `console` (virtual terminal emulation enabled programmatically for classic conhost).
- Top banner: version, target host, OS, detected privilege level, air-gapped status.
- Streaming check progress: check ID, short title, status icon (`✓` Compliant, `✗` NonCompliant, `⚠` Degraded, `–` N/A, `!` Error), severity badge.
- Live metric footer: counts for Critical, High, Medium, Low, Info, Degraded, Errors.
- Closing summary: total duration, peak RSS (from OS getrusage/GetProcessMemoryInfo), sealed report path, push status.
- **Non-TTY mode**: when stdout is piped/redirected or `--quiet`, emits clean line-by-line machine/CI readable text without cursor movement or ANSI escapes.
- **Windows interactive run**: console opens in dedicated window and pauses on exit; suppressed via `--no-pause`.
- **Command-line flags**:
  `--list-checks`, `--only <ids>`, `--category <name>`, `--min-severity <level>`, `--out <path>`, `--push <url>`, `--push-token-file <path>`, `--no-elevate`, `--no-pause`, `--quiet`, `--elevated-child` (internal).
- **Offline by default & Push Security**:
  - Without `--push`, extractor opens zero network sockets, sends no DNS queries, and performs no HTTP operations.
  - When `--push <url>` is provided: report is first sealed and written to local disk. Local report file remains intact regardless of push outcome.
  - Network push uses bounded timeout (connect 5s, transfer 15s) and max 2 retries with exponential backoff.
  - Push authentication token must NEVER appear on command line (`argv`) or URL query parameters. Token is sourced solely from `HBS_PUSH_TOKEN` environment variable or read-only `--push-token-file <path>`. Redaction engine scrubs push token from all logs, self-audit, and report payload.

### 4.2 Least Privilege Model

The extractor adheres to strict least privilege:
1. **Always starts unprivileged**: binary executes as current user; it never prompts for elevation on startup merely because admin checks exist.
2. **Phase 1 (Unprivileged execution)**: runs all checks that are nonprivileged or fallback-capable. Records findings with full or fallback evidence depth.
3. **Elevation consent gate**:
   - If (and only if) selected checks remain that require privileged access to achieve authoritative primary evidence, AND `--no-elevate` was not supplied:
   - **Windows**: presents one explicit prompt informing user why elevation is requested, then requests single UAC elevation via `ShellExecuteW` (`runas`). Child process receives `--elevated-child` to prevent relaunch loops. If user declines or cancels UAC, scan continues unprivileged.
   - **Linux**: never invokes `sudo` or re-executes itself. If running as non-root, scan proceeds using non-root read-only fallbacks. Closing summary provides explicit operator-controlled re-run guidance (`sudo ./hbs-extractor ...`) only when privileged primary evidence remains unresolved.
4. **Graceful degradation**:
   - Denied or cancelled elevation does NOT abort scan.
   - Checks lacking permission execute alternative read-only fallbacks.
   - Checks unable to reach authoritative resolution are marked `Status::DegradedPartial` with explicit `degraded_reason` ("elevation denied/absent; primary evidence unavailable"). Never marked false pass or hard Error.
5. **Privilege auditing**: report records `privilegeRequested`, `privilegeGranted`, `privilegeRefused`, and per-check `runContext` (`user`, `uid`, `elevated`, `evidenceDepth`).

### 4.3 Engine, Fallbacks & Result Model

Testcases are immutable static structs registered into a compile-time catalog. The runner manages execution order, caches shared context (parsed `/etc/passwd`, read-only registry views), and isolates failures.

#### Ordered Fallback Requirements
Every testcase must define ordered fallback descriptors:
- **Fallback 1 (Primary)**: authoritative primary read-only source (e.g. system API, direct configuration file).
- **Fallback 2 (Secondary)**: independent read-only source (e.g. allowlisted query tool, effective runtime state query).
- **Fallback 3+ (Tertiary)**: fallback heuristic (e.g. process argument inspection, filesystem permissions inspection).
- *Single-source exception*: allowed only when platform architecture provides exactly one source (e.g. unique kernel sysctl); must document manual verification rationale in check definition.

Catalog validation verifies fallback metadata at startup. During execution:
- The runner records every attempted source and outcome in `fallback_log`.
- Execution stops as soon as authoritative evidence is achieved.
- If fallbacks disagree, the check resolves conservatively to `DegradedPartial` with conflict details in evidence.
- If all fallbacks are unavailable or denied, check returns `DegradedPartial`.
- `Status::Error` is reserved strictly for unexpected internal invariants, panics (caught via `catch_unwind`), or unparseable corrupted buffers.

#### Result Fields

| Field | Content |
|---|---|
| `id` | Stable identifier: `LIN-FS-001`, `WIN-AU-003`, `GEN-INV-001` |
| `title`, `description` | Testcase purpose and description |
| `severity` | `Critical` (10), `High` (6), `Medium` (3), `Low` (1), `Informational` (0) |
| `status` | `Compliant`, `NonCompliant`, `NotApplicable`, `Error`, `DegradedPartial` |
| `evidenceDepth` | `AuthoritativePrimary`, `AuthoritativeFallback`, `DegradedPartial` |
| `evidence` | Human-readable string summary of finding |
| `location` | Specific source path, registry key, or query identifier |
| `repro` | Exact read-only CLI or inspection command to reproduce finding |
| `impact`, `recommendation` | Technical impact explanation and exact remediation steps |
| `references` | CIS benchmark items, NIST 800-53, ISO 27001, PCI-DSS controls |
| `fallback_log` | Ordered array of `{source, outcome, depth}` |
| `evidence_blocks` | Discriminated pinpoint evidence blocks |
| `run_context` | `{user, uid, elevated}` at check execution time |
| `duration_ms` | Execution duration in milliseconds |

#### Discriminated Evidence Block Contract

Every locatable `NonCompliant` finding attaches one or more discriminated evidence blocks:

```json
{
  "sourceType": "file",
  "source": "/etc/ssh/sshd_config",
  "line": 42,
  "col": 1,
  "contextBefore": [
    "# Port 22",
    "# AddressFamily any"
  ],
  "offendingValue": "PermitRootLogin yes",
  "contextAfter": [
    "AuthorizedKeysFile .ssh/authorized_keys",
    "PasswordAuthentication yes"
  ],
  "fileMode": 420,
  "fileUid": 0,
  "fileGid": 0,
  "redacted": true
}
```

- `sourceType`: `file` | `registry` | `command` | `api`.
- `source`: exact redacted path, hive path, command string, or API symbol.
- `line` & `col`: 1-based start location. Column is computed using Unicode scalar / grapheme offsets (not naive byte slices or line-split drift). Missing source or non-file findings show ordered fallback attempts; never emit artificial line 0.
- `contextBefore`: up to 3 lines preceding offending content.
- `offendingValue`: the exact violating configuration or value line.
- `contextAfter`: up to 3 lines following offending content.
- `fileMode`, `fileUid`, `fileGid`: optional filesystem metadata (Unix permissions mode and owner IDs).
- `redacted`: boolean flag confirming all strings passed through secret redaction before report serialization.

### 4.4 Strict Read-Only Guarantee

1. Target files opened strictly `O_RDONLY`. File writes, creations, and truncations on target are blocked at compile time and runtime.
2. Allowlisted query-only commands only: all executed processes must match `COMMAND_ALLOWLIST` and restricted verb filters.
3. Prohibited tools: `secedit /export`, temporary file redirects, configuration changers, remediation commands, and active exploit probes are strictly forbidden.
4. Sole disk write: the requested sealed `.hbs` report written to `--out` (or CWD) is the single allowed write on the target host.
5. Self-audit log: every attempted file read and command request is recorded before validation/open/spawn, including denied, missing, failed, and timed-out attempts with redacted locator/arguments and outcome. Cache hits retain the original attempt record. No secret or push token may enter `self_audit`.

### 4.5 Sealed Report Envelope (`.hbs` v2)

The `.hbs` report format is upgraded from v1 to **v2** for reliable upload routing and AEAD integrity over header routing data.

#### Envelope Layout (v2)

Header length: 93 bytes (little-endian throughout):

```
Offset  Size  Field
0       4     Magic "HBS2"
4       2     format version (u16 = 2)
6       1     cipher suite (0 = X25519+HKDF-SHA256+ChaCha20-Poly1305,
                            1 = X25519+HKDF-SHA256+AES-256-GCM)
7       2     key id (u16, issuance key version)
9       16    extractor_id (16 raw bytes, uniquely identifying the issuance)
25      16    scan_id (16 random bytes)
41      32    ephemeral X25519 public key
73      12    nonce (12 random bytes)
85      8     ciphertext length (u64)
93      ..    ciphertext = AEAD(zstd(report JSON)), 16-byte Poly1305/GCM tag appended
```

#### Cryptographic Specification
- **AEAD Additional Authenticated Data (AAD)**: bytes `0..93` (entire header from magic through `ciphertext_len`) are fed as AAD into the AEAD cipher. Any tampering with `extractor_id`, `key_id`, `version`, or `scan_id` causes authentication failure and immediate rejection.
- **Key Derivation**:
  - `ikm = X25519(ephemeral_secret, recipient_pub)` (32 bytes)
  - `salt = scan_id || ephemeral_pub` (48 bytes)
  - `info = "HBS-report-v2" || suite_u8 || key_id_u16_le || extractor_id` (32 bytes)
  - `aead_key = HKDF-SHA256(ikm, salt, info)` (32 bytes)
- **Inner Identity Cross-Binding**: report JSON contains internal `extractorId`, `campaignId`, `keyId`, `machineId`, and `hostname`. At ingest, dashboard verifies inner IDs match outer header envelope and issuance records exactly.
- **Legacy v1 Migration**:
  - Dashboard retains bounded backward compatibility for v1 reports (`HBS1`, 77-byte header).
  - V1 reports route by looking up key using legacy unique `key_id`, decrypting, and matching inner `extractor_id`.
  - Dashboard never issues new v1 extractors. If legacy v1 `key_id` is ambiguous or revoked, ingest rejects.

### 4.6 Keyslot Specification & Strict Validation

Fixed 512-byte `.rodata` slot emitted via `#[used]` static, starting with magic `HBSKSLOT`.

```
Offset  Size  Field
0       8     Magic "HBSKSLOT"
8       2     slot_version (u16 = 1)
10      2     flags (u16 = 0)
12      2     key_id (u16)
14      2     reserved (u16 = 0)
16      16    campaign_id (16 bytes)
32      16    extractor_id (16 bytes, unique per issuance)
48      8     expiry_unix (u64 unix timestamp)
56      8     issued_at_unix (u64 unix timestamp)
64      32    recipient_public_key (32 raw X25519 bytes)
96      384   reserved zero pad
480     32    sha256 checksum over bytes [0..480]
```

#### Strict Slot Validation Rules
At boot, extractor scans own binary image and validates:
1. Exactly one keyslot exists. Multiple slots or absent slot causes immediate exit.
2. `slot_version == 1` and `flags == 0`.
3. Reserved fields (`14..16` and `96..480`) must be strictly zero.
4. `campaign_id` and `extractor_id` must not be nil/all-zero.
5. `recipient_public_key` must not be nil/all-zero.
6. `issued_at_unix < expiry_unix`. If `now > expiry_unix`, exit with clear expiry error.
7. `sha256(bytes[0..480]) == bytes[480..512]`. All-zero checksum indicates unpatched placeholder binary.
*Checksum is corruption detection, not security trust.*

### 4.7 Hardening Profile & Honest Security Statement

- Release build: `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, `strip = true`, `opt-level = "z"`.
- Sensitive internal strings and path constants obfuscated via compile-time XOR (`obfstr`).
- **Honest Security Statement**:
  - Sealed reports provide confidentiality and tamper-proof integrity under modern cryptography (X25519, HKDF-SHA256, ChaCha20-Poly1305 / AES-256-GCM).
  - Security depends on dashboard private-key protection, system RNG quality, endpoint integrity, and implementation correctness. Never claim 'nobody can break it'.
  - Extractor binary itself contains ONLY public encryption key; it cannot decrypt reports. Binary cannot be encrypted while executable; logic reverse engineering remains possible despite stripping and obfuscation.

### 4.8 Resource Budgets

| Metric | Budget | Enforcement Mechanism |
|---|---|---|
| RAM (peak RSS) | < 200 MB (expected 20–40 MB) | Bounded file reads (≤ 1 MB), streaming JSON serialization, single-pass buffers |
| Binary size | < 10 MB (expected 5–8 MB) | Static musl, `opt-level="z"`, LTO fat, strip, CI build-gate failure if ≥ 10 MB |
| CPU usage | < 0.5 core sustained | Sequential check execution, max 2 threads, 2–5s command timeouts, process priority lowering (`nice(10)` / `BELOW_NORMAL_PRIORITY_CLASS`) |
| Disk writes | Exactly 1 file | Sealed `.hbs` report only. Zero temporary exports, zero debug dumps |

## 5. Testcase Catalog (~325)

Structured into CIS benchmarks (~110 per OS), threat-informed modern attack patterns (~40 per OS), and shared informational inventory (~25).

### Linux CIS (~110, `LIN-*`)
- **Filesystem & Partitions (`LIN-FS-*`)**: `/tmp`, `/dev/shm`, `/var`, `/var/tmp`, `/home` mount separation and options (`nodev`, `nosuid`, `noexec`); fstab consistency; bootloader permissions (grub.cfg ≤ 0600); core dumps disabled.
- **Legacy Services (`LIN-SV-*`)**: inetd/xinetd disabled; legacy servers (telnet, rsh, tftp, talk, NIS) absent; MTA not listening externally.
- **Network Parameters (`LIN-NET-*`)**: sysctl parameters: `ip_forward=0`, `icmp_echo_ignore_broadcasts=1`, `rp_filter=1`, `accept_source_route=0`, `accept_redirects=0`, `log_martians=1`, `tcp_syncookies=1`, IPv6 equivalents.
- **Firewall (`LIN-FW-*`)**: active status and default-deny policies for firewalld, ufw, nftables, or iptables.
- **Logging & Auditing (`LIN-LOG-*`, `LIN-AU-*`)**: rsyslog/journald configuration, remote log forwarding, logfile permissions (≤ 0640), auditd daemon rules (identity changes, login events, system calls, immutable flag).
- **SSH Hardening (`LIN-SSH-*`)**: `sshd_config` checks: `PermitRootLogin no/prohibit-password`, strong ciphers/MACs/KEX, `MaxAuthTries ≤ 4`, `ClientAliveInterval ≤ 900`, `X11Forwarding no`.
- **PAM & Passwords (`LIN-PAM-*`)**: `pwquality.conf` (minlen ≥ 14, complexity), `pam_faillock` lockout, `pam_pwhistory`, password age limits in `/etc/login.defs`, SHA-512 hashing, sudo timeout ≤ 15m.
- **Users & Permissions (`LIN-USER-*`)**: permissions on `/etc/passwd`, `/etc/shadow`, `/etc/group`; UID 0 uniqueness; default umask 027; cron permissions; home directory permissions.

### Linux Threat-Informed (~40, `LIN-TH-*`)
- **Kernel Attack Surface**: unprivileged eBPF disabled (`unprivileged_bpf_disabled=1`), unprivileged user namespace restrictions (`kernel.unprivileged_userns_clone=0` or AppArmor restrict), `io_uring_disabled ≥ 1`, `kptr_restrict=2`, `dmesg_restrict=1`, `yama.ptrace_scope ≥ 1`, kernel module signature enforcement, Secure Boot lockdown mode.
- **Persistence Hunting**: empty/absent `ld.so.preload`; unowned systemd units with temp-dir `ExecStart`; suspicious udev rules; cron entries targeting `/tmp` or `/dev/shm`; root `authorized_keys` anomalies; PAM module tampering; unowned SUID/SGID binaries; `NOPASSWD: ALL` sudo grants; OpenSSH CVE currency; xz/liblzma provenance check.
- **Containers & Supply Chain**: docker group memberships; container socket permissions (`docker.sock`); privileged daemon flags; `hidepid` on `/proc`; EOL distribution detection; package integrity spot-checks (`rpm -V`, `debsums`).

### Windows CIS (~110, `WIN-*`)
- **Account Policies (`WIN-ACC-*`)**: evaluated strictly via read-only APIs (`NetUserModalsGet`), `net accounts` query, and policy registry: min password length ≥ 14, max password age ≤ 365, lockout threshold ≤ 50, lockout duration ≥ 15, blank password restriction (`LimitBlankPasswordUse=1`), anonymous restrictions (`RestrictAnonymous=1`).
- **Audit Policies (`WIN-AU-*`)**: evaluated strictly via `auditpol /get /category:* /r` CSV queries mapping subcategory GUIDs: Logon/Logoff, Account Logon, Account Management, Policy Change, Privilege Use, Process Tracking, Object Access. Never uses `secedit /export`.
- **Security Options (`WIN-SEC-*`)**: registry evaluations: LANMAN level (`LmCompatibilityLevel ≥ 5`), SMB signing required, UAC sliders (`EnableLUA=1`, `ConsentPromptBehaviorAdmin ≥ 2`), idle session lock, clear pagefile on shutdown, legal notice text.
- **User Rights (`WIN-UR-*`)**: evaluated strictly via Windows LSA policy APIs (`LsaOpenPolicy` + `LsaEnumerateAccountsWithUserRight`), resolving SIDs read-only: `SeDebugPrivilege`, `SeTcbPrivilege`, `SeAssignPrimaryToken`, `SeNetworkLogonRight`, `SeRemoteShutdown`. Never uses `secedit /export`.
- **Event Logs & Services (`WIN-EVT-*`, `WIN-SVC-*`)**: `wevtutil gl` log sizes (≥ 32 MB), retention, access ACLs; services disabled: Telnet, TFTP, RemoteRegistry, PrintSpooler (PrintNightmare hardening), SMBv1.
- **Defender & Network (`WIN-DEF-*`, `WIN-NET-*`)**: Defender AV real-time protection, signature currency, ASR rule configuration, Windows Firewall profiles enabled with default inbound deny, RDP NLA (`UserAuthentication=1`), SMBv1 disabled, LDAP signing.

### Windows Threat-Informed (~40, `WIN-TH-*`)
- **Credential Protection**: LSA protection (`RunAsPPL=1`), Credential Guard / VBS active, HVCI memory integrity, Microsoft vulnerable-driver blocklist active, `WDigest` disabled (`UseLogonCredential=0`), `AutoAdminLogon=0`, stored credentials sweep (`cmdkey /list`).
- **Ransomware & Persistence Hunting**: ASR rules (WMI persistence, LSASS credential theft, ransomware behaviors); Controlled Folder Access; Tamper Protection; RUN keys & IFEO debugger hijacks; scheduled tasks with user-writable actions; WMI permanent event subscriptions (`CommandLineEventConsumer`); hosts-file redirection anomalies; NETSH helper DLLs; OS EOL status; LAPS presence.

### Shared Informational Inventory (~25, `GEN-INV-*`)
Listening ports (`ss` / `netstat`), installed software list, user/group accounts, scheduled tasks, active shares, patch staleness, virtualization platform (`systemd-detect-virt` / WMI), time-sync source and drift (`chrony` / `w32tm`), DNS resolvers, EDR/AV agent presence, backup agent state, Secure Boot and TPM status, FIPS mode, effective firewall summary.

## 6. Dashboard Platform

### 6.1 Authentication, Access Control & Audit Trail

- **First-run initialization**: if zero users exist in SQLite DB, all HTTP requests redirect to `/setup` wizard to create initial `super_admin`. Passwords hashed with `argon2id` (`Bun.password.hash`).
- **Role Hierarchy**:
  - `super_admin`: system settings, user management, key export, retention configuration, all audit actions.
  - `auditor`: create campaigns/locations, issue extractors, ingest reports, adjust treatment states, add comments, export deliverables.
  - `viewer`: read-only access to campaigns, findings, reports, and dashboards.
- **Session Management**: secure HttpOnly cookies (`SameSite=Lax`), server-side token session tracking, per-IP and per-username rate-limiting with progressive delay.
- **Audit Logging (`audit_log`)**: append-only audit trail logging every administrative, key, issuance, and treatment action (actor, timestamp, IP, action, resource, details).

### 6.2 Campaign Hierarchy & Routing

Hierarchy: **Campaign -> Location -> Issuance -> Host/Report**

```
Campaign (e.g. "Acme Q3 Audit")
 ├── Location: "DC-East"
 │    ├── Issuance: extractor_id_A (Keypair A, x86_64 Linux) ──> Report 1 (Host X)
 │    └── Issuance: extractor_id_B (Keypair B, x86_64 Windows) ──> Report 2 (Host Y)
 └── Location: "Branch-London"
      └── Issuance: extractor_id_C (Keypair C, x86_64 Linux) ──> Report 3 (Host X)
```

1. **Dedicated Keypairs**: every issuance generates an independent X25519 keypair. The private key is saved with `0600` permissions in `server/data/keys/<issuance_id>.key`. Keys are NEVER shared between issuances. DB enforces `keys.issuance_id UNIQUE NOT NULL`.
2. **Immutable Issuance**:
   - `POST /api/campaigns/:id/locations/:loc/issuances`: generates issuance record, unique random extractor_id, dedicated X25519 keypair, patches pre-compiled template with issuance keyslot, and atomically saves immutable artifact under `server/data/binaries/<issuance_id>`. Returns issuance metadata and download URL.
   - `GET /api/issuances/:id/download`: streams stored immutable pre-patched binary artifact, verifies active/unexpired/unrevoked issuance, and increments download count. Does NOT generate a new identity or re-patch binary. (Also accessible via alias `GET /api/campaigns/:id/locations/:loc/issuances/:issuance_id/download`).
3. **Automatic Host Routing & Multi-Location Tracking**:
   - On upload or optional extractor push, dashboard derives campaign and location solely from authenticated issuance/extractor identity; it never accepts routing ownership from request fields or report JSON.
   - Host identity is keyed by normalized stable `machine_id` (`/etc/machine-id` or `MachineGuid`). Hostname is mutable display metadata: preserve hostname history, rename one machine rather than duplicating it, and keep distinct machine IDs separate even when hostnames match.
   - Upsert the machine under issuance-derived Campaign -> Location, persist host detail and testcase results, and use `host_locations` so one machine can appear at multiple locations/campaigns over time without losing history.
   - Successful ingest immediately updates that location's host inventory, summary, findings, freshness, and telemetry. Response includes resolved campaign/location/host/report links for visible UI confirmation.
   - A mixed upload batch routes each envelope independently. Unknown, revoked, or outer/inner-mismatched issuance rejects atomically and creates no orphan host/report/location mapping.
4. **Soft-Retirement & Revocation**:
   - Locations can be soft-retired (`retired_at`), hiding them from active issuance while preserving historical reports.
   - Issuance revocation marks `issuances.revoked = 1`. Ingest pipeline rejects future reports from revoked issuances, but retains private key to allow decrypting past reports. Destructive purge is a separate explicit admin action.

### 6.3 Unified Ingestion Pipeline (`validateAndIngestEnvelope`)

Both HTTP push (`POST /api/ingest`) and multipart file upload (`POST /api/reports/upload`) funnel through a single validation and ingestion engine:

```
Raw Envelope Bytes (Push or Upload)
  │
  ├── 1. Size & Header Gate: length ≥ 93, Magic "HBS2", format == 2
  ├── 2. Issuance Resolution: extract extractor_id & key_id; verify active issuance & campaign
  ├── 3. Push Token Authentication: if push, constant-time compare against campaign scan token
  ├── 4. AEAD Decryption: compute AAD (bytes 0..93), derive key via HKDF, decrypt & decompress zstd
  ├── 5. Schema & Cross-Binding Verification:
  │      - JSON schema validates
  │      - inner extractorId, campaignId, keyId match envelope & DB exactly
  │      - machineId and hostname non-empty and normalized
  │      - check IDs unique and match catalog format
  ├── 6. Deduplication & Replay Guard:
  │      - Check (extractor_id, scan_id) uniqueness in DB
  │      - If duplicate scan_id, return idempotent 200 OK without re-inserting
  ├── 7. Server-Authoritative Metrics Calculation:
  │      - Recompute Risk Score, Coverage %, Summary counts from raw results
  ├── 8. Atomic Database Transaction:
  │      - Upsert host and host_locations
  │      - Insert report row
  │      - Auto-resolve treatment states (previously NonCompliant -> now Compliant)
  │      - Record ingest_event (success, bytes, duration, arrival path)
  └── 9. Event Dispatch: emit SSE `report-arrived` to connected clients
```

#### Fixed Ingest Bounds

Reject before expensive parsing when any bound is exceeded: raw HTTP body **64 MiB**, multipart batch **32 files**, each envelope **16 MiB**, decompressed report JSON **64 MiB**, JSON nesting depth **32**, any string **1 MiB**, any array **10,000 elements**, and report results **1,000 checks**. Require exactly one raw body for push; upload accepts only file parts. Parsed ciphertext length must equal remaining bytes exactly; trailing bytes are rejected.

- **Batch Upload Isolation**: uploading multiple files processes each file in an isolated transaction. One corrupt or revoked report returns an error for that file while allowing valid reports in the batch to ingest successfully.
- **Typed Rejection & Atomicity**: every failure has a stable rejection code, writes no report/finding/host state, and records only a redacted `ingest_events` row. Duplicate `(extractor_id, scan_id)` replay returns the original report ID idempotently.
- **Ingest Audit Trail (`ingest_events`)**: logs `received_at`, arrival method (`push` vs `upload`), envelope size, processing duration, accepted/rejected status, and rejection code without evidence, decrypted findings, or credentials.

### 6.4 Metrics & Treatment Workflow

- **Server-Authoritative Risk Score (0–100, higher = safer)**:
  `score = 100 * (1 - Σ(weight_i * failed_i) / Σ(weight_i * applicable_i))`
  Weights: Critical = 10, High = 6, Medium = 3, Low = 1, Info = 0.
  Findings marked `accepted_risk` or `false_positive` are excluded from the numerator.
- **Coverage %**:
  `coverage = (decided_checks / applicable_checks) * 100`
  Checks ending in `Error` or unreached fallbacks reduce coverage; surfaced honestly.
- **Finding Treatment States**:
  `open` -> `in_progress` -> `mitigated` -> `accepted_risk` -> `false_positive` -> `resolved`.
  - State changes require user attribution and optional due dates / assignees.
  - `accepted_risk` and `false_positive` require non-empty justification text.
  - `resolved` is set automatically by ingestion when subsequent scan verifies compliance.
  - Append-only table `finding_state_history` preserves audit history of all status changes.
  - Discussion comments thread supported per finding (`comments` table).

### 6.5 Enterprise Dashboard UI

Dark auditor console built with React, Vite, Tailwind, Lucide icons, and Recharts.

#### Core Pages & Views
1. **Global Overview**: enterprise KPI stat tiles (campaign count, active hosts, open criticals, weighted risk score), risk score trend line, active campaign list.
2. **Campaign Summary**:
   - Scope Selector: toggle between `Latest Campaign State`, `Single Report`, or `Date Range`.
   - Executive View: animated risk gauge, severity donut, category compliance bars, host × category heatmap, top 10 failing checks table, automated plain-language summary sentences.
   - Technical Findings Explorer: full findings grid with filter chips and search bar.
3. **Report Detail & Enterprise Pivots**:
   - **Pivot "By Host"**: select a machine to view all evaluated testcases, severity icons, check IDs, status, and treatment chips.
   - **Pivot "By Check"**: select a check ID (`WIN-AU-003`) to view every host failing that check across the scope, with per-host evidence excerpts.
   - **Telemetry Panel**: scan duration, ingest latency, privilege level, coverage %, error/degraded counts, commands run, files read, peak RSS, arrival method.
4. **Nessus-Style Evidence Drawer**:
   - Path/source header with copy button.
   - 1-based line and column indicator.
   - Offending value line highlighted with exact 3 lines of context before and after.
   - Redaction badge verifying client-side secret scrubbing.
   - Ordered fallback attempt log.
   - Exact CLI reproduction command block.
   - Impact, remediation recommendations, and compliance references.
   - Treatment controls (state selector, assignee, due date, justification) and comments thread.
5. **Locations & Hosts**: location cards, platform download cards (SHA-256, curl/PowerShell snippets), batch report drop-zone, auto-populated host list.
6. **Host Detail**: host history, score over time, diff between scans.
7. **Diff View**: side-by-side comparison of two scans (Fixed, Regressed, Unchanged).
8. **Treatment Board**: Kanban/grid view by treatment state (`open`, `in_progress`, `mitigated`, `accepted_risk`, `resolved`).
9. **Standards & References**: mapping of findings to CIS Controls, NIST 800-53, ISO 27001, PCI-DSS.
10. **Telemetry & Freshness**: aggregate scan metrics, agent version adoption, stale scan warnings, data quality banners.
11. **Admin Workspace**: user management, per-issuance key inventory, key export, data retention settings, audit trail explorer.

#### Filter & Chart Interaction Model
- **Canonical URL & API Parameters**:
  `severity`, `category`, `status`, `treatment`, `locationId`, `hostId`, `checkId`, `reportId`, `standard`, `from`, `to`, `via`, `privilege`, `extractorVersion`, `platform`, `evidenceDepth`, `q`.
  URL query string is the single source of truth; reloads, back buttons, and shared links preserve active filter state. Visible chips with one-click clear.
- **Saved Views (`saved_views`)**: auditors can save, rename, and share specific filter combinations with personal or team visibility.
- **Exact Chart Click Matrix**:
  - Open critical KPI stat tile -> sets `status=NonCompliant&severity=Critical`.
  - Severity donut segment -> sets `status=NonCompliant&severity=<segment>`.
  - Category bar -> sets `status=NonCompliant&category=<category>`.
  - Host heatmap cell -> sets `status=NonCompliant&hostId=<host>&category=<category>`.
  - Top failing check bar -> sets `status=NonCompliant&checkId=<checkId>`.
  - Trend line node -> sets the exact `reportId=<reportId>` and matching `from=<timestamp>&to=<timestamp>` scope.
  - Remediation segment -> sets `treatment=<state>`.
  - Location, platform, arrival-route, privilege, extractor-version, or evidence-depth segment -> sets its corresponding canonical filter (`locationId`, `platform`, `via`, `privilege`, `extractorVersion`, `evidenceDepth`).
  - Keyboard accessible: Enter / Space triggers behavior identical to click.
  - Data-viz standards: every chart provides exact-value tooltip, visible keyboard focus, and linked tabular twin. KPIs are stat tiles; trends are line charts; categories are bars; host/category is a heatmap; severity is a stacked bar, or a donut only at ≤ 6 segments. No dual axes. Entity colors are stable, categorical palettes use ≤ 8 classes, and status always has icon plus label. Light/dark palettes pass accessibility checks. Refetch preserves the previous frame.

#### XSS & Hostile Input Sanitization
All report content (evidence, hostname, command output, config lines) is treated as untrusted text. The UI escapes all text content, forbids raw `dangerouslySetInnerHTML`, rejects ANSI/control characters, and permits only safe URL schemes (`https:`, `http:`).

### 6.6 Deliverable Exports

Server-side export generation producing professional deliverables:
- **Excel (`.xlsx`, via `exceljs`)**: Executive Summary sheet (KPIs, risk scores) + Findings sheet (severity color coding, autofilters, frozen headers).
- **CSV (`.csv`)**: flat tabular export of all findings, locations, machine IDs, and fallback statuses.
- **PDF (`.pdf`, via `pdfkit`)**:
  - *Executive Template*: high-level score gauge, summary tables, top findings, plain-language callouts.
  - *Technical Audit Template*: complete deliverable with per-host and per-check sections, severity badges, and remediation instructions.
- **Word (`.docx`, via `docx`)**: editable deliverable report mirroring technical PDF.
- **Diagnostic Download**: super-admin bundle containing redacted ingest logs, self-audit summaries, and error events for platform troubleshooting.

## 7. Threat Model & Security Posture

| Threat | Mitigation |
|---|---|
| Sealed report intercepted in transit / at rest | X25519 + ChaCha20-Poly1305 / AES-256-GCM AEAD encryption. Plaintext never touches network or unencrypted storage. |
| Extractor binary stolen or disassembled | Extractor holds ONLY public key (encrypt-only). Cannot decrypt past or future reports. Logic stripped and obfuscated. |
| Compromised target system attempts tampering | Extractor is read-only; records self-audit of all commands and files. Envelope header AAD prevents routing tampering. |
| Dashboard server compromised | Every issuance uses unique random X25519 keypair. Private keys stored in `0600` files. Localhost bind by default. |
| Stale extractor execution | Embedded expiry timestamp in keyslot; binary refuses to execute past expiration. |
| Ingest replay / denial of service | Max payload bounds, rate-limiting, constant-time token comparison, unique `(extractor_id, scan_id)` replay rejection. |
| Secrets leaked in reports | Extractor-side regex/entropy secret redaction masks credentials, passwords, and tokens before report encryption. |

## 8. Honest Cryptography & Capability Statement

- Sealed reports use modern, audited cryptography: X25519 Diffie-Hellman key exchange, HKDF-SHA256 key derivation, and ChaCha20-Poly1305 or AES-256-GCM AEAD encryption.
- Confidentiality and integrity hold under standard cryptographic assumptions: the dashboard's private keys must remain protected, the operating system RNG must be sound, and endpoint memory must be secure.
- We make no pseudoscientific claim of 'unbreakable' security. Binary reverse engineering cannot be made impossible on client executables; binary logic is made expensive to reverse through stripping and obfuscation, while encryption guarantees data-in-transit confidentiality.

## 9. Telemetry & Observability (Local-Only)

All telemetry is strictly local and never leaves the auditor's dashboard:
- Per-scan and aggregate scan count/rate, `received_at`, arrival method (`push` vs `upload`), envelope bytes, scan duration and ingest duration p50/p95.
- Scan metadata: peak RSS, coverage, authoritative-decided/error/degraded counts, commands/files read, privilege requested/granted/refused, and evidence-depth distribution.
- Dimensions: platform, architecture, OS, location, extractor version adoption, last seen/freshness, and configurable SLA (default stale threshold 30 days).
- Ingest events: accepted/rejected counts and stable rejection reasons with no evidence or secrets.
- Freshness/SLA and data-quality banners surface stale scans, low coverage, degraded evidence, and stale extractor versions.

## 10. Product Quality Ideas (Binding v1)

Concrete product features implemented in v1:
1. **Audit Trail (`audit_log`)**: persistent tracking of all admin actions, key operations, user logins, and treatment changes (Task 41, 42, 49, 56).
2. **Deterministic Catalog Fingerprint**: SHA-256 hash of testcase IDs, versions, and check logic embedded in report for audit reproducibility (Task 2, 11, 48).
3. **Standards Coverage Page**: matrix mapping current testcases and findings to CIS, NIST 800-53, and ISO 27001 controls (Task 49, 55).
4. **Saved Views**: custom named filter presets with personal or team scope (Task 41, 49, 54).
5. **Compare Baselines / Diff**: side-by-side visual diff of two scans on the same machine or between two distinct baselines (Task 49, 55).
6. **Stale Extractor Warning**: dashboard banner highlighting extractors nearing expiry or older versions (Task 46, 53).
7. **Data Retention Policies**: automatic purging or archiving of old scans based on retention settings (Task 41, 49, 56).
8. **Encrypted Backup & Restore**: passphrase-encrypted export of SQLite DB and private key storage (Task 43, 56).
9. **Accessibility & Table Twins**: every chart provides an accessible, focusable data table alternative (Task 54).
10. **Diagnostic Download**: downloadable archive of redacted error logs and ingest statistics (Task 49, 56).
