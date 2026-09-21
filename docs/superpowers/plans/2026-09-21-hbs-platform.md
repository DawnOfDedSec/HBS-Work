# HBS Platform Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the HBS security-review platform per the approved spec: a Rust read-only extractor (Linux + Windows, amd64/arm64, ~325 testcases) that seals reports with per-issuance X25519 keys, and a Bun + Hono + React dashboard that issues extractors per campaign/location, auto-routes hosts by machine ID, and renders enterprise-grade reports with exports.

**Architecture:** Monorepo: `extractor/` (single Rust crate, lib + bin, runtime platform detection instead of per-distro builds) and `dashboard/` (Bun/Hono backend with SQLite + Vite/React/TS SPA). The two sides share two exact byte formats — the sealed-report envelope and the binary keyslot — defined once in Global Constraints and implemented identically in Rust and TypeScript. Checks are data-driven structs registered by macro into a compile-time catalog; every check has an ordered fallback chain and can never abort the scan.

**Tech Stack:** Rust (stable, static musl + MSVC targets, `x25519-dalek`, `chacha20poly1305`, `aes-gcm`, `hkdf`/`sha2`, `zstd`, `serde`, `clap`, `indicatif`, `console`, `obfstr`, `ureq`+rustls, `windows-sys`, `libc`), Bun (`hono`, `bun:sqlite`, `exceljs`, `docx`, `pdfkit`), React 18 + TypeScript strict + Vite + Tailwind, `recharts`, `framer-motion`, `cmdk`, `lucide-react`, Playwright.

**Spec:** `docs/superpowers/specs/2026-09-21-hbs-security-review-platform-design.md` — the plan argues from the spec; executors read both.

## Global Constraints

- **Read-only guarantee:** the extractor opens files read-only, runs only allowlisted query commands, and writes exactly one file (the report). Enforced in `evidence.rs`.
- **Zero telemetry:** the extractor makes no network connection unless `--push <url>` is passed.
- **Resource budgets:** binary < 10 MB per target; peak RSS < 200 MB; ≤ 2 worker threads; per-command timeout 2–5 s; process lowers own priority at start.
- **Build targets (required):** `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `x86_64-pc-windows-msvc`. Stretch: `aarch64-pc-windows-msvc`, `armv7-unknown-linux-musleabihf`.
- **Sealed envelope byte layout (v1, little-endian) — identical in Rust and TS:**
  ```
  0:  magic "HBS1" (4 bytes)
  4:  format version u16 = 1
  6:  suite u8  (0 = X25519+HKDF-SHA256+ChaCha20-Poly1305, 1 = X25519+HKDF-SHA256+AES-256-GCM)
  7:  key_id u16
  9:  scan_id (16 random bytes)
  25: ephemeral X25519 public key (32 bytes raw)
  57: nonce (12 bytes random)
  69: ciphertext length u64
  77: ciphertext = AEAD(zstd(JSON report)) with 16-byte tag appended
  ```
  Key schedule: `ikm = X25519(ephemeral_secret, recipient_pub)`; `salt = scan_id || ephemeral_pub`; `info = "HBS-report-v1" || suite_u8 || key_id_u16_le`; HKDF-SHA256 → 32-byte key.
- **Keyslot byte layout (512 bytes total, little-endian) — identical in Rust and TS:**
  ```
  0:   magic "HBSKSLOT" (8 bytes)
  8:   slot_version u16 = 1
  10:  flags u16 (0)
  12:  key_id u16
  14:  reserved u16 (0)
  16:  campaign_id (16 bytes)
  32:  extractor_id (16 bytes)
  48:  expiry_unix u64
  56:  issued_at_unix u64
  64:  recipient_pubkey (32 raw X25519 bytes)
  96:  zero pad
  480: sha256(bytes[0..480]) (32 bytes)
  ```
  Placeholder build (unissued): bytes 8..480 = `0xAA`, bytes 480..512 = zero. Issued: real values, pad zeroed, real sha256.
- **Check IDs:** `LIN-<SEC>-NNN`, `WIN-<SEC>-NNN`, `GEN-INV-NNN`. Stable forever once assigned.
- **Host identity:** machine ID = `/etc/machine-id` (Linux) or `MachineGuid` (Windows). Internal key = machine ID; display = `hostname:machineid[0..8]`.
- **Dashboard binds 127.0.0.1 by default.** Private keys stored as 0600 files in `dashboard/server/data/keys/`.
- **Risk score:** `100 * (1 - Σ(wᵢ×failedᵢ) / Σ(wᵢ×applicableᵢ))`, weights Critical=10, High=6, Medium=3, Low=1; Informational, NotApplicable and accepted-risk findings excluded; computed server-side at ingest.
- **TS strict mode everywhere; Rust `#![deny(unsafe_op_in_unsafe_fn)]`; every `unsafe` block gets a `// SAFETY:` comment.**

## Review Focus

Inputs the spec implies but tasks must pin with tests (each line's test lives in the owning task):

1. **Tampered/truncated sealed report** (bit-flip in ciphertext, header shorter than 77 bytes, wrong magic): dashboard rejects with a clear per-file error and continues processing the rest of a batch — never crashes, never files garbage. → Task 25 tests.
2. **Report from unknown or revoked `extractor_id`** (binary issued by a different dashboard, or revoked issuance): ingest refuses with explicit "unknown/revoked extractor" error, files nothing under the wrong campaign. → Task 25 tests.
3. **Duplicate hostname across locations / renamed host**: same machine ID arriving with a new hostname upserts one host record; two different machines sharing a hostname stay separate. → Task 25 tests.
4. **Future/past `schema_version`** (report newer than dashboard, or older): processed if ≤ current, explicitly rejected with a version message if newer — never mis-parsed. → Task 25 tests.
5. **Missing evidence paths on target** (no `/etc/ssh/sshd_config`, `auditpol` absent, permission denied): check returns `Error`/`Degraded` with the full fallback log; scan continues to completion; coverage % reflects it. → Tasks 6 and 16 tests.

---

## Phase 0 — Scaffolding

### Task 1: Repo scaffolding

**Files:**
- Create: `extractor/Cargo.toml`, `extractor/src/lib.rs`, `extractor/src/main.rs`, `rust-toolchain.toml`, `.gitignore`, `scripts/build-all.sh`
- Create: `dashboard/package.json`, `dashboard/tsconfig.json`, `dashboard/vite.config.ts`, `dashboard/index.html`, `dashboard/src/main.tsx` (placeholder), `dashboard/server/index.ts` (placeholder)

**Interfaces:**
- Produces: crate `hbs_extractor` (lib name `hbs_extractor`), package `dashboard` (bun). Binary name `hbs-extractor`.

- [ ] **Step 1: Create extractor crate**

`extractor/Cargo.toml`:
```toml
[package]
name = "hbs-extractor"
version = "0.1.0"
edition = "2021"

[lib]
name = "hbs_extractor"
path = "src/lib.rs"

[[bin]]
name = "hbs-extractor"
path = "src/main.rs"

[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
zstd = "0.13"
x25519-dalek = { version = "2", features = ["static_secrets"] }
hkdf = "0.12"
sha2 = "0.10"
chacha20poly1305 = "0.10"
aes-gcm = "0.10"
getrandom = "0.2"
hex = "0.4"
clap = { version = "4", features = ["derive"] }
indicatif = "0.17"
console = "0.15"
obfstr = "0.4"
anyhow = "1"
ureq = { version = "2", features = ["tls"] }
libc = "0.2"
wait-timeout = "0.2"

[target.'cfg(windows)'.dependencies]
windows-sys = { version = "0.59", features = [
  "Win32_Foundation", "Win32_Security", "Win32_System_Registry",
  "Win32_System_SystemInformation", "Win32_System_Threading",
  "Win32_UI_Shell", "Win32_System_ProcessStatus" ] }

[profile.release]
lto = "fat"
codegen-units = 1
panic = "abort"
strip = true
opt-level = "z"
```
`src/lib.rs`: `pub mod model;` etc. will grow per task; start with `pub mod placeholder;` removed later — instead an empty `pub mod nothing {}` is not needed; lib.rs can be empty until Task 2. `src/main.rs`: `fn main() { println!("hbs"); }` (replaced in Task 11).

`rust-toolchain.toml`:
```toml
[toolchain]
channel = "stable"
```

- [ ] **Step 2: Create dashboard package**

`dashboard/package.json` (deps installed over the plan; start minimal):
```json
{
  "name": "hbs-dashboard",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "bun run --cwd=. ./server/index.ts",
    "build": "vite build",
    "test": "bun test"
  }
}
```
Plus `vite.config.ts` (react plugin, proxy `/api` → `http://localhost:8787`), `tsconfig.json` with `"strict": true`, and placeholder `server/index.ts` responding `{ok:true}` on `/api/health`.

`.gitignore`: `target/`, `node_modules/`, `dist/`, `dashboard/server/data/`, `*.hbs`, `dashboard/binaries/`.

- [ ] **Step 3: Verify builds**

Run: `cd extractor && cargo build` → expected: success.
Run: `cd dashboard && bun install && bun run ./server/index.ts &` then `curl -s localhost:8787/api/health` → `{"ok":true}`. Kill it.

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "chore: scaffold extractor crate and dashboard package"
```

---

## Phase 1 — Extractor core

### Task 2: Result model

**Files:**
- Create: `extractor/src/model.rs` (declared in `lib.rs`)
- Test: `extractor/tests/model.rs`

**Interfaces:**
- Produces (used everywhere):
  - `pub enum Severity { Critical, High, Medium, Low, Informational }` (serde snake_case, `as_str()`, `weight() -> u32` = 10/6/3/1/0)
  - `pub enum Status { Compliant, NonCompliant, NotApplicable, Error, DegradedPartial }` (serde snake_case)
  - `pub struct Testcase { pub id: &'static str, pub title: &'static str, pub description: &'static str, pub impact: &'static str, pub recommendation: &'static str, pub severity: Severity, pub category: &'static str, pub references: &'static [&'static str] }`
  - `pub struct FallbackAttempt { pub source: String, pub outcome: String }`
  - `pub struct CheckResult { pub id: String, pub title: String, pub status: Status, pub severity: Severity, pub category: String, pub description: String, pub impact: String, pub recommendation: String, pub references: Vec<String>, pub evidence: String, pub location: String, pub repro: String, pub degraded_reason: Option<String>, pub fallback_log: Vec<FallbackAttempt>, pub duration_ms: u64 }`
  - `pub struct CheckOutcome { pub status: Status, pub evidence: String, pub location: String, pub repro: String, pub recommendation_override: Option<String>, pub degraded_reason: Option<String> }`
  - `pub type CheckFn = fn(&mut crate::context::ScanContext) -> CheckOutcome;`
  - `pub struct RegisteredCheck { pub tc: Testcase, pub applies: fn(&crate::platform::PlatformInfo) -> bool, pub run: CheckFn }`
  - `pub struct SelfAudit { pub commands: Vec<String>, pub files_read: Vec<String> }`
  - `pub struct Summary { pub compliant: u32, pub non_compliant: u32, pub not_applicable: u32, pub error: u32, pub degraded: u32, pub informational: u32 }`
  - `pub struct Report { pub schema_version: u16, pub scan: serde_json::Value, pub metadata: serde_json::Value, pub results: Vec<CheckResult>, pub summary: Summary, pub self_audit: SelfAudit }`

- [ ] **Step 1: Write failing tests** — `extractor/tests/model.rs`:
```rust
use hbs_extractor::model::*;
use serde_json::json;

#[test]
fn severity_serde_roundtrip() {
    assert_eq!(serde_json::to_string(&Severity::High).unwrap(), "\"High\"");
    assert_eq!(Severity::Critical.weight(), 10);
    assert_eq!(Severity::Informational.weight(), 0);
}

#[test]
fn check_result_serializes_all_fields() {
    let r = CheckResult {
        id: "LIN-SSH-001".into(), title: "t".into(), status: Status::NonCompliant,
        severity: Severity::High, category: "SSH".into(), description: "d".into(),
        impact: "i".into(), recommendation: "r".into(), references: vec!["CIS 5.2.8".into()],
        evidence: "PermitRootLogin yes".into(), location: "/etc/ssh/sshd_config".into(),
        repro: "grep PermitRootLogin /etc/ssh/sshd_config".into(),
        degraded_reason: None, fallback_log: vec![FallbackAttempt{source:"file".into(),outcome:"ok".into()}],
        duration_ms: 3,
    };
    let v: serde_json::Value = serde_json::to_value(&r).unwrap();
    assert_eq!(v["status"], "NonCompliant");
    assert_eq!(v["fallbackLog"][0]["source"], "file");
}
```
(serde renames: `#[serde(rename_all = "camelCase")]` on CheckResult/FallbackAttempt/Report structs so report JSON is camelCase.)

- [ ] **Step 2: Run** `cargo test --test model` → FAIL (module missing).
- [ ] **Step 3: Implement `model.rs`** with exact fields above, derives `Serialize, Deserialize, Clone, Debug` where needed, `PartialEq, Eq` on enums.
- [ ] **Step 4: Run** `cargo test --test model` → PASS.
- [ ] **Step 5: Commit** `git commit -m "feat(extractor): result model with serde report shapes"`

### Task 3: Evidence helpers (read-only enforcement)

**Files:**
- Create: `extractor/src/evidence.rs`
- Test: `extractor/tests/evidence.rs`

**Interfaces:**
- Consumes: `model::SelfAudit`.
- Produces:
  - `pub const MAX_READ: usize = 1024 * 1024;`
  - `pub fn read_file_capped(path: &Path, audit: &mut SelfAudit) -> Option<String>` — opens read-only, reads ≤ 1 MB, records in audit, returns None on any error (missing/perm).
  - `pub fn read_bytes_capped(path: &Path, audit: &mut SelfAudit) -> Option<Vec<u8>>`
  - `pub const COMMAND_ALLOWLIST: &[&str]` — exact list: `uname`, `hostname`, `id`, `getent`, `systemd-detect-virt`, `ss`, `ip`, `sysctl`, `dpkg-query`, `rpm`, `apk`, `pacman`, `zypper`, `apt-get` (with `-s`/`--no-download` simulate args only, enforced by caller), `chkconfig`, `systemctl`, `timedatectl`, `localectl`, `docker` (read-only subcommands only, enforced by caller), `package`, `lsb_release`, `cat /proc` handled by file reads; Windows: `systeminfo`, `reg` (only `query`), `auditpol` (only `/get`), `secedit` (only `/export` to stdout-redirect temp under report dir? **No system writes allowed** — `secedit /export` writes a file; use `CFGFILE=CON`? It requires a path. Decision: allow `secedit /export` only with output path inside a directory we create under the report output dir, deleted immediately after read; document as the single sanctioned temp write, owned by us, outside system areas), `net`, `wmic` (query only), `sc` (only `qc`/`query`), `wevtutil` (only `gl`/`el`/`qe`), `powershell`/`pwsh` (only with `-NoProfile -NonInteractive -Command` and an internal script allowlist pattern — commands are code constants, never user input), `manage-bde` (only `-status`), `dsregcmd` (only `/status`), `cmdkey` (only `/list`), `tzutil`(`/g`), `driverquery`, `ntoskrnl` none.
  - `pub fn run_command(program: &str, args: &[&str], timeout_ms: u64, audit: &mut SelfAudit, injector: &Option<Box<dyn Fn(&str, &[&str]) -> Option<String>>>) -> Option<String>` — allowlist check (program must be listed; for `reg`/`auditpol`/`secedit`/`sc`/`wevtutil`/`docker` the caller passes validated args — helper asserts the restricted verb is present), spawn, kill on timeout via `wait_timeout`, return trimmed stdout on exit 0.
  - Timeout is enforced by `wait-timeout` crate; on Windows also `CREATE_NO_WINDOW` (0x08000000) via `CommandExt::creation_flags`.

- [ ] **Step 1: Failing tests** (`extractor/tests/evidence.rs`): create temp file of 2 MB → `read_file_capped` returns Some with len ≤ 1 MB; missing file → None; allowlisted `uname -s` (skip on windows host with `#[cfg(unix)]`) → Some; program `evil` → None and not spawned; injector stub returns canned output when set (fake runner used for all command tests on any host).
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.** `run_command` signature uses `std::process::Command`; `#[cfg(windows)] use std::os::windows::process::CommandExt;` creation_flags(0x08000000).
- [ ] **Step 4: Run** → PASS. **Step 5: Commit** `feat(extractor): capped reads and allowlisted command execution`

### Task 4: Platform detection + priority lowering

**Files:**
- Create: `extractor/src/platform.rs`
- Test: `extractor/tests/platform.rs`

**Interfaces:**
- Produces:
  - `pub enum Os { Linux, Windows }` ; `pub enum DistroFamily { Rhel, Debian, Suse, Arch, Alpine, Unknown }`
  - `pub struct PlatformInfo { pub os: Os, pub arch: String, pub kernel: String, pub distro: Option<String>, pub distro_version: Option<String>, pub family: DistroFamily, pub virtualized: Option<String> }`
  - `pub fn detect() -> PlatformInfo` — Linux: `/etc/os-release` parse (NAME, VERSION_ID, ID_LIKE→family), `uname -r` via allowlisted command, `systemd-detect-virt`; Windows: version from `windows-sys` `RtlGetVersion`, arch from env `PROCESSOR_ARCHITECTURE`; `std::env::consts::ARCH`.
  - `pub fn lower_own_priority()` — Linux: `unsafe { libc::nice(10) }` (SAFETY comment: single-threaded call, returns new nice value, ignore error); Windows: `SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS)`.

- [ ] **Step 1: Failing tests:** fixture `os-release` files for ubuntu/rocky/alpine/arch parsed by a test-visible `parse_os_release(&str) -> (Option<String>, DistroFamily)` → assert families Debian/Rhel/Alpine/Arch; `lower_own_priority()` runs without panic; on Linux assert `nice` increased via `libc::getpriority`.
- [ ] **Step 2: FAIL. Step 3: Implement** (export `parse_os_release` pub for tests). **Step 4: PASS. Step 5: Commit.**

### Task 5: ScanContext (caches, root prefix, audit)

**Files:**
- Create: `extractor/src/context.rs`
- Test: `extractor/tests/context.rs`

**Interfaces:**
- Consumes: `evidence::*`, `platform::PlatformInfo`, `model::SelfAudit`.
- Produces:
  - `pub type CmdInjector = Box<dyn Fn(&str, &[&str]) -> Option<String>>;`
  - `pub struct ScanContext { pub platform: PlatformInfo, pub elevated: bool, pub root_prefix: std::path::PathBuf, pub audit: SelfAudit, pub caches: std::collections::HashMap<String, String>, injector: Option<CmdInjector> }`
  - `impl ScanContext { pub fn new(platform: PlatformInfo, elevated: bool) -> Self; pub fn with_root_prefix(mut self, p: &str) -> Self; pub fn with_injector(mut self, f: CmdInjector) -> Self;`
  - `pub fn read(&mut self, abs_path: &str) -> Option<String>` — joins `root_prefix`, calls `read_file_capped`, caches by path.
  - `pub fn exists(&self, abs_path: &str) -> bool` (joined), `pub fn path(&self, abs_path: &str) -> PathBuf`
  - `pub fn cmd(&mut self, program: &str, args: &[&str]) -> Option<String>` — timeout 5000 ms default, routes injector in tests.
  - `pub fn unix_mode(&self, abs_path: &str) -> Option<u32>` (`#[cfg(unix)]` stat mode bits; None elsewhere) — records read in audit too.
  - `pub fn linux(&self) -> bool`, `pub fn windows(&self) -> bool`

- [ ] **Step 1: Failing tests:** temp fixture tree `fixtures/fake-root/etc/login.defs`; `ctx.read("/etc/login.defs")` with root prefix returns content; second call served from cache (assert audit.files_read has exactly 1 entry); injector returns canned `sshd -T` output via `ctx.cmd("sshd", &["-T"])`; missing path → None.
- [ ] **Step 2: FAIL. Step 3: Implement. Step 4: PASS. Step 5: Commit.**

### Task 6: Engine runner (never aborts)

**Files:**
- Create: `extractor/src/engine.rs`
- Test: `extractor/tests/engine.rs`

**Interfaces:**
- Consumes: `model::*`, `context::ScanContext`.
- Produces:
  - `pub fn run_all(registry: &[RegisteredCheck], ctx: &mut ScanContext) -> Vec<CheckResult>` — for each applicable check: measure duration, call `(check.run)(ctx)`; on panic (catch_unwind — requires `std::panic::AssertUnwindSafe(ctx)`) synthesize `Status::Error` result with fallback attempt "engine" / "check panicked". Non-applicable checks yield `Status::NotApplicable` with evidence "not applicable on this platform".
  - `pub fn summarize(results: &[CheckResult]) -> Summary`

- [ ] **Step 1: Failing tests:**
```rust
#[test]
fn panicking_check_yields_error_not_abort() {
    let mut reg = Vec::new();
    reg.push(RegisteredCheck{ tc: toy_tc("T-1"), applies: |_| true,
        run: |_ctx| panic!("boom") });
    let mut ctx = test_ctx();
    let out = engine::run_all(&reg, &mut ctx);
    assert_eq!(out.len(), 1);
    assert!(matches!(out[0].status, Status::Error));
    assert!(out[0].fallback_log.iter().any(|f| f.outcome.contains("panicked")));
}
#[test]
fn non_applicable_check_reports_not_applicable() { /* applies: |_| false */ }
#[test]
fn missing_paths_reported_as_error_with_fallback_log() { /* check reads /nope/x twice via two fallbacks; assert Status::Error and fallback_log.len()==2 with per-source outcomes */ }
```
(`panic = "abort"` in release profile does not affect dev/test builds — catch_unwind works under test profile.)
- [ ] **Step 2: FAIL. Step 3: Implement. Step 4: PASS. Step 5: Commit** `feat(extractor): engine with panic containment and fallback logging`

### Task 7: Registry macro

**Files:**
- Create: `extractor/src/registry.rs`, `extractor/src/checks/mod.rs` (exports `register_all(registry: &mut Vec<RegisteredCheck>)` calling submodules; initially only a `checks/toy.rs` used by tests, removed in Phase 2)
- Test: `extractor/tests/registry.rs`

**Interfaces:**
- Produces:
  - `#[macro_export] macro_rules! check { ($id:literal, $title:literal, $desc:literal, $impact:literal, $rec:literal, $sev:ident, $cat:literal, $refs:expr, $applies:expr, $run:expr) => { registry.push(RegisteredCheck{ tc: Testcase{ id:$id, title:$title, description:$desc, impact:$impact, recommendation:$rec, severity:Severity::$sev, category:$cat, references:$refs }, applies:$applies, run:$run }); } }`
  - `checks::register_all(&mut Vec<RegisteredCheck>)` — cfg-gated per OS at runtime (each module registers only checks whose `applies` allows).

- [ ] **Step 1: Failing test:** `register_all` on any host returns ≥ 1 check; IDs unique across whole registry (`HashSet` assert).
- [ ] **Step 2: FAIL. Step 3: Implement** toy check. **Step 4: PASS. Step 5: Commit.**

### Task 8: Crypto envelope

**Files:**
- Create: `extractor/src/crypto.rs`
- Test: `extractor/tests/crypto.rs`

**Interfaces:**
- Produces:
  - `pub fn seal(plaintext: &[u8], recipient_pub: &[u8; 32], key_id: u16, suite: u8) -> anyhow::Result<Vec<u8>>` — random ephemeral, random scan_id+nonce, zstd level 3 compression, envelope exactly per Global Constraints.
  - `pub fn unseal(envelope: &[u8], recipient_priv: &[u8; 32]) -> anyhow::Result<Vec<u8>>` (used by tests + vectors; never called by main flow)
  - `pub fn derive_key(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32]`

- [ ] **Step 1: Failing tests:** round-trip both suites (plaintext = JSON blob incl. unicode); tamper any ciphertext byte → unseal Err; truncated header (76 bytes) → Err with "header"; wrong magic → Err; deterministic `derive_key` against a fixed vector: ikm=32×0x11, salt=16×0x22||32×0x33, info=b"HBS-report-v1\x00\x00\x00" → assert hex of key equals a value pinned by computing once and hard-coding (both languages must match; Task 20 reuses it).
- [ ] **Step 2: FAIL. Step 3: Implement** using `x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret}`, `hkdf::Hkdf::<Sha2_256>`, `chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::{Aead, Payload}}`, `aes_gcm::Aes256Gcm`.
- [ ] **Step 4: PASS. Step 5: Commit** `feat(extractor): sealed envelope X25519+HKDF+AEAD`

### Task 9: Keyslot

**Files:**
- Create: `extractor/src/keyslot.rs`
- Test: `extractor/tests/keyslot.rs`

**Interfaces:**
- Produces:
  - `pub const SLOT_MAGIC: [u8; 8]; pub const SLOT_LEN: usize = 512;`
  - `pub struct SlotData { pub key_id: u16, pub campaign_id: [u8; 16], pub extractor_id: [u8; 16], pub expiry_unix: u64, pub issued_at_unix: u64, pub recipient_pub: [u8; 32] }`
  - `pub fn read_own_slot() -> anyhow::Result<SlotData>` — `std::env::current_exe()`, read whole file, find SLOT_MAGIC (scan windows, reject if not found or placeholder), `parse`.
  - `pub fn parse(buf: &[u8]) -> anyhow::Result<SlotData>` — layout per Global Constraints; reject placeholder (sha field zero); verify sha256(bytes[0..480]).
  - `pub fn placeholder_bytes() -> [u8; 512]` (test + build helper).
  - `pub fn hex_id(id: &[u8; 16]) -> String` (uuid-style formatting for extractor/campaign ids: 8-4-4-4-12).

- [ ] **Step 1: Failing tests:** build placeholder → parse Err("not issued"); craft valid slot (fixed ids, expiry = now+3600, pub 32×0xAB, sha256 computed) → parse Ok + fields match; corrupt 1 byte of pubkey → Err("checksum"); slot with expiry in past → helper `pub fn check_expiry(slot: &SlotData) -> Result<(), String>` returns Err containing "expired".
- [ ] **Step 2: FAIL. Step 3: Implement. Step 4: PASS. Step 5: Commit.**

### Task 10: Metadata collectors

**Files:**
- Create: `extractor/src/metadata.rs`
- Test: `extractor/tests/metadata.rs`

**Interfaces:**
- Consumes: `ScanContext` (with injector/fixture support so both OS collectors are unit-testable on the dev host).
- Produces: `pub fn collect(ctx: &mut ScanContext) -> serde_json::Value` — object with keys: `hostname`, `fqdn`, `machine_id`, `os_name`, `os_version`, `kernel`, `arch`, `distro`, `distro_family`, `virtualization`, `install_date`, `last_boot`, `uptime_seconds`, `timezone`, `locale`, `cpu_model`, `cpu_cores`, `memory_mb`, `disks` (array {mount,total_mb,free_mb}), `registered_owner`, `patch_level` (linux: count of installed security packages + last update date; windows: count of QFE hotfixes + newest date), `users` (array {name, uid, gid, groups, shell_or_usertype, last_logon, privileged}), `elevated` (bool). Linux sources: `/etc/hostname`, `/proc/sys/kernel/hostname`, `hostname -f` cmd, `/etc/machine-id`, `/proc/meminfo`, `/proc/cpuinfo`, `/proc/mounts`+`statvfs`, `/etc/passwd`+`getent group`, `lastlog`-light via `last -n1 <user>` skip — use `/var/log/wtmp` too heavy → omit last_logon on linux (document as N/A), `uptime` from `/proc/uptime`. Windows sources: env vars + `systeminfo` parse, registry `MachineGuid` via `reg query HKLM\SOFTWARE\Microsoft\Cryptography /v MachineGuid`, `wmic qfe`/PowerShell `Get-HotFix` fallback, `net users` + `Get-LocalGroupMember Administrators` fallbacks.
- All paths through `ctx` (so fixture/injector tests work identically).

- [ ] **Step 1: Failing tests:** fixture root with `/etc/hostname`, `/etc/machine-id`, `/proc/uptime`-shaped files under prefix; injected `systeminfo` canned text (Windows collector test runs on any host because sources are injected); assert json keys present with expected values for the fixture.
- [ ] **Step 2: FAIL. Step 3: Implement** (per-OS functions selected by `ctx.platform.os`, both compiled on all hosts via runtime branch — file reads just fail on wrong OS, which is the degraded path).
- [ ] **Step 4: PASS. Step 5: Commit** `feat(extractor): system fingerprint both OS`

### Task 11: Report assembly + CLI args

**Files:**
- Create: `extractor/src/report.rs`; rewrite `extractor/src/main.rs` (arg parsing + orchestration, no TUI yet)
- Test: `extractor/tests/report.rs`

**Interfaces:**
- Consumes: Tasks 2–10.
- Produces:
  - `report::build(scan: Value, metadata: Value, results: Vec<CheckResult>, audit: SelfAudit, started: SystemTime, duration_ms: u64, version: &str) -> Report` — fills `scan` block: `extractor_id` (hex from slot), `machine_id`, `hostname`, `platform`, `arch`, `started_unix`, `duration_ms`, `privilege` ("elevated"|"degraded"), `extractor_version`, `schema_version: 1`.
  - CLI (clap derive): `--list-checks`, `--only <ids csv>`, `--category <name>`, `--min-severity <critical|high|medium|low|informational>`, `--out <path>`, `--push <url>`, `--no-elevate`, `--no-pause`, `--quiet`, `--elevated-child` (hidden).
  - `main` flow: parse → `lower_own_priority()` → `keyslot::read_own_slot()` (friendly error on unissued) → `check_expiry` → `platform::detect` → elevation (Task 12) → build ctx → metadata → engine → report → `crypto::seal` → write `hbs-report-<hostname>-<UTC stamp>.hbs` (or `--out`) → optional push (ureq POST, `X-HBS-Extractor: <id>`, body = envelope; print result).
  - Exit codes: 0 success, 2 unissued/expired, 3 nothing ran.

- [ ] **Step 1: Failing test:** `report::build` returns `schema_version == 1` and scan block contains extractor_id hex, machine_id, hostname, privilege.
- [ ] **Step 2: FAIL. Step 3: Implement** report.rs + main.rs skeleton (progress printing via `println!` per check for now). **Step 4: PASS** + manual: `cargo run -- --list-checks` prints toy check; `cargo run` on dev host (unissued placeholder in debug builds → exit 2 with message; acceptable until Task 19 patcher — for local runs add hidden `--dev-insecure-key <hex64>` flag compiling only in debug builds (`#[cfg(debug_assertions)]`) that overrides slot pubkey+ids so the loop is testable pre-dashboard).
- [ ] **Step 5: Commit** `feat(extractor): end-to-end sealed report from CLI`

### Task 12: Windows elevation

**Files:**
- Create: `extractor/src/elevate.rs` (`#[cfg(windows)]` module; stub fn for unix returning current state)
- Test: manual on Windows host (automatable partially via `is_elevated()` unit test)

**Interfaces:**
- Produces: `pub fn is_elevated() -> bool` — `OpenProcessToken` + `GetTokenInformation(TokenElevation)`; `pub fn request_relaunch(no_elevate: bool) -> bool` — if not elevated and not `--no-elevate`: `ShellExecuteW(NULL, "runas", own_exe, "--elevated-child <same args>", NULL, SW_SHOW)`, returns true if parent should exit(0).

- [ ] **Step 1:** Unit test `is_elevated()` returns bool without panic; integration: run binary non-elevated on Windows dev machine → UAC prompt appears, child runs elevated, parent exits (record screenshot/output in task notes).
- [ ] **Step 2–4:** Implement, verify, **Step 5: Commit** `feat(extractor): UAC self-elevation with graceful decline`

### Task 13: Terminal UX

**Files:**
- Create: `extractor/src/cli.rs` (progress rendering: banner, per-check lines, summary; non-TTY detection via `console::Term::stdout().features().is_attended()`)
- Modify: `extractor/src/main.rs`
- Test: manual + `extractor/tests/cli.rs` (pure formatting helpers)

**Interfaces:**
- Produces: `pub struct Progress` with `new(quiet: bool, total: usize)`, `banner(&PlatformInfo, privilege: &str, version: &str)`, `check_done(&CheckResult)`, `finish(&Summary, path: &str, push_status: Option<&str>)`, `pause_if_interactive()`; `pub fn fmt_check_line(r: &CheckResult) -> String` (e.g. `✓ LIN-SSH-001 root login disabled` / `✗ WIN-AU-003 audit: logon events [High]`) — unit-testable pure fn.
- Uses `indicatif::MultiProgress` + styled bar; colors via `console::style`; auto-disable when not attended or `--quiet`; Windows: `console` enables VT processing; pause at end only when launched interactively without `--no-pause` (detect via `GetConsoleProcessList`>1 on Windows; `isatty(stdin)` on Linux).

- [ ] **Step 1: Failing tests** for `fmt_check_line` (each status icon/severity tag exact strings).
- [ ] **Step 2: FAIL. Step 3: Implement. Step 4: PASS** + manual run on Windows + git-bash pipe (`cargo run -- --quiet | cat` shows plain lines, no ANSI). **Step 5: Commit** `feat(extractor): rich TUI progress with non-TTY fallback`

### Task 14: Cross-compile matrix

**Files:**
- Create: `scripts/build-all.sh`
- Test: script assertions

**Interfaces:**
- Produces: `dashboard/binaries/<target>/hbs-extractor[.exe]` + `dashboard/binaries/manifest.json` (`{target, file, sha256, size, built_at}`).

- [ ] **Step 1:** Install once: `cargo install cargo-zigbuild` + `rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl`.
- [ ] **Step 2:** Script builds `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` via `cargo zigbuild --release --target ...`, and `x86_64-pc-windows-msvc` via `cargo build --release`; copies binaries, computes sha256 manifest, **fails if any binary ≥ 10 MB** (10*1024*1024).
- [ ] **Step 3:** Run on dev machine → all 3 binaries under budget (record sizes in commit message).
- [ ] **Step 4: Commit** `build: cross-compile matrix with size budget gate`

### Task 15: Cross-language crypto vectors

**Files:**
- Create: `extractor/tests/crypto_vectors.rs` (writes `fixtures/crypto-vectors.json`), commit the generated `fixtures/crypto-vectors.json`
- Test: the same file

**Interfaces:**
- Produces: `fixtures/crypto-vectors.json` — array of `{name, suite, key_id, recipient_priv_hex (32B), recipient_pub_hex, envelope_hex, plaintext}` — at least: suite 0 round trip, suite 1 round trip, empty plaintext, 1 MB plaintext (hex omitted for this one — store sha256 instead + flag `large: true`).

- [ ] **Step 1:** Test generates vectors via `crypto::seal` with fixed recipient keys, asserts each round-trips via `unseal`, writes JSON.
- [ ] **Step 2: Run** → file exists and test passes.
- [ ] **Step 3: Commit** vectors file + `test(extractor): cross-language crypto vector generation`

---

## Phase 2 — Linux + shared checks

Every check-module task in Phases 2–3 follows this locked pattern (established by Tasks 3–7):

**Implementation recipe per module (all tasks below):**
1. Create `extractor/src/checks/<module>.rs` with `pub fn register(r: &mut Vec<RegisteredCheck>)` and one private fn per check.
2. Each check fn: build `Vec<FallbackAttempt>`; try fallback 1 (primary evidence source) → if missing/denied try fallback 2 → 3; convert evidence to pass/fail with explicit criteria; return `CheckOutcome { status, evidence, location, repro, recommendation_override: None, degraded_reason }`. On all-fallbacks-failed return `CheckOutcome` with `status: Error`, `evidence: "unavailable: " + per-fallback outcomes joined`.
3. Register with `check!` macro: static texts (title/description/impact/recommendation), severity, category, refs (e.g. `&["CIS 5.2.8", "NIST AC-3"]`), `applies` closure (usually `|p| p.os == Os::Linux`).
4. **Tests** (`extractor/tests/checks_<module>.rs`): fixture root under `extractor/fixtures/<module>/` + injector for command fallbacks; one test per status class: compliant fixture, non-compliant fixture, missing-path → Error with fallback_log asserting every attempted source appears. Use `ScanContext::with_root_prefix(...).with_injector(...)`.
5. Wire module into `checks/mod.rs::register_all`; registry uniqueness test still passes.

Exemplar — complete code for **LIN-SSH-001** (root login) to copy the shape from:
```rust
fn ssh_permit_root_login(ctx: &mut ScanContext) -> CheckOutcome {
    let mut log = Vec::new();
    let mut last_cfg = String::new();
    // fallback 1: sshd_config effective value (last uncommented occurrence wins)
    if let Some(text) = ctx.read("/etc/ssh/sshd_config") {
        log.push(FallbackAttempt { source: "/etc/ssh/sshd_config".into(), outcome: "read".into() });
        last_cfg = text;
    } else {
        log.push(FallbackAttempt { source: "/etc/ssh/sshd_config".into(), outcome: "missing or unreadable".into() });
        // fallback 2: effective config dump
        if let Some(out) = ctx.cmd("sshd", &["-T"]) {
            log.push(FallbackAttempt { source: "sshd -T".into(), outcome: "read".into() });
            last_cfg = out;
        } else {
            log.push(FallbackAttempt { source: "sshd -T".into(), outcome: "unavailable (needs root or sshd not in PATH)".into() });
        }
    }
    if last_cfg.is_empty() {
        return err_outcome("LIN-SSH-001", log);
    }
    let v = last_cfg.lines().filter_map(|l| {
        let l = l.trim_start();
        if l.starts_with('#') { return None; }
        l.split_whitespace().collect::<Vec<_>>()
    })
    .filter(|p| p.len() == 2 && p[0].eq_ignore_ascii_case("permitrootlogin"))
    .last().map(|p| p[1].to_lowercase());
    match v.as_deref() {
        Some(x @ ("no" | "prohibit-password" | "without-password")) => ok(format!("PermitRootLogin {x}"), "/etc/ssh/sshd_config", "sshd -T | grep -i permitrootlogin"),
        Some(other) => nok(format!("PermitRootLogin {other}"), "/etc/ssh/sshd_config", format!("grep -i '^PermitRootLogin' /etc/ssh/sshd_config (found '{other}')")),
        None => degraded("no explicit PermitRootLogin (OpenSSH default 'prohibit-password' applies)"),
    }
}
```
Helpers `ok/nok/degraded/err_outcome` live in `checks/mod.rs` returning `CheckOutcome` (build once in Task 16, reused by every module).

### Task 16: Shared check helpers + GEN-INV inventory (~25 checks)

**Files:**
- Create: `extractor/src/checks/mod.rs` helpers, `extractor/src/checks/shared.rs`
- Test: `extractor/tests/checks_shared.rs` + fixtures

Check table (all Informational severity, applies: any OS; evidence sources in fallback order; "pass" = inventory recorded):

| ID | Title | Sources (fallback order) |
|---|---|---|
| GEN-INV-001 | Listening ports | `ss -tulpn` → `netstat -tulpn` → `/proc/net/tcp` parse |
| GEN-INV-002 | Installed packages | `dpkg-query -W` → `rpm -qa` → `apk info` → `pacman -Q` → PowerShell `Get-Package` |
| GEN-INV-003 | Users & groups | `/etc/passwd`+`/etc/group` → `getent passwd` → `net users`+`Get-LocalGroup` |
| GEN-INV-004 | Scheduled tasks | `crontab -l` + `/etc/cron*` + `systemctl list-timers` → `schtasks /query /fo csv` |
| GEN-INV-005 | Autoruns/persistence inventory | rc.local/systemd user units/win RUN keys + startup folders |
| GEN-INV-006 | Open shares | `net share` (win) / `/etc/exports` + `showmount -e localhost` (linux) |
| GEN-INV-007 | Patch currency | last update age: `/var/log/dpkg.log` → `rpm -qa --last` → `Get-HotFix` newest |
| GEN-INV-008 | Virtualization platform | `systemd-detect-virt` → dmi `/sys/class/dmi/id/product_name` → wmic ComputerSystem |
| GEN-INV-009 | Time sync | `timedatectl` → `/etc/chrony.conf`+`chronyc tracking` → `w32tm /query /status` |
| GEN-INV-010 | DNS resolver config | `/etc/resolv.conf` → `netsh interface ip show dns` |
| GEN-INV-011 | Logging agent presence | rsyslog forwarder config / win forwarder registry |
| GEN-INV-012 | Secure Boot state | `mokutil --sb-state` → `bootctl status` → `Confirm-SecureBootUEFI` |
| GEN-INV-013 | TPM state | `/sys/class/tpm` → `get-tpm` |
| GEN-INV-014 | FIPS mode | `/proc/sys/crypto/fips_enabled` → `fips-mode-setup --check` → win registry `Enabled` |
| GEN-INV-015 | Audit coverage score | auditd rules count / win auditpol passing subcategory count |
| GEN-INV-016 | Privileged group inventory | sudo/wheel/admins members |
| GEN-INV-017 | Effective firewall profile | `systemctl is-active firewalld/ufw/nftables` → `netsh advfirewall show allprofiles` |
| GEN-INV-018 | Cloud agent/init presence | cloud-init / EC2Launch / WALA / aws-cli config |
| GEN-INV-019 | EDR/AV agent | clamd/defender states + known agent processes |
| GEN-INV-020 | Backup agent + last success | installed backup clients + their status files/logs |
| GEN-INV-021 | Kernel module inventory | `lsmod` → driverquery |
| GEN-INV-022 | Environment/agents summary | sshd/auditd/winrm service presence overview |
| GEN-INV-023 | Locale & timezone | locale cmd / tzutil |
| GEN-INV-024 | Disk & mount inventory | `/proc/mounts` → `Get-PSDrive` |
| GEN-INV-025 | Host identity block | machine_id + hostname + domain join state (`realm`/`dsregcmd`) |

- [ ] **Step 1: Write helpers** `ok/nok/degraded/err_outcome` (unit tests for each helper's mapping to Status/evidence shapes).
- [ ] **Step 2: Failing tests** for GEN-INV-001 (fixture `/proc/net/tcp` parse), GEN-INV-003 (fixture passwd), GEN-INV-007 (dpkg.log fixture), one missing-everything → Error case.
- [ ] **Step 3: Implement** all 25 following the table (each ≤ ~40 lines using helpers).
- [ ] **Step 4:** `cargo test` PASS. **Step 5: Commit.**

### Task 17: LIN-FS filesystem (~15)

Checks (id base LIN-FS-001..): tmp partition separate + nodev/nosuid/noexec (3 checks via `/proc/mounts`→`findmnt`); dev/shm same trio; /var separate; /var/tmp separate + opts; /home separate; /home nodev; fstab entries match opts (`/etc/fstab` parse); `/` not mounted with `user` opts; bootloader config perms ≤ 0600 root-owned (`/boot/grub2/grub.cfg`, `/boot/grub/grub.cfg`, `/etc/default/grub` first found); bootloader dir perms; `grub` password set (grub.cfg `password_pbkdf2`); core dump storage disabled (`/etc/security/limits.conf` + `ulimit -c 0` via sysctl `fs.suid_dumpable`); `mount` of freefstab… stick to CIS 1.1.x list; separate partition check helper shared (`fn is_separate_mount(ctx, path) -> Option<bool>`).
Tests: fixture `/proc/mounts` compliant/non-compliant; missing `/etc/fstab` → degraded.
Commit.

### Task 18: LIN-SV services (~8)

CIS 2.x: xinetd not enabled; inetdservices files absent; time services (rsync/syslog listener) off; `mailtransfer`: postfix/exim not listening externally; `apt`-equivalent: `wget`/`ftp`/`telnet`/`rsh` clients absent (`dpkg-query -W`/`rpm -q` per family, applied via `ctx.platform.family`); NIS/ypbind absent; `talk`/`tftp` servers absent. Evidence: `systemctl is-enabled <svc>` → `/etc/systemd/system` symlink presence → package query. Tests: enabled/disabled/uninstalled fixture outputs via injector; package-absent on unknown family → NotApplicable.

### Task 19: LIN-NET network sysctl (~20)

`sysctl` keys (fallback: `sysctl -n <key>` → `/proc/sys/<key path>` → `/etc/sysctl.conf`+`/etc/sysctl.d/*` for configured value):
ip_forward=0; ip_forward v6; icmp_echo_ignore_broadcasts=1; icmp_ignore_bogus_error_responses=1; rp_filter=1 (all+default); accept_source_route=0 (v4 all/default, v6 all/default = 4 checks); accept_redirects=0 (v4/v6 all+default); secure_redirects=0; log_martians=1 (all+default); send_redirects=0 (all+default); tcp_syncookies=1; ipv6 accept_ra=0; tcp_max_syn_backlog≥2048 (informational Low). Shared helper `fn sysctl_value(ctx, key) -> Option<String>`. Tests: proc fixture value present/missing; sysctl.d override parse.

### Task 20: LIN-FW firewall (~5)

firewalld/ufw/nftables/iptables: at most one active (informational), active firewall running (`systemctl is-active` ×3 → `iptables -L -n` count), default zone deny / ufw default deny policy (`ufw status verbose` → `/etc/default/ufw`), nftables ruleset non-empty (`nft list ruleset`), loopback not wide-open… final: firewall service enabled at boot. NotApplicable when none installed (evidence records all probes).

### Task 21: LIN-LOG logging (~14)

rsyslog installed+enabled; `/etc/rsyslog.conf` forwards to remote (info); logfile perms (`/var/log/messages`… ≤0640 via unix_mode); all rsyslog facilities configured (`/etc/rsyslog.conf`/`conf.d` mail/news/auth…); journald forward to syslog (`/etc/systemd/journald.conf`); journald compression; journald persistent storage; logrotate configured (`/etc/logrotate.conf` exists + weekly); permissions on `/var/log` dir; `logcheck`… trim to CIS 4.2.x core. Tests: fixture conf files.

### Task 22: LIN-AU auditd (~12)

auditd installed/enabled; `/etc/audit/auditd.conf` max_log_file_action; space_left_action; `auditctl -l`→`/etc/audit/audit.rules` identity (passwd/group/sudoers/shadow events), logins (lastb/faillog paths), session (wtmp/btmp), time-change (adjtime/date perms), perms-modification rules; `auditd` immutable flag (`-e 2`); audit logs not auto-deleted (`keep_logs`/num_logs). Tests: audit.rules fixture containing/missing rule patterns.

### Task 23: LIN-SSH sshd (~14)

CIS 5.2.x: LogLevel ≥ verbose; PermitRootLogin (exemplar, done in Task 16 docs — implement here); Protocol 2 (N/A modern — degraded note); SSH protocol ciphers (chacha20/aes-gcm list), MACs (hmac-sha2-*), Kex (curve25519/…), `ClientAliveInterval ≤900` + `ClientAliveCountMax ≤3` (2), `LoginGraceTime ≤60`, `MaxAuthTries ≤4`, `MaxSessions ≤10`, `X11Forwarding no`, `AllowTcpForwarding` restricted, `AllowAgentForwarding no`, banner set, `IgnoreRhosts yes`, `HostbasedAuthentication no`, `PermitEmptyPasswords no`, `PermitUserEnvironment no`. Shared effective-value parser fn `sshd_effective(ctx, key)` (last-wins incl. `sshd -T` fallback — extracted from exemplar). Tests: fixture sshd_config with overrides (first `PermitRootLogin yes` commented, second active `no` → Compliant), sshd -T injector fallback.

### Task 24: LIN-PAM auth (~14)

`/etc/security/fwopasswd.conf`? exact: `pwquality.conf` (minlen≥14, minclass/credit dcredit…=3-4 checks); `pam_faillock` (deny ≤5, unlock_time ≥900) via `/etc/pam.d/` grep (system-auth/common-auth); password remembering ≥5 (pam_pwhistory remember); expiry (`/etc/login.defs` PASS_MAX_DAYS ≤365, PASS_MIN_DAYS ≥7, PASS_WARN_AGE ≥7 — 3 checks); hashing sha512 (`login.defs` ENCRYPT_METHOD + pam_unix); sudo: `use_pty` default, `logfile` set, `timeout`/`timestamp_timeout ≤15` (`/etc/sudoers`+`/etc/sudoers.d/*`); `tty_tickets` on. Shared fn `pam_grep(ctx, file_glob, pattern)`. Tests: fixture login.defs/pam.d.

### Task 25: LIN-USER users & perms (~20)

`/etc/passwd`+`/etc/group`+`/etc/shadow` perms/ownership (0600/0644 root:root set — via unix_mode fallback to `ls -l` parse → degraded without root); no UID-0 accounts beyond root; no duplicate UIDs; shadow no empty password fields (needs root — degraded otherwise via `getent shadow` attempt); root PATH has no world/group-writable entries; home dirs perms ≤0750; dotfiles not group/world writable (sample); no `.forward`/`.rhosts` for root; umask (`/etc/profile`/`/etc/login.defs` UMASK 027); no legacy + entries in passwd/group; default shell nologin for system users; `.netrc`/`.rhosts` absent for interactive users; cron dirs perms. Tests: fixture trees incl. a world-writable home → NonCompliant.

### Task 26: LIN-TH kernel attack surface + persistence (~26)

Kernel group (sysctl/paths per spec): unprivileged_bpf_disabled=1; userns restricted (`kernel.unprivileged_userns_clone`=0 or `user.max_user_namespaces`=0 or AppArmor `kernel.apparmor_restrict_unprivileged_userns`=1 — any-of = compliant); io_uring_disabled ≥1 (Low if 0); kptr_restrict=2; dmesg_restrict=1; yama ptrace_scope≥1; perf_event_paranoid≥2; modules_disabled/kexec_load_disabled (kexec_load_disabled=1); bpf_jit_harden=2; lockdown (`/sys/kernel/security/lockdown` contains "[confidentiality]" or "integrity"); module sig force (`/proc/sys/kernel/tainted` info + `CONFIG_MODULE_SIG_FORCE` via `/boot/config-$(uname -r)` → degraded); protected_hardlinks/symlinks=1 (2 checks); suid_dumpable=0 + core_pattern not pipe to arbitrary (`/proc/sys/kernel/core_pattern`).
Persistence group: ld.so.preload absent/empty; systemd units non-package & suspicious ExecStart (parse `systemctl list-units --type=service --no-legend` + per-unit `systemctl cat` → compare owning package via `dpkg -S`/`rpm -qf`, flag /tmp,/dev/shm,/proc paths) — implemented as Low/Info sweep with clear evidence; systemd timers sweep (same logic); udev rules referencing temp paths; rc.local executable+content scan; cron all-locations sweep flagging temp-dir commands (5 locations); at jobs (`atq`); root authorized_keys presence (Info/High per spec); shell rc tampering (root + sampled users: non-comment content in `.bashrc` referencing temp dirs — Info); PAM module substitution (`/etc/pam.d` modules resolving to files not owned by package — degraded without root); SUID/SGID inventory + diff vs package-owned (`find / -perm -4000` bounded to standard dirs to keep runtime sane → `rpm -qf`/`dpkg -S`; unknown-owner SUIDs listed); file capabilities inventory (getcap if present); hidden UID-0 / duplicate UID accounts; sudoers `NOPASSWD: ALL` grants; OpenSSH version currency (`sshd -V`/`ssh -V` parse vs min 9.8p1 → Low/Info); xz/liblzma version (`dpkg-query -W liblzma5`/`rpm -q xz-libs` vs patched ≥5.6.1 or <5.5 — NonCompliant only if in known-bad band 5.6.0/5.6.1, else Info).
Tests: sysctl proc fixtures; a fixture systemd unit with `/tmp` ExecStart → flagged; cron fixture; crafted `ld.so.preload` with content → NonCompliant.

### Task 27: LIN-TH containers, EOL & currency (~14)

docker group members; docker/containerd/podman socket perms (unix_mode on `/var/run/docker.sock` etc.); docker daemon `--privileged` / live-restore insecure flags (`systemctl cat docker` + `/etc/docker/daemon.json`); `hidepid` on /proc (findmnt opts); privileged containers where daemon queryable read-only (`docker ps --format` + `docker inspect --format '{{.HostConfig.Privileged}}'` — allowlisted read-only subcommands); EOL distro detect (date table: centos7≤2024-06-30, ubuntu non-LTS +1y, debian9… hard-coded map vs today); security-patch backlog count (`apt-get -s upgrade` count of `-security` lines / `dnf updateinfo list` → Low if >0, Info); kernel older than distro current (Info); old service versions (OpenSSH<9.8 → Medium/Info per spec, nginx/apache EOL majors → Info); third-party repos configured (`/etc/apt/sources.list.d` non-official hosts, `.repo` files); package integrity spot check (`debsums -s` on core pkgs / `rpm -V basesystem` — bounded, timeout 5 s, result Info); Secure Boot already GEN — here: kernel cmdline integrity (`/proc/cmdline` no `init=/bin/sh` etc. — Low); `/etc/ld.so.conf.d` non-package entries (Info).
Tests: EOL map unit test with injected dates; docker socket fixture mode 0660 root:docker vs 0666 world.

### Task 28: Docker validation matrix

**Files:** `scripts/docker-test/run.sh`, `scripts/docker-test/Dockerfile.assert` (or inline)

- [ ] **Step 1:** Script: build linux-x64 target, then for each of `ubuntu:24.04`, `debian:12`, `alpine:3.20`, `rockylinux:9` run twice (root; `su nobody -s /bin/sh -c`): mount binary + out dir, run `./hbs-extractor --no-pause --quiet --out /out/r.hbs`; assert exit 0 + file exists; then (on host) a bun script `scripts/docker-test/ingest.ts` posts it to a running dashboard dev server with a matching issuance (created via API) and asserts 200 + host row appears.
- [ ] **Step 2:** Resource assertion: `/usr/bin/time -v` run captures `Maximum resident set size` < 200000 KB; recorded into `scripts/docker-test/results-<date>.json` (committed).
- [ ] **Step 3:** Fix any check that Error'd > 0 times on two distros (adjust fallbacks) — target: 0 hard Errors on all four images except documented root-only-degraded.
- [ ] **Step 4: Commit** `test: linux docker matrix green across 4 distros`

---

## Phase 3 — Windows checks

Same recipe as Phase 2; evidence sources are `reg query`, `auditpol`, `secedit /export` (sanctioned temp file under output dir), `powershell -NoProfile -NonInteractive -Command "<script>"` with script constants. All checks `applies: |p| p.os == Os::Windows`. Registry helper in Task 29, reused by all: `fn reg_query_dword(ctx, hive_path: &str, name: &str) -> Option<u32>` and `reg_query_sz(...) -> Option<String>` (parse `reg query` output; fallback PowerShell `Get-ItemProperty`).

### Task 29: WIN-ACC account policies (~12) + windows helpers

`net accounts` parse (fallback `secedit` export `SystemAccess` section, fallback registry Policy* values): MinimumPasswordLength≥14; MaximumPasswordAge≤365or0-unused-needs-care (NonCompliant if >365 or 0-with-passwords-required nuance recorded in evidence); MinimumPasswordAge≥1; PasswordHistorySize≥24; LockoutBadCount≤50≠0 (recommend ≤5 evidence); LockoutDuration≥15; ResetLockoutCount≥15; clear-text storage (LimitBlankPasswordUse); PasswordComplexity=1 (secedit); `LSA` anonymous restrictions (restrictanonymous=1, restrictanonymoussam=1). Tests: canned `net accounts` good/bad outputs via injector; secedit fixture.

### Task 30: WIN-AU audit policy (~10)

`auditpol /get /category:*` parse (fallback secedit `EventAuditPolicy`): Logon/Logoff success+failure; Account Logon success+failure; Account Management both; Policy Change both; Privilege Use failure; Process Tracking (≥failure per CIS L2→Low), Detailed Tracking, DS Access, Object Access (≥failure on key subcats: File Share, Kernel, Registry, SAM); Audit: ForceAuditPolicyShutdown… trim: 10 highest-value subcategories, each a check. Tests: canned auditpol CSVs.

### Task 31: WIN-SEC security options (~22)

Registry-based (path → expected): LANMAN `LmCompatibilityLevel`≥5 (also NoLMHash=1); SMB signing RequireSecuritySignature Server+Client (2); `RestrictAnonymous`/`RestrictAnonymousSAM` (moved here from 29 if cleaner — keep single home in 29); UAC: EnableLUA=1, ConsentPromptBehaviorAdmin≥2, EnableInstallerDetection, EnableSecureUIPaths, EnableVirtualization (5); Shutdown:ClearVirtualPageFile=1; NoConnectedUser→offline; LockSessionIdle (`InactivityTimeoutSecs`≥900); screensaver secure (`ScreenSaverIsSecure`+Timeout ≤900 via policy keys); ForceUnlockLogon; DoNotDisplayLastUserName=1; legal banner text set (`legalnoticecaption/text`); SMBv1 removed (difscfeature or `SMB1` registry 0); Winlogon `AutoRestartShell`… keep CIS 2.3/2.5 core. Tests: reg fixture outputs good/bad/missing.

### Task 32: WIN-UR user rights (~16)

Parse `secedit /export` `Privilege Rights` section: SeDebugProgram/SeTcbName/SeAssignPrimaryToken/SeIncreaseQuota → empty or Administrators only; SeRemoteShutdown → Administrators; SeNetworkLogonRight excludes Guests/Everyone; SeInteractiveLogonRight excludes Guests; SeDenyNetworkLogonRight includes Guests; SeDenyInteractiveLogonRight includes Guests; SeCreatePagefile/SeLockMemory/SeCreateGlobal/SeProfileSingleProcess admins-only; SeMachineAccount deny users; SeSyncAgentPrivilege empty; SeEnableDelegationPrivilege empty. Tests: secedit fixture with violations.

### Task 33: WIN-EVT event logs (~6)

`wevtutil gl <log>` parse: Application/Security/System max size ≥ 32768 KB (3 checks); retention ≥ 30 days or `AutoBackup` policy; access ACL on Security log; `wevtutil el` count (Info). Tests: canned `gl` output.

### Task 34: WIN-DEF defender & updates (~10)

PowerShell `Get-MpComputerStatus` + `Get-MpPreference`: AV enabled+up-to-date; real-time protection on; behavior monitoring; script scan; PUAs; tamper protection; signature age ≤7d (Low); ASR rules enabled count + `-AttackSurfaceReductionRules_Ids` presence (Medium); Windows Update: `Get-HotFix` newest ≤90d (Medium if >90); `UsoClient`/WU policy (`NoAutoUpdate`=0, scheduled install). Tests: canned PS JSON outputs.

### Task 35: WIN-SVC services (~20)

`sc qc`/`Get-Service` on: Telnet, TFTP (feature), RemoteRegistry, PrintSpooler (with print-nightmare rationale; recommendation disable if unused), Fax, SMBv1-related (mrxsmb10 via optional features), WPADSVC (WinHTTP Web Proxy), SNMP, RemoteAccess (RAS/Routing), SSDPSRV/upnphost (2), Wecsvc, W3SVC/IIS admin (info if installed), msftpsvc, Xbox services (info), SysMain (Low per CIS), Bluetooth (Low), `spooler` covered; plus `Get-Service` where StartType=Auto for known-dangerous set → each = one check `enabled & running? NonCompliant if enabled`. Tests: canned `sc qc` outputs enabled/disabled/not-installed (NotApplicable).

### Task 36: WIN-REG/PERMS (~10)

Registry ACLs on HKLM\SAM/SECURITY/SYSTEM (Administrators+SYSTEM+Backup Operators limited — via PowerShell Get-Acl parse, degrade to `reg query` existence); `%SystemRoot%`/`Program Files` dir perms not world-writable (Get-Acl sample of key dirs: windir, system32, ProgramFiles, inetpub); `PerfLogs` empty; `%SystemDrive%\` root ACL (info if Users writable); `Run`/`RunOnce` keys enumerated to evidence (info); Startup folder inventory (info); unquoted service paths scan (Medium: enumerate services binPath unquoted-with-space + writable-dir check → evidence). Tests: canned Get-Acl SDDL good/bad.

### Task 37: WIN-NET network (~12)

Firewall: Domain/Private/Public Enabled (3) + `DoNotAllowExceptions`-equivalent inbound default block (`netsh advfirewall show allprofiles` parse); mDNS (EnableMDNS=0); LLMNR (`EnableMulticast`=0); WPAD (`DisableAutoProxyCache`=1 per CIS 18.9.85.x + WinHttpDisable); RDP: `fDenyTSConnections` per use (N/A flag if intentionally enabled — record), UserAuthentication(NLA)=1, SecurityLayer=2/1, MinEncryptionLevel≥2, DisableClipboardRedirection/Drive (2 per L2→Low); WinRM `AllowUnencrypted=0` + TrustedHosts scope (Low); LDAP signing `LDAPClientIntegrity`=1; NTLM `RestrictSendingNTLMTraffic`≥1 (Low, evidence-only in audit mode).

### Task 38: WIN-TH credential protection & ransomware posture (~14)

RunAsPPL (`RunAsPPL`=1 + `RunAsPPLBoot`); Credential Guard (`HKLM\SYSTEM\CurrentControlSet\Control\LSA` `LsaCfgFlags`=1 or DeviceGuard `Enabled`/`Running` via `dgreadiness`-equivalent registry); memory integrity HVCI (`HVCI` MitigationOptions / `MemoryIntegrityProtection`); Microsoft vulnerable driver blocklist (`Enabled`); WDAC/AppLocker policy present (any of `AppLocker` policy XML present / `CodeIntegrity\SkuPolicyRequired`); WDigest `UseLogonCredential`=0; AutoAdminLogon=0 (+ DefaultPassword present → Critical if set); cmdkey inventory (Info); LSA security packages list unchanged (Info); ASR full rule set state (top rules: WMI persistence block, LSASS steal block, vulnerable driver block, ransomware protection — 4 checks from Get-MpPreference IDs); Controlled Folder Access enabled; tamper protection (already 34 — here only if moved); Smart App Control on (Info on unsupported SKU); PowerShell Constrained Language / script block logging (`EnableScriptBlockLogging`=1, Medium).

### Task 39: WIN-TH persistence hunting + EOL (~13)

RUN keys + IFEO `Debugger` values sweep (flag any Debugger set); startup folders (all users + per-user default profile) inventory+flag exe; scheduled tasks non-Microsoft authors or actions in temp paths (`schtasks /query /fo csv /v` parse); services binPath in temp/unquoted (from 36 — here: services whose binPath lives in user-writable dirs, Medium); WMI permanent subscriptions (`Get-CimInstance -Namespace root\subscription __EventFilter/CommandLineEventConsumer` presence → High if any); hosts file non-default entries count+flag (Info/Medium if localhost-redirect entries); firewall rules allowing inbound to temp-path exe (`netsh advfirewall firewall show rule name=all` parse, Medium); NETSH helper DLLs (High if any); Print Spooler service running (dup of 35 as High w/ PrintNightmare rationale — keep single home in 35; here instead: `Spooler` RPC exposure via `RegisterSpoolerRemoteRpcEndPoint`? too deep — use: fax/`FxSSVC` off); OS EOL map (2012/2012R2/2016-pre-ESU…) vs build number; patch staleness >180d (Medium); LAPS presence (classic `AdmPwdService`/modern `LAPS` AdmPwdEnabled → Info if absent on domain-joined, recommendation); local admin count >1 (Low, evidence lists names).

### Task 40: Windows local validation

- [ ] Run `cargo run --release -- --no-pause` on dev machine (elevated path via UAC prompt; then non-elevated with `--no-elevate`) — record: exit 0 both, Error-count, degraded counts, report decrypts via dashboard dev server (Task 25 ingestion script reused). Record Defender state: binary must run without Defender flagging (if flagged: verify no packer used, add exclusions guidance to README; report honestly in commit message).
- [ ] Commit results file `scripts/win-test/results-<date>.md`.

---

## Phase 4 — Dashboard backend

### Task 41: Bun server scaffold + DB schema

**Files:**
- Create: `dashboard/server/db.ts` (bun:sqlite, migrations array applied on boot), rewrite `dashboard/server/index.ts` (Hono app, `/api/health`, static `dist/` serve, 127.0.0.1 bind, `--host` arg)
- Test: `dashboard/server/db.test.ts`

Interfaces (SQL schema exactly):
```sql
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, pw_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('super_admin','auditor','viewer')), active INTEGER DEFAULT 1, created_at INTEGER, last_login INTEGER);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id INTEGER, expires_at INTEGER);
CREATE TABLE IF NOT EXISTS campaigns(id TEXT PRIMARY KEY, name TEXT NOT NULL, client TEXT, scope TEXT, expires_at INTEGER NOT NULL, created_at INTEGER, status TEXT DEFAULT 'active');
CREATE TABLE IF NOT EXISTS locations(id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL, name TEXT NOT NULL, notes TEXT, created_at INTEGER);
CREATE TABLE IF NOT EXISTS issuances(extractor_id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL, location_id TEXT NOT NULL, key_id INTEGER NOT NULL, platform TEXT NOT NULL, created_at INTEGER, download_count INTEGER DEFAULT 0, revoked INTEGER DEFAULT 0, last_used INTEGER);
CREATE TABLE IF NOT EXISTS keys(id INTEGER PRIMARY KEY, issuance_id TEXT, campaign_id TEXT NOT NULL, public_key BLOB NOT NULL, key_file TEXT NOT NULL, created_at INTEGER, retired_at INTEGER);
CREATE TABLE IF NOT EXISTS hosts(id INTEGER PRIMARY KEY, campaign_id TEXT NOT NULL, machine_id TEXT NOT NULL, display_id TEXT NOT NULL, hostname TEXT, platform TEXT, os_version TEXT, arch TEXT, first_seen INTEGER, last_seen INTEGER, latest_report_id INTEGER, UNIQUE(campaign_id, machine_id));
CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY, campaign_id TEXT, location_id TEXT, host_id INTEGER, envelope BLOB, report_json TEXT, schema_version INTEGER, score REAL, coverage REAL, scanned_at INTEGER, arrived_via TEXT, created_at INTEGER);
CREATE TABLE IF NOT EXISTS finding_states(id INTEGER PRIMARY KEY, campaign_id TEXT NOT NULL, host_id INTEGER NOT NULL, check_id TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'open' CHECK(state IN ('open','in_progress','mitigated','accepted_risk','false_positive','resolved')), assigned_to INTEGER, due_date INTEGER, justification TEXT, decided_by INTEGER, updated_at INTEGER, UNIQUE(host_id, check_id));
CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY, host_id INTEGER NOT NULL, check_id TEXT NOT NULL, user_id INTEGER NOT NULL, body TEXT NOT NULL, created_at INTEGER);
CREATE TABLE IF NOT EXISTS scan_tokens(campaign_id TEXT PRIMARY KEY, token_hash TEXT);
CREATE TABLE IF NOT EXISTS download_tokens(campaign_id TEXT PRIMARY KEY, token_hash TEXT);
```
- Tests: boot creates all tables; migrations idempotent.
- Commit.

### Task 42: Auth (setup wizard, login, sessions, rate limit)

**Files:** `dashboard/server/auth.ts`, `dashboard/server/users.ts`; tests `auth.test.ts`.

Interfaces:
- `POST /api/auth/setup {username,password}` → 409 if users exist; creates super_admin with `Bun.password.hash(pw,{algorithm:"argon2id"})`; sets session.
- `POST /api/auth/login` → argon2 verify; rate limit: max 5 failures/15 min per username+IP (in-memory map) → 429; on success cookie `hbs_session` (HttpOnly, SameSite=Lax) = raw token; DB stores sha256(token).
- `POST /api/auth/logout`; `GET /api/auth/status` → `{initialized, user?, role?}`.
- Middleware `requireRole(...roles)`; `requireAuth`.
- `GET/POST/PATCH/DELETE /api/users` (super_admin) — deactivate (never delete last super_admin), reset password, change role.
- Tests: setup→login→me; wrong pw 401; rate limit 429; auditor blocked from /api/users 403; last-super-admin protection.
- Commit.

### Task 43: Keys (per-issuance X25519)

**Files:** `dashboard/server/keys.ts`; tests.

Interfaces:
- `import { generateKeyPairSync, createPublicKey, createPrivateKey } from "node:crypto";`
- `const SPKI_X25519 = Buffer.from("302a300506032b656e032100","hex"); const PKCS8_X25519 = Buffer.from("302e020100300506032b656e04220420","hex");`
- `export function keygen(): { pubRaw: Buffer; privRaw: Buffer }` — generateKeyPairSync("x25519"), export DER, strip prefixes to raw 32 B.
- `export function saveKey(campaignId: string, issuanceId: string, privRaw: Buffer): {keyFile: string}` — writes `server/data/keys/<issuanceId>.key` with `Bun.write` then `chmod 0o600` (`Bun.file(...).chmod? use fs.chmodSync`).
- `export function loadPriv(issuanceId: string): Buffer`.
- `GET /api/keys/status` — inventory join issuances; `POST /api/keys/export {passphrase, campaignId?}` — argon2id(pw) → derive AEAD key (same HKDF scheme, info "HBS-keyexport-v1") → encrypted bundle of {issuanceId: privHex}; `DELETE /api/issuances/:id` retires key + revokes issuance.
- Tests: raw 32-byte keys round-trip; file mode 0600; export bundle decrypts with passphrase (pure-Bun crypto AEAD `aes-256-gcm`).

### Task 44: Envelope decrypt (TS side)

**Files:** `dashboard/server/envelope.ts`; tests `envelope.test.ts` consuming `../../fixtures/crypto-vectors.json`.

Interfaces:
- `export function unseal(env: Buffer, privRaw: Buffer): { plaintext: Buffer; keyId: number; scanId: Buffer }` — parse per Global Constraints, X25519 via `crypto.diffieHellman({privateKey: createPrivateKey({key: PKCS8 prefix+privRaw, format:"der", type:"pkcs8"}), publicKey: createPublicKey({key: SPKI prefix+pubRaw, ...})})`, HKDF via `crypto.hkdfSync("sha256", ikm, salt, info, 32)`, AEAD decipher `chacha20-poly1305` or `aes-256-gcm`, then `zstd` decompress (bun `Bun.gunzipSync`? zstd: use `brotli`? **No** — spec says zstd; Bun has `Bun.dec`ompress? Use npm `fzstd` (pure JS zstd decompressor) — small and works everywhere).
- Tests: every vector from fixtures decrypts to expected plaintext; tampered byte → throws; wrong magic → throws; suite 1 vector passes.
- Commit (this task proves the shared format end-to-end cross-language — the riskiest interface in the system).

### Task 45: Binary patcher

**Files:** `dashboard/server/patcher.ts`; tests `patcher.test.ts`.

Interfaces:
- `export const SLOT_MAGIC = Buffer.from("HBSKSLOT");`
- `export function findSlot(buf: Buffer): number` — indexOf magic; `export function isPlaceholder(buf, off): boolean` (sha bytes 480..512 all zero).
- `export function patch(binary: Buffer, data: {keyId, campaignId: Buffer(16), extractorId: Buffer(16), expiryUnix, issuedAtUnix, recipientPub: Buffer(32)}): Buffer` — verify slot present + placeholder; write fields LE (writeUInt16LE/32LE — note u64: `writeBigUInt64LE`), zero pad 96..480, sha256 → 480..512; return copy.
- `export function sha256(buf: Buffer): Buffer`.
- Tests: fake 2048-byte buffer with placeholder → patch → fields readable via independent parser (mirror of Rust layout constants); patched buffer sha256-of-file changes; double-patch rejected.

### Task 46: Campaigns + locations routes

**Files:** `dashboard/server/campaigns.ts`; tests.
Routes exactly per spec §6.3 (`GET/POST /api/campaigns`, `PATCH /api/campaigns/:id`, locations CRUD nested). Creating a campaign generates `scan_token` + `download_token` (random 32 B, sha256 stored, raw returned once in response). Campaign response includes `expired: boolean` computed. Auditor+ roles allowed.
Tests: create→list→patch expiry→add locations; viewer blocked 403.
Commit.

### Task 47: Issuances + downloads

**Files:** `dashboard/server/downloads.ts`; tests.
- `GET /api/campaigns/:id/locations/:loc/downloads` — platforms from `dashboard/binaries/manifest.json`; each card: `{platform, url: /api/campaigns/:id/locations/:loc/download/:platform?t=<dl_token>, sha256 (post-patch computed on the fly), size}`; plus curl/PowerShell snippet strings.
- `GET .../download/:platform?t=` — session auth **or** valid dl token; loads binary from binaries dir, `keygen()`, `patch()`, inserts `issuances` + `keys` rows, increments download_count, serves `application/octet-stream` with filename `hbs-extractor-<platform>[.exe]`. Revocation check: campaign expired → 410.
- Tests (fake 4 KB placeholder binary fixture in `dashboard/server/test-fixtures/fakebin`): download returns patched file whose slot parses (reuse patcher parser); db rows created; bad token → 401; expired campaign → 410.
- Commit.

### Task 48: Ingest pipeline (push + upload, routing, metrics, SSE)

**Files:** `dashboard/server/ingest.ts`, `dashboard/server/metrics.ts`, `dashboard/server/sse.ts`, `dashboard/server/hosts.ts`; tests `ingest.test.ts` (the Review Focus task).

Interfaces:
- `export function ingestEnvelope(env: Buffer, via: "push"|"upload", ctx: {campaignToken?: string}): {reportId: number} | {error: string}` — steps: header sanity (Review Focus 1: short/magic/corrupt → typed error); `key_id`+`extractor_id` lookup in `issuances` (unknown/revoked → typed error, Review Focus 2); `unseal` with issuance key; JSON parse; `schema_version` check (`> CURRENT` → typed error, Review Focus 4); zstd+parse; scan block validation; host upsert by `machine_id` with `display_id = hostname:machineId.slice(0,8)` (Review Focus 3: rename → update hostname only; same hostname different machine → separate rows); insert report; **auto-resolve treatment states**: for every check that was previously NonCompliant with state ≠ open and is now Compliant → set `resolved` + system comment `auto-resolved by scan #<id>`; compute metrics (`risk score` per Global Constraints from results, excluding findings whose `finding_states.state` is `accepted_risk` or `false_positive`); SSE emit `report-arrived`.
- `POST /api/ingest` — `X-HBS-Token` header = campaign scan token (constant-time compare via `crypto.timingSafeEqual`); body raw envelope.
- `POST /api/reports/upload` — session auth, multipart, **batch**: every file processed independently; per-file `{filename, ok, reportId?|error}` summary (one bad file never fails the batch — Review Focus 1).
- `GET /api/events` — SSE stream (Hono streamSSE).
- Tests (using fixtures from Task 15 + Rust-sealed real binary output if available): all five Review Focus scenarios as explicit test cases; happy path push with token; happy path batch upload 3 files where middle one is garbage.
- Commit `feat(dashboard): ingest pipeline with auto host routing and metrics`.

### Task 49: Reports API + summary + diff

**Files:** `dashboard/server/reports.ts`; tests.
- `GET /api/reports?campaignId=` (list: host display_id, platform, score, coverage, scanned_at), `GET /api/reports/:id` (full json), `GET /api/reports/:id/findings?severity=&category=&status=&treatment=` filters, `GET /api/campaigns/:id/summary` (metrics rollup: campaign score, per-category compliance, severity counts, hosts×category heatmap matrix, trend series, top failing checks, remediation vs previous scans), `GET /api/campaigns/:id/hosts`, `GET /api/reports/diff?a=&b=` (per-check status transitions incl. treatment states), `POST /api/annotations` removed — replaced by treatment API below.
- **Treatment API (VM workflow):** `GET /api/campaigns/:id/findings/treatment?state=&assignee=&severity=` (board list joining latest report findings with finding_states + open comment counts), `PATCH /api/findings/:hostId/:checkId/state` body `{state, justification?, assignedTo?, dueDate?}` (auditor+; `accepted_risk`/`false_positive` require `justification`; never delete history — insert new row version), `GET|POST /api/findings/:hostId/:checkId/comments`.
- Tests: seeded two reports same host → diff shows fixed/regressed; summary math matches Global Constraints formula (hand-computed fixture, including one accepted_risk + one false_positive exclusion); auto-resolve on re-scan (seed finding_states in_progress → ingest compliant report → state resolved + system comment); state change without justification on accepted_risk → 400; viewer PATCH → 403.
- Commit.

---

## Phase 5 — Frontend

### Task 50: Vite + React scaffold, API client, auth pages

**Files:** `dashboard/src/main.tsx`, `App.tsx`, `api.ts` (typed fetch wrapper with 401 → redirect login), `types.ts` (mirror report JSON: `CheckResult`, `Report`, `Summary` camelCase fields exactly matching Rust serde output), router with lazy routes + `RequireRole` guard, pages `Setup.tsx` (wizard form calling /auth/setup when `initialized:false`), `Login.tsx`.
- Verify manually: fresh DB → visiting any URL redirects to /setup; after setup → /login → overview.
- Playwright smoke: setup→login→redirect. Commit.

### Task 51: App shell + Overview

**Files:** `dashboard/src/components/layout/` (Sidebar, Breadcrumbs, TopBar with user menu), `palette.tsx` (cmdk Ctrl+K), `pages/Overview.tsx` (KPI tiles via number-ticker animation, campaign table with status chips, spark trend).
- KPI tiles: campaigns, hosts scanned, open criticals, average risk — each with hover tooltip (title attr + custom tooltip component).
- Commit after Playwright nav smoke (sidebar → campaigns).

### Task 52: Campaigns pages + create wizard

**Files:** `pages/Campaigns.tsx` (list + create modal: name, client, scope, expiry date, first location name), `pages/CampaignDetail.tsx` with tabs: Summary (placeholder → Task 54), Locations & Hosts (Task 53), Reports (Task 55), Downloads (Task 53).
- Commit.

### Task 53: Locations, downloads & batch upload

**Files:** `pages/campaign/Locations.tsx` (location cards, add/rename), `Downloads.tsx` (platform cards: sha256, copy-link button, curl + PowerShell snippets with copy buttons, revocation list), `components/DropZone.tsx` (react-dropzone multi-file → `POST /api/reports/upload`; per-file result toasts; SSE listener refreshes host lists live), host table (display_id, platform, os_version, last scan, score chip) linking to Host page (history list + per-host trend spark).
- Playwright: drop 2 fixture envelopes (one corrupt) → one success toast + one error toast; host row appears.
- Commit.

### Task 54: Chart kit + Campaign Summary (executive + technical) + presentation mode

**Files:** `dashboard/src/components/charts/` (RiskGauge, SeverityDonut, CategoryBars, HostHeatmap, TrendLine, TopFailingBars — Recharts wrappers), `pages/campaign/Summary.tsx`, `pages/campaign/Present.tsx`.

Before writing chart code, apply the dataviz design checklist (Skill: dataviz) — consistent severity palette (color-blind-safe, one hue ramp), accessible contrast, consistent 0–100 scales, tooltips show exact counts + percentages, donut segment click → navigates to findings filtered by that severity, bars hover → highlight + tooltip, heatmap diverging scale with legend. All charts: skeleton loaders, animated (framer-motion), keyboard-focusable with accessible labels.

- Executive view: hero RiskGauge (animated ticker), SeverityDonut, CategoryBars, HostHeatmap, TrendLine, Top-10 failing checks, remediation progress bar, auto callouts list (top 3 criticals as plain-language sentences from a template fn `plainLanguage(findings)` — unit-tested), coverage banner.
- Technical view toggle: full findings table (sortable, filterable) → detail drawer (all fields incl. fallback log table, repro steps code block, references chips, accepted-risk button).
- Present mode route: hides shell, big-type sections stepped with ←/→ keys, URL-shareable (`/c/:id/present`).
- Unit test `plainLanguage`; Playwright: toggle views, click donut → findings filtered, present mode keyboard nav.
- Commit `feat(dashboard): executive summary, interactive charts, presentation mode`.

### Task 55: Report detail (By Host / By Check) + telemetry + diff + treatment

**Files:** `pages/ReportDetail.tsx` (pivot tabs: By Host = this report's findings; By Check = aggregated across campaign hosts from /summary), `components/TelemetryPanel.tsx` (duration, privilege, coverage, errors/degraded, commands run, files read, arrival path), `pages/Diff.tsx` (report pickers, improved/regressed/unchanged table with arrows), `components/TreatmentControls.tsx` (state dropdown with color-coded chips, assignee select from users, due date, justification textarea — shown when state is accepted_risk/false_positive), `components/CommentThread.tsx` (list + composer, optimistic add), `pages/campaign/Treatment.tsx` (board: filter rails by state/assignee/severity, overdue due-date highlight, bulk state change on selected rows).
- Finding drawer gains TreatmentControls + CommentThread below the evidence sections; findings tables gain a state chip column.
- Playwright: pivot switch renders different table; diff page shows fixture transitions; set accepted_risk without justification → inline error; post comment → appears in thread; treatment board filter by state.
- Commit.

### Task 56: Admin (users & keys)

**Files:** `pages/admin/Users.tsx` (create/deactivate/reset/role), `pages/admin/Keys.tsx` (issuance inventory: campaign, location, platform, created, downloads, revoked; export bundle modal; revoke button).
- Role guard: auditor/viewer get 403 page.
- Commit.

---

## Phase 6 — Exports, docs, end-to-end

### Task 57: XLSX + CSV exports

**Files:** `dashboard/server/exports/xlsx.ts`, `csv.ts`, route `GET /api/export/:reportId?format=`; tests writing files and re-reading (exceljs read).
- XLSX: sheet 1 Summary (KPIs, severity counts, score), sheet 2 Findings (all fields, severity color fill, autofilter, frozen header). CSV: flat findings incl. fallback log summary column.
- Commit.

### Task 58: PDF (2 templates) + DOCX

**Files:** `exports/pdf.ts` (executive: cover w/ campaign+host+date, score gauge drawn as arc?, severity table, top findings, plain-language summary; findings: per-host sections ordered remediation-priority), `exports/docx.ts` (same structure, editable).
- Tests: generated files non-empty, PDF page count > 1, docx opens via `docx` round-trip parse; manual visual check committed as screenshots.
- Commit.

### Task 59: README

**Files:** `README.md` — sections: what it is (with honest security statement from spec §8 verbatim), quickstart (dashboard first-run, create campaign+location, download extractor per platform, run on Linux/Windows incl. sudo/UAC behavior, upload or push), architecture diagram (mermaid), threat model table, adding-a-testcase guide (module + macro + check table conventions + rebuild matrix), resource budgets with measured numbers, limitations (AV false-positive note, logic-obfuscation honesty), license note.
- Commit.

### Task 60: End-to-end validation + budget gate

- [ ] Full loop on Linux (docker ubuntu + rocky): dashboard dev server → create campaign/location → download linux-x64 → run in container (root + nobody) → push with token → report visible in UI → export all 4 formats → diff second run.
- [ ] Full loop on Windows dev machine (elevated + non-elevated).
- [ ] Budget assertions: all binaries < 10 MB (script), docker-measured RSS < 200 MB recorded.
- [ ] Playwright suite green; `cargo test` green (host) + docker cargo test green (linux modules).
- [ ] Final commit `chore: v0.1.0 end-to-end validated`.

---

## Self-Review (done at plan time)

- **Spec coverage:** §3 layout→T1; §4.1 CLI→T11/T13; §4.2 privileges→T12; §4.3 engine/result→T2/T6/T7; §4.4 read-only→T3; §4.5 envelope→T8/T44; §4.6 keyslot→T9/T45; §4.7 hardening→T1 profile + obfstr usage note (strings obfuscation applied to path literals in threat modules — folded into T26/T38 implementation); §4.8 budgets→T14/T28/T60; §5 catalog→T16–T40 (all tables enumerated); §6.1 auth→T42; §6.2 campaigns/locations/keys→T43/T46/T47/T48; §6.3 API→T41–T49; §6.4 metrics→T48; §6.5 frontend→T50–T56; §6.6 exports→T57/T58; §9 testing→per-task + T28/T40/T60; §10 phases matched.
- **Placeholders:** none — every check module task carries its full check table with evidence sources and pass criteria; every core task carries code.
- **Type consistency:** `CheckOutcome` fields used by helpers in T16 match T2; envelope/keyslot byte layouts identical in T8/T9 (Rust) and T44/T45 (TS); `display_id` formula identical in T48 only (single owner).
- **Review Focus tests assigned** to owning tasks as noted.
