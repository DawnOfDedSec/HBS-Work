# HBS Platform Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the HBS security-review platform per the approved spec: a Rust read-only extractor (Linux + Windows, amd64/arm64, ~325 testcases) that seals reports with per-issuance X25519 keys, and a Bun + Hono + React dashboard that issues extractors per campaign/location, auto-routes hosts by machine ID, and renders enterprise-grade reports with exports.

**Architecture:** Monorepo: `extractor/` (single Rust crate, lib + bin, runtime platform detection instead of per-distro builds) and `dashboard/` (Bun/Hono backend with SQLite + Vite/React/TS SPA). The two sides share two exact byte formats — the sealed-report envelope and the binary keyslot — defined once in Global Constraints and implemented identically in Rust and TypeScript. Checks are data-driven structs registered by macro into a compile-time catalog; every check has an ordered fallback chain and can never abort the scan.

**Tech Stack:** Rust (stable, static musl + MSVC targets, `x25519-dalek`, `chacha20poly1305`, `aes-gcm`, `hkdf`/`sha2`, `zstd`, `serde`, `clap`, `indicatif`, `console`, `obfstr`, `ureq`+rustls, `windows-sys`, `libc`), Bun (`hono`, `bun:sqlite`, `exceljs`, `docx`, `pdfkit`), React 18 + TypeScript strict + Vite + Tailwind, `recharts`, `framer-motion`, `cmdk`, `lucide-react`, Playwright.

**Spec:** `docs/superpowers/specs/2026-09-21-hbs-security-review-platform-design.md` — the plan argues from the spec; executors read both.

## Delivery State and Task 29+ Gate

- **Implemented baseline:** Tasks 1–28 exist in product code as of commit `1a1c223`; their unchecked historical steps remain acceptance criteria, not a claim that work is absent. Amendments below supersede older contracts and must be applied as focused regression work before or alongside remaining implementation.
- **Remaining scope:** Tasks 29–60. Existing working-tree product changes are partial Task 29 and are not proof that Task 29 passed review.
- **Mandatory gate:** do not write or resume Task 29+ product code until this spec and plan pass their self-review, contradiction scans, and human review. Current session changes documentation only.
- **TDD:** each implementation step starts with a failing focused test, then minimum code, then focused and full-suite verification. No placeholders.
- **Checkpoints, not commits:** every former commit step means “review diff and record checkpoint.” Commit/push only after a later explicit user request.

## Global Constraints

- **Strict read-only:** target files/registry/APIs are queried read-only. Commands are allowlisted query-only. No write-capable probes, temp evidence exports, redirects, or `secedit /export`; requested sealed `.hbs` is sole target-host disk write. Record every attempted file read and command before validation/open/spawn, including denied, missing, failed, and timed-out outcomes, after redacting locators and args.
- **Offline by default:** without explicit `--push <url>`, open no sockets, perform no DNS, and make no network call. Local sealing/write succeeds air-gapped. Push happens only after successful local write, sends those exact bytes, keeps local report on every failure, uses 5s connect/15s transfer timeouts and at most 2 retries. Token comes only from `HBS_PUSH_TOKEN` or read-only `--push-token-file`; never argv, URL, report, logs, audit, or keyslot.
- **Least privilege:** start unprivileged and run nonprivileged/fallback-capable work first. Windows may make one explicit consent/UAC request only for unresolved selected checks unless `--no-elevate`; denial continues with fallbacks. Linux never invokes sudo or re-execs; it may print operator-controlled rerun guidance. Record requested/granted/refused/not-needed and per-result run context/evidence depth.
- **Fallback semantics:** every testcase declares ordered source descriptors: normally authoritative primary plus independent read-only fallback. A single-source check needs explicit rationale/manual verification. Validate whole catalog. Log every attempt; stop only at authoritative evidence; conflicts and exhausted missing/denied/localized/tool-absent sources are `DegradedPartial`. `Error` means internal invariant failure, panic, or corrupt parser/input only. Coverage counts authoritative decided applicable checks.
- **Exact evidence:** `sourceType` is `file|registry|command|api`; source is exact redacted locator; line/column are optional 1-based values; `contextBefore`/`contextAfter` have at most 3 lines; `offendingValue` is explicit; safe file metadata is optional; `redacted=true`. Every locatable NonCompliant result has a block. No fake line 0. Redact source, context, fallback outcomes, location, repro, and evidence before serialization. Columns must be correct on later lines and after Unicode.
- **Resource/compatibility:** binary <10 MiB, peak RSS <200 MiB, ≤2 workers, command timeout 2–5s. Required targets: `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `x86_64-pc-windows-msvc`; stretch: `aarch64-pc-windows-msvc`, `armv7-unknown-linux-musleabihf`. Use capability adapters across listed Linux families and Windows 10/11/Server 2016–2025; unsupported OS/arch exits clearly without host modification.
- **Envelope v2, little-endian:** `HBS2`; version 2; suite u8 at 6; key_id u16 at 7; extractor_id 16 bytes at 9; scan_id 16 bytes at 25; ephemeral public key 32 bytes at 41; nonce 12 bytes at 73; ciphertext length u64 at 85; ciphertext at 93. Header bytes `0..93` are AEAD AAD. HKDF info is `"HBS-report-v2" || suite_u8 || key_id_u16_le || extractor_id`. New issuance emits v2 only. Bounded v1 ingest uses globally unique legacy `key_id`, verifies inner identity, and rejects ambiguous/revoked routing; never issue v1.
- **Keyslot:** exactly one 512-byte `HBSKSLOT`; version 1, flags/reserved/pad zero; nonnil campaign/extractor IDs and public key; `issued_at < expiry`; SHA-256 over bytes `0..480`. Reject absent/multiple/invalid slots. Checksum detects corruption, not trust.
- **Issuance hierarchy:** Campaign → Location → Issuance → Host/Report. Each issuance has unique random extractor ID and independently generated X25519 keypair; `keys.issuance_id UNIQUE NOT NULL`. POST creates issuance/artifact; GET returns same patched bytes and increments downloads. Revocation blocks future ingest/download but preserves mapping/key/history; purge is separate, explicit, confirmed, and audited. Reports derive campaign/location only from issuance. `host_locations` supports host history across locations.
- **Fixed ingest bounds:** raw HTTP body 64 MiB; multipart batch 32 files; envelope 16 MiB; decompressed JSON 64 MiB; JSON depth 32; string 1 MiB; array 10,000; results 1,000 checks. Require exact ciphertext length and no trailing bytes. Push/upload share one typed, atomic `validateAndIngestEnvelope`; validate identity/schema/unique check IDs; normalize nonempty host IDs; recompute summary/score/coverage/audit counts; unique replay `(extractor_id,scan_id)` is idempotent; mixed batches isolate failures; `ingest_events` contains no evidence/secrets.
- **Dashboard contract:** query string is source of truth with `severity`, `category`, `status`, `treatment`, `locationId`, `hostId`, `checkId`, `reportId`, `standard`, `from`, `to`, `via`, `privilege`, `extractorVersion`, `platform`, `evidenceDepth`, `q`; reload/back/share preserve it, with visible chips and clear-all. Scope selector precedes By Host/By Check pivots: latest campaign, one report, or date range. Treat report text as hostile escaped text; no raw HTML/ANSI/control chars/unsafe URL schemes. Copy redacted evidence only.
- **Security claims:** report confidentiality/integrity depends on modern crypto, dashboard private-key protection, RNG, endpoint integrity, and correct implementation. Never claim absolute or “unbreakable.” Executable cannot be encrypted while executable; it is signed/hashed/stripped/optionally obfuscated, contains only a public key, and remains reverse-engineerable. README repeats this.
- **Check IDs/host identity:** IDs remain `LIN-<SEC>-NNN`, `WIN-<SEC>-NNN`, `GEN-INV-NNN`. Normalize machine ID from `/etc/machine-id` or `MachineGuid`; display `hostname:machineid[0..8]`.
- **Dashboard/storage:** bind `127.0.0.1` by default; private key files mode 0600. SQLite migrations are idempotent with foreign keys/indexes. TS strict; Rust denies unsafe operations in unsafe functions and every unsafe block has `// SAFETY:`.
- **Risk/coverage:** server computes `100 * (1 - Σ(wᵢ×failedᵢ)/Σ(wᵢ×applicableᵢ))`, weights 10/6/3/1, excluding Info, N/A, accepted risk, false positive. Coverage = authoritative decided applicable / applicable.

## Review Focus

1. **Malformed/bomb envelope:** short/tampered header or ciphertext, length mismatch/trailing bytes, decompression/JSON limit breach, or mixed batch rejects with stable per-file code and no partial state; valid siblings ingest. → Tasks 44 and 48.
2. **Identity/auth/replay:** unknown, revoked, mismatched outer/inner identity, ambiguous v1 key, wrong token, and duplicate replay never cross-route; constant-time auth and idempotent duplicate are tested. → Tasks 43, 47, 48.
3. **Evidence uncertainty:** denied/missing/localized/tool-absent/conflicting sources exhaust ordered fallbacks into `DegradedPartial`, never false pass/Error; catalog audit catches missing independent fallback/rationale. → Tasks 2, 3, 6, 16–40.
4. **Read-only/offline boundary:** all attempts are audited and redacted; command allowlist rejects writes/network probes; `secedit /export` and temp files cannot run; no `--push` produces zero DNS/socket activity; push preserves exact local bytes on failure. → Tasks 3, 11, 12, 28, 40, 60.
5. **Hostile UI/filter fidelity:** Unicode later-line columns, XSS/control chars/secrets, browser back/reload/share, chart click/Enter/Space, and table twin produce exact URL and API query without unsafe rendering. → Tasks 49, 50, 54, 55.

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

- [ ] **Step 4: Checkpoint** — review diff and verify builds clean. Commit/push happens only on later explicit user request.

---

## Phase 1 — Extractor core

### Task 2: Result model [implemented; amendment required]

**Files:**
- Modify: `extractor/src/model.rs`
- Test: `extractor/tests/model.rs`, `extractor/tests/catalog.rs`

**Interfaces:** retain existing severity/status fields and add:
- `EvidenceDepth { AuthoritativePrimary, AuthoritativeFallback, DegradedPartial }`.
- `SourceType { File, Registry, Command, Api }`.
- `FallbackDescriptor { source_type: SourceType, source: &'static str, authoritative: bool, independent: bool }` and `FallbackPolicy { sources: &'static [FallbackDescriptor], single_source_rationale: Option<&'static str>, manual_verification: Option<&'static str> }` on every `Testcase`.
- `FallbackAttempt { source_type: SourceType, source: String, outcome: String, depth: EvidenceDepth }`.
- `EvidenceBlock { source_type: SourceType, source: String, line: Option<u32>, col: Option<u32>, context_before: Vec<String>, offending_value: String, context_after: Vec<String>, file_mode: Option<u32>, file_uid: Option<u32>, file_gid: Option<u32>, redacted: bool }`.
- `RunContext { user: String, uid: Option<u32>, elevated: bool }`; each `CheckResult` has `evidence_depth`, `evidence_blocks`, and `run_context`.
- `AuditAttempt { source: String, outcome: String }`; `SelfAudit { commands: Vec<AuditAttempt>, files_read: Vec<AuditAttempt> }`.
- Report scan metadata includes 16-byte/UUID `scanId`, `extractorId`, `campaignId`, `keyId`, `catalogFingerprint`, privilege requested/granted/refused/not-needed, peak RSS, and extractor version.
- `catalog_fingerprint(registry) -> [u8;32]`: SHA-256 over deterministic ordered serialization of ID, semantic check version, static criteria, fallback descriptors, severity/category/references. Runtime state is excluded.

- [ ] **Step 1: Add failing serde tests** asserting all discriminants and camelCase field names, optional line/column omission, three separate context fields, `redacted=true`, fallback depth, run context, privilege state, and audit outcomes.
- [ ] **Step 2: Add failing catalog tests** asserting duplicate IDs fail; each check has primary plus independent fallback or complete single-source rationale/manual verification; fingerprint is stable across registry insertion order and changes when criteria/descriptors change.
- [ ] **Step 3: Run** `cargo test --test model --test catalog` and confirm failures name missing fields/validation.
- [ ] **Step 4: Make minimum model/macro/catalog changes**, preserving existing IDs and result meaning. Apply extractor-wide serialization redaction to evidence, source, contexts, fallback outcome, location, and repro.
- [ ] **Step 5: Run** focused tests, then `cargo test`; review diff checkpoint. No commit without explicit user request.

### Task 3: Evidence helpers (read-only enforcement) [implemented; amendment required]

**Files:**
- Modify: `extractor/src/evidence.rs`, `extractor/src/context.rs`, `extractor/src/redact.rs`
- Test: `extractor/tests/evidence.rs`, `extractor/tests/context.rs`, `extractor/tests/redact.rs`

**Locked behavior:**
- Keep `MAX_READ = 1 MiB`; open target data read-only and access it only through `ScanContext` adapters for file, registry, command, and API sources.
- Record a redacted audit attempt **before** allowlist validation/open/spawn. Update outcome after success, missing/denied, rejection, nonzero exit, or timeout. Caching must not erase the original attempt. Metadata reads also route through/audit `ScanContext`.
- Remove network-capable evidence tools such as `nslookup`, remote `showmount`, SSH connection modes, package update/download behavior, and hostname forms that may resolve DNS. Offline checks may inspect local config/cache only. `--push` networking is owned solely by Task 11 and never exposed to checks.
- Reject all unlisted programs and unsupported verbs. Explicit regression cases: `secedit /export`, redirects, PowerShell file/state/network cmdlets, `reg add/delete`, `auditpol /set`, write-capable `netsh`, shell interpreters, and temp-path exports. No sanctioned temp write exists.
- PowerShell/pwsh accepts only exact internal query descriptors, `-NoProfile -NonInteractive -Command`, never user-generated script text. Restricted verbs are validated centrally, not trusted to callers.
- Redaction runs before any string reaches report/audit/log serialization, including secrets/tokens embedded in paths, command args, source, outcome, location, context, and repro.

- [ ] **Step 1: Add failing audit tests** for missing/permission-denied file, rejected command, spawn failure, nonzero exit, timeout, injected success, cached read, and metadata read; assert one ordered redacted attempt and exact outcome.
- [ ] **Step 2: Add failing read-only/offline tests** enumerating every allowlisted program/verb and proving no command descriptor can write, export, redirect, mutate configuration, invoke network/DNS, or include `secedit`. Assert forbidden requests are not spawned.
- [ ] **Step 3: Add secret tests** placing push tokens/password-like values in every serializable locator/outcome field and asserting plaintext never appears.
- [ ] **Step 4: Run** `cargo test --test evidence --test context --test redact`; implement minimum central fixes in `evidence.rs`/`ScanContext`, then rerun focused and full suites.
- [ ] **Step 5: Review diff checkpoint** including static search for direct `File::open`, `fs::read`, `Command::new`, registry/API access outside approved adapters. No commit without explicit user request.

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

### Task 6: Engine runner (never aborts) [implemented; amendment required]

**Files:**
- Modify: `extractor/src/engine.rs`, `extractor/src/checks/mod.rs`, `extractor/src/registry.rs`
- Test: `extractor/tests/engine.rs`, `extractor/tests/catalog.rs`, `extractor/tests/evidence.rs`

**Interfaces:**
- `validate_catalog(&[RegisteredCheck]) -> Result<(), CatalogError>` validates unique IDs and fallback policy before scanning.
- `run_all` records each attempted descriptor, stops only on authoritative evidence, stamps `EvidenceDepth`/`RunContext`, reconciles conflicting authoritative sources to `DegradedPartial`, and continues after each check.
- `degraded_from_attempts(log, reason)` replaces evidence-unavailable `err_outcome`. `Status::Error` constructors remain private to engine/parser invariant failures and caught test-profile panics. Production `panic=abort` means prevention/tests remain required; docs do not promise catchability in release.
- `summarize` and coverage distinguish authoritative decided applicable checks from degraded/error/N/A.

- [ ] **Step 1: Add failing tests** for missing, denied, absent tool, localized/unparseable external output, conflicting sources, authoritative fallback, single-source rationale, and panic/internal corrupt-parser paths. Assert first four are Degraded, conflict is Degraded with both values, panic/corrupt internal state alone is Error.
- [ ] **Step 2: Add whole-catalog test** asserting fallback descriptor quality and stable fingerprint over every registered check.
- [ ] **Step 3: Add evidence regression test** where match is on a later line with multibyte Unicode before the needle; assert correct 1-based scalar column, max/exactly available three lines per side, separate offending value, optional missing location fields, and no line 0.
- [ ] **Step 4: Implement minimum shared changes**, then run `cargo test --test engine --test catalog --test evidence` and full `cargo test`.
- [ ] **Step 5: Review diff checkpoint.** Search check modules for `Status::Error`/`err_outcome`; only internal engine/parser cases may remain. No commit without explicit user request.

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

### Task 8: Crypto envelope [v1 implemented; v2 amendment required]

**Files:**
- Modify: `extractor/src/crypto.rs`
- Test: `extractor/tests/crypto.rs`

**Interfaces:**
- `seal_v2(plaintext, recipient_pub, key_id, extractor_id, suite) -> Result<SealedEnvelope>` emits only Global Constraints v2 and returns generated `scan_id` plus exact bytes. No production v1 sealer remains.
- Header length is 93 bytes. AEAD `Payload.aad` is exact bytes `0..93`; length includes authentication tag and must equal remaining bytes.
- HKDF salt is `scan_id || ephemeral_pub`; info is `HBS-report-v2 || suite || key_id_le || extractor_id`.
- Test-only `unseal_v2` returns plaintext and parsed routing fields. Dashboard Task 44 owns bounded v1 ingest.

- [ ] **Step 1: Add failing tests** for both suites, Unicode JSON, unique random scan IDs/nonces, exact offsets/LE length, extractor ID, AAD mutation at every routing field, ciphertext mutation, unsupported suite/version, header <93, length mismatch, and trailing byte rejection.
- [ ] **Step 2: Pin deterministic HKDF/AAD vectors** with fixed IKM/salt/info; hard-code expected bytes rather than generating expected output from implementation under test.
- [ ] **Step 3: Run** `cargo test --test crypto` and confirm old HBS1 implementation fails v2 assertions.
- [ ] **Step 4: Implement minimum v2 seal/unseal**, then rerun focused/full tests and search production extractor for `HBS1`, `HBS-report-v1`, empty AAD, and 77-byte assumptions; none may govern new issuance.
- [ ] **Step 5: Review diff checkpoint.** No commit without explicit user request.

### Task 9: Keyslot [implemented; strict-validation amendment required]

**Files:**
- Modify: `extractor/src/keyslot.rs`
- Test: `extractor/tests/keyslot.rs`

**Interfaces:** retain 512-byte layout from Global Constraints. `read_own_slot` scans binary once and requires exactly one magic occurrence; `parse` validates structure before returning `SlotData`.

- [ ] **Step 1: Add independent fixture builder** and failing tests for absent slot, placeholder, two slots, unsupported version, nonzero flags, nonzero reserved u16, any nonzero pad byte, nil campaign ID, nil extractor ID, nil public key, `issued_at == expiry`, `issued_at > expiry`, expired timestamp, and checksum corruption.
- [ ] **Step 2: Add valid-boundary tests** for one slot, earliest valid ordering, UUID formatting, and checksum verification. Assert errors are typed/friendly and never call scanning logic twice.
- [ ] **Step 3: Run** `cargo test --test keyslot`; implement exact validation in parse/read path. Checksum remains corruption detection and is never described/used as authenticity.
- [ ] **Step 4: Run** focused/full suites; Task 45’s independent TS parser must consume identical fixtures.
- [ ] **Step 5: Review diff checkpoint.** No commit without explicit user request.

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

### Task 11: Report assembly, CLI, offline push [implemented; amendment required]

**Files:**
- Modify: `extractor/src/report.rs`, `extractor/src/main.rs`, `extractor/src/cli.rs`; create focused `extractor/src/push.rs` only if current main cannot stay small
- Test: `extractor/tests/report.rs`, `extractor/tests/cli.rs`, `extractor/tests/push.rs`

**Interfaces:**
- CLI retains existing selectors and adds documented `--push <url>` and `--push-token-file <path>`; token itself has no CLI flag. `--no-elevate`, `--no-pause`, `--quiet`, hidden `--elevated-child` remain.
- Report contains schema version, v2 `scanId`, slot identities, normalized machine/host identity, catalog fingerprint, peak RSS, full self-audit, privilege requested/granted/refused/not-needed, per-result run context/evidence depth, and server-verifiable summary inputs.
- Flow: parse → priority/platform/keyslot/catalog validation → Task 12 two-phase scan → redact/serialize → `seal_v2` → write requested local path once → optionally read token source and POST exact on-disk sealed bytes. No push code initializes resolver/client without `--push`.
- Push token precedence is an error when both env and file are present, avoiding ambiguity. Token file is read-only through secret-specific code and logged only as redacted source, never content. Push uses Authorization header, 5s connect, 15s transfer, max 2 retries/backoff; every failure leaves local file and returns scan success with push-failed status.

- [ ] **Step 1: Add failing report tests** for all identity/catalog/privilege/evidence-depth/peak-RSS/audit fields and redaction across the complete serialized JSON.
- [ ] **Step 2: Add failing CLI/token tests** for missing token when pushing, env source, file source, both-source rejection, unsupported URL scheme, and proof secret is absent from argv/debug/output/report/audit/keyslot.
- [ ] **Step 3: Add local HTTP fixture tests** proving push begins after successful write, request body byte-equals file, retry/timeouts are bounded, failures retain file, and no retry exceeds two.
- [ ] **Step 4: Add zero-network integration test** using OS/container socket/DNS observation: normal run and failed local sealing without `--push` make zero network calls. Implement minimum changes, then run focused and full tests.
- [ ] **Step 5: Review diff checkpoint.** CLI help/README owner Task 59 must show push/token-file/offline behavior. No commit without explicit user request.

### Task 12: Two-phase least privilege [startup-elevation amendment required]

**Files:**
- Modify: `extractor/src/elevate.rs`, `extractor/src/main.rs`, `extractor/src/engine.rs`
- Test: `extractor/tests/elevate.rs`, Windows integration harness

**Interfaces:**
- `is_elevated()` remains read-only.
- Phase 1 runs every selected nonprivileged or fallback-capable source before any prompt. Engine returns only check/source work still requiring privileged primary evidence.
- On Windows, `request_remaining_with_consent(plan, args)` displays one explicit reason/count, then invokes one UAC `runas` child with hidden `--elevated-child` and a bounded signed/validated remaining-check selection. No startup prompt, loop, bypass, or repeat request. Parent merges results by stable check ID, preserving Phase 1 audit/fallback attempts.
- On `--no-elevate`, denial, cancellation, or launch failure, run remaining read-only fallbacks and produce `DegradedPartial` where unresolved. Report requested/granted/refused/not-needed accurately.
- Linux never invokes `sudo` or re-execs; it finishes unprivileged and prints explicit rerun guidance only when privileged primaries remain.

- [ ] **Step 1: Add failing orchestration tests** proving no request occurs before Phase 1, no request when nothing remains, no request under `--no-elevate`, exactly one request when needed, and selected checks are not rerun unnecessarily.
- [ ] **Step 2: Add denial/cancel/failure tests** asserting scan completes, fallbacks execute, unresolved results are Degraded, local report is written, and privilege fields are exact.
- [ ] **Step 3: Add Windows integration cases** non-elevated granted/denied and already-elevated; add Linux test proving no subprocess named sudo is requested.
- [ ] **Step 4: Implement minimum orchestration**, run focused/full tests and Windows manual matrix.
- [ ] **Step 5: Review diff checkpoint.** No commit without explicit user request.

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

### Task 14: Cross-compile and compatibility matrix [implemented; amendment required]

**Files:**
- Modify: `scripts/build-all.sh`; add/modify CI workflow if repository uses one
- Test: script assertions and target smoke harnesses

- [ ] **Step 1: Add failing gates** requiring `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, and `x86_64-pc-windows-msvc`; optional stretch targets report clearly but do not weaken required gates. Manifest records target, file, SHA-256, size, build time, version, and catalog fingerprint.
- [ ] **Step 2: Build required targets** with size <10 MiB and static-link checks for musl. Unsupported runtime OS/arch fixture exits code 3 with clear text and no write/network attempt.
- [ ] **Step 3: Run capability smoke matrix** across major Debian/RHEL/SUSE/Arch/Alpine families and Windows 10/11/Server 2016–2025 where runners exist; include missing tools/localized output. Hardcoded OS-name branching that bypasses capability probes fails review.
- [ ] **Step 4: Review results checkpoint** with exact sizes/targets. No commit without explicit user request.

### Task 15: Independent cross-language crypto vectors [v1 implemented; v2 amendment required]

**Files:**
- Modify: `extractor/tests/crypto_vectors.rs`, `fixtures/crypto-vectors.json`
- Test: Rust vector consumer plus Task 44 TypeScript consumer

**Interfaces:** fixtures contain immutable inputs/expected bytes for v2 suite 0 and suite 1: recipient private/public keys, ephemeral private/public key, extractor ID, scan ID, key ID, nonce, header/AAD, HKDF key, plaintext, compressed bytes, ciphertext, envelope. Separate fixtures cover legacy-v1 **ingest only**. Expected values must come from an independent implementation or reviewed one-time script, not production sealer output during tests.

- [ ] **Step 1: Add fixed v2 fixtures** for both suites, Unicode/empty payloads, and header/ciphertext mutations; add bounded large-payload hash fixture without storing huge hex.
- [ ] **Step 2: Add legacy v1 ingest fixtures** for unique key success, ambiguous key rejection, revoked key rejection, and inner-identity mismatch. No v1 issuance/seal fixture API.
- [ ] **Step 3: Make Rust and TS consume identical fixture bytes**, assert every intermediate plus exact final bytes, then run both suites.
- [ ] **Step 4: Review fixture checkpoint.** No commit without explicit user request.

---

## Phase 2 — Linux + shared checks

Every check-module task in Phases 2–3 follows this locked contract. Tasks 16–28 are implemented but require catalog-wide amendment; Tasks 29–39 apply it during first implementation.

**Implementation recipe per module (binding on every check):**
1. Preserve stable IDs/criteria. Register immutable ordered `FallbackDescriptor`s with authoritative/independent metadata. Normally provide primary plus an independent read-only fallback; where impossible, include specific rationale and manual read-only verification.
2. Attempt sources in order through `ScanContext`; append every attempt/outcome; stop only when evidence is authoritative. Do not run later fallbacks after authoritative resolution. If authoritative sources conflict, return `DegradedPartial` with both redacted values. Exhausted missing, denied, localized, malformed external output, or absent tools returns `DegradedPartial`, never Error.
3. `Error` is reserved for engine invariant/panic/corrupt internal parser input. No check helper may use Error as “unavailable.” Evidence depth is Primary/Fallback/Degraded; run context is attached by engine.
4. Every locatable NonCompliant result attaches discriminated evidence: redacted source type/locator, optional correct 1-based line/Unicode column, at most three lines before, explicit offending value, at most three after, optional safe metadata, `redacted=true`. Registry/command/API sources use their source type and omit fake coordinates.
5. Tests per module cover compliant, noncompliant, primary absent then fallback success, all unavailable/denied, localized/malformed output, and conflicts where sources can coexist. Assert fallback order, evidence depth, redaction, read-only descriptors, and no false pass. Privileged checks add elevated/non-elevated/denied cases.
6. Whole-catalog audit in Tasks 6/40 fails missing descriptors, duplicate IDs, weak single-source exceptions, write/network-capable sources, locatable NonCompliant results without blocks, and unexpected Error outcomes.

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
        return degraded_from_attempts(log, "sshd config and sshd -T unavailable");
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
Helpers `ok/nok/degraded/degraded_from_attempts` live in `checks/mod.rs` returning `CheckOutcome` (build once in Task 16, reused by every module). Missing, denied, localized, malformed external output, or absent tools return degraded/degraded_from_attempts, never Error.

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

- [ ] **Step 1: Amend helpers**: `ok`, `nok`, `degraded_from_attempts`; remove public unavailable→Error helper. Add discriminated file/registry/command/API evidence builders and centralized serialization redaction.
- [ ] **Step 2: Add failing regressions** for GEN-INV-001/003/007 covering primary/fallback/degraded, missing everything → `DegradedPartial`, conflicting sources, localized command output, and locatable evidence shape.
- [ ] **Step 3: Audit all 25 checks** against binding module recipe; remove network-active sources (`showmount -e localhost` etc.) and replace with local config/API/cache evidence or documented single-source rationale.
- [ ] **Step 4: Run focused and full catalog tests.** Review diff checkpoint; no commit without explicit user request.

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

### Task 28: Docker validation matrix [implemented; amendment required]

**Files:** `scripts/docker-test/run.sh`, existing Docker harness/results

- [ ] **Step 1: Update assertions** from new-output HBS1 to HBS2 and verify v2 header/length/AAD through Task 44 fixtures. Do not require dashboard for local seal success.
- [ ] **Step 2: Run** Ubuntu 24.04, Debian 12, Alpine 3.20, Rocky 9 as root/non-root. Assert exit 0, one report write, <200 MB RSS, no hard Error except injected internal failures, and expected Degraded deltas.
- [ ] **Step 3: Prove offline boundary** by isolating/observing network namespace and DNS: run without `--push` and assert zero socket/DNS attempts. Run explicit push against local fixture, assert exact sealed bytes, retry bound, and retained file on failure.
- [ ] **Step 4: Run fallback-quality audit** over full implemented Linux/shared catalog and store machine-readable results in existing results convention. Review checkpoint; no commit without explicit user request.

---

## Phase 3 — Windows checks

Same recipe as Phase 2; evidence sources are read-only APIs, `reg query`, `auditpol /get`, and `powershell -NoProfile -NonInteractive -Command "<constant query script>"`. `secedit /export` and every other command that writes a file or changes target state are forbidden. Missing evidence yields `Degraded`. All checks `applies: |p| p.os == Os::Windows`. Registry helper in Task 29, reused by all: `fn reg_query_dword(ctx, hive_path: &str, name: &str) -> Option<u32>` and `reg_query_sz(...) -> Option<String>` (parse `reg query` output; fallback PowerShell `Get-ItemProperty`).

### Task 29: WIN-ACC account policies (12 checks) + windows helpers

**Files:**
- Create: `extractor/src/checks/windows/mod.rs`, `extractor/src/checks/windows/account.rs`
- Test: `extractor/tests/checks_windows_account.rs`

**Interfaces:**
- `reg_query_dword(ctx: &mut ScanContext, hive_path: &str, value_name: &str) -> Option<u32>`
- `reg_query_sz(ctx: &mut ScanContext, hive_path: &str, value_name: &str) -> Option<String>`
- `checks::windows::account::register(reg: &mut Vec<RegisteredCheck>)`

| ID | Title | Pass Criteria | Sources (fallback order) |
|---|---|---|---|
| WIN-ACC-001 | Minimum password length | >= 14 | NetUserModalsGet lvl 0 -> `net accounts` -> RSOP reg |
| WIN-ACC-002 | Maximum password age | <= 365 (Never=NonCompliant) | NetUserModalsGet lvl 0 -> `net accounts` -> RSOP reg |
| WIN-ACC-003 | Minimum password age | >= 1 | NetUserModalsGet lvl 0 -> `net accounts` -> RSOP reg |
| WIN-ACC-004 | Password history size | >= 24 | NetUserModalsGet lvl 0 -> `net accounts` -> RSOP reg |
| WIN-ACC-005 | Account lockout threshold | <= 50 and != 0 | NetUserModalsGet lvl 3 -> `net accounts` -> RSOP reg |
| WIN-ACC-006 | Account lockout duration | >= 15 min (TIMEQ_FOREVER=pass) | NetUserModalsGet lvl 3 -> `net accounts` -> RSOP reg |
| WIN-ACC-007 | Reset lockout counter | >= 15 min | NetUserModalsGet lvl 3 -> `net accounts` -> RSOP reg |
| WIN-ACC-008 | Limit blank password use | LimitBlankPasswordUse = 1 | `reg query` System\CurrentControlSet\Control\Lsa |
| WIN-ACC-009 | Password complexity required | Complexity = 1 | RSOP reg -> DegradedPartial if unavailable |
| WIN-ACC-010 | Store passwords with reversible encryption | ClearTextPassword = 0 | RSOP reg -> DegradedPartial if unavailable |
| WIN-ACC-011 | Restrict anonymous access to named pipes/shares | RestrictAnonymous = 1 | `reg query` System\CurrentControlSet\Services\LanmanServer\Parameters |
| WIN-ACC-012 | Restrict anonymous SAM and shares enumeration | RestrictAnonymousSAM = 1 | `reg query` System\CurrentControlSet\Control\Lsa |

- [ ] **Step 1: Write failing unit/integration tests** in `extractor/tests/checks_windows_account.rs` covering compliant/non-compliant values, `TIMEQ_FOREVER` duration handling, missing tools, and localized text.
- [ ] **Step 2: Run test to verify it fails**: `cargo test --test checks_windows_account` fails.
- [ ] **Step 3: Implement registry helpers and account checks** in `extractor/src/checks/windows/`, enforcing read-only commands and `DegradedPartial` on unavailable sources.
- [ ] **Step 4: Run test to verify it passes**: `cargo test --test checks_windows_account` passes.
- [ ] **Step 5: Review checkpoint** — review diff and run tests. No commit without explicit user request.

### Task 30: WIN-AU audit policy (10 checks)

**Files:**
- Create: `extractor/src/checks/windows/audit.rs`
- Test: `extractor/tests/checks_windows_audit.rs`

**Interfaces:**
- `checks::windows::audit::register(reg: &mut Vec<RegisteredCheck>)`

| ID | Title | Pass Criteria | Sources (fallback order) |
|---|---|---|---|
| WIN-AU-001 | Audit Logon | Success and Failure | `auditpol /get /subcategory:"Logon" /r` -> CSV parse |
| WIN-AU-002 | Audit Logoff | Success | `auditpol /get /subcategory:"Logoff" /r` -> CSV parse |
| WIN-AU-003 | Audit Account Logon | Success and Failure | `auditpol /get /subcategory:"Credential Validation" /r` |
| WIN-AU-004 | Audit User Account Management | Success and Failure | `auditpol /get /subcategory:"User Account Management" /r` |
| WIN-AU-005 | Audit Security Group Management | Success and Failure | `auditpol /get /subcategory:"Security Group Management" /r` |
| WIN-AU-006 | Audit Audit Policy Change | Success and Failure | `auditpol /get /subcategory:"Audit Policy Change" /r` |
| WIN-AU-007 | Audit Sensitive Privilege Use | Failure | `auditpol /get /subcategory:"Sensitive Privilege Use" /r` |
| WIN-AU-008 | Audit Process Creation | Success | `auditpol /get /subcategory:"Process Creation" /r` |
| WIN-AU-009 | Audit File Share Access | Failure | `auditpol /get /subcategory:"File Share" /r` |
| WIN-AU-010 | Audit Security System Extension | Success and Failure | `auditpol /get /subcategory:"Security System Extension" /r` |

- [x] **Step 1: Write failing audit tests** in `extractor/tests/checks_windows_audit.rs` covering canned CSV, GUID mapping, missing auditpol, and non-`/get` rejection.
- [x] **Step 2: Run test to verify it fails**: `cargo test --test checks_windows_audit` fails.
- [x] **Step 3: Implement auditpol parser and checks** in `extractor/src/checks/windows/audit.rs`, ensuring no `secedit` export and fallback to `DegradedPartial`.
- [x] **Step 4: Run test to verify it passes**: `cargo test --test checks_windows_audit` passes.
- [x] **Step 5: Review checkpoint** — review diff and run tests. No commit without explicit user request.

### Task 31: WIN-SEC security options (22 checks)

**Files:**
- Create: `extractor/src/checks/windows/sec_options.rs`
- Test: `extractor/tests/checks_windows_sec_options.rs`

**Interfaces:**
- `checks::windows::sec_options::register(reg: &mut Vec<RegisteredCheck>)`

Registry-based checks (HKLM):
- WIN-SEC-001: LmCompatibilityLevel >= 5
- WIN-SEC-002: NoLMHash = 1
- WIN-SEC-003: RequireSecuritySignature Server = 1
- WIN-SEC-004: RequireSecuritySignature Client = 1
- WIN-SEC-005: EnableLUA = 1
- WIN-SEC-006: ConsentPromptBehaviorAdmin >= 2
- WIN-SEC-007: EnableInstallerDetection = 1
- WIN-SEC-008: EnableSecureUIPaths = 1
- WIN-SEC-009: EnableVirtualization = 1
- WIN-SEC-010: ClearVirtualPageFile = 1
- WIN-SEC-011: NoConnectedUser = 3
- WIN-SEC-012: InactivityTimeoutSecs <= 900
- WIN-SEC-013: ScreenSaverIsSecure = 1
- WIN-SEC-014: ScreenSaverTimeout <= 900
- WIN-SEC-015: ForceUnlockLogon = 1
- WIN-SEC-016: DoNotDisplayLastUserName = 1
- WIN-SEC-017: LegalNoticeCaption configured
- WIN-SEC-018: LegalNoticeText configured
- WIN-SEC-019: SMBv1 protocol disabled
- WIN-SEC-020: AutoRestartShell = 0
- WIN-SEC-021: CachedLogonsCount <= 4
- WIN-SEC-022: RestrictNullSessAccess = 1
*(Note: RestrictAnonymous and RestrictAnonymousSAM have single authoritative home in Task 29).*

- [ ] **Step 1: Write failing security options tests** covering valid/invalid registry values, missing keys, and non-elevated behavior.
- [ ] **Step 2: Run test to verify it fails**: `cargo test --test checks_windows_sec_options` fails.
- [ ] **Step 3: Implement registry query checks** in `extractor/src/checks/windows/sec_options.rs`.
- [ ] **Step 4: Run test to verify it passes**: `cargo test --test checks_windows_sec_options` passes.
- [ ] **Step 5: Review checkpoint** — review diff and run tests. No commit without explicit user request.

### Task 32: WIN-UR user rights (16 checks)

**Files:**
- Create: `extractor/src/checks/windows/user_rights.rs`
- Test: `extractor/tests/checks_windows_user_rights.rs`

**Interfaces:**
- `checks::windows::user_rights::register(reg: &mut Vec<RegisteredCheck>)`
- Uses Windows LSA policy APIs (`LsaOpenPolicy` + `LsaEnumerateAccountsWithUserRight`) strictly read-only. No `secedit /export` or disk writes.

Check definitions:
- WIN-UR-001: SeDebugProgramPrivilege (Administrators only)
- WIN-UR-002: SeTcbPrivilege (empty/no accounts)
- WIN-UR-003: SeAssignPrimaryTokenPrivilege (Administrators/LocalSystem only)
- WIN-UR-004: SeIncreaseQuotaPrivilege (Administrators/LocalSystem only)
- WIN-UR-005: SeRemoteShutdownPrivilege (Administrators only)
- WIN-UR-006: SeNetworkLogonRight (excludes Guests/Everyone)
- WIN-UR-007: SeInteractiveLogonRight (excludes Guests)
- WIN-UR-008: SeDenyNetworkLogonRight (includes Guests)
- WIN-UR-009: SeDenyInteractiveLogonRight (includes Guests)
- WIN-UR-010: SeCreatePagefilePrivilege (Administrators only)
- WIN-UR-011: SeLockMemoryPrivilege (empty)
- WIN-UR-012: SeCreateGlobalPrivilege (Administrators/LocalSystem/LocalService/NetworkService)
- WIN-UR-013: SeProfileSingleProcessPrivilege (Administrators only)
- WIN-UR-014: SeMachineAccountPrivilege (empty)
- WIN-UR-015: SeSyncAgentPrivilege (empty)
- WIN-UR-016: SeEnableDelegationPrivilege (empty)

- [ ] **Step 1: Write failing user rights tests** with mocked SID rights mappings and access denied cases.
- [ ] **Step 2: Run test to verify it fails**: `cargo test --test checks_windows_user_rights` fails.
- [ ] **Step 3: Implement LSA policy queries and account lookup** returning `DegradedPartial` on non-elevated or unsupported platforms.
- [ ] **Step 4: Run test to verify it passes**: `cargo test --test checks_windows_user_rights` passes.
- [ ] **Step 5: Review checkpoint** — review diff and run tests. No commit without explicit user request.

### Task 33: WIN-EVT event logs (6 checks)

**Files:**
- Create: `extractor/src/checks/windows/event_logs.rs`
- Test: `extractor/tests/checks_windows_event_logs.rs`

**Interfaces:**
- `checks::windows::event_logs::register(reg: &mut Vec<RegisteredCheck>)`

Check definitions:
- WIN-EVT-001: Application log maxSize >= 32768 KB (`wevtutil gl Application`)
- WIN-EVT-002: Security log maxSize >= 32768 KB (`wevtutil gl Security`)
- WIN-EVT-003: System log maxSize >= 32768 KB (`wevtutil gl System`)
- WIN-EVT-004: Security log retention / AutoBackup configured
- WIN-EVT-005: Security log access permissions restricted
- WIN-EVT-006: Event log channels inventory (Informational)

- [ ] **Step 1: Write failing event log tests** with canned `wevtutil gl` output.
- [ ] **Step 2: Run test to verify it fails**: `cargo test --test checks_windows_event_logs` fails.
- [ ] **Step 3: Implement wevtutil parser and checks** in `extractor/src/checks/windows/event_logs.rs`.
- [ ] **Step 4: Run test to verify it passes**: `cargo test --test checks_windows_event_logs` passes.
- [ ] **Step 5: Review checkpoint** — review diff and run tests. No commit without explicit user request.

### Task 34: WIN-DEF defender & updates (10 checks)

**Files:**
- Create: `extractor/src/checks/windows/defender.rs`
- Test: `extractor/tests/checks_windows_defender.rs`

**Interfaces:**
- `checks::windows::defender::register(reg: &mut Vec<RegisteredCheck>)`

Check definitions:
- WIN-DEF-001: Defender Antivirus enabled and running
- WIN-DEF-002: Real-time protection enabled
- WIN-DEF-003: Behavior monitoring enabled
- WIN-DEF-004: Script scanning enabled
- WIN-DEF-005: PUA protection enabled
- WIN-DEF-006: Tamper protection enabled (single authoritative home in Task 34)
- WIN-DEF-007: Signature update age <= 7 days
- WIN-DEF-008: Attack Surface Reduction (ASR) rules active count
- WIN-DEF-009: Windows Update hotfix age <= 90 days
- WIN-DEF-010: Windows Update NoAutoUpdate = 0

- [ ] **Step 1: Write failing defender and update tests** with mocked PowerShell JSON outputs.
- [ ] **Step 2: Run test to verify it fails**: `cargo test --test checks_windows_defender` fails.
- [ ] **Step 3: Implement PowerShell query parsers and checks** in `extractor/src/checks/windows/defender.rs`.
- [ ] **Step 4: Run test to verify it passes**: `cargo test --test checks_windows_defender` passes.
- [ ] **Step 5: Review checkpoint** — review diff and run tests. No commit without explicit user request.

### Task 35: WIN-SVC services (20 checks)

**Files:**
- Create: `extractor/src/checks/windows/services.rs`
- Test: `extractor/tests/checks_windows_services.rs`

**Interfaces:**
- `checks::windows::services::register(reg: &mut Vec<RegisteredCheck>)`

Check definitions (`sc qc` / `Get-Service`):
- WIN-SVC-001: Telnet service disabled or absent
- WIN-SVC-002: TFTP service disabled or absent
- WIN-SVC-003: RemoteRegistry service disabled
- WIN-SVC-004: Print Spooler service disabled if unused (single authoritative home in Task 35; PrintNightmare rationale)
- WIN-SVC-005: Fax service disabled or absent
- WIN-SVC-006: SMBv1 driver disabled
- WIN-SVC-007: WPADSVC (WinHTTP Web Proxy Auto-Discovery) disabled
- WIN-SVC-008: SNMP service disabled or absent
- WIN-SVC-009: RemoteAccess (Routing and Remote Access) service disabled
- WIN-SVC-010: SSDPSRV (SSDP Discovery) disabled
- WIN-SVC-011: upnphost (UPnP Device Host) disabled
- WIN-SVC-012: Wecsvc (Windows Event Collector) evaluated
- WIN-SVC-013: W3SVC (IIS Admin) evaluated
- WIN-SVC-014: msftpsvc (FTP Service) disabled or absent
- WIN-SVC-015: Xbox Live services disabled
- WIN-SVC-016: SysMain (Superfetch) evaluated
- WIN-SVC-017: Bluetooth Audio/Support service evaluated
- WIN-SVC-018: Peer Name Resolution Protocol (PNRPsvc) disabled
- WIN-SVC-019: Link-Layer Topology Discovery (lltdsvc) disabled
- WIN-SVC-020: Unnecessary Auto-start services inventory (Informational)

- [ ] **Step 1: Write failing service query tests** with canned `sc qc` and `Get-Service` outputs.
- [ ] **Step 2: Run test to verify it fails**: `cargo test --test checks_windows_services` fails.
- [ ] **Step 3: Implement service checks** in `extractor/src/checks/windows/services.rs`.
- [ ] **Step 4: Run test to verify it passes**: `cargo test --test checks_windows_services` passes.
- [ ] **Step 5: Review checkpoint** — review diff and run tests. No commit without explicit user request.

### Task 36: WIN-REG/PERMS filesystem and registry permissions (10 checks)

**Files:**
- Create: `extractor/src/checks/windows/perms.rs`
- Test: `extractor/tests/checks_windows_perms.rs`

**Interfaces:**
- `checks::windows::perms::register(reg: &mut Vec<RegisteredCheck>)`

Check definitions:
- WIN-REG-001: HKLM\SAM ACL restricted to Administrators and SYSTEM
- WIN-REG-002: HKLM\SECURITY ACL restricted to Administrators and SYSTEM
- WIN-REG-003: HKLM\SYSTEM ACL restricted to Administrators and SYSTEM
- WIN-REG-004: %SystemRoot% directory permissions non-world-writable
- WIN-REG-005: %ProgramFiles% directory permissions non-world-writable
- WIN-REG-006: %SystemRoot%\System32 permissions non-world-writable
- WIN-REG-007: %SystemDrive%\PerfLogs directory permissions restricted
- WIN-REG-008: Run and RunOnce registry startup inventory (Informational)
- WIN-REG-009: Startup folder permissions and inventory (Informational)
- WIN-REG-010: Unquoted service paths detection (Medium)

- [ ] **Step 1: Write failing permission tests** with mocked `Get-Acl` SDDL outputs.
- [ ] **Step 2: Run test to verify it fails**: `cargo test --test checks_windows_perms` fails.
- [ ] **Step 3: Implement ACL and path checks** in `extractor/src/checks/windows/perms.rs`.
- [ ] **Step 4: Run test to verify it passes**: `cargo test --test checks_windows_perms` passes.
- [ ] **Step 5: Review checkpoint** — review diff and run tests. No commit without explicit user request.

### Task 37: WIN-NET network hardening (18 checks)

**Files:**
- Create: `extractor/src/checks/windows/network.rs`
- Test: `extractor/tests/checks_windows_network.rs`

**Interfaces:**
- `checks::windows::network::register(reg: &mut Vec<RegisteredCheck>)`

| ID | Title | Pass Criteria | Sources (fallback order) |
|---|---|---|---|
| WIN-NET-001 | Domain firewall profile enabled | State = ON | `netsh advfirewall show domainprofile` -> reg query |
| WIN-NET-002 | Private firewall profile enabled | State = ON | `netsh advfirewall show privateprofile` -> reg query |
| WIN-NET-003 | Public firewall profile enabled | State = ON | `netsh advfirewall show publicprofile` -> reg query |
| WIN-NET-004 | Inbound default block | Inbound = Block | `netsh advfirewall show allprofiles` -> reg query |
| WIN-NET-005 | mDNS disabled | EnableMDNS = 0 | `reg query` HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters |
| WIN-NET-006 | LLMNR disabled | EnableMulticast = 0 | `reg query` HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient |
| WIN-NET-007 | WPAD DisableAutoProxyCache | DisableAutoProxyCache = 1 | `reg query` HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings |
| WIN-NET-008 | WPAD WinHttpDisable | WinHttpDisable = 1 | `reg query` HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp |
| WIN-NET-009 | RDP fDenyTSConnections configured | fDenyTSConnections = 1 or documented | `reg query` HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server |
| WIN-NET-010 | RDP Network Level Authentication | UserAuthentication = 1 | `reg query` HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp |
| WIN-NET-011 | RDP SecurityLayer configured | SecurityLayer >= 1 | `reg query` HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp |
| WIN-NET-012 | RDP MinEncryptionLevel | MinEncryptionLevel >= 2 | `reg query` HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp |
| WIN-NET-013 | RDP DisableClipboardRedirection | fDisableClip = 1 | `reg query` HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services |
| WIN-NET-014 | RDP DisableDriveRedirection | fDisableCdm = 1 | `reg query` HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services |
| WIN-NET-015 | WinRM AllowUnencrypted = 0 | AllowUnencrypted = 0 | `reg query` HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service |
| WIN-NET-016 | WinRM TrustedHosts restricted | TrustedHosts not "*" | `reg query` HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client |
| WIN-NET-017 | LDAP client signing | LDAPClientIntegrity >= 1 | `reg query` HKLM\SYSTEM\CurrentControlSet\Services\LDAP |
| WIN-NET-018 | RestrictSendingNTLMTraffic | RestrictSendingNTLMTraffic >= 1 | `reg query` HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 |

- [ ] **Step 1: Write failing network configuration tests** in `extractor/tests/checks_windows_network.rs` covering firewall parsing and registry settings.
- [ ] **Step 2: Run test to verify it fails**: `cargo test --test checks_windows_network` fails.
- [ ] **Step 3: Implement network hardening checks** in `extractor/src/checks/windows/network.rs`.
- [ ] **Step 4: Run test to verify it passes**: `cargo test --test checks_windows_network` passes.
- [ ] **Step 5: Review checkpoint** — review diff and run tests. No commit without explicit user request.

### Task 38: WIN-TH credential protection & ransomware posture (14 checks)

**Files:**
- Create: `extractor/src/checks/windows/threat_creds.rs`
- Test: `extractor/tests/checks_windows_threat_creds.rs`

**Interfaces:**
- `checks::windows::threat_creds::register(reg: &mut Vec<RegisteredCheck>)`

Check definitions:
- WIN-TH-001: LSA Protection RunAsPPL = 1 and RunAsPPLBoot
- WIN-TH-002: Credential Guard configured and active
- WIN-TH-003: Hypervisor-protected Code Integrity (HVCI) enabled
- WIN-TH-004: Microsoft vulnerable driver blocklist enabled
- WIN-TH-005: Application control policy active (WDAC or AppLocker)
- WIN-TH-006: WDigest UseLogonCredential = 0
- WIN-TH-007: AutoAdminLogon disabled and no default password
- WIN-TH-008: Saved credentials inventory (cmdkey)
- WIN-TH-009: LSA security packages inventory
- WIN-TH-010: ASR Rule - Block credential stealing from LSASS
- WIN-TH-011: ASR Rule - Block process creation from PSExec and WMI
- WIN-TH-012: ASR Rule - Block execution of vulnerable signed drivers
- WIN-TH-013: Controlled Folder Access enabled
- WIN-TH-014: PowerShell Script Block Logging enabled
*(Note: Tamper protection is authoritatively in Task 34).*

- [ ] **Step 1: Write failing threat/credential tests** covering registry/ASR inputs.
- [ ] **Step 2: Run test to verify it fails**: `cargo test --test checks_windows_threat_creds` fails.
- [ ] **Step 3: Implement credential protection and ransomware checks** in `extractor/src/checks/windows/threat_creds.rs`.
- [ ] **Step 4: Run test to verify it passes**: `cargo test --test checks_windows_threat_creds` passes.
- [ ] **Step 5: Review checkpoint** — review diff and run tests. No commit without explicit user request.

### Task 39: WIN-TH persistence hunting + EOL (13 checks)

**Files:**
- Create: `extractor/src/checks/windows/threat_persist.rs`
- Test: `extractor/tests/checks_windows_threat_persist.rs`

**Interfaces:**
- `checks::windows::threat_persist::register(reg: &mut Vec<RegisteredCheck>)`

Check definitions:
- WIN-TH-015: IFEO Debugger hijacking sweep
- WIN-TH-016: Startup folder anomalous executable inventory
- WIN-TH-017: Scheduled tasks running from temporary or user paths
- WIN-TH-018: Services with binary paths in user-writable directories
- WIN-TH-019: WMI permanent event subscriptions detection
- WIN-TH-020: Non-default hosts file redirection entries
- WIN-TH-021: Inbound firewall rules targeting executables in user paths
- WIN-TH-022: Netsh helper DLL registration persistence sweep
- WIN-TH-023: Fax Service (FxSSVC) disabled
- WIN-TH-024: Operating system End-of-Life build check
- WIN-TH-025: Patch staleness exceeds 180 days
- WIN-TH-026: LAPS policy configured on domain hosts
- WIN-TH-027: Local Administrator accounts count <= 1
*(Note: Print Spooler service is authoritatively checked in Task 35; Fax service check is placed here).*

- [ ] **Step 1: Write failing persistence and EOL tests** covering registry, WMI query output, and EOL build tables.
- [ ] **Step 2: Run test to verify it fails**: `cargo test --test checks_windows_threat_persist` fails.
- [ ] **Step 3: Implement persistence and EOL hunting checks** in `extractor/src/checks/windows/threat_persist.rs`.
- [ ] **Step 4: Run test to verify it passes**: `cargo test --test checks_windows_threat_persist` passes.
- [ ] **Step 5: Review checkpoint** — review diff and run tests. No commit without explicit user request.

### Task 40: Windows local validation and catalog gate

- [ ] Run non-elevated first and assert no startup UAC. Exercise `--no-elevate`, one consent/grant, one decline/cancel, and already-elevated flows; all complete and seal locally, with exact privilege/evidence-depth/Degraded reporting.
- [ ] Run Windows 10/11 and Server 2016–2025 compatibility fixtures/runners, including missing tools, localized `net accounts`/audit output, denied registry/API access, and x64 required target. Assert no `secedit /export`, temp evidence file, state-changing command, or silent elevation.
- [ ] Run whole-catalog fallback/evidence audit for Tasks 16–39: ordered descriptors, independent fallback or rationale, all attempts recorded, no availability→Error, all locatable NonCompliant findings blocked correctly, and all source strings redacted.
- [ ] Prove zero DNS/socket activity without `--push`; validate local report HBS2 and Task 48 decrypt. Record result in existing Windows test-results convention and review checkpoint. No commit without explicit user request.

---

## Phase 4 — Dashboard backend

### Task 41: Bun server scaffold + authoritative DB schema

**Files:**
- Create/modify: `dashboard/server/db.ts`, `dashboard/server/index.ts`
- Test: `dashboard/server/db.test.ts`

**Schema contract:** enable `PRAGMA foreign_keys=ON`; versioned migrations are transactional/idempotent. Keep users/sessions/comments/token tables, then enforce:
- `campaigns`: ID/name/client/scope/expiry/status, tags JSON, retention policy, timestamps.
- `locations`: FK campaign, unique `(campaign_id,name)`, tags JSON, `retired_at`, timestamps.
- `issuances`: immutable `id` plus `extractor_id UNIQUE NOT NULL`, FK campaign/location, `key_id`, platform, artifact path/hash/size, expiry/created, download count, revoked timestamp/reason/actor. Unique legacy routing index on `key_id` only for marked v1 records.
- `keys`: `issuance_id UNIQUE NOT NULL` FK issuance, public key, private-key path, created; never cascade-delete historical key on revocation.
- `hosts`: globally normalized `machine_id UNIQUE NOT NULL`, latest hostname/platform/OS/arch and first/last seen.
- `host_locations`: FKs host/location, first/last seen, `PRIMARY KEY(host_id,location_id)`.
- `reports`: FK issuance/host/location/campaign, `extractor_id`, `scan_id`, schema/catalog fingerprint, sealed envelope and validated JSON, score/coverage/summary counts, scan/received timestamps, via, durations, bytes, peak RSS, privilege/evidence-depth metrics; `UNIQUE(extractor_id,scan_id)`.
- `ingest_events`: `received_at`, via, envelope bytes, duration, accepted/rejected, stable reason code, optional report/issuance FKs; no evidence/secrets.
- `finding_states` current projection plus append-only `finding_state_history` with actor/time/from/to/justification/assignee/due date.
- `saved_views`: owner FK, campaign optional FK, name, scope/query JSON, visibility `personal|team`, timestamps; uniqueness by owner/name/scope.
- append-only `audit_log`: actor/IP/action/resource/details-redacted/timestamp.
- `settings`: retention/freshness SLA; backup metadata table. Add indexes for every FK, report scope/time, latest host, finding filters, ingest status/time, and audit time.

**Server interface & Optional TLS:** Default bind is `127.0.0.1:3000`. Optional TLS enabled via CLI flags `--tls-cert <path> --tls-key <path>` or env vars `HBS_TLS_CERT`, `HBS_TLS_KEY`. When TLS is active, compute and print certificate SHA-256 fingerprint to stdout on startup.

- [ ] **Step 1: Write failing migration tests** for fresh DB, upgrade from old schema fixture, FK rejection, required one-to-one key, duplicate replay, cross-location host mapping, append-only history/audit triggers, retired location, and idempotent rerun.
- [ ] **Step 2: Add destructive-migration rollback test**: injected failure leaves old DB intact; startup reports migration version clearly.
- [ ] **Step 3: Implement minimum migrations and indexes**, bind 127.0.0.1 by default, support optional `--tls-cert`/`--tls-key`, then run `bun test dashboard/server/db.test.ts` twice against same DB.
- [ ] **Step 4: Inspect schema/index/FK lists** and review checkpoint. No commit without explicit user request.

### Task 42: Auth (setup wizard, login, sessions, rate limit)

**Files:**
- Create/modify: `dashboard/server/auth.ts`, `dashboard/server/users.ts`
- Test: `dashboard/server/auth.test.ts`

**Interfaces:**
- `POST /api/auth/setup {username,password}` → 409 if users exist; creates super_admin with `Bun.password.hash(pw,{algorithm:"argon2id"})`; sets session.
- `POST /api/auth/login` → argon2 verify; rate limit: max 5 failures/15 min per username+IP (in-memory map) → 429; on success cookie `hbs_session` (HttpOnly, SameSite=Lax) = raw token; DB stores sha256(token).
- `POST /api/auth/logout`; `GET /api/auth/status` → `{initialized, user?, role?}`.
- Middleware `requireRole(...roles)`; `requireAuth`.
- `GET/POST/PATCH/DELETE /api/users` (super_admin) — deactivate (never delete last super_admin), reset password, change role.

- [ ] **Step 1: Write failing auth tests** covering setup wizard (first user super_admin, second call 409), login verification with argon2id, wrong password 401, rate-limiting lockout (429 on >5 failures/15 min), session cookie issuance (`HttpOnly`, `SameSite=Lax`), role middleware enforcement (`auditor` denied on `/api/users`), and last-super-admin deactivation prevention.
- [ ] **Step 2: Run test to verify it fails**: `bun test dashboard/server/auth.test.ts` fails with missing routes.
- [ ] **Step 3: Implement minimum auth and user management code**, argon2id hashing, in-memory rate limiter, session token hashing, and role middleware.
- [ ] **Step 4: Run test to verify it passes**: `bun test dashboard/server/auth.test.ts` passes.
- [ ] **Step 5: Review checkpoint** — review diff and run auth tests. No commit without explicit user request.

### Task 43: Per-issuance keys, revocation, encrypted backup

**Files:** `dashboard/server/keys.ts`; tests.

**Interfaces:**
- `keygen()` uses OS RNG and returns one new X25519 pair per issuance; reject nil/duplicate public key and never derive/reuse a campaign key.
- `saveKey(issuanceId, privRaw)` writes `server/data/keys/<issuanceId>.key` mode 0600 atomically; DB inserts `keys.issuance_id UNIQUE NOT NULL` in same issuance transaction. `loadPriv` requires issuance mapping.
- `revokeIssuance(id,{reason,actor})` sets revoked timestamp/reason/actor, blocks later ingest/download, retains key/artifact/mapping, and appends audit event. It is not DELETE.
- `purgeIssuance(id, confirmation)` is separate super-admin API, requires typed extractor ID plus second confirmation, checks retention/legal hold, and records irreversible audit metadata before deletion.
- Encrypted backup/restore includes SQLite plus key directory, authenticated manifest/hashes/version, passphrase-based memory-hard KDF and AEAD; restore verifies/decrypts into staging, validates DB/key one-to-one, then atomically swaps. Passphrase never logged/stored.

- [ ] **Step 1: Add failing tests** for unique random pairs across issuances, 0600 mode, rollback orphan cleanup, key retention after revocation, download/ingest block, purge confirmation/role/audit, and no shared campaign key.
- [ ] **Step 2: Add backup tests** correct passphrase round-trip, wrong passphrase/tamper rejection, missing/extra key rejection, old backup version handling, and atomic rollback.
- [ ] **Step 3: Implement minimum key/revoke/backup paths**, run focused tests, inspect audit records for no secrets.
- [ ] **Step 4: Review checkpoint.** No commit without explicit user request.

### Task 44: Bounded envelope parser/decryptor (TS)

**Files:** `dashboard/server/envelope.ts`; `dashboard/server/envelope.test.ts`; consume Task 15 fixtures. Use installed/platform zstd support; add no dependency unless current runtime cannot satisfy bounded decompression.

**Interfaces:**
```ts
type ParsedEnvelope =
  | {version: 2; suite: 0|1; keyId: number; extractorId: Uint8Array; scanId: Uint8Array; ephemeralPub: Uint8Array; nonce: Uint8Array; ciphertext: Uint8Array; aad: Uint8Array}
  | {version: 1; suite: 0|1; keyId: number; scanId: Uint8Array; ephemeralPub: Uint8Array; nonce: Uint8Array; ciphertext: Uint8Array};
parseEnvelope(bytes: Uint8Array): ParsedEnvelope;
unsealEnvelope(parsed: ParsedEnvelope, privRaw: Uint8Array, limits: IngestLimits): Uint8Array;
```
- Parser enforces fixed 16 MiB envelope limit, exact minimum header by version, suite/version, LE length ≤ safe/buffer range, exact remaining ciphertext/no trailing bytes, and nonnil routing fields. v2 uses exact 93-byte AAD and v2 HKDF info. v1 is accepted only by Task 48 migration route.
- Decompression is streaming/bounded to 64 MiB; abort on limit before allocating claimed output. Typed errors expose stable code, not crypto internals.

- [ ] **Step 1: Consume independent vectors** for both v2 suites and legacy v1; assert exact parsed fields/AAD/plaintext.
- [ ] **Step 2: Add mutation/table tests** every truncation boundary, magic/version/suite, huge/overflow/short/long length, trailing bytes, routing-header bit flip, tag/ciphertext tamper, zstd bomb/malformed frame, and output bound.
- [ ] **Step 3: Implement minimum parser/decryptor**, run envelope tests and Rust vectors.
- [ ] **Step 4: Review checkpoint.** Search for HBS1 issuance or unbounded decompression; only migration ingest may retain HBS1. No commit without explicit user request.

### Task 45: Strict binary patcher and immutable artifact

**Files:** `dashboard/server/patcher.ts`; `dashboard/server/patcher.test.ts`.

**Interfaces:** `findOnlySlot` requires exactly one 512-byte placeholder; `patch` validates all Task 9 fields and writes a copy, zeroing all reserved bytes and computing SHA-256. `createArtifact` atomically stores patched bytes under issuance ID and returns `{path,sha256,size}`; later GET streams those exact bytes.

- [ ] **Step 1: Reuse independent Task 9 fixtures** to test zero/one/two slots, truncated slot, non-placeholder/double patch, nil IDs/key, bad timestamp order, unsupported values, reserved bytes, checksum, and Rust/TS parse agreement.
- [ ] **Step 2: Add immutable artifact test**: POST-time patch writes once; repeated GET byte-equals/hash-equals original despite source binary changes and increments only download count.
- [ ] **Step 3: Implement minimum patch/artifact logic**, run focused tests and cross-language slot tests.
- [ ] **Step 4: Review checkpoint.** No commit without explicit user request.

### Task 46: Campaigns, locations, tokens, retention routes

**Files:**
- Create/modify: `dashboard/server/campaigns.ts`, `dashboard/server/locations.ts`
- Test: `dashboard/server/campaigns.test.ts`

**Interfaces:**
- `GET/POST /api/campaigns`: list/create campaigns (name, client, scope, expiry, tags array, retention policy). Creating campaign atomically generates download and push tokens, returning raw tokens once. DB stores `sha256(token)`.
- `GET/PATCH /api/campaigns/:id`: get/update metadata, rotate download or push token (returns new raw token once; audits actor and timestamp).
- `POST /api/campaigns/:id/locations`: create location (name, tags array). Atomic with initial campaign creation when requested.
- `PATCH /api/campaigns/:id/locations/:loc`: update tags or soft-retire (`retired_at`). Soft-retired locations block new issuances.
- `POST /api/campaigns/:id/retention/dry-run`: super-admin preview of expired reports and unlinked entities according to policy.
- `POST /api/campaigns/:id/retention/apply`: super-admin execute retention cleanup with explicit confirmation text, respecting legal holds and key retention.

- [ ] **Step 1: Write failing campaign and location route tests** covering CRUD, one-time raw token return, constant-time token verification, tag filtering, soft-retire blocking new issuances, viewer authorization blocks, retention dry-run, and retention apply audit logging.
- [ ] **Step 2: Run test to verify it fails**: `bun test dashboard/server/campaigns.test.ts` fails with 404s.
- [ ] **Step 3: Implement minimum campaign and location routes**, token hashing, soft-retire logic, and retention policies.
- [ ] **Step 4: Run test to verify it passes**: `bun test dashboard/server/campaigns.test.ts` passes.
- [ ] **Step 5: Review checkpoint** — review diff and run campaign tests. No commit without explicit user request.

### Task 47: Immutable issuance creation and downloads

**Files:**
- Create/modify: `dashboard/server/downloads.ts`, `dashboard/server/issuances.ts`
- Test: `dashboard/server/downloads.test.ts`

**Interfaces:**
- `POST /api/campaigns/:id/locations/:loc/issuances {platform,expiry}`: requires auditor+ role; validates active campaign/location; generates random 16-byte `extractor_id` and fresh X25519 keypair; patches pre-compiled base template binary with keyslot; writes immutable artifact to `server/data/binaries/<issuance_id>`; transactionally stores issuance, public key, artifact path, SHA-256 hash, and size. Returns issuance metadata with download URL `/api/issuances/:id/download`.
- `GET /api/issuances/:id/download`: accepts session cookie or download token; verifies issuance is active, unexpired, and not revoked; streams exact stored artifact bytes with matching SHA-256 header; increments `download_count`. (Also accepts alias `GET /api/campaigns/:id/locations/:loc/issuances/:issuance_id/download`).
- `GET /api/campaigns/:id/locations/:loc/issuances`: lists issuances with platform, artifact SHA-256, download count, expiry, revoked status, and version staleness warning.
- `DELETE /api/campaigns/:id/issuances/:extractor_id`: binding revocation route per Ruling 7; marks issuance revoked with timestamp, reason, actor; deletes private key file; blocks future downloads and report ingest; past reports remain queryable.

- [ ] **Step 1: Write failing issuance creation and download tests** covering atomic issuance generation with unique keypair and patched artifact, GET streaming identical bytes/checksum, download count increment, revoked issuance download rejection, expired issuance rejection, cross-campaign token denial, and revocation route deleting key file.
- [ ] **Step 2: Run test to verify it fails**: `bun test dashboard/server/downloads.test.ts` fails with missing endpoints.
- [ ] **Step 3: Implement minimum issuance creation, binary artifact persistence, streaming download, and revocation endpoints**.
- [ ] **Step 4: Run test to verify it passes**: `bun test dashboard/server/downloads.test.ts` passes.
- [ ] **Step 5: Review checkpoint** — review diff and run download tests. No commit without explicit user request.

### Task 48: Unified bounded ingest, automatic routing, metrics, SSE

**Files:** `dashboard/server/ingest.ts`, `dashboard/server/metrics.ts`, `dashboard/server/sse.ts`, `dashboard/server/hosts.ts`; `dashboard/server/ingest.test.ts`.

**Interface:**
```ts
type Via = "push" | "upload";
type IngestResult =
  | {ok:true; duplicate:boolean; reportId:number; campaignId:string; locationId:string; hostId:number; links:{campaign:string; location:string; host:string; report:string}}
  | {ok:false; code:RejectionCode};
async function validateAndIngestEnvelope(bytes: Uint8Array, via: Via, auth: PushAuth|SessionAuth): Promise<IngestResult>;
```
Both endpoints call only this pipeline. Push requires exactly one raw body and token from Authorization header; upload allows ≤32 file parts and processes each independently.

1. Enforce all fixed body/envelope/decompression/JSON depth/string/array/check bounds and exact ciphertext/no trailing bytes before costly work.
2. Parse v2 extractor ID/key ID and resolve one active issuance. V1 resolves only globally unique legacy key ID, then verifies inner identity; reject ambiguous/revoked. Constant-time token hash comparison is scoped to resolved campaign/issuance.
3. Decrypt, bounded-decompress, parse/schema validate; require unique valid check IDs, nonempty normalized machine/host IDs, and exact outer/inner extractor/campaign/key cross-binding.
4. Derive campaign/location **only** from authenticated issuance. Ignore/reject client/report routing claims. Normalize/upsert machine, preserve hostname history, map `host_locations`, and keep duplicate hostnames with different machine IDs separate.
5. Recompute summary, score, coverage, self-audit counts, decided/error/degraded, privilege/evidence-depth, and telemetry server-side. Never trust supplied aggregates.
6. In one transaction insert report/results/host-location/history/ingest event and auto-resolution history. Unique `(extractor_id,scan_id)` returns original links idempotently. Rejection writes only redacted ingest event and no host/report/orphan mapping.
7. After commit, invalidate/update issuance-derived location inventory/summary/findings/telemetry and emit SSE containing IDs/links, never evidence.

- [ ] **Step 1: Write failing bounds/typed-error tests** covering all Review Focus malformed/bomb cases, exact body/file counts, schema versions, duplicate check IDs, nonempty normalized IDs, aggregate tampering, and no partial rows.
- [ ] **Step 2: Write failing auth/migration tests** wrong/missing token, timing-safe equal-length handling, unknown/revoked/mismatched v2, valid/ambiguous/revoked/mismatched v1, and idempotent duplicate replay.
- [ ] **Step 3: Write failing routing tests** automatic placement from issuance for upload and push; hostname rename preserves history/host ID; duplicate hostname creates distinct hosts; same machine across locations creates `host_locations`; mixed campaigns/locations batch routes each independently; exact campaign/location/host/report links; rejected item leaves no orphan.
- [ ] **Step 4: Implement minimum pipeline/transaction**, then run focused tests plus Task 15/44 vectors. Verify ingest events omit evidence/secrets.
- [ ] **Step 5: Review checkpoint.** No commit without explicit user request.

### Task 49: Scoped query API, reports, summaries, treatment, telemetry

**Files:** `dashboard/server/reports.ts`, `dashboard/server/metrics.ts`; tests.
- One validated query parser owns canonical parameters from Global Constraints. Every report/findings/host/check/summary/chart/telemetry endpoint applies identical scope and filters. Scope is required: latest campaign state, one `reportId`, or inclusive `from`/`to` date range.
- APIs cover global overview, campaign summary, findings explorer, reports, location host inventory, host/check/report detail, By Host/By Check pivots, diff, treatment board, standards/references, telemetry/freshness, saved views, and diagnostic download.
- Every result returns immutable campaign/location/host/report IDs and exact links derived from stored issuance routing. Location summary/inventory/findings/telemetry reflects a successful Task 48 ingest immediately.
- Metrics are server-authoritative: scan count/rate, received time, upload/push, scan/ingest p50/p95, bytes, RSS, coverage, decided/error/degraded, commands/files, privilege/evidence-depth, platform/arch/OS/location/version, freshness, accepted/rejected reasons. Add stale-version, SLA, low-coverage/data-quality banners.
- Treatment current state plus append-only history; accepted-risk/false-positive require justification; auto-resolve appends history. Saved views preserve owner/scope/visibility/query. Diagnostic bundle is redacted.

- [ ] **Step 1: Add exact query tests** for every canonical parameter, invalid combinations, latest/report/date scopes, pagination/order, and SQL parameterization. Assert chart/table endpoints agree under same query.
- [ ] **Step 2: Add routing visibility tests** automatic placement, hostname rename/history, duplicate hostname, same machine across locations, mixed campaign/location batch, exact links, and no unknown/revoked orphan surfaced.
- [ ] **Step 3: Add hand-computed metric/treatment tests** risk/coverage/recomputed counts, accepted-risk exclusions, append-only changes/auto-resolve, p50/p95, freshness/version/data-quality, standards coverage, saved-view authorization, and redacted diagnostic output.
- [ ] **Step 4: Implement minimum APIs**, run focused tests, and review SQL/index plans for common filters.
- [ ] **Step 5: Review checkpoint.** No commit without explicit user request.

---

## Phase 5 — Frontend

### Task 50: Vite/React scaffold, typed API, auth, URL filter state

**Files:**
- Create/modify: `dashboard/src/api.ts`, `dashboard/src/types.ts`, `dashboard/src/filters.ts`, `dashboard/src/pages/Login.tsx`, `dashboard/src/pages/Setup.tsx`
- Test: `dashboard/src/filters.test.ts`, `dashboard/tests/auth.spec.ts`

**Interfaces:**
- `useScopeFilters()`: parses/serializes URL parameters (`scope`, `reportId`, `from`, `to`, `severity`, `status`, `category`, `search`, `location`, `platform`, `via`, `privilege`, `version`, `treatment`); returns active filter state, setter functions, chips, and clear-all.
- `apiClient`: typed client wrapping backend endpoints with credential/cookie handling and error normalization.

- [ ] **Step 1: Write unit tests for URL filter parsing and canonicalization** in `dashboard/src/filters.test.ts` (round-trip params, repeated values, canonical sorting, clear-all).
- [ ] **Step 2: Run test to verify it fails**: `bun test dashboard/src/filters.test.ts` fails.
- [ ] **Step 3: Implement `filters.ts`, types, API client, and Login/Setup components**.
- [ ] **Step 4: Run test to verify it passes**: `bun test dashboard/src/filters.test.ts` passes.
- [ ] **Step 5: Review checkpoint** — review diff and run auth Playwright tests. No commit without explicit user request.

### Task 51: App shell + Global Overview

**Files:**
- Create/modify: `dashboard/src/components/Layout.tsx`, `dashboard/src/components/Navigation.tsx`, `dashboard/src/pages/Overview.tsx`, `dashboard/src/components/KpiTile.tsx`
- Test: `dashboard/tests/overview.spec.ts`

**Interfaces:**
- Navigation layout with accessible light/dark theme toggle, route highlights, and role-gated Admin link.
- Global Overview page rendering server-aggregated KPI tiles (Total Campaigns, Active Locations, Scanned Hosts, Critical Findings, Open Findings, Compliance Score) and risk trend sparkline.

- [ ] **Step 1: Write Playwright tests** asserting App shell rendering, navigation routes, theme toggle, and keyboard accessibility for KPI click drilldowns.
- [ ] **Step 2: Run test to verify it fails**: `bunx playwright test dashboard/tests/overview.spec.ts` fails.
- [ ] **Step 3: Implement App shell, Navigation, and Global Overview** consuming `GET /api/overview` metrics.
- [ ] **Step 4: Run test to verify it passes**: `bunx playwright test dashboard/tests/overview.spec.ts` passes.
- [ ] **Step 5: Review checkpoint** — review diff and tests. No commit without explicit user request.

### Task 52: Campaign workspace and scope selector

**Files:**
- Create/modify: `dashboard/src/pages/Campaigns.tsx`, `dashboard/src/pages/CampaignDetail.tsx`, `dashboard/src/components/ScopeSelector.tsx`, `dashboard/src/components/CreateCampaignModal.tsx`
- Test: `dashboard/tests/campaigns.spec.ts`

**Interfaces:**
- Campaign workspace with tabbed routing: Summary, Findings, Reports, Locations & Hosts, Treatment, Standards, Telemetry.
- `ScopeSelector`: radio/dropdown setting scope to latest campaign view, specific single report, or inclusive date range; synchronizes URL parameters.
- Campaign creation modal supporting campaign name, client, scope, tags, and atomic first location.

- [ ] **Step 1: Write Playwright tests** covering campaign creation wizard, first location generation, scope selector state updates in URL, and tab routing.
- [ ] **Step 2: Run test to verify it fails**: `bunx playwright test dashboard/tests/campaigns.spec.ts` fails.
- [ ] **Step 3: Implement Campaigns list, Campaign workspace shell, ScopeSelector, and Create modal**.
- [ ] **Step 4: Run test to verify it passes**: `bunx playwright test dashboard/tests/campaigns.spec.ts` passes.
- [ ] **Step 5: Review checkpoint** — review diff and tests. No commit without explicit user request.

### Task 53: Locations, immutable issuances, routing-visible upload

**Files:**
- Create/modify: `dashboard/src/pages/Locations.tsx`, `dashboard/src/pages/Downloads.tsx`, `dashboard/src/components/DropZone.tsx`, `dashboard/src/pages/HostDetail.tsx`
- Test: `dashboard/tests/upload_downloads.spec.ts`

**Interfaces:**
- Locations view showing tags, retired status, host inventory counts, freshness indicator.
- Downloads page with issuance generator modal, displaying pre-patched artifact SHA-256 hash, size, and curl/PowerShell download snippets.
- `DropZone` supporting multipart batch drag-and-drop (up to 32 files), rendering real-time per-file progress, resolved `Campaign -> Location -> Host` link badges, and SSE live refresh.
- `HostDetail`: host timeline, hostname change history, multi-location associations, and historical reports.

- [ ] **Step 1: Write Playwright tests** for issuance creation, download checksum display, multipart upload with automatic host placement, duplicate hostnames with different machine IDs, and SSE updates.
- [ ] **Step 2: Run test to verify it fails**: `bunx playwright test dashboard/tests/upload_downloads.spec.ts` fails.
- [ ] **Step 3: Implement Locations, Downloads, DropZone, and HostDetail components**.
- [ ] **Step 4: Run test to verify it passes**: `bunx playwright test dashboard/tests/upload_downloads.spec.ts` passes.
- [ ] **Step 5: Review checkpoint** — review diff and tests. No commit without explicit user request.

### Task 54: Accessible chart kit + Campaign Summary

**Files:**
- Create/modify: `dashboard/src/components/charts/RiskGauge.tsx`, `dashboard/src/components/charts/SeverityDonut.tsx`, `dashboard/src/components/charts/CategoryBars.tsx`, `dashboard/src/components/charts/HostHeatmap.tsx`, `dashboard/src/components/charts/TrendLine.tsx`, `dashboard/src/pages/CampaignSummary.tsx`
- Test: `dashboard/tests/charts.spec.ts`

**Interfaces:**
- Server-authoritative visual components adhering to dataviz marks/anatomy (<=24px bars, 4px rounded cap, 2px surface gap/ring, no dual axes, accessible text tokens, keyboard hit targets).
- Click/Enter/Space interaction matrix: every chart element navigates to exact URL-filtered findings in `Findings.tsx`.
- Table twin toggle for every chart for full screen-reader and keyboard accessibility.
- Presentation mode toggle with high-contrast executive summary view.

- [ ] **Step 1: Write Playwright tests** for chart kit rendering, contrast compliance, keyboard focus, table twin toggle, and clicking chart marks leading to exact URL filter parameters.
- [ ] **Step 2: Run test to verify it fails**: `bunx playwright test dashboard/tests/charts.spec.ts` fails.
- [ ] **Step 3: Implement chart components and Campaign Summary dashboard**.
- [ ] **Step 4: Run test to verify it passes**: `bunx playwright test dashboard/tests/charts.spec.ts` passes.
- [ ] **Step 5: Review checkpoint** — review diff and tests. No commit without explicit user request.

### Task 55: Findings/report/check detail, evidence, pivots, diff, treatment, telemetry

**Files:**
- Create/modify: `dashboard/src/pages/Findings.tsx`, `dashboard/src/pages/ReportDetail.tsx`, `dashboard/src/pages/CheckDetail.tsx`, `dashboard/src/pages/Diff.tsx`, `dashboard/src/pages/Treatment.tsx`, `dashboard/src/pages/Telemetry.tsx`, `dashboard/src/components/EvidenceDrawer.tsx`
- Test: `dashboard/tests/findings_evidence.spec.ts`

**Interfaces:**
- By Host and By Check pivot views over the findings catalog.
- `EvidenceDrawer`: renders pinpoint source path header, 1-based line/col, highlighted offending line, exact 3 context lines before and after (±3 lines), redaction indicator, ordered fallback attempts table, repro CLI, impact, recommendation, and run context.
- Treatment workflow board (`open`, `in_progress`, `mitigated`, `resolved`, `accepted_risk`, `false_positive`) with justification modal and audit history.
- Telemetry view showing scan durations, ingest duration, arrival path, privilege levels, peak RSS, coverage %, files read, commands executed, and extractor version adoption.
- Diff view comparing two scans of the same host with changed/fixed/new finding indicators.

- [ ] **Step 1: Write Playwright tests** asserting By Host vs By Check pivots, EvidenceDrawer ±3 context lines rendering, redacted secret concealment, treatment state mutations with justification, and diff views.
- [ ] **Step 2: Run test to verify it fails**: `bunx playwright test dashboard/tests/findings_evidence.spec.ts` fails.
- [ ] **Step 3: Implement Findings, ReportDetail, CheckDetail, Diff, Treatment, Telemetry, and EvidenceDrawer**.
- [ ] **Step 4: Run test to verify it passes**: `bunx playwright test dashboard/tests/findings_evidence.spec.ts` passes.
- [ ] **Step 5: Review checkpoint** — review diff and tests. No commit without explicit user request.

### Task 56: Admin (users, keys, retention, audit, backup)

**Files:**
- Create/modify: `dashboard/src/pages/admin/Users.tsx`, `dashboard/src/pages/admin/Keys.tsx`, `dashboard/src/pages/admin/Retention.tsx`, `dashboard/src/pages/admin/Audit.tsx`, `dashboard/src/pages/admin/Backup.tsx`
- Test: `dashboard/tests/admin.spec.ts`

**Interfaces:**
- User management: create, deactivate, role assignment, last super-admin protection.
- Key inventory: issuance mapping, status, download key bundle, revocation with required justification.
- Retention policy: dry-run affected report counts, confirm cleanup execution with legal hold safety.
- Audit log: searchable append-only security event history.
- Backup & restore: encrypted backup export download and password-authenticated restore upload.

- [ ] **Step 1: Write Playwright tests** asserting role-gating (403 for viewers/auditors), user deactivation, key revocation, retention dry-run, and encrypted backup download.
- [ ] **Step 2: Run test to verify it fails**: `bunx playwright test dashboard/tests/admin.spec.ts` fails.
- [ ] **Step 3: Implement Admin pages and subviews**.
- [ ] **Step 4: Run test to verify it passes**: `bunx playwright test dashboard/tests/admin.spec.ts` passes.
- [ ] **Step 5: Review checkpoint** — review diff and tests. No commit without explicit user request.

---

## Phase 6 — Exports, docs, end-to-end

### Task 57: Deliverable exports and diagnostic bundle

**Files:**
- Create/modify: `dashboard/server/exports/xlsx.ts`, `dashboard/server/exports/csv.ts`, `dashboard/server/exports/diagnostic.ts`
- Test: `dashboard/server/exports/exports.test.ts`

**Interfaces:**
- `GET /api/export/:reportId?format=xlsx`: multi-tab Excel workbook (Executive Summary sheet with KPI cards + Findings sheet with colored severity styling and auto-filter).
- `GET /api/export/:reportId?format=csv`: flat CSV with quoted fields and sanitized cell formulas.
- `GET /api/export/diagnostic`: super-admin diagnostic bundle with redacted ingest logs, self-audits, and telemetry metrics.

- [ ] **Step 1: Write failing export tests** in `dashboard/server/exports/exports.test.ts` covering XLSX structure, CSV escaping/formula injection protection (`=`, `+`, `-`, `@`), redaction in exports, and role restrictions.
- [ ] **Step 2: Run test to verify it fails**: `bun test dashboard/server/exports/exports.test.ts` fails.
- [ ] **Step 3: Implement XLSX, CSV, and diagnostic bundle generators**.
- [ ] **Step 4: Run test to verify it passes**: `bun test dashboard/server/exports/exports.test.ts` passes.
- [ ] **Step 5: Review checkpoint** — review diff and tests. No commit without explicit user request.

### Task 58: PDF (2 templates) + DOCX

**Files:**
- Create/modify: `dashboard/server/exports/pdf.ts`, `dashboard/server/exports/docx.ts`
- Test: `dashboard/server/exports/documents.test.ts`

**Interfaces:**
- Executive PDF template: cover sheet, score gauge, severity breakdown, top findings, plain-language executive summary.
- Technical PDF / DOCX template: complete host audit details in remediation order, pinpoint evidence blocks (±3 context lines), fallback logs, repro steps, references.
- Strict server-side secret redaction applied prior to document rendering.

- [ ] **Step 1: Write failing document generation tests** in `dashboard/server/exports/documents.test.ts` validating PDF/DOCX byte generation, page layout, secret redaction, and error handling.
- [ ] **Step 2: Run test to verify it fails**: `bun test dashboard/server/exports/documents.test.ts` fails.
- [ ] **Step 3: Implement PDF and DOCX export generators**.
- [ ] **Step 4: Run test to verify it passes**: `bun test dashboard/server/exports/documents.test.ts` passes.
- [ ] **Step 5: Review checkpoint** — review diff and tests. No commit without explicit user request.

### Task 59: Honest documentation

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Write comprehensive documentation** covering system overview, quickstart, air-gapped scanning default, optional `--push` and secure token usage (`HBS_PUSH_TOKEN` / `--push-token-file`), two-phase dynamic elevation, strict read-only guarantees (no temp files, no `secedit`), catalog structure, and resource budgets.
- [ ] **Step 2: Include honest cryptography statement**: modern confidentiality and integrity (X25519, HKDF-SHA256, ChaCha20-Poly1305, AES-256-GCM) under clearly stated assumptions; no absolute "unbreakable" claims; public-key only in extractor binary.
- [ ] **Step 3: Review checkpoint** — verify all CLI flags, endpoints, and commands against implementation. No commit without explicit user request.

### Task 60: End-to-end validation, budget gate, review handoff

- [ ] Linux loop: issue v2 extractor → run container offline → assert zero network sockets/DNS → sealed HBS2 report written → push with token file → ingest 200 → host routed by machine ID → exports generated → diff second run.
- [ ] Windows loop: non-elevated start → Phase 1 nonprivileged work → Phase 2 consent/decline tested → offline local write → ingest via upload → host routed.
- [ ] Legacy migration loop: valid legacy v1 ingest succeeds; ambiguous/revoked legacy v1 rejected; new issuance produces v2 only.
- [ ] Budget gates: all target binaries <10 MiB; peak RSS <200 MiB; Playwright test suite green; unit/integration tests green.
- [ ] Document final results in review checkpoint. Final commit/push happens only upon later explicit user instruction.

---

## Self-Review (done at plan time)

- **Spec coverage:** §3 layout→T1; §4.1 CLI→T11/T13; §4.2 privileges→T12; §4.3 engine/result→T2/T6/T7; §4.4 read-only→T3; §4.5 envelope→T8/T44; §4.6 keyslot→T9/T45; §4.7 hardening→T1 profile + obfstr usage note (strings obfuscation applied to path literals in threat modules — folded into T26/T38 implementation); §4.8 budgets→T14/T28/T60; §5 catalog→T16–T40 (all tables and check IDs enumerated); §6.1 auth→T42; §6.2 campaigns/locations/keys→T43/T46/T47/T48; §6.3 API→T41–T49; §6.4 metrics→T48; §6.5 frontend→T50–T56; §6.6 exports→T57/T58; §9 testing→per-task + T28/T40/T60; §10 phases matched.
- **Placeholders:** none — every check module task carries its full check table or enumerated ID list with evidence sources and pass criteria; every core task carries files, interfaces, and step-by-step TDD checkboxes.
- **Type consistency:** `CheckOutcome` fields used by helpers in T16 match T2; envelope/keyslot byte layouts identical in T8/T9 (Rust) and T44/T45 (TS); `display_id` formula identical in T48 only (single owner).
- **Review Focus tests assigned** to owning tasks as noted.
