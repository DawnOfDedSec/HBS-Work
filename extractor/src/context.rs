//! Shared scan context: platform info, root prefix (fixture testing),
//! command injector (deterministic tests), read caches, and the
//! self-audit log. All checks receive `&mut ScanContext` and never
//! touch the filesystem or process spawning directly.

use crate::evidence::{self, CmdInjector};
use crate::model::{bounded_redact, AuditKind, AuditStatus, EvidenceBlock, SelfAudit};
use crate::platform::{EnvironmentInfo, EnvProbe, PlatformInfo};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub const DEFAULT_CMD_TIMEOUT_MS: u64 = 5000;

pub struct ScanContext {
    pub platform: PlatformInfo,
    pub elevated: bool,
    /// Prefix joined onto every absolute path ("" in production; a
    /// fixture tree in tests).
    pub root_prefix: PathBuf,
    pub audit: SelfAudit,
    caches: HashMap<String, String>,
    injector: Option<CmdInjector>,
    /// Whether native (in-process, no external tool) Windows API
    /// fallbacks may run. Disabled automatically whenever an injector
    /// is installed so deterministic tests never touch host state;
    /// re-enabled explicitly by tests that exercise the native path.
    native_fallbacks: bool,
}

impl ScanContext {
    pub fn new(platform: PlatformInfo, elevated: bool) -> Self {
        ScanContext {
            platform,
            elevated,
            root_prefix: PathBuf::new(),
            audit: SelfAudit::default(),
            caches: HashMap::new(),
            injector: None,
            native_fallbacks: true,
        }
    }

    pub fn with_root_prefix(mut self, p: &str) -> Self {
        self.root_prefix = PathBuf::from(p);
        self
    }

    pub fn with_injector(mut self, f: CmdInjector) -> Self {
        self.injector = Some(f);
        // Injected evidence is a deterministic test/portable mode: never
        // let a check reach past it into the host's real registry or
        // account database.
        self.native_fallbacks = false;
        self
    }

    /// Re-enable native in-process Windows API fallbacks. Call *after*
    /// `with_injector` to exercise the native path with injected
    /// command responses (used by the fallback-chain tests).
    pub fn with_native_fallbacks(mut self, enabled: bool) -> Self {
        self.native_fallbacks = enabled;
        self
    }

    /// Whether native Windows API fallbacks are permitted for this run.
    pub fn native_fallbacks_enabled(&self) -> bool {
        self.native_fallbacks
    }

    pub(crate) fn has_injector(&self) -> bool {
        self.injector.is_some()
    }

    /// Join the root prefix onto an absolute path.
    pub fn path(&self, abs_path: &str) -> PathBuf {
        let p = Path::new(abs_path);
        if p.is_absolute() || !abs_path.starts_with('/') {
            self.root_prefix.join(p.strip_prefix("/").unwrap_or(p))
        } else {
            self.root_prefix.join(&abs_path[1..])
        }
    }

    pub fn exists(&self, abs_path: &str) -> bool {
        self.path(abs_path).exists()
    }

    /// Cached, capped read. A cache hit records a `cached: true` attempt
    /// (the original attempt is preserved) but does not re-log the compact
    /// `files_read` list.
    pub fn read(&mut self, abs_path: &str) -> Option<String> {
        if let Some(hit) = self.caches.get(abs_path).cloned() {
            let idx = self.audit.begin_attempt(AuditKind::File, abs_path);
            let bytes = hit.len() as u64;
            self.audit.finish_attempt(idx, |a| {
                a.status = AuditStatus::Cached;
                a.cached = true;
                a.bytes = Some(bytes);
                a.outcome = format!("cache hit; {bytes} bytes");
            });
            return Some(hit);
        }
        let full = self.path(abs_path);
        let out = evidence::read_file_capped_as(&full, abs_path, &mut self.audit)?;
        self.caches.insert(abs_path.to_string(), out.clone());
        Some(out)
    }

    pub fn cmd(&mut self, program: &str, args: &[&str]) -> Option<String> {
        self.cmd_timeout(program, args, DEFAULT_CMD_TIMEOUT_MS)
    }

    pub fn cmd_timeout(&mut self, program: &str, args: &[&str], timeout_ms: u64) -> Option<String> {
        evidence::run_command(program, args, timeout_ms, &mut self.audit, &self.injector)
    }

    /// Back-reference the attempts that produced a finding's evidence
    /// blocks. `start` is the attempts length captured before the check
    /// ran, so only this check's attempts are touched. Matches by redacted
    /// source path (file attempts), including cache hits.
    pub fn link_evidence(&mut self, start: usize, check_id: &str, blocks: &[EvidenceBlock]) {
        if blocks.is_empty() || start >= self.audit.attempts.len() {
            return;
        }
        for b in blocks {
            let want = bounded_redact(&b.path);
            let reference = bounded_redact(&format!("{}:{}", check_id, b.line));
            for a in self.audit.attempts[start..].iter_mut() {
                if a.kind == AuditKind::File && a.source == want {
                    a.evidence_ref = Some(reference.clone());
                }
            }
        }
    }

    /// Unix permission bits (mode) of a path, via stat. None when the
    /// path is missing, unreadable, or on a non-unix host.
    #[cfg(unix)]
    pub fn unix_mode(&self, abs_path: &str) -> Option<u32> {
        use std::os::unix::fs::MetadataExt;
        let md = std::fs::metadata(self.path(abs_path)).ok()?;
        Some(md.mode() & 0o7777)
    }

    #[cfg(not(unix))]
    pub fn unix_mode(&self, _abs_path: &str) -> Option<u32> {
        None
    }

    pub fn linux(&self) -> bool {
        self.platform.os == crate::platform::Os::Linux
    }

    pub fn windows(&self) -> bool {
        self.platform.os == crate::platform::Os::Windows
    }

    /// Environment classification (bare metal / VM / container / WSL).
    pub fn environment(&self) -> &EnvironmentInfo {
        &self.platform.environment
    }

    /// True when the scan runs inside a container.
    pub fn is_container(&self) -> bool {
        self.platform.environment.is_container()
    }

    /// True when the scan runs inside a virtual machine.
    pub fn is_vm(&self) -> bool {
        self.platform.environment.is_vm()
    }

    /// Re-run environment detection through this context (fixture root +
    /// injected commands) and store the result. Useful for tests and for
    /// re-probing after a context is built by hand.
    pub fn refresh_environment(&mut self) -> EnvironmentInfo {
        let env = crate::platform::detect_environment(self);
        self.platform.environment = env.clone();
        env
    }
}

impl EnvProbe for ScanContext {
    fn env_read(&mut self, abs_path: &str) -> Option<String> {
        self.read(abs_path)
    }

    fn env_cmd(&mut self, program: &str, args: &[&str]) -> Option<String> {
        self.cmd(program, args)
    }

    fn env_var(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }

    fn is_windows(&self) -> bool {
        self.windows()
    }

    fn arch(&self) -> &str {
        &self.platform.arch
    }
}
