//! Shared scan context: platform info, root prefix (fixture testing),
//! command injector (deterministic tests), read caches, and the
//! self-audit log. All checks receive `&mut ScanContext` and never
//! touch the filesystem or process spawning directly.

use crate::evidence::{self, CmdInjector};
use crate::model::SelfAudit;
use crate::platform::PlatformInfo;
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
        }
    }

    pub fn with_root_prefix(mut self, p: &str) -> Self {
        self.root_prefix = PathBuf::from(p);
        self
    }

    pub fn with_injector(mut self, f: CmdInjector) -> Self {
        self.injector = Some(f);
        self
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

    /// Cached, capped read. Cache hit does not re-log the audit entry.
    pub fn read(&mut self, abs_path: &str) -> Option<String> {
        if let Some(hit) = self.caches.get(abs_path) {
            return Some(hit.clone());
        }
        let full = self.path(abs_path);
        let out = evidence::read_file_capped(&full, &mut self.audit)?;
        self.caches.insert(abs_path.to_string(), out.clone());
        Some(out)
    }

    pub fn cmd(&mut self, program: &str, args: &[&str]) -> Option<String> {
        self.cmd_timeout(program, args, DEFAULT_CMD_TIMEOUT_MS)
    }

    pub fn cmd_timeout(&mut self, program: &str, args: &[&str], timeout_ms: u64) -> Option<String> {
        evidence::run_command(program, args, timeout_ms, &mut self.audit, &self.injector)
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
}
