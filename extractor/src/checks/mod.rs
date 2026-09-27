//! Testcase catalog. Each module exposes `register(&mut Vec<RegisteredCheck>)`
//! and is wired into `register_all` below. Adding a testcase = one entry
//! in a module via the `check!` macro (spec §4.3).

pub mod linux;
pub mod server_config;
pub mod shared;
pub mod toy;
pub mod windows;

use crate::context::ScanContext;
use crate::model::{CheckOutcome, EvidenceBlock, FallbackAttempt, RegisteredCheck, Status};

pub fn register_all(reg: &mut Vec<RegisteredCheck>) {
    linux::auditd::register(reg);
    windows::account::register(reg);
    windows::audit::register(reg);
    windows::sec_options::register(reg);
    windows::defender::register(reg);
    windows::event_logs::register(reg);
    windows::user_rights::register(reg);
    windows::services::register(reg);
    windows::perms::register(reg);
    windows::network::register(reg);
    windows::threat_creds::register(reg);
    windows::threat_persist::register(reg);
    linux::containers::register(reg);
    linux::firewall::register(reg);
    linux::fsck::register(reg);
    linux::logging::register(reg);
    linux::network::register(reg);
    linux::pam::register(reg);
    linux::services::register(reg);
    linux::users::register(reg);
    linux::ssh::register(reg);
    linux::threat::register(reg);
    server_config::register(reg);
    shared::register(reg);
    toy::register(reg);
    // Further Phase 2/3 modules register here as they land.
}

// ---- Nessus-style pinpoint evidence (target line +/- 3, redacted) ----

/// Build an EvidenceBlock for the first line in `path` containing
/// `needle`: 1-based line + column, three context lines each side,
/// every line redacted before it enters the report.
pub fn evidence_at(ctx: &mut ScanContext, path: &str, needle: &str) -> Option<EvidenceBlock> {
    let text = ctx.read(path)?;
    let lines: Vec<&str> = text.lines().collect();
    let idx = lines.iter().position(|l| l.contains(needle))?;
    let col = lines[idx]
        .find(needle)
        .map(|b| text[..b].chars().count())
        .unwrap_or(0) as u32
        + 1;
    let start = idx.saturating_sub(3);
    let end = (idx + 3).min(lines.len().saturating_sub(1));
    let context: Vec<String> = lines[start..=end]
        .iter()
        .map(|l| crate::redact::redact(l))
        .collect();
    let (file_mode, file_uid, file_gid) = stat_meta(ctx, path);
    Some(EvidenceBlock {
        path: path.to_string(),
        line: idx as u32 + 1,
        col,
        context,
        target_index: (idx - start) as u32,
        file_mode,
        file_uid,
        file_gid,
    })
}

#[cfg(unix)]
fn stat_meta(_ctx: &ScanContext, path: &str) -> (Option<u32>, Option<u32>, Option<u32>) {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(_ctx.path(path))
        .ok()
        .map(|md| (Some(md.mode() & 0o7777), Some(md.uid()), Some(md.gid())))
        .unwrap_or((None, None, None))
}

#[cfg(not(unix))]
fn stat_meta(_ctx: &ScanContext, _path: &str) -> (Option<u32>, Option<u32>, Option<u32>) {
    (None, None, None)
}

/// Attach an evidence block (or two) to an outcome.
pub fn with_block(mut o: CheckOutcome, b: Option<EvidenceBlock>) -> CheckOutcome {
    if let Some(b) = b {
        o.evidence_blocks.push(b);
    }
    o
}

// ---- shared outcome helpers (the recipe every check uses) ----

/// Compliant outcome with evidence.
pub fn ok(evidence: String, location: String, repro: String) -> CheckOutcome {
    CheckOutcome {
        status: Status::Compliant,
        evidence,
        location,
        repro,
        recommendation_override: None,
        degraded_reason: None,
        fallback_log: Vec::new(),
        evidence_blocks: Vec::new(),
    }
}

/// Non-compliant outcome with the found evidence.
pub fn nok(evidence: String, location: String, repro: String) -> CheckOutcome {
    CheckOutcome {
        status: Status::NonCompliant,
        evidence,
        location,
        repro,
        recommendation_override: None,
        degraded_reason: None,
        fallback_log: Vec::new(),
        evidence_blocks: Vec::new(),
    }
}

/// Partial evidence: a value/section was absent and defaults or reduced
/// visibility applied — the check completed but with reduced certainty.
pub fn degraded(reason: &str) -> CheckOutcome {
    CheckOutcome {
        status: Status::DegradedPartial,
        evidence: format!("degraded: {reason}"),
        location: String::new(),
        repro: String::new(),
        recommendation_override: None,
        degraded_reason: Some(reason.to_string()),
        fallback_log: Vec::new(),
        evidence_blocks: Vec::new(),
    }
}

/// A control that genuinely cannot exist in this runtime environment
/// (firmware/boot/hardware controls inside a container, or virtual
/// firmware a VM does not expose). This is `NotApplicable`, never
/// `NonCompliant` and never `DegradedPartial`: there is no capability
/// to assess and no fake evidence block is attached.
pub fn not_applicable(reason: &str) -> CheckOutcome {
    CheckOutcome {
        status: Status::NotApplicable,
        evidence: format!("not applicable: {reason}"),
        location: String::new(),
        repro: String::new(),
        recommendation_override: None,
        degraded_reason: None,
        fallback_log: Vec::new(),
        evidence_blocks: Vec::new(),
    }
}

/// True when the scan runs inside a container (host-only controls cannot
/// be evaluated).
pub fn in_container(ctx: &ScanContext) -> bool {
    ctx.platform.environment.is_container()
}

/// True when the scan runs inside a virtual machine.
pub fn on_vm(ctx: &ScanContext) -> bool {
    ctx.platform.environment.is_vm()
}

/// Hypervisor label for evidence text (e.g. `VMware`), with a fallback.
pub fn hypervisor_label(ctx: &ScanContext) -> String {
    ctx.platform.environment.hypervisor_or("unknown hypervisor")
}

/// Every fallback for a check was tried and none produced authoritative
/// evidence: missing, permission-denied, absent tool, timeout,
/// empty/unreadable source, or localized/malformed external output.
///
/// This is `DegradedPartial`, never `Status::Error`. `Error` is reserved
/// for internal invariant failures, panics, or corrupt parser/input. The
/// ordered attempts are preserved in `fallback_log` and rendered into
/// `evidence` so reports still show exactly what was tried.
pub fn degraded_from_attempts(log: Vec<FallbackAttempt>, reason: &str) -> CheckOutcome {
    let joined = join_attempts(&log);
    let evidence = if joined.is_empty() {
        format!("degraded: {reason}")
    } else {
        format!("degraded: {reason} — {joined}")
    };
    CheckOutcome {
        status: Status::DegradedPartial,
        evidence,
        location: String::new(),
        repro: String::new(),
        recommendation_override: None,
        degraded_reason: Some(reason.to_string()),
        fallback_log: log,
        evidence_blocks: Vec::new(),
    }
}

/// Render ordered fallback attempts as `"source (outcome); …"` — the same
/// convenience the former `err_outcome` helper offered.
pub fn join_attempts(log: &[FallbackAttempt]) -> String {
    log.iter()
        .map(|f| format!("{} ({})", f.source, f.outcome))
        .collect::<Vec<_>>()
        .join("; ")
}
