//! Testcase catalog. Each module exposes `register(&mut Vec<RegisteredCheck>)`
//! and is wired into `register_all` below. Adding a testcase = one entry
//! in a module via the `check!` macro (spec §4.3).

pub mod linux;
pub mod shared;
pub mod toy;

use crate::context::ScanContext;
use crate::model::{CheckOutcome, EvidenceBlock, FallbackAttempt, RegisteredCheck, Status};

pub fn register_all(reg: &mut Vec<RegisteredCheck>) {
    linux::auditd::register(reg);
    linux::firewall::register(reg);
    linux::fsck::register(reg);
    linux::logging::register(reg);
    linux::network::register(reg);
    linux::pam::register(reg);
    linux::services::register(reg);
    linux::users::register(reg);
    linux::ssh::register(reg);
    linux::threat::register(reg);
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
    let col = lines[idx].find(needle).map(|b| text[..b].chars().count()).unwrap_or(0) as u32 + 1;
    let start = idx.saturating_sub(3);
    let end = (idx + 3).min(lines.len().saturating_sub(1));
    let context: Vec<String> = lines[start..=end]
        .iter()
        .map(|l| crate::redact::redact(l))
        .collect();
    Some(EvidenceBlock {
        path: path.to_string(),
        line: idx as u32 + 1,
        col,
        context,
        target_index: (idx - start) as u32,
    })
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

/// Every fallback failed — full Error outcome whose evidence enumerates
/// each attempt ("source (outcome); …"), exactly what the report shows.
pub fn err_outcome(log: Vec<FallbackAttempt>) -> CheckOutcome {
    let joined = log
        .iter()
        .map(|f| format!("{} ({})", f.source, f.outcome))
        .collect::<Vec<_>>()
        .join("; ");
    CheckOutcome {
        status: Status::Error,
        evidence: format!("unavailable: {joined}"),
        location: String::new(),
        repro: String::new(),
        recommendation_override: None,
        degraded_reason: None,
        fallback_log: log,
        evidence_blocks: Vec::new(),
    }
}
