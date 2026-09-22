//! Testcase catalog. Each module exposes `register(&mut Vec<RegisteredCheck>)`
//! and is wired into `register_all` below. Adding a testcase = one entry
//! in a module via the `check!` macro (spec §4.3).

pub mod linux;
pub mod shared;
pub mod toy;

use crate::model::{CheckOutcome, FallbackAttempt, RegisteredCheck, Status};

pub fn register_all(reg: &mut Vec<RegisteredCheck>) {
    linux::fsck::register(reg);
    linux::network::register(reg);
    linux::services::register(reg);
    shared::register(reg);
    toy::register(reg);
    // Further Phase 2/3 modules register here as they land.
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
    }
}
