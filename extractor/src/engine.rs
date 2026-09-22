//! Check runner: walks the registry, contains panics, measures
//! durations, folds static testcase text + CheckOutcome into the
//! final CheckResult. The scan never aborts (spec §4.3).

use crate::context::ScanContext;
use crate::model::{CheckOutcome, CheckResult, FallbackAttempt, RegisteredCheck, Status, Summary};

/// Run every applicable registered check against the context.
pub fn run_all(registry: &[RegisteredCheck], ctx: &mut ScanContext) -> Vec<CheckResult> {
    let run_ctx = current_run_context(ctx.elevated);
    let mut out = Vec::with_capacity(registry.len());
    for rc in registry {
        let started = std::time::Instant::now();
        let audit_start = ctx.audit.attempts.len();
        let (outcome, mut fallback_log) = if !(rc.applies)(&ctx.platform) {
            (
                CheckOutcome {
                    status: Status::NotApplicable,
                    evidence: "not applicable on this platform".into(),
                    location: String::new(),
                    repro: String::new(),
                    recommendation_override: None,
                    degraded_reason: None,
                    fallback_log: Vec::new(),
                    evidence_blocks: Vec::new(),
                },
                Vec::new(),
            )
        } else if rc.admin && !ctx.elevated {
            // Privilege-gated check: the scan runs unprivileged by
            // default; admin-only checks are skipped with an explicit
            // reason rather than run degraded (user request: ask for
            // elevation only when needed, never silently downgrade).
            (
                CheckOutcome {
                    status: Status::DegradedPartial,
                    evidence: "requires elevation — rerun with --elevate for this check's full depth".into(),
                    location: String::new(),
                    repro: String::new(),
                    recommendation_override: None,
                    degraded_reason: Some("requires elevation (skipped: unprivileged run)".into()),
                    fallback_log: Vec::new(),
                    evidence_blocks: Vec::new(),
                },
                Vec::new(),
            )
        } else {
            // AssertUnwindSafe: the context is not shared with other
            // threads; on panic we still own it and any partial state is
            // discarded by the next check overwriting what it uses.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (rc.run)(ctx)));
            match result {
                Ok(o) => (o, Vec::new()),
                Err(payload) => {
                    let msg = payload
                        .downcast_ref::<&str>()
                        .map(|s| s.to_string())
                        .or_else(|| payload.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "unknown panic".into());
                    (
                        CheckOutcome {
                            status: Status::Error,
                            evidence: format!("check panicked: {msg}"),
                            location: String::new(),
                            repro: String::new(),
                            recommendation_override: None,
                            degraded_reason: None,
                            fallback_log: vec![FallbackAttempt {
                                source: "engine".into(),
                                outcome: format!("check panicked: {msg}"),
                            }],
                            evidence_blocks: Vec::new(),
                        },
                        Vec::new(),
                    )
                }
            }
        };
        // The check's own fallback log (present on outcomes built by
        // degraded_from_attempts / the check helpers) takes precedence
        // over the engine's.
        if !outcome.fallback_log.is_empty() {
            fallback_log = outcome.fallback_log.clone();
        }
        if outcome.status == Status::Error && fallback_log.is_empty() {
            fallback_log.push(FallbackAttempt {
                source: "engine".into(),
                outcome: "check completed with Error status and no fallback log".into(),
            });
        }
        // Link each evidence block back to the attempt(s) that produced
        // it, so a finding can be traced to its audit log line(s).
        if !outcome.evidence_blocks.is_empty() {
            ctx.link_evidence(audit_start, rc.tc.id, &outcome.evidence_blocks);
        }
        out.push(CheckResult {
            id: rc.tc.id.to_string(),
            title: rc.tc.title.to_string(),
            status: outcome.status,
            severity: rc.tc.severity,
            category: rc.tc.category.to_string(),
            description: rc.tc.description.to_string(),
            impact: rc.tc.impact.to_string(),
            recommendation: outcome
                .recommendation_override
                .unwrap_or_else(|| rc.tc.recommendation.to_string()),
            references: rc.tc.references.iter().map(|s| s.to_string()).collect(),
            evidence: crate::redact::redact(&outcome.evidence),
            location: outcome.location,
            repro: outcome.repro,
            degraded_reason: outcome.degraded_reason,
            fallback_log,
            evidence_blocks: outcome.evidence_blocks.clone(),
            run_context: run_ctx.clone(),
            duration_ms: started.elapsed().as_millis() as u64,
        });
    }
    out
}

/// Identity of the scanning process at check time.
fn current_run_context(elevated: bool) -> crate::model::RunContext {
    #[cfg(unix)]
    {
        let uid = unsafe { libc::getuid() };
        let user = std::env::var("USER")
            .ok()
            .or_else(|| {
                // passwd lookup without a crate: read /etc/passwd for uid
                std::fs::read_to_string("/etc/passwd").ok().and_then(|p| {
                    p.lines()
                        .find(|l| l.split(':').nth(2) == Some(&uid.to_string()))
                        .and_then(|l| l.split(':').next().map(str::to_string))
                })
            })
            .unwrap_or_else(|| format!("uid:{uid}"));
        crate::model::RunContext { user, uid: Some(uid), elevated }
    }
    #[cfg(not(unix))]
    {
        let user = std::env::var("USERNAME").unwrap_or_else(|_| "unknown".into());
        crate::model::RunContext { user, uid: None, elevated }
    }
}

pub fn summarize(results: &[CheckResult]) -> Summary {
    let mut s = Summary::default();
    for r in results {
        match r.status {
            Status::Compliant => s.compliant += 1,
            Status::NonCompliant => s.non_compliant += 1,
            Status::NotApplicable => s.not_applicable += 1,
            Status::Error => s.error += 1,
            Status::DegradedPartial => s.degraded += 1,
        }
        if r.severity == crate::model::Severity::Informational {
            s.informational += 1;
        }
    }
    s
}
