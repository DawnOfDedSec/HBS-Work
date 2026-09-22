use hbs_extractor::context::ScanContext;
use hbs_extractor::engine::run_all;
use hbs_extractor::model::*;
use hbs_extractor::platform::{detect, DistroFamily, Os};

fn toy_tc(id: &'static str) -> Testcase {
    Testcase {
        id,
        title: "toy",
        description: "toy check",
        impact: "toy impact",
        recommendation: "toy rec",
        severity: Severity::Medium,
        category: "Test",
        references: &["CIS 9.9.9"],
    }
}

fn test_ctx() -> ScanContext {
    let mut p = detect();
    p.os = Os::Linux;
    p.family = DistroFamily::Debian;
    ScanContext::new(p, false).with_root_prefix("tests/fixtures/context-root")
}

#[test]
fn panicking_check_yields_error_not_abort() {
    let mut reg: Vec<RegisteredCheck> = Vec::new();
    reg.push(RegisteredCheck {
        tc: toy_tc("T-1"),
        applies: |_| true,
        admin: false,
        run: |_ctx| panic!("boom"),
    });
    let mut ctx = test_ctx();
    let out = run_all(&reg, &mut ctx);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].status, Status::Error);
    assert!(out[0].fallback_log.iter().any(|f| f.outcome.contains("panicked")));
    assert_eq!(out[0].id, "T-1");
}

#[test]
fn non_applicable_check_reports_not_applicable() {
    let mut reg: Vec<RegisteredCheck> = Vec::new();
    reg.push(RegisteredCheck {
        tc: toy_tc("T-2"),
        applies: |_| false,
        admin: false,
        run: |_| panic!("must not run"),
    });
    let mut ctx = test_ctx();
    let out = run_all(&reg, &mut ctx);
    assert_eq!(out[0].status, Status::NotApplicable);
}

#[test]
fn admin_only_check_skipped_with_reason_when_unprivileged() {
    // The check fn panics if it ever runs: only the privilege gate can
    // make this test pass (unprivileged ctx + admin-only check).
    let mut reg: Vec<RegisteredCheck> = Vec::new();
    reg.push(RegisteredCheck {
        tc: toy_tc("T-ADMIN"),
        applies: |_| true,
        admin: true,
        run: |_| panic!("admin check must be gated, not run"),
    });
    let mut ctx = test_ctx(); // elevated = false
    let out = run_all(&reg, &mut ctx);
    assert_eq!(out[0].status, Status::DegradedPartial);
    assert!(out[0].degraded_reason.as_deref().unwrap().contains("requires elevation"));
    assert!(out[0].evidence.contains("--elevate"));
}

#[test]
fn admin_only_check_runs_when_elevated() {
    fn always_ok(_: &mut ScanContext) -> CheckOutcome {
        CheckOutcome {
            status: Status::Compliant,
            evidence: "ran with depth".into(),
            location: String::new(),
            repro: String::new(),
            recommendation_override: None,
            degraded_reason: None,
            fallback_log: Vec::new(),
            evidence_blocks: Vec::new(),
        }
    }
    let mut reg: Vec<RegisteredCheck> = Vec::new();
    reg.push(RegisteredCheck { tc: toy_tc("T-ADMIN2"), applies: |_| true, admin: true, run: always_ok });
    let mut p = detect();
    p.os = Os::Linux;
    let mut ctx = ScanContext::new(p, true); // elevated
    let out = run_all(&reg, &mut ctx);
    assert_eq!(out[0].status, Status::Compliant);
}

#[test]
fn missing_paths_reported_as_error_with_fallback_log() {
    let check = |ctx: &mut ScanContext| {
        let mut log: Vec<FallbackAttempt> = Vec::new();
        for (src, path) in [("file:/etc/nope/x", "/etc/nope/x"), ("file:/etc/nope/y", "/etc/nope/y")] {
            match ctx.read(path) {
                Some(_) => log.push(FallbackAttempt { source: src.into(), outcome: "read".into() }),
                None => log.push(FallbackAttempt { source: src.into(), outcome: "missing or unreadable".into() }),
            }
        }
        CheckOutcome {
            status: Status::Error,
            evidence: format!("unavailable: {}", log.iter().map(|f| format!("{} ({})", f.source, f.outcome)).collect::<Vec<_>>().join("; ")),
            location: "/etc/nope".into(),
            repro: "cat /etc/nope/x".into(),
            recommendation_override: None,
            degraded_reason: None,
            fallback_log: log,
            evidence_blocks: Vec::new(),
        }
    };
    let mut reg: Vec<RegisteredCheck> = Vec::new();
    reg.push(RegisteredCheck { tc: toy_tc("T-3"), applies: |_| true, admin: false, run: check });
    let mut ctx = test_ctx();
    let out = run_all(&reg, &mut ctx);
    assert_eq!(out[0].status, Status::Error);
    assert!(out[0].evidence.contains("missing or unreadable"));
}

fn ok_check(_: &mut ScanContext) -> CheckOutcome {
    CheckOutcome {
        status: Status::NonCompliant,
        evidence: "e".into(),
        location: "l".into(),
        repro: "r".into(),
        recommendation_override: None,
        degraded_reason: None,
        fallback_log: Vec::new(),
        evidence_blocks: Vec::new(),
    }
}

#[test]
fn result_carries_testcase_texts_and_summarize_counts() {
    let mut reg: Vec<RegisteredCheck> = Vec::new();
    reg.push(RegisteredCheck { tc: toy_tc("T-4"), applies: |_| true, admin: false, run: ok_check });
    reg.push(RegisteredCheck { tc: toy_tc("T-5"), applies: |_| false, admin: false, run: ok_check });
    let mut ctx = test_ctx();
    let out = run_all(&reg, &mut ctx);
    assert_eq!(out[0].impact, "toy impact");
    assert_eq!(out[0].references, vec!["CIS 9.9.9".to_string()]);
    let s = hbs_extractor::engine::summarize(&out);
    assert_eq!(s.non_compliant, 1);
    assert_eq!(s.not_applicable, 1);
    assert_eq!(s.compliant, 0);
}
