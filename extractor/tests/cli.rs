use hbs_extractor::cli::fmt_check_line;
use hbs_extractor::model::{CheckResult, Severity, Status};

fn res(id: &str, status: Status, sev: Severity) -> CheckResult {
    CheckResult {
        id: id.into(),
        title: "audit logon events".into(),
        status,
        severity: sev,
        category: "Audit".into(),
        description: String::new(),
        impact: String::new(),
        recommendation: String::new(),
        references: vec![],
        evidence: String::new(),
        location: String::new(),
        repro: String::new(),
        degraded_reason: None,
        fallback_log: vec![],
        evidence_blocks: vec![],
        run_context: hbs_extractor::model::RunContext { user: "test".into(), uid: Some(1000), elevated: false },
        duration_ms: 0,
    }
}

#[test]
fn compliant_line_format() {
    let l = fmt_check_line(&res("LIN-SSH-001", Status::Compliant, Severity::Medium));
    assert!(l.starts_with('\u{2713}'), "icon: {l}");
    assert!(l.contains("LIN-SSH-001"));
    assert!(!l.contains("Critical"), "no severity tag on pass: {l}");
}

#[test]
fn failed_line_carries_severity() {
    let l = fmt_check_line(&res("WIN-AU-003", Status::NonCompliant, Severity::High));
    assert!(l.starts_with('\u{2717}'), "icon: {l}");
    assert!(l.contains("[High]"), "severity tag: {l}");
}

#[test]
fn degraded_error_na_icons() {
    let d = fmt_check_line(&res("X-1", Status::DegradedPartial, Severity::Low));
    let e = fmt_check_line(&res("X-2", Status::Error, Severity::Low));
    let n = fmt_check_line(&res("X-3", Status::NotApplicable, Severity::Low));
    assert!(d.starts_with('\u{26a0}'));
    assert!(e.starts_with('!'));
    assert!(n.starts_with('-'));
}
