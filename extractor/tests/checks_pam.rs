use hbs_extractor::checks::register_all;
use hbs_extractor::context::ScanContext;
use hbs_extractor::engine::run_all;
use hbs_extractor::model::{RegisteredCheck, Status};
use hbs_extractor::platform::{detect, DistroFamily, Os};

fn ctx_with(root: &str) -> ScanContext {
    let mut p = detect();
    p.os = Os::Linux;
    p.family = DistroFamily::Debian;
    ScanContext::new(p, false)
        .with_root_prefix(root)
        .with_injector(Box::new(|_, _| None))
}

fn run_one(ctx: &mut ScanContext, id: &str) -> hbs_extractor::model::CheckResult {
    let mut reg: Vec<RegisteredCheck> = Vec::new();
    register_all(&mut reg);
    let subset: Vec<RegisteredCheck> = reg.into_iter().filter(|c| c.tc.id == id).collect();
    run_all(&subset, ctx).remove(0)
}

#[test]
fn hardened_pam_passes() {
    let mut ctx = ctx_with("tests/fixtures/pam-hardened");
    for id in [
        "LIN-PAM-001",
        "LIN-PAM-002",
        "LIN-PAM-004",
        "LIN-PAM-005",
        "LIN-PAM-008",
    ] {
        let r = run_one(&mut ctx, id);
        assert_eq!(r.status, Status::Compliant, "{id}: {}", r.evidence);
    }
}

#[test]
fn weak_pam_fails() {
    let mut ctx = ctx_with("tests/fixtures/pam-weak");
    assert_eq!(
        run_one(&mut ctx, "LIN-PAM-001").status,
        Status::NonCompliant
    );
    assert_eq!(
        run_one(&mut ctx, "LIN-PAM-005").status,
        Status::NonCompliant
    );
    let r = run_one(&mut ctx, "LIN-PAM-004");
    assert_eq!(r.status, Status::NonCompliant, "{}", r.evidence);
}

#[test]
fn system_account_with_shell_fails() {
    let mut ctx = ctx_with("tests/fixtures/pam-weak");
    let r = run_one(&mut ctx, "LIN-PAM-014");
    assert_eq!(r.status, Status::NonCompliant, "{}", r.evidence);
    assert!(r.evidence.contains("games") || r.evidence.contains("daemon"));
}

#[test]
fn missing_login_defs_degrades() {
    let mut ctx = ctx_with("tests/fixtures/empty-root");
    let r = run_one(&mut ctx, "LIN-PAM-005");
    assert_eq!(r.status, Status::DegradedPartial, "{}", r.evidence);
    assert!(r.degraded_reason.as_deref().unwrap().contains("login.defs"));
}
