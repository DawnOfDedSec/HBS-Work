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
fn identity_watches_pass_on_full_rules() {
    let mut ctx = ctx_with("tests/fixtures/au-root");
    let r = run_one(&mut ctx, "LIN-AU-006");
    assert_eq!(r.status, Status::Compliant, "{}", r.evidence);
}

#[test]
fn missing_watches_fail() {
    let mut ctx = ctx_with("tests/fixtures/au-weak");
    let r = run_one(&mut ctx, "LIN-AU-006");
    assert_eq!(r.status, Status::NonCompliant, "{}", r.evidence);
    assert!(r.evidence.contains("/etc/sudoers"));
}

#[test]
fn immutable_flag_passes() {
    let mut ctx = ctx_with("tests/fixtures/au-root");
    let r = run_one(&mut ctx, "LIN-AU-011");
    assert_eq!(r.status, Status::Compliant, "{}", r.evidence);
}

#[test]
fn no_auditd_degrades_with_elevation_hint() {
    let mut ctx = ctx_with("tests/fixtures/empty-root");
    let r = run_one(&mut ctx, "LIN-AU-006");
    assert_eq!(r.status, Status::DegradedPartial, "{}", r.evidence);
    assert!(r.evidence.contains("--elevate") || r.degraded_reason.unwrap().contains("root"));
}

#[test]
fn auditd_conf_actions() {
    let mut ctx = ctx_with("tests/fixtures/au-root");
    assert_eq!(run_one(&mut ctx, "LIN-AU-004").status, Status::Compliant);
    assert_eq!(run_one(&mut ctx, "LIN-AU-005").status, Status::Compliant);
}
