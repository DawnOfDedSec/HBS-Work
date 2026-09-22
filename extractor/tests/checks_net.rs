use hbs_extractor::checks::register_all;
use hbs_extractor::context::ScanContext;
use hbs_extractor::engine::run_all;
use hbs_extractor::model::{RegisteredCheck, Status};
use hbs_extractor::platform::{detect, DistroFamily, Os};

fn ctx_with(root: &str) -> ScanContext {
    let mut p = detect();
    p.os = Os::Linux;
    p.family = DistroFamily::Debian;
    ScanContext::new(p, false).with_root_prefix(root).with_injector(Box::new(|_, _| None))
}

fn run_one(ctx: &mut ScanContext, id: &str) -> hbs_extractor::model::CheckResult {
    let mut reg: Vec<RegisteredCheck> = Vec::new();
    register_all(&mut reg);
    let subset: Vec<RegisteredCheck> = reg.into_iter().filter(|c| c.tc.id == id).collect();
    run_all(&subset, ctx).remove(0)
}

#[test]
fn forwarding_disabled_is_compliant() {
    let mut ctx = ctx_with("tests/fixtures/net-hardened");
    let r = run_one(&mut ctx, "LIN-NET-001");
    assert_eq!(r.status, Status::Compliant, "{}", r.evidence);
    let r = run_one(&mut ctx, "LIN-NET-020");
    assert_eq!(r.status, Status::Compliant, "{}", r.evidence);
}

#[test]
fn forwarding_enabled_fails() {
    let mut ctx = ctx_with("tests/fixtures/net-weak");
    let r = run_one(&mut ctx, "LIN-NET-001");
    assert_eq!(r.status, Status::NonCompliant, "{}", r.evidence);
    assert!(r.evidence.contains("expected 0"));
}

#[test]
fn missing_key_degrades_for_default_one() {
    // net-weak fixture lacks icmp_echo_ignore_broadcasts
    let mut ctx = ctx_with("tests/fixtures/net-weak");
    let r = run_one(&mut ctx, "LIN-NET-003");
    assert_eq!(r.status, Status::DegradedPartial, "{}", r.evidence);
}

#[test]
fn missing_required_key_is_error() {
    let mut ctx = ctx_with("tests/fixtures/empty-root");
    let r = run_one(&mut ctx, "LIN-NET-001");
    assert_eq!(r.status, Status::Error, "{}", r.evidence);
    assert!(r.evidence.contains("unavailable"));
}

#[test]
fn pair_check_fails_on_one_bad_value() {
    let mut ctx = ctx_with("tests/fixtures/net-weak");
    let r = run_one(&mut ctx, "LIN-NET-010"); // accept_redirects all=1 bad, default absent
    assert_eq!(r.status, Status::NonCompliant, "{}", r.evidence);
}
