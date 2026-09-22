use hbs_extractor::checks::register_all;
use hbs_extractor::context::ScanContext;
use hbs_extractor::engine::run_all;
use hbs_extractor::model::{RegisteredCheck, Status};
use hbs_extractor::platform::{detect, DistroFamily, Os};

fn linux_ctx(root: &str, injector: Option<hbs_extractor::evidence::CmdInjector>) -> ScanContext {
    let mut p = detect();
    p.os = Os::Linux;
    p.family = DistroFamily::Debian;
    let mut ctx = ScanContext::new(p, false).with_root_prefix(root);
    if let Some(f) = injector {
        ctx = ctx.with_injector(f);
    }
    ctx
}

fn run_one(ctx: &mut ScanContext, id: &str) -> hbs_extractor::model::CheckResult {
    let mut reg: Vec<RegisteredCheck> = Vec::new();
    register_all(&mut reg);
    let subset: Vec<RegisteredCheck> = reg.into_iter().filter(|c| c.tc.id == id).collect();
    assert_eq!(subset.len(), 1, "check {id} must be registered");
    run_all(&subset, ctx).remove(0)
}

#[test]
fn gen_inv_001_parses_proc_net_tcp_when_ss_missing() {
    // injector returns None for every command -> ss fails -> falls back
    // to the /proc/net/tcp fixture
    let mut ctx = linux_ctx("tests/fixtures/shared-root", Some(Box::new(|_, _| None)));
    let r = run_one(&mut ctx, "GEN-INV-001");
    assert_eq!(r.status, Status::DegradedPartial);
    // 0.0.0.0:22 (0016 hex) and 127.0.0.1:5432 (1538 hex) in fixture
    assert!(r.evidence.contains("22"), "evidence: {}", r.evidence);
    assert!(r.evidence.contains("5432"));
    assert!(r.degraded_reason.is_some());
}

#[test]
fn gen_inv_003_reads_passwd() {
    let mut ctx = linux_ctx("tests/fixtures/shared-root", Some(Box::new(|_, _| None)));
    let r = run_one(&mut ctx, "GEN-INV-003");
    assert_eq!(r.status, Status::Compliant);
    assert!(r.evidence.contains("root"));
    assert!(r.evidence.contains("svc-web"));
}

#[test]
fn gen_inv_007_reads_dpkg_log() {
    let mut ctx = linux_ctx("tests/fixtures/shared-root", Some(Box::new(|_, _| None)));
    let r = run_one(&mut ctx, "GEN-INV-007");
    assert_eq!(r.status, Status::Compliant);
    assert!(r.evidence.contains("2026-09-01"), "evidence: {}", r.evidence);
}

#[test]
fn missing_everything_degrades_with_full_log() {
    let mut ctx = linux_ctx("tests/fixtures/empty-root", Some(Box::new(|_, _| None)));
    let r = run_one(&mut ctx, "GEN-INV-007");
    assert_eq!(r.status, Status::DegradedPartial);
    assert!(r.evidence.contains("degraded"), "evidence: {}", r.evidence);
    assert!(r.degraded_reason.is_some());
    assert!(!r.fallback_log.is_empty());
}
