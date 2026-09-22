use hbs_extractor::checks::register_all;
use hbs_extractor::context::ScanContext;
use hbs_extractor::engine::run_all;
use hbs_extractor::model::{RegisteredCheck, Status};
use hbs_extractor::platform::{detect, DistroFamily, EnvironmentInfo, Os};

fn linux_ctx(root: &str) -> ScanContext {
    let mut p = detect();
    p.os = Os::Linux;
    p.family = DistroFamily::Debian;
    p.environment = EnvironmentInfo::default();
    ScanContext::new(p, false).with_root_prefix(root).with_injector(Box::new(|_, _| None))
}

fn run_one(ctx: &mut ScanContext, id: &str) -> hbs_extractor::model::CheckResult {
    let mut reg: Vec<RegisteredCheck> = Vec::new();
    register_all(&mut reg);
    let subset: Vec<RegisteredCheck> = reg.into_iter().filter(|c| c.tc.id == id).collect();
    assert_eq!(subset.len(), 1, "{id} registered");
    run_all(&subset, ctx).remove(0)
}

#[test]
fn hardened_mounts_pass() {
    let mut ctx = linux_ctx("tests/fixtures/fs-hardened");
    for id in ["LIN-FS-001", "LIN-FS-002", "LIN-FS-003", "LIN-FS-005"] {
        let r = run_one(&mut ctx, id);
        assert_eq!(r.status, Status::Compliant, "{id}: {:?} — {}", r.status, r.evidence);
    }
}

#[test]
fn weak_mounts_fail() {
    let mut ctx = linux_ctx("tests/fixtures/fs-weak");
    let r = run_one(&mut ctx, "LIN-FS-002");
    assert_eq!(r.status, Status::NonCompliant, "{}", r.evidence);
    assert!(r.evidence.contains("WITHOUT nodev"));
    let r = run_one(&mut ctx, "LIN-FS-005");
    assert_eq!(r.status, Status::NonCompliant);
}

#[test]
fn missing_mounts_degrade_not_error() {
    let mut ctx = linux_ctx("tests/fixtures/fs-weak");
    let r = run_one(&mut ctx, "LIN-FS-010"); // /home not separate
    assert_eq!(r.status, Status::DegradedPartial, "{}", r.evidence);
}

#[test]
fn missing_proc_mounts_degrades() {
    let mut ctx = linux_ctx("tests/fixtures/empty-root");
    let r = run_one(&mut ctx, "LIN-FS-001");
    assert_eq!(r.status, Status::DegradedPartial, "{}", r.evidence);
    assert!(r.degraded_reason.as_deref().unwrap().contains("/proc/mounts"));
}

#[test]
fn bootloader_password_detected() {
    let mut ctx = linux_ctx("tests/fixtures/fs-weak");
    let r = run_one(&mut ctx, "LIN-FS-013");
    // fixture grub.cfg has no password
    assert_eq!(r.status, Status::NonCompliant, "{}", r.evidence);
}
