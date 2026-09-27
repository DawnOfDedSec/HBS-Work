use hbs_extractor::checks::register_all;
use hbs_extractor::context::ScanContext;
use hbs_extractor::engine::run_all;
use hbs_extractor::model::{RegisteredCheck, Status};
use hbs_extractor::platform::{detect, DistroFamily, Os};

fn ctx_with(root: &str, injector: Option<hbs_extractor::evidence::CmdInjector>) -> ScanContext {
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
    run_all(&subset, ctx).remove(0)
}

#[test]
fn last_assignment_wins() {
    // Fixture: commented 'PermitRootLogin yes', active 'PermitRootLogin no'
    let mut ctx = ctx_with("tests/fixtures/ssh-root", None);
    let r = run_one(&mut ctx, "LIN-SSH-001");
    assert_eq!(r.status, Status::Compliant, "{}", r.evidence);
}

#[test]
fn weak_values_fail() {
    let mut ctx = ctx_with("tests/fixtures/ssh-weak", None);
    let r = run_one(&mut ctx, "LIN-SSH-001");
    assert_eq!(r.status, Status::NonCompliant, "{}", r.evidence);
    let r = run_one(&mut ctx, "LIN-SSH-012");
    assert_eq!(r.status, Status::NonCompliant, "{}", r.evidence);
}

#[test]
fn sshd_dash_t_fallback_used_when_config_missing() {
    let mut ctx = ctx_with(
        "tests/fixtures/empty-root",
        Some(Box::new(|prog, args| {
            assert_eq!(prog, "sshd");
            assert_eq!(args, ["-T"]);
            Some("permitrootlogin no\nmaxauthtries 3\n".into())
        })),
    );
    let r = run_one(&mut ctx, "LIN-SSH-001");
    assert_eq!(r.status, Status::Compliant, "{}", r.evidence);
    assert!(r.fallback_log.iter().any(|f| f.source == "sshd -T"));
}

#[test]
fn unset_key_degrades() {
    // The injector simulates `sshd -T` without HostbasedAuthentication so the
    // test stays hermetic — hosted runners may ship a real sshd whose config
    // would otherwise answer the probe and flip the result to Compliant.
    let mut ctx = ctx_with(
        "tests/fixtures/ssh-weak",
        Some(Box::new(|prog, args| {
            assert_eq!(prog, "sshd");
            assert_eq!(args, ["-T"]);
            Some("permitrootlogin no\nmaxauthtries 3\n".into())
        })),
    );
    let r = run_one(&mut ctx, "LIN-SSH-014"); // HostbasedAuthentication not in fixture
    assert_eq!(r.status, Status::DegradedPartial, "{}", r.evidence);
}

#[test]
fn strong_ciphers_pass_weak_fail() {
    let mut ctx = ctx_with("tests/fixtures/ssh-root", None);
    assert_eq!(run_one(&mut ctx, "LIN-SSH-003").status, Status::Compliant);
    let mut ctx = ctx_with("tests/fixtures/ssh-weak", None);
    let r = run_one(&mut ctx, "LIN-SSH-003");
    assert_eq!(r.status, Status::NonCompliant, "{}", r.evidence);
}
