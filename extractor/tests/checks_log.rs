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
fn forwarding_configured_passes() {
    let mut ctx = ctx_with("tests/fixtures/log-root", None);
    let r = run_one(&mut ctx, "LIN-LOG-002");
    assert_eq!(r.status, Status::Compliant, "{}", r.evidence);
    assert!(r.evidence.contains("@@"));
}

#[test]
fn facilities_missing_fails() {
    let mut ctx = ctx_with("tests/fixtures/log-root", None);
    let r = run_one(&mut ctx, "LIN-LOG-004");
    // fixture has auth but not daemon/syslog
    assert_eq!(r.status, Status::NonCompliant, "{}", r.evidence);
}

#[test]
fn journald_persistent_passes() {
    let mut ctx = ctx_with("tests/fixtures/log-root", None);
    let r = run_one(&mut ctx, "LIN-LOG-007");
    assert_eq!(r.status, Status::Compliant, "{}", r.evidence);
}

#[test]
fn logrotate_retention_passes() {
    let mut ctx = ctx_with("tests/fixtures/log-root", None);
    let r = run_one(&mut ctx, "LIN-LOG-013");
    assert_eq!(r.status, Status::Compliant, "{}", r.evidence);
}

#[test]
fn rsyslog_enabled_via_systemctl() {
    let mut ctx = ctx_with(
        "tests/fixtures/log-root",
        Some(Box::new(|prog, args| {
            if prog == "systemctl" && args.contains(&"is-enabled") && args.contains(&"rsyslog") {
                Some("enabled".into())
            } else {
                None
            }
        })),
    );
    assert_eq!(run_one(&mut ctx, "LIN-LOG-001").status, Status::Compliant);
}

#[test]
fn no_config_degrades() {
    let mut ctx = ctx_with("tests/fixtures/empty-root", Some(Box::new(|_, _| None)));
    let r = run_one(&mut ctx, "LIN-LOG-002");
    assert_eq!(r.status, Status::DegradedPartial);
}
