use hbs_extractor::checks::register_all;
use hbs_extractor::context::ScanContext;
use hbs_extractor::engine::run_all;
use hbs_extractor::model::{RegisteredCheck, Status};
use hbs_extractor::platform::{detect, DistroFamily, Os};

fn ctx_with(injector: hbs_extractor::evidence::CmdInjector) -> ScanContext {
    let mut p = detect();
    p.os = Os::Linux;
    p.family = DistroFamily::Debian;
    ScanContext::new(p, false).with_root_prefix("tests/fixtures/empty-root").with_injector(injector)
}

fn run_one(ctx: &mut ScanContext, id: &str) -> hbs_extractor::model::CheckResult {
    let mut reg: Vec<RegisteredCheck> = Vec::new();
    register_all(&mut reg);
    let subset: Vec<RegisteredCheck> = reg.into_iter().filter(|c| c.tc.id == id).collect();
    run_all(&subset, ctx).remove(0)
}

#[test]
fn installed_telnet_fails() {
    let mut ctx = ctx_with(Box::new(|prog, args| {
        if prog == "dpkg-query" && args.contains(&"telnet") {
            Some("install ok installed".into())
        } else {
            None
        }
    }));
    let r = run_one(&mut ctx, "LIN-SV-005");
    assert_eq!(r.status, Status::NonCompliant, "{}", r.evidence);
    assert!(r.evidence.contains("telnet"));
}

#[test]
fn absent_packages_pass() {
    let mut ctx = ctx_with(Box::new(|_, _| None));
    let r = run_one(&mut ctx, "LIN-SV-005");
    assert_eq!(r.status, Status::Compliant, "{}", r.evidence);
}

#[test]
fn xinetd_disabled_passes_enabled_fails() {
    let mut ctx = ctx_with(Box::new(|prog, args| {
        if prog == "systemctl" && args.contains(&"is-enabled") && args.contains(&"xinetd") {
            Some("disabled".into())
        } else {
            None
        }
    }));
    assert_eq!(run_one(&mut ctx, "LIN-SV-001").status, Status::Compliant);

    let mut ctx = ctx_with(Box::new(|prog, args| {
        if prog == "systemctl" && args.contains(&"is-enabled") && args.contains(&"xinetd") {
            Some("enabled".into())
        } else {
            None
        }
    }));
    assert_eq!(run_one(&mut ctx, "LIN-SV-001").status, Status::NonCompliant);
}

#[test]
fn inetd_empty_conf_is_compliant() {
    let mut p = detect();
    p.os = Os::Linux;
    p.family = DistroFamily::Debian;
    let mut ctx = ScanContext::new(p, false)
        .with_root_prefix("tests/fixtures/svc-root")
        .with_injector(Box::new(|_, _| None));
    let r = run_one(&mut ctx, "LIN-SV-002");
    assert_eq!(r.status, Status::Compliant, "{}", r.evidence);
}

#[test]
fn unknown_distro_degrades_not_errors() {
    let mut p = detect();
    p.os = Os::Linux;
    p.family = DistroFamily::Unknown;
    let mut ctx = ScanContext::new(p, false).with_root_prefix("tests/fixtures/empty-root").with_injector(Box::new(|_, _| None));
    let r = run_one(&mut ctx, "LIN-SV-005");
    assert_eq!(r.status, Status::DegradedPartial);
}
