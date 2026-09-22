use hbs_extractor::checks::register_all;
use hbs_extractor::context::ScanContext;
use hbs_extractor::engine::run_all;
use hbs_extractor::model::{RegisteredCheck, Status};
use hbs_extractor::platform::{detect, DistroFamily, EnvironmentInfo, Os};

fn ctx_with(injector: hbs_extractor::evidence::CmdInjector, root: &str) -> ScanContext {
    let mut p = detect();
    p.os = Os::Linux;
    p.family = DistroFamily::Debian;
    p.environment = EnvironmentInfo::default();
    ScanContext::new(p, false).with_root_prefix(root).with_injector(injector)
}

fn run_one(ctx: &mut ScanContext, id: &str) -> hbs_extractor::model::CheckResult {
    let mut reg: Vec<RegisteredCheck> = Vec::new();
    register_all(&mut reg);
    let subset: Vec<RegisteredCheck> = reg.into_iter().filter(|c| c.tc.id == id).collect();
    run_all(&subset, ctx).remove(0)
}

#[test]
fn running_ufw_passes() {
    let mut ctx = ctx_with(
        Box::new(|prog, args| {
            if prog == "systemctl" && args.contains(&"is-active") && args.contains(&"ufw") {
                Some("active".into())
            } else if prog == "systemctl" && args.contains(&"is-enabled") && args.contains(&"ufw") {
                Some("enabled".into())
            } else if prog == "ufw" {
                Some("Status: active\nDefault: deny (incoming), allow (outgoing)".into())
            } else {
                None
            }
        }),
        "tests/fixtures/empty-root",
    );
    assert_eq!(run_one(&mut ctx, "LIN-FW-001").status, Status::Compliant);
    assert_eq!(run_one(&mut ctx, "LIN-FW-002").status, Status::Compliant);
    assert_eq!(run_one(&mut ctx, "LIN-FW-004").status, Status::Compliant);
}

#[test]
fn no_firewall_fails() {
    let mut ctx = ctx_with(Box::new(|_, _| None), "tests/fixtures/empty-root");
    // systemctl exists (returns "inactive" via fallback path? injector None means unavailable)
    let r = run_one(&mut ctx, "LIN-FW-001");
    assert_eq!(r.status, Status::DegradedPartial); // systemd unqueryable -> degraded, not false-positive
}

#[test]
fn ufw_default_deny_falls_back_to_config_file() {
    let mut ctx = ctx_with(
        Box::new(|prog, _| if prog == "systemctl" { Some("active".into()) } else { None }),
        "tests/fixtures/fw-root",
    );
    let r = run_one(&mut ctx, "LIN-FW-004");
    assert_eq!(r.status, Status::Compliant, "{}", r.evidence);
    assert!(r.evidence.contains("DROP"));
}
