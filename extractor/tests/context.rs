use hbs_extractor::context::ScanContext;
use hbs_extractor::platform::{detect, DistroFamily, Os};

fn fixture_ctx() -> ScanContext {
    let mut p = detect();
    p.os = Os::Linux;
    p.family = DistroFamily::Debian;
    ScanContext::new(p, false)
        .with_root_prefix("tests/fixtures/context-root")
        .with_injector(Box::new(|prog, args| {
            assert_eq!(prog, "sshd");
            assert_eq!(args, ["-T"]);
            Some("permitrootlogin no".into())
        }))
}

#[test]
fn reads_join_root_prefix() {
    let mut ctx = fixture_ctx();
    let out = ctx.read("/etc/login.defs").unwrap();
    assert!(out.contains("PASS_MAX_DAYS 90"));
}

#[test]
fn second_read_is_served_from_cache_and_audited_once() {
    let mut ctx = fixture_ctx();
    let a = ctx.read("/etc/login.defs").unwrap();
    let b = ctx.read("/etc/login.defs").unwrap();
    assert_eq!(a, b);
    assert_eq!(ctx.audit.files_read.len(), 1);
}

#[test]
fn missing_path_returns_none() {
    let mut ctx = fixture_ctx();
    assert!(ctx.read("/etc/definitely/absent").is_none());
}

#[test]
fn cmd_uses_injector_in_tests() {
    let mut ctx = fixture_ctx();
    assert_eq!(ctx.cmd("sshd", &["-T"]).unwrap(), "permitrootlogin no");
    assert_eq!(ctx.audit.commands.len(), 1);
}

#[test]
fn path_helpers() {
    let ctx = fixture_ctx();
    assert!(ctx.exists("/etc/login.defs"));
    assert!(!ctx.exists("/etc/absent"));
    assert!(ctx.linux());
    assert!(!ctx.windows());
}
