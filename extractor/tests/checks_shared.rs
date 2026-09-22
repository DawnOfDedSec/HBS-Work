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
    assert!(
        r.fallback_log.iter().any(|a| a.source == "/etc/passwd"),
        "fallback_log should record the source: {:?}",
        r.fallback_log
    );
}

/// Windows users/groups chain: `net user` -> `net localgroup` ->
/// PowerShell -> native NetAPI -> registry ProfileList. Every step is
/// recorded, and a failed read falls through to the next source.
#[test]
fn gen_inv_003_windows_chain_records_every_attempt() {
    let mut p = detect();
    p.os = Os::Windows;
    let mut ctx = ScanContext::new(p, false).with_injector(Box::new(|_, _| None));
    let r = run_one(&mut ctx, "GEN-INV-003");
    assert_eq!(r.status, Status::DegradedPartial, "{}", r.evidence);
    let sources: Vec<&str> = r.fallback_log.iter().map(|a| a.source.as_str()).collect();
    assert_eq!(
        sources,
        [
            "net user",
            "net localgroup",
            "PowerShell Get-LocalUser",
            "PowerShell Get-LocalGroup",
            "native NetUserEnum/NetLocalGroupEnum",
        ],
        "{}",
        r.evidence
    );
}

/// GEN-INV-002 Windows chain: package managers -> Get-Package ->
/// Win32_Product CIM -> native registry Uninstall keys.
#[test]
fn gen_inv_002_windows_chain_records_every_attempt() {
    let mut p = detect();
    p.os = Os::Windows;
    let mut ctx = ScanContext::new(p, false).with_injector(Box::new(|_, _| None));
    let r = run_one(&mut ctx, "GEN-INV-002");
    assert_eq!(r.status, Status::DegradedPartial, "{}", r.evidence);
    let sources: Vec<&str> = r.fallback_log.iter().map(|a| a.source.as_str()).collect();
    assert!(sources.contains(&"Get-Package".to_string().as_str()) || sources.contains(&"powershell Get-Package"));
    assert!(sources.contains(&"Get-CimInstance Win32_Product"));
    assert!(sources.contains(&"native registry Uninstall keys"));
    assert!(r.evidence.contains("native registry") || r.evidence.contains("Uninstall"));
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
