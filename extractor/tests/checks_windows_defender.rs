use hbs_extractor::checks::{register_all, windows};
use hbs_extractor::context::ScanContext;
use hbs_extractor::engine::run_all;
use hbs_extractor::evidence::CmdInjector;
use hbs_extractor::model::{CheckResult, RegisteredCheck, Status};
use hbs_extractor::platform::{detect, Os};

const GOOD_STATUS: &str = r#"{
  "AMServiceEnabled": true,
  "AntivirusEnabled": true,
  "RealTimeProtectionEnabled": true,
  "BehaviorMonitorEnabled": true,
  "IsTamperProtected": true,
  "AntivirusSignatureAge": 7
}"#;

const BAD_STATUS: &str = r#"{
  "AMServiceEnabled": false,
  "AntivirusEnabled": false,
  "RealTimeProtectionEnabled": false,
  "BehaviorMonitorEnabled": false,
  "IsTamperProtected": false,
  "AntivirusSignatureAge": 8
}"#;

const GOOD_PREFERENCE: &str = r#"{
  "DisableScriptScanning": false,
  "PUAProtection": 1,
  "AttackSurfaceReductionRules_Ids": ["rule-a", "rule-b", "rule-c"],
  "AttackSurfaceReductionRules_Actions": [1, 0, 6]
}"#;

const BAD_PREFERENCE: &str = r#"{
  "DisableScriptScanning": true,
  "PUAProtection": 0,
  "AttackSurfaceReductionRules_Ids": [],
  "AttackSurfaceReductionRules_Actions": []
}"#;

fn windows_ctx(injector: CmdInjector) -> ScanContext {
    let mut platform = detect();
    platform.os = Os::Windows;
    ScanContext::new(platform, true).with_injector(injector)
}

fn fixture_injector(
    status: Option<&'static str>,
    preference: Option<&'static str>,
    hotfix: Option<&'static str>,
    no_auto_update: Option<u32>,
) -> CmdInjector {
    Box::new(move |program, args| match program {
        "powershell" => {
            let script = args.last().copied().unwrap_or_default();
            if script.starts_with("Get-MpComputerStatus ") {
                status.map(str::to_owned)
            } else if script.starts_with("Get-MpPreference ") {
                preference.map(str::to_owned)
            } else if script.starts_with("Get-HotFix ") {
                hotfix.map(str::to_owned)
            } else {
                None
            }
        }
        "reg" if args == [
            "query",
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
            "/v",
            "NoAutoUpdate",
        ] => no_auto_update.map(|value| {
            format!("    NoAutoUpdate    REG_DWORD    0x{value:x}")
        }),
        _ => None,
    })
}

fn run_one(ctx: &mut ScanContext, id: &str) -> CheckResult {
    let mut registry: Vec<RegisteredCheck> = Vec::new();
    register_all(&mut registry);
    let subset: Vec<_> = registry.into_iter().filter(|c| c.tc.id == id).collect();
    assert_eq!(subset.len(), 1, "check {id} must be registered once");
    run_all(&subset, ctx).remove(0)
}

fn defender_results(ctx: &mut ScanContext) -> Vec<CheckResult> {
    let mut registry = Vec::new();
    windows::defender::register(&mut registry);
    run_all(&registry, ctx)
}

#[test]
fn registers_ten_stable_defender_ids_with_tamper_protection_here() {
    let mut registry = Vec::new();
    windows::defender::register(&mut registry);
    let ids: Vec<_> = registry.iter().map(|check| check.tc.id).collect();
    assert_eq!(
        ids,
        (1..=10)
            .map(|number| format!("WIN-DEF-{number:03}"))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        registry
            .iter()
            .filter(|check| check.tc.title.to_ascii_lowercase().contains("tamper"))
            .count(),
        1
    );
}

#[test]
fn healthy_defender_and_current_updates_pass_all_policy_checks() {
    let mut ctx = windows_ctx(fixture_injector(
        Some(GOOD_STATUS),
        Some(GOOD_PREFERENCE),
        Some(r#"{"HotFixID":"KB5065426","AgeDays":90}"#),
        Some(0),
    ));
    for result in defender_results(&mut ctx) {
        assert_eq!(
            result.status,
            Status::Compliant,
            "{}: {}",
            result.id,
            result.evidence
        );
    }
}

#[test]
fn disabled_or_stale_values_fail_their_checks() {
    let mut ctx = windows_ctx(fixture_injector(
        Some(BAD_STATUS),
        Some(BAD_PREFERENCE),
        Some(r#"{"HotFixID":"KB5000000","AgeDays":91}"#),
        Some(1),
    ));
    for result in defender_results(&mut ctx) {
        if result.id == "WIN-DEF-008" {
            assert_eq!(result.status, Status::Compliant, "{}", result.evidence);
            assert!(result.evidence.contains("active count = 0"), "{}", result.evidence);
        } else {
            assert_eq!(
                result.status,
                Status::NonCompliant,
                "{}: {}",
                result.id,
                result.evidence
            );
        }
    }
}

#[test]
fn asr_active_count_pairs_ids_and_actions_including_scalar_json() {
    let preference = r#"{
      "DisableScriptScanning": false,
      "PUAProtection": 1,
      "AttackSurfaceReductionRules_Ids": "rule-a",
      "AttackSurfaceReductionRules_Actions": 2
    }"#;
    let mut ctx = windows_ctx(fixture_injector(None, Some(preference), None, None));
    let result = run_one(&mut ctx, "WIN-DEF-008");
    assert_eq!(result.status, Status::Compliant, "{}", result.evidence);
    assert!(result.evidence.contains("active count = 1"), "{}", result.evidence);
}

#[test]
fn missing_cmdlets_denied_queries_and_bad_json_degrade_never_error() {
    for injector in [
        fixture_injector(None, None, None, None),
        fixture_injector(Some("Access denied"), Some("{"), Some("null"), None),
    ] {
        let mut ctx = windows_ctx(injector);
        let results = defender_results(&mut ctx);
        assert_eq!(results.len(), 10);
        for result in results {
            assert_eq!(
                result.status,
                Status::DegradedPartial,
                "{}: {}",
                result.id,
                result.evidence
            );
            assert!(!result.fallback_log.is_empty(), "{} missing source log", result.id);
        }
    }
}

#[test]
fn non_windows_platform_is_clearly_not_applicable() {
    let mut platform = detect();
    platform.os = Os::Linux;
    let mut ctx = ScanContext::new(platform, true).with_injector(Box::new(|_, _| {
        panic!("non-Windows defender checks must not execute commands")
    }));
    let mut registry = Vec::new();
    windows::defender::register(&mut registry);
    for result in run_all(&registry, &mut ctx) {
        assert_eq!(result.status, Status::NotApplicable, "{}", result.id);
    }
}

#[test]
fn defender_uses_constant_query_only_powershell_and_registry_commands() {
    let mut ctx = windows_ctx(fixture_injector(
        Some(GOOD_STATUS),
        Some(GOOD_PREFERENCE),
        Some(r#"{"HotFixID":"KB5065426","AgeDays":1}"#),
        Some(0),
    ));
    let results = defender_results(&mut ctx);
    assert!(results.iter().all(|result| result.status == Status::Compliant));

    let powershell_commands: Vec<_> = ctx
        .audit
        .commands
        .iter()
        .filter(|command| command.starts_with("powershell "))
        .collect();
    assert!(!powershell_commands.is_empty());
    assert!(powershell_commands.iter().all(|command| {
        command.contains("Get-MpComputerStatus")
            || command.contains("Get-MpPreference")
            || command.contains("Get-HotFix")
    }));
    assert!(ctx.audit.commands.iter().any(|command| command
        == r"reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate"));
    assert!(ctx.audit.commands.iter().all(|command| {
        !command.to_ascii_lowercase().contains("set-")
            && !command.to_ascii_lowercase().contains("invoke-")
            && !command.to_ascii_lowercase().contains("http")
    }));
}
