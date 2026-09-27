use hbs_extractor::checks::windows::event_logs::{parse_log_config, LogConfig};
use hbs_extractor::checks::{register_all, windows};
use hbs_extractor::context::ScanContext;
use hbs_extractor::engine::run_all;
use hbs_extractor::evidence::CmdInjector;
use hbs_extractor::model::{CheckResult, RegisteredCheck, Status};
use hbs_extractor::platform::{detect, Os};

const APPLICATION_GOOD: &str = r#"name: Application
enabled: true
channelAccess: O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)
logging:
  logFileName: %SystemRoot%\System32\Winevt\Logs\Application.evtx
  retention: false
  autoBackup: false
  maxSize: 33554432
"#;

const SECURITY_GOOD: &str = r#"name: Security
enabled: true
channelAccess: O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)
logging:
  logFileName: %SystemRoot%\System32\Winevt\Logs\Security.evtx
  retention: true
  autoBackup: false
  maxSize: 67108864
"#;

const SYSTEM_GOOD: &str = r#"name: System
enabled: true
channelAccess: O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)
logging:
  logFileName: %SystemRoot%\System32\Winevt\Logs\System.evtx
  retention: false
  autoBackup: false
  maxSize: 33554432
"#;

fn windows_ctx(injector: CmdInjector) -> ScanContext {
    let mut platform = detect();
    platform.os = Os::Windows;
    ScanContext::new(platform, true).with_injector(injector)
}

fn event_log_injector(
    application: Option<&'static str>,
    security: Option<&'static str>,
    system: Option<&'static str>,
    channels: Option<&'static str>,
) -> CmdInjector {
    Box::new(move |program, args| match (program, args) {
        ("wevtutil", ["gl", "Application"]) => application.map(str::to_owned),
        ("wevtutil", ["gl", "Security"]) => security.map(str::to_owned),
        ("wevtutil", ["gl", "System"]) => system.map(str::to_owned),
        ("wevtutil", ["el"]) => channels.map(str::to_owned),
        _ => None,
    })
}

fn run_one(ctx: &mut ScanContext, id: &str) -> CheckResult {
    let mut registry: Vec<RegisteredCheck> = Vec::new();
    register_all(&mut registry);
    let subset: Vec<_> = registry.into_iter().filter(|c| c.tc.id == id).collect();
    assert!(!subset.is_empty(), "Check {id} not found in registry");
    run_all(&subset, ctx).remove(0)
}

#[test]
fn parses_wevtutil_log_configuration_without_inventing_retention_duration() {
    assert_eq!(
        parse_log_config(SECURITY_GOOD),
        LogConfig {
            max_size_bytes: Some(67_108_864),
            retention: Some(true),
            auto_backup: Some(false),
            channel_access: Some("O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)".into()),
        }
    );
}

#[test]
fn registers_six_stable_event_log_ids() {
    let mut registry = Vec::new();
    windows::event_logs::register(&mut registry);
    let ids: Vec<_> = registry.iter().map(|c| c.tc.id).collect();
    assert_eq!(
        ids,
        (1..=6)
            .map(|n| format!("WIN-EVT-{n:03}"))
            .collect::<Vec<_>>()
    );
}

#[test]
fn configured_logs_pass_size_retention_and_acl_checks() {
    let mut ctx = windows_ctx(event_log_injector(
        Some(APPLICATION_GOOD),
        Some(SECURITY_GOOD),
        Some(SYSTEM_GOOD),
        Some("Application\nSecurity\nSystem\nWindows PowerShell\n"),
    ));

    for i in 1..=6 {
        let id = format!("WIN-EVT-{i:03}");
        let result = run_one(&mut ctx, &id);
        assert_eq!(
            result.status,
            Status::Compliant,
            "{id}: {}",
            result.evidence
        );
    }
}

#[test]
fn undersized_logs_are_non_compliant() {
    const SMALL: &str = "logging:\n  maxSize: 33554431\n";
    let mut ctx = windows_ctx(event_log_injector(
        Some(SMALL),
        Some(SMALL),
        Some(SMALL),
        None,
    ));

    for i in 1..=3 {
        let id = format!("WIN-EVT-{i:03}");
        let result = run_one(&mut ctx, &id);
        assert_eq!(
            result.status,
            Status::NonCompliant,
            "{id}: {}",
            result.evidence
        );
    }
}

#[test]
fn security_retention_passes_when_auto_backup_is_enabled() {
    const AUTO_BACKUP: &str = "logging:\n  retention: false\n  autoBackup: true\n  maxSize: 33554432\nchannelAccess: O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)\n";
    let mut ctx = windows_ctx(event_log_injector(None, Some(AUTO_BACKUP), None, None));
    assert_eq!(run_one(&mut ctx, "WIN-EVT-004").status, Status::Compliant);
}

#[test]
fn disabled_retention_and_auto_backup_is_non_compliant() {
    const OVERWRITE: &str = "logging:\n  retention: false\n  autoBackup: false\n  maxSize: 33554432\nchannelAccess: O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)\n";
    let mut ctx = windows_ctx(event_log_injector(None, Some(OVERWRITE), None, None));
    assert_eq!(
        run_one(&mut ctx, "WIN-EVT-004").status,
        Status::NonCompliant
    );
}

#[test]
fn broad_security_log_acl_is_non_compliant() {
    const BROAD_ACL: &str = "logging:\n  retention: true\n  autoBackup: false\n  maxSize: 33554432\nchannelAccess: O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;WD)\n";
    let mut ctx = windows_ctx(event_log_injector(None, Some(BROAD_ACL), None, None));
    assert_eq!(
        run_one(&mut ctx, "WIN-EVT-005").status,
        Status::NonCompliant
    );
}

#[test]
fn unavailable_or_unknown_values_degrade_never_error() {
    const UNKNOWN: &str = "name: Security\nlogging:\n  maxSize: unknown\n  retention: unknown\n  autoBackup: unknown\n";
    let mut ctx = windows_ctx(event_log_injector(
        Some(UNKNOWN),
        Some(UNKNOWN),
        Some(UNKNOWN),
        None,
    ));

    for i in 1..=6 {
        let id = format!("WIN-EVT-{i:03}");
        let result = run_one(&mut ctx, &id);
        assert_eq!(
            result.status,
            Status::DegradedPartial,
            "{id}: {:?}",
            result.status
        );
        assert!(
            !result.fallback_log.is_empty(),
            "{id} must record query attempt"
        );
    }
}

#[test]
fn event_log_checks_execute_only_wevtutil_queries() {
    let mut ctx = windows_ctx(event_log_injector(
        Some(APPLICATION_GOOD),
        Some(SECURITY_GOOD),
        Some(SYSTEM_GOOD),
        Some("Application\nSecurity\nSystem\n"),
    ));

    for i in 1..=6 {
        run_one(&mut ctx, &format!("WIN-EVT-{i:03}"));
    }

    assert!(!ctx.audit.commands.is_empty());
    assert!(
        ctx.audit.commands.iter().all(|command| {
            command == "wevtutil el"
                || command == "wevtutil gl Application"
                || command == "wevtutil gl Security"
                || command == "wevtutil gl System"
        }),
        "unexpected command(s): {:?}",
        ctx.audit.commands
    );
}

#[test]
fn mutating_wevtutil_commands_are_rejected_by_evidence_allowlist() {
    let mut ctx = windows_ctx(Box::new(|_, _| Some("stub".into())));

    assert!(ctx.cmd("wevtutil", &["gl", "Security"]).is_some());
    assert!(ctx.cmd("wevtutil", &["el"]).is_some());
    assert!(ctx
        .cmd("wevtutil", &["sl", "Security", "/rt:true"])
        .is_none());
    assert!(ctx.cmd("wevtutil", &["cl", "Security"]).is_none());
    assert!(ctx.cmd("wevtutil", &["im", "manifest.xml"]).is_none());
}
