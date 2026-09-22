//! WIN-TH-015..027 (Task 39): persistence hunting, EOL, LAPS.

use hbs_extractor::checks::windows::threat_persist::{
    parse_firewall_rules, parse_localgroup_members, parse_schtasks_csv, windows_build_support,
    WindowsBuildSupport,
};
use hbs_extractor::checks::{register_all, windows};
use hbs_extractor::context::ScanContext;
use hbs_extractor::engine::run_all;
use hbs_extractor::evidence::CmdInjector;
use hbs_extractor::model::{CheckResult, RegisteredCheck, Status};
use hbs_extractor::platform::{detect, Os};

fn windows_ctx(injector: CmdInjector) -> ScanContext {
    let mut platform = detect();
    platform.os = Os::Windows;
    ScanContext::new(platform, true).with_injector(injector)
}

fn run_one(ctx: &mut ScanContext, id: &str) -> CheckResult {
    let mut registry: Vec<RegisteredCheck> = Vec::new();
    register_all(&mut registry);
    let subset: Vec<_> = registry.into_iter().filter(|c| c.tc.id == id).collect();
    assert_eq!(subset.len(), 1, "Check {id} registration count");
    run_all(&subset, ctx).remove(0)
}

fn injector(responses: &'static [(&'static str, Option<&'static str>)]) -> CmdInjector {
    Box::new(move |program, args| {
        let joined = format!("{program} {}", args.join(" "));
        responses
            .iter()
            .find(|(needle, _)| joined.contains(needle))
            .and_then(|(_, out)| out.map(str::to_owned))
    })
}

#[test]
fn registers_thirteen_stable_persistence_ids() {
    let mut registry = Vec::new();
    windows::threat_persist::register(&mut registry);
    let ids: Vec<_> = registry.iter().map(|c| c.tc.id).collect();
    assert_eq!(
        ids,
        (15..=27)
            .map(|n| format!("WIN-TH-{n:03}"))
            .collect::<Vec<_>>()
    );
}

#[test]
fn ifeo_debugger_and_netsh_helper_sweeps() {
    let dirty: &'static [(&'static str, Option<&'static str>)] = &[
        (
            "Image File Execution Options",
            Some("HKEY_LOCAL_MACHINE\\...\\sethc.exe\n    Debugger    REG_SZ    C:\\evil.exe\n"),
        ),
        (
            "Microsoft\\NetSh",
            Some("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\NetSh\n    EvilHelper    REG_SZ    C:\\evil.dll\n"),
        ),
    ];
    let mut ctx = windows_ctx(injector(dirty));
    assert_eq!(run_one(&mut ctx, "WIN-TH-015").status, Status::NonCompliant);
    assert_eq!(run_one(&mut ctx, "WIN-TH-022").status, Status::NonCompliant);

    let clean: &'static [(&'static str, Option<&'static str>)] = &[
        (
            "Image File Execution Options",
            Some("HKEY_LOCAL_MACHINE\\...\\notepad.exe\n"),
        ),
        (
            "Microsoft\\NetSh",
            Some("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\NetSh\n"),
        ),
    ];
    let mut ctx2 = windows_ctx(injector(clean));
    assert_eq!(run_one(&mut ctx2, "WIN-TH-015").status, Status::Compliant);
    assert_eq!(run_one(&mut ctx2, "WIN-TH-022").status, Status::Compliant);
}

/// WIN-TH-015 fallback chain: `reg query /s` -> PowerShell
/// `Get-ChildItem` + value reads -> native in-process IFEO enumeration.
#[test]
fn ifeo_fallback_chain_is_ordered_and_never_errors() {
    let mut ctx = windows_ctx(Box::new(|_, _| None));
    let res = run_one(&mut ctx, "WIN-TH-015");
    assert_eq!(res.status, Status::DegradedPartial, "{}", res.evidence);
    assert_eq!(
        res.fallback_log
            .iter()
            .map(|a| a.source.as_str())
            .collect::<Vec<_>>(),
        [
            "reg query HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options /s /v Debugger",
            "PowerShell Get-ChildItem",
            "native registry IFEO enumeration",
        ],
        "{}",
        res.evidence
    );
    assert!(res.degraded_reason.is_some());
}

#[test]
fn scheduled_task_parser_handles_quoted_commas_and_flags_risk() {
    let csv = concat!(
        "\"HostName\",\"TaskName\",\"Next Run Time\",\"Status\",\"Logon Mode\",\"Last Run Time\",\"Last Result\",\"Author\",\"Task To Run\"\n",
        "\"HOST\",\"\\Microsoft\\Safe\",\"N/A\",\"Ready\",\"Interactive\",\"N/A\",\"0\",\"Microsoft Corporation\",\"C:\\Windows\\System32\\clean.exe\"\n",
        "\"HOST\",\"\\Bad, Task\",\"N/A\",\"Ready\",\"Interactive\",\"N/A\",\"0\",\"Unknown\",\"C:\\Users\\bob\\AppData\\Local\\Temp\\run.exe\"\n",
    );
    let rows = parse_schtasks_csv(csv).expect("parse csv");
    assert_eq!(rows.len(), 2);
    assert!(!rows[0].suspicious);
    assert!(rows[1].suspicious);

    let responses: &'static [(&'static str, Option<&'static str>)] = &[(
        "schtasks /query",
        Some(concat!(
            "\"HostName\",\"TaskName\",\"Author\",\"Task To Run\"\n",
            "\"HOST\",\"\\Bad\",\"Unknown\",\"C:\\Temp\\run.exe\"\n",
        )),
    )];
    let mut ctx = windows_ctx(injector(responses));
    assert_eq!(run_one(&mut ctx, "WIN-TH-017").status, Status::NonCompliant);
}

#[test]
fn service_paths_and_wmi_subscriptions_evaluated() {
    let dirty: &'static [(&'static str, Option<&'static str>)] = &[
        (
            "Win32_Service",
            Some(
                r#"[{"Name":"Safe","PathName":"C:\\Windows\\safe.exe"},{"Name":"Bad","PathName":"C:\\Users\\bob\\svc.exe"}]"#,
            ),
        ),
        ("__EventFilter", Some(r#"[{"Name":"PersistFilter"}]"#)),
        (
            "CommandLineEventConsumer",
            Some(r#"[{"Name":"PersistConsumer","CommandLineTemplate":"cmd.exe /c calc"}]"#),
        ),
    ];
    let mut ctx = windows_ctx(injector(dirty));
    assert_eq!(run_one(&mut ctx, "WIN-TH-018").status, Status::NonCompliant);
    assert_eq!(run_one(&mut ctx, "WIN-TH-019").status, Status::NonCompliant);

    let clean: &'static [(&'static str, Option<&'static str>)] = &[
        (
            "Win32_Service",
            Some(r#"[{"Name":"Safe","PathName":"C:\\Windows\\safe.exe"}]"#),
        ),
        ("__EventFilter", Some("[]")),
        ("CommandLineEventConsumer", Some("[]")),
    ];
    let mut ctx2 = windows_ctx(injector(clean));
    assert_eq!(run_one(&mut ctx2, "WIN-TH-018").status, Status::Compliant);
    assert_eq!(run_one(&mut ctx2, "WIN-TH-019").status, Status::Compliant);
}

#[test]
fn firewall_rule_parser_flags_inbound_user_path_program() {
    let raw = concat!(
        "Rule Name: Safe\nEnabled: Yes\nDirection: In\nAction: Allow\nProgram: C:\\Windows\\safe.exe\n\n",
        "Rule Name: Bad\nEnabled: Yes\nDirection: In\nAction: Allow\nProgram: C:\\Users\\bob\\evil.exe\n",
    );
    let rules = parse_firewall_rules(raw);
    assert_eq!(rules.len(), 2);
    assert!(!rules[0].suspicious);
    assert!(rules[1].suspicious);

    let responses: &'static [(&'static str, Option<&'static str>)] = &[(
        "netsh advfirewall firewall show rule name=all",
        Some(concat!(
            "Rule Name: Bad\nEnabled: Yes\nDirection: In\nAction: Allow\nProgram: C:\\Temp\\evil.exe\n",
        )),
    )];
    let mut ctx = windows_ctx(injector(responses));
    assert_eq!(run_one(&mut ctx, "WIN-TH-021").status, Status::NonCompliant);
}

#[test]
fn fax_disabled_or_absent_passes_enabled_fails() {
    let off: &'static [(&'static str, Option<&'static str>)] = &[(
        "sc qc Fax",
        Some("SERVICE_NAME: Fax\n        START_TYPE         : 4   DISABLED\n"),
    )];
    let mut ctx = windows_ctx(injector(off));
    assert_eq!(run_one(&mut ctx, "WIN-TH-023").status, Status::Compliant);

    let on: &'static [(&'static str, Option<&'static str>)] = &[(
        "sc qc Fax",
        Some("SERVICE_NAME: Fax\n        START_TYPE         : 2   AUTO_START\n"),
    )];
    let mut ctx2 = windows_ctx(injector(on));
    assert_eq!(
        run_one(&mut ctx2, "WIN-TH-023").status,
        Status::NonCompliant
    );
}

#[test]
fn eol_build_table_is_explicit_and_unknown_degrades() {
    assert_eq!(windows_build_support("10.0.9200"), WindowsBuildSupport::Eol);
    assert_eq!(windows_build_support("10.0.9600"), WindowsBuildSupport::Eol);
    assert_eq!(
        windows_build_support("10.0.17763"),
        WindowsBuildSupport::Supported
    );
    assert_eq!(
        windows_build_support("10.0.99999"),
        WindowsBuildSupport::Unknown
    );

    let mut ctx = windows_ctx(Box::new(|_, _| None));
    ctx.platform.kernel = "10.0.9200".into();
    assert_eq!(run_one(&mut ctx, "WIN-TH-024").status, Status::NonCompliant);

    ctx.platform.kernel = "10.0.99999".into();
    assert_eq!(
        run_one(&mut ctx, "WIN-TH-024").status,
        Status::DegradedPartial
    );
}

#[test]
fn patch_age_laps_and_local_admins_evaluated() {
    let dirty: &'static [(&'static str, Option<&'static str>)] = &[
        ("Get-HotFix", Some(r#"{"HotFixID":"KB1","InstalledOn":"1/1/2020 00:00:00"}"#)),
        ("dsregcmd /status", Some("DomainJoined : YES\nAzureAdJoined : NO\n")),
        ("Windows\\LAPS", Some("ERROR: unable to find key\n")),
        ("AdmPwdService", Some("ERROR: unable to find key\n")),
        (
            "net localgroup Administrators",
            Some("Alias name     Administrators\n---\nAdministrator\nCORP\\Domain Admins\nbob\nThe command completed successfully.\n"),
        ),
    ];
    let mut ctx = windows_ctx(injector(dirty));
    assert_eq!(run_one(&mut ctx, "WIN-TH-025").status, Status::NonCompliant);
    assert_eq!(run_one(&mut ctx, "WIN-TH-026").status, Status::NonCompliant);
    assert_eq!(run_one(&mut ctx, "WIN-TH-027").status, Status::NonCompliant);

    let local =
        "Alias name     Administrators\n---\nAdministrator\nThe command completed successfully.\n";
    assert_eq!(parse_localgroup_members(local), vec!["Administrator"]);
}

#[test]
fn all_blocked_degrades_never_errors_except_platform_only_eol() {
    let mut ctx = windows_ctx(Box::new(|_, _| None));
    ctx.root_prefix = std::path::PathBuf::from("Z:/definitely-missing-hbs-fixture");
    ctx.platform.kernel = "10.0.99999".into();
    for i in 15..=27 {
        let id = format!("WIN-TH-{i:03}");
        let res = run_one(&mut ctx, &id);
        assert_eq!(
            res.status,
            Status::DegradedPartial,
            "{id}: {}",
            res.evidence
        );
    }
}

#[test]
fn threat_persistence_commands_are_query_only() {
    let data: &'static [(&'static str, Option<&'static str>)] = &[
        (
            "Image File Execution Options",
            Some("HKEY_LOCAL_MACHINE\\...\n"),
        ),
        (
            "Shell Folders",
            Some("    Common Startup    REG_SZ    C:\\ProgramData\\StartUp\n"),
        ),
        (
            "schtasks /query",
            Some("\"TaskName\",\"Author\",\"Task To Run\"\n"),
        ),
        ("Win32_Service", Some("[]")),
        ("__EventFilter", Some("[]")),
        ("CommandLineEventConsumer", Some("[]")),
        ("netsh advfirewall firewall show", Some("No rules match\n")),
        (
            "Microsoft\\NetSh",
            Some("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\NetSh\n"),
        ),
        (
            "sc qc Fax",
            Some("SERVICE_NAME: Fax\n START_TYPE : 4 DISABLED\n"),
        ),
        (
            "Get-HotFix",
            Some(r#"{"HotFixID":"KB1","InstalledOn":"12/31/2099"}"#),
        ),
        (
            "dsregcmd /status",
            Some("DomainJoined : NO\nAzureAdJoined : NO\n"),
        ),
        (
            "net localgroup Administrators",
            Some("---\nAdministrator\nThe command completed successfully.\n"),
        ),
    ];
    let mut ctx = windows_ctx(injector(data));
    ctx.platform.kernel = "10.0.17763".into();
    for i in 15..=27 {
        run_one(&mut ctx, &format!("WIN-TH-{i:03}"));
    }
    let bad: Vec<_> = ctx
        .audit
        .commands
        .iter()
        .filter(|c| {
            !(c.starts_with("reg query ")
                || c.starts_with("powershell ")
                || c.starts_with("schtasks /query ")
                || c.starts_with("netsh advfirewall firewall show ")
                || c.starts_with("sc qc ")
                || c.starts_with("dsregcmd /status")
                || c.starts_with("net localgroup "))
        })
        .collect();
    assert!(bad.is_empty(), "unexpected commands: {bad:?}");
}
