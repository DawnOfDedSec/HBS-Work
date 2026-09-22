use hbs_extractor::checks::windows::services::parse_sc_qc;
use hbs_extractor::checks::{register_all, windows};
use hbs_extractor::context::ScanContext;
use hbs_extractor::engine::run_all;
use hbs_extractor::evidence::CmdInjector;
use hbs_extractor::model::{CheckResult, RegisteredCheck, Status};
use hbs_extractor::platform::{detect, Os};

const TELNET_DISABLED: &str = "SERVICE_NAME: TlntSvr\n        TYPE               : 10  WIN32_OWN_PROCESS\n        START_TYPE         : 4   DISABLED\n        BINARY_PATH_NAME   : C:\\Windows\\System32\\tlntsvr.exe\n";
const SPOOLER_AUTO: &str = "SERVICE_NAME: Spooler\n        TYPE               : 110  WIN32_OWN_PROCESS (shared)\n        START_TYPE         : 2   AUTO_START\n        BINARY_PATH_NAME   : C:\\Windows\\System32\\spoolsv.exe\n";
const SPOOLER_DISABLED: &str = "SERVICE_NAME: Spooler\n        START_TYPE         : 4   DISABLED\n        BINARY_PATH_NAME   : C:\\Windows\\System32\\spoolsv.exe\n";
const SMBV1_DRIVER: &str = "SERVICE_NAME: MRxSmb10\n        START_TYPE         : 4   DISABLED\n";
const SYSMAIN_AUTO: &str = "SERVICE_NAME: SysMain\n        START_TYPE         : 2   AUTO_START\n";

fn windows_ctx(injector: CmdInjector) -> ScanContext {
    let mut platform = detect();
    platform.os = Os::Windows;
    ScanContext::new(platform, true).with_injector(injector)
}

fn run_one(ctx: &mut ScanContext, id: &str) -> CheckResult {
    let mut registry: Vec<RegisteredCheck> = Vec::new();
    register_all(&mut registry);
    let subset: Vec<_> = registry.into_iter().filter(|c| c.tc.id == id).collect();
    assert!(!subset.is_empty(), "Check {id} not found in registry");
    run_all(&subset, ctx).remove(0)
}

fn sc_injector(responses: &'static [(&'static str, Option<&'static str>)]) -> CmdInjector {
    Box::new(move |program, args| match (program, args) {
        // Probe services exist on every build: answering them proves sc works.
        ("sc", ["qc", name]) if ["RpcSs", "Schedule", "winmgmt"].contains(name) => {
            Some("START_TYPE : 2 AUTO_START\n".to_owned())
        }
        ("sc", ["qc", name]) => responses
            .iter()
            .find(|(svc, _)| svc.eq_ignore_ascii_case(name))
            .and_then(|(_, out)| out.map(str::to_owned)),
        ("sc", ["query", name]) => responses
            .iter()
            .find(|(svc, _)| svc.eq_ignore_ascii_case(name))
            .and_then(|(_, out)| out.map(|_| "RUNNING\n".to_owned())),
        _ => None,
    })
}

fn all_services() -> &'static [(&'static str, Option<&'static str>)] {
    &[
        ("TlntSvr", Some(TELNET_DISABLED)),
        ("Spooler", Some(SPOOLER_DISABLED)),
        ("MRxSmb10", Some(SMBV1_DRIVER)),
        ("SysMain", Some(SYSMAIN_AUTO)),
    ]
}

#[test]
fn registers_twenty_stable_service_ids() {
    let mut registry = Vec::new();
    windows::services::register(&mut registry);
    let ids: Vec<_> = registry.iter().map(|c| c.tc.id).collect();
    assert_eq!(
        ids,
        (1..=20)
            .map(|n| format!("WIN-SVC-{n:03}"))
            .collect::<Vec<_>>()
    );
}

#[test]
fn parse_sc_qc_reads_start_type_and_path() {
    let cfg = parse_sc_qc(TELNET_DISABLED).expect("parses canned output");
    assert_eq!(cfg.start_type, Some(4));
    assert_eq!(
        cfg.binary_path.as_deref(),
        Some(r"C:\Windows\System32\tlntsvr.exe")
    );
}

#[test]
fn disabled_or_absent_services_pass() {
    let mut ctx = windows_ctx(sc_injector(all_services()));
    // WIN-SVC-001 Telnet disabled -> Compliant
    let res = run_one(&mut ctx, "WIN-SVC-001");
    assert_eq!(res.status, Status::Compliant, "{}", res.evidence);

    // WIN-SVC-005 Fax absent -> Compliant
    let res = run_one(&mut ctx, "WIN-SVC-005");
    assert_eq!(res.status, Status::Compliant, "{}", res.evidence);

    // WIN-SVC-006 SMBv1 driver disabled -> Compliant
    let res = run_one(&mut ctx, "WIN-SVC-006");
    assert_eq!(res.status, Status::Compliant, "{}", res.evidence);
}

#[test]
fn spooler_enabled_is_non_compliant_when_disabled_expected() {
    let responses: &'static [(&'static str, Option<&'static str>)] = &[
        ("TlntSvr", Some(TELNET_DISABLED)),
        ("Spooler", Some(SPOOLER_AUTO)),
        ("MRxSmb10", Some(SMBV1_DRIVER)),
    ];
    let mut ctx = windows_ctx(sc_injector(responses));
    let res = run_one(&mut ctx, "WIN-SVC-004");
    assert_eq!(res.status, Status::NonCompliant, "{}", res.evidence);

    let responses2: &'static [(&'static str, Option<&'static str>)] =
        &[("Spooler", Some(SPOOLER_DISABLED))];
    let mut ctx2 = windows_ctx(sc_injector(responses2));
    let res2 = run_one(&mut ctx2, "WIN-SVC-004");
    assert_eq!(res2.status, Status::Compliant, "{}", res2.evidence);
}

#[test]
fn missing_sc_tool_degrades_never_errors() {
    let mut ctx = windows_ctx(Box::new(|_, _| None));
    for i in 1..=19 {
        let id = format!("WIN-SVC-{i:03}");
        let res = run_one(&mut ctx, &id);
        assert_eq!(
            res.status,
            Status::DegradedPartial,
            "{id}: {:?}",
            res.status
        );
    }
}

#[test]
fn service_checks_only_use_query_verbs() {
    let mut ctx = windows_ctx(sc_injector(all_services()));
    for i in 1..=19 {
        run_one(&mut ctx, &format!("WIN-SVC-{i:03}"));
    }
    assert!(ctx
        .audit
        .commands
        .iter()
        .all(|c| c.starts_with("sc qc ") || c.starts_with("sc query ")));
}

#[test]
fn informational_auto_start_inventory_never_fails() {
    let mut ctx = windows_ctx(sc_injector(all_services()));
    let res = run_one(&mut ctx, "WIN-SVC-020");
    assert_ne!(res.status, Status::NonCompliant);
    assert_ne!(res.status, Status::Error);
}
