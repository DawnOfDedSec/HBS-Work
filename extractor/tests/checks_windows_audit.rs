use hbs_extractor::checks::windows::audit::{
    parse_auditpol_csv, AuditPolicyRecord, AuditRequirement, AUDIT_CHECKS,
};
use hbs_extractor::checks::{register_all, windows};
use hbs_extractor::context::ScanContext;
use hbs_extractor::engine::run_all;
use hbs_extractor::evidence::CmdInjector;
use hbs_extractor::model::{CheckResult, RegisteredCheck, Status};
use hbs_extractor::platform::{detect, Os};

const GOOD_AUDITPOL_CSV: &str = r#"Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting
MYMACHINE,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,No Auditing
MYMACHINE,System,Logoff,{0CCE9216-69AE-11D9-BED3-505054503030},Success,No Auditing
MYMACHINE,System,Credential Validation,{0CCE923F-69AE-11D9-BED3-505054503030},Success and Failure,No Auditing
MYMACHINE,System,User Account Management,{0CCE9235-69AE-11D9-BED3-505054503030},Success and Failure,No Auditing
MYMACHINE,System,Security Group Management,{0CCE9237-69AE-11D9-BED3-505054503030},Success and Failure,No Auditing
MYMACHINE,System,Audit Policy Change,{0CCE922F-69AE-11D9-BED3-505054503030},Success and Failure,No Auditing
MYMACHINE,System,Sensitive Privilege Use,{0CCE9228-69AE-11D9-BED3-505054503030},Failure,No Auditing
MYMACHINE,System,Process Creation,{0CCE922B-69AE-11D9-BED3-505054503030},Success,No Auditing
MYMACHINE,System,File Share,{0CCE9224-69AE-11D9-BED3-505054503030},Failure,No Auditing
MYMACHINE,System,Security System Extension,{0CCE9211-69AE-11D9-BED3-505054503030},Success and Failure,No Auditing
"#;

const BAD_AUDITPOL_CSV: &str = r#"Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting
MYMACHINE,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},No Auditing,No Auditing
MYMACHINE,System,Logoff,{0CCE9216-69AE-11D9-BED3-505054503030},No Auditing,No Auditing
MYMACHINE,System,Credential Validation,{0CCE923F-69AE-11D9-BED3-505054503030},No Auditing,No Auditing
MYMACHINE,System,User Account Management,{0CCE9235-69AE-11D9-BED3-505054503030},No Auditing,No Auditing
MYMACHINE,System,Security Group Management,{0CCE9237-69AE-11D9-BED3-505054503030},No Auditing,No Auditing
MYMACHINE,System,Audit Policy Change,{0CCE922F-69AE-11D9-BED3-505054503030},No Auditing,No Auditing
MYMACHINE,System,Sensitive Privilege Use,{0CCE9228-69AE-11D9-BED3-505054503030},No Auditing,No Auditing
MYMACHINE,System,Process Creation,{0CCE922B-69AE-11D9-BED3-505054503030},No Auditing,No Auditing
MYMACHINE,System,File Share,{0CCE9224-69AE-11D9-BED3-505054503030},No Auditing,No Auditing
MYMACHINE,System,Security System Extension,{0CCE9211-69AE-11D9-BED3-505054503030},No Auditing,No Auditing
"#;

const LOCALIZED_GERMAN_AUDITPOL_CSV: &str = r#"Computername,Richtlinienbereich,Unterkategorie,Unterkategorie-GUID,Einbindungseinstellung,Ausschlusseinstellung
MYMACHINE,System,Anmeldung,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure,Keine Überwachung
MYMACHINE,System,Abmeldung,{0CCE9216-69AE-11D9-BED3-505054503030},Success,Keine Überwachung
MYMACHINE,System,Anmeldeinformationsüberprüfung,{0CCE923F-69AE-11D9-BED3-505054503030},Success and Failure,Keine Überwachung
MYMACHINE,System,Benutzerkontenverwaltung,{0CCE9235-69AE-11D9-BED3-505054503030},Success and Failure,Keine Überwachung
MYMACHINE,System,Sicherheitsgruppenverwaltung,{0CCE9237-69AE-11D9-BED3-505054503030},Success and Failure,Keine Überwachung
MYMACHINE,System,Richtlinienänderung,{0CCE922F-69AE-11D9-BED3-505054503030},Success and Failure,Keine Überwachung
MYMACHINE,System,Sensible Berechtigungsverwendung,{0CCE9228-69AE-11D9-BED3-505054503030},Failure,Keine Überwachung
MYMACHINE,System,Prozesserstellung,{0CCE922B-69AE-11D9-BED3-505054503030},Success,Keine Überwachung
MYMACHINE,System,Dateifreigabe,{0CCE9224-69AE-11D9-BED3-505054503030},Failure,Keine Überwachung
MYMACHINE,System,Sicherheitssystemerweiterung,{0CCE9211-69AE-11D9-BED3-505054503030},Success and Failure,Keine Überwachung
"#;

fn windows_ctx(injector: CmdInjector) -> ScanContext {
    let mut platform = detect();
    platform.os = Os::Windows;
    ScanContext::new(platform, true).with_injector(injector)
}

fn audit_injector(csv: Option<&'static str>) -> CmdInjector {
    Box::new(move |program, args| match (program, args) {
        ("auditpol", [first, ..]) if *first == "/get" => csv.map(str::to_owned),
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
fn registers_ten_stable_audit_policy_ids() {
    let mut registry = Vec::new();
    windows::audit::register(&mut registry);
    let ids: Vec<_> = registry.iter().map(|c| c.tc.id).collect();
    assert_eq!(
        ids,
        (1..=10)
            .map(|n| format!("WIN-AU-{n:03}"))
            .collect::<Vec<_>>()
    );
}

#[test]
fn good_english_auditpol_csv_passes_all_ten_checks() {
    let mut ctx = windows_ctx(audit_injector(Some(GOOD_AUDITPOL_CSV)));
    for i in 1..=10 {
        let id = format!("WIN-AU-{i:03}");
        let res = run_one(&mut ctx, &id);
        assert_eq!(
            res.status,
            Status::Compliant,
            "Check {id} failed: {}",
            res.evidence
        );
    }
}

#[test]
fn bad_english_auditpol_csv_fails_all_ten_checks() {
    let mut ctx = windows_ctx(audit_injector(Some(BAD_AUDITPOL_CSV)));
    for i in 1..=10 {
        let id = format!("WIN-AU-{i:03}");
        let res = run_one(&mut ctx, &id);
        assert_eq!(
            res.status,
            Status::NonCompliant,
            "Check {id} should be non-compliant: {}",
            res.evidence
        );
    }
}

#[test]
fn localized_csv_with_guids_resolves_correctly() {
    let mut ctx = windows_ctx(audit_injector(Some(LOCALIZED_GERMAN_AUDITPOL_CSV)));
    for i in 1..=10 {
        let id = format!("WIN-AU-{i:03}");
        let res = run_one(&mut ctx, &id);
        assert_eq!(
            res.status,
            Status::Compliant,
            "Check {id} with localized CSV failed: {}",
            res.evidence
        );
    }
}

#[test]
fn missing_or_unprivileged_auditpol_yields_degraded_never_error() {
    let mut ctx = windows_ctx(audit_injector(None));
    for i in 1..=10 {
        let id = format!("WIN-AU-{i:03}");
        let res = run_one(&mut ctx, &id);
        assert_eq!(
            res.status,
            Status::DegradedPartial,
            "Check {id} should degrade gracefully when auditpol is unavailable: {:?}",
            res.status
        );
        assert!(
            !res.fallback_log.is_empty(),
            "Check {id} must record fallback attempt"
        );
    }
}

#[test]
fn non_get_auditpol_commands_rejected_by_evidence_allowlist() {
    let mut ctx = windows_ctx(Box::new(|_, _| Some("stub".into())));

    // /get is allowed
    assert!(ctx.cmd("auditpol", &["/get", "/category:*", "/r"]).is_some());
    assert!(ctx.cmd("auditpol", &["/get", "/subcategory:Logon", "/r"]).is_some());

    // Mutation or non-query verbs must be rejected
    assert!(ctx.cmd("auditpol", &["/set", "/subcategory:Logon", "/success:enable"]).is_none());
    assert!(ctx.cmd("auditpol", &["/backup", "/file:audit.csv"]).is_none());
    assert!(ctx.cmd("auditpol", &["/restore", "/file:audit.csv"]).is_none());
    assert!(ctx.cmd("auditpol", &["/clear"]).is_none());
    assert!(ctx.cmd("auditpol", &["/remove", "/user:Alice"]).is_none());
}

#[test]
fn partial_success_only_fails_success_and_failure_checks() {
    // Logon has "Success" only, but requires "Success and Failure"
    // Logoff has "Success" only, which matches its "Success" requirement
    const MIXED_CSV: &str = r#"Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting
MYMACHINE,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success,No Auditing
MYMACHINE,System,Logoff,{0CCE9216-69AE-11D9-BED3-505054503030},Success,No Auditing
"#;

    let mut ctx = windows_ctx(audit_injector(Some(MIXED_CSV)));

    let logon = run_one(&mut ctx, "WIN-AU-001");
    assert_eq!(logon.status, Status::NonCompliant, "WIN-AU-001 requires Success and Failure");

    let logoff = run_one(&mut ctx, "WIN-AU-002");
    assert_eq!(logoff.status, Status::Compliant, "WIN-AU-002 only requires Success");
}
