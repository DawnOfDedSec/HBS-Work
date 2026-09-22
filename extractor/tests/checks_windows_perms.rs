//! WIN-REG (Task 36): filesystem/registry permission checks.
//!
//! Evidence from query-only PowerShell `Get-Acl ... | Select -Expand SDDL`
//! and `reg.exe query` Startup inventory; registry Run/RunOnce via
//! `reg query`. Every command is read-only; missing evidence degrades,
//! never errors.

use hbs_extractor::checks::windows::perms::parse_sddl;
use hbs_extractor::checks::{register_all, windows};
use hbs_extractor::context::ScanContext;
use hbs_extractor::engine::run_all;
use hbs_extractor::evidence::CmdInjector;
use hbs_extractor::model::{CheckResult, RegisteredCheck, Status};
use hbs_extractor::platform::{detect, Os};

const ADMIN_ONLY_SAM: &str = r"O:SYG:SYD:PAI(A;CI;KA;;;BA)(A;CI;KA;;;SY)";
const BROAD_SAM: &str = r"O:SYG:SYD:PAI(A;CI;KA;;;WD)(A;CI;KA;;;BA)(A;CI;KA;;;SY)";
const DIR_NO_WORLD: &str = r"O:SYG:SYD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)";
const DIR_WORLD_WRITABLE: &str = r"O:SYG:SYD:PAI(A;OICI;FA;;;WD)(A;OICI;FA;;;BA)";

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

fn acl_injector(
    responses: &'static [(&'static str, Option<&'static str>)],
) -> CmdInjector {
    Box::new(move |program, args| match (program, args) {
        ("powershell", _) => {
            // Last arg is the script; match on which path it queries.
            let script = args.last().copied().unwrap_or("");
            for (needle, out) in responses {
                if script.contains(needle) {
                    return out.map(str::to_owned);
                }
            }
            None
        }
        ("reg", a) if a.len() >= 3 && a[0] == "query" => {
            let joined = a.join(" ");
            for (needle, out) in responses {
                if joined.contains(needle) {
                    return out.map(str::to_owned);
                }
            }
            None
        }
        _ => None,
    })
}

#[test]
fn registers_ten_stable_perm_ids() {
    let mut registry = Vec::new();
    windows::perms::register(&mut registry);
    let ids: Vec<_> = registry.iter().map(|c| c.tc.id).collect();
    assert_eq!(
        ids,
        (1..=10)
            .map(|n| format!("WIN-REG-{n:03}"))
            .collect::<Vec<_>>()
    );
}

#[test]
fn parse_sddl_reads_aces() {
    let acl = parse_sddl(ADMIN_ONLY_SAM).expect("parses SDDL string");
    assert!(acl.trustees.iter().any(|t| t == "BA")); // Administrators
    assert!(acl.trustees.iter().any(|t| t == "SY")); // SYSTEM
    assert!(!acl.trustees.iter().any(|t| t == "WD" || t == "S-1-1-0"));
    assert!(acl.owner_is_admin_or_system);

    let broad = parse_sddl(BROAD_SAM).unwrap();
    assert!(broad.has_world_write);

    let dir = parse_sddl(DIR_NO_WORLD).unwrap();
    assert!(!dir.has_world_write);
    assert!(dir.owner_is_admin_or_system);
}

#[test]
fn sam_security_system_acls_restricted_or_flagged() {
    // All three hive ACLs restricted -> Compliant for 001/002/003.
    let responses: &'static [(&'static str, Option<&'static str>)] = &[
        ("SAM", Some(ADMIN_ONLY_SAM)),
        ("SECURITY", Some(ADMIN_ONLY_SAM)),
        ("SYSTEM", Some(ADMIN_ONLY_SAM)),
    ];
    let mut ctx = windows_ctx(acl_injector(responses));
    for id in ["WIN-REG-001", "WIN-REG-002", "WIN-REG-003"] {
        let res = run_one(&mut ctx, id);
        assert_eq!(res.status, Status::Compliant, "{id}: {}", res.evidence);
    }

    // World-writable SAM ACL -> NonCompliant.
    let bad: &'static [(&'static str, Option<&'static str>)] =
        &[("SAM", Some(BROAD_SAM))];
    let mut ctx2 = windows_ctx(acl_injector(bad));
    let res2 = run_one(&mut ctx2, "WIN-REG-001");
    assert_eq!(res2.status, Status::NonCompliant, "{}", res2.evidence);
}

#[test]
fn directory_world_writable_flagged_absent_degrades() {
    // 004 %SystemRoot% fine.
    let good: &'static [(&'static str, Option<&'static str>)] =
        &[("C:\\Windows", Some(DIR_NO_WORLD))];
    let mut ctx = windows_ctx(acl_injector(good));
    let res = run_one(&mut ctx, "WIN-REG-004");
    assert_eq!(res.status, Status::Compliant, "{}", res.evidence);

    // World-writable -> NonCompliant.
    let bad: &'static [(&'static str, Option<&'static str>)] =
        &[("C:\\Windows", Some(DIR_WORLD_WRITABLE))];
    let mut ctx2 = windows_ctx(acl_injector(bad));
    let res2 = run_one(&mut ctx2, "WIN-REG-004");
    assert_eq!(res2.status, Status::NonCompliant, "{}", res2.evidence);

    // PowerShell blocked entirely -> DegradedPartial, never Error.
    let mut ctx3 = windows_ctx(Box::new(|_, _| None));
    for i in 1..=7 {
        let id = format!("WIN-REG-{i:03}");
        let res3 = run_one(&mut ctx3, &id);
        assert_eq!(
            res3.status,
            Status::DegradedPartial,
            "{id}: {:?}",
            res3.status
        );
    }
}

#[test]
fn run_key_inventory_is_informational() {
    let responses: &'static [(&'static str, Option<&'static str>)] = &[(
        "Run",
        Some(r"\r\nHKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\r\n    Security    REG_SZ    C:\\Windows\\system32\\SecurityHealthService.exe\r\n"),
    )];
    let mut ctx = windows_ctx(acl_injector(responses));
    let res = run_one(&mut ctx, "WIN-REG-008");
    assert_ne!(res.status, Status::NonCompliant);
    assert_ne!(res.status, Status::Error);
}

#[test]
fn unquoted_service_path_detected() {
    let responses: &'static [(&'static str, Option<&'static str>)] = &[(
        "Win32_Service",
        Some(
            r#"[{"PathName":"C:\\Program Files\\Vendor App\\service.exe -k run","StartMode":"Auto","State":"Running"},{"PathName":"C:\\Windows\\System32\\svchost.exe -k netsvcs","StartMode":"Auto","State":"Running"}]"#,
        ),
    )];
    let mut ctx = windows_ctx(acl_injector(responses));
    let res = run_one(&mut ctx, "WIN-REG-010");
    assert_eq!(res.status, Status::NonCompliant, "{}", res.evidence);
}

#[test]
fn perm_checks_query_only_verbs() {
    let responses: &'static [(&'static str, Option<&'static str>)] = &[
        ("SAM", Some(ADMIN_ONLY_SAM)),
        ("SECURITY", Some(ADMIN_ONLY_SAM)),
        ("SYSTEM", Some(ADMIN_ONLY_SAM)),
        ("C:\\Windows", Some(DIR_NO_WORLD)),
        ("Program Files", Some(DIR_NO_WORLD)),
        ("System32", Some(DIR_NO_WORLD)),
        ("PerfLogs", Some(DIR_NO_WORLD)),
        ("Run", Some("")),
        ("RunOnce", Some("")),
        ("Startup", Some(DIR_NO_WORLD)),
    ];
    let mut ctx = windows_ctx(acl_injector(responses));
    for i in 1..=9 {
        run_one(&mut ctx, &format!("WIN-REG-{i:03}"));
    }
    let ok = ctx.audit.commands.iter().all(|c| {
        c.starts_with("powershell -")
            || c.starts_with("reg query ")
    });
    assert!(ok, "unexpected commands: {:?}", &ctx.audit.commands[..3.min(ctx.audit.commands.len())]);
}
