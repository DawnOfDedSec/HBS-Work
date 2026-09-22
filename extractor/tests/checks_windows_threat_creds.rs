//! WIN-TH-001..014 (Task 38): credential protection & ransomware checks.
//!
//! Registry values (LSA PPL, WDigest, DeviceGuard, ASR, CFA, script block
//! logging) with query-only PowerShell fallbacks; `cmdkey /list` and LSA
//! package inventories are informational. Everything blocked degrades,
//! never errors.

use hbs_extractor::checks::register_all;
use hbs_extractor::checks::windows::threat_creds;
use hbs_extractor::context::ScanContext;
use hbs_extractor::engine::run_all;
use hbs_extractor::evidence::CmdInjector;
use hbs_extractor::model::{CheckResult, RegisteredCheck, Status};
use hbs_extractor::platform::{detect, Os};

const LSASS_ASR: &str = "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2";
const PSEXEC_ASR: &str = "D3E037E1-3EB8-44C8-A917-57927947596D";
const DRIVER_ASR: &str = "56A863A9-875E-4185-98A7-B882C64B5CE5";

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

/// Match reg/powershell/cmdkey queries by substring needle.
fn th_injector(responses: &'static [(&'static str, Option<&'static str>)]) -> CmdInjector {
    Box::new(move |program, args| match (program, args) {
        ("reg", a) if a.first() == Some(&"query") => {
            let joined = a.join(" ");
            for (needle, out) in responses {
                if joined.contains(needle) {
                    return out.map(str::to_owned);
                }
            }
            None
        }
        ("powershell", _) => {
            let script = args.last().copied().unwrap_or("");
            for (needle, out) in responses {
                if script.contains(needle) {
                    return out.map(str::to_owned);
                }
            }
            None
        }
        ("cmdkey", _) => {
            for (needle, out) in responses {
                if needle == &"cmdkey" {
                    return out.map(str::to_owned);
                }
            }
            None
        }
        _ => None,
    })
}

#[test]
fn registers_fourteen_stable_threat_creds_ids() {
    let mut registry = Vec::new();
    threat_creds::register(&mut registry);
    let ids: Vec<_> = registry.iter().map(|c| c.tc.id).collect();
    assert_eq!(
        ids,
        (1..=14)
            .map(|n| format!("WIN-TH-{n:03}"))
            .collect::<Vec<_>>()
    );
}

#[test]
fn lsa_ppl_and_wdigest_evaluated() {
    // WIN-TH-001: RunAsPPL=1 -> Compliant; 0 -> NonCompliant.
    let ppl_on: &'static [(&'static str, Option<&'static str>)] = &[(
        "RunAsPPL",
        Some("    RunAsPPL    REG_DWORD    0x1\n    RunAsPPLBoot    REG_DWORD    0x2\n"),
    )];
    let mut ctx = windows_ctx(th_injector(ppl_on));
    assert_eq!(run_one(&mut ctx, "WIN-TH-001").status, Status::Compliant);

    let ppl_off: &'static [(&'static str, Option<&'static str>)] =
        &[("RunAsPPL", Some("    RunAsPPL    REG_DWORD    0x0\n"))];
    let mut ctx2 = windows_ctx(th_injector(ppl_off));
    assert_eq!(
        run_one(&mut ctx2, "WIN-TH-001").status,
        Status::NonCompliant
    );

    // WIN-TH-006: UseLogonCredential absent -> default-safe Compliant;
    // =1 -> NonCompliant.
    let wd_absent: &'static [(&'static str, Option<&'static str>)] = &[(
        "WDigest",
        Some("\r\nERROR: The system was unable to find the specified registry key or value.\r\n"),
    )];
    let mut ctx3 = windows_ctx(th_injector(wd_absent));
    assert_eq!(run_one(&mut ctx3, "WIN-TH-006").status, Status::Compliant);

    let wd_on: &'static [(&'static str, Option<&'static str>)] = &[(
        "UseLogonCredential",
        Some("    UseLogonCredential    REG_DWORD    0x1\n"),
    )];
    let mut ctx4 = windows_ctx(th_injector(wd_on));
    assert_eq!(
        run_one(&mut ctx4, "WIN-TH-006").status,
        Status::NonCompliant
    );
}

#[test]
fn credential_guard_configured_and_active() {
    // WIN-TH-002: LsaCfgFlags=1 + CIM SecurityServicesRunning=[1] -> ok.
    let good: &'static [(&'static str, Option<&'static str>)] = &[
        ("LsaCfgFlags", Some("    LsaCfgFlags    REG_DWORD    0x1\n")),
        (
            "SecurityServicesRunning",
            Some(
                r#"{"SecurityServicesRunning":  [1], "SecurityServicesConfigured":  [1], "CodeIntegrityPolicyEnforcementStatus":  2}"#,
            ),
        ),
    ];
    let mut ctx = windows_ctx(th_injector(good));
    assert_eq!(run_one(&mut ctx, "WIN-TH-002").status, Status::Compliant);

    // Configured but not running -> NonCompliant.
    let not_running: &'static [(&'static str, Option<&'static str>)] = &[
        ("LsaCfgFlags", Some("    LsaCfgFlags    REG_DWORD    0x1\n")),
        (
            "SecurityServicesRunning",
            Some(
                r#"{"SecurityServicesRunning":  [], "SecurityServicesConfigured":  [1], "CodeIntegrityPolicyEnforcementStatus":  0}"#,
            ),
        ),
    ];
    let mut ctx2 = windows_ctx(th_injector(not_running));
    assert_eq!(
        run_one(&mut ctx2, "WIN-TH-002").status,
        Status::NonCompliant
    );

    // Configured, CIM blocked -> DegradedPartial (runtime unverifiable).
    let reg_only: &'static [(&'static str, Option<&'static str>)] =
        &[("LsaCfgFlags", Some("    LsaCfgFlags    REG_DWORD    0x1\n"))];
    let mut ctx3 = windows_ctx(th_injector(reg_only));
    assert_eq!(
        run_one(&mut ctx3, "WIN-TH-002").status,
        Status::DegradedPartial
    );
}

#[test]
fn hvci_and_driver_blocklist_evaluated() {
    // WIN-TH-003: HECI Enabled=1 -> ok; 0 -> nok.
    let hvci_on: &'static [(&'static str, Option<&'static str>)] = &[(
        "HypervisorEnforcedCodeIntegrity",
        Some("    Enabled    REG_DWORD    0x1\n"),
    )];
    let mut ctx = windows_ctx(th_injector(hvci_on));
    assert_eq!(run_one(&mut ctx, "WIN-TH-003").status, Status::Compliant);

    let hvci_off: &'static [(&'static str, Option<&'static str>)] = &[(
        "HypervisorEnforcedCodeIntegrity",
        Some("    Enabled    REG_DWORD    0x0\n"),
    )];
    let mut ctx2 = windows_ctx(th_injector(hvci_off));
    assert_eq!(
        run_one(&mut ctx2, "WIN-TH-003").status,
        Status::NonCompliant
    );

    // WIN-TH-004: VulnerableDriverBlocklistEnable=1 -> ok; 0 -> nok.
    let dbl_on: &'static [(&'static str, Option<&'static str>)] = &[(
        "VulnerableDriverBlocklistEnable",
        Some("    VulnerableDriverBlocklistEnable    REG_DWORD    0x1\n"),
    )];
    let mut ctx3 = windows_ctx(th_injector(dbl_on));
    assert_eq!(run_one(&mut ctx3, "WIN-TH-004").status, Status::Compliant);

    let dbl_off: &'static [(&'static str, Option<&'static str>)] = &[(
        "VulnerableDriverBlocklistEnable",
        Some("    VulnerableDriverBlocklistEnable    REG_DWORD    0x0\n"),
    )];
    let mut ctx4 = windows_ctx(th_injector(dbl_off));
    assert_eq!(
        run_one(&mut ctx4, "WIN-TH-004").status,
        Status::NonCompliant
    );
}

#[test]
fn asr_rules_evaluated_with_mppreference_fallback() {
    let ids = [LSASS_ASR, PSEXEC_ASR, DRIVER_ASR];
    // All three blocked (1) in registry -> Compliant.
    let reg_all: &'static [(&'static str, Option<&'static str>)] = &[
        (
            LSASS_ASR,
            Some("    9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2    REG_DWORD    0x1\n"),
        ),
        (
            PSEXEC_ASR,
            Some("    D3E037E1-3EB8-44C8-A917-57927947596D    REG_DWORD    0x1\n"),
        ),
        (
            DRIVER_ASR,
            Some("    56A863A9-875E-4185-98A7-B882C64B5CE5    REG_DWORD    0x1\n"),
        ),
    ];
    let mut ctx = windows_ctx(th_injector(reg_all));
    for (i, id) in ["WIN-TH-010", "WIN-TH-011", "WIN-TH-012"]
        .into_iter()
        .enumerate()
    {
        let res = run_one(&mut ctx, id);
        assert_eq!(res.status, Status::Compliant, "{id}: {}", res.evidence);
    }
    drop(ids);

    // Registry value missing; Get-MpPreference lists the rule with
    // action 1 (block) -> still Compliant. JSON body (needle is on the
    // script, body comes back parsed as JSON).
    let mp_only: &'static [(&'static str, Option<&'static str>)] = &[(
        "Get-MpPreference",
        Some(
            r#"{"EnableControlledFolderAccess": 0, "AttackSurfaceReductionRules_Ids": ["9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2", "D3E037E1-3EB8-44C8-A917-57927947596D"], "AttackSurfaceReductionRules_Actions": [1, 2]}"#,
        ),
    )];
    let mut ctx2 = windows_ctx(th_injector(mp_only));
    assert_eq!(run_one(&mut ctx2, "WIN-TH-010").status, Status::Compliant);
    // Action 2 = audit only -> NonCompliant.
    assert_eq!(
        run_one(&mut ctx2, "WIN-TH-011").status,
        Status::NonCompliant
    );

    // Rule configured nowhere (explicit reg miss + no MpPreference) -> nok.
    let none: &'static [(&'static str, Option<&'static str>)] = &[(
        "Exploit Guard",
        Some("\r\nERROR: The system was unable to find the specified registry key or value.\r\n"),
    )];
    let mut ctx3 = windows_ctx(th_injector(none));
    assert_eq!(
        run_one(&mut ctx3, "WIN-TH-010").status,
        Status::NonCompliant
    );
}

#[test]
fn cfa_and_script_block_logging_evaluated() {
    // WIN-TH-013: EnableControlledFolderAccess=1 -> ok; 0 -> nok.
    let cfa_on: &'static [(&'static str, Option<&'static str>)] = &[(
        "EnableControlledFolderAccess",
        Some("    EnableControlledFolderAccess    REG_DWORD    0x1\n"),
    )];
    let mut ctx = windows_ctx(th_injector(cfa_on));
    assert_eq!(run_one(&mut ctx, "WIN-TH-013").status, Status::Compliant);

    let cfa_off: &'static [(&'static str, Option<&'static str>)] = &[(
        "EnableControlledFolderAccess",
        Some("    EnableControlledFolderAccess    REG_DWORD    0x0\n"),
    )];
    let mut ctx2 = windows_ctx(th_injector(cfa_off));
    assert_eq!(
        run_one(&mut ctx2, "WIN-TH-013").status,
        Status::NonCompliant
    );

    // WIN-TH-014: EnableScriptBlockLogging=1 -> ok; absent -> nok.
    let sbl_on: &'static [(&'static str, Option<&'static str>)] = &[(
        "EnableScriptBlockLogging",
        Some("    EnableScriptBlockLogging    REG_DWORD    0x1\n"),
    )];
    let mut ctx3 = windows_ctx(th_injector(sbl_on));
    assert_eq!(run_one(&mut ctx3, "WIN-TH-014").status, Status::Compliant);

    let sbl_absent: &'static [(&'static str, Option<&'static str>)] = &[(
        "ScriptBlockLogging",
        Some("\r\nERROR: The system was unable to find the specified registry key or value.\r\n"),
    )];
    let mut ctx4 = windows_ctx(th_injector(sbl_absent));
    assert_eq!(
        run_one(&mut ctx4, "WIN-TH-014").status,
        Status::NonCompliant
    );
}

#[test]
fn autoadminlogon_and_defaultpassword() {
    // WIN-TH-007: AutoAdminLogon=1 -> nok; =0 without DefaultPassword -> ok;
    // =0 but DefaultPassword present -> nok (stale secret).
    let auto_on: &'static [(&'static str, Option<&'static str>)] = &[(
        "AutoAdminLogon",
        Some("    AutoAdminLogon    REG_DWORD    0x1\n"),
    )];
    let mut ctx = windows_ctx(th_injector(auto_on));
    assert_eq!(run_one(&mut ctx, "WIN-TH-007").status, Status::NonCompliant);

    let clean: &'static [(&'static str, Option<&'static str>)] = &[
        (
            "AutoAdminLogon",
            Some("    AutoAdminLogon    REG_DWORD    0x0\n"),
        ),
        (
            "DefaultPassword",
            Some(
                "\r\nERROR: The system was unable to find the specified registry key or value.\r\n",
            ),
        ),
    ];
    let mut ctx2 = windows_ctx(th_injector(clean));
    assert_eq!(run_one(&mut ctx2, "WIN-TH-007").status, Status::Compliant);

    let stale_pw: &'static [(&'static str, Option<&'static str>)] = &[
        (
            "AutoAdminLogon",
            Some("    AutoAdminLogon    REG_DWORD    0x0\n"),
        ),
        (
            "DefaultPassword",
            Some("    DefaultPassword    REG_SZ    hunter2\n"),
        ),
    ];
    let mut ctx3 = windows_ctx(th_injector(stale_pw));
    let res = run_one(&mut ctx3, "WIN-TH-007");
    assert_eq!(res.status, Status::NonCompliant);
    // The secret must never land in evidence.
    assert!(!res.evidence.contains("hunter2"), "{}", res.evidence);
}

#[test]
fn inventories_ok_when_present_degrade_when_blocked() {
    // WIN-TH-008 cmdkey inventory present -> ok; blocked -> degraded.
    let creds: &'static [(&'static str, Option<&'static str>)] = &[(
        "cmdkey",
        Some("Currently stored credentials:\n\n    Target: Domain:target=corp\n    Type: Domain Password\n"),
    )];
    let mut ctx = windows_ctx(th_injector(creds));
    assert_eq!(run_one(&mut ctx, "WIN-TH-008").status, Status::Compliant);

    // WIN-TH-009 LSA packages listing present -> ok.
    let pkgs: &'static [(&'static str, Option<&'static str>)] = &[(
        "Security Packages",
        Some("    Security Packages    REG_MULTI_SZ    msv1_0 schannel wdigest\n"),
    )];
    let mut ctx2 = windows_ctx(th_injector(pkgs));
    assert_eq!(run_one(&mut ctx2, "WIN-TH-009").status, Status::Compliant);

    // Everything blocked: informational checks degrade, never error.
    let mut ctx3 = windows_ctx(Box::new(|_, _| None));
    for id in ["WIN-TH-008", "WIN-TH-009"] {
        assert_eq!(
            run_one(&mut ctx3, id).status,
            Status::DegradedPartial,
            "{id}"
        );
    }
}

#[test]
fn all_blocked_degrades_never_errors() {
    let mut ctx = windows_ctx(Box::new(|_, _| None));
    for i in 1..=14 {
        let id = format!("WIN-TH-{i:03}");
        let res = run_one(&mut ctx, &id);
        assert_eq!(
            res.status,
            Status::DegradedPartial,
            "{id}: {:?} {}",
            res.status,
            res.evidence
        );
    }
}

#[test]
fn threat_creds_query_only_verbs() {
    let good: &'static [(&'static str, Option<&'static str>)] = &[
        (
            "RunAsPPL",
            Some("    RunAsPPL    REG_DWORD    0x1\n    RunAsPPLBoot    REG_DWORD    0x2\n"),
        ),
        ("LsaCfgFlags", Some("    LsaCfgFlags    REG_DWORD    0x1\n")),
        (
            "SecurityServicesRunning",
            Some(
                r#"{"SecurityServicesRunning":  [1], "SecurityServicesConfigured":  [1], "CodeIntegrityPolicyEnforcementStatus":  2}"#,
            ),
        ),
        (
            "HypervisorEnforcedCodeIntegrity",
            Some("    Enabled    REG_DWORD    0x1\n"),
        ),
        (
            "VulnerableDriverBlocklistEnable",
            Some("    VulnerableDriverBlocklistEnable    REG_DWORD    0x1\n"),
        ),
        ("CiPolicies", Some("dummy.cip\n")),
        (
            "WDigest",
            Some("    UseLogonCredential    REG_DWORD    0x0\n"),
        ),
        (
            "AutoAdminLogon",
            Some("    AutoAdminLogon    REG_DWORD    0x0\n"),
        ),
        (
            "DefaultPassword",
            Some(
                "\r\nERROR: The system was unable to find the specified registry key or value.\r\n",
            ),
        ),
        (
            "cmdkey",
            Some("Currently stored credentials:\n\n    Target: Domain:target=corp\n"),
        ),
        (
            "Security Packages",
            Some("    Security Packages    REG_MULTI_SZ    msv1_0 schannel wdigest\n"),
        ),
        (
            LSASS_ASR,
            Some("    9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2    REG_DWORD    0x1\n"),
        ),
        (
            PSEXEC_ASR,
            Some("    D3E037E1-3EB8-44C8-A917-57927947596D    REG_DWORD    0x1\n"),
        ),
        (
            DRIVER_ASR,
            Some("    56A863A9-875E-4185-98A7-B882C64B5CB5    REG_DWORD    0x1\n"),
        ),
        (
            "EnableControlledFolderAccess",
            Some("    EnableControlledFolderAccess    REG_DWORD    0x1\n"),
        ),
        (
            "EnableScriptBlockLogging",
            Some("    EnableScriptBlockLogging    REG_DWORD    0x1\n"),
        ),
    ];
    let mut ctx = windows_ctx(th_injector(good));
    for i in 1..=14 {
        run_one(&mut ctx, &format!("WIN-TH-{i:03}"));
    }
    let bad: Vec<_> = ctx
        .audit
        .commands
        .iter()
        .filter(|c| {
            !(c.starts_with("reg query ")
                || c.starts_with("powershell ")
                || c.starts_with("cmdkey "))
        })
        .collect();
    assert!(bad.is_empty(), "unexpected commands: {bad:?}");
}
