use hbs_extractor::checks::windows::account::{
    convert_lockout_duration_seconds, convert_max_password_age_seconds,
    convert_min_password_age_seconds, convert_observation_window_seconds, TIMEQ_FOREVER,
};
use hbs_extractor::checks::{register_all, windows};
use hbs_extractor::context::ScanContext;
use hbs_extractor::engine::run_all;
use hbs_extractor::evidence::CmdInjector;
use hbs_extractor::model::{CheckResult, RegisteredCheck, Status};
use hbs_extractor::platform::{detect, Os};

const GOOD_ACCOUNTS: &str = r#"
Force user logoff how long after time expires?:       Never
Minimum password age (days):                          1
Maximum password age (days):                          365
Minimum password length:                              14
Length of password history maintained:                24
Lockout threshold:                                    5
Lockout duration (minutes):                           15
Lockout observation window (minutes):                 15
Computer role:                                        WORKSTATION
The command completed successfully.
"#;

const BAD_ACCOUNTS: &str = r#"
Force user logoff how long after time expires?:       Never
Minimum password age (days):                          0
Maximum password age (days):                          Never
Minimum password length:                              13
Length of password history maintained:                None
Lockout threshold:                                    Never
Lockout duration (minutes):                           14
Lockout observation window (minutes):                 14
Computer role:                                        WORKSTATION
The command completed successfully.
"#;

const FOREVER_LOCKOUT_ACCOUNTS: &str = r#"
Force user logoff how long after time expires?:       Never
Minimum password age (days):                          1
Maximum password age (days):                          Never
Minimum password length:                              14
Length of password history maintained:                24
Lockout threshold:                                    5
Lockout duration (minutes):                           Forever
Lockout observation window (minutes):                 15
Computer role:                                        WORKSTATION
The command completed successfully.
"#;

fn windows_ctx(injector: CmdInjector) -> ScanContext {
    let mut platform = detect();
    platform.os = Os::Windows;
    ScanContext::new(platform, true).with_injector(injector)
}

fn windows_non_elevated_ctx(injector: CmdInjector) -> ScanContext {
    let mut platform = detect();
    platform.os = Os::Windows;
    ScanContext::new(platform, false).with_injector(injector)
}

fn run_one(ctx: &mut ScanContext, id: &str) -> CheckResult {
    let mut registry: Vec<RegisteredCheck> = Vec::new();
    register_all(&mut registry);
    let subset: Vec<_> = registry.into_iter().filter(|c| c.tc.id == id).collect();
    run_all(&subset, ctx).remove(0)
}

fn account_injector(accounts: Option<&'static str>) -> CmdInjector {
    Box::new(move |program, args| match (program, args) {
        ("net", ["accounts"]) => accounts.map(str::to_owned),
        _ => None,
    })
}

fn account_results(accounts: &'static str) -> Vec<CheckResult> {
    let mut ctx = windows_ctx(account_injector(Some(accounts)));
    let mut registry = Vec::new();
    windows::account::register(&mut registry);
    run_all(&registry[..7], &mut ctx)
}

#[test]
fn registers_twelve_stable_account_policy_ids_without_kerberos_probe() {
    let mut registry = Vec::new();
    windows::account::register(&mut registry);
    let ids: Vec<_> = registry.iter().map(|c| c.tc.id).collect();
    assert_eq!(
        ids,
        (1..=14)
            .map(|n| format!("WIN-ACC-{n:03}"))
            .collect::<Vec<_>>()
    );
    assert!(registry.iter().all(|c| !c.tc.title.contains("Kerberos")));
}

#[test]
fn good_english_net_accounts_passes_all_seven_account_values() {
    for result in account_results(GOOD_ACCOUNTS) {
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
fn bad_english_net_accounts_fails_all_seven_account_values() {
    for result in account_results(BAD_ACCOUNTS) {
        assert_eq!(
            result.status,
            Status::NonCompliant,
            "{}: {}",
            result.id,
            result.evidence
        );
    }
}

#[test]
fn timeq_forever_duration_passes_while_max_age_fails() {
    let mut ctx = windows_ctx(account_injector(Some(FOREVER_LOCKOUT_ACCOUNTS)));

    // WIN-ACC-006: Account lockout duration with Forever / TIMEQ_FOREVER passes (admin unlock required)
    let duration = run_one(&mut ctx, "WIN-ACC-006");
    assert_eq!(
        duration.status,
        Status::Compliant,
        "lockout duration forever should pass: {}",
        duration.evidence
    );
    assert!(
        duration.evidence.contains("TIMEQ_FOREVER"),
        "{}",
        duration.evidence
    );

    // WIN-ACC-002: Maximum password age with Never / TIMEQ_FOREVER fails (passwords must expire)
    let max_age = run_one(&mut ctx, "WIN-ACC-002");
    assert_eq!(
        max_age.status,
        Status::NonCompliant,
        "max password age never should fail: {}",
        max_age.evidence
    );
}

#[test]
fn none_and_never_map_to_zero_not_missing() {
    let mut history_ctx = windows_ctx(account_injector(Some(BAD_ACCOUNTS)));
    let history = run_one(&mut history_ctx, "WIN-ACC-004");
    assert_eq!(history.status, Status::NonCompliant);
    assert!(history.evidence.contains("= 0"), "{}", history.evidence);

    let mut threshold_ctx = windows_ctx(account_injector(Some(BAD_ACCOUNTS)));
    let threshold = run_one(&mut threshold_ctx, "WIN-ACC-005");
    assert_eq!(threshold.status, Status::NonCompliant);
    assert!(threshold.evidence.contains("0"), "{}", threshold.evidence);

    let mut max_age_ctx = windows_ctx(account_injector(Some(BAD_ACCOUNTS)));
    let max_age = run_one(&mut max_age_ctx, "WIN-ACC-002");
    assert!(
        max_age.evidence.contains("passwords are required"),
        "{}",
        max_age.evidence
    );
}

#[test]
fn missing_or_localized_net_accounts_degrades_with_accurate_level_fallbacks() {
    for accounts in [None, Some("Longueur minimale du mot de passe : 14")] {
        // Level 0 check: WIN-ACC-001
        let mut ctx = windows_ctx(account_injector(accounts));
        let result_lvl0 = run_one(&mut ctx, "WIN-ACC-001");
        assert_eq!(
            result_lvl0.status,
            Status::DegradedPartial,
            "{}",
            result_lvl0.evidence
        );
        assert_eq!(
            result_lvl0
                .fallback_log
                .iter()
                .map(|attempt| attempt.source.as_str())
                .collect::<Vec<_>>(),
            [
                "NetUserModalsGet level 0",
                "net accounts",
                "local LSA account-policy values"
            ]
        );

        // Level 3 check: WIN-ACC-005
        let mut ctx3 = windows_ctx(account_injector(accounts));
        let result_lvl3 = run_one(&mut ctx3, "WIN-ACC-005");
        assert_eq!(
            result_lvl3.status,
            Status::DegradedPartial,
            "{}",
            result_lvl3.evidence
        );
        assert_eq!(
            result_lvl3
                .fallback_log
                .iter()
                .map(|attempt| attempt.source.as_str())
                .collect::<Vec<_>>(),
            [
                "NetUserModalsGet level 3",
                "net accounts",
                "local LSA account-policy values"
            ]
        );
    }
}

#[test]
fn native_conversion_seconds_to_units_handles_forever_and_standard_values() {
    // Max password age: TIMEQ_FOREVER means passwords never expire -> 0 (non-compliant)
    assert_eq!(convert_max_password_age_seconds(TIMEQ_FOREVER), 0);
    assert_eq!(convert_max_password_age_seconds(90 * 86_400), 90);
    assert_eq!(convert_max_password_age_seconds(365 * 86_400), 365);
    assert_eq!(convert_max_password_age_seconds(400 * 86_400), 400);

    // Min password age: standard conversion
    assert_eq!(convert_min_password_age_seconds(86_400), 1);
    assert_eq!(convert_min_password_age_seconds(0), 0);
    assert_eq!(convert_min_password_age_seconds(7 * 86_400), 7);

    // Lockout duration: TIMEQ_FOREVER means admin unlock required -> TIMEQ_FOREVER (compliant)
    assert_eq!(convert_lockout_duration_seconds(TIMEQ_FOREVER), TIMEQ_FOREVER);
    assert_eq!(convert_lockout_duration_seconds(15 * 60), 15);
    assert_eq!(convert_lockout_duration_seconds(30 * 60), 30);
    assert_eq!(convert_lockout_duration_seconds(10 * 60), 10);

    // Observation window: TIMEQ_FOREVER preserved
    assert_eq!(convert_observation_window_seconds(TIMEQ_FOREVER), TIMEQ_FOREVER);
    assert_eq!(convert_observation_window_seconds(15 * 60), 15);
    assert_eq!(convert_observation_window_seconds(5 * 60), 5);
}

#[test]
fn non_elevated_execution_evaluates_without_error() {
    let mut ctx = windows_non_elevated_ctx(account_injector(Some(GOOD_ACCOUNTS)));
    let mut registry = Vec::new();
    windows::account::register(&mut registry);
    let results = run_all(&registry, &mut ctx);
    assert_eq!(results.len(), 14);
    for r in &results {
        assert_ne!(
            r.status,
            Status::Error,
            "check {} produced an error in non-elevated scan: {}",
            r.id,
            r.evidence
        );
        assert!(
            !r.run_context.elevated,
            "run_context elevated should be false for {}",
            r.id
        );
    }
}

#[test]
fn offline_environment_degrades_gracefully_without_panics() {
    // In an offline/bare environment where external query tools return None
    let mut ctx = windows_ctx(Box::new(|_, _| None));
    let mut registry = Vec::new();
    windows::account::register(&mut registry);
    let results = run_all(&registry, &mut ctx);
    assert_eq!(results.len(), 14);
    for r in &results {
        assert_eq!(
            r.status,
            Status::DegradedPartial,
            "check {} should degrade gracefully in offline/bare environment: {}",
            r.id,
            r.evidence
        );
        assert!(
            !r.fallback_log.is_empty(),
            "fallback_log should record attempted sources for {}",
            r.id
        );
    }
}

#[test]
fn registry_dword_parser_treats_decimal_as_decimal_and_prefixed_as_hex() {
    for (raw, want) in [("10", 10), ("0x10", 16)] {
        let mut ctx = windows_ctx(Box::new(move |program, _| {
            (program == "reg").then(|| format!("    SampleValue    REG_DWORD    {raw}"))
        }));
        assert_eq!(
            windows::reg_query_dword(&mut ctx, "HKLM\\Sample", "SampleValue"),
            Some(want)
        );
    }
}

#[test]
fn registry_fallback_preserves_path_and_order() {
    let mut ctx = windows_ctx(Box::new(|program, args| {
        if program == "powershell" {
            let script = args.last().copied().unwrap_or_default();
            assert!(
                script.contains(r"Registry::HKLM\SYSTEM\CurrentControlSet\Control\Lsa"),
                "{script}"
            );
            Some("1".into())
        } else {
            None
        }
    }));
    let result = run_one(&mut ctx, "WIN-ACC-008");
    assert_eq!(result.status, Status::Compliant, "{}", result.evidence);
    assert_eq!(
        result
            .fallback_log
            .iter()
            .map(|attempt| attempt.source.as_str())
            .collect::<Vec<_>>(),
        ["reg query", "PowerShell Get-ItemProperty"]
    );
}

#[test]
fn registry_backed_checks_handle_good_bad_and_missing_values() {
    for (id, name) in [
        ("WIN-ACC-008", "LimitBlankPasswordUse"),
        ("WIN-ACC-011", "RestrictAnonymous"),
        ("WIN-ACC-012", "RestrictAnonymousSAM"),
    ] {
        for (raw, want) in [
            (Some("1"), Status::Compliant),
            (Some("0"), Status::NonCompliant),
            (None, Status::DegradedPartial),
        ] {
            let mut ctx = windows_ctx(Box::new(move |program, args| {
                if program == "reg" && args.iter().any(|arg| arg.eq_ignore_ascii_case(name)) {
                    raw.map(|value| format!("    {name}    REG_DWORD    {value}"))
                } else {
                    None
                }
            }));
            let result = run_one(&mut ctx, id);
            assert_eq!(result.status, want, "{id}: {}", result.evidence);
            if raw.is_none() {
                assert_eq!(
                    result
                        .fallback_log
                        .iter()
                        .map(|attempt| attempt.source.as_str())
                        .collect::<Vec<_>>(),
                    ["reg query", "PowerShell Get-ItemProperty", "native registry"]
                );
            }
        }
    }
}

#[test]
fn win_acc_012_restrict_anonymous_sam_explicit() {
    let mut registry = Vec::new();
    windows::account::register(&mut registry);
    let check = registry
        .iter()
        .find(|c| c.tc.id == "WIN-ACC-012")
        .expect("WIN-ACC-012 must be registered");

    assert_eq!(
        check.tc.title,
        "Restrict anonymous SAM and shares enumeration"
    );
    assert_eq!(check.tc.references, &["CIS 2.3.10.1"]);

    // Test compliant (value = 1)
    let mut ctx_pass = windows_ctx(Box::new(|program, args| {
        (program == "reg" && args.contains(&"RestrictAnonymousSAM"))
            .then(|| "    RestrictAnonymousSAM    REG_DWORD    0x1".to_string())
    }));
    let res_pass = run_one(&mut ctx_pass, "WIN-ACC-012");
    assert_eq!(res_pass.status, Status::Compliant);
    assert!(res_pass.evidence.contains("= 1"));

    // Test non-compliant (value = 0)
    let mut ctx_fail = windows_ctx(Box::new(|program, args| {
        (program == "reg" && args.contains(&"RestrictAnonymousSAM"))
            .then(|| "    RestrictAnonymousSAM    REG_DWORD    0x0".to_string())
    }));
    let res_fail = run_one(&mut ctx_fail, "WIN-ACC-012");
    assert_eq!(res_fail.status, Status::NonCompliant);
    assert!(res_fail.evidence.contains("= 0 (expected 1)"));

    // Test missing / degraded
    let mut ctx_deg = windows_ctx(Box::new(|_, _| None));
    let res_deg = run_one(&mut ctx_deg, "WIN-ACC-012");
    assert_eq!(res_deg.status, Status::DegradedPartial);
    assert_eq!(
        res_deg
            .fallback_log
            .iter()
            .map(|a| a.source.as_str())
            .collect::<Vec<_>>(),
        ["reg query", "PowerShell Get-ItemProperty", "native registry"]
    );
}

#[test]
fn password_complexity_and_reversible_encryption_rsop() {
    for (id, setting_name, pass_val, fail_val) in [
        ("WIN-ACC-009", "PasswordComplexity", "1", "0"),
        ("WIN-ACC-010", "ClearTextPassword", "0", "1"),
    ] {
        // Test Compliant
        let mut ctx_pass = windows_ctx(Box::new(move |program, args| {
            if program == "powershell" && args.join(" ").contains(setting_name) {
                Some(pass_val.to_string())
            } else {
                None
            }
        }));
        let res_pass = run_one(&mut ctx_pass, id);
        assert_eq!(res_pass.status, Status::Compliant, "{id}: {}", res_pass.evidence);

        // Test NonCompliant
        let mut ctx_fail = windows_ctx(Box::new(move |program, args| {
            if program == "powershell" && args.join(" ").contains(setting_name) {
                Some(fail_val.to_string())
            } else {
                None
            }
        }));
        let res_fail = run_one(&mut ctx_fail, id);
        assert_eq!(res_fail.status, Status::NonCompliant, "{id}: {}", res_fail.evidence);

        // Test Degraded
        let mut ctx_deg = windows_ctx(Box::new(|_, _| None));
        let res_deg = run_one(&mut ctx_deg, id);
        assert_eq!(res_deg.status, Status::DegradedPartial, "{id}: {}", res_deg.evidence);
        assert_eq!(
            res_deg
                .fallback_log
                .iter()
                .map(|a| a.source.as_str())
                .collect::<Vec<_>>(),
            [
                format!("RSOP {setting_name}"),
                "reg query".to_string(),
                "PowerShell Get-ItemProperty".to_string(),
                "native registry".to_string()
            ]
        );
    }
}
