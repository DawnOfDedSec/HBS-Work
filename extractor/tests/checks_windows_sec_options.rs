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

fn sec_injector(pass: bool) -> CmdInjector {
    Box::new(move |program, args| match (program, args) {
        ("reg", ["query", path, "/v", name]) => {
            let p = *path;
            let n = *name;
            if pass {
                mock_reg_pass(p, n)
            } else {
                mock_reg_fail(p, n)
            }
        }
        _ => None,
    })
}

fn mock_reg_pass(path: &str, name: &str) -> Option<String> {
    match (path, name) {
        (r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel") => {
            Some(format!("\r\n    LmCompatibilityLevel    REG_DWORD    0x5\r\n"))
        }
        (r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "NoLMHash") => {
            Some(format!("\r\n    NoLMHash    REG_DWORD    0x1\r\n"))
        }
        (r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature") => {
            Some(format!("\r\n    RequireSecuritySignature    REG_DWORD    0x1\r\n"))
        }
        (r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "RequireSecuritySignature") => {
            Some(format!("\r\n    RequireSecuritySignature    REG_DWORD    0x1\r\n"))
        }
        (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA") => {
            Some(format!("\r\n    EnableLUA    REG_DWORD    0x1\r\n"))
        }
        (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin") => {
            Some(format!("\r\n    ConsentPromptBehaviorAdmin    REG_DWORD    0x2\r\n"))
        }
        (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableInstallerDetection") => {
            Some(format!("\r\n    EnableInstallerDetection    REG_DWORD    0x1\r\n"))
        }
        (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableSecureUIPaths") => {
            Some(format!("\r\n    EnableSecureUIPaths    REG_DWORD    0x1\r\n"))
        }
        (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableVirtualization") => {
            Some(format!("\r\n    EnableVirtualization    REG_DWORD    0x1\r\n"))
        }
        (r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management", "ClearPageFileAtShutdown") => {
            Some(format!("\r\n    ClearPageFileAtShutdown    REG_DWORD    0x1\r\n"))
        }
        (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "NoConnectedUser") => {
            Some(format!("\r\n    NoConnectedUser    REG_DWORD    0x3\r\n"))
        }
        (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "InactivityTimeoutSecs") => {
            Some(format!("\r\n    InactivityTimeoutSecs    REG_DWORD    0x384\r\n")) // 900
        }
        (r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop", "ScreenSaverIsSecure") => {
            Some(format!("\r\n    ScreenSaverIsSecure    REG_SZ    1\r\n"))
        }
        (r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop", "ScreenSaveTimeOut") => {
            Some(format!("\r\n    ScreenSaveTimeOut    REG_SZ    900\r\n"))
        }
        (r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "ForceUnlockLogon") => {
            Some(format!("\r\n    ForceUnlockLogon    REG_DWORD    0x1\r\n"))
        }
        (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "dontdisplaylastusername") => {
            Some(format!("\r\n    dontdisplaylastusername    REG_DWORD    0x1\r\n"))
        }
        (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "LegalNoticeCaption") => {
            Some(format!("\r\n    LegalNoticeCaption    REG_SZ    Authorized Use Only\r\n"))
        }
        (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "LegalNoticeText") => {
            Some(format!("\r\n    LegalNoticeText    REG_SZ    All activities are monitored and logged.\r\n"))
        }
        (r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1") => {
            Some(format!("\r\n    SMB1    REG_DWORD    0x0\r\n"))
        }
        (r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoRestartShell") => {
            Some(format!("\r\n    AutoRestartShell    REG_DWORD    0x0\r\n"))
        }
        (r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "CachedLogonsCount") => {
            Some(format!("\r\n    CachedLogonsCount    REG_SZ    4\r\n"))
        }
        (r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RestrictNullSessAccess") => {
            Some(format!("\r\n    RestrictNullSessAccess    REG_DWORD    0x1\r\n"))
        }
        _ => None,
    }
}

fn mock_reg_fail(path: &str, name: &str) -> Option<String> {
    match (path, name) {
        (r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel") => {
            Some(format!("\r\n    LmCompatibilityLevel    REG_DWORD    0x2\r\n"))
        }
        (r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "NoLMHash") => {
            Some(format!("\r\n    NoLMHash    REG_DWORD    0x0\r\n"))
        }
        (r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature") => {
            Some(format!("\r\n    RequireSecuritySignature    REG_DWORD    0x0\r\n"))
        }
        (r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "RequireSecuritySignature") => {
            Some(format!("\r\n    RequireSecuritySignature    REG_DWORD    0x0\r\n"))
        }
        (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA") => {
            Some(format!("\r\n    EnableLUA    REG_DWORD    0x0\r\n"))
        }
        (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin") => {
            Some(format!("\r\n    ConsentPromptBehaviorAdmin    REG_DWORD    0x0\r\n"))
        }
        (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableInstallerDetection") => {
            Some(format!("\r\n    EnableInstallerDetection    REG_DWORD    0x0\r\n"))
        }
        (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableSecureUIPaths") => {
            Some(format!("\r\n    EnableSecureUIPaths    REG_DWORD    0x0\r\n"))
        }
        (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableVirtualization") => {
            Some(format!("\r\n    EnableVirtualization    REG_DWORD    0x0\r\n"))
        }
        (r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management", "ClearPageFileAtShutdown") => {
            Some(format!("\r\n    ClearPageFileAtShutdown    REG_DWORD    0x0\r\n"))
        }
        (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "NoConnectedUser") => {
            Some(format!("\r\n    NoConnectedUser    REG_DWORD    0x1\r\n"))
        }
        (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "InactivityTimeoutSecs") => {
            Some(format!("\r\n    InactivityTimeoutSecs    REG_DWORD    0x708\r\n")) // 1800
        }
        (r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop", "ScreenSaverIsSecure") => {
            Some(format!("\r\n    ScreenSaverIsSecure    REG_SZ    0\r\n"))
        }
        (r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop", "ScreenSaveTimeOut") => {
            Some(format!("\r\n    ScreenSaveTimeOut    REG_SZ    1800\r\n"))
        }
        (r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "ForceUnlockLogon") => {
            Some(format!("\r\n    ForceUnlockLogon    REG_DWORD    0x0\r\n"))
        }
        (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "dontdisplaylastusername") => {
            Some(format!("\r\n    dontdisplaylastusername    REG_DWORD    0x0\r\n"))
        }
        (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "LegalNoticeCaption") => {
            Some(format!("\r\n    LegalNoticeCaption    REG_SZ    \r\n"))
        }
        (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "LegalNoticeText") => {
            Some(format!("\r\n    LegalNoticeText    REG_SZ    \r\n"))
        }
        (r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1") => {
            Some(format!("\r\n    SMB1    REG_DWORD    0x1\r\n"))
        }
        (r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoRestartShell") => {
            Some(format!("\r\n    AutoRestartShell    REG_DWORD    0x1\r\n"))
        }
        (r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "CachedLogonsCount") => {
            Some(format!("\r\n    CachedLogonsCount    REG_SZ    10\r\n"))
        }
        (r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RestrictNullSessAccess") => {
            Some(format!("\r\n    RestrictNullSessAccess    REG_DWORD    0x0\r\n"))
        }
        _ => None,
    }
}

fn run_one(ctx: &mut ScanContext, id: &str) -> CheckResult {
    let mut registry: Vec<RegisteredCheck> = Vec::new();
    register_all(&mut registry);
    let subset: Vec<_> = registry.into_iter().filter(|c| c.tc.id == id).collect();
    assert!(!subset.is_empty(), "Check {id} not found in registry");
    run_all(&subset, ctx).remove(0)
}

#[test]
fn registers_twenty_two_stable_sec_options_ids() {
    let mut registry = Vec::new();
    windows::sec_options::register(&mut registry);
    let ids: Vec<_> = registry.iter().map(|c| c.tc.id).collect();
    assert_eq!(
        ids,
        (1..=22)
            .map(|n| format!("WIN-SEC-{n:03}"))
            .collect::<Vec<_>>()
    );
}

#[test]
fn compliant_registry_values_pass_all_twenty_two_checks() {
    let mut ctx = windows_ctx(sec_injector(true));
    for i in 1..=22 {
        let id = format!("WIN-SEC-{i:03}");
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
fn non_compliant_registry_values_fail_all_twenty_two_checks() {
    let mut ctx = windows_ctx(sec_injector(false));
    for i in 1..=22 {
        let id = format!("WIN-SEC-{i:03}");
        let res = run_one(&mut ctx, &id);
        assert_eq!(
            res.status,
            Status::NonCompliant,
            "Check {id} expected NonCompliant but got {:?}: {}",
            res.status,
            res.evidence
        );
    }
}

#[test]
fn missing_registry_keys_degrade_gracefully() {
    let mut ctx = windows_ctx(Box::new(|_, _| None));
    for i in 1..=22 {
        let id = format!("WIN-SEC-{i:03}");
        // With no read-only registry source available at all, every option
        // is missing evidence -> DegradedPartial, never NonCompliant/Error.
        let res = run_one(&mut ctx, &id);
        assert_eq!(
            res.status,
            Status::DegradedPartial,
            "Check {id} expected DegradedPartial on missing keys: {:?} — {}",
            res.status,
            res.evidence
        );
        assert!(res.degraded_reason.is_some(), "Check {id} degraded_reason missing");
        assert!(!res.fallback_log.is_empty(), "Check {id} fallback_log missing");
    }
}
