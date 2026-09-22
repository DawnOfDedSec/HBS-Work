//! WIN-DEF: Microsoft Defender and Windows Update posture checks.
//!
//! Evidence comes from constant query-only PowerShell cmdlets
//! (`Get-MpComputerStatus`, `Get-MpPreference`, `Get-HotFix`) and one
//! registry read (`NoAutoUpdate`). Missing cmdlets, denied queries, or
//! malformed output degrade to `DegradedPartial`, never `Error`.
//! Tamper protection has its single authoritative home here.

use super::reg_query_dword_with_log;
use crate::checks::{degraded, nok, ok};
use crate::context::ScanContext;
use crate::model::{CheckOutcome, FallbackAttempt, RegisteredCheck};
use crate::platform::Os;

const WU_POLICY_PATH: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";
const DEFENDER_POLICY_PATH: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender";
const DEFENDER_RTP_PATH: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection";
const DEFENDER_FEATURES_PATH: &str = r"HKLM\SOFTWARE\Microsoft\Windows Defender\Features";
const STATUS_CMD: &str = "Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled, IsTamperProtected, AntivirusSignatureAge | ConvertTo-Json";
const PREFERENCE_CMD: &str = "Get-MpPreference | Select-Object DisableScriptScanning, PUAProtection, AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions | ConvertTo-Json";
const HOTFIX_CMD: &str = "Get-HotFix | Sort-Object InstalledOn | Select-Object -Last 1 HotFixID, InstalledOn | ConvertTo-Json";

/// Registry fallback when PowerShell/cmd is blocked or cmdlets are gone.
/// `policy_zero_pass`: value 0 (or key absent with policy default enabled).
fn registry_flag_fallback(
    ctx: &mut ScanContext,
    path: &str,
    name: &str,
    invert: bool,
    attempts: Vec<FallbackAttempt>,
) -> CheckOutcome {
    let query = reg_query_dword_with_log(ctx, path, name);
    let mut attempts = attempts;
    let outcome = match query.value {
        Some(value) => {
            attempts.push(FallbackAttempt {
                source: format!("reg query {path}\\{name}"),
                outcome: format!("read {name} = {value}"),
            });
            let enabled = if invert { value == 0 } else { value != 0 };
            if enabled {
                ok(
                    format!("{name} = {value} (registry fallback)"),
                    format!(r"{path}\{name}"),
                    format!("reg query {path} /v {name}"),
                )
            } else {
                nok(
                    format!("{name} = {value} via registry (expected compliant value)"),
                    format!(r"{path}\{name}"),
                    format!("reg query {path} /v {name}"),
                )
            }
        }
        None => {
            attempts.push(FallbackAttempt {
                source: format!("reg query {path}\\{name}"),
                outcome: "unavailable or missing".into(),
            });
            degraded("PowerShell cmdlets and registry fallback both unavailable")
        }
    };
    with_attempts(outcome, attempts)
}

fn run_ps_json(ctx: &mut ScanContext, script: &str, source: &str) -> (Option<serde_json::Value>, Vec<FallbackAttempt>) {
    let mut attempts = Vec::new();
    let Some(raw) = ctx.cmd(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", script],
    ) else {
        attempts.push(FallbackAttempt {
            source: source.into(),
            outcome: "cmdlet unavailable or query denied".into(),
        });
        return (None, attempts);
    };
    match serde_json::from_str::<serde_json::Value>(raw.trim()) {
        Ok(value) => {
            attempts.push(FallbackAttempt {
                source: source.into(),
                outcome: "parsed JSON".into(),
            });
            (Some(value), attempts)
        }
        Err(_) => {
            attempts.push(FallbackAttempt {
                source: source.into(),
                outcome: "output missing required fields or localized".into(),
            });
            (None, attempts)
        }
    }
}

fn fetch_status(ctx: &mut ScanContext) -> (Option<serde_json::Value>, Vec<FallbackAttempt>) {
    run_ps_json(ctx, STATUS_CMD, "PowerShell Get-MpComputerStatus")
}

fn fetch_preference(ctx: &mut ScanContext) -> (Option<serde_json::Value>, Vec<FallbackAttempt>) {
    run_ps_json(ctx, PREFERENCE_CMD, "PowerShell Get-MpPreference")
}

fn bool_field(status: &serde_json::Value, name: &str) -> Option<bool> {
    status.get(name).and_then(|v| v.as_bool())
}

fn number_field(value: &serde_json::Value, name: &str) -> Option<f64> {
    value.get(name).and_then(|v| v.as_f64())
}

/// Registry fallback route per status field, used when the PowerShell
/// cmdlet layer is blocked. `invert` means policy DWORD 0 = enabled.
fn status_registry_fallback(
    ctx: &mut ScanContext,
    field: &str,
    attempts: Vec<FallbackAttempt>,
) -> CheckOutcome {
    match field {
        "RealTimeProtectionEnabled" => registry_flag_fallback(
            ctx,
            DEFENDER_RTP_PATH,
            "DisableRealtimeMonitoring",
            true,
            attempts,
        ),
        "BehaviorMonitorEnabled" => registry_flag_fallback(
            ctx,
            DEFENDER_RTP_PATH,
            "DisableBehaviorMonitoring",
            true,
            attempts,
        ),
        "AntivirusEnabled" => {
            registry_flag_fallback(ctx, DEFENDER_POLICY_PATH, "DisableAntiSpyware", true, attempts)
        }
        "IsTamperProtected" => registry_flag_fallback(
            ctx,
            DEFENDER_FEATURES_PATH,
            "TamperProtection",
            false,
            attempts,
        ),
        // AMServiceEnabled has no independent policy DWORD; no honest
        // second source exists for it.
        _ => {
            let mut outcome = degraded(&format!(
                "{field} unavailable (Get-MpComputerStatus) and no registry fallback exists"
            ));
            outcome.fallback_log = attempts;
            outcome
        }
    }
}

/// Boolean Defender property expected true: pass/fail on parsed JSON,
/// registry fallback when cmdlets are unavailable, degraded otherwise.
fn status_bool_check(ctx: &mut ScanContext, field: &str, id: &'static str) -> CheckOutcome {
    let _ = id;
    let (status, attempts) = fetch_status(ctx);
    let Some(status) = status else {
        return status_registry_fallback(ctx, field, attempts);
    };
    let Some(value) = bool_field(&status, field) else {
        return status_registry_fallback(ctx, field, attempts);
    };
    let mut outcome = if value {
        ok(
            format!("{field} = true"),
            format!("defender:{field}"),
            "Get-MpComputerStatus | ConvertTo-Json".into(),
        )
    } else {
        nok(
            format!("{field} = false (expected true)"),
            format!("defender:{field}"),
            "Get-MpComputerStatus | ConvertTo-Json".into(),
        )
    };
    outcome.fallback_log = attempts;
    outcome
}

/// Count ASR rules with a non-zero action (1=block, 2=audit, 6=warn).
/// Ids/Actions arrive as arrays or single scalars; unpaired entries are
/// ignored. Informational: evidence is reported, value never fails.
fn asr_active_count(ctx: &mut ScanContext) -> CheckOutcome {
    let (pref, attempts) = fetch_preference(ctx);
    let Some(pref) = pref else {
        let mut outcome = degraded("ASR rules unavailable (Get-MpPreference)");
        outcome.fallback_log = attempts;
        return outcome;
    };
    let ids = pref.get("AttackSurfaceReductionRules_Ids");
    let actions = pref.get("AttackSurfaceReductionRules_Actions");
    let (Some(ids), Some(actions)) = (ids, actions) else {
        let mut outcome = degraded("ASR rule fields missing from Get-MpPreference output");
        outcome.fallback_log = attempts;
        return outcome;
    };

    fn len(v: &serde_json::Value) -> usize {
        match v {
            serde_json::Value::Array(items) => items.len(),
            serde_json::Value::Null => 0,
            _ => 1,
        }
    }
    fn at<'a>(v: &'a serde_json::Value, i: usize) -> Option<&'a serde_json::Value> {
        match v {
            serde_json::Value::Array(items) => items.get(i),
            _ => (i == 0).then_some(v),
        }
    }

    let total = len(ids).min(len(actions));
    let mut active = 0usize;
    for i in 0..total {
        let action = at(actions, i).and_then(|a| a.as_i64()).unwrap_or(0);
        if action != 0 {
            active += 1;
        }
    }

    let mut outcome = ok(
        format!("ASR active count = {active}"),
        "defender:AttackSurfaceReductionRules".to_string(),
        "Get-MpPreference | ConvertTo-Json".into(),
    );
    outcome.fallback_log = attempts;
    outcome
}

fn hotfix_age(ctx: &mut ScanContext) -> CheckOutcome {
    let (hotfix, attempts) = run_ps_json(ctx, HOTFIX_CMD, "PowerShell Get-HotFix");
    let Some(hotfix) = hotfix else {
        let mut outcome = degraded("hotfix age unavailable (Get-HotFix)");
        outcome.fallback_log = attempts;
        return outcome;
    };
    let Some(age) = number_field(&hotfix, "AgeDays") else {
        let mut outcome = degraded("AgeDays missing from Get-HotFix output");
        outcome.fallback_log = attempts;
        return outcome;
    };
    let kb = hotfix
        .get("HotFixID")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let mut outcome = if age <= 90.0 {
        ok(
            format!("latest hotfix {kb} is {age} days old (expected <= 90)"),
            "windows-update:latest-hotfix".into(),
            "Get-HotFix | ConvertTo-Json".into(),
        )
    } else {
        nok(
            format!("latest hotfix {kb} is {age} days old (expected <= 90)"),
            "windows-update:latest-hotfix".into(),
            "Get-HotFix | ConvertTo-Json".into(),
        )
    };
    outcome.fallback_log = attempts;
    outcome
}

fn no_auto_update(ctx: &mut ScanContext) -> CheckOutcome {
    let query = reg_query_dword_with_log(ctx, WU_POLICY_PATH, "NoAutoUpdate");
    let outcome = match query.value {
        Some(0) => ok(
            "NoAutoUpdate = 0 (automatic updates enabled)".to_string(),
            format!(r"{WU_POLICY_PATH}\NoAutoUpdate"),
            format!("reg query {WU_POLICY_PATH} /v NoAutoUpdate"),
        ),
        Some(value) => nok(
            format!("NoAutoUpdate = {value} (expected 0)"),
            format!(r"{WU_POLICY_PATH}\NoAutoUpdate"),
            format!("reg query {WU_POLICY_PATH} /v NoAutoUpdate"),
        ),
        None => degraded("NoAutoUpdate unavailable through read-only registry queries"),
    };
    with_attempts(outcome, query.attempts)
}

fn with_attempts(mut outcome: CheckOutcome, attempts: Vec<FallbackAttempt>) -> CheckOutcome {
    outcome.fallback_log = attempts;
    outcome
}

fn win(p: &crate::platform::PlatformInfo) -> bool {
    p.os == Os::Windows
}

pub fn register(reg: &mut Vec<RegisteredCheck>) {
    use crate::check;
    check!(
        reg,
        "WIN-DEF-001",
        "Defender Antivirus enabled and running",
        "Microsoft Defender antivirus and its service are active.",
        "A disabled endpoint AV leaves the host open to commodity malware.",
        "Ensure Microsoft Defender Antivirus and the Antimalware Service are enabled.",
        High,
        "Defender",
        &["CIS 10.1"],
        win,
        |ctx| status_bool_check(ctx, "AntivirusEnabled", "WIN-DEF-001")
    );
    check!(
        reg,
        "WIN-DEF-002",
        "Real-time protection enabled",
        "Defender scans files and processes as they are accessed.",
        "Without real-time scanning, malware executes before any scheduled scan.",
        "Enable real-time protection in Microsoft Defender.",
        High,
        "Defender",
        &["CIS 10.1"],
        win,
        |ctx| status_bool_check(ctx, "RealTimeProtectionEnabled", "WIN-DEF-002")
    );
    check!(
        reg,
        "WIN-DEF-003",
        "Behavior monitoring enabled",
        "Defender watches process and API behavior for malicious patterns.",
        "Signature-free attacks are only caught by behavioral detection.",
        "Enable behavior monitoring in Microsoft Defender.",
        Medium,
        "Defender",
        &["CIS 10.1"],
        win,
        |ctx| status_bool_check(ctx, "BehaviorMonitorEnabled", "WIN-DEF-003")
    );
    check!(
        reg,
        "WIN-DEF-004",
        "Script scanning enabled",
        "Defender inspects PowerShell, VBScript and JScript content.",
        "Malicious scripts are a top initial-access vector; scan them.",
        "Set DisableScriptScanning to false in Defender preferences.",
        Medium,
        "Defender",
        &["CIS 10.1"],
        win,
        |ctx| script_scanning(ctx)
    );
    check!(
        reg,
        "WIN-DEF-005",
        "PUA protection enabled",
        "Potentially unwanted applications are blocked.",
        "PUAs are adware, coin miners and bundleware that open the door to worse.",
        "Set PUAProtection to 1 (block mode).",
        Medium,
        "Defender",
        &["CIS 10.1"],
        win,
        |ctx| pua_protection(ctx)
    );
    check!(
        reg,
        "WIN-DEF-006",
        "Tamper protection enabled",
        "Defender settings cannot be changed by malware or unprivileged users.",
        "Tamper protection is what keeps every other Defender setting from being flipped off.",
        "Enable Tamper Protection in Microsoft Defender settings.",
        High,
        "Defender",
        &["CIS 10.1"],
        win,
        |ctx| status_bool_check(ctx, "IsTamperProtected", "WIN-DEF-006")
    );
    check!(
        reg,
        "WIN-DEF-007",
        "Signature update age <= 7 days",
        "Antimalware signatures are current within a week.",
        "Stale signatures miss actively exploited malware families.",
        "Verify definition updates flow; investigate hosts older than 7 days.",
        Medium,
        "Defender",
        &["CIS 10.1"],
        win,
        |ctx| signature_age(ctx)
    );
    check!(
        reg,
        "WIN-DEF-008",
        "Attack Surface Reduction rules active count",
        "Counts ASR rules with block/audit/warn actions configured.",
        "ASR rules block Office/script abuse techniques before signatures exist.",
        "Deploy Microsoft-recommended ASR rules in block mode.",
        Informational,
        "Defender",
        &["CIS 10.1"],
        win,
        asr_active_count
    );
    check!(
        reg,
        "WIN-DEF-009",
        "Windows Update hotfix age <= 90 days",
        "The most recent installed hotfix is no older than 90 days.",
        "Unpatched hosts accumulate known, weaponized CVEs.",
        "Patch on a monthly cycle at most; investigate hosts past 90 days.",
        Medium,
        "Defender",
        &["CIS 1.9"],
        win,
        hotfix_age
    );
    check!(
        reg,
        "WIN-DEF-010",
        "Windows Update not disabled (NoAutoUpdate = 0)",
        "Automatic Updates policy does not disable patching.",
        "Hosts with NoAutoUpdate=1 silently stop receiving security fixes.",
        "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU!NoAutoUpdate to 0.",
        Medium,
        "Defender",
        &["CIS 1.9"],
        win,
        no_auto_update
    );
}

fn script_scanning(ctx: &mut ScanContext) -> CheckOutcome {
    let (pref, attempts) = fetch_preference(ctx);
    let Some(pref) = pref else {
        return registry_flag_fallback(
            ctx,
            DEFENDER_RTP_PATH,
            "DisableScriptScanning",
            true,
            attempts,
        );
    };
    let Some(disabled) = bool_field(&pref, "DisableScriptScanning") else {
        return registry_flag_fallback(
            ctx,
            DEFENDER_RTP_PATH,
            "DisableScriptScanning",
            true,
            attempts,
        );
    };
    let mut outcome = if !disabled {
        ok(
            "script scanning enabled (DisableScriptScanning = false)".to_string(),
            "defender:DisableScriptScanning".into(),
            "Get-MpPreference | ConvertTo-Json".into(),
        )
    } else {
        nok(
            "script scanning disabled (DisableScriptScanning = true)".to_string(),
            "defender:DisableScriptScanning".into(),
            "Get-MpPreference | ConvertTo-Json".into(),
        )
    };
    outcome.fallback_log = attempts;
    outcome
}

fn pua_protection(ctx: &mut ScanContext) -> CheckOutcome {
    let (pref, attempts) = fetch_preference(ctx);
    let Some(pref) = pref else {
        return registry_flag_fallback(
            ctx,
            DEFENDER_POLICY_PATH,
            "PUAProtection",
            false,
            attempts,
        );
    };
    let Some(pua) = number_field(&pref, "PUAProtection") else {
        return registry_flag_fallback(
            ctx,
            DEFENDER_POLICY_PATH,
            "PUAProtection",
            false,
            attempts,
        );
    };
    let mut outcome = if pua >= 1.0 {
        ok(
            format!("PUAProtection = {} (block/audit mode)", pua as i64),
            "defender:PUAProtection".into(),
            "Get-MpPreference | ConvertTo-Json".into(),
        )
    } else {
        nok(
            format!("PUAProtection = {} (expected >= 1)", pua as i64),
            "defender:PUAProtection".into(),
            "Get-MpPreference | ConvertTo-Json".into(),
        )
    };
    outcome.fallback_log = attempts;
    outcome
}

fn signature_age(ctx: &mut ScanContext) -> CheckOutcome {
    let (status, attempts) = fetch_status(ctx);
    let Some(status) = status else {
        let mut outcome = degraded(
            "signature age unavailable (Get-MpComputerStatus) and no registry fallback exists",
        );
        outcome.fallback_log = attempts;
        return outcome;
    };
    let Some(age) = number_field(&status, "AntivirusSignatureAge") else {
        let mut outcome = degraded("AntivirusSignatureAge missing from Get-MpComputerStatus output");
        outcome.fallback_log = attempts;
        return outcome;
    };
    let mut outcome = if age <= 7.0 {
        ok(
            format!("signature age = {} days (expected <= 7)", age as i64),
            "defender:AntivirusSignatureAge".into(),
            "Get-MpComputerStatus | ConvertTo-Json".into(),
        )
    } else {
        nok(
            format!("signature age = {} days (expected <= 7)", age as i64),
            "defender:AntivirusSignatureAge".into(),
            "Get-MpComputerStatus | ConvertTo-Json".into(),
        )
    };
    outcome.fallback_log = attempts;
    outcome
}
