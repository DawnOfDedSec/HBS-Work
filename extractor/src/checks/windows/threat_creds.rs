//! WIN-TH (part 1): credential protection & ransomware posture.
//!
//! Registry evaluations (LSA PPL, WDigest, DeviceGuard, ASR, Controlled
//! Folder Access, script block logging) with the shared reg→PowerShell
//! fallback helpers; Credential Guard/HVCI verify runtime state through
//! query-only `Get-CimInstance Win32_DeviceGuard`; `cmdkey /list` and the
//! LSA package list are informational inventories. Everything read-only;
//! missing evidence degrades, never errors.

use super::{reg_query_dword_with_log, reg_query_sz_with_log, QueryResult};
use crate::checks::{degraded, nok, ok};
use crate::context::ScanContext;
use crate::model::{CheckOutcome, FallbackAttempt, RegisteredCheck};
use crate::platform::Os;
use serde_json::Value as Json;

const LSA: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa";
const CI_CONFIG: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\CI\Config";
const HVCI_SCENARIO: &str =
    r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity";
const WDIGEST: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest";
const WINLOGON: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
const ASR_RULES: &str =
    r"HKLM\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules";
const CFA: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access";
const SBL: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging";
const CI_POLICIES: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\CiPolicies";
const SRP_V2: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2";

/// Standard Microsoft ASR GUIDs (case-insensitive wherever compared).
const LSASS_ASR: &str = "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2";
const PSEXEC_ASR: &str = "D3E037E1-3EB8-44C8-A917-57927947596D";
const DRIVER_ASR: &str = "56A863A9-875E-4185-98A7-B882C64B5CE5";

const GUARD_CMD: &str = "Get-CimInstance -Namespace 'root\\Microsoft\\Windows\\DeviceGuard' -ClassName Win32_DeviceGuard | Select-Object SecurityServicesRunning, SecurityServicesConfigured, CodeIntegrityPolicyEnforcementStatus | ConvertTo-Json";
const MPPREF_CMD: &str = "Get-MpPreference | Select-Object EnableControlledFolderAccess, AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions | ConvertTo-Json";

/// Was the reg-query route alive for this attempt list? (explicit value
/// miss vs whole tool unavailable).
fn reg_alive(attempts: &[FallbackAttempt]) -> bool {
    attempts.iter().any(|a| {
        a.source == "reg query"
            && !a.outcome.contains("unavailable")
            && !a.outcome.contains("blocked")
    })
}

fn ps_json(
    ctx: &mut ScanContext,
    script: &str,
    label: &str,
    attempts: &mut Vec<FallbackAttempt>,
) -> Option<Json> {
    let Some(raw) = ctx.cmd(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", script],
    ) else {
        attempts.push(FallbackAttempt {
            source: label.into(),
            outcome: "unavailable or blocked".into(),
        });
        return None;
    };
    let parsed: Option<Json> = serde_json::from_str(raw.trim()).ok();
    attempts.push(FallbackAttempt {
        source: label.into(),
        outcome: if parsed.is_some() {
            "read JSON".into()
        } else {
            "unparseable output".into()
        },
    });
    parsed
}

/// JSON array-or-scalar accessor (ConvertTo-Json unwraps singletons).
fn at<'a>(v: &'a Json, i: usize) -> Option<&'a Json> {
    match v {
        Json::Array(items) => items.get(i),
        Json::Null => None,
        _ => (i == 0).then_some(v),
    }
}

fn as_u64(v: &Json) -> Option<u64> {
    v.as_u64().or_else(|| v.as_str()?.trim().parse().ok())
}

/// Win32_DeviceGuard runtime state (single CIM query shared by 002/003/005).
fn device_guard(ctx: &mut ScanContext, attempts: &mut Vec<FallbackAttempt>) -> Option<Json> {
    ps_json(
        ctx,
        GUARD_CMD,
        "PowerShell Get-CimInstance Win32_DeviceGuard",
        attempts,
    )
}

fn guard_field<'a>(guard: &'a Json, field: &str) -> Option<&'a Json> {
    match guard {
        Json::Array(items) => items.first()?.get(field),
        Json::Object(_) => guard.get(field),
        _ => None,
    }
}

fn guard_running(guard: &Json, flag: u64) -> Option<bool> {
    let running = guard_field(guard, "SecurityServicesRunning")?;
    match running {
        Json::Array(items) => Some(items.iter().filter_map(as_u64).any(|v| v == flag)),
        Json::Null => Some(false),
        single => as_u64(single).map(|v| v == flag),
    }
}

// ---- individual check bodies ----

/// WIN-TH-001: RunAsPPL=1 (+ RunAsPPLBoot pinned).
fn lsa_ppl(ctx: &mut ScanContext) -> CheckOutcome {
    let mut attempts = Vec::new();
    let ppl = reg_query_dword_with_log(ctx, LSA, "RunAsPPL");
    attempts.extend(ppl.attempts);
    let Some(v) = ppl.value else {
        return degraded_with("RunAsPPL unreadable through read-only sources", attempts);
    };
    if v != 1 {
        return nok_with(
            format!("RunAsPPL = {v} (expected 1)"),
            format!("registry:{LSA}"),
            format!("reg query {LSA} /v RunAsPPL"),
            attempts,
        );
    }
    // Runtime PPL is on; boot pinning reported as secondary evidence.
    let boot = reg_query_dword_with_log(ctx, LSA, "RunAsPPLBoot");
    let boot_alive = reg_alive(&boot.attempts);
    attempts.extend(boot.attempts);
    let note = match boot.value {
        Some(b) if b >= 1 => format!("RunAsPPLBoot = {b}"),
        Some(b) => {
            return nok_with(
                format!("RunAsPPL = 1 but RunAsPPLBoot = {b} (boot enforcement disabled)"),
                format!("registry:{LSA}"),
                format!("reg query {LSA} /v RunAsPPLBoot"),
                attempts,
            )
        }
        None if boot_alive => {
            return nok_with(
                "RunAsPPL = 1 but RunAsPPLBoot is not configured".into(),
                format!("registry:{LSA}"),
                format!("reg query {LSA} /v RunAsPPLBoot"),
                attempts,
            )
        }
        None => {
            return degraded_with(
                "RunAsPPL enabled but RunAsPPLBoot unreadable through read-only sources",
                attempts,
            )
        }
    };
    ok_with(
        format!("RunAsPPL = 1; {note}"),
        format!("registry:{LSA}"),
        format!("reg query {LSA} /v RunAsPPL"),
        attempts,
    )
}

/// WIN-TH-002: Credential Guard configured (LsaCfgFlags=1) AND active
/// (DeviceGuard SecurityServicesRunning contains 1).
fn cred_guard(ctx: &mut ScanContext) -> CheckOutcome {
    let mut attempts = Vec::new();
    let cfg = reg_query_dword_with_log(ctx, LSA, "LsaCfgFlags");
    attempts.extend(cfg.attempts);
    match cfg.value {
        Some(v) if v != 1 => {
            return nok_with(
                format!("LsaCfgFlags = {v} (expected 1)"),
                format!("registry:{LSA}"),
                format!("reg query {LSA} /v LsaCfgFlags"),
                attempts,
            )
        }
        None if reg_alive(&attempts) => {
            return nok_with(
                "LsaCfgFlags not configured (Credential Guard policy absent)".into(),
                format!("registry:{LSA}"),
                format!("reg query {LSA} /v LsaCfgFlags"),
                attempts,
            )
        }
        None => return degraded_with("LsaCfgFlags unreadable through read-only sources", attempts),
        _ => {}
    }
    let Some(guard) = device_guard(ctx, &mut attempts) else {
        return degraded_with(
            "Credential Guard configured in registry but runtime state unverifiable (Win32_DeviceGuard unavailable)",
            attempts,
        );
    };
    match guard_running(&guard, 1) {
        Some(true) => ok_with(
            "Credential Guard configured and running".into(),
            format!("cim:Win32_DeviceGuard"),
            GUARD_CMD.into(),
            attempts,
        ),
        Some(false) => nok_with(
            "LsaCfgFlags = 1 but Credential Guard not in SecurityServicesRunning".into(),
            "cim:Win32_DeviceGuard".into(),
            GUARD_CMD.into(),
            attempts,
        ),
        None => degraded_with(
            "DeviceGuard output missing SecurityServicesRunning",
            attempts,
        ),
    }
}

/// WIN-TH-003: HVCI running (SecurityServicesRunning contains 2), with
/// registry scenario fallback when CIM is unavailable.
fn hvci(ctx: &mut ScanContext) -> CheckOutcome {
    let mut attempts = Vec::new();
    if let Some(guard) = device_guard(ctx, &mut attempts) {
        return match guard_running(&guard, 2) {
            Some(true) => ok_with(
                "HVCI running (SecurityServicesRunning contains 2)".into(),
                "cim:Win32_DeviceGuard".into(),
                GUARD_CMD.into(),
                attempts,
            ),
            Some(false) => nok_with(
                "HVCI not running (SecurityServicesRunning lacks 2)".into(),
                "cim:Win32_DeviceGuard".into(),
                GUARD_CMD.into(),
                attempts,
            ),
            None => degraded_with(
                "DeviceGuard output missing SecurityServicesRunning",
                attempts,
            ),
        };
    }
    let q = reg_query_dword_with_log(ctx, HVCI_SCENARIO, "Enabled");
    attempts.extend(q.attempts);
    match q.value {
        Some(1) => ok_with(
            "HVCI enabled per registry scenario (runtime state unverified)".into(),
            format!("registry:{HVCI_SCENARIO}"),
            format!("reg query {HVCI_SCENARIO} /v Enabled"),
            attempts,
        ),
        Some(0) => nok_with(
            "HVCI disabled (Enabled = 0)".into(),
            format!("registry:{HVCI_SCENARIO}"),
            format!("reg query {HVCI_SCENARIO} /v Enabled"),
            attempts,
        ),
        _ => degraded_with("HVCI state unreadable through read-only sources", attempts),
    }
}

/// WIN-TH-004: Microsoft vulnerable driver blocklist.
fn driver_blocklist(ctx: &mut ScanContext) -> CheckOutcome {
    let mut attempts = Vec::new();
    let q = reg_query_dword_with_log(ctx, CI_CONFIG, "VulnerableDriverBlocklistEnable");
    attempts.extend(q.attempts);
    match q.value {
        Some(1) => ok_with(
            "VulnerableDriverBlocklistEnable = 1".into(),
            format!("registry:{CI_CONFIG}"),
            format!("reg query {CI_CONFIG} /v VulnerableDriverBlocklistEnable"),
            attempts,
        ),
        Some(0) => nok_with(
            "VulnerableDriverBlocklistEnable = 0 (blocklist off)".into(),
            format!("registry:{CI_CONFIG}"),
            format!("reg query {CI_CONFIG} /v VulnerableDriverBlocklistEnable"),
            attempts,
        ),
        // Absent with HVCI on means the blocklist is enforced by default;
        // absent alone stays honest: cannot confirm either way.
        Some(_) => degraded_with(
            "VulnerableDriverBlocklistEnable has unexpected non-0/1 value",
            attempts,
        ),
        None if reg_alive(&attempts) => degraded_with(
            "VulnerableDriverBlocklistEnable not present (default depends on build)",
            attempts,
        ),
        None => degraded_with(
            "VulnerableDriverBlocklistEnable unreadable through read-only sources",
            attempts,
        ),
    }
}

/// WIN-TH-005: application control active - WDAC policy or AppLocker.
fn app_control(ctx: &mut ScanContext) -> CheckOutcome {
    let mut attempts = Vec::new();
    if let Some(guard) = device_guard(ctx, &mut attempts) {
        if let Some(status) =
            guard_field(&guard, "CodeIntegrityPolicyEnforcementStatus").and_then(as_u64)
        {
            return if status >= 1 {
                ok_with(
                    format!(
                        "WDAC enforcement status {status} (CodeIntegrityPolicyEnforcementStatus)"
                    ),
                    "cim:Win32_DeviceGuard".into(),
                    GUARD_CMD.into(),
                    attempts,
                )
            } else {
                // WDAC off; AppLocker may still cover it.
                applocker_fallback(ctx, "WDAC not enforcing", attempts)
            };
        }
    }
    // Registry CiPolicies probe (any policy file registered = WDAC active).
    match ctx.cmd("reg", &["query", CI_POLICIES]) {
        Some(raw) if !raw.contains("unable to find") && !raw.trim().is_empty() => {
            attempts.push(FallbackAttempt {
                source: format!("reg query {CI_POLICIES}"),
                outcome: "read WDAC policy key".into(),
            });
            ok_with(
                "WDAC Code Integrity policy present".into(),
                format!("registry:{CI_POLICIES}"),
                format!("reg query {CI_POLICIES}"),
                attempts,
            )
        }
        Some(_) => {
            attempts.push(FallbackAttempt {
                source: format!("reg query {CI_POLICIES}"),
                outcome: "no WDAC policy registered".into(),
            });
            applocker_fallback(ctx, "no WDAC policy", attempts)
        }
        None => {
            attempts.push(FallbackAttempt {
                source: format!("reg query {CI_POLICIES}"),
                outcome: "unavailable".into(),
            });
            applocker_fallback(ctx, "WDAC state unverifiable", attempts)
        }
    }
}

fn applocker_fallback(
    ctx: &mut ScanContext,
    wdac_note: &str,
    mut attempts: Vec<FallbackAttempt>,
) -> CheckOutcome {
    match ctx.cmd("reg", &["query", SRP_V2]) {
        Some(raw) if raw.contains("Exe") => {
            attempts.push(FallbackAttempt {
                source: format!("reg query {SRP_V2}"),
                outcome: "read AppLocker SrpV2 rules".into(),
            });
            ok_with(
                format!("{wdac_note}; AppLocker policy rules present"),
                format!("registry:{SRP_V2}"),
                format!("reg query {SRP_V2}"),
                attempts,
            )
        }
        Some(_) => {
            attempts.push(FallbackAttempt {
                source: format!("reg query {SRP_V2}"),
                outcome: "no AppLocker rules".into(),
            });
            nok_with(
                format!("{wdac_note} and no AppLocker rules (no application control)"),
                format!("registry:{SRP_V2}"),
                format!("reg query {SRP_V2}"),
                attempts,
            )
        }
        None => {
            attempts.push(FallbackAttempt {
                source: format!("reg query {SRP_V2}"),
                outcome: "unavailable".into(),
            });
            degraded_with(
                "application control state unverifiable through read-only sources",
                attempts,
            )
        }
    }
}

/// What an absent DWORD means for this check.
#[derive(Clone, Copy, PartialEq)]
enum Absent {
    /// Value genuinely absent: passes (default-safe off state).
    Pass,
    /// Value absent = feature off: fails.
    Fail,
}

struct FlagDef {
    path: &'static str,
    name: &'static str,
    /// Expected DWORD for Compliant (typically 0 or 1).
    want: u32,
    absent: Absent,
}

impl FlagDef {
    fn repro(&self) -> String {
        format!("reg query {} /v {}", self.path, self.name)
    }
}

/// Table-driven single-DWORD checks (004-style but for the plain ones).
fn flag_check(ctx: &mut ScanContext, def: &FlagDef) -> CheckOutcome {
    let mut attempts = Vec::new();
    let q = reg_query_dword_with_log(ctx, def.path, def.name);
    attempts.extend(q.attempts);
    match q.value {
        Some(v) => {
            let mut outcome = if v == def.want {
                ok(
                    format!("{0} = {v} (expected {1})", def.name, def.want),
                    format!("registry:{}", def.path),
                    def.repro(),
                )
            } else {
                nok(
                    format!("{0} = {v} (expected {1})", def.name, def.want),
                    format!("registry:{}", def.path),
                    def.repro(),
                )
            };
            outcome.fallback_log = attempts;
            outcome
        }
        None if reg_alive(&attempts) && def.absent == Absent::Pass => ok_with(
            format!(
                "{0} not configured (platform default already {1})",
                def.name, def.want
            ),
            format!("registry:{}", def.path),
            def.repro(),
            attempts,
        ),
        None if reg_alive(&attempts) && def.absent == Absent::Fail => nok_with(
            format!("{0} not configured (feature disabled by default)", def.name),
            format!("registry:{}", def.path),
            def.repro(),
            attempts,
        ),
        None => degraded_with(
            &format!("{0} unreadable through read-only sources", def.name),
            attempts,
        ),
    }
}

/// WIN-TH-007: no automatic admin logon, no stored DefaultPassword.
fn auto_admin_logon(ctx: &mut ScanContext) -> CheckOutcome {
    let mut attempts = Vec::new();
    let auto = reg_query_sz_with_log(ctx, WINLOGON, "AutoAdminLogon");
    attempts.extend(auto.attempts);
    let enabled = match auto.value.as_deref() {
        Some(v) => {
            let v = v.trim();
            let n = v
                .strip_prefix("0x")
                .or_else(|| v.strip_prefix("0X"))
                .and_then(|hex| u32::from_str_radix(hex, 16).ok())
                .or_else(|| v.parse::<u32>().ok());
            Some(n.map_or(!v.is_empty(), |n| n != 0))
        }
        None if reg_alive(&attempts) => Some(false),
        None => None,
    };
    let Some(enabled) = enabled else {
        return degraded_with("Winlogon unreadable through read-only sources", attempts);
    };
    if enabled {
        return nok_with(
            "AutoAdminLogon enabled (unattended logon with cached credentials)".into(),
            format!("registry:{WINLOGON}"),
            format!("reg query {WINLOGON} /v AutoAdminLogon"),
            attempts,
        );
    }
    // Logon auto-disabled; a stale DefaultPassword is still a findable secret.
    let pw = reg_query_sz_with_log(ctx, WINLOGON, "DefaultPassword");
    let pw_alive = reg_alive(&pw.attempts);
    attempts.extend(pw.attempts);
    match pw.value {
        Some(v) if !v.trim().is_empty() => {
            // Value deliberately omitted from evidence (secret).
            nok_with(
                "DefaultPassword value stored under Winlogon (stale cleartext secret)".into(),
                format!("registry:{WINLOGON}"),
                format!("reg query {WINLOGON} /v DefaultPassword"),
                attempts,
            )
        }
        _ if pw_alive => ok_with(
            "AutoAdminLogon disabled, no DefaultPassword stored".into(),
            format!("registry:{WINLOGON}"),
            format!("reg query {WINLOGON} /v AutoAdminLogon"),
            attempts,
        ),
        _ => degraded_with("DefaultPassword state unverifiable", attempts),
    }
}

/// WIN-TH-008: `cmdkey /list` stored-credentials inventory. Informational.
fn cmdkey_inventory(ctx: &mut ScanContext) -> CheckOutcome {
    let mut attempts = Vec::new();
    match ctx.cmd("cmdkey", &["/list"]) {
        Some(raw) => {
            let targets: Vec<&str> = raw
                .lines()
                .filter_map(|l| {
                    let t = l.trim();
                    t.starts_with("Target:").then(|| t.to_string()).map(|_| t)
                })
                .collect();
            attempts.push(FallbackAttempt {
                source: "cmdkey /list".into(),
                outcome: format!("{} stored credentials", targets.len()),
            });
            let listing = if targets.is_empty() {
                "none".to_string()
            } else {
                targets.join(" | ")
            };
            ok_with(
                format!("stored credentials ({}): {listing}", targets.len()),
                "cmdkey:list".into(),
                "cmdkey /list".into(),
                attempts,
            )
        }
        None => {
            attempts.push(FallbackAttempt {
                source: "cmdkey /list".into(),
                outcome: "unavailable or blocked".into(),
            });
            degraded_with("stored credential inventory unreadable (cmdkey)", attempts)
        }
    }
}

/// WIN-TH-009: LSA security packages inventory. Informational.
fn lsa_packages(ctx: &mut ScanContext) -> CheckOutcome {
    let mut attempts = Vec::new();
    let q: QueryResult<String> = reg_query_sz_with_log(ctx, LSA, "Security Packages");
    attempts.extend(q.attempts);
    match q.value {
        Some(pkgs) => ok_with(
            format!("LSA security packages: {pkgs}"),
            format!("registry:{LSA}"),
            format!("reg query {LSA} /v \"Security Packages\""),
            attempts,
        ),
        None if reg_alive(&attempts) => degraded_with(
            "Security Packages value not present (non-default configuration)",
            attempts,
        ),
        None => degraded_with(
            "LSA security package list unreadable through read-only sources",
            attempts,
        ),
    }
}

/// WIN-TH-010..012: specific ASR rules must exist with action 1 (block).
fn asr_rule(ctx: &mut ScanContext, guid: &str) -> CheckOutcome {
    let mut attempts = Vec::new();
    let q = reg_query_dword_with_log(ctx, ASR_RULES, guid);
    attempts.extend(q.attempts);
    if let Some(v) = q.value {
        let mut outcome = if v == 1 {
            ok(
                format!("ASR {guid} action = Block"),
                format!("registry:{ASR_RULES}"),
                format!("reg query {ASR_RULES} /v {guid}"),
            )
        } else {
            nok(
                format!("ASR {guid} action = {v} (expected 1 = Block)"),
                format!("registry:{ASR_RULES}"),
                format!("reg query {ASR_RULES} /v {guid}"),
            )
        };
        outcome.fallback_log = attempts;
        return outcome;
    }
    // Registry didn't answer; Get-MpPreference is the runtime view.
    let mut mp_attempts = Vec::new();
    let pref = ps_json(
        ctx,
        MPPREF_CMD,
        "PowerShell Get-MpPreference",
        &mut mp_attempts,
    );
    attempts.extend(mp_attempts);
    if let Some(pref) = pref {
        let ids = pref.get("AttackSurfaceReductionRules_Ids");
        let actions = pref.get("AttackSurfaceReductionRules_Actions");
        if let (Some(ids), Some(actions)) = (ids, actions) {
            let total = match (ids, actions) {
                (Json::Array(a), Json::Array(b)) => a.len().min(b.len()),
                _ => 1,
            };
            for i in 0..total {
                let (Some(id), Some(action)) = (at(ids, i), at(actions, i)) else {
                    continue;
                };
                if id.as_str().map_or(false, |s| s.eq_ignore_ascii_case(guid)) {
                    let action = action.as_i64().unwrap_or(0);
                    let mut outcome = if action == 1 {
                        ok(
                            format!("ASR {guid} action = Block (Get-MpPreference)"),
                            "defender:AttackSurfaceReductionRules".into(),
                            "Get-MpPreference | ConvertTo-Json".into(),
                        )
                    } else {
                        nok(
                            format!("ASR {guid} action = {action} (expected 1 = Block)"),
                            "defender:AttackSurfaceReductionRules".into(),
                            "Get-MpPreference | ConvertTo-Json".into(),
                        )
                    };
                    outcome.fallback_log = attempts;
                    return outcome;
                }
            }
        }
    }
    if reg_alive(&attempts) {
        // Tools alive, rule simply absent everywhere: not configured.
        nok_with(
            format!("ASR rule {guid} not configured (absent in registry and Get-MpPreference)"),
            format!("registry:{ASR_RULES}"),
            format!("reg query {ASR_RULES} /v {guid}"),
            attempts,
        )
    } else {
        degraded_with(
            &format!("ASR rule {guid} state unverifiable through read-only sources"),
            attempts,
        )
    }
}

fn win(p: &crate::platform::PlatformInfo) -> bool {
    p.os == Os::Windows
}

// outcome helpers that carry the fallback log
fn ok_with(
    evidence: String,
    location: String,
    repro: String,
    attempts: Vec<FallbackAttempt>,
) -> CheckOutcome {
    let mut o = ok(evidence, location, repro);
    o.fallback_log = attempts;
    o
}

fn nok_with(
    evidence: String,
    location: String,
    repro: String,
    attempts: Vec<FallbackAttempt>,
) -> CheckOutcome {
    let mut o = nok(evidence, location, repro);
    o.fallback_log = attempts;
    o
}

fn degraded_with(reason: &str, attempts: Vec<FallbackAttempt>) -> CheckOutcome {
    let mut o = degraded(reason);
    o.fallback_log = attempts;
    o
}

pub fn register(reg: &mut Vec<RegisteredCheck>) {
    use crate::check;
    check!(
        reg,
        "WIN-TH-001",
        "LSA protection RunAsPPL enabled",
        "RunAsPPL = 1 pins LSA into PPL mode; RunAsPPLBoot recorded alongside.",
        "Without LSASS PPL, mimikatz-class tools read credentials straight from memory.",
        "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa!RunAsPPL = 1 (DWORD) and reboot.",
        High,
        "Threat",
        &[
            "MITRE T1003",
            "CIS Microsoft Windows Server Benchmark",
            "Microsoft Security Baseline"
        ],
        win,
        lsa_ppl
    );
    check!(
        reg,
        "WIN-TH-002",
        "Credential Guard configured and active",
        "LsaCfgFlags = 1 and Win32_DeviceGuard lists Credential Guard as running.",
        "Credential Guard keeps domain secrets out of LSASS memory even with PPL bypassed.",
        "Enable Credential Guard via EMS policy or set LsaCfgFlags = 1 with VBS available.",
        High,
        "Threat",
        &[
            "MITRE T1003",
            "CIS Microsoft Windows Server Benchmark",
            "Microsoft Security Baseline"
        ],
        win,
        cred_guard
    );
    check!(
        reg,
        "WIN-TH-003",
        "Hypervisor-protected Code Integrity (HVCI) enabled",
        "Win32_DeviceGuard reports HVCI running; registry scenario read as fallback.",
        "HVCI blocks kernel exploits from mapping unsigned executable memory.",
        "Enable Memory Integrity: Windows Security > Device security, or DeviceGuard Enabled = 1.",
        Medium,
        "Threat",
        &[
            "MITRE T1068",
            "CIS Microsoft Windows Server Benchmark",
            "Microsoft Security Baseline"
        ],
        win,
        hvci
    );
    check!(
        reg, "WIN-TH-004",
        "Microsoft vulnerable driver blocklist enabled",
        "VulnerableDriverBlocklistEnable = 1 under CI\\Config.",
        "Signed-but-vulnerable drivers are the easiest BYOVD kernel escalation path.",
        "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config!VulnerableDriverBlocklistEnable = 1.",
        Medium, "Threat", &["MITRE T1553.002", "CIS Microsoft Windows Server Benchmark", "Microsoft Security Baseline"],
        win,
        driver_blocklist
    );
    check!(
        reg,
        "WIN-TH-005",
        "Application control policy active (WDAC or AppLocker)",
        "A WDAC Code Integrity policy enforces or AppLocker SrpV2 rules exist.",
        "Without application control, every user-writable directory is a malware drop zone.",
        "Deploy a WDAC policy or AppLocker Executable rules in Enforce mode.",
        High,
        "Threat",
        &[
            "CIS Microsoft Windows Server Benchmark",
            "Microsoft Security Baseline"
        ],
        win,
        app_control
    );
    check!(
        reg,
        "WIN-TH-006",
        "WDigest cleartext credential caching disabled",
        "UseLogonCredential is 0 or absent (default-safe).",
        "WDigest=1 leaves plaintext passwords in LSASS memory for any admin-level reader.",
        "Set HKLM\\...\\SecurityProviders\\WDigest!UseLogonCredential = 0 (or delete the value).",
        High,
        "Threat",
        &[
            "MITRE T1003.001",
            "CIS Microsoft Windows Server Benchmark",
            "Microsoft Security Baseline"
        ],
        win,
        |ctx| flag_check(
            ctx,
            &FlagDef {
                path: WDIGEST,
                name: "UseLogonCredential",
                want: 0,
                absent: Absent::Pass
            }
        )
    );
    check!(
        reg,
        "WIN-TH-007",
        "Automatic admin logon disabled, no stored default password",
        "AutoAdminLogon is 0/absent and no DefaultPassword value remains.",
        "AutoAdminLogon plus DefaultPassword hands interactive admin to whoever reboots the box.",
        "Remove AutoAdminLogon/DefaultPassword from HKLM\\...\\Winlogon.",
        High,
        "Threat",
        &[
            "MITRE T1078",
            "CIS Microsoft Windows Server Benchmark",
            "Microsoft Security Baseline"
        ],
        win,
        auto_admin_logon
    );
    check!(
        reg,
        "WIN-TH-008",
        "Stored credentials inventory (cmdkey)",
        "cmdkey /list output recorded as inventory.",
        "Stored credential blobs survive the account that made them and replay on this host.",
        "Review and prune stored credentials: cmdkey /delete:<target>.",
        Informational,
        "Threat",
        &[
            "MITRE T1555",
            "CIS Microsoft Windows Server Benchmark",
            "Microsoft Security Baseline"
        ],
        win,
        cmdkey_inventory
    );
    check!(
        reg,
        "WIN-TH-009",
        "LSA security packages inventory",
        "Security Packages value under Lsa recorded.",
        "Extra authentication packages are a classic LSA-rooted persistence layer.",
        "Review the package list; remove unknown SSPs from HKLM\\...\\Lsa.",
        Informational,
        "Threat",
        &[
            "CIS Microsoft Windows Server Benchmark",
            "Microsoft Security Baseline"
        ],
        win,
        lsa_packages
    );
    check!(
        reg,
        "WIN-TH-010",
        "ASR rule: block credential stealing from LSASS",
        "ASR 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 configured with action 1 (Block).",
        "The single highest-value ASR rule: kills the dominant credential-dump family.",
        "Add rule 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 in Block mode via Intune/GPO.",
        High,
        "Threat",
        &[
            "MITRE T1003.001",
            "CIS Microsoft Windows Server Benchmark",
            "Microsoft Security Baseline"
        ],
        win,
        |ctx| asr_rule(ctx, LSASS_ASR)
    );
    check!(
        reg,
        "WIN-TH-011",
        "ASR rule: block process creations from PSExec and WMI",
        "ASR D3E037E1-3EB8-44C8-A917-57927947596D configured with action 1 (Block).",
        "PSExec/WMI originate most lateral movement; blocking strips the loudest path.",
        "Add rule D3E037E1-3EB8-44C8-A917-57927947596D in Block mode.",
        Medium,
        "Threat",
        &[
            "MITRE T1021",
            "CIS Microsoft Windows Server Benchmark",
            "Microsoft Security Baseline"
        ],
        win,
        |ctx| asr_rule(ctx, PSEXEC_ASR)
    );
    check!(
        reg,
        "WIN-TH-012",
        "ASR rule: block execution of vulnerable signed drivers",
        "ASR 56A863A9-875E-4185-98A7-B882C64B5CE5 configured with action 1 (Block).",
        "Complements the driver blocklist at the process-creation layer.",
        "Add rule 56A863A9-875E-4185-98A7-B882C64B5CE5 in Block mode.",
        High,
        "Threat",
        &[
            "MITRE T1553.002",
            "CIS Microsoft Windows Server Benchmark",
            "Microsoft Security Baseline"
        ],
        win,
        |ctx| asr_rule(ctx, DRIVER_ASR)
    );
    check!(
        reg, "WIN-TH-013",
        "Controlled Folder Access enabled",
        "EnableControlledFolderAccess = 1 (policy or Get-MpPreference).",
        "CFA blocks untrusted processes from writing to Documents-class folders: ransomware speed bump.",
        "Set Exploit Guard CFA EnableControlledFolderAccess = 1 via GPO/Intune.",
        Medium, "Threat", &["MITRE T1486", "CIS Microsoft Windows Server Benchmark", "Microsoft Security Baseline"],
        win,
        |ctx| flag_check(ctx, &FlagDef { path: CFA, name: "EnableControlledFolderAccess", want: 1, absent: Absent::Fail })
    );
    check!(
        reg, "WIN-TH-014",
        "PowerShell Script Block Logging enabled",
        "EnableScriptBlockLogging = 1 under the PowerShell policy key.",
        "Without block logging, obfuscated PowerShell leaves no forensic trail.",
        "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging!EnableScriptBlockLogging = 1.",
        Low, "Threat", &["MITRE T1059.001", "CIS Microsoft Windows Server Benchmark", "Microsoft Security Baseline"],
        win,
        |ctx| flag_check(ctx, &FlagDef { path: SBL, name: "EnableScriptBlockLogging", want: 1, absent: Absent::Fail })
    );
}
