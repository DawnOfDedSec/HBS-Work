//! WIN-SEC: Windows security options checks using read-only registry evidence.
//!
//! Evaluated strictly via the ordered `reg query` -> PowerShell
//! `Get-ItemProperty` -> native in-process registry fallback chain, so
//! every option still resolves on an image without `reg` or PowerShell.
//! Missing or unavailable evidence returns `DegradedPartial`, never
//! `Error`. No writes, no `secedit /export`, no temp files.

use super::{reg_query_sz_with_log, QueryResult};
use crate::checks::{degraded, nok, ok};
use crate::context::ScanContext;
use crate::model::{CheckOutcome, FallbackAttempt, RegisteredCheck};
use crate::platform::Os;

const POLICIES_SYSTEM: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
const CONTROL_LSA: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa";
const LANMAN_SERVER: &str =
    r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
const LANMAN_WORKSTATION: &str =
    r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters";
const MEMORY_MGMT: &str =
    r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management";
const WINLOGON: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
const CONTROL_PANEL_DESKTOP: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop";

#[derive(Clone, Copy)]
enum ValueKind {
    /// Must equal `expected` exactly.
    Equals(u32),
    /// Must be >= `expected`.
    AtLeast(u32),
    /// Must be <= `expected` and nonzero where meaningful.
    AtMost(u32),
    /// Non-empty non-whitespace string required.
    NonEmpty,
    /// DWORD 0 required.
    Disabled,
}

struct SecOptionDef {
    id: &'static str,
    title: &'static str,
    description: &'static str,
    rationale: &'static str,
    remediation: &'static str,
    severity: crate::model::Severity,
    benchmarks: &'static [&'static str],
    path: &'static str,
    value_name: &'static str,
    kind: ValueKind,
}

const SEC_OPTIONS: &[SecOptionDef] = &[
    SecOptionDef {
        id: "WIN-SEC-001",
        title: "LM compatibility level >= 5",
        description: "Only NTLMv2 session security permitted; LM and NTLMv1 refused.",
        rationale: "LM and NTLMv1 hashes are trivially crackable and enable pass-the-hash replay.",
        remediation: "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa!LmCompatibilityLevel to 5.",
        severity: crate::model::Severity::High,
        benchmarks: &["CIS 2.3.11.4"],
        path: CONTROL_LSA,
        value_name: "LmCompatibilityLevel",
        kind: ValueKind::AtLeast(5),
    },
    SecOptionDef {
        id: "WIN-SEC-002",
        title: "Do not store LM hash (NoLMHash)",
        description: "New passwords must not be stored as reversible LM hashes.",
        rationale: "Stored LM hashes expose every password to offline cracking within seconds.",
        remediation: "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa!NoLMHash to 1.",
        severity: crate::model::Severity::High,
        benchmarks: &["CIS 2.3.11.5"],
        path: CONTROL_LSA,
        value_name: "NoLMHash",
        kind: ValueKind::Equals(1),
    },
    SecOptionDef {
        id: "WIN-SEC-003",
        title: "SMB server requires signing",
        description: "SMB server negotiates packet signing to block tampering and relay attacks.",
        rationale: "Unsigned SMB traffic allows man-in-the-middle session hijacking.",
        remediation: "Set LanmanServer\\Parameters!RequireSecuritySignature to 1.",
        severity: crate::model::Severity::High,
        benchmarks: &["CIS 2.3.11.8"],
        path: LANMAN_SERVER,
        value_name: "RequireSecuritySignature",
        kind: ValueKind::Equals(1),
    },
    SecOptionDef {
        id: "WIN-SEC-004",
        title: "SMB client requires signing",
        description: "SMB client refuses unsigned server sessions.",
        rationale: "Clients that accept unsigned sessions are silently downgraded to insecure SMB.",
        remediation: "Set LanmanWorkstation\\Parameters!RequireSecuritySignature to 1.",
        severity: crate::model::Severity::High,
        benchmarks: &["CIS 2.3.11.9"],
        path: LANMAN_WORKSTATION,
        value_name: "RequireSecuritySignature",
        kind: ValueKind::Equals(1),
    },
    SecOptionDef {
        id: "WIN-SEC-005",
        title: "UAC runs in Admin Approval Mode (EnableLUA)",
        description: "All administrators run with split-token until elevation is approved.",
        rationale: "Without UAC every process in an admin session runs with full privileges.",
        remediation: "Set Policies\\System!EnableLUA to 1.",
        severity: crate::model::Severity::Critical,
        benchmarks: &["CIS 2.3.17.1"],
        path: POLICIES_SYSTEM,
        value_name: "EnableLUA",
        kind: ValueKind::Equals(1),
    },
    SecOptionDef {
        id: "WIN-SEC-006",
        title: "UAC admin consent prompt behavior >= 2",
        description: "Elevation requests require explicit consent or credentials.",
        rationale: "Silent elevation lets malware operate with admin rights undetected.",
        remediation: "Set Policies\\System!ConsentPromptBehaviorAdmin to 2 (or higher).",
        severity: crate::model::Severity::High,
        benchmarks: &["CIS 2.3.17.2"],
        path: POLICIES_SYSTEM,
        value_name: "ConsentPromptBehaviorAdmin",
        kind: ValueKind::AtLeast(2),
    },
    SecOptionDef {
        id: "WIN-SEC-007",
        title: "UAC installer detection enabled",
        description: "Legacy installer heuristics trigger elevation prompts.",
        rationale: "Undetected legacy installers run without user awareness of elevation.",
        remediation: "Set Policies\\System!EnableInstallerDetection to 1.",
        severity: crate::model::Severity::Low,
        benchmarks: &["CIS 2.3.17.3"],
        path: POLICIES_SYSTEM,
        value_name: "EnableInstallerDetection",
        kind: ValueKind::Equals(1),
    },
    SecOptionDef {
        id: "WIN-SEC-008",
        title: "UAC only elevates signed/validated executables",
        description: "Elevation requests validate the executable before showing a prompt.",
        rationale: "Unsigned elevation paths are abused by malicious binaries.",
        remediation: "Set Policies\\System!EnableSecureUIPaths to 1.",
        severity: crate::model::Severity::Medium,
        benchmarks: &["CIS 2.3.17.5"],
        path: POLICIES_SYSTEM,
        value_name: "EnableSecureUIPaths",
        kind: ValueKind::Equals(1),
    },
    SecOptionDef {
        id: "WIN-SEC-009",
        title: "UAC file/registry virtualization enabled",
        description: "Legacy writes to protected locations are virtualized per-user.",
        rationale: "Virtualization contains legacy-app writes that would otherwise fail open.",
        remediation: "Set Policies\\System!EnableVirtualization to 1.",
        severity: crate::model::Severity::Low,
        benchmarks: &["CIS 2.3.17.7"],
        path: POLICIES_SYSTEM,
        value_name: "EnableVirtualization",
        kind: ValueKind::Equals(1),
    },
    SecOptionDef {
        id: "WIN-SEC-010",
        title: "Clear virtual memory pagefile at shutdown",
        description: "Pagefile is wiped at shutdown so spilled secrets are not left on disk.",
        rationale: "Pagefiles accumulate credentials and keys readable via offline disk access.",
        remediation: "Set Memory Management!ClearPageFileAtShutdown to 1.",
        severity: crate::model::Severity::Low,
        benchmarks: &["CIS 2.3.6.1"],
        path: MEMORY_MGMT,
        value_name: "ClearPageFileAtShutdown",
        kind: ValueKind::Equals(1),
    },
    SecOptionDef {
        id: "WIN-SEC-011",
        title: "No Microsoft accounts for Store apps (NoConnectedUser = 3)",
        description: "Windows Store apps cannot authenticate with Microsoft accounts.",
        rationale: "Consumer accounts bypass corporate identity controls and leak data to cloud services.",
        remediation: "Set Policies\\System!NoConnectedUser to 3.",
        severity: crate::model::Severity::Medium,
        benchmarks: &["CIS 18.9.4.1"],
        path: POLICIES_SYSTEM,
        value_name: "NoConnectedUser",
        kind: ValueKind::Equals(3),
    },
    SecOptionDef {
        id: "WIN-SEC-012",
        title: "Inactivity timeout <= 900 seconds",
        description: "Idle sessions lock within 15 minutes.",
        rationale: "Unattended unlocked sessions invite tampering and data theft.",
        remediation: "Set Policies\\System!InactivityTimeoutSecs to 900 or less.",
        severity: crate::model::Severity::Medium,
        benchmarks: &["CIS 2.3.17.8"],
        path: POLICIES_SYSTEM,
        value_name: "InactivityTimeoutSecs",
        kind: ValueKind::AtMost(900),
    },
    SecOptionDef {
        id: "WIN-SEC-013",
        title: "Password-protected screen saver",
        description: "Screen saver lock requires password to resume.",
        rationale: "A screen saver without password protection is a decorative lock.",
        remediation: "Set Control Panel\\Desktop!ScreenSaverIsSecure to 1.",
        severity: crate::model::Severity::Medium,
        benchmarks: &["CIS 18.9.30.2"],
        path: CONTROL_PANEL_DESKTOP,
        value_name: "ScreenSaverIsSecure",
        kind: ValueKind::Equals(1),
    },
    SecOptionDef {
        id: "WIN-SEC-014",
        title: "Screen saver timeout <= 900 seconds",
        description: "Screen saver engages within 15 minutes of inactivity.",
        rationale: "Long idle windows extend exposure of unlocked sessions.",
        remediation: "Set Control Panel\\Desktop!ScreenSaveTimeOut to 900 or less.",
        severity: crate::model::Severity::Medium,
        benchmarks: &["CIS 18.9.30.3"],
        path: CONTROL_PANEL_DESKTOP,
        value_name: "ScreenSaveTimeOut",
        kind: ValueKind::AtMost(900),
    },
    SecOptionDef {
        id: "WIN-SEC-015",
        title: "Require domain controller to unlock (ForceUnlockLogon)",
        description: "Cached credentials cannot unlock the machine offline.",
        rationale: "Offline unlock with stolen cached hashes defeats account lockout.",
        remediation: "Set Winlogon!ForceUnlockLogon to 1.",
        severity: crate::model::Severity::Low,
        benchmarks: &["CIS 2.3.7.3"],
        path: WINLOGON,
        value_name: "ForceUnlockLogon",
        kind: ValueKind::Equals(1),
    },
    SecOptionDef {
        id: "WIN-SEC-016",
        title: "Do not display last user name",
        description: "Logon screen does not reveal the previous account.",
        rationale: "Displayed usernames halve the work of credential attacks.",
        remediation: "Set Policies\\System!dontdisplaylastusername to 1.",
        severity: crate::model::Severity::Low,
        benchmarks: &["CIS 2.3.7.1"],
        path: POLICIES_SYSTEM,
        value_name: "dontdisplaylastusername",
        kind: ValueKind::Equals(1),
    },
    SecOptionDef {
        id: "WIN-SEC-017",
        title: "Interactive logon legal notice caption configured",
        description: "A legal notice caption is presented before logon.",
        rationale: "Notice supports prosecution and sets expectation of monitoring.",
        remediation: "Set Policies\\System!LegalNoticeCaption to organizational text.",
        severity: crate::model::Severity::Low,
        benchmarks: &["CIS 2.3.7.5"],
        path: POLICIES_SYSTEM,
        value_name: "LegalNoticeCaption",
        kind: ValueKind::NonEmpty,
    },
    SecOptionDef {
        id: "WIN-SEC-018",
        title: "Interactive logon legal notice text configured",
        description: "A legal notice body is presented before logon.",
        rationale: "Notice supports prosecution and sets expectation of monitoring.",
        remediation: "Set Policies\\System!LegalNoticeText to organizational text.",
        severity: crate::model::Severity::Low,
        benchmarks: &["CIS 2.3.7.6"],
        path: POLICIES_SYSTEM,
        value_name: "LegalNoticeText",
        kind: ValueKind::NonEmpty,
    },
    SecOptionDef {
        id: "WIN-SEC-019",
        title: "SMBv1 protocol disabled",
        description: "Legacy SMBv1 protocol stack is turned off.",
        rationale: "SMBv1 carries EternalBlue/WannaCry-class worms and lacks integrity controls.",
        remediation: "Set LanmanServer\\Parameters!SMB1 to 0 and remove the SMB1Optional feature.",
        severity: crate::model::Severity::Critical,
        benchmarks: &["CIS 18.3.2"],
        path: LANMAN_SERVER,
        value_name: "SMB1",
        kind: ValueKind::Disabled,
    },
    SecOptionDef {
        id: "WIN-SEC-020",
        title: "Auto restart shell cleared (AutoRestartShell = 0)",
        description: "Explorer is not silently respawned by Winlogon.",
        rationale: "Attackers abuse shell respawn to relaunch injected shellcode after crashes.",
        remediation: "Set Winlogon!AutoRestartShell to 0 per hardening baseline.",
        severity: crate::model::Severity::Low,
        benchmarks: &[],
        path: WINLOGON,
        value_name: "AutoRestartShell",
        kind: ValueKind::Equals(0),
    },
    SecOptionDef {
        id: "WIN-SEC-021",
        title: "Cached logons count <= 4",
        description: "At most four domain credentials are cached locally.",
        rationale: "Large caches give offline attackers many targets for hash extraction.",
        remediation: "Set Winlogon!CachedLogonsCount to 4 or less.",
        severity: crate::model::Severity::Medium,
        benchmarks: &["CIS 2.3.7.2"],
        path: WINLOGON,
        value_name: "CachedLogonsCount",
        kind: ValueKind::AtMost(4),
    },
    SecOptionDef {
        id: "WIN-SEC-022",
        title: "Restrict null session access",
        description: "Anonymous sessions cannot enumerate shares, users, or policies.",
        rationale: "Null sessions leak the enumeration data that recon tooling feeds on.",
        remediation: "Set LanmanServer\\Parameters!RestrictNullSessAccess to 1.",
        severity: crate::model::Severity::High,
        benchmarks: &["CIS 2.3.10.1"],
        path: LANMAN_SERVER,
        value_name: "RestrictNullSessAccess",
        kind: ValueKind::Equals(1),
    },
];

pub fn register(reg: &mut Vec<RegisteredCheck>) {
    use crate::check;
    check!(
        reg,
        "WIN-SEC-001",
        "LM compatibility level >= 5",
        "Only NTLMv2 session security permitted; LM and NTLMv1 refused.",
        "LM and NTLMv1 hashes are trivially crackable and enable pass-the-hash replay.",
        "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa!LmCompatibilityLevel to 5.",
        High,
        "Security Options",
        &["CIS 2.3.11.4"],
        win_applies,
        |ctx| sec_option_check_run(ctx, 0)
    );
    check!(
        reg,
        "WIN-SEC-002",
        "Do not store LM hash (NoLMHash)",
        "New passwords must not be stored as reversible LM hashes.",
        "Stored LM hashes expose every password to offline cracking within seconds.",
        "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa!NoLMHash to 1.",
        High,
        "Security Options",
        &["CIS 2.3.11.5"],
        win_applies,
        |ctx| sec_option_check_run(ctx, 1)
    );
    check!(
        reg,
        "WIN-SEC-003",
        "SMB server requires signing",
        "SMB server negotiates packet signing to block tampering and relay attacks.",
        "Unsigned SMB traffic allows man-in-the-middle session hijacking.",
        "Set LanmanServer\\Parameters!RequireSecuritySignature to 1.",
        High,
        "Security Options",
        &["CIS 2.3.11.8"],
        win_applies,
        |ctx| sec_option_check_run(ctx, 2)
    );
    check!(
        reg,
        "WIN-SEC-004",
        "SMB client requires signing",
        "SMB client refuses unsigned server sessions.",
        "Clients that accept unsigned sessions are silently downgraded to insecure SMB.",
        "Set LanmanWorkstation\\Parameters!RequireSecuritySignature to 1.",
        High,
        "Security Options",
        &["CIS 2.3.11.9"],
        win_applies,
        |ctx| sec_option_check_run(ctx, 3)
    );
    check!(
        reg,
        "WIN-SEC-005",
        "UAC runs in Admin Approval Mode (EnableLUA)",
        "All administrators run with split-token until elevation is approved.",
        "Without UAC every process in an admin session runs with full privileges.",
        "Set Policies\\System!EnableLUA to 1.",
        Critical,
        "Security Options",
        &["CIS 2.3.17.1"],
        win_applies,
        |ctx| sec_option_check_run(ctx, 4)
    );
    check!(
        reg,
        "WIN-SEC-006",
        "UAC admin consent prompt behavior >= 2",
        "Elevation requests require explicit consent or credentials.",
        "Silent elevation lets malware operate with admin rights undetected.",
        "Set Policies\\System!ConsentPromptBehaviorAdmin to 2 (or higher).",
        High,
        "Security Options",
        &["CIS 2.3.17.2"],
        win_applies,
        |ctx| sec_option_check_run(ctx, 5)
    );
    check!(
        reg,
        "WIN-SEC-007",
        "UAC installer detection enabled",
        "Legacy installer heuristics trigger elevation prompts.",
        "Undetected legacy installers run without user awareness of elevation.",
        "Set Policies\\System!EnableInstallerDetection to 1.",
        Low,
        "Security Options",
        &["CIS 2.3.17.3"],
        win_applies,
        |ctx| sec_option_check_run(ctx, 6)
    );
    check!(
        reg,
        "WIN-SEC-008",
        "UAC only elevates signed/validated executables",
        "Elevation requests validate the executable before showing a prompt.",
        "Unsigned elevation paths are abused by malicious binaries.",
        "Set Policies\\System!EnableSecureUIPaths to 1.",
        Medium,
        "Security Options",
        &["CIS 2.3.17.5"],
        win_applies,
        |ctx| sec_option_check_run(ctx, 7)
    );
    check!(
        reg,
        "WIN-SEC-009",
        "UAC file/registry virtualization enabled",
        "Legacy writes to protected locations are virtualized per-user.",
        "Virtualization contains legacy-app writes that would otherwise fail open.",
        "Set Policies\\System!EnableVirtualization to 1.",
        Low,
        "Security Options",
        &["CIS 2.3.17.7"],
        win_applies,
        |ctx| sec_option_check_run(ctx, 8)
    );
    check!(
        reg,
        "WIN-SEC-010",
        "Clear virtual memory pagefile at shutdown",
        "Pagefile is wiped at shutdown so spilled secrets are not left on disk.",
        "Pagefiles accumulate credentials and keys readable via offline disk access.",
        "Set Memory Management!ClearPageFileAtShutdown to 1.",
        Low,
        "Security Options",
        &["CIS 2.3.6.1"],
        win_applies,
        |ctx| sec_option_check_run(ctx, 9)
    );
    check!(
        reg,
        "WIN-SEC-011",
        "No Microsoft accounts for Store apps (NoConnectedUser = 3)",
        "Windows Store apps cannot authenticate with Microsoft accounts.",
        "Consumer accounts bypass corporate identity controls and leak data to cloud services.",
        "Set Policies\\System!NoConnectedUser to 3.",
        Medium,
        "Security Options",
        &["CIS 18.9.4.1"],
        win_applies,
        |ctx| sec_option_check_run(ctx, 10)
    );
    check!(
        reg,
        "WIN-SEC-012",
        "Inactivity timeout <= 900 seconds",
        "Idle sessions lock within 15 minutes.",
        "Unattended unlocked sessions invite tampering and data theft.",
        "Set Policies\\System!InactivityTimeoutSecs to 900 or less.",
        Medium,
        "Security Options",
        &["CIS 2.3.17.8"],
        win_applies,
        |ctx| sec_option_check_run(ctx, 11)
    );
    check!(
        reg,
        "WIN-SEC-013",
        "Password-protected screen saver",
        "Screen saver lock requires password to resume.",
        "A screen saver without password protection is a decorative lock.",
        "Set Control Panel\\Desktop!ScreenSaverIsSecure to 1.",
        Medium,
        "Security Options",
        &["CIS 18.9.30.2"],
        win_applies,
        |ctx| sec_option_check_run(ctx, 12)
    );
    check!(
        reg,
        "WIN-SEC-014",
        "Screen saver timeout <= 900 seconds",
        "Screen saver engages within 15 minutes of inactivity.",
        "Long idle windows extend exposure of unlocked sessions.",
        "Set Control Panel\\Desktop!ScreenSaveTimeOut to 900 or less.",
        Medium,
        "Security Options",
        &["CIS 18.9.30.3"],
        win_applies,
        |ctx| sec_option_check_run(ctx, 13)
    );
    check!(
        reg,
        "WIN-SEC-015",
        "Require domain controller to unlock (ForceUnlockLogon)",
        "Cached credentials cannot unlock the machine offline.",
        "Offline unlock with stolen cached hashes defeats account lockout.",
        "Set Winlogon!ForceUnlockLogon to 1.",
        Low,
        "Security Options",
        &["CIS 2.3.7.3"],
        win_applies,
        |ctx| sec_option_check_run(ctx, 14)
    );
    check!(
        reg,
        "WIN-SEC-016",
        "Do not display last user name",
        "Logon screen does not reveal the previous account.",
        "Displayed usernames halve the work of credential attacks.",
        "Set Policies\\System!dontdisplaylastusername to 1.",
        Low,
        "Security Options",
        &["CIS 2.3.7.1"],
        win_applies,
        |ctx| sec_option_check_run(ctx, 15)
    );
    check!(
        reg,
        "WIN-SEC-017",
        "Interactive logon legal notice caption configured",
        "A legal notice caption is presented before logon.",
        "Notice supports prosecution and sets expectation of monitoring.",
        "Set Policies\\System!LegalNoticeCaption to organizational text.",
        Low,
        "Security Options",
        &["CIS 2.3.7.5"],
        win_applies,
        |ctx| sec_option_check_run(ctx, 16)
    );
    check!(
        reg,
        "WIN-SEC-018",
        "Interactive logon legal notice text configured",
        "A legal notice body is presented before logon.",
        "Notice supports prosecution and sets expectation of monitoring.",
        "Set Policies\\System!LegalNoticeText to organizational text.",
        Low,
        "Security Options",
        &["CIS 2.3.7.6"],
        win_applies,
        |ctx| sec_option_check_run(ctx, 17)
    );
    check!(
        reg,
        "WIN-SEC-019",
        "SMBv1 protocol disabled",
        "Legacy SMBv1 protocol stack is turned off.",
        "SMBv1 carries EternalBlue/WannaCry-class worms and lacks integrity controls.",
        "Set LanmanServer\\Parameters!SMB1 to 0 and remove the SMB1Optional feature.",
        Critical,
        "Security Options",
        &["CIS 18.3.2"],
        win_applies,
        |ctx| sec_option_check_run(ctx, 18)
    );
    check!(
        reg,
        "WIN-SEC-020",
        "Auto restart shell cleared (AutoRestartShell = 0)",
        "Explorer is not silently respawned by Winlogon.",
        "Attackers abuse shell respawn to relaunch injected shellcode after crashes.",
        "Set Winlogon!AutoRestartShell to 0 per hardening baseline.",
        Low,
        "Security Options",
        &[],
        win_applies,
        |ctx| sec_option_check_run(ctx, 19)
    );
    check!(
        reg,
        "WIN-SEC-021",
        "Cached logons count <= 4",
        "At most four domain credentials are cached locally.",
        "Large caches give offline attackers many targets for hash extraction.",
        "Set Winlogon!CachedLogonsCount to 4 or less.",
        Medium,
        "Security Options",
        &["CIS 2.3.7.2"],
        win_applies,
        |ctx| sec_option_check_run(ctx, 20)
    );
    check!(
        reg,
        "WIN-SEC-022",
        "Restrict null session access",
        "Anonymous sessions cannot enumerate shares, users, or policies.",
        "Null sessions leak the enumeration data that recon tooling feeds on.",
        "Set LanmanServer\\Parameters!RestrictNullSessAccess to 1.",
        High,
        "Security Options",
        &["CIS 2.3.10.1"],
        win_applies,
        |ctx| sec_option_check_run(ctx, 21)
    );
}

fn win_applies(p: &crate::platform::PlatformInfo) -> bool {
    p.os == Os::Windows
}

fn sec_option_check_run(ctx: &mut ScanContext, idx: usize) -> CheckOutcome {
    evaluate(ctx, &SEC_OPTIONS[idx])
}

#[allow(dead_code)]
fn sec_option_check(idx: usize) -> impl Fn(&mut ScanContext) -> CheckOutcome {
    move |ctx| evaluate(ctx, &SEC_OPTIONS[idx])
}

fn evaluate(ctx: &mut ScanContext, d: &'static SecOptionDef) -> CheckOutcome {
    let query: QueryResult<String> = match d.kind {
        ValueKind::NonEmpty => reg_query_sz_with_log(ctx, d.path, d.value_name),
        _ => stringified_dword(ctx, d.path, d.value_name),
    };

    let attempts = query.attempts;
    let Some(raw) = query.value else {
        // A NonEmpty option read as absent can mean the value does not
        // exist: that is a hardening failure, not missing evidence. But
        // when every read-only source was unavailable, no evidence was
        // gathered at all — that is DegradedPartial, never Error.
        if matches!(d.kind, ValueKind::NonEmpty) {
            let observed_absent = attempts.iter().any(|a| {
                a.outcome.contains("missing") && !a.outcome.contains("unavailable")
            });
            if observed_absent {
                let mut outcome = nok(
                    format!("{} not configured (expected organizational text)", d.value_name),
                    format!(r"{}\{}", d.path, d.value_name),
                    format!("reg query {} /v {}", d.path, d.value_name),
                );
                outcome.fallback_log = attempts;
                return outcome;
            }
        }
        let mut outcome = degraded(&format!(
            "{} unavailable through read-only registry queries",
            d.value_name
        ));
        outcome.fallback_log = attempts;
        return outcome;
    };

    let passed = match d.kind {
        ValueKind::Equals(expected) => parse_number(&raw) == Some(expected),
        ValueKind::AtLeast(expected) => parse_number(&raw).is_some_and(|v| v >= expected),
        ValueKind::AtMost(expected) => parse_number(&raw).is_some_and(|v| v <= expected && v > 0),
        ValueKind::Disabled => parse_number(&raw) == Some(0),
        ValueKind::NonEmpty => !raw.trim().is_empty(),
    };

    let shown = if raw.chars().count() > 60 {
        let truncated: String = raw.chars().take(57).collect();
        format!("{truncated}...")
    } else {
        raw.clone()
    };

    let mut outcome = if passed {
        ok(
            format!("{} = {} (pass)", d.value_name, shown),
            format!(r"{}\{}", d.path, d.value_name),
            format!("reg query {} /v {}", d.path, d.value_name),
        )
    } else {
        nok(
            format!("{} = {} (fail)", d.value_name, shown),
            format!(r"{}\{}", d.path, d.value_name),
            format!("reg query {} /v {}", d.path, d.value_name),
        )
    };
    outcome.fallback_log = attempts;
    outcome
}

/// DWORD values arrive as `0x5`/`5` text; SZ values arrive bare.
fn stringified_dword(ctx: &mut ScanContext, path: &str, name: &str) -> QueryResult<String> {
    reg_query_sz_with_log(ctx, path, name)
}

fn parse_number(raw: &str) -> Option<u32> {
    let t = raw.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        t.parse::<u32>().ok()
    }
}

#[allow(dead_code)]
fn with_attempts(mut outcome: CheckOutcome, attempts: Vec<FallbackAttempt>) -> CheckOutcome {
    outcome.fallback_log = attempts;
    outcome
}
