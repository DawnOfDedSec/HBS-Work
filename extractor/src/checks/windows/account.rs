//! WIN-ACC: Windows account-policy checks using read-only evidence.

use super::{reg_query_dword_with_log, QueryResult};
use crate::checks::{degraded, nok, ok};
use crate::context::ScanContext;
use crate::model::{CheckOutcome, FallbackAttempt, RegisteredCheck};
use crate::platform::Os;

pub const TIMEQ_FOREVER: u32 = u32::MAX;
const LSA_PATH: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa";
/// Local security policy values that hold the account-policy booleans the
/// RSOP view exposes as `PasswordComplexity`/`ClearTextPassword`.
const CONTROL_LSA: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa";
const LANMAN_PARAMS_PATH: &str = r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters";
const SECONDS_PER_DAY: u32 = 86_400;
const SECONDS_PER_MINUTE: u32 = 60;

#[derive(Clone, Debug)]
pub struct AccountPolicy {
    pub minimum_password_length: u32,
    pub maximum_password_age_days: u32,
    pub minimum_password_age_days: u32,
    pub password_history_size: u32,
    pub lockout_bad_count: u32,
    pub lockout_duration_minutes: u32,
    pub reset_lockout_count_minutes: u32,
}

/// Guard SID for the built-in `Power Users` group: membership is a local
/// privilege-escalation tell left behind by GPP/legacy delegation abuse.
pub const POWER_USERS_SID: &str = "S-1-5-32-547";
/// The built-in Administrators group.
pub const ADMINISTRATORS_GROUP: &str = "Administrators";

/// Enumerate local Administrators members. Ordered chain:
/// `net localgroup` -> PowerShell `Get-LocalGroupMember` -> native
/// `NetLocalGroupGetMembers`. All sources are read-only; the native
/// call is the one that survives a PowerShell-less image.
#[cfg(windows)]
fn local_administrators_native() -> Option<Vec<String>> {
    use crate::checks::windows::native_accounts::native_local_group_members;
    // The English well-known group name is resolved by the OS; on a
    // non-English build this returns None and the caller degrades with
    // the recorded attempts rather than guessing a name.
    native_local_group_members(ADMINISTRATORS_GROUP)
}

#[cfg(not(windows))]
fn local_administrators_native() -> Option<Vec<String>> {
    None
}

/// Resolve a well-known SID string to its local account name.
#[cfg(windows)]
fn account_name_from_sid_string(sid_string: &str) -> Option<String> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidA;
    use windows_sys::Win32::Security::LookupAccountSidA;
    let c = std::ffi::CString::new(sid_string).ok()?;
    let mut sid = null_mut();
    // SAFETY: `c` is a NUL-terminated SID string; `sid` is an out-pointer
    // allocated by the API and freed with LocalFree below.
    if unsafe { ConvertStringSidToSidA(c.as_ptr() as *const u8, &mut sid) } == 0 || sid.is_null() {
        return None;
    }
    struct SidGuard(*mut core::ffi::c_void);
    impl Drop for SidGuard {
        fn drop(&mut self) {
            // SAFETY: allocated by ConvertStringSidToSidA, freed once.
            unsafe { windows_sys::Win32::Foundation::LocalFree(self.0) };
        }
    }
    let _guard = SidGuard(sid as *mut core::ffi::c_void);

    let mut name_size = 0u32;
    let mut domain_size = 0u32;
    let mut use_type: i32 = 0;
    // SAFETY: size-query form with null buffers.
    unsafe {
        LookupAccountSidA(
            std::ptr::null(),
            sid,
            null_mut(),
            &mut name_size,
            null_mut(),
            &mut domain_size,
            &mut use_type,
        )
    };
    let mut name_buf = vec![0u8; name_size.max(1) as usize];
    let mut domain_buf = vec![0u8; domain_size.max(1) as usize];
    let mut name_len = name_size;
    let mut domain_len = domain_size;
    // SAFETY: buffers sized by the preceding query.
    let ok = unsafe {
        LookupAccountSidA(
            std::ptr::null(),
            sid,
            name_buf.as_mut_ptr(),
            &mut name_len,
            domain_buf.as_mut_ptr(),
            &mut domain_len,
            &mut use_type,
        )
    };
    if ok == 0 {
        return None;
    }
    let nul = name_buf.iter().position(|b| *b == 0).unwrap_or(name_buf.len());
    Some(String::from_utf8_lossy(&name_buf[..nul]).into_owned())
}

#[cfg(not(windows))]
fn account_name_from_sid_string(_sid_string: &str) -> Option<String> {
    None
}

fn local_administrators_group(ctx: &mut ScanContext) -> CheckOutcome {
    let mut attempts = Vec::new();

    if let Some(raw) = ctx.cmd("net", &["localgroup", ADMINISTRATORS_GROUP]) {
        if raw.contains("---") {
            let members = super::threat_persist::parse_localgroup_members(&raw);
            attempts.push(FallbackAttempt {
                source: format!("net localgroup {ADMINISTRATORS_GROUP}"),
                outcome: format!("{} members", members.len()),
            });
            return with_attempts(admin_group_outcome(members, "net localgroup Administrators".into()), attempts);
        }
        attempts.push(FallbackAttempt {
            source: format!("net localgroup {ADMINISTRATORS_GROUP}"),
            outcome: "unparseable/localized output".into(),
        });
    } else {
        attempts.push(FallbackAttempt {
            source: format!("net localgroup {ADMINISTRATORS_GROUP}"),
            outcome: "unavailable or blocked".into(),
        });
    }

    let script = "Get-LocalGroupMember -Group 'Administrators' | Select-Object -ExpandProperty Name";
    if let Some(raw) =
        ctx.cmd("powershell", &["-NoProfile", "-NonInteractive", "-Command", script])
    {
        let members: Vec<String> = raw
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect();
        attempts.push(FallbackAttempt {
            source: "PowerShell Get-LocalGroupMember".into(),
            outcome: format!("{} members", members.len()),
        });
        return with_attempts(admin_group_outcome(members, script.into()), attempts);
    }
    attempts.push(FallbackAttempt {
        source: "PowerShell Get-LocalGroupMember".into(),
        outcome: "unavailable or blocked".into(),
    });

    if ctx.native_fallbacks_enabled() {
        if let Some(members) = local_administrators_native() {
            attempts.push(FallbackAttempt {
                source: "native NetLocalGroupGetMembers".into(),
                outcome: format!("{} members", members.len()),
            });
            return with_attempts(
                admin_group_outcome(members, "NetLocalGroupGetMembers(Administrators)".into()),
                attempts,
            );
        }
        attempts.push(FallbackAttempt {
            source: "native NetLocalGroupGetMembers".into(),
            outcome: "unreadable".into(),
        });
    } else {
        attempts.push(FallbackAttempt {
            source: "native NetLocalGroupGetMembers".into(),
            outcome: "skipped (injected context)".into(),
        });
    }

    degraded_with_attempts("local Administrators group unreadable", attempts)
}

fn admin_group_outcome(members: Vec<String>, repro: String) -> CheckOutcome {
    let listing = if members.is_empty() {
        "(none)".to_string()
    } else {
        members.join(", ")
    };
    if members.len() <= 1 {
        ok(
            format!("local Administrators count = {}: {listing}", members.len()),
            "group:Administrators".into(),
            repro,
        )
    } else {
        nok(
            format!("local Administrators count = {} (>1): {listing}", members.len()),
            "group:Administrators".into(),
            repro,
        )
    }
}

fn local_power_users_group(ctx: &mut ScanContext) -> CheckOutcome {
    let mut attempts = Vec::new();
    let group_name = account_name_from_sid_string(POWER_USERS_SID).unwrap_or_else(|| "Power Users".into());

    if let Some(raw) = ctx.cmd("net", &["localgroup", &group_name]) {
        if raw.contains("---") {
            let members = super::threat_persist::parse_localgroup_members(&raw);
            attempts.push(FallbackAttempt {
                source: format!("net localgroup {group_name}"),
                outcome: format!("{} members", members.len()),
            });
            return with_attempts(power_users_outcome(members, format!("net localgroup {group_name}")), attempts);
        }
        attempts.push(FallbackAttempt {
            source: format!("net localgroup {group_name}"),
            outcome: "unparseable/localized output".into(),
        });
    } else {
        attempts.push(FallbackAttempt {
            source: format!("net localgroup {group_name}"),
            outcome: "unavailable or blocked".into(),
        });
    }

    let script = format!(
        "Get-LocalGroupMember -Group '{group_name}' | Select-Object -ExpandProperty Name"
    );
    if let Some(raw) = ctx.cmd(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", &script],
    ) {
        let members: Vec<String> = raw
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect();
        attempts.push(FallbackAttempt {
            source: "PowerShell Get-LocalGroupMember".into(),
            outcome: format!("{} members", members.len()),
        });
        return with_attempts(power_users_outcome(members, script), attempts);
    }
    attempts.push(FallbackAttempt {
        source: "PowerShell Get-LocalGroupMember".into(),
        outcome: "unavailable or blocked".into(),
    });

    if ctx.native_fallbacks_enabled() {
        if let Some(members) =
            crate::checks::windows::native_accounts::native_local_group_members(&group_name)
        {
            attempts.push(FallbackAttempt {
                source: "native NetLocalGroupGetMembers".into(),
                outcome: format!("{} members", members.len()),
            });
            return with_attempts(
                power_users_outcome(members, format!("NetLocalGroupGetMembers({group_name})")),
                attempts,
            );
        }
        attempts.push(FallbackAttempt {
            source: "native NetLocalGroupGetMembers".into(),
            outcome: "unreadable".into(),
        });
    } else {
        attempts.push(FallbackAttempt {
            source: "native NetLocalGroupGetMembers".into(),
            outcome: "skipped (injected context)".into(),
        });
    }

    degraded_with_attempts("local Power Users group unreadable", attempts)
}

fn power_users_outcome(members: Vec<String>, repro: String) -> CheckOutcome {
    let listing = if members.is_empty() {
        "(none)".to_string()
    } else {
        members.join(", ")
    };
    if members.is_empty() {
        ok(
            "no members in Power Users".into(),
            "group:Power Users".into(),
            repro,
        )
    } else {
        nok(
            format!("Power Users members (legacy privilege group): {listing}"),
            "group:Power Users".into(),
            repro,
        )
    }
}

#[derive(Clone, Copy)]
pub enum AccountField {
    MinimumPasswordLength,
    MaximumPasswordAge,
    MinimumPasswordAge,
    PasswordHistorySize,
    LockoutBadCount,
    LockoutDuration,
    ResetLockoutCount,
}

impl AccountField {
    pub fn modals_level(self) -> u32 {
        match self {
            AccountField::MinimumPasswordLength
            | AccountField::MaximumPasswordAge
            | AccountField::MinimumPasswordAge
            | AccountField::PasswordHistorySize => 0,
            AccountField::LockoutBadCount
            | AccountField::LockoutDuration
            | AccountField::ResetLockoutCount => 3,
        }
    }
}

pub fn convert_max_password_age_seconds(seconds: u32) -> u32 {
    if seconds == TIMEQ_FOREVER {
        0 // Never expires -> non-compliant
    } else {
        seconds / SECONDS_PER_DAY
    }
}

pub fn convert_min_password_age_seconds(seconds: u32) -> u32 {
    seconds / SECONDS_PER_DAY
}

pub fn convert_lockout_duration_seconds(seconds: u32) -> u32 {
    if seconds == TIMEQ_FOREVER {
        TIMEQ_FOREVER // Administrator unlock required -> compliant (pass)
    } else {
        seconds / SECONDS_PER_MINUTE
    }
}

pub fn convert_observation_window_seconds(seconds: u32) -> u32 {
    if seconds == TIMEQ_FOREVER {
        TIMEQ_FOREVER
    } else {
        seconds / SECONDS_PER_MINUTE
    }
}

pub fn register(reg: &mut Vec<RegisteredCheck>) {
    use crate::check;
    check!(
        reg,
        "WIN-ACC-001",
        "Minimum password length >= 14",
        "Passwords must resist guessing attacks.",
        "Short passwords are easier to crack.",
        "Set Minimum password length to 14 or more.",
        Medium,
        "Account Policy",
        &["CIS 1.1.4"],
        win,
        |ctx| account_check(ctx, AccountField::MinimumPasswordLength)
    );
    check!(
        reg,
        "WIN-ACC-002",
        "Maximum password age <= 365",
        "Passwords must expire within 365 days.",
        "Indefinitely valid passwords outlive credential exposure.",
        "Set Maximum password age between 1 and 365 days.",
        Medium,
        "Account Policy",
        &["CIS 1.1.2"],
        win,
        |ctx| account_check(ctx, AccountField::MaximumPasswordAge)
    );
    check!(
        reg,
        "WIN-ACC-003",
        "Minimum password age >= 1",
        "Password changes must be separated by at least one day.",
        "A zero minimum lets users cycle back to an old password immediately.",
        "Set Minimum password age to at least 1 day.",
        Low,
        "Account Policy",
        &["CIS 1.1.3"],
        win,
        |ctx| account_check(ctx, AccountField::MinimumPasswordAge)
    );
    check!(
        reg,
        "WIN-ACC-004",
        "Password history size >= 24",
        "Remember at least 24 previous passwords.",
        "Shallow history permits password reuse.",
        "Set Enforce password history to 24 or more.",
        Medium,
        "Account Policy",
        &["CIS 1.1.1"],
        win,
        |ctx| account_check(ctx, AccountField::PasswordHistorySize)
    );
    check!(
        reg,
        "WIN-ACC-005",
        "Account lockout threshold <= 50 and != 0",
        "Failed logons must trigger lockout.",
        "Unlimited or high retry counts permit sustained guessing.",
        "Set Account lockout threshold to 5 attempts (must be 1 through 50).",
        Medium,
        "Account Policy",
        &["CIS 1.2.1"],
        win,
        |ctx| account_check(ctx, AccountField::LockoutBadCount)
    );
    check!(
        reg,
        "WIN-ACC-006",
        "Account lockout duration >= 15",
        "Locked accounts must remain locked for at least 15 minutes.",
        "Short lockouts permit repeated guessing campaigns.",
        "Set Account lockout duration to at least 15 minutes.",
        Medium,
        "Account Policy",
        &["CIS 1.2.2"],
        win,
        |ctx| account_check(ctx, AccountField::LockoutDuration)
    );
    check!(
        reg,
        "WIN-ACC-007",
        "Reset account lockout counter >= 15",
        "Failed-attempt counters must persist at least 15 minutes.",
        "Rapid counter reset weakens brute-force protection.",
        "Set Reset account lockout counter after to at least 15 minutes.",
        Medium,
        "Account Policy",
        &["CIS 1.2.3"],
        win,
        |ctx| account_check(ctx, AccountField::ResetLockoutCount)
    );
    check!(
        reg,
        "WIN-ACC-008",
        "Blank-password remote use restricted",
        "Accounts with blank passwords must be limited to console logon.",
        "Remote use of blank passwords enables trivial compromise.",
        "Set LimitBlankPasswordUse to 1.",
        Medium,
        "Account Policy",
        &["CIS 2.3.1.4"],
        win,
        |ctx| registry_path_equals_one(ctx, LSA_PATH, "LimitBlankPasswordUse")
    );
    check!(
        reg,
        "WIN-ACC-009",
        "Password complexity enabled",
        "Password complexity policy must be enabled.",
        "Single-class passwords are easier to guess.",
        "Enable Password must meet complexity requirements.",
        Medium,
        "Account Policy",
        &["CIS 1.1.5"],
        win,
        password_complexity
    );
    check!(
        reg,
        "WIN-ACC-010",
        "Reversible password encryption disabled",
        "Passwords must not be stored with reversible encryption.",
        "Reversible password storage exposes recoverable credentials.",
        "Disable Store passwords using reversible encryption.",
        High,
        "Account Policy",
        &["CIS 1.1.6"],
        win,
        reversible_encryption
    );
    check!(
        reg,
        "WIN-ACC-011",
        "Restrict anonymous access to named pipes and shares",
        "Anonymous users must not access named pipes and shares.",
        "Anonymous share access exposes sensitive network assets.",
        "Set RestrictAnonymous to 1.",
        Medium,
        "Account Policy",
        &["CIS 2.3.10.2"],
        win,
        |ctx| registry_path_equals_one(ctx, LANMAN_PARAMS_PATH, "RestrictAnonymous")
    );
    check!(
        reg,
        "WIN-ACC-012",
        "Restrict anonymous SAM and shares enumeration",
        "Anonymous users must not enumerate SAM accounts and shares.",
        "SAM enumeration exposes account names for attacks.",
        "Set RestrictAnonymousSAM to 1.",
        Medium,
        "Account Policy",
        &["CIS 2.3.10.1"],
        win,
        |ctx| registry_path_equals_one(ctx, LSA_PATH, "RestrictAnonymousSAM")
    );
    check!(
        reg,
        "WIN-ACC-013",
        "Local Administrators membership minimized",
        "Local Administrators group has at most one member.",
        "Every extra local administrator is another credential and persistence path.",
        "Remove unnecessary direct/group memberships from local Administrators.",
        Medium,
        "Account Policy",
        &["CIS 5.1", "CIS 5.4"],
        win,
        local_administrators_group
    );
    check!(
        reg,
        "WIN-ACC-014",
        "Legacy Power Users group empty",
        "The legacy Power Users group has no members.",
        "Power Users retain dangerous legacy rights and are a classic escalation persistence spot.",
        "Remove every member from the built-in Power Users group.",
        Medium,
        "Account Policy",
        &["CIS 5.7", "Microsoft Security Baseline"],
        win,
        local_power_users_group
    );
}

fn win(platform: &crate::platform::PlatformInfo) -> bool {
    platform.os == Os::Windows
}

fn account_check(ctx: &mut ScanContext, field: AccountField) -> CheckOutcome {
    let query = account_policy_field(ctx, field);
    let Some(policy) = query.value else {
        return degraded_with_attempts(
            "account policy unavailable through read-only sources; localized net accounts output may require Windows API access",
            query.attempts,
        );
    };
    let (_name, is_pass, evidence) = match field {
        AccountField::MinimumPasswordLength => {
            let good = policy.minimum_password_length >= 14;
            let val = policy.minimum_password_length;
            (
                "Minimum password length",
                good,
                format!("Minimum password length = {val} (expected >= 14)"),
            )
        }
        AccountField::MaximumPasswordAge => {
            let good =
                policy.maximum_password_age_days > 0 && policy.maximum_password_age_days <= 365;
            let val = policy.maximum_password_age_days;
            (
                "Maximum password age (days)",
                good,
                format!("Maximum password age (days) = {val} (expected 1..=365; 0/Never means passwords do not expire while passwords are required)"),
            )
        }
        AccountField::MinimumPasswordAge => {
            let good = policy.minimum_password_age_days >= 1;
            let val = policy.minimum_password_age_days;
            (
                "Minimum password age (days)",
                good,
                format!("Minimum password age (days) = {val} (expected >= 1)"),
            )
        }
        AccountField::PasswordHistorySize => {
            let good = policy.password_history_size >= 24;
            let val = policy.password_history_size;
            (
                "Password history size",
                good,
                format!("Password history size = {val} (expected >= 24; None means 0)"),
            )
        }
        AccountField::LockoutBadCount => {
            let good = policy.lockout_bad_count != 0 && policy.lockout_bad_count <= 50;
            let val = policy.lockout_bad_count;
            (
                "Lockout bad count",
                good,
                format!("Lockout bad count = {val} (expected 1..=50; 5 recommended; Never means 0)"),
            )
        }
        AccountField::LockoutDuration => {
            let good = policy.lockout_duration_minutes >= 15
                || policy.lockout_duration_minutes == TIMEQ_FOREVER;
            let val_str = if policy.lockout_duration_minutes == TIMEQ_FOREVER {
                "TIMEQ_FOREVER".to_string()
            } else {
                policy.lockout_duration_minutes.to_string()
            };
            (
                "Lockout duration (minutes)",
                good,
                format!("Lockout duration (minutes) = {val_str} (expected >= 15 min; TIMEQ_FOREVER=pass)"),
            )
        }
        AccountField::ResetLockoutCount => {
            let good = policy.reset_lockout_count_minutes >= 15
                || policy.reset_lockout_count_minutes == TIMEQ_FOREVER;
            let val_str = if policy.reset_lockout_count_minutes == TIMEQ_FOREVER {
                "TIMEQ_FOREVER".to_string()
            } else {
                policy.reset_lockout_count_minutes.to_string()
            };
            (
                "Reset lockout count (minutes)",
                good,
                format!("Reset lockout count (minutes) = {val_str} (expected >= 15)"),
            )
        }
    };
    let mut outcome = if is_pass {
        ok(
            evidence,
            "Windows account policy".into(),
            "net accounts".into(),
        )
    } else {
        nok(
            evidence,
            "Windows account policy".into(),
            "net accounts".into(),
        )
    };
    outcome.fallback_log = query.attempts;
    outcome
}

fn account_policy_field(ctx: &mut ScanContext, field: AccountField) -> QueryResult<AccountPolicy> {
    account_policy_field_native(ctx, field, account_policy_registry)
}

fn account_policy_field_native(
    ctx: &mut ScanContext,
    field: AccountField,
    native_policy: fn(u32) -> Option<AccountPolicy>,
) -> QueryResult<AccountPolicy> {
    let mut attempts = Vec::new();
    let lvl = field.modals_level();
    let modals_source = format!("NetUserModalsGet level {lvl}");

    if !ctx.has_injector() {
        if let Some(policy) = native_policy(lvl) {
            attempts.push(FallbackAttempt {
                source: modals_source,
                outcome: format!("read level {lvl} account policy"),
            });
            return QueryResult {
                value: Some(policy),
                attempts,
            };
        }
    }
    attempts.push(FallbackAttempt {
        source: modals_source,
        outcome: if ctx.has_injector() {
            "skipped for injected portable evidence"
        } else if cfg!(windows) {
            "unavailable"
        } else {
            "not available on this build platform"
        }
        .into(),
    });

    match ctx.cmd("net", &["accounts"]) {
        Some(output) => match parse_net_accounts(&output) {
            Some(policy) => {
                attempts.push(FallbackAttempt {
                    source: "net accounts".into(),
                    outcome: "parsed English account policy".into(),
                });
                return QueryResult {
                    value: Some(policy),
                    attempts,
                };
            }
            None => attempts.push(FallbackAttempt {
                source: "net accounts".into(),
                outcome: "output missing required English fields or localized".into(),
            }),
        },
        None => attempts.push(FallbackAttempt {
            source: "net accounts".into(),
            outcome: "unavailable".into(),
        }),
    }

    // Last read-only source: the local security policy values under
    // HKLM\SYSTEM\CurrentControlSet\Control\Lsa, read through the shared
    // reg -> PowerShell -> native chain. Only fields that actually exist
    // as local LSA values are populated; the rest stay absent so the
    // caller degrades rather than inventing a partial policy.
    if !ctx.has_injector() {
        if let Some(policy) = lsa_account_policy(field) {
            attempts.push(FallbackAttempt {
                source: "local LSA account-policy values".into(),
                outcome: "read the local policy field".into(),
            });
            return QueryResult {
                value: Some(policy),
                attempts,
            };
        }
    }
    attempts.push(FallbackAttempt {
        source: "local LSA account-policy values".into(),
        outcome: "no complete read-only value for this field".into(),
    });
    QueryResult {
        value: None,
        attempts,
    }
}

/// Read one account-policy field from the local LSA registry values via
/// the shared reg -> PowerShell -> native helper chain.
#[cfg(windows)]
fn lsa_account_policy(field: AccountField) -> Option<AccountPolicy> {
    let mut policy = empty_policy();
    match field {
        AccountField::LockoutBadCount => {
            policy.lockout_bad_count = read_lsa_dword("LockoutBadCount")?;
        }
        AccountField::LockoutDuration => {
            let seconds = read_lsa_dword("LockoutDuration")?;
            policy.lockout_duration_minutes = convert_lockout_duration_seconds(seconds);
        }
        AccountField::ResetLockoutCount => {
            let seconds = read_lsa_dword("ResetLockoutCount")?;
            policy.reset_lockout_count_minutes = convert_observation_window_seconds(seconds);
        }
        AccountField::MinimumPasswordLength => {
            policy.minimum_password_length = read_lsa_dword("MinimumPasswordLength")?;
        }
        AccountField::MaximumPasswordAge => {
            let seconds = read_lsa_dword("MaximumPasswordAge")?;
            policy.maximum_password_age_days = convert_max_password_age_seconds(seconds);
        }
        AccountField::MinimumPasswordAge => {
            let seconds = read_lsa_dword("MinimumPasswordAge")?;
            policy.minimum_password_age_days = convert_min_password_age_seconds(seconds);
        }
        AccountField::PasswordHistorySize => {
            policy.password_history_size = read_lsa_dword("PasswordHistorySize")?;
        }
    }
    Some(policy)
}

#[cfg(not(windows))]
fn lsa_account_policy(_field: AccountField) -> Option<AccountPolicy> {
    None
}

fn empty_policy() -> AccountPolicy {
    AccountPolicy {
        minimum_password_length: 0,
        maximum_password_age_days: 0,
        minimum_password_age_days: 0,
        password_history_size: 0,
        lockout_bad_count: 0,
        lockout_duration_minutes: 0,
        reset_lockout_count_minutes: 0,
    }
}

/// Read a local LSA account-policy DWORD without going through a
/// `ScanContext` (the native LSA value lives under the machine hive).
#[cfg(windows)]
fn read_lsa_dword(name: &str) -> Option<u32> {
    use crate::checks::windows::native_reg::native_reg_dword;
    native_reg_dword(CONTROL_LSA, name)
}

/// Registry-backed account policy is not a documented source for every
/// field, so this variant always declines and lets the caller fall
/// through to `lsa_account_policy`.
fn account_policy_registry(_level: u32) -> Option<AccountPolicy> {
    None
}

pub fn parse_net_accounts(output: &str) -> Option<AccountPolicy> {
    let lockout_duration = parse_net_lockout_duration(output, "Lockout duration (minutes)")?;
    Some(AccountPolicy {
        minimum_password_length: parse_net_number(output, "Minimum password length")?,
        maximum_password_age_days: parse_net_number(output, "Maximum password age (days)")?,
        minimum_password_age_days: parse_net_number(output, "Minimum password age (days)")?,
        password_history_size: parse_net_number(output, "Length of password history maintained")?,
        lockout_bad_count: parse_net_number(output, "Lockout threshold")?,
        lockout_duration_minutes: lockout_duration,
        reset_lockout_count_minutes: parse_net_number(
            output,
            "Lockout observation window (minutes)",
        )?,
    })
}

fn parse_net_lockout_duration(output: &str, key: &str) -> Option<u32> {
    let value = output.lines().find_map(|line| {
        let (label, value) = line.split_once(':')?;
        label.trim().eq_ignore_ascii_case(key).then(|| value.trim())
    })?;
    if value.eq_ignore_ascii_case("forever") || value.eq_ignore_ascii_case("timeq_forever") {
        Some(TIMEQ_FOREVER)
    } else if value.eq_ignore_ascii_case("none")
        || value.eq_ignore_ascii_case("never")
        || value.eq_ignore_ascii_case("unlimited")
    {
        Some(0)
    } else {
        value.replace(',', "").parse().ok()
    }
}

fn parse_net_number(output: &str, key: &str) -> Option<u32> {
    let value = output.lines().find_map(|line| {
        let (label, value) = line.split_once(':')?;
        label.trim().eq_ignore_ascii_case(key).then(|| value.trim())
    })?;
    if value.eq_ignore_ascii_case("none")
        || value.eq_ignore_ascii_case("never")
        || value.eq_ignore_ascii_case("unlimited")
    {
        Some(0)
    } else {
        value.replace(',', "").parse().ok()
    }
}

fn registry_path_equals_one(ctx: &mut ScanContext, hive_path: &str, name: &str) -> CheckOutcome {
    let query = reg_query_dword_with_log(ctx, hive_path, name);
    let outcome = match query.value {
        Some(1) => ok(
            format!("{name} = 1"),
            format!(r"{hive_path}\{name}"),
            format!("reg query {hive_path} /v {name}"),
        ),
        Some(value) => nok(
            format!("{name} = {value} (expected 1)"),
            format!(r"{hive_path}\{name}"),
            format!("reg query {hive_path} /v {name}"),
        ),
        None => {
            return degraded_with_attempts(
                &format!("{name} unavailable through read-only registry queries"),
                query.attempts,
            )
        }
    };
    with_attempts(outcome, query.attempts)
}

fn password_complexity(ctx: &mut ScanContext) -> CheckOutcome {
    rsop_boolean(
        ctx,
        "PasswordComplexity",
        true,
        Some((CONTROL_LSA, "PasswordComplexity")),
    )
}

fn reversible_encryption(ctx: &mut ScanContext) -> CheckOutcome {
    rsop_boolean(
        ctx,
        "ClearTextPassword",
        false,
        Some((CONTROL_LSA, "ClearTextPassword")),
    )
}

/// RSOP policy view first (applies domain GPO + local policy), then the
/// local security policy registry value with the shared
/// `reg query` -> PowerShell -> native chain when RSOP is unavailable
/// (e.g. a Server Core image without the RSOP CIM provider). A local LSA
/// value is authoritative for the local-policy case; when only a domain
/// GPO sets it, the fallback degrades rather than guessing.
fn rsop_boolean(
    ctx: &mut ScanContext,
    key: &str,
    want: bool,
    reg_fallback: Option<(&str, &str)>,
) -> CheckOutcome {
    let script = format!(
        "(Get-CimInstance -Namespace 'root\\rsop\\computer' -ClassName RSOP_SecuritySettingBoolean -Filter \"KeyName='{key}'\" -ErrorAction SilentlyContinue | Sort-Object Precedence | Select-Object -First 1 -ExpandProperty Setting)"
    );
    let source = format!("RSOP {key}");
    let raw = ctx.cmd(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", &script],
    );
    let value = raw.as_deref().and_then(parse_bool_value);
    let attempts = vec![FallbackAttempt {
        source: source.clone(),
        outcome: match value {
            Some(value) => format!("read {}", u8::from(value)),
            None => "unavailable or missing".into(),
        },
    }];
    match value {
        Some(value) => {
            let evidence = format!("{key} = {} (expected {})", u8::from(value), u8::from(want));
            let outcome = if value == want {
                ok(evidence, "RSOP_SecuritySettingBoolean".into(), script)
            } else {
                nok(evidence, "RSOP_SecuritySettingBoolean".into(), script)
            };
            with_attempts(outcome, attempts)
        }
        None => match reg_fallback {
            Some((path, name)) => {
                let query = reg_query_dword_with_log(ctx, path, name);
                let mut attempts = attempts;
                attempts.extend(query.attempts);
                match query.value {
                    Some(value) => {
                        let passed = (value != 0) == want;
                        let evidence = format!(
                            "{key} = {value} via local security policy (expected {})",
                            if want { "enabled" } else { "disabled" }
                        );
                        let outcome = if passed {
                            ok(
                                evidence,
                                format!(r"registry:{path}\{name}"),
                                format!("reg query {path} /v {name}"),
                            )
                        } else {
                            nok(
                                evidence,
                                format!(r"registry:{path}\{name}"),
                                format!("reg query {path} /v {name}"),
                            )
                        };
                        with_attempts(outcome, attempts)
                    }
                    None => degraded_with_attempts(
                        &format!(
                            "{key} unavailable through read-only RSOP policy evidence or local LSA registry value"
                        ),
                        attempts,
                    ),
                }
            }
            None => degraded_with_attempts(
                &format!("{key} unavailable through read-only RSOP policy evidence"),
                attempts,
            ),
        },
    }
}

fn parse_bool_value(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" => Some(true),
        "0" | "false" => Some(false),
        _ => None,
    }
}

fn with_attempts(mut outcome: CheckOutcome, attempts: Vec<FallbackAttempt>) -> CheckOutcome {
    outcome.fallback_log = attempts;
    outcome
}

fn degraded_with_attempts(reason: &str, attempts: Vec<FallbackAttempt>) -> CheckOutcome {
    with_attempts(degraded(reason), attempts)
}

