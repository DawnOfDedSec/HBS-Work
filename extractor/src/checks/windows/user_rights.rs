//! WIN-UR: Windows user rights assignment checks.
//!
//! Rights come from read-only LSA policy APIs (`LsaOpenPolicy` +
//! `LsaEnumerateAccountsWithUserRight` + `LsaLookupSids`) on Windows.
//! Evaluation itself is portable: a SID-based requirement table decides
//! compliance regardless of localized account names. Missing privileges,
//! access denial, or unsupported platforms degrade, never error.
//! No `secedit /export` and no disk writes anywhere.

use crate::checks::{degraded, nok, ok};
use crate::context::ScanContext;
use crate::model::{CheckOutcome, FallbackAttempt, RegisteredCheck};
use crate::platform::Os;

pub const ADMINISTRATORS_SID: &str = "S-1-5-32-544";
pub const SYSTEM_SID: &str = "S-1-5-18";
pub const LOCAL_SERVICE_SID: &str = "S-1-5-19";
pub const NETWORK_SERVICE_SID: &str = "S-1-5-20";
pub const GUESTS_SID: &str = "S-1-5-32-546";
pub const EVERYONE_SID: &str = "S-1-1-0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SidAccount {
    pub sid: String,
    pub name: String,
}

/// Portability: `sid -> name`, keyed by well-known SID strings.
pub type UserRightMap = std::collections::BTreeMap<String, Vec<SidAccount>>;

#[derive(Clone, Copy, Debug)]
pub enum Requirement {
    /// Only these well-known SIDs may hold the right.
    Only(&'static [&'static str]),
    /// The right must not be assigned to anyone.
    Empty,
    /// None of the listed SIDs may hold the right (e.g. Guests/Everyone).
    Excludes(&'static [&'static str]),
    /// Each listed SID must hold the right.
    Includes(&'static [&'static str]),
}

#[derive(Clone, Copy, Debug)]
pub struct UserRightDef {
    pub id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub rationale: &'static str,
    pub remediation: &'static str,
    pub severity: crate::model::Severity,
    pub benchmarks: &'static [&'static str],
    pub right: &'static str,
    pub requirement: Requirement,
}

pub const USER_RIGHT_CHECKS: &[UserRightDef] = &[
    UserRightDef {
        id: "WIN-UR-001",
        title: "SeDebugProgramPrivilege restricted to Administrators",
        description: "Only Administrators may debug arbitrary processes.",
        rationale: "Debug privilege reads any process memory, including LSASS credentials.",
        remediation: "Assign SeDebugPrivilege to Administrators only.",
        severity: crate::model::Severity::Critical,
        benchmarks: &["CIS 2.2.1"],
        right: "SeDebugPrivilege",
        requirement: Requirement::Only(&[ADMINISTRATORS_SID]),
    },
    UserRightDef {
        id: "WIN-UR-002",
        title: "SeTcbPrivilege not assigned",
        description: "No account acts as part of the operating system.",
        rationale: "TCB privilege creates arbitrary tokens: full impersonation of any user.",
        remediation: "Remove every account from 'Act as part of the operating system'.",
        severity: crate::model::Severity::Critical,
        benchmarks: &["CIS 2.2.2"],
        right: "SeTcbPrivilege",
        requirement: Requirement::Empty,
    },
    UserRightDef {
        id: "WIN-UR-003",
        title: "SeAssignPrimaryTokenPrivilege restricted",
        description: "Only Administrators and SYSTEM may replace process tokens.",
        rationale: "Token replacement privilege enables privilege escalation via crafted tokens.",
        remediation: "Assign SeAssignPrimaryTokenPrivilege to Administrators and SYSTEM only.",
        severity: crate::model::Severity::High,
        benchmarks: &["CIS 2.2.3"],
        right: "SeAssignPrimaryTokenPrivilege",
        requirement: Requirement::Only(&[ADMINISTRATORS_SID, SYSTEM_SID]),
    },
    UserRightDef {
        id: "WIN-UR-004",
        title: "SeIncreaseQuotaPrivilege restricted",
        description: "Only Administrators and SYSTEM may adjust process memory quotas.",
        rationale: "Quota elevation supports memory-manipulation attacks.",
        remediation: "Assign SeIncreaseQuotaPrivilege to Administrators and SYSTEM only.",
        severity: crate::model::Severity::High,
        benchmarks: &["CIS 2.2.4"],
        right: "SeIncreaseQuotaPrivilege",
        requirement: Requirement::Only(&[ADMINISTRATORS_SID, SYSTEM_SID]),
    },
    UserRightDef {
        id: "WIN-UR-005",
        title: "SeRemoteShutdownPrivilege restricted to Administrators",
        description: "Only Administrators may shut down the machine remotely.",
        rationale: "Remote shutdown is a denial-of-service primitive against servers.",
        remediation: "Assign SeRemoteShutdownPrivilege to Administrators only.",
        severity: crate::model::Severity::Medium,
        benchmarks: &["CIS 2.2.10"],
        right: "SeRemoteShutdownPrivilege",
        requirement: Requirement::Only(&[ADMINISTRATORS_SID]),
    },
    UserRightDef {
        id: "WIN-UR-006",
        title: "SeNetworkLogonRight excludes Guests and Everyone",
        description: "Guests and Everyone must not log on over the network.",
        rationale: "Broad network logon rights make every share reachable by anonymous users.",
        remediation: "Deny SeNetworkLogonRight to Guests and Everyone.",
        severity: crate::model::Severity::High,
        benchmarks: &["CIS 2.2.24"],
        right: "SeNetworkLogonRight",
        requirement: Requirement::Excludes(&[GUESTS_SID, EVERYONE_SID]),
    },
    UserRightDef {
        id: "WIN-UR-007",
        title: "SeInteractiveLogonRight excludes Guests and Everyone",
        description: "Guests and Everyone must not log on locally.",
        rationale: "Guest sessions bypass attribution and per-user controls.",
        remediation: "Deny SeInteractiveLogonRight to Guests and Everyone.",
        severity: crate::model::Severity::Medium,
        benchmarks: &["CIS 2.2.23"],
        right: "SeInteractiveLogonRight",
        requirement: Requirement::Excludes(&[GUESTS_SID, EVERYONE_SID]),
    },
    UserRightDef {
        id: "WIN-UR-008",
        title: "SeDenyNetworkLogonRight includes Guests",
        description: "Guests are explicitly denied network logon.",
        rationale: "Explicit deny survives accidental allow-list changes.",
        remediation: "Assign SeDenyNetworkLogonRight to Guests.",
        severity: crate::model::Severity::Medium,
        benchmarks: &["CIS 2.2.25"],
        right: "SeDenyNetworkLogonRight",
        requirement: Requirement::Includes(&[GUESTS_SID]),
    },
    UserRightDef {
        id: "WIN-UR-009",
        title: "SeDenyInteractiveLogonRight includes Guests",
        description: "Guests are explicitly denied interactive logon.",
        rationale: "Explicit deny survives accidental allow-list changes.",
        remediation: "Assign SeDenyInteractiveLogonRight to Guests.",
        severity: crate::model::Severity::Medium,
        benchmarks: &["CIS 2.2.26"],
        right: "SeDenyInteractiveLogonRight",
        requirement: Requirement::Includes(&[GUESTS_SID]),
    },
    UserRightDef {
        id: "WIN-UR-010",
        title: "SeCreatePagefilePrivilege restricted to Administrators",
        description: "Only Administrators may create the pagefile.",
        rationale: "Pagefile control enables offline-secret and crash-dump attacks.",
        remediation: "Assign SeCreatePagefilePrivilege to Administrators only.",
        severity: crate::model::Severity::Low,
        benchmarks: &["CIS 2.2.5"],
        right: "SeCreatePagefilePrivilege",
        requirement: Requirement::Only(&[ADMINISTRATORS_SID]),
    },
    UserRightDef {
        id: "WIN-UR-011",
        title: "SeLockMemoryPrivilege not assigned",
        description: "No account may lock pages in memory.",
        rationale: "Locked pages evade pagefile inspection and enable DoS.",
        remediation: "Remove every account from 'Lock pages in memory'.",
        severity: crate::model::Severity::Low,
        benchmarks: &["CIS 2.2.9"],
        right: "SeLockMemoryPrivilege",
        requirement: Requirement::Empty,
    },
    UserRightDef {
        id: "WIN-UR-012",
        title: "SeCreateGlobalPrivilege restricted to service accounts",
        description: "Only Administrators and service SIDs may create global objects.",
        rationale: "Global objects are shared across sessions and enable symlink attacks.",
        remediation: "Assign SeCreateGlobalPrivilege to Administrators, SYSTEM, LOCAL SERVICE and NETWORK SERVICE only.",
        severity: crate::model::Severity::Medium,
        benchmarks: &["CIS 2.2.6"],
        right: "SeCreateGlobalPrivilege",
        requirement: Requirement::Only(&[
            ADMINISTRATORS_SID,
            SYSTEM_SID,
            LOCAL_SERVICE_SID,
            NETWORK_SERVICE_SID,
        ]),
    },
    UserRightDef {
        id: "WIN-UR-013",
        title: "SeProfileSingleProcessPrivilege restricted to Administrators",
        description: "Only Administrators may profile single processes.",
        rationale: "Profiling privilege leaks process memory and instrumentation data.",
        remediation: "Assign SeProfileSingleProcessPrivilege to Administrators only.",
        severity: crate::model::Severity::Low,
        benchmarks: &["CIS 2.2.12"],
        right: "SeProfileSingleProcessPrivilege",
        requirement: Requirement::Only(&[ADMINISTRATORS_SID]),
    },
    UserRightDef {
        id: "WIN-UR-014",
        title: "SeMachineAccountPrivilege not assigned",
        description: "No account may add workstations to the domain by default.",
        rationale: "Unlimited machine joins let attackers plant rogue computers.",
        remediation: "Remove every account from 'Add workstations to domain'.",
        severity: crate::model::Severity::Medium,
        benchmarks: &["CIS 2.2.7"],
        right: "SeMachineAccountPrivilege",
        requirement: Requirement::Empty,
    },
    UserRightDef {
        id: "WIN-UR-015",
        title: "SeSyncAgentPrivilege not assigned",
        description: "No account may synchronize directory service data.",
        rationale: "Sync agent privilege reads the entire directory, including password hashes.",
        remediation: "Remove every account from 'Synchronize directory service data'.",
        severity: crate::model::Severity::High,
        benchmarks: &["CIS 2.2.19"],
        right: "SeSyncAgentPrivilege",
        requirement: Requirement::Empty,
    },
    UserRightDef {
        id: "WIN-UR-016",
        title: "SeEnableDelegationPrivilege not assigned",
        description: "No account may mark others trusted for delegation.",
        rationale: "Delegation grants are a direct path to domain-wide impersonation.",
        remediation: "Remove every account from 'Enable computer and user accounts to be trusted for delegation'.",
        severity: crate::model::Severity::Critical,
        benchmarks: &["CIS 2.2.8"],
        right: "SeEnableDelegationPrivilege",
        requirement: Requirement::Empty,
    },
];

/// Portable evaluation: pure function of the requirement table and the
/// holder list. `Err(reason)` degrades with the exact cause recorded.
pub fn evaluate_user_right(
    def: &UserRightDef,
    holders: Result<&[SidAccount], &str>,
) -> CheckOutcome {
    let Ok(accounts) = holders else {
        let reason = holders.unwrap_err();
        let mut outcome = degraded(&format!("{} not evaluated: {reason}", def.right));
        outcome.fallback_log = vec![FallbackAttempt {
            source: format!("LSA {}", def.right),
            outcome: reason.into(),
        }];
        return outcome;
    };

    let sids: Vec<&str> = accounts.iter().map(|a| a.sid.as_str()).collect();
    let listing = |sids: &[&str]| -> String {
        if sids.is_empty() {
            "(none)".to_string()
        } else {
            sids.join(", ")
        }
    };

    let (passed, evidence) = match def.requirement {
        Requirement::Empty => {
            let good = sids.is_empty();
            (
                good,
                format!("{} holders: {} (expected none)", def.right, listing(&sids)),
            )
        }
        Requirement::Only(allowed) => {
            let good = !sids.is_empty() && sids.iter().all(|sid| allowed.contains(sid));
            (
                good,
                format!(
                    "{} holders: {} (expected only {})",
                    def.right,
                    listing(&sids),
                    allowed.join(", ")
                ),
            )
        }
        Requirement::Excludes(forbidden) => {
            let offenders: Vec<&str> = sids
                .iter()
                .filter(|sid| forbidden.contains(sid))
                .copied()
                .collect();
            (
                offenders.is_empty(),
                format!(
                    "{} holders: {} (must exclude {})",
                    def.right,
                    listing(&sids),
                    forbidden.join(", ")
                ),
            )
        }
        Requirement::Includes(required) => {
            let missing: Vec<&str> = required
                .iter()
                .filter(|sid| !sids.contains(sid))
                .copied()
                .collect();
            (
                missing.is_empty(),
                format!(
                    "{} holders: {} (must include {})",
                    def.right,
                    listing(&sids),
                    required.join(", ")
                ),
            )
        }
    };

    let location = format!("lsa:{}", def.right);
    let repro = format!("LsaEnumerateAccountsWithUserRight({})", def.right);
    let mut outcome = if passed {
        ok(evidence, location, repro)
    } else {
        nok(evidence, location, repro)
    };
    outcome.fallback_log = vec![FallbackAttempt {
        source: format!("LSA {}", def.right),
        outcome: format!("enumerated {} holders", sids.len()),
    }];
    outcome
}

#[cfg(windows)]
fn query_right_holders(right: &str) -> Result<Vec<SidAccount>, String> {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{LocalFree, HLOCAL};
    use windows_sys::Win32::Security::Authentication::Identity::{
        LsaClose, LsaEnumerateAccountsWithUserRight, LsaFreeMemory, LsaOpenPolicy,
        LSA_ENUMERATION_INFORMATION, LSA_OBJECT_ATTRIBUTES, LSA_UNICODE_STRING,
        POLICY_LOOKUP_NAMES,
    };
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidA;
    use windows_sys::Win32::Security::LookupAccountSidA;

    fn lsa_str(s: &str) -> LSA_UNICODE_STRING {
        let mut bytes = s.encode_utf16().collect::<Vec<_>>();
        bytes.push(0);
        LSA_UNICODE_STRING {
            Length: (bytes.len() as u16) * 2,
            MaximumLength: (bytes.len() as u16) * 2,
            Buffer: bytes.as_mut_ptr(),
        }
    }

    let mut sys_name = lsa_str("");
    let mut attrs: LSA_OBJECT_ATTRIBUTES = unsafe { std::mem::zeroed() };
    let mut handle: isize = 0;
    // SAFETY: read-only POLICY_LOOKUP_NAMES handle; outputs are freed below.
    let status = unsafe {
        LsaOpenPolicy(
            &mut sys_name,
            &mut attrs,
            POLICY_LOOKUP_NAMES as u32,
            &mut handle,
        )
    };
    if status != 0 {
        return Err(format!(
            "LsaOpenPolicy: status 0x{status:08x} (access denied or unsupported)"
        ));
    }
    struct LsaHandle(isize);
    impl Drop for LsaHandle {
        fn drop(&mut self) {
            // SAFETY: handle was opened above and closed exactly once.
            unsafe { LsaClose(self.0) };
        }
    }
    let _handle_guard = LsaHandle(handle);

    let mut right_buf = lsa_str(right);
    let mut enumeration = null_mut();
    let mut count = 0u32;
    // SAFETY: read-only enumeration; enumeration buffer freed with LsaFreeMemory.
    let status = unsafe {
        LsaEnumerateAccountsWithUserRight(handle, &mut right_buf, &mut enumeration, &mut count)
    };
    if status != 0 {
        // STATUS_NO_MORE_ENTRIES / 259 means no accounts hold the right.
        if status == 0x00000103 {
            return Ok(Vec::new());
        }
        return Err(format!(
            "LsaEnumerateAccountsWithUserRight: status 0x{status:08x}"
        ));
    }

    let mut holders = Vec::new();
    let infos = enumeration as *const LSA_ENUMERATION_INFORMATION;
    for i in 0..count as usize {
        let sid = unsafe { (*infos.add(i)).Sid };
        if sid.is_null() {
            continue;
        }
        // Convert SID to string form.
        let mut sid_string: *mut u8 = null_mut();
        // SAFETY: sid_string is allocated by the API and freed with LocalFree.
        if unsafe { ConvertSidToStringSidA(sid, &mut sid_string) } != 0 && !sid_string.is_null() {
            let cstr = unsafe { std::ffi::CStr::from_ptr(sid_string.cast()) };
            let sid_text = cstr.to_string_lossy().into_owned();
            unsafe { LocalFree(sid_string as HLOCAL) };

            // Resolve a readable name best-effort; SID stays authoritative.
            let mut name_size = 0u32;
            let mut domain_size = 0u32;
            let mut use_type: i32 = 0;
            // SAFETY: size-query form; buffers are null and sizes updated.
            unsafe {
                LookupAccountSidA(
                    null(),
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
            // SAFETY: buffers sized by the query above.
            let ok = unsafe {
                LookupAccountSidA(
                    null(),
                    sid,
                    name_buf.as_mut_ptr(),
                    &mut name_len,
                    domain_buf.as_mut_ptr(),
                    &mut domain_len,
                    &mut use_type,
                )
            };
            let name = if ok != 0 {
                let nul = name_buf
                    .iter()
                    .position(|b| *b == 0)
                    .unwrap_or(name_buf.len());
                let name = String::from_utf8_lossy(&name_buf[..nul]).into_owned();
                let dnul = domain_buf
                    .iter()
                    .position(|b| *b == 0)
                    .unwrap_or(domain_buf.len());
                let domain = String::from_utf8_lossy(&domain_buf[..dnul]).into_owned();
                if domain.is_empty() {
                    name
                } else {
                    format!("{domain}\\{name}")
                }
            } else {
                sid_text.clone()
            };
            holders.push(SidAccount {
                sid: sid_text,
                name,
            });
        }
    }
    // SAFETY: enumeration buffer returned by LsaEnumerateAccountsWithUserRight.
    unsafe { LsaFreeMemory(enumeration as *const _) };
    Ok(holders)
}

#[cfg(not(windows))]
fn query_right_holders(_right: &str) -> Result<Vec<SidAccount>, String> {
    Err("unsupported platform".into())
}

fn user_right_check(ctx: &mut ScanContext, def: &'static UserRightDef) -> CheckOutcome {
    let holders = if ctx.has_injector() {
        // Portable evidence path: injected maps are only produced by tests;
        // on live scans fall through to the native query.
        Err("portable evidence not configured".to_string())
    } else {
        query_right_holders(def.right)
    };
    match holders {
        Ok(ref accounts) => evaluate_user_right(def, Ok(accounts)),
        Err(reason) => evaluate_user_right(def, Err(&reason)),
    }
}

fn win(p: &crate::platform::PlatformInfo) -> bool {
    p.os == Os::Windows
}

pub fn register(reg: &mut Vec<RegisteredCheck>) {
    use crate::check;
    check!(
        reg,
        "WIN-UR-001",
        "SeDebugProgramPrivilege restricted to Administrators",
        "Only Administrators may debug arbitrary processes.",
        "Debug privilege reads any process memory, including LSASS credentials.",
        "Assign SeDebugPrivilege to Administrators only.",
        Critical,
        "User Rights",
        &["CIS 2.2.1"],
        win,
        |ctx| user_right_check(ctx, &USER_RIGHT_CHECKS[0])
    );
    check!(
        reg,
        "WIN-UR-002",
        "SeTcbPrivilege not assigned",
        "No account acts as part of the operating system.",
        "TCB privilege creates arbitrary tokens: full impersonation of any user.",
        "Remove every account from 'Act as part of the operating system'.",
        Critical,
        "User Rights",
        &["CIS 2.2.2"],
        win,
        |ctx| user_right_check(ctx, &USER_RIGHT_CHECKS[1])
    );
    check!(
        reg,
        "WIN-UR-003",
        "SeAssignPrimaryTokenPrivilege restricted",
        "Only Administrators and SYSTEM may replace process tokens.",
        "Token replacement privilege enables privilege escalation via crafted tokens.",
        "Assign SeAssignPrimaryTokenPrivilege to Administrators and SYSTEM only.",
        High,
        "User Rights",
        &["CIS 2.2.3"],
        win,
        |ctx| user_right_check(ctx, &USER_RIGHT_CHECKS[2])
    );
    check!(
        reg,
        "WIN-UR-004",
        "SeIncreaseQuotaPrivilege restricted",
        "Only Administrators and SYSTEM may adjust process memory quotas.",
        "Quota elevation supports memory-manipulation attacks.",
        "Assign SeIncreaseQuotaPrivilege to Administrators and SYSTEM only.",
        High,
        "User Rights",
        &["CIS 2.2.4"],
        win,
        |ctx| user_right_check(ctx, &USER_RIGHT_CHECKS[3])
    );
    check!(
        reg,
        "WIN-UR-005",
        "SeRemoteShutdownPrivilege restricted to Administrators",
        "Only Administrators may shut down the machine remotely.",
        "Remote shutdown is a denial-of-service primitive against servers.",
        "Assign SeRemoteShutdownPrivilege to Administrators only.",
        Medium,
        "User Rights",
        &["CIS 2.2.10"],
        win,
        |ctx| user_right_check(ctx, &USER_RIGHT_CHECKS[4])
    );
    check!(
        reg,
        "WIN-UR-006",
        "SeNetworkLogonRight excludes Guests and Everyone",
        "Guests and Everyone must not log on over the network.",
        "Broad network logon rights make every share reachable by anonymous users.",
        "Deny SeNetworkLogonRight to Guests and Everyone.",
        High,
        "User Rights",
        &["CIS 2.2.24"],
        win,
        |ctx| user_right_check(ctx, &USER_RIGHT_CHECKS[5])
    );
    check!(
        reg,
        "WIN-UR-007",
        "SeInteractiveLogonRight excludes Guests",
        "Guests must not log on locally.",
        "Guest sessions bypass attribution and per-user controls.",
        "Deny SeInteractiveLogonRight to Guests.",
        Medium,
        "User Rights",
        &["CIS 2.2.23"],
        win,
        |ctx| user_right_check(ctx, &USER_RIGHT_CHECKS[6])
    );
    check!(
        reg,
        "WIN-UR-008",
        "SeDenyNetworkLogonRight includes Guests",
        "Guests are explicitly denied network logon.",
        "Explicit deny survives accidental allow-list changes.",
        "Assign SeDenyNetworkLogonRight to Guests.",
        Medium,
        "User Rights",
        &["CIS 2.2.25"],
        win,
        |ctx| user_right_check(ctx, &USER_RIGHT_CHECKS[7])
    );
    check!(
        reg,
        "WIN-UR-009",
        "SeDenyInteractiveLogonRight includes Guests",
        "Guests are explicitly denied interactive logon.",
        "Explicit deny survives accidental allow-list changes.",
        "Assign SeDenyInteractiveLogonRight to Guests.",
        Medium,
        "User Rights",
        &["CIS 2.2.26"],
        win,
        |ctx| user_right_check(ctx, &USER_RIGHT_CHECKS[8])
    );
    check!(
        reg,
        "WIN-UR-010",
        "SeCreatePagefilePrivilege restricted to Administrators",
        "Only Administrators may create the pagefile.",
        "Pagefile control enables offline-secret and crash-dump attacks.",
        "Assign SeCreatePagefilePrivilege to Administrators only.",
        Low,
        "User Rights",
        &["CIS 2.2.5"],
        win,
        |ctx| user_right_check(ctx, &USER_RIGHT_CHECKS[9])
    );
    check!(
        reg,
        "WIN-UR-011",
        "SeLockMemoryPrivilege not assigned",
        "No account may lock pages in memory.",
        "Locked pages evade pagefile inspection and enable DoS.",
        "Remove every account from 'Lock pages in memory'.",
        Low,
        "User Rights",
        &["CIS 2.2.9"],
        win,
        |ctx| user_right_check(ctx, &USER_RIGHT_CHECKS[10])
    );
    check!(
        reg,
        "WIN-UR-012",
        "SeCreateGlobalPrivilege restricted to service accounts",
        "Only Administrators and service SIDs may create global objects.",
        "Global objects are shared across sessions and enable symlink attacks.",
        "Assign SeCreateGlobalPrivilege to Administrators, SYSTEM, LOCAL SERVICE and NETWORK SERVICE only.",
        Medium,
        "User Rights",
        &["CIS 2.2.6"],
        win,
        |ctx| user_right_check(ctx, &USER_RIGHT_CHECKS[11])
    );
    check!(
        reg,
        "WIN-UR-013",
        "SeProfileSingleProcessPrivilege restricted to Administrators",
        "Only Administrators may profile single processes.",
        "Profiling privilege leaks process memory and instrumentation data.",
        "Assign SeProfileSingleProcessPrivilege to Administrators only.",
        Low,
        "User Rights",
        &["CIS 2.2.12"],
        win,
        |ctx| user_right_check(ctx, &USER_RIGHT_CHECKS[12])
    );
    check!(
        reg,
        "WIN-UR-014",
        "SeMachineAccountPrivilege not assigned",
        "No account may add workstations to the domain by default.",
        "Unlimited machine joins let attackers plant rogue computers.",
        "Remove every account from 'Add workstations to domain'.",
        Medium,
        "User Rights",
        &["CIS 2.2.7"],
        win,
        |ctx| user_right_check(ctx, &USER_RIGHT_CHECKS[13])
    );
    check!(
        reg,
        "WIN-UR-015",
        "SeSyncAgentPrivilege not assigned",
        "No account may synchronize directory service data.",
        "Sync agent privilege reads the entire directory, including password hashes.",
        "Remove every account from 'Synchronize directory service data'.",
        High,
        "User Rights",
        &["CIS 2.2.19"],
        win,
        |ctx| user_right_check(ctx, &USER_RIGHT_CHECKS[14])
    );
    check!(
        reg,
        "WIN-UR-016",
        "SeEnableDelegationPrivilege not assigned",
        "No account may mark others trusted for delegation.",
        "Delegation grants are a direct path to domain-wide impersonation.",
        "Remove every account from 'Enable computer and user accounts to be trusted for delegation'.",
        Critical,
        "User Rights",
        &["CIS 2.2.8"],
        win,
        |ctx| user_right_check(ctx, &USER_RIGHT_CHECKS[15])
    );
}
