//! WIN-REG: filesystem and registry permission checks.
//!
//! ACL evidence from query-only PowerShell `Get-Acl ... | Select-Object
//! -ExpandProperty Sddl`; startup inventory from `reg query`. All
//! read-only; missing evidence degrades, never errors. Unquoted service
//! paths come from the Win32_Service CIM inventory (query-only JSON).

use crate::checks::{degraded, nok, ok};
use crate::context::ScanContext;
use crate::model::{CheckOutcome, FallbackAttempt, RegisteredCheck};
use crate::platform::Os;
use super::{perf_logs_dir, program_files, startup_dir, system32_dir, system_root};

/// SDDL trustees that must hold (or fail) an ACL.
const ADMIN_ADMINS: &str = "BA"; // Built-in Administrators
const ADMIN_SYSTEM: &str = "SY"; // SYSTEM
const EVERYONE_ALIASES: &[&str] = &["WD", "S-1-1-0"]; // World/Everyone

#[derive(Debug, Default, Clone)]
pub struct SddlAcl {
    pub owner: String,
    /// Every trustee appearing in the DACL (allow or deny ACEs).
    pub trustees: Vec<String>,
    pub owner_is_admin_or_system: bool,
    /// Any allow ACE granting write-class rights to Everyone/World.
    pub has_world_write: bool,
}

/// Parse an SDDL string: owner/group headers then `(type;flags;rights;..;..;trustee)` ACEs.
pub fn parse_sddl(raw: &str) -> Option<SddlAcl> {
    let s = raw.trim();
    let rest = s.strip_prefix("O:")?;
    let (owner, after_owner) = match rest.find("G:") {
        Some(i) => (rest[..i].to_string(), &rest[i + 2..]),
        None => match rest.find("D:") {
            Some(i) => (rest[..i].to_string(), &rest[i..]),
            None => (rest.to_string(), ""),
        },
    };
    if owner.is_empty() {
        return None;
    }
    let dacl = after_owner
        .find("D:")
        .map(|i| &after_owner[i + 2..])
        .unwrap_or("");
    let mut acl = SddlAcl {
        owner: owner.clone(),
        owner_is_admin_or_system: is_admin_trustee(&owner),
        ..SddlAcl::default()
    };
    for ace in parenthesized(dacl) {
        // type;flags;rights;object-guid;inherit-guid;trustee
        let fields: Vec<&str> = ace.split(';').collect();
        if fields.len() < 6 {
            continue;
        }
        let (ace_type, rights, trustee) = (fields[0].trim(), fields[2].trim(), fields[5].trim());
        if trustee.is_empty() {
            continue;
        }
        if !acl.trustees.iter().any(|t| t == trustee) {
            acl.trustees.push(trustee.to_string());
        }
        if ace_type == "A" && is_world_trustee(trustee) && grants_write(rights) {
            acl.has_world_write = true;
        }
    }
    Some(acl)
}

fn parenthesized(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'(' {
            if let Some(close) = s[i..].find(')') {
                out.push(&s[i + 1..i + close]);
                i += close + 1;
                continue;
            }
            break;
        }
        i += 1;
    }
    out
}

fn is_admin_trustee(t: &str) -> bool {
    matches!(
        t,
        "BA" | "SY" | "BO" | "LS" | "NS" | "S-1-5-32-544" | "S-1-5-18"
    )
}

fn is_world_trustee(t: &str) -> bool {
    EVERYONE_ALIASES.iter().any(|a| a.eq_ignore_ascii_case(t))
}

/// Write-class access rights worth flagging on a broad trustee. Pure
/// read sets (RX, RC, R) do not count.
fn grants_write(rights: &str) -> bool {
    let r = rights.to_ascii_uppercase();
    r == "*" || ["W", "KA", "FA", "DC", "SD", "WD", "AD", "LC", "DE", "CC", "GW", "GR"]
        .iter()
        .any(|m| r.contains(m))
}

/// How strict an ACL must be.
#[derive(Clone, Copy, PartialEq)]
enum AclMode {
    /// Registry hive: must grant Administrators + SYSTEM and no world write.
    Hive,
    /// Directory: world-writable is the failure; other shapes accepted.
    Directory,
}

fn ps_get_acl(ctx: &mut ScanContext, path: &str, attempts: &mut Vec<FallbackAttempt>) -> Option<String> {
    let script = format!("Get-Acl -Path '{}' | Select-Object -ExpandProperty Sddl", path.replace('\'', "''"));
    match ctx.cmd(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", &script],
    ) {
        Some(raw) => {
            let sddl = raw.trim().to_string();
            if sddl.is_empty() {
                attempts.push(FallbackAttempt {
                    source: format!("powershell Get-Acl {path}"),
                    outcome: "empty SDDL output".into(),
                });
                None
            } else {
                attempts.push(FallbackAttempt {
                    source: format!("powershell Get-Acl {path}"),
                    outcome: "read SDDL".into(),
                });
                Some(sddl)
            }
        }
        None => {
            attempts.push(FallbackAttempt {
                source: format!("powershell Get-Acl {path}"),
                outcome: "unavailable or blocked".into(),
            });
            None
        }
    }
}

fn acl_check(ctx: &mut ScanContext, path: &str, label: &str, mode: AclMode) -> CheckOutcome {
    let mut attempts = Vec::new();
    let Some(sddl) = ps_get_acl(ctx, path, &mut attempts) else {
        return degraded_outcome(
            &format!("ACL of {label} unreadable through read-only sources"),
            attempts,
        );
    };
    let Some(acl) = parse_sddl(&sddl) else {
        return degraded_outcome(&format!("SDDL of {label} unparseable"), attempts);
    };
    if acl.has_world_write {
        let mut outcome = nok(
            format!("{label} ACL grants Everyone write access (SDDL: {sddl})"),
            format!("acl:{path}"),
            format!("Get-Acl -Path '{path}'"),
        );
        outcome.fallback_log = attempts;
        return outcome;
    }
    if mode == AclMode::Hive {
        let has_admins = acl.trustees.iter().any(|t| t == ADMIN_ADMINS || t == "S-1-5-32-544");
        let has_system = acl.trustees.iter().any(|t| t == ADMIN_SYSTEM || t == "S-1-5-18");
        if !has_admins || !has_system || !acl.owner_is_admin_or_system {
            let mut outcome = nok(
                format!(
                    "{label} ACL not restricted to Administrators/SYSTEM (SDDL: {sddl})"
                ),
                format!("acl:{path}"),
                format!("Get-Acl -Path '{path}'"),
            );
            outcome.fallback_log = attempts;
            return outcome;
        }
    }
    let mut outcome = ok(
        format!("{label} ACL restricted (SDDL: {sddl})"),
        format!("acl:{path}"),
        format!("Get-Acl -Path '{path}'"),
    );
    outcome.fallback_log = attempts;
    outcome
}

fn degraded_outcome(reason: &str, attempts: Vec<FallbackAttempt>) -> CheckOutcome {
    let mut outcome = degraded(reason);
    outcome.fallback_log = attempts;
    outcome
}

/// WIN-REG-008: Run/RunOnce auto-start entries (HKLM + HKCU).
/// Informational: never fails.
fn run_inventory(ctx: &mut ScanContext) -> CheckOutcome {
    const KEYS: &[&str] = &[
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    ];
    let mut attempts = Vec::new();
    let mut entries: Vec<String> = Vec::new();
    for key in KEYS {
        match ctx.cmd("reg", &["query", key]) {
            Some(raw) => {
                let names = parse_reg_value_names(&raw);
                attempts.push(FallbackAttempt {
                    source: format!("reg query {key}"),
                    outcome: format!("{} entries", names.len()),
                });
                entries.extend(names);
            }
            None => attempts.push(FallbackAttempt {
                source: format!("reg query {key}"),
                outcome: "unavailable or key absent".into(),
            }),
        }
    }
    if attempts.iter().all(|a| a.outcome.contains("unavailable")) {
        return degraded_outcome("Run/RunOnce keys unreadable through any read-only source", attempts);
    }
    let listing = if entries.is_empty() {
        "none".to_string()
    } else {
        entries.join(", ")
    };
    let mut outcome = ok(
        format!("Run/RunOnce auto-start entries ({}): {listing}", entries.len()),
        "registry:Run+RunOnce".into(),
        "reg query ...\\CurrentVersion\\Run".into(),
    );
    outcome.fallback_log = attempts;
    outcome
}

fn parse_reg_value_names(raw: &str) -> Vec<String> {
    raw.lines()
        .filter_map(|line| {
            let idx = line.find("REG_SZ").or_else(|| line.find("REG_EXPAND_SZ"))?;
            let name = line[..idx].trim();
            (!name.is_empty() && !name.starts_with("HKEY_")).then(|| name.to_string())
        })
        .collect()
}

/// WIN-REG-009: Startup folder location + ACL. Informational: never fails.
fn startup_inventory(ctx: &mut ScanContext) -> CheckOutcome {
    const SHELL_FOLDERS: &str =
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders";
    let default_startup = startup_dir();
    let mut attempts = Vec::new();
    // Locate the all-users Startup folder via registry, else assume default.
    let folder = match ctx.cmd(
        "reg",
        &["query", SHELL_FOLDERS, "/v", "Common Startup"],
    ) {
        Some(raw) => {
            let value = raw
                .lines()
                .find_map(|l| l.split("REG_SZ").nth(1).map(str::trim))
                .filter(|v| !v.is_empty())
                .map(str::to_string);
            attempts.push(FallbackAttempt {
                source: format!("reg query {SHELL_FOLDERS}\\Common Startup"),
                outcome: match &value {
                    Some(v) => format!("located {v}"),
                    None => "value absent".into(),
                },
            });
            value.unwrap_or_else(|| default_startup.clone())
        }
        None => {
            attempts.push(FallbackAttempt {
                source: format!("reg query {SHELL_FOLDERS}\\Common Startup"),
                outcome: "unavailable; using default path".into(),
            });
            default_startup.clone()
        }
    };
    // ACL read is best-effort: unreadable ACL still leaves the inventory.
    if let Some(sddl) = ps_get_acl(ctx, &folder, &mut attempts) {
        let world = parse_sddl(&sddl).map_or(false, |a| a.has_world_write);
        let mut outcome = ok(
            format!(
                "startup folder {folder}; world-writable: {world}; SDDL: {sddl}"
            ),
            format!("folder:{folder}"),
            format!("Get-Acl -Path '{folder}'"),
        );
        outcome.fallback_log = attempts;
        return outcome;
    }
    let mut outcome = ok(
        format!("startup folder {folder} (ACL unreadable through read-only sources)"),
        format!("folder:{folder}"),
        format!("reg query {SHELL_FOLDERS}"),
    );
    outcome.fallback_log = attempts;
    outcome
}

#[derive(Debug)]
struct SvcPathRow {
    pathname: String,
    start_mode: String,
    state: String,
}

fn parse_service_json(raw: &str) -> Option<Vec<SvcPathRow>> {
    let v: serde_json::Value = serde_json::from_str(raw.trim()).ok()?;
    let rows = match v {
        serde_json::Value::Array(items) => items,
        serde_json::Value::Object(_) => vec![v],
        _ => return None,
    };
    Some(
        rows.into_iter()
            .filter_map(|row| {
                let path = row.get("PathName")?.as_str()?.to_string();
                if path.is_empty() {
                    return None;
                }
                Some(SvcPathRow {
                    pathname: path,
                    start_mode: row
                        .get("StartMode")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    state: row
                        .get("State")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                })
            })
            .collect(),
    )
}

/// A path is unquoted-vulnerable when it has no leading quote and the
/// executable portion contains a space (interpreter prepend risk).
fn unquoted_risk(pathname: &str) -> bool {
    let p = pathname.trim();
    if p.starts_with('"') {
        return false;
    }
    let lower = p.to_ascii_lowercase();
    match lower.find(".exe") {
        Some(i) => lower[..i].contains(' '),
        None => lower.contains(' '),
    }
}

/// WIN-REG-010: unquoted service binary paths from Win32_Service.
fn unquoted_paths(ctx: &mut ScanContext) -> CheckOutcome {
    const SCRIPT: &str = "Get-CimInstance -ClassName Win32_Service | Select-Object PathName,StartMode,State | ConvertTo-Json";
    let mut attempts = Vec::new();
    let Some(raw) = ctx.cmd(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", SCRIPT],
    ) else {
        attempts.push(FallbackAttempt {
            source: "powershell Get-CimInstance Win32_Service".into(),
            outcome: "unavailable or blocked".into(),
        });
        return degraded_outcome(
            "service path inventory unreadable through read-only sources",
            attempts,
        );
    };
    attempts.push(FallbackAttempt {
        source: "powershell Get-CimInstance Win32_Service".into(),
        outcome: "read service inventory".into(),
    });
    let Some(rows) = parse_service_json(&raw) else {
        return degraded_outcome("service inventory output unparseable", attempts);
    };
    let offending: Vec<&SvcPathRow> = rows
        .iter()
        .filter(|r| {
            (r.start_mode.eq_ignore_ascii_case("auto") || r.state.eq_ignore_ascii_case("running"))
                && unquoted_risk(&r.pathname)
        })
        .collect();
    if offending.is_empty() {
        let mut outcome = ok(
            format!(
                "no unquoted auto-start/running service paths among {} services",
                rows.len()
            ),
            "cim:Win32_Service".into(),
            "Get-CimInstance Win32_Service".into(),
        );
        outcome.fallback_log = attempts;
        return outcome;
    }
    let listing = offending
        .iter()
        .map(|r| r.pathname.as_str())
        .collect::<Vec<_>>()
        .join("; ");
    let mut outcome = nok(
        format!(
            "{} service(s) with unquoted spaced paths: {listing}",
            offending.len()
        ),
        "cim:Win32_Service".into(),
        "Get-CimInstance Win32_Service".into(),
    );
    outcome.fallback_log = attempts;
    outcome
}

fn win(p: &crate::platform::PlatformInfo) -> bool {
    p.os == Os::Windows
}

pub fn register(reg: &mut Vec<RegisteredCheck>) {
    use crate::check;
    check!(
        reg, "WIN-REG-001",
        "HKLM\\SAM ACL restricted to Administrators and SYSTEM",
        "The SAM registry hive grants access only to Administrators and SYSTEM.",
        "An open SAM hive exposes local account hashes to any local user.",
        "Restore the default SAM hive ACL (Administrators: Full Control, SYSTEM: Full Control).",
        High, "Permissions", &["Microsoft Security Baseline"],
        win,
        |ctx| acl_check(ctx, r"HKLM:\SAM", "HKLM\\SAM", AclMode::Hive)
    );
    check!(
        reg, "WIN-REG-002",
        "HKLM\\SECURITY ACL restricted to Administrators and SYSTEM",
        "The SECURITY registry hive grants access only to Administrators and SYSTEM.",
        "An open SECURITY hive leaks LSA policy and secrets metadata.",
        "Restore the default SECURITY hive ACL (Administrators: Full Control, SYSTEM: Full Control).",
        High, "Permissions", &["Microsoft Security Baseline"],
        win,
        |ctx| acl_check(ctx, r"HKLM:\SECURITY", "HKLM\\SECURITY", AclMode::Hive)
    );
    check!(
        reg, "WIN-REG-003",
        "HKLM\\SYSTEM ACL restricted to Administrators and SYSTEM",
        "The SYSTEM registry hive grants access only to Administrators and SYSTEM.",
        "An open SYSTEM hive exposes service configuration and boot secrets.",
        "Restore the default SYSTEM hive ACL (Administrators: Full Control, SYSTEM: Full Control).",
        High, "Permissions", &["Microsoft Security Baseline"],
        win,
        |ctx| acl_check(ctx, r"HKLM:\SYSTEM", "HKLM\\SYSTEM", AclMode::Hive)
    );
    check!(
        reg, "WIN-REG-004",
        "%SystemRoot% directory ACL non-world-writable",
        "The Windows directory does not grant Everyone write access.",
        "A writable Windows directory lets malware replace OS binaries.",
        "Reset inherited ACLs: icacls C:\\Windows /reset or restore default inheritance.",
        High, "Permissions", &[],
        win,
        |ctx| acl_check(ctx, &system_root(), "%SystemRoot%", AclMode::Directory)
    );
    check!(
        reg, "WIN-REG-005",
        "%ProgramFiles% directory ACL non-world-writable",
        "The Program Files directory does not grant Everyone write access.",
        "Writable program directories enable binary-planting privilege escalation.",
        "Remove Everyone/Users write ACEs from the Program Files tree.",
        High, "Permissions", &[],
        win,
        |ctx| acl_check(ctx, &program_files(), "%ProgramFiles%", AclMode::Directory)
    );
    check!(
        reg, "WIN-REG-006",
        "%SystemRoot%\\System32 directory ACL non-world-writable",
        "The System32 directory does not grant Everyone write access.",
        "System32 is the highest-value DLL-sideloading target on the host.",
        "Reset inherited ACLs on C:\\Windows\\System32.",
        High, "Permissions", &[],
        win,
        |ctx| acl_check(ctx, &system32_dir(), "%SystemRoot%\\System32", AclMode::Directory)
    );
    check!(
        reg, "WIN-REG-007",
        "%SystemDrive%\\PerfLogs directory ACL restricted",
        "The PerfLogs directory does not grant Everyone write access.",
        "PerfLogs is world-writable by default on some builds and a known drop point.",
        "Restrict write access on C:\\PerfLogs to Administrators/SYSTEM.",
        Medium, "Permissions", &[],
        win,
        |ctx| acl_check(ctx, &perf_logs_dir(), "%SystemDrive%\\PerfLogs", AclMode::Directory)
    );
    check!(
        reg, "WIN-REG-008",
        "Run and RunOnce auto-start inventory",
        "Registry Run and RunOnce entries (HKLM and HKCU) are enumerated.",
        "Run keys are the most abused persistence location; inventory exposes drift.",
        "Review Run/RunOnce entries against the approved software baseline.",
        Informational, "Permissions", &[],
        win,
        run_inventory
    );
    check!(
        reg, "WIN-REG-009",
        "Startup folder location and ACL",
        "The all-users Startup folder is located and its ACL recorded.",
        "Startup folders execute everything placed inside them at logon.",
        "Review Startup folder contents and keep its ACL restricted.",
        Informational, "Permissions", &[],
        win,
        startup_inventory
    );
    check!(
        reg, "WIN-REG-010",
        "Unquoted service binary paths",
        "No auto-start or running service uses an unquoted path containing spaces.",
        "Unquoted spaced paths let attackers escalate by planting executables early in the path.",
        "Quote the ImagePath value or move the binary to a path without spaces.",
        Medium, "Permissions", &[],
        win,
        unquoted_paths
    );
}
