//! WIN-TH (part 2): persistence hunting, lifecycle, and local-admin posture.
//!
//! Every source is read-only: registry queries, CIM inventories, schtasks,
//! netsh, service configuration, dsregcmd, local-group enumeration, and the
//! hosts file. Missing or blocked evidence degrades; it never becomes Error.

use super::services::parse_sc_qc;
use super::{reg_query_dword_with_log, QueryResult};
use crate::checks::{degraded, nok, ok};
use crate::context::ScanContext;
use crate::model::{CheckOutcome, FallbackAttempt, RegisteredCheck};
use crate::platform::Os;
use serde_json::Value as Json;
use std::time::{SystemTime, UNIX_EPOCH};

const IFEO: &str =
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
const NETSH_HELPERS: &str = r"HKLM\SOFTWARE\Microsoft\NetSh";
const SHELL_FOLDERS: &str =
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders";
const DEFAULT_STARTUP: &str = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp";
const MODERN_LAPS: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\LAPS";
const LEGACY_LAPS: &str =
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Services\AdmPwdService";
const SERVICES: &str = r"HKLM\SYSTEM\CurrentControlSet\Services";

const SERVICE_CMD: &str =
    "Get-CimInstance -ClassName Win32_Service | Select-Object Name,PathName | ConvertTo-Json";
const FILTER_CMD: &str = r"Get-CimInstance -Namespace 'root\subscription' -ClassName __EventFilter | Select-Object Name,Query | ConvertTo-Json";
const CONSUMER_CMD: &str = r"Get-CimInstance -Namespace 'root\subscription' -ClassName CommandLineEventConsumer | Select-Object Name,CommandLineTemplate | ConvertTo-Json";
const HOTFIX_CMD: &str = "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 HotFixID,InstalledOn | ConvertTo-Json";

fn with_attempts(mut outcome: CheckOutcome, attempts: Vec<FallbackAttempt>) -> CheckOutcome {
    outcome.fallback_log = attempts;
    outcome
}

fn degraded_with(reason: &str, attempts: Vec<FallbackAttempt>) -> CheckOutcome {
    with_attempts(degraded(reason), attempts)
}

fn unavailable(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    lower.contains("unable to find") || lower.contains("cannot find") || lower.starts_with("error:")
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
    let value = serde_json::from_str(raw.trim()).ok();
    attempts.push(FallbackAttempt {
        source: label.into(),
        outcome: if value.is_some() {
            "read JSON".into()
        } else {
            "unparseable output".into()
        },
    });
    value
}

fn json_rows(value: Json) -> Option<Vec<Json>> {
    match value {
        Json::Array(rows) => Some(rows),
        Json::Object(_) => Some(vec![value]),
        Json::Null => Some(Vec::new()),
        _ => None,
    }
}

// WIN-TH-015
fn ifeo_debuggers(ctx: &mut ScanContext) -> CheckOutcome {
    let mut attempts = Vec::new();
    match ctx.cmd("reg", &["query", IFEO, "/s", "/v", "Debugger"]) {
        Some(raw) if unavailable(&raw) => {
            attempts.push(FallbackAttempt {
                source: format!("reg query {IFEO} /s /v Debugger"),
                outcome: "key/value absent".into(),
            });
            with_attempts(
                ok(
                    "no IFEO Debugger values found".into(),
                    format!("registry:{IFEO}"),
                    format!("reg query {IFEO} /s /v Debugger"),
                ),
                attempts,
            )
        }
        Some(raw) => {
            let debuggers: Vec<String> = raw
                .lines()
                .filter(|line| line.to_ascii_lowercase().contains("debugger"))
                .map(|line| line.trim().to_string())
                .collect();
            attempts.push(FallbackAttempt {
                source: format!("reg query {IFEO} /s /v Debugger"),
                outcome: format!("{} values", debuggers.len()),
            });
            let outcome = if debuggers.is_empty() {
                ok(
                    "no IFEO Debugger values found".into(),
                    format!("registry:{IFEO}"),
                    format!("reg query {IFEO} /s /v Debugger"),
                )
            } else {
                nok(
                    format!("IFEO Debugger persistence found: {}", debuggers.join(" | ")),
                    format!("registry:{IFEO}"),
                    format!("reg query {IFEO} /s /v Debugger"),
                )
            };
            with_attempts(outcome, attempts)
        }
        None => {
            attempts.push(FallbackAttempt {
                source: format!("reg query {IFEO} /s /v Debugger"),
                outcome: "unavailable or blocked".into(),
            });
            degraded_with("IFEO Debugger values unreadable", attempts)
        }
    }
}

// WIN-TH-016
fn startup_executables(ctx: &mut ScanContext) -> CheckOutcome {
    const RUN_KEYS: &[&str] = &[
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    ];
    let mut attempts = Vec::new();
    let mut suspicious = Vec::new();
    let mut readable = false;
    for key in RUN_KEYS {
        match ctx.cmd("reg", &["query", key]) {
            Some(raw) => {
                readable = true;
                let values: Vec<String> = raw
                    .lines()
                    .filter(|line| line.contains("REG_SZ") || line.contains("REG_EXPAND_SZ"))
                    .filter(|line| {
                        let lower = line.to_ascii_lowercase();
                        [".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js"]
                            .iter()
                            .any(|ext| lower.contains(ext))
                    })
                    .map(|line| line.trim().to_string())
                    .collect();
                attempts.push(FallbackAttempt {
                    source: format!("reg query {key}"),
                    outcome: format!("{} executable/script values", values.len()),
                });
                suspicious.extend(values);
            }
            None => attempts.push(FallbackAttempt {
                source: format!("reg query {key}"),
                outcome: "unavailable or key absent".into(),
            }),
        }
    }
    // Locate the folder even though strict no-directory-enumeration policy
    // prevents listing it without introducing a broader shell capability.
    let folder = ctx
        .cmd("reg", &["query", SHELL_FOLDERS, "/v", "Common Startup"])
        .and_then(|raw| {
            readable = true;
            raw.lines().find_map(|line| {
                line.find("REG_SZ")
                    .map(|i| line[i + "REG_SZ".len()..].trim().to_string())
            })
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_STARTUP.into());
    attempts.push(FallbackAttempt {
        source: format!("reg query {SHELL_FOLDERS} /v Common Startup"),
        outcome: format!("startup folder: {folder}"),
    });
    if !readable {
        return degraded_with("startup persistence sources unreadable", attempts);
    }
    let outcome = if suspicious.is_empty() {
        ok(
            format!("no executable/script Run entries; startup folder located at {folder}"),
            "registry:Run+RunOnce".into(),
            "reg query ...\\CurrentVersion\\Run".into(),
        )
    } else {
        nok(
            format!(
                "startup executable/script entries: {}",
                suspicious.join(" | ")
            ),
            "registry:Run+RunOnce".into(),
            "reg query ...\\CurrentVersion\\Run".into(),
        )
    };
    with_attempts(outcome, attempts)
}

#[derive(Debug, PartialEq, Eq)]
pub struct ScheduledTaskRow {
    pub name: String,
    pub author: String,
    pub action: String,
    pub suspicious: bool,
}

fn split_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut chars = line.chars().peekable();
    let mut quoted = false;
    while let Some(ch) = chars.next() {
        match ch {
            '"' if quoted && chars.peek() == Some(&'"') => {
                current.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => {
                fields.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    fields.push(current.trim().to_string());
    fields
}

fn path_is_user_writable(path: &str) -> bool {
    let p = path.replace('/', "\\").to_ascii_lowercase();
    p.contains(r"\users\")
        || p.contains(r"\temp\")
        || p.contains(r"\appdata\")
        || (p.contains(r"\programdata\") && !p.contains(r"\programdata\microsoft\"))
}

pub fn parse_schtasks_csv(raw: &str) -> Option<Vec<ScheduledTaskRow>> {
    let mut lines = raw.lines().filter(|line| !line.trim().is_empty());
    let header = split_csv_line(lines.next()?);
    let find = |names: &[&str]| {
        header
            .iter()
            .position(|field| names.iter().any(|n| field.eq_ignore_ascii_case(n)))
    };
    let name_i = find(&["TaskName", "Task Name"])?;
    let author_i = find(&["Author"]).unwrap_or(usize::MAX);
    let action_i = find(&["Task To Run", "Actions", "Action"])?;
    Some(
        lines
            .filter_map(|line| {
                let fields = split_csv_line(line);
                let name = fields.get(name_i)?.to_string();
                let author = fields.get(author_i).cloned().unwrap_or_default();
                let action = fields.get(action_i)?.to_string();
                let suspicious = path_is_user_writable(&action)
                    || (!author.is_empty() && !author.to_ascii_lowercase().contains("microsoft"));
                Some(ScheduledTaskRow {
                    name,
                    author,
                    action,
                    suspicious,
                })
            })
            .collect(),
    )
}

// WIN-TH-017
fn scheduled_tasks(ctx: &mut ScanContext) -> CheckOutcome {
    let mut attempts = Vec::new();
    let Some(raw) = ctx.cmd("schtasks", &["/query", "/fo", "csv", "/v"]) else {
        attempts.push(FallbackAttempt {
            source: "schtasks /query /fo csv /v".into(),
            outcome: "unavailable or blocked".into(),
        });
        return degraded_with("scheduled-task inventory unavailable", attempts);
    };
    let Some(rows) = parse_schtasks_csv(&raw) else {
        attempts.push(FallbackAttempt {
            source: "schtasks /query /fo csv /v".into(),
            outcome: "unparseable or localized headers".into(),
        });
        return degraded_with("scheduled-task CSV unparseable", attempts);
    };
    let risky: Vec<&ScheduledTaskRow> = rows.iter().filter(|row| row.suspicious).collect();
    attempts.push(FallbackAttempt {
        source: "schtasks /query /fo csv /v".into(),
        outcome: format!("{} tasks, {} suspicious", rows.len(), risky.len()),
    });
    let outcome = if risky.is_empty() {
        ok(
            format!("{} scheduled tasks; no risky author/action", rows.len()),
            "tasks:schtasks".into(),
            "schtasks /query /fo csv /v".into(),
        )
    } else {
        nok(
            format!(
                "suspicious scheduled tasks: {}",
                risky
                    .iter()
                    .map(|row| format!("{} -> {}", row.name, row.action))
                    .collect::<Vec<_>>()
                    .join(" | ")
            ),
            "tasks:schtasks".into(),
            "schtasks /query /fo csv /v".into(),
        )
    };
    with_attempts(outcome, attempts)
}

// WIN-TH-018
fn risky_service_paths(ctx: &mut ScanContext) -> CheckOutcome {
    let mut attempts = Vec::new();
    let Some(value) = ps_json(ctx, SERVICE_CMD, "PowerShell Win32_Service", &mut attempts) else {
        return degraded_with("service path inventory unavailable", attempts);
    };
    let Some(rows) = json_rows(value) else {
        return degraded_with("service path inventory unparseable", attempts);
    };
    let risky: Vec<String> = rows
        .iter()
        .filter_map(|row| {
            let name = row.get("Name")?.as_str().unwrap_or("unknown");
            let path = row.get("PathName")?.as_str()?;
            path_is_user_writable(path).then(|| format!("{name}: {path}"))
        })
        .collect();
    let outcome = if risky.is_empty() {
        ok(
            format!(
                "{} services; no binary under user-writable paths",
                rows.len()
            ),
            "cim:Win32_Service".into(),
            SERVICE_CMD.into(),
        )
    } else {
        nok(
            format!(
                "service binaries in user-writable paths: {}",
                risky.join(" | ")
            ),
            "cim:Win32_Service".into(),
            SERVICE_CMD.into(),
        )
    };
    with_attempts(outcome, attempts)
}

// WIN-TH-019
fn wmi_subscriptions(ctx: &mut ScanContext) -> CheckOutcome {
    let mut attempts = Vec::new();
    let filters = ps_json(
        ctx,
        FILTER_CMD,
        "PowerShell WMI __EventFilter",
        &mut attempts,
    )
    .and_then(json_rows);
    let consumers = ps_json(
        ctx,
        CONSUMER_CMD,
        "PowerShell WMI CommandLineEventConsumer",
        &mut attempts,
    )
    .and_then(json_rows);
    let (Some(filters), Some(consumers)) = (filters, consumers) else {
        return degraded_with("WMI permanent-subscription inventory unavailable", attempts);
    };
    let total = filters.len() + consumers.len();
    let outcome = if total == 0 {
        ok(
            "no WMI permanent event filters or command-line consumers".into(),
            "cim:root\\subscription".into(),
            FILTER_CMD.into(),
        )
    } else {
        let names = filters
            .iter()
            .chain(consumers.iter())
            .filter_map(|row| row.get("Name").and_then(Json::as_str))
            .collect::<Vec<_>>()
            .join(", ");
        nok(
            format!("{total} WMI permanent-subscription objects: {names}"),
            "cim:root\\subscription".into(),
            FILTER_CMD.into(),
        )
    };
    with_attempts(outcome, attempts)
}

// WIN-TH-020
fn hosts_redirects(ctx: &mut ScanContext) -> CheckOutcome {
    const HOSTS: &str = "C:/Windows/System32/drivers/etc/hosts";
    // Fixture roots cannot prefix a drive-qualified path on Windows.
    let source = if ctx.root_prefix.as_os_str().is_empty() {
        HOSTS
    } else {
        "/Windows/System32/drivers/etc/hosts"
    };
    let Some(raw) = ctx.read(source) else {
        return degraded("hosts file unreadable");
    };
    let entries: Vec<String> = raw
        .lines()
        .map(|line| line.split('#').next().unwrap_or("").trim())
        .filter(|line| !line.is_empty())
        .filter(|line| {
            let parts: Vec<_> = line.split_whitespace().collect();
            !(parts.len() >= 2
                && matches!(parts[0], "127.0.0.1" | "::1")
                && parts[1].eq_ignore_ascii_case("localhost"))
        })
        .map(str::to_string)
        .collect();
    if entries.is_empty() {
        ok(
            "hosts file contains only default loopback entries".into(),
            format!("file:{HOSTS}"),
            format!("read {HOSTS}"),
        )
    } else {
        nok(
            format!("non-default hosts redirects: {}", entries.join(" | ")),
            format!("file:{HOSTS}"),
            format!("read {HOSTS}"),
        )
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct FirewallRule {
    pub name: String,
    pub program: String,
    pub suspicious: bool,
}

pub fn parse_firewall_rules(raw: &str) -> Vec<FirewallRule> {
    fn value<'a>(line: &'a str, labels: &[&str]) -> Option<&'a str> {
        let (key, value) = line.split_once(':')?;
        labels
            .iter()
            .any(|label| key.trim().eq_ignore_ascii_case(label))
            .then_some(value.trim())
    }
    let mut result = Vec::new();
    let mut current: Vec<&str> = Vec::new();
    let finish = |lines: &[&str], out: &mut Vec<FirewallRule>| {
        if lines.is_empty() {
            return;
        }
        let get = |labels: &[&str]| lines.iter().find_map(|line| value(line, labels));
        let name = get(&["Rule Name", "Regelname"]).unwrap_or("unknown");
        let enabled = get(&["Enabled", "Aktiviert"]).unwrap_or("");
        let direction = get(&["Direction", "Richtung"]).unwrap_or("");
        let action = get(&["Action", "Aktion"]).unwrap_or("");
        let program = get(&["Program", "Programm"]).unwrap_or("");
        let suspicious = matches!(enabled.to_ascii_lowercase().as_str(), "yes" | "ja")
            && matches!(
                direction.to_ascii_lowercase().as_str(),
                "in" | "inbound" | "eingehend"
            )
            && matches!(action.to_ascii_lowercase().as_str(), "allow" | "zulassen")
            && path_is_user_writable(program);
        out.push(FirewallRule {
            name: name.into(),
            program: program.into(),
            suspicious,
        });
    };
    for line in raw.lines() {
        if line.trim().is_empty() {
            finish(&current, &mut result);
            current.clear();
        } else {
            current.push(line);
        }
    }
    finish(&current, &mut result);
    result
}

// WIN-TH-021
fn firewall_user_paths(ctx: &mut ScanContext) -> CheckOutcome {
    let mut attempts = Vec::new();
    let Some(raw) = ctx.cmd(
        "netsh",
        &["advfirewall", "firewall", "show", "rule", "name=all"],
    ) else {
        attempts.push(FallbackAttempt {
            source: "netsh advfirewall firewall show rule name=all".into(),
            outcome: "unavailable or blocked".into(),
        });
        return degraded_with("firewall rule inventory unavailable", attempts);
    };
    let rules = parse_firewall_rules(&raw);
    if rules.is_empty() && !raw.to_ascii_lowercase().contains("no rules") {
        attempts.push(FallbackAttempt {
            source: "netsh advfirewall firewall show rule name=all".into(),
            outcome: "unparseable/localized output".into(),
        });
        return degraded_with("firewall rule output unparseable", attempts);
    }
    let risky: Vec<&FirewallRule> = rules.iter().filter(|rule| rule.suspicious).collect();
    attempts.push(FallbackAttempt {
        source: "netsh advfirewall firewall show rule name=all".into(),
        outcome: format!("{} rules, {} risky", rules.len(), risky.len()),
    });
    let outcome = if risky.is_empty() {
        ok(
            "no enabled inbound allow rule targets user-writable executable paths".into(),
            "firewall:rules".into(),
            "netsh advfirewall firewall show rule name=all".into(),
        )
    } else {
        nok(
            format!(
                "inbound rules target user-writable paths: {}",
                risky
                    .iter()
                    .map(|rule| format!("{} -> {}", rule.name, rule.program))
                    .collect::<Vec<_>>()
                    .join(" | ")
            ),
            "firewall:rules".into(),
            "netsh advfirewall firewall show rule name=all".into(),
        )
    };
    with_attempts(outcome, attempts)
}

// WIN-TH-022
fn netsh_helpers(ctx: &mut ScanContext) -> CheckOutcome {
    let mut attempts = Vec::new();
    let Some(raw) = ctx.cmd("reg", &["query", NETSH_HELPERS]) else {
        attempts.push(FallbackAttempt {
            source: format!("reg query {NETSH_HELPERS}"),
            outcome: "unavailable or blocked".into(),
        });
        return degraded_with("NETSH helper registration unreadable", attempts);
    };
    if unavailable(&raw) {
        attempts.push(FallbackAttempt {
            source: format!("reg query {NETSH_HELPERS}"),
            outcome: "key absent".into(),
        });
        return with_attempts(
            ok(
                "no NETSH helper DLL registrations".into(),
                format!("registry:{NETSH_HELPERS}"),
                format!("reg query {NETSH_HELPERS}"),
            ),
            attempts,
        );
    }
    let helpers: Vec<String> = raw
        .lines()
        .filter(|line| line.contains("REG_SZ") || line.contains("REG_EXPAND_SZ"))
        .map(|line| line.trim().to_string())
        .collect();
    attempts.push(FallbackAttempt {
        source: format!("reg query {NETSH_HELPERS}"),
        outcome: format!("{} helpers", helpers.len()),
    });
    let outcome = if helpers.is_empty() {
        ok(
            "no NETSH helper DLL registrations".into(),
            format!("registry:{NETSH_HELPERS}"),
            format!("reg query {NETSH_HELPERS}"),
        )
    } else {
        nok(
            format!("NETSH helper DLL registrations: {}", helpers.join(" | ")),
            format!("registry:{NETSH_HELPERS}"),
            format!("reg query {NETSH_HELPERS}"),
        )
    };
    with_attempts(outcome, attempts)
}

// WIN-TH-023
fn fax_disabled(ctx: &mut ScanContext) -> CheckOutcome {
    let mut attempts = Vec::new();
    let sc = ctx.cmd("sc", &["qc", "Fax"]);
    if let Some(raw) = &sc {
        attempts.push(FallbackAttempt {
            source: "sc qc Fax".into(),
            outcome: "queried service".into(),
        });
        if let Some(config) = parse_sc_qc(raw) {
            let disabled = config.start_type == Some(4);
            return with_attempts(
                if disabled {
                    ok(
                        "Fax service disabled".into(),
                        "services:Fax".into(),
                        "sc qc Fax".into(),
                    )
                } else {
                    nok(
                        format!("Fax start type {:?} (expected disabled)", config.start_type),
                        "services:Fax".into(),
                        "sc qc Fax".into(),
                    )
                },
                attempts,
            );
        }
    } else {
        attempts.push(FallbackAttempt {
            source: "sc qc Fax".into(),
            outcome: "unavailable or blocked".into(),
        });
    }
    let path = format!(r"{SERVICES}\Fax");
    let q: QueryResult<u32> = reg_query_dword_with_log(ctx, &path, "Start");
    attempts.extend(q.attempts);
    match q.value {
        Some(4) => with_attempts(
            ok(
                "Fax service disabled (Start=4)".into(),
                format!("registry:{path}"),
                format!("reg query {path} /v Start"),
            ),
            attempts,
        ),
        Some(value) => with_attempts(
            nok(
                format!("Fax service Start={value} (expected 4)"),
                format!("registry:{path}"),
                format!("reg query {path} /v Start"),
            ),
            attempts,
        ),
        // `sc` returned a normal non-configuration response and the
        // service key is absent: safely confirm service is not installed.
        None if sc.is_some() => with_attempts(
            ok(
                "Fax service not installed".into(),
                "services:Fax".into(),
                "sc qc Fax".into(),
            ),
            attempts,
        ),
        None => degraded_with("Fax service state unreadable", attempts),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsBuildSupport {
    Supported,
    Eol,
    Unknown,
}

pub fn windows_build_support(version: &str) -> WindowsBuildSupport {
    let build = version
        .split('.')
        .nth(2)
        .and_then(|part| part.parse::<u32>().ok());
    match build {
        // Server 2012 / 2012 R2: ESU ended 2026-10; baseline support ended 2023.
        Some(9200 | 9600) => WindowsBuildSupport::Eol,
        // Server 2016/2019/2022/2025 and current Windows 11 branches.
        Some(14393 | 17763 | 20348 | 25398 | 26100) => WindowsBuildSupport::Supported,
        // Windows 10 build support depends on edition/LTSC, not build alone.
        _ => WindowsBuildSupport::Unknown,
    }
}

// WIN-TH-024
fn os_eol(ctx: &mut ScanContext) -> CheckOutcome {
    let version = &ctx.platform.kernel;
    match windows_build_support(version) {
        WindowsBuildSupport::Supported => ok(
            format!("Windows build {version} is in the supported server matrix"),
            "platform:version".into(),
            "RtlGetVersion".into(),
        ),
        WindowsBuildSupport::Eol => nok(
            format!("Windows build {version} is end-of-life"),
            "platform:version".into(),
            "RtlGetVersion".into(),
        ),
        WindowsBuildSupport::Unknown => degraded(&format!(
            "support status for Windows build {version} needs edition/product verification"
        )),
    }
}

fn civil_days(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let mp = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn parse_date(raw: &str) -> Option<i64> {
    let date = raw.split_whitespace().next()?;
    let parts: Vec<_> = if date.contains('-') {
        date.split('-').collect()
    } else {
        date.split('/').collect()
    };
    if parts.len() != 3 {
        return None;
    }
    let nums: Vec<i64> = parts
        .iter()
        .map(|part| part.parse().ok())
        .collect::<Option<_>>()?;
    let (year, month, day) = if parts[0].len() == 4 {
        (nums[0], nums[1], nums[2])
    } else {
        (nums[2], nums[0], nums[1])
    };
    (year >= 1970 && (1..=12).contains(&month) && (1..=31).contains(&day))
        .then(|| civil_days(year, month, day))
}

// WIN-TH-025
fn patch_staleness(ctx: &mut ScanContext) -> CheckOutcome {
    let mut attempts = Vec::new();
    let Some(value) = ps_json(ctx, HOTFIX_CMD, "PowerShell Get-HotFix", &mut attempts) else {
        return degraded_with("latest hotfix date unavailable", attempts);
    };
    let row = match value {
        Json::Array(rows) => rows.into_iter().next(),
        Json::Object(_) => Some(value),
        _ => None,
    };
    let Some(installed) = row
        .as_ref()
        .and_then(|row| row.get("InstalledOn"))
        .and_then(Json::as_str)
        .and_then(parse_date)
    else {
        return degraded_with("latest hotfix date unparseable/localized", attempts);
    };
    let today = (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 86_400) as i64;
    let age = today.saturating_sub(installed);
    let outcome = if age <= 180 {
        ok(
            format!("latest hotfix age {age} days (maximum 180)"),
            "hotfix:latest".into(),
            HOTFIX_CMD.into(),
        )
    } else {
        nok(
            format!("latest hotfix age {age} days (maximum 180)"),
            "hotfix:latest".into(),
            HOTFIX_CMD.into(),
        )
    };
    with_attempts(outcome, attempts)
}

// WIN-TH-026
fn laps(ctx: &mut ScanContext) -> CheckOutcome {
    let mut attempts = Vec::new();
    let Some(join) = ctx.cmd("dsregcmd", &["/status"]) else {
        attempts.push(FallbackAttempt {
            source: "dsregcmd /status".into(),
            outcome: "unavailable or blocked".into(),
        });
        return degraded_with("domain join state unavailable", attempts);
    };
    attempts.push(FallbackAttempt {
        source: "dsregcmd /status".into(),
        outcome: "read join state".into(),
    });
    let upper = join.to_ascii_uppercase();
    let joined = upper.lines().any(|line| {
        (line.contains("DOMAINJOINED") || line.contains("AZUREADJOINED")) && line.contains("YES")
    });
    if !joined {
        return with_attempts(
            ok(
                "host not domain/Azure AD joined; LAPS policy not required".into(),
                "identity:join-state".into(),
                "dsregcmd /status".into(),
            ),
            attempts,
        );
    }
    let modern = reg_query_dword_with_log(ctx, MODERN_LAPS, "AdmPwdEnabled");
    let modern_value = modern.value;
    attempts.extend(modern.attempts);
    if modern_value.unwrap_or(0) >= 1 {
        return with_attempts(
            ok(
                "Windows LAPS AdmPwdEnabled configured".into(),
                format!("registry:{MODERN_LAPS}"),
                format!("reg query {MODERN_LAPS} /v AdmPwdEnabled"),
            ),
            attempts,
        );
    }
    match ctx.cmd("reg", &["query", LEGACY_LAPS]) {
        Some(raw) if !unavailable(&raw) => {
            attempts.push(FallbackAttempt {
                source: format!("reg query {LEGACY_LAPS}"),
                outcome: "legacy LAPS present".into(),
            });
            with_attempts(
                ok(
                    "legacy LAPS (AdmPwdService) present".into(),
                    format!("registry:{LEGACY_LAPS}"),
                    format!("reg query {LEGACY_LAPS}"),
                ),
                attempts,
            )
        }
        Some(_) => {
            attempts.push(FallbackAttempt {
                source: format!("reg query {LEGACY_LAPS}"),
                outcome: "legacy LAPS absent".into(),
            });
            with_attempts(
                nok(
                    "domain-joined host has no modern or legacy LAPS configuration".into(),
                    format!("registry:{MODERN_LAPS}"),
                    format!("reg query {MODERN_LAPS} /v AdmPwdEnabled"),
                ),
                attempts,
            )
        }
        None => {
            attempts.push(FallbackAttempt {
                source: format!("reg query {LEGACY_LAPS}"),
                outcome: "unavailable or blocked".into(),
            });
            degraded_with("LAPS state unreadable on domain-joined host", attempts)
        }
    }
}

pub fn parse_localgroup_members(raw: &str) -> Vec<String> {
    let mut inside = false;
    raw.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with("---") {
                inside = true;
                return None;
            }
            if !inside
                || line.is_empty()
                || line.to_ascii_lowercase().starts_with("the command")
                || line.to_ascii_lowercase().starts_with("der befehl")
            {
                return None;
            }
            Some(line.to_string())
        })
        .collect()
}

// WIN-TH-027
fn local_admins(ctx: &mut ScanContext) -> CheckOutcome {
    let mut attempts = Vec::new();
    let Some(raw) = ctx.cmd("net", &["localgroup", "Administrators"]) else {
        attempts.push(FallbackAttempt {
            source: "net localgroup Administrators".into(),
            outcome: "unavailable or blocked".into(),
        });
        return degraded_with("local Administrators group unreadable", attempts);
    };
    let members = parse_localgroup_members(&raw);
    if !raw.contains("---") {
        attempts.push(FallbackAttempt {
            source: "net localgroup Administrators".into(),
            outcome: "unparseable/localized output".into(),
        });
        return degraded_with("local Administrators output unparseable", attempts);
    }
    attempts.push(FallbackAttempt {
        source: "net localgroup Administrators".into(),
        outcome: format!("{} members", members.len()),
    });
    let outcome = if members.len() <= 1 {
        ok(
            format!(
                "local Administrators count = {}: {}",
                members.len(),
                members.join(", ")
            ),
            "group:Administrators".into(),
            "net localgroup Administrators".into(),
        )
    } else {
        nok(
            format!(
                "local Administrators count = {} (>1): {}",
                members.len(),
                members.join(", ")
            ),
            "group:Administrators".into(),
            "net localgroup Administrators".into(),
        )
    };
    with_attempts(outcome, attempts)
}

fn win(p: &crate::platform::PlatformInfo) -> bool {
    p.os == Os::Windows
}

pub fn register(reg: &mut Vec<RegisteredCheck>) {
    use crate::check;
    const REFS: &[&str] = &[
        "CIS Microsoft Windows Server Benchmark",
        "Microsoft Security Baseline",
    ];
    check!(
        reg,
        "WIN-TH-015",
        "IFEO Debugger hijacking sweep",
        "No Image File Execution Options subkey defines a Debugger value.",
        "IFEO Debugger values transparently replace trusted binaries with attacker programs.",
        "Remove unapproved Debugger values below Image File Execution Options.",
        High,
        "Threat",
        REFS,
        win,
        ifeo_debuggers
    );
    check!(
        reg,
        "WIN-TH-016",
        "Startup folder anomalous executable inventory",
        "All-users Startup folder contains no executable or script payload.",
        "Startup entries execute at every interactive logon and survive reboots.",
        "Remove unapproved executables/scripts and restrict the Startup folder ACL.",
        Informational,
        "Threat",
        REFS,
        win,
        startup_executables
    );
    check!(
        reg,
        "WIN-TH-017",
        "Scheduled tasks avoid temporary and user paths",
        "Scheduled task authors/actions are Microsoft-owned or outside user-writable paths.",
        "Tasks launched from Temp or user profiles provide durable privilege escalation.",
        "Move approved actions to protected paths and remove unapproved tasks.",
        Medium,
        "Threat",
        REFS,
        win,
        scheduled_tasks
    );
    check!(
        reg,
        "WIN-TH-018",
        "Service binaries avoid user-writable directories",
        "No service ImagePath resolves below Users, Temp, AppData, or untrusted ProgramData.",
        "Writable service binaries turn file-write access into SYSTEM execution.",
        "Move service binaries to protected Program Files/System32 paths and fix ACLs.",
        Medium,
        "Threat",
        REFS,
        win,
        risky_service_paths
    );
    check!(
        reg,
        "WIN-TH-019",
        "No WMI permanent event subscriptions",
        "root\\subscription contains no event filters or command-line consumers.",
        "Permanent WMI subscriptions execute quietly without normal startup artifacts.",
        "Remove unapproved filters, consumers, and bindings from root\\subscription.",
        High,
        "Threat",
        REFS,
        win,
        wmi_subscriptions
    );
    check!(
        reg,
        "WIN-TH-020",
        "Hosts file has no non-default redirects",
        "Hosts contains only default localhost mappings.",
        "Static redirects silently divert updates, authentication, or security telemetry.",
        "Remove unapproved hosts mappings and investigate the writer.",
        Informational,
        "Threat",
        REFS,
        win,
        hosts_redirects
    );
    check!(
        reg,
        "WIN-TH-021",
        "Inbound firewall rules avoid user-path executables",
        "No enabled inbound allow rule targets an executable in a user-writable path.",
        "An attacker can replace the target executable while retaining firewall access.",
        "Delete the rule or move the binary to a protected directory.",
        Medium,
        "Threat",
        REFS,
        win,
        firewall_user_paths
    );
    check!(
        reg,
        "WIN-TH-022",
        "No NETSH helper DLL registrations",
        "HKLM\\SOFTWARE\\Microsoft\\NetSh has no helper DLL values.",
        "NETSH helper DLLs load into an administrative utility and provide persistence.",
        "Remove unapproved NETSH helper registrations and investigate the DLL.",
        High,
        "Threat",
        REFS,
        win,
        netsh_helpers
    );
    check!(
        reg,
        "WIN-TH-023",
        "Fax service disabled",
        "Fax service is absent or start type Disabled.",
        "FxSSVC expands RPC/service attack surface on hosts that do not fax.",
        "Disable the Fax service unless a documented business requirement exists.",
        Low,
        "Threat",
        REFS,
        win,
        fax_disabled
    );
    check!(
        reg,
        "WIN-TH-024",
        "Operating system remains supported",
        "Detected Windows product build remains within vendor support.",
        "Unsupported systems stop receiving security fixes and accumulate known exploits.",
        "Upgrade to a supported Windows Server/Windows release.",
        High,
        "Threat",
        REFS,
        win,
        os_eol
    );
    check!(
        reg,
        "WIN-TH-025",
        "Latest patch is no older than 180 days",
        "Newest installed hotfix date is within 180 days.",
        "Patch gaps longer than six months expose mature, commodity exploits.",
        "Apply current cumulative/security updates and verify update servicing.",
        Medium,
        "Threat",
        REFS,
        win,
        patch_staleness
    );
    check!(
        reg,
        "WIN-TH-026",
        "LAPS configured on domain-joined hosts",
        "Modern Windows LAPS or legacy AdmPwdService is present when domain joined.",
        "Shared static local-admin passwords allow lateral movement across the estate.",
        "Deploy Windows LAPS and rotate each host's local administrator password.",
        Informational,
        "Threat",
        REFS,
        win,
        laps
    );
    check!(
        reg,
        "WIN-TH-027",
        "Local Administrators membership minimized",
        "Local Administrators group has at most one member.",
        "Every extra local administrator is another credential and persistence path.",
        "Remove unnecessary direct/group memberships from local Administrators.",
        Low,
        "Threat",
        REFS,
        win,
        local_admins
    );
}
