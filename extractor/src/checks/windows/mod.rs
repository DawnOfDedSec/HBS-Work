//! Windows checks and read-only evidence helpers.

pub mod account;
pub mod audit;
pub mod defender;
pub mod event_logs;
pub mod native_accounts;
pub mod native_reg;
pub mod network;
pub mod perms;
pub mod sec_options;
pub mod services;
pub mod threat_creds;
pub mod threat_persist;
pub mod user_rights;

use crate::context::ScanContext;
use crate::model::FallbackAttempt;

#[derive(Debug)]
pub struct QueryResult<T> {
    pub value: Option<T>,
    pub attempts: Vec<FallbackAttempt>,
}

fn attempt(source: &str, outcome: impl Into<String>) -> FallbackAttempt {
    FallbackAttempt {
        source: source.into(),
        outcome: outcome.into(),
    }
}

fn powershell_registry_path(path: &str) -> String {
    if path.starts_with("Registry::") {
        path.to_owned()
    } else {
        format!("Registry::{path}")
    }
}

// ---- environment-derived system paths ---------------------------------------
// Never assume `C:\`: the system drive and profile directories are configurable
// (SystemRoot/SystemDrive/ProgramFiles/ProgramData) and differ across hosts.

/// `%SystemRoot%` (e.g. `D:\Windows`), falling back to the canonical default.
pub fn system_root() -> String {
    std::env::var("SystemRoot")
        .or_else(|_| std::env::var("windir"))
        .unwrap_or_else(|_| r"C:\Windows".to_string())
}

/// `%SystemDrive%` (e.g. `D:`).
pub fn system_drive() -> String {
    std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string())
}

/// `%ProgramFiles%`.
pub fn program_files() -> String {
    std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".to_string())
}

/// `%ProgramData%`.
pub fn program_data() -> String {
    std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string())
}

pub fn system32_dir() -> String {
    format!("{}\\System32", system_root())
}

pub fn perf_logs_dir() -> String {
    format!("{}\\PerfLogs", system_drive())
}

/// The all-users Startup folder.
pub fn startup_dir() -> String {
    format!(
        "{}\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp",
        program_data()
    )
}

/// The hosts file under the real system root.
pub fn hosts_file() -> String {
    format!("{}\\System32\\drivers\\etc\\hosts", system_root())
}

fn reg_query_value(output: &str, name: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let line = line.trim();
        let prefix = line.get(..name.len())?;
        if !prefix.eq_ignore_ascii_case(name) {
            return None;
        }
        let rest = line.get(name.len()..)?.trim_start();
        let mut fields = rest.split_whitespace();
        let kind = fields.next()?;
        if !kind.starts_with("REG_") {
            return None;
        }
        let value = fields.collect::<Vec<_>>().join(" ");
        (!value.is_empty()).then_some(value)
    })
}

fn parse_dword(raw: &str) -> Option<u32> {
    let token = raw.split_whitespace().find(|token| {
        token.starts_with("0x")
            || token.starts_with("0X")
            || token.bytes().all(|b| b.is_ascii_digit())
    })?;
    if let Some(hex) = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).ok()
    } else {
        token.parse().ok()
    }
}

pub fn reg_query_dword_with_log(ctx: &mut ScanContext, path: &str, name: &str) -> QueryResult<u32> {
    let mut attempts = Vec::new();
    match ctx.cmd("reg", &["query", path, "/v", name]) {
        Some(output) => match reg_query_value(&output, name).and_then(|raw| parse_dword(&raw)) {
            Some(value) => {
                attempts.push(attempt("reg query", format!("read {name}={value}")));
                return QueryResult {
                    value: Some(value),
                    attempts,
                };
            }
            None => attempts.push(attempt(
                "reg query",
                format!("{name} missing or unparseable"),
            )),
        },
        None => attempts.push(attempt("reg query", "unavailable")),
    }

    let registry_path = powershell_registry_path(path);
    let script = format!(
        "(Get-ItemProperty -LiteralPath '{}' -Name '{}' -ErrorAction SilentlyContinue).'{}'",
        registry_path.replace('\'', "''"),
        name.replace('\'', "''"),
        name.replace('\'', "''"),
    );
    let value = match ctx.cmd(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", &script],
    ) {
        Some(output) => match parse_dword(output.trim()) {
            Some(value) => {
                attempts.push(attempt(
                    "PowerShell Get-ItemProperty",
                    format!("read {name}={value}"),
                ));
                Some(value)
            }
            None => {
                attempts.push(attempt(
                    "PowerShell Get-ItemProperty",
                    format!("{name} missing or unparseable"),
                ));
                None
            }
        },
        None => {
            attempts.push(attempt("PowerShell Get-ItemProperty", "unavailable"));
            None
        }
    };

    // Final fallback: in-process, read-only registry access. This is the
    // only source that survives a Server Core image with neither `reg`
    // nor PowerShell, and it never spawns a process.
    let value = match value {
        Some(value) => Some(value),
        None if ctx.native_fallbacks_enabled() => match native_reg::native_reg_dword(path, name) {
            Some(value) => {
                attempts.push(attempt("native registry", format!("read {name}={value}")));
                Some(value)
            }
            None => {
                attempts.push(attempt(
                    "native registry",
                    format!("{name} missing or unreadable"),
                ));
                None
            }
        },
        None => {
            attempts.push(attempt("native registry", "skipped (injected context)"));
            None
        }
    };
    QueryResult { value, attempts }
}

/// Read a DWORD through the ordered `reg query` -> PowerShell
/// `Get-ItemProperty` -> native in-process registry chain.
pub fn reg_query_dword(ctx: &mut ScanContext, path: &str, name: &str) -> Option<u32> {
    reg_query_dword_with_log(ctx, path, name).value
}

pub fn reg_query_sz_with_log(ctx: &mut ScanContext, path: &str, name: &str) -> QueryResult<String> {
    let mut attempts = Vec::new();
    match ctx.cmd("reg", &["query", path, "/v", name]) {
        Some(output) => match reg_query_value(&output, name) {
            Some(value) => {
                let value = value.trim_matches('"').to_owned();
                attempts.push(attempt("reg query", format!("read {name}")));
                return QueryResult {
                    value: Some(value),
                    attempts,
                };
            }
            None => attempts.push(attempt("reg query", format!("{name} missing"))),
        },
        None => attempts.push(attempt("reg query", "unavailable")),
    }

    let registry_path = powershell_registry_path(path);
    let script = format!(
        "(Get-ItemProperty -LiteralPath '{}' -Name '{}' -ErrorAction SilentlyContinue).'{}'",
        registry_path.replace('\'', "''"),
        name.replace('\'', "''"),
        name.replace('\'', "''"),
    );
    let value = ctx
        .cmd(
            "powershell",
            &["-NoProfile", "-NonInteractive", "-Command", &script],
        )
        .map(|value| value.trim().to_owned())
        .filter(|value| {
            !value.is_empty()
                && !value.to_ascii_lowercase().contains("unable to find")
                && !value.to_ascii_lowercase().starts_with("error:")
        });
    attempts.push(attempt(
        "PowerShell Get-ItemProperty",
        if value.is_some() {
            format!("read {name}")
        } else {
            "unavailable or missing".into()
        },
    ));

    // Final fallback: in-process, read-only registry access (see the
    // DWORD helper above). Skipped in injected/deterministic contexts.
    let value = match value {
        Some(value) => Some(value),
        None if ctx.native_fallbacks_enabled() => match native_reg::native_reg_sz(path, name) {
            Some(value) if !value.is_empty() => {
                attempts.push(attempt("native registry", format!("read {name}")));
                Some(value)
            }
            _ => {
                attempts.push(attempt(
                    "native registry",
                    format!("{name} missing or unreadable"),
                ));
                None
            }
        },
        None => {
            attempts.push(attempt("native registry", "skipped (injected context)"));
            None
        }
    };
    QueryResult { value, attempts }
}

/// Read a string through the ordered `reg query` -> PowerShell
/// `Get-ItemProperty` -> native in-process registry chain.
pub fn reg_query_sz(ctx: &mut ScanContext, path: &str, name: &str) -> Option<String> {
    reg_query_sz_with_log(ctx, path, name).value
}
