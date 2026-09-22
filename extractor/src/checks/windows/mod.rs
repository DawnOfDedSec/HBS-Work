//! Windows checks and read-only evidence helpers.

pub mod account;
pub mod audit;
pub mod defender;
pub mod event_logs;
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
    QueryResult { value, attempts }
}

/// Read a DWORD through `reg query`, then PowerShell `Get-ItemProperty`.
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
    QueryResult { value, attempts }
}

/// Read a string through `reg query`, then PowerShell `Get-ItemProperty`.
pub fn reg_query_sz(ctx: &mut ScanContext, path: &str, name: &str) -> Option<String> {
    reg_query_sz_with_log(ctx, path, name).value
}
