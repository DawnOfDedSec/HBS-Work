//! WIN-EVT: Windows event log configuration checks.
//!
//! Evidence comes from query-only `wevtutil gl <channel>` reads. Retention
//! duration is never invented: only what the log actually reports
//! (`retention`, `autoBackup`) is evaluated; unknown values degrade.
//! Missing tools or denied access return `DegradedPartial`, never `Error`.

use crate::checks::{degraded, nok, ok};
use crate::context::ScanContext;
use crate::model::{CheckOutcome, FallbackAttempt, RegisteredCheck};
use crate::platform::Os;

const MIN_LOG_BYTES: u64 = 32 * 1024 * 1024; // 32768 KB

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LogConfig {
    pub max_size_bytes: Option<u64>,
    pub retention: Option<bool>,
    pub auto_backup: Option<bool>,
    pub channel_access: Option<String>,
}

/// Parse `wevtutil gl <channel>` text output. Accepts the YAML-ish key
/// lines wevtutil emits; unknown values map to `None` rather than guesses.
pub fn parse_log_config(raw: &str) -> LogConfig {
    let mut cfg = LogConfig {
        max_size_bytes: None,
        retention: None,
        auto_backup: None,
        channel_access: None,
    };
    let mut in_logging = false;
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if indent == 0 && !trimmed.starts_with(' ') {
            in_logging = trimmed.starts_with("logging:");
            if !in_logging {
                if let Some(value) = trimmed.strip_prefix("channelAccess:") {
                    let value = value.trim();
                    if !value.is_empty() && !value.eq_ignore_ascii_case("unknown") {
                        cfg.channel_access = Some(value.to_string());
                    }
                }
            }
            continue;
        }
        if !in_logging {
            // Top-level keys can also carry the values on some builds.
            if let Some(v) = key_value(trimmed, "maxSize") {
                cfg.max_size_bytes = parse_bytes(&v);
            } else if let Some(v) = key_value(trimmed, "retention") {
                cfg.retention = parse_bool(&v);
            } else if let Some(v) = key_value(trimmed, "autoBackup") {
                cfg.auto_backup = parse_bool(&v);
            } else if let Some(v) = key_value(trimmed, "channelAccess") {
                let v = v.trim();
                if !v.is_empty() && !v.eq_ignore_ascii_case("unknown") {
                    cfg.channel_access = Some(v.to_string());
                }
            }
            continue;
        }
        if let Some(v) = key_value(trimmed, "maxSize") {
            cfg.max_size_bytes = parse_bytes(&v);
        } else if let Some(v) = key_value(trimmed, "retention") {
            cfg.retention = parse_bool(&v);
        } else if let Some(v) = key_value(trimmed, "autoBackup") {
            cfg.auto_backup = parse_bool(&v);
        }
    }
    cfg
}

fn key_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(key)?;
    let rest = rest.strip_prefix(':')?;
    Some(rest.trim())
}

fn parse_bytes(value: &str) -> Option<u64> {
    if value.eq_ignore_ascii_case("unknown") || value.is_empty() {
        return None;
    }
    value.replace(',', "").parse().ok()
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn fetch_log(ctx: &mut ScanContext, channel: &str) -> (Option<LogConfig>, Vec<FallbackAttempt>) {
    let mut attempts = Vec::new();
    let Some(raw) = ctx.cmd("wevtutil", &["gl", channel]) else {
        attempts.push(FallbackAttempt {
            source: format!("wevtutil gl {channel}"),
            outcome: "tool unavailable or query denied".into(),
        });
        return (None, attempts);
    };
    attempts.push(FallbackAttempt {
        source: format!("wevtutil gl {channel}"),
        outcome: "read log configuration".into(),
    });
    (Some(parse_log_config(&raw)), attempts)
}

fn degraded_outcome(reason: &str, attempts: Vec<FallbackAttempt>) -> CheckOutcome {
    let mut outcome = degraded(reason);
    outcome.fallback_log = attempts;
    outcome
}

/// WIN-EVT-001/002/003: log size >= 32768 KB.
fn log_size_check(ctx: &mut ScanContext, channel: &str) -> CheckOutcome {
    let (cfg, attempts) = fetch_log(ctx, channel);
    let Some(cfg) = cfg else {
        return degraded_outcome(
            &format!("{channel} log configuration unavailable"),
            attempts,
        );
    };
    let Some(size) = cfg.max_size_bytes else {
        return degraded_outcome(
            &format!("{channel} log size not reported (unknown value)"),
            attempts,
        );
    };
    let mb = size / (1024 * 1024);
    let mut outcome = if size >= MIN_LOG_BYTES {
        ok(
            format!("{channel} log maxSize = {mb} MB (expected >= 32 MB)"),
            format!("eventlog:{channel}"),
            format!("wevtutil gl {channel}"),
        )
    } else {
        nok(
            format!("{channel} log maxSize = {mb} MB (expected >= 32 MB)"),
            format!("eventlog:{channel}"),
            format!("wevtutil gl {channel}"),
        )
    };
    outcome.fallback_log = attempts;
    outcome
}

/// WIN-EVT-004: Security log retention configured: `retention: true` or
/// `autoBackup: true`. A duration is never inferred from either flag.
fn security_retention(ctx: &mut ScanContext) -> CheckOutcome {
    let (cfg, attempts) = fetch_log(ctx, "Security");
    let Some(cfg) = cfg else {
        return degraded_outcome("Security log configuration unavailable", attempts);
    };
    let (Some(retention), Some(backup)) = (cfg.retention, cfg.auto_backup) else {
        return degraded_outcome(
            "Security log retention/autoBackup not reported (unknown values)",
            attempts,
        );
    };
    let mut outcome = if retention || backup {
        ok(
            format!(
                "Security log retention configured (retention: {retention}, autoBackup: {backup})"
            ),
            "eventlog:Security".into(),
            "wevtutil gl Security".into(),
        )
    } else {
        nok(
            "Security log retention not configured (retention: false, autoBackup: false)"
                .to_string(),
            "eventlog:Security".into(),
            "wevtutil gl Security".into(),
        )
    };
    outcome.fallback_log = attempts;
    outcome
}

/// WIN-EVT-005: Security log ACL grants access only to System/Admins.
/// Any `WD` (Everyone) / `BU` grant or broad write bits elsewhere fail.
fn security_acl(ctx: &mut ScanContext) -> CheckOutcome {
    let (cfg, attempts) = fetch_log(ctx, "Security");
    let Some(cfg) = cfg else {
        return degraded_outcome("Security log configuration unavailable", attempts);
    };
    let Some(acl) = cfg.channel_access else {
        return degraded_outcome(
            "Security log channelAccess not reported (unknown value)",
            attempts,
        );
    };
    let upper = acl.to_ascii_lowercase();
    // Everyone / Authenticated Users / broad access markers in SDDL.
    let broad = ["(a;;", "wd)"]
        .iter()
        .any(|needle| upper.contains(needle) && upper.contains(";;0x") && upper.contains("wd)"))
        || upper.contains(";;;wd)");
    let mut outcome = if broad {
        nok(
            "Security log ACL grants Everyone access (expected System/Admins only)".to_string(),
            "eventlog:Security".to_string(),
            "wevtutil gl Security".into(),
        )
    } else {
        ok(
            "Security log ACL restricted to System/Administrators".to_string(),
            "eventlog:Security".into(),
            "wevtutil gl Security".into(),
        )
    };
    outcome.fallback_log = attempts;
    outcome
}

/// WIN-EVT-006: channel inventory (Informational, never pass/fail).
fn channel_inventory(ctx: &mut ScanContext) -> CheckOutcome {
    let mut attempts = Vec::new();
    let Some(raw) = ctx.cmd("wevtutil", &["el"]) else {
        attempts.push(FallbackAttempt {
            source: "wevtutil el".into(),
            outcome: "tool unavailable or query denied".into(),
        });
        return degraded_outcome("channel enumeration unavailable", attempts);
    };
    let count = raw.lines().filter(|l| !l.trim().is_empty()).count();
    attempts.push(FallbackAttempt {
        source: "wevtutil el".into(),
        outcome: format!("enumerated {count} channels"),
    });
    let mut outcome = ok(
        format!("{count} event channels registered"),
        "eventlog:channels".into(),
        "wevtutil el".into(),
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
        reg,
        "WIN-EVT-001",
        "Application log size >= 32768 KB",
        "Application event log retains at least 32 MB before overwrite.",
        "Undersized logs overwrite the forensics an investigation needs.",
        "Raise the Application log maximum size to 32768 KB or more.",
        Medium,
        "Event Logs",
        &["CIS 8.2"],
        win,
        |ctx| log_size_check(ctx, "Application")
    );
    check!(
        reg,
        "WIN-EVT-002",
        "Security log size >= 32768 KB",
        "Security event log retains at least 32 MB before overwrite.",
        "The Security log is the primary audit trail; overflow erases attack evidence.",
        "Raise the Security log maximum size to 32768 KB or more.",
        High,
        "Event Logs",
        &["CIS 8.2"],
        win,
        |ctx| log_size_check(ctx, "Security")
    );
    check!(
        reg,
        "WIN-EVT-003",
        "System log size >= 32768 KB",
        "System event log retains at least 32 MB before overwrite.",
        "System log drives service and driver forensics; overflow hides incidents.",
        "Raise the System log maximum size to 32768 KB or more.",
        Medium,
        "Event Logs",
        &["CIS 8.2"],
        win,
        |ctx| log_size_check(ctx, "System")
    );
    check!(
        reg,
        "WIN-EVT-004",
        "Security log retention configured",
        "Security log keeps events (retention) or archives them (autoBackup).",
        "Without retention/archive control, the oldest evidence is silently destroyed.",
        "Enable retention or autoBackup on the Security log; report duration from your SIEM.",
        Medium,
        "Event Logs",
        &["CIS 8.3"],
        win,
        security_retention
    );
    check!(
        reg,
        "WIN-EVT-005",
        "Security log access restricted",
        "Security log readable only by System and Administrators.",
        "Broad ACLs let attackers read or clear the audit trail.",
        "Restrict Security log channelAccess to BA/SY principals.",
        High,
        "Event Logs",
        &["CIS 8.1"],
        win,
        security_acl
    );
    check!(
        reg,
        "WIN-EVT-006",
        "Event channels inventory",
        "Enumerates registered event channels for context.",
        "Channel coverage shows what telemetry exists before an incident.",
        "Review channel coverage against your monitoring requirements.",
        Informational,
        "Event Logs",
        &[],
        win,
        channel_inventory
    );
}
