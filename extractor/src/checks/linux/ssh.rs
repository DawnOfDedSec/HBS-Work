//! LIN-SSH: sshd hardening (CIS 5.2.x). Effective-value resolution:
//! /etc/ssh/sshd_config last-wins, `sshd -T` fallback for includes.

use crate::checks::{degraded, err_outcome, nok, ok, with_block};
use crate::context::ScanContext;
use crate::model::{CheckOutcome, FallbackAttempt, RegisteredCheck};
use crate::platform::Os;

pub fn register(reg: &mut Vec<RegisteredCheck>) {
    use crate::check;
    check!(reg, "LIN-SSH-001", "Direct root login restricted", "PermitRootLogin must be no/prohibit-password.", "Direct root logons leave no attribution and are brute-force magnets.", "PermitRootLogin no (use sudo for admin).", High, "SSH", &["CIS 5.2.8"], linux, |c| ssh_kv(c, "PermitRootLogin", &["no", "prohibit-password", "without-password"], "yes"));
    check!(reg, "LIN-SSH-002", "LogLevel appropriately verbose", "sshd must log at INFO or higher.", "Quiet sshd hides brute-force and key-attempt evidence.", "LogLevel VERBOSE (INFO minimum).", Low, "SSH", &["CIS 5.2.2"], linux, |c| ssh_kv(c, "LogLevel", &["VERBOSE", "INFO"], "QUIET"));
    check!(reg, "LIN-SSH-003", "Strong ciphers configured", "Only modern AEAD ciphers.", "Legacy CBC ciphers enable padding-oracle decryption.", "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com.", Medium, "SSH", &["CIS 5.2.12"], linux, |c| ssh_kv_contains_any(c, "Ciphers", &["chacha20-poly1305", "aes256-gcm", "aes128-gcm"]));
    check!(reg, "LIN-SSH-004", "Strong MACs configured", "hmac-sha2 family only.", "Weak MACs (hmac-md5/96-bit) allow forgery.", "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com.", Medium, "SSH", &["CIS 5.2.13"], linux, |c| ssh_kv_contains_any(c, "MACs", &["hmac-sha2-512", "hmac-sha2-256"]));
    check!(reg, "LIN-SSH-005", "Strong KEX algorithms", "curve25519/ecdh/nistp256+ only.", "Weak DH groups permit passive decryption.", "KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512.", Medium, "SSH", &["CIS 5.2.14"], linux, |c| ssh_kv_contains_any(c, "KexAlgorithms", &["curve25519", "group16", "group18", "ecdh-sha2-nistp256"]));
    check!(reg, "LIN-SSH-006", "Idle session timeout set", "ClientAliveInterval/CountMax must bound idle sessions.", "Abandoned sessions become hijack windows.", "ClientAliveInterval <= 900 with ClientAliveCountMax <= 3.", Medium, "SSH", &["CIS 5.2.15-16"], linux, client_alive);
    check!(reg, "LIN-SSH-007", "Login grace period bounded", "LoginGraceTime <= 60s.", "Long grace periods hold unauthenticated state for DoS.", "LoginGraceTime 60.", Low, "SSH", &["CIS 5.2.4"], linux, |c| ssh_num_max(c, "LoginGraceTime", 60));
    check!(reg, "LIN-SSH-008", "MaxAuthTries limited", "MaxAuthTries <= 4.", "High try-counts allow extensive brute forcing per connection.", "MaxAuthTries 4.", Medium, "SSH", &["CIS 5.2.5"], linux, |c| ssh_num_max(c, "MaxAuthTries", 4));
    check!(reg, "LIN-SSH-009", "MaxSessions limited", "MaxSessions <= 10.", "Unbounded sessions multiply multiplex abuse.", "MaxSessions 10.", Low, "SSH", &["CIS 5.2.6"], linux, |c| ssh_num_max(c, "MaxSessions", 10));
    check!(reg, "LIN-SSH-010", "X11 forwarding disabled", "X11Forwarding no.", "X tunnels expose displays and keylog paths.", "X11Forwarding no.", Low, "SSH", &["CIS 5.2.10"], linux, |c| ssh_kv(c, "X11Forwarding", &["no"], "yes"));
    check!(reg, "LIN-SSH-011", "Agent forwarding disabled", "AllowAgentForwarding no.", "Forwarded agents can be hijacked by root on the jump host.", "AllowAgentForwarding no.", Low, "SSH", &["CIS 5.2.11"], linux, |c| ssh_kv(c, "AllowAgentForwarding", &["no"], "yes"));
    check!(reg, "LIN-SSH-012", "Empty passwords refused", "PermitEmptyPasswords no.", "Passwordless accounts log in trivially.", "PermitEmptyPasswords no.", High, "SSH", &["CIS 5.2.9"], linux, |c| ssh_kv(c, "PermitEmptyPasswords", &["no"], "yes"));
    check!(reg, "LIN-SSH-013", "Login banner configured", "Banner path must be set.", "Banners establish access warnings (legal stance).", "Banner /etc/issue.net.", Low, "SSH", &["CIS 5.2.17"], linux, ssh_banner);
    check!(reg, "LIN-SSH-014", "Host-based authentication disabled", "HostbasedAuthentication no.", "Host trust is spoofable.", "HostbasedAuthentication no.", Medium, "SSH", &["CIS 5.2.7"], linux, |c| ssh_kv(c, "HostbasedAuthentication", &["no"], "yes"));
    check!(reg, "LIN-SSH-015", "PermitUserEnvironment disabled", "PermitUserEnvironment no.", "User-environment injection bypasses restrictions.", "PermitUserEnvironment no.", Medium, "SSH", &["CIS 5.2.18"], linux, |c| ssh_kv(c, "PermitUserEnvironment", &["no"], "yes"));
}

fn linux(p: &crate::platform::PlatformInfo) -> bool {
    p.os == Os::Linux
}

/// Effective sshd value: last uncommented assignment wins; `sshd -T`
/// fallback covers Include directives.
fn sshd_effective(ctx: &mut ScanContext, key: &str, log: &mut Vec<FallbackAttempt>) -> Option<String> {
    if let Some(conf) = ctx.read("/etc/ssh/sshd_config") {
        log.push(FallbackAttempt { source: "/etc/ssh/sshd_config".into(), outcome: "read".into() });
        let v = conf
            .lines()
            .map(str::trim_start)
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| l.split_whitespace().next().map(|k| (k, l)))
            .filter(|(k, _)| k.eq_ignore_ascii_case(key))
            .filter_map(|(_, l)| l.split_whitespace().nth(1).map(str::to_string))
            .next_back();
        if v.is_some() {
            return v;
        }
    } else {
        log.push(FallbackAttempt { source: "/etc/ssh/sshd_config".into(), outcome: "missing".into() });
    }
    if let Some(out) = ctx.cmd("sshd", &["-T"]) {
        log.push(FallbackAttempt { source: "sshd -T".into(), outcome: "read".into() });
        return out
            .lines()
            .map(|l| l.split_whitespace().collect::<Vec<&str>>())
            .find(|p| p.len() >= 2 && p[0].eq_ignore_ascii_case(key))
            .map(|p| p[1..].join(" "));
    }
    log.push(FallbackAttempt { source: "sshd -T".into(), outcome: "unavailable (needs root or absent)".into() });
    None
}

fn with_log(mut o: CheckOutcome, log: Vec<FallbackAttempt>) -> CheckOutcome {
    if o.fallback_log.is_empty() {
        o.fallback_log = log;
    }
    o
}

fn ssh_absent(ctx: &mut ScanContext) -> bool {
    !ctx.exists("/etc/ssh/sshd_config") && !ctx.exists("/usr/sbin/sshd") && !ctx.exists("/etc/ssh")
}

fn na_no_ssh() -> CheckOutcome {
    CheckOutcome {
        status: crate::model::Status::NotApplicable,
        evidence: "sshd not installed on this host".into(),
        location: String::new(),
        repro: String::new(),
        recommendation_override: None,
        degraded_reason: None,
        fallback_log: Vec::new(),
        evidence_blocks: Vec::new(),
    }
}

fn ssh_kv(ctx: &mut ScanContext, key: &str, good: &[&str], bad: &str) -> CheckOutcome {
    let mut log = Vec::new();
    let block = crate::checks::evidence_at(ctx, "/etc/ssh/sshd_config", key);
    match sshd_effective(ctx, key, &mut log) {
        Some(v) => {
            let loc = "/etc/ssh/sshd_config".to_string();
            let lv = v.to_lowercase();
            if good.iter().any(|g| lv == *g) {
                with_log(with_block(ok(format!("{key} {v}"), loc, format!("sshd -T | grep -i {key}")), block), log)
            } else if lv == bad.to_lowercase() {
                with_log(with_block(nok(format!("{Key} {v} (expected {expect})", Key = key, expect = good.join("/")), loc, format!("sshd -T | grep -i {key}")), block), log)
            } else {
                with_log(with_block(nok(format!("{Key} {v} (expected {expect})", Key = key, expect = good.join("/")), loc, format!("sshd -T | grep -i {key}")), block), log)
            }
        }
        None => {
            if ssh_absent(ctx) {
                return na_no_ssh();
            }
            if log.iter().any(|f| f.source == "/etc/ssh/sshd_config" && f.outcome == "read") {
                degraded(&format!("{key} not explicitly set — OpenSSH default applies; verify default is acceptable"))
            } else {
                err_outcome(log)
            }
        }
    }
}

fn ssh_kv_contains_any(ctx: &mut ScanContext, key: &str, want_any: &[&str]) -> CheckOutcome {
    let mut log = Vec::new();
    match sshd_effective(ctx, key, &mut log) {
        Some(v) => {
            let loc = "/etc/ssh/sshd_config".to_string();
            let has = want_any.iter().any(|w| v.to_lowercase().contains(&w.to_lowercase()));
            if has {
                ok(format!("{key} {v}"), loc, format!("sshd -T | grep -i {key}"))
            } else {
                nok(format!("{Key} {v} (no strong algorithm from {any})", Key = key, any = want_any.join("/")), loc, format!("sshd -T | grep -i {key}"))
            }
        }
        None => {
            if ssh_absent(ctx) {
                return na_no_ssh();
            }
            if log.iter().any(|f| f.outcome == "read") {
                degraded(&format!("{key} not set — OpenSSH defaults apply (modern defaults are strong; verify version)"))
            } else {
                err_outcome(log)
            }
        }
    }
}

fn ssh_num_max(ctx: &mut ScanContext, key: &str, max: u64) -> CheckOutcome {
    let mut log = Vec::new();
    match sshd_effective(ctx, key, &mut log) {
        Some(v) => {
            let n: u64 = v.trim().parse().unwrap_or(u64::MAX);
            let loc = "/etc/ssh/sshd_config".to_string();
            if n <= max {
                ok(format!("{key} {n}"), loc, format!("sshd -T | grep -i {key}"))
            } else {
                nok(format!("{Key} {n} (> {max})", Key = key), loc, format!("sshd -T | grep -i {key}"))
            }
        }
        None => {
            if ssh_absent(ctx) {
                return na_no_ssh();
            }
            if log.iter().any(|f| f.outcome == "read") {
                degraded(&format!("{key} not set — OpenSSH default applies"))
            } else {
                err_outcome(log)
            }
        }
    }
}

fn client_alive(ctx: &mut ScanContext) -> CheckOutcome {
    let mut log = Vec::new();
    let interval = sshd_effective(ctx, "ClientAliveInterval", &mut log)
        .and_then(|v| v.trim().parse::<u64>().ok());
    let count = sshd_effective(ctx, "ClientAliveCountMax", &mut log)
        .and_then(|v| v.trim().parse::<u64>().ok());
    let loc = "/etc/ssh/sshd_config".to_string();
    match (interval, count) {
        (Some(i), Some(c)) => {
            if i <= 900 && c <= 3 {
                ok(format!("ClientAliveInterval {i} / CountMax {c}"), loc, "sshd -T | grep -i clientalive".into())
            } else {
                nok(format!("ClientAliveInterval {i} / CountMax {c} (want <=900/<=3)"), loc, "sshd -T | grep -i clientalive".into())
            }
        }
        (Some(i), None) => {
            if i <= 900 {
                ok(format!("ClientAliveInterval {i}; CountMax default 3"), loc, "sshd -T | grep -i clientalive".into())
            } else {
                nok(format!("ClientAliveInterval {i} too long"), loc, "sshd -T | grep -i clientalive".into())
            }
        }
        _ => degraded("ClientAlive settings absent — OpenSSH defaults never terminate idle sessions (compliant only if enforced elsewhere)"),
    }
}

fn ssh_banner(ctx: &mut ScanContext) -> CheckOutcome {
    let mut log = Vec::new();
    match sshd_effective(ctx, "Banner", &mut log) {
        Some(v) if v != "none" && !v.is_empty() => ok(format!("Banner {v}"), "/etc/ssh/sshd_config".into(), "sshd -T | grep -i banner".into()),
        Some(_) => nok("Banner disabled (none)".into(), "/etc/ssh/sshd_config".into(), "sshd -T | grep -i banner".into()),
        None => {
            if ssh_absent(ctx) {
                return na_no_ssh();
            }
            if log.iter().any(|f| f.outcome == "read") {
                degraded("Banner not set — OpenSSH default (none)")
            } else {
                err_outcome(log)
            }
        }
    }
}
