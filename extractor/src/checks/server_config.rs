//! GEN-SRV: cross-platform server configuration review.
//!
//! These checks review *configuration posture* rather than inventory
//! (GEN-INV) or OS-specific hardening (LIN-*/WIN-*). Every check is
//! read-only, applies to Linux and/or Windows, and declares an ordered
//! fallback chain: an authoritative primary source plus at least one
//! independent read-only fallback. Availability failures always degrade
//! to `DegradedPartial` (via `degraded`/`degraded_from_attempts`), never
//! `Status::Error`; `Error` is reserved for engine/parser invariants.
//!
//! Each function's doc comment names its primary source and fallbacks,
//! and its `applies` predicate. Where a platform's authoritative source
//! is unavailable through the read-only command allowlist, the check
//! documents that and degrades rather than spawning a write-capable tool.

use crate::checks::linux::sysctl_value;
use crate::checks::{
    degraded, degraded_from_attempts, evidence_at, hypervisor_label, in_container, nok,
    not_applicable, ok, on_vm, with_block,
};
use crate::context::ScanContext;
use crate::model::{CheckOutcome, FallbackAttempt, RegisteredCheck};
use crate::platform::{Os, PlatformInfo};

pub fn register(reg: &mut Vec<RegisteredCheck>) {
    use crate::check;
    check!(reg, "GEN-SRV-001", "Time synchronization source configured", "A non-local, authoritative time source (chrony/ntp/timesyncd on Linux; W32Time on Windows) must be configured.", "Hosts without an authoritative clock source drift, breaking Kerberos, TLS validity windows and log correlation.", "Configure approved internal NTP servers (chrony/ntp/timesyncd or W32Time) and monitor drift.", Medium, "Server Config", &["CIS 2.1.1", "CIS 2.1.3"], any, time_sync_source);
    check!(reg, "GEN-SRV-002", "Clock drift bounded", "Observed clock offset must stay within a small bound.", "Large offsets invalidate certificates, Kerberos tickets and audit timelines.", "Investigate chrony/systemd-timesyncd tracking and correct the upstream source.", Medium, "Server Config", &["CIS 2.1.2"], linux, clock_drift);
    check!(reg, "GEN-SRV-003", "DNS resolver redundancy configured", "At least two resolvers must be configured.", "A single resolver is a single point of failure for every name lookup.", "Configure two or more approved resolvers (resolv.conf / resolved.conf / interface DNS).", Medium, "Server Config", &["CIS 2.1.1"], any, dns_redundancy);
    check!(reg, "GEN-SRV-004", "DNS resolvers are not public-only", "At least one configured resolver must be internal/approved.", "Public-only resolution bypasses internal zones and enables data exfiltration via DNS.", "Point hosts at approved internal resolvers; keep public resolvers only as last resort.", Low, "Server Config", &["CIS 2.1.1"], any, dns_not_public_only);
    check!(reg, "GEN-SRV-005", "Default route present", "The host must have a default route.", "A missing default route silently breaks updates, agent check-in and time sync.", "Restore the default gateway / DHCP default route.", Medium, "Server Config", &["CIS 3.1"], any, default_route);
    check!(reg, "GEN-SRV-006", "No pending reboot indicators", "No pending-reboot markers should be outstanding.", "A pending reboot leaves patched binaries unloaded and vulnerabilities exploitable until reboot.", "Schedule and perform the pending reboot; verify markers clear.", Low, "Server Config", &["CIS 1.9"], any, pending_reboot);
    check!(reg, "GEN-SRV-007", "OS build within vendor support", "Windows build must be at or above the minimum supported build.", "Unsupported builds receive no security fixes and are permanently exposed.", "Upgrade to a supported Windows release.", High, "Server Config", &["CIS 1.1"], windows, os_build_support);
    check!(reg, "GEN-SRV-008", "Automatic security updates enabled", "Unattended security updates must be enabled.", "Manual-only patching drifts and leaves known CVEs unpatched.", "Enable unattended-upgrades / dnf-automatic / Windows Update AU policy.", High, "Server Config", &["CIS 1.9"], any, auto_updates);
    check!(reg, "GEN-SRV-009", "Legacy TLS/SSL protocols disabled", "SSL 2.0/3.0 and TLS 1.0/1.1 must be disabled at the stack level.", "Legacy protocol versions are vulnerable to downgrade and padding-oracle attacks.", "Disable legacy SCHANNEL protocols / set MinProtocol=TLSv1.2+.", Medium, "Server Config", &["CIS 3.6"], any, tls_legacy);
    check!(reg, "GEN-SRV-010", "Certificate trust store is current", "The system CA bundle must be refreshed within the last year.", "A stale trust store trusts revoked CAs and misses new roots.", "Update ca-certificates / ca-bundle from the vendor.", Medium, "Server Config", &["CIS 3.6"], linux, cert_inventory);
    check!(reg, "GEN-SRV-011", "Backup agent configured", "A known backup agent must be configured and running.", "Unverified backups turn incidents into total data loss.", "Deploy and monitor a supported backup agent; verify last success.", Medium, "Server Config", &["CIS 11.1", "CIS 11.2"], any, backup_agent);
    check!(reg, "GEN-SRV-012", "Log retention bounds configured", "Security log retention must cover the incident-response window.", "Short retention erases the evidence needed to scope a breach.", "Retain security logs 90+ days (logrotate rotate>=13 or EventLog MaxSize/retention).", Medium, "Server Config", &["CIS 4.2.4", "CIS 8.3"], any, log_retention);
    check!(reg, "GEN-SRV-013", "Remote log forwarding configured", "Security logs must be forwarded off-host.", "Local-only logs die with the machine and are trivially wiped by an intruder.", "Forward rsyslog/journald or Windows Event Log to a central collector.", Medium, "Server Config", &["CIS 8.1", "CIS 8.2"], any, remote_log_forwarding);
    check!(reg, "GEN-SRV-014", "Firewall default-deny posture", "All firewall profiles/subsystems must deny inbound by default.", "An allow-by-default firewall exposes every listening service.", "Set default inbound deny/block on every profile and subsystem.", High, "Server Config", &["CIS 3.5"], any, firewall_default_deny);
    check!(reg, "GEN-SRV-015", "Management listeners bound to expected interfaces", "SSH/WinRM listeners should not be bound to wildcard addresses.", "Wildcard management listeners expose remote administration on every interface.", "Bind sshd ListenAddress / WinRM listeners to specific management interfaces.", Medium, "Server Config", &["CIS 5.2", "CIS 2.2"], any, mgmt_listener_binding);
    check!(reg, "GEN-SRV-016", "Service accounts hold no privileged group membership", "Service accounts must not be members of privileged groups.", "A compromised service account with admin rights is an immediate domain/host takeover.", "Remove service accounts from sudo/wheel/Administrators; scope with least privilege.", Low, "Server Config", &["CIS 6.2"], any, service_account_privilege);
    check!(reg, "GEN-SRV-017", "Password and lockout policy present", "Both a password-complexity policy and an account-lockout policy must exist.", "Weak or unbounded passwords enable brute force; no lockout enables infinite attempts.", "Configure pwquality minlen + faillock deny (or Windows minimum length + lockout threshold).", Medium, "Server Config", &["CIS 5.3"], any, password_lockout_presence);
    check!(reg, "GEN-SRV-018", "sudo / UAC policy present", "Privilege elevation must be mediated and logged.", "Unmediated elevation hides administrative actions and weakens accountability.", "Keep sudoers Defaults hardening / UAC (EnableLUA) enabled.", Medium, "Server Config", &["CIS 1.3", "CIS 2.3.1.1"], any, sudo_uac_presence);
    check!(reg, "GEN-SRV-019", "Secure Boot and TPM posture summary", "Secure Boot should be enabled and a TPM present (summary only).", "Without Secure Boot/TPM, boot-chain and disk-integrity protections are unavailable.", "Enable Secure Boot and provision TPM 2.0 (detail owned by GEN-INV-012/013).", Low, "Server Config", &[], any, secureboot_tpm_summary);
    check!(reg, "GEN-SRV-020", "Kernel hardlink/symlink protections enabled", "fs.protected_* sysctls must be enabled.", "Without protected hardlinks/symlinks, sticky-directory link attacks overwrite privileged files.", "Set fs.protected_hardlinks/symlinks/fifos/regular to their hardened values.", Medium, "Server Config", &["CIS 1.1.18", "CIS 1.1.19"], linux, kernel_link_protection);
    check!(reg, "GEN-SRV-021", "System mounts have adequate free space", "System filesystems must not be near capacity.", "A full system filesystem halts logging, updates and the audit trail.", "Free space or expand the affected system mount; alert below 15% free.", Medium, "Server Config", &["CIS 1.1"], any, disk_free);
    check!(reg, "GEN-SRV-022", "Swap / pagefile configured", "A swap device or pagefile should be configured.", "No swap/pagefile turns memory pressure into process kills and OOM instability.", "Configure a sized swap device / pagefile (or document an intentional no-swap design).", Low, "Server Config", &["CIS 1.1.10"], any, swap_pagefile);
    check!(reg, "GEN-SRV-023", "Core security services enabled", "Core security services must be running/enabled.", "Disabled audit, logging, time or update services silently remove controls.", "Enable auditd/rsyslog/chronyd (or WinDefend/EventLog/wuauserv/w32time).", Medium, "Server Config", &["CIS 4.1", "CIS 4.2"], any, core_services);
    check!(reg, "GEN-SRV-024", "LDAP / Kerberos client configuration present", "Directory/Kerberos client configuration must be complete when deployed.", "Malformed realm/domain configuration breaks authentication and can silently fall back to local accounts.", "Complete krb5.conf default_realm / sssd or rejoin the Windows domain.", Low, "Server Config", &["CIS 6.1"], any, ldap_kerberos_config);
}

// ---- applicability predicates --------------------------------------------

fn any(_: &PlatformInfo) -> bool {
    true
}
fn linux(p: &PlatformInfo) -> bool {
    p.os == Os::Linux
}
fn windows(p: &PlatformInfo) -> bool {
    p.os == Os::Windows
}

// ---- shared helpers ------------------------------------------------------

fn att(source: &str, outcome: impl Into<String>) -> FallbackAttempt {
    FallbackAttempt { source: source.into(), outcome: outcome.into() }
}

/// Attempt a command, appending the ordered fallback-log entry.
fn cmd_log(
    ctx: &mut ScanContext,
    log: &mut Vec<FallbackAttempt>,
    program: &str,
    args: &[&str],
) -> Option<String> {
    let label = if args.is_empty() {
        program.to_string()
    } else {
        format!("{program} {}", args.join(" "))
    };
    match ctx.cmd(program, args) {
        Some(o) => {
            log.push(att(&label, "read"));
            Some(o)
        }
        None => {
            log.push(att(&label, "unavailable"));
            None
        }
    }
}

/// First readable path among candidates, logging each miss.
fn read_first(
    ctx: &mut ScanContext,
    log: &mut Vec<FallbackAttempt>,
    paths: &[&str],
) -> Option<(String, String)> {
    for p in paths {
        match ctx.read(p) {
            Some(text) => {
                log.push(att(p, "read"));
                return Some(((*p).to_string(), text));
            }
            None => log.push(att(p, "missing or unreadable")),
        }
    }
    None
}

/// `reg query` output value for `name` (REG_* line), trimmed.
fn reg_val(output: &str, name: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let line = line.trim();
        if line.len() < name.len() {
            return None;
        }
        let (head, rest) = line.split_at(name.len());
        if !head.eq_ignore_ascii_case(name) {
            return None;
        }
        let mut fields = rest.trim_start().split_whitespace();
        let kind = fields.next()?;
        if !kind.starts_with("REG_") {
            return None;
        }
        let value = fields.collect::<Vec<_>>().join(" ");
        Some(value)
    })
}

/// Parse a decimal or `0x`-prefixed integer from loose command output.
fn parse_num(s: &str) -> Option<u64> {
    let token = s.split_whitespace().find(|t| {
        t.starts_with("0x") || t.starts_with("0X") || t.chars().all(|c| c.is_ascii_digit())
    })?;
    if let Some(hex) = token.strip_prefix("0x").or_else(|| token.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        token.parse().ok()
    }
}

/// Build a NonCompliant outcome carrying the pinpoint block at `needle`.
fn nok_at(
    ctx: &mut ScanContext,
    path: &str,
    needle: &str,
    evidence: String,
    repro: String,
) -> CheckOutcome {
    let block = evidence_at(ctx, path, needle);
    with_block(nok(evidence, path.to_string(), repro), block)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn is_local_time_source(s: &str) -> bool {
    let s = s.trim().to_ascii_lowercase();
    s.is_empty()
        || s.starts_with("127.")
        || s == "localhost"
        || s == "::1"
        || s == "0.0.0.0"
}

fn is_public_dns(ip: &str) -> bool {
    let ip = ip.trim().to_ascii_lowercase();
    matches!(
        ip.as_str(),
        "8.8.8.8"
            | "8.8.4.4"
            | "1.1.1.1"
            | "1.0.0.1"
            | "9.9.9.9"
            | "149.112.112.112"
            | "208.67.222.222"
            | "208.67.220.220"
            | "64.6.64.6"
            | "64.6.65.6"
            | "77.88.8.8"
            | "77.88.8.1"
            | "156.154.70.1"
            | "156.154.71.1"
            | "114.114.114.114"
            | "8.26.56.26"
            | "8.20.247.20"
            | "84.200.69.80"
            | "84.200.70.40"
            | "76.76.2.0"
            | "76.76.19.61"
            | "94.140.14.14"
            | "94.140.15.15"
            | "185.228.168.9"
            | "185.228.169.9"
            | "205.171.3.65"
            | "205.171.2.65"
            | "2001:4860:4860::8888"
            | "2001:4860:4860::8844"
            | "2606:4700:4700::1111"
            | "2606:4700:4700::1001"
    )
}

fn looks_like_ipv4(token: &str) -> bool {
    let t = token.trim_matches(|c: char| !c.is_ascii_hexdigit() && c != '.');
    let parts: Vec<&str> = t.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 3 && p.parse::<u16>().map(|v| v <= 255).unwrap_or(false))
}

/// Pull IPv4 resolver tokens out of `netsh ... show dns` output.
fn netsh_dns_servers(out: &str) -> Vec<String> {
    let mut v = Vec::new();
    for tok in out.split_whitespace() {
        if looks_like_ipv4(tok) {
            let t = tok
                .trim_matches(|c: char| !c.is_ascii_hexdigit() && c != '.')
                .to_string();
            if !v.contains(&t) {
                v.push(t);
            }
        }
    }
    v
}

fn systemd_unit_good(v: &str) -> bool {
    matches!(
        v.trim(),
        "enabled" | "enabled-runtime" | "static" | "indirect" | "alias"
    )
}

fn sc_state(out: &str) -> Option<&'static str> {
    if out.contains("RUNNING") {
        Some("running")
    } else if out.contains("STOPPED") {
        Some("stopped")
    } else {
        None
    }
}

// ---- 001: time synchronization source ------------------------------------

/// Primary: chrony/ntp/timesyncd config files (`server`/`pool`/`NTP=`).
/// Fallback: `timedatectl show` then `chronyc sources`.
/// Windows primary: W32Time `Parameters` (Type/NtpServer) registry.
/// Windows fallback: NtpClient `Enabled`, then `sc query w32time`.
fn time_sync_source(ctx: &mut ScanContext) -> CheckOutcome {
    let mut log = Vec::new();
    if ctx.linux() {
        let candidates = [
            "/etc/chrony.conf",
            "/etc/chrony/chrony.conf",
            "/etc/ntp.conf",
            "/etc/systemd/timesyncd.conf",
        ];
        if let Some((path, text)) = read_first(ctx, &mut log, &candidates) {
            let mut sources: Vec<String> = Vec::new();
            for line in text.lines() {
                let l = line.trim();
                if l.is_empty() || l.starts_with('#') || l.starts_with(';') {
                    continue;
                }
                let lower = l.to_ascii_lowercase();
                if let Some(rest) = lower.strip_prefix("server").or_else(|| lower.strip_prefix("pool")) {
                    if let Some(tok) = rest.trim().split_whitespace().next() {
                        sources.push(tok.to_string());
                    }
                } else if let Some(rest) = l.strip_prefix("NTP=").or_else(|| l.strip_prefix("FallbackNTP=")) {
                    for tok in rest.split_whitespace() {
                        sources.push(tok.to_string());
                    }
                }
            }
            if sources.iter().any(|s| !is_local_time_source(s)) {
                return ok(
                    format!("time sources: {}", sources.join(", ")),
                    path,
                    "grep -E '^(server|pool|NTP)' /etc/chrony.conf".into(),
                );
            }
            if !sources.is_empty() {
                return nok_at(
                    ctx,
                    &path,
                    &sources[0],
                    format!("only local time sources configured: {}", sources.join(", ")),
                    "grep -E '^(server|pool)' /etc/chrony.conf".into(),
                );
            }
            return nok(
                format!("{path} present but no server/pool time source configured"),
                path,
                "grep -E '^(server|pool)' /etc/chrony.conf".into(),
            );
        }
        if let Some(out) = cmd_log(ctx, &mut log, "timedatectl", &["show", "--property=NTPSynchronized,ServerAddress"]) {
            let addr = out
                .lines()
                .find_map(|l| l.strip_prefix("ServerAddress="))
                .unwrap_or("")
                .trim()
                .to_string();
            if !addr.is_empty() && !is_local_time_source(&addr) {
                return ok(format!("systemd-timesyncd server {addr}"), "timedatectl".into(), "timedatectl show".into());
            }
        }
        if let Some(out) = cmd_log(ctx, &mut log, "chronyc", &["sources"]) {
            let has_server = out.lines().any(|l| l.contains("^*") || l.contains("^+"));
            if has_server {
                return ok("chronyc reports a selected synchronised source".into(), "chronyc sources".into(), "chronyc sources".into());
            }
        }
        return degraded_from_attempts(log, "no authoritative time source found in config or live queries");
    }
    // Windows
    if let Some(out) = cmd_log(ctx, &mut log, "reg", &["query", r"HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters", "/v", "Type"]) {
        let t = reg_val(&out, "Type").unwrap_or_default();
        let ntp = cmd_log(ctx, &mut log, "reg", &["query", r"HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters", "/v", "NtpServer"])
            .and_then(|o| reg_val(&o, "NtpServer"))
            .unwrap_or_default();
        let good_type = matches!(t.trim(), "NTP" | "AllSync" | "NT5DS" | "NTP5" | "DOMHIER");
        if good_type && !ntp.trim().is_empty() {
            return ok(format!("W32Time Type={} NtpServer={}", t.trim(), ntp.trim()), "W32Time Parameters".into(), "reg query W32Time\\Parameters".into());
        }
        if matches!(t.trim(), "NoSync" | "Local") {
            return nok(
                format!("W32Time Type={} (no external source)", t.trim()),
                "W32Time Parameters".into(),
                "reg query W32Time\\Parameters /v Type".into(),
            );
        }
    }
    if let Some(out) = cmd_log(ctx, &mut log, "reg", &["query", r"HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient", "/v", "Enabled"]) {
        if let Some(v) = reg_val(&out, "Enabled") {
            if parse_num(&v) == Some(1) {
                return ok("W32Time NtpClient enabled".into(), "NtpClient".into(), "reg query W32Time\\TimeProviders\\NtpClient".into());
            }
            return nok("W32Time NtpClient disabled".into(), "NtpClient".into(), "reg query W32Time\\TimeProviders\\NtpClient /v Enabled".into());
        }
    }
    if let Some(out) = cmd_log(ctx, &mut log, "sc", &["query", "w32time"]) {
        match sc_state(&out) {
            Some("running") => return ok("w32time service running".into(), "w32time".into(), "sc query w32time".into()),
            Some(_) => return nok("w32time service not running".into(), "w32time".into(), "sc query w32time".into()),
            None => {}
        }
    }
    degraded_from_attempts(log, "time-source configuration not readable on Windows")
}

// ---- 002: clock drift -----------------------------------------------------

/// Primary: `chronyc tracking` (System time / Leap status).
/// Fallback: `timedatectl status`, then `timedatectl show NTPSynchronized`.
fn clock_drift(ctx: &mut ScanContext) -> CheckOutcome {
    let mut log = Vec::new();
    if let Some(out) = cmd_log(ctx, &mut log, "chronyc", &["tracking"]) {
        let offset = out
            .lines()
            .find(|l| l.trim_start().to_ascii_lowercase().starts_with("system time"))
            .and_then(|l| l.split_whitespace().nth(3))
            .and_then(|s| s.parse::<f64>().ok());
        let leap_ok = out
            .lines()
            .find(|l| l.trim_start().to_ascii_lowercase().starts_with("leap status"))
            .map(|l| l.to_ascii_lowercase().contains("normal"))
            .unwrap_or(true);
        if let Some(off) = offset {
            if off.abs() <= 1.0 && leap_ok {
                return ok(format!("chrony offset {off:.3}s (within 1s)"), "chronyc tracking".into(), "chronyc tracking".into());
            }
            return nok(format!("chrony offset {off:.3}s exceeds 1s bound"), "chronyc tracking".into(), "chronyc tracking".into());
        }
    }
    if let Some(out) = cmd_log(ctx, &mut log, "timedatectl", &["status"]) {
        let synced = out
            .lines()
            .find(|l| l.to_ascii_lowercase().contains("system clock synchronized"))
            .map(|l| l.to_ascii_lowercase().contains("yes"));
        match synced {
            Some(true) => return ok("system clock synchronized".into(), "timedatectl".into(), "timedatectl status".into()),
            Some(false) => return nok("system clock not synchronized".into(), "timedatectl".into(), "timedatectl status".into()),
            None => {}
        }
    }
    if let Some(out) = cmd_log(ctx, &mut log, "timedatectl", &["show", "--property=NTPSynchronized"]) {
        if out.to_ascii_lowercase().contains("ntpsynchronized=yes") {
            return ok("NTP synchronized (timedatectl)".into(), "timedatectl".into(), "timedatectl show".into());
        }
        return nok("NTP not synchronized (timedatectl)".into(), "timedatectl".into(), "timedatectl show".into());
    }
    degraded_from_attempts(log, "clock offset not observable (chrony/timedatectl unavailable)")
}

// ---- 003: DNS resolver redundancy ----------------------------------------

/// Linux primary: `/etc/resolv.conf` `nameserver` count.
/// Linux fallback: `/etc/systemd/resolved.conf` `DNS=`.
/// Windows primary: `netsh interface ip show dns`.
/// Windows fallback: Tcpip `NameServer`/`DhcpNameServer` registry.
fn dns_redundancy(ctx: &mut ScanContext) -> CheckOutcome {
    let mut log = Vec::new();
    if ctx.linux() {
        if let Some(resolv) = ctx.read("/etc/resolv.conf") {
            log.push(att("/etc/resolv.conf", "read"));
            let servers: Vec<&str> = resolv
                .lines()
                .filter_map(|l| l.strip_prefix("nameserver "))
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            if servers.len() >= 2 {
                return ok(format!("{} resolvers: {}", servers.len(), servers.join(", ")), "/etc/resolv.conf".into(), "cat /etc/resolv.conf".into());
            }
            if servers.len() == 1 {
                return nok_at(ctx, "/etc/resolv.conf", "nameserver", format!("only one resolver configured: {}", servers[0]), "cat /etc/resolv.conf".into());
            }
            return nok("no resolvers configured in /etc/resolv.conf".into(), "/etc/resolv.conf".into(), "cat /etc/resolv.conf".into());
        }
        log.push(att("/etc/resolv.conf", "missing"));
        if let Some(conf) = ctx.read("/etc/systemd/resolved.conf") {
            log.push(att("/etc/systemd/resolved.conf", "read"));
            let servers: Vec<&str> = conf
                .lines()
                .filter(|l| l.trim_start().to_ascii_uppercase().starts_with("DNS="))
                .flat_map(|l| l.split('=').nth(1).unwrap_or("").split_whitespace())
                .collect();
            if servers.len() >= 2 {
                return ok(format!("{} resolvers in resolved.conf", servers.len()), "/etc/systemd/resolved.conf".into(), "cat /etc/systemd/resolved.conf".into());
            }
            if servers.len() == 1 {
                return nok_at(ctx, "/etc/systemd/resolved.conf", "DNS=", format!("only one resolver: {}", servers[0]), "cat /etc/systemd/resolved.conf".into());
            }
        } else {
            log.push(att("/etc/systemd/resolved.conf", "missing"));
        }
        return degraded_from_attempts(log, "resolver configuration unreadable");
    }
    if let Some(out) = cmd_log(ctx, &mut log, "netsh", &["interface", "ip", "show", "dns"]) {
        let servers = netsh_dns_servers(&out);
        if servers.len() >= 2 {
            return ok(format!("{} resolvers: {}", servers.len(), servers.join(", ")), "netsh".into(), "netsh interface ip show dns".into());
        }
        if servers.len() == 1 {
            return nok(format!("only one resolver configured: {}", servers[0]), "netsh".into(), "netsh interface ip show dns".into());
        }
    }
    if let Some(out) = cmd_log(ctx, &mut log, "reg", &["query", r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "/v", "NameServer"]) {
        let v = reg_val(&out, "NameServer").unwrap_or_default();
        let servers: Vec<&str> = v.split([',', ' ']).filter(|s| !s.is_empty()).collect();
        if servers.len() >= 2 {
            return ok(format!("{} static resolvers", servers.len()), "Tcpip\\Parameters".into(), "reg query Tcpip\\Parameters".into());
        }
        if servers.len() == 1 {
            return nok(format!("only one static resolver: {}", servers[0]), "Tcpip\\Parameters".into(), "reg query Tcpip\\Parameters".into());
        }
    }
    degraded_from_attempts(log, "Windows resolver configuration unreadable")
}

// ---- 004: DNS not public-only --------------------------------------------

/// Linux primary: `/etc/resolv.conf`; fallback `/etc/systemd/resolved.conf`.
/// Windows primary: `netsh interface ip show dns`.
fn dns_not_public_only(ctx: &mut ScanContext) -> CheckOutcome {
    let mut log = Vec::new();
    if ctx.linux() {
        let mut servers: Vec<String> = Vec::new();
        let mut source = "";
        if let Some(resolv) = ctx.read("/etc/resolv.conf") {
            log.push(att("/etc/resolv.conf", "read"));
            source = "/etc/resolv.conf";
            servers = resolv
                .lines()
                .filter_map(|l| l.strip_prefix("nameserver "))
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        } else {
            log.push(att("/etc/resolv.conf", "missing"));
            if let Some(conf) = ctx.read("/etc/systemd/resolved.conf") {
                log.push(att("/etc/systemd/resolved.conf", "read"));
                source = "/etc/systemd/resolved.conf";
                servers = conf
                    .lines()
                    .filter(|l| l.trim_start().to_ascii_uppercase().starts_with("DNS="))
                    .flat_map(|l| l.split('=').nth(1).unwrap_or("").split_whitespace())
                    .map(str::to_string)
                    .collect();
            } else {
                log.push(att("/etc/systemd/resolved.conf", "missing"));
            }
        }
        if servers.is_empty() {
            return degraded_from_attempts(log, "no resolvers found to evaluate");
        }
        if servers.iter().any(|s| !is_public_dns(s)) {
            return ok(format!("non-public resolver present: {}", servers.join(", ")), source.into(), "cat /etc/resolv.conf".into());
        }
        let needle = if source == "/etc/resolv.conf" { "nameserver" } else { "DNS=" };
        return nok_at(ctx, source, needle, format!("all resolvers are public: {}", servers.join(", ")), "cat /etc/resolv.conf".into());
    }
    if let Some(out) = cmd_log(ctx, &mut log, "netsh", &["interface", "ip", "show", "dns"]) {
        let servers = netsh_dns_servers(&out);
        if servers.is_empty() {
            return degraded_from_attempts(log, "no resolvers parsed from netsh output");
        }
        if servers.iter().any(|s| !is_public_dns(s)) {
            return ok(format!("non-public resolver present: {}", servers.join(", ")), "netsh".into(), "netsh interface ip show dns".into());
        }
        return nok(format!("all resolvers are public: {}", servers.join(", ")), "netsh".into(), "netsh interface ip show dns".into());
    }
    degraded_from_attempts(log, "resolver configuration unreadable")
}

// ---- 005: default route ---------------------------------------------------

/// Linux primary: `/proc/net/route` (Destination 00000000, live gateway).
/// Linux fallback: `ip route show default`.
/// Windows primary: `route print`; fallback `netsh interface ipv4 show route`.
fn default_route(ctx: &mut ScanContext) -> CheckOutcome {
    let mut log = Vec::new();
    if ctx.linux() {
        if let Some(routes) = ctx.read("/proc/net/route") {
            log.push(att("/proc/net/route", "read"));
            let has_default = routes.lines().skip(1).any(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                f.len() >= 3 && f[1] == "00000000" && f[2] != "00000000"
            });
            if has_default {
                return ok("default route present (/proc/net/route)".into(), "/proc/net/route".into(), "cat /proc/net/route".into());
            }
            return nok("no default route in /proc/net/route".into(), "/proc/net/route".into(), "cat /proc/net/route".into());
        }
        log.push(att("/proc/net/route", "missing"));
        if let Some(out) = cmd_log(ctx, &mut log, "ip", &["route", "show", "default"]) {
            if out.lines().any(|l| l.trim_start().starts_with("default")) {
                return ok(format!("default route: {}", out.lines().next().unwrap_or("").trim()), "ip route".into(), "ip route show default".into());
            }
            return nok("no default route reported by ip route".into(), "ip route".into(), "ip route show default".into());
        }
        return degraded_from_attempts(log, "routing table unreadable");
    }
    if let Some(out) = cmd_log(ctx, &mut log, "route", &["print"]) {
        let has_default = out.lines().any(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            f.len() >= 3 && f[0] == "0.0.0.0" && f[1] == "0.0.0.0" && f[2] != "0.0.0.0"
        });
        if has_default {
            return ok("default route present (route print)".into(), "route print".into(), "route print".into());
        }
        return nok("no default route in route print".into(), "route print".into(), "route print".into());
    }
    if let Some(out) = cmd_log(ctx, &mut log, "netsh", &["interface", "ipv4", "show", "route"]) {
        if out.contains("0.0.0.0/0") {
            return ok("default route present (netsh)".into(), "netsh".into(), "netsh interface ipv4 show route".into());
        }
        return nok("no default route reported by netsh".into(), "netsh".into(), "netsh interface ipv4 show route".into());
    }
    degraded_from_attempts(log, "routing table unreadable")
}

// ---- 006: pending reboot --------------------------------------------------

/// Linux primary: `/run/reboot-required` / `/var/run/reboot-required`.
/// Linux fallback: `/run/reboot-required.pkgs`.
/// Windows primary: CBS `RebootPending` key + Session Manager
/// `PendingFileRenameOperations`; fallback PowerShell `Test-Path`.
fn pending_reboot(ctx: &mut ScanContext) -> CheckOutcome {
    let mut log = Vec::new();
    if ctx.linux() {
        for p in ["/run/reboot-required", "/var/run/reboot-required"] {
            if let Some(text) = ctx.read(p) {
                log.push(att(p, "present"));
                let needle = text
                    .lines()
                    .find(|l| !l.trim().is_empty())
                    .map(str::to_string)
                    .unwrap_or_else(|| "reboot-required".to_string());
                return nok_at(ctx, p, &needle, format!("pending reboot marker present ({p})"), format!("ls {p}"));
            }
            log.push(att(p, "absent"));
        }
        if let Some(text) = ctx.read("/run/reboot-required.pkgs") {
            log.push(att("/run/reboot-required.pkgs", "present"));
            let needle = text.lines().next().unwrap_or("reboot").to_string();
            return nok_at(ctx, "/run/reboot-required.pkgs", &needle, "pending reboot package list present".into(), "cat /run/reboot-required.pkgs".into());
        }
        log.push(att("/run/reboot-required.pkgs", "absent"));
        // Absence of the marker is authoritative only when /run exists.
        if ctx.exists("/run") || ctx.exists("/var/run") {
            return ok("no pending-reboot marker present".into(), "/run/reboot-required".into(), "test -f /run/reboot-required".into());
        }
        return degraded_from_attempts(log, "cannot determine reboot state (/run absent)");
    }
    let cbs = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending";
    let sm = r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager";
    let mut saw_any = false;
    if let Some(out) = cmd_log(ctx, &mut log, "reg", &["query", cbs]) {
        saw_any = true;
        if !out.trim().is_empty() {
            return nok("CBS RebootPending key present".into(), cbs.into(), format!("reg query \"{cbs}\""));
        }
    }
    if let Some(out) = cmd_log(ctx, &mut log, "reg", &["query", sm, "/v", "PendingFileRenameOperations"]) {
        saw_any = true;
        let v = reg_val(&out, "PendingFileRenameOperations").unwrap_or_default();
        if !v.trim().is_empty() {
            return nok("PendingFileRenameOperations present".into(), sm.into(), format!("reg query \"{sm}\" /v PendingFileRenameOperations"));
        }
    }
    if !saw_any {
        if let Some(out) = cmd_log(ctx, &mut log, "powershell", &["-NoProfile", "-NonInteractive", "-Command", &format!("(Test-Path 'Registry::{cbs}')")]) {
            if out.trim().eq_ignore_ascii_case("true") {
                return nok("CBS RebootPending key present".into(), cbs.into(), format!("Test-Path 'Registry::{cbs}'"));
            }
            return ok("no pending-reboot indicator".into(), "Test-Path".into(), format!("Test-Path 'Registry::{cbs}'"));
        }
        return degraded_from_attempts(log, "reboot indicators unreadable");
    }
    ok("no pending-reboot indicator found".into(), "registry".into(), "reg query CBS/Session Manager".into())
}

// ---- 007: OS build support ------------------------------------------------

/// Primary: `CurrentBuildNumber` registry.
/// Fallback: `systeminfo` OS Version line.
fn os_build_support(ctx: &mut ScanContext) -> CheckOutcome {
    let mut log = Vec::new();
    const KEY: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    if let Some(out) = cmd_log(ctx, &mut log, "reg", &["query", KEY, "/v", "CurrentBuildNumber"]) {
        if let Some(build) = reg_val(&out, "CurrentBuildNumber").and_then(|v| parse_num(&v)) {
            let product = cmd_log(ctx, &mut log, "reg", &["query", KEY, "/v", "ProductName"])
                .and_then(|o| reg_val(&o, "ProductName"))
                .unwrap_or_default();
            if build >= 17763 {
                return ok(format!("build {build} ({product}) is supported"), KEY.into(), "reg query CurrentVersion".into());
            }
            return nok(format!("build {build} ({product}) is below the supported floor (17763)"), KEY.into(), "reg query CurrentVersion".into());
        }
    }
    if let Some(out) = cmd_log(ctx, &mut log, "systeminfo", &[]) {
        for line in out.lines() {
            if line.to_ascii_lowercase().contains("os version") {
                if let Some(build) = line.split_whitespace().filter_map(|t| t.parse::<u64>().ok()).max() {
                    if build >= 17763 {
                        return ok(format!("build {build} supported (systeminfo)"), "systeminfo".into(), "systeminfo".into());
                    }
                    return nok(format!("build {build} below supported floor (systeminfo)"), "systeminfo".into(), "systeminfo".into());
                }
            }
        }
    }
    degraded_from_attempts(log, "Windows build not readable")
}

// ---- 008: automatic security updates -------------------------------------

/// Linux primary: unattended-upgrades / dnf-automatic / yum-cron config.
/// Linux fallback: `systemctl is-enabled unattended-upgrades|dnf-automatic.timer`.
/// Windows primary: Windows Update AU policy (`NoAutoUpdate`/`AUOptions`).
/// Windows fallback: `sc qc wuauserv` start type.
fn auto_updates(ctx: &mut ScanContext) -> CheckOutcome {
    let mut log = Vec::new();
    if ctx.linux() {
        let candidates = [
            "/etc/apt/apt.conf.d/20auto-upgrades",
            "/etc/dnf/automatic.conf",
            "/etc/yum/yum-cron.conf",
            "/etc/yum/yum-cron-hourly.conf",
        ];
        if let Some((path, text)) = read_first(ctx, &mut log, &candidates) {
            let lower = text.to_ascii_lowercase();
            let enabled = lower.contains("unattended-upgrade \"1\"")
                || lower.contains("apply_updates = yes")
                || lower.contains("apply_updates=yes")
                || lower.contains("upgrade_type = security")
                || lower.contains("download_updates = yes");
            let disabled = lower.contains("unattended-upgrade \"0\"")
                || lower.contains("apply_updates = no")
                || lower.contains("apply_updates=no");
            if enabled {
                return ok(format!("automatic security updates enabled in {path}"), path.clone(), format!("grep -iE 'unattended|apply_updates' {path}"));
            }
            if disabled {
                let needle = if lower.contains("unattended") { "Unattended-Upgrade" } else { "apply_updates" };
                return nok_at(ctx, &path, needle, format!("automatic updates explicitly disabled in {path}"), format!("grep -iE 'unattended|apply_updates' {path}"));
            }
            return degraded(&format!("{path} present but no enable/disable directive parsed"));
        }
        for unit in ["unattended-upgrades", "dnf-automatic.timer", "yum-cron"] {
            if let Some(out) = cmd_log(ctx, &mut log, "systemctl", &["is-enabled", unit]) {
                if systemd_unit_good(&out) {
                    return ok(format!("{unit} enabled at boot"), "systemctl".into(), format!("systemctl is-enabled {unit}"));
                }
                if out.trim() == "disabled" || out.trim() == "masked" {
                    return nok(format!("{unit} is {}", out.trim()), "systemctl".into(), format!("systemctl is-enabled {unit}"));
                }
            }
        }
        return degraded_from_attempts(log, "automatic-update configuration not found");
    }
    const AU: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";
    if let Some(out) = cmd_log(ctx, &mut log, "reg", &["query", AU, "/v", "NoAutoUpdate"]) {
        if let Some(v) = reg_val(&out, "NoAutoUpdate").and_then(|s| parse_num(&s)) {
            if v == 0 {
                let opts = cmd_log(ctx, &mut log, "reg", &["query", AU, "/v", "AUOptions"]).and_then(|o| reg_val(&o, "AUOptions")).and_then(|s| parse_num(&s));
                if opts.map(|o| o >= 3).unwrap_or(true) {
                    return ok(format!("Windows Update AU enabled (AUOptions={})", opts.map(|o| o.to_string()).unwrap_or_else(|| "auto".into())), AU.into(), "reg query WindowsUpdate\\AU".into());
                }
                return nok(format!("AUOptions={} does not auto-install", opts.unwrap_or(0)), AU.into(), "reg query WindowsUpdate\\AU".into());
            }
            return nok("NoAutoUpdate=1 disables automatic updates".into(), AU.into(), "reg query WindowsUpdate\\AU /v NoAutoUpdate".into());
        }
    }
    if let Some(out) = cmd_log(ctx, &mut log, "sc", &["qc", "wuauserv"]) {
        let lower = out.to_ascii_lowercase();
        if lower.contains("auto_start") || lower.contains("auto start") {
            return ok("wuauserv set to Automatic start".into(), "wuauserv".into(), "sc qc wuauserv".into());
        }
        if lower.contains("demand_start") || lower.contains("disabled") {
            return nok("wuauserv is not set to Automatic start".into(), "wuauserv".into(), "sc qc wuauserv".into());
        }
    }
    degraded_from_attempts(log, "automatic-update policy unreadable")
}

// ---- 009: legacy TLS/SSL --------------------------------------------------

/// Windows primary: SCHANNEL `Protocols\<ver>\Server\Enabled`.
/// Windows fallback: enumerate SCHANNEL `Protocols` subkeys.
/// Linux primary: `/etc/ssl/openssl.cnf` MinProtocol/CipherString.
/// Linux fallback: `/etc/crypto-policies/config` (RHEL family).
fn tls_legacy(ctx: &mut ScanContext) -> CheckOutcome {
    let mut log = Vec::new();
    if ctx.linux() {
        if let Some((path, text)) = read_first(ctx, &mut log, &["/etc/ssl/openssl.cnf", "/etc/pki/tls/openssl.cnf"]) {
            let lower = text.to_ascii_lowercase();
            if let Some(idx) = lower.find("minprotocol") {
                let line = text[idx..].lines().next().unwrap_or("");
                let val = line.split('=').nth(1).unwrap_or("").trim().to_ascii_lowercase();
                if val.contains("tlsv1.2") || val.contains("tlsv1.3") {
                    return ok(format!("MinProtocol={val}"), path.clone(), format!("grep -i MinProtocol {path}"));
                }
                if !val.is_empty() {
                    return nok_at(ctx, &path, "MinProtocol", format!("legacy MinProtocol={val}"), format!("grep -i MinProtocol {path}"));
                }
            }
            if lower.contains("seclevel=1") {
                return nok_at(ctx, &path, "SECLEVEL", "legacy cipher SECLEVEL=1".into(), format!("grep -i SECLEVEL {path}"));
            }
        }
        if let Some(conf) = ctx.read("/etc/crypto-policies/config") {
            log.push(att("/etc/crypto-policies/config", "read"));
            let v = conf.trim().to_ascii_uppercase();
            if v.contains("LEGACY") {
                return nok_at(ctx, "/etc/crypto-policies/config", "LEGACY", format!("crypto policy is {v}"), "cat /etc/crypto-policies/config".into());
            }
            if !v.is_empty() {
                return ok(format!("crypto policy {v}"), "/etc/crypto-policies/config".into(), "cat /etc/crypto-policies/config".into());
            }
        } else {
            log.push(att("/etc/crypto-policies/config", "missing"));
        }
        return degraded_from_attempts(log, "TLS stack configuration not readable");
    }
    let mut bad: Vec<String> = Vec::new();
    let mut good = 0;
    for proto in ["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"] {
        let key = format!(r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\{proto}\Server");
        if let Some(out) = cmd_log(ctx, &mut log, "reg", &["query", &key, "/v", "Enabled"]) {
            if let Some(v) = reg_val(&out, "Enabled").and_then(|s| parse_num(&s)) {
                if v == 1 {
                    bad.push(proto.to_string());
                } else {
                    good += 1;
                }
            }
        }
    }
    let tls12 = r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server";
    if let Some(out) = cmd_log(ctx, &mut log, "reg", &["query", tls12, "/v", "Enabled"]) {
        if let Some(v) = reg_val(&out, "Enabled").and_then(|s| parse_num(&s)) {
            if v == 0 {
                bad.push("TLS 1.2 disabled".into());
            } else {
                good += 1;
            }
        }
    }
    if good == 0 && bad.is_empty() {
        return degraded_from_attempts(log, "SCHANNEL protocol policy not readable (defaults apply)");
    }
    if !bad.is_empty() {
        return nok(format!("legacy protocols enabled: {}", bad.join(", ")), "SCHANNEL".into(), "reg query SCHANNEL\\Protocols".into());
    }
    ok(format!("{good} protocol policies hardened"), "SCHANNEL".into(), "reg query SCHANNEL\\Protocols".into())
}

// ---- 010: certificate trust store ----------------------------------------

/// Primary: `stat` mtime of the Debian CA bundle.
/// Fallback: `stat` mtime of the RHEL CA bundle.
/// Windows store enumeration is not reachable read-only through the
/// command allowlist, so this check is Linux-only by design.
fn cert_inventory(ctx: &mut ScanContext) -> CheckOutcome {
    let mut log = Vec::new();
    let bundles = [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    ];
    for b in bundles {
        if let Some(out) = cmd_log(ctx, &mut log, "stat", &["-c", "%Y", b]) {
            if let Some(mtime) = parse_num(&out) {
                let age_days = now_secs().saturating_sub(mtime) / 86_400;
                if age_days <= 365 {
                    return ok(format!("CA bundle refreshed {age_days} days ago"), b.into(), format!("stat -c %Y {b}"));
                }
                return nok(format!("CA bundle is {age_days} days old (stale)"), b.into(), format!("stat -c %Y {b}"));
            }
        }
    }
    degraded_from_attempts(log, "CA bundle freshness not observable")
}

// ---- 011: backup agent ----------------------------------------------------

/// Linux primary: known backup-agent config files.
/// Linux fallback: `systemctl is-active` backup services.
/// Windows primary: `sc query` backup services.
fn backup_agent(ctx: &mut ScanContext) -> CheckOutcome {
    let mut log = Vec::new();
    if ctx.linux() {
        let candidates = [
            "/etc/bacula/bacula-fd.conf",
            "/etc/backuppc/config.pl",
            "/etc/amanda/amanda.conf",
            "/etc/veeam/veeam.ini",
            "/etc/duply/main/conf",
        ];
        if let Some((path, _)) = read_first(ctx, &mut log, &candidates) {
            return ok(format!("backup agent configured ({path})"), path.clone(), format!("ls {path}"));
        }
        for svc in ["bacula-fd", "backuppc", "amanda", "veeamflr", "duplicity"] {
            if let Some(out) = cmd_log(ctx, &mut log, "systemctl", &["is-active", svc]) {
                if out.trim() == "active" {
                    return ok(format!("{svc} active"), "systemctl".into(), format!("systemctl is-active {svc}"));
                }
            }
        }
        return degraded_from_attempts(log, "no backup agent configuration or service detected");
    }
    let mut any_running = false;
    let mut any_stopped = false;
    for svc in ["wbengine", "VeeamEndpointBackupSvc", "BackupExecRPCService", "SDRSVC"] {
        if let Some(out) = cmd_log(ctx, &mut log, "sc", &["query", svc]) {
            match sc_state(&out) {
                Some("running") => any_running = true,
                Some(_) => any_stopped = true,
                None => {}
            }
        }
    }
    if any_running {
        return ok("a known backup service is running".into(), "sc query".into(), "sc query <backup>".into());
    }
    if any_stopped {
        return nok("a known backup service is installed but not running".into(), "sc query".into(), "sc query <backup>".into());
    }
    degraded_from_attempts(log, "no backup service detected on Windows")
}

// ---- 012: log retention ---------------------------------------------------

/// Linux primary: `/etc/logrotate.conf` `rotate` directive.
/// Linux fallback: `/etc/logrotate.d/syslog`, `/etc/systemd/journald.conf`.
/// Windows primary: EventLog Security `MaxSize` registry.
/// Windows fallback: `wevtutil gl Security`.
fn log_retention(ctx: &mut ScanContext) -> CheckOutcome {
    let mut log = Vec::new();
    if ctx.linux() {
        if let Some((path, text)) = read_first(ctx, &mut log, &["/etc/logrotate.conf"]) {
            if let Some(rotate) = text
                .lines()
                .map(str::trim_start)
                .filter(|l| !l.starts_with('#'))
                .find_map(|l| l.strip_prefix("rotate").map(|r| r.trim()))
                .and_then(|v| v.split_whitespace().next())
                .and_then(|v| v.parse::<u32>().ok())
            {
                if rotate >= 13 {
                    return ok(format!("logrotate retains {rotate} rotations"), path, "grep rotate /etc/logrotate.conf".into());
                }
                if rotate < 4 {
                    return nok_at(ctx, &path, "rotate", format!("logrotate retains only {rotate} rotations"), "grep rotate /etc/logrotate.conf".into());
                }
                return degraded(&format!("logrotate retains {rotate} rotations (below 13-week target)"));
            }
        }
        if let Some((path, text)) = read_first(ctx, &mut log, &["/etc/systemd/journald.conf", "/etc/logrotate.d/syslog"]) {
            if let Some(v) = text
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("maxretentionsec"))
                .and_then(|l| l.split('=').nth(1))
            {
                return ok(format!("journald MaxRetentionSec={}", v.trim()), path, "grep MaxRetentionSec journald.conf".into());
            }
            return degraded(&format!("{path} present but no explicit retention bound"));
        }
        return degraded_from_attempts(log, "log retention configuration not found");
    }
    let key = r"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security";
    if let Some(out) = cmd_log(ctx, &mut log, "reg", &["query", key, "/v", "MaxSize"]) {
        if let Some(size) = reg_val(&out, "MaxSize").and_then(|s| parse_num(&s)) {
            if size >= 20_971_520 {
                return ok(format!("Security log MaxSize={} bytes", size), key.into(), "reg query EventLog\\Security".into());
            }
            return nok(format!("Security log MaxSize={} bytes (< 20 MiB)", size), key.into(), "reg query EventLog\\Security".into());
        }
    }
    if let Some(out) = cmd_log(ctx, &mut log, "wevtutil", &["gl", "Security"]) {
        for line in out.lines() {
            if line.to_ascii_lowercase().contains("maxsize") {
                if let Some(n) = parse_num(line) {
                    if n >= 20_971_520 {
                        return ok(format!("Security log maxSize={n}"), "wevtutil".into(), "wevtutil gl Security".into());
                    }
                    return nok(format!("Security log maxSize={n} (< 20 MiB)"), "wevtutil".into(), "wevtutil gl Security".into());
                }
            }
        }
    }
    degraded_from_attempts(log, "Security log retention not readable")
}

// ---- 013: remote log forwarding ------------------------------------------

/// Linux primary: `/etc/rsyslog.conf` `@`/`@@` remote actions.
/// Linux fallback: `/etc/syslog-ng/syslog-ng.conf`, journald ForwardToSyslog.
/// Windows primary: `sc query Wecsvc`.
/// Windows fallback: EventLog forwarding policy registry.
fn remote_log_forwarding(ctx: &mut ScanContext) -> CheckOutcome {
    let mut log = Vec::new();
    if ctx.linux() {
        if let Some(conf) = ctx.read("/etc/rsyslog.conf") {
            log.push(att("/etc/rsyslog.conf", "read"));
            let remote = conf.lines().any(|l| {
                let t = l.trim();
                !t.starts_with('#') && (t.contains("@@") || t.contains("@ ") || t.contains("@["))
            });
            if remote {
                return ok("rsyslog remote forwarding configured".into(), "/etc/rsyslog.conf".into(), "grep '@@' /etc/rsyslog.conf".into());
            }
            return nok("rsyslog.conf has no remote forwarding action".into(), "/etc/rsyslog.conf".into(), "grep '@@' /etc/rsyslog.conf".into());
        }
        log.push(att("/etc/rsyslog.conf", "missing"));
        if let Some(conf) = ctx.read("/etc/syslog-ng/syslog-ng.conf") {
            log.push(att("/etc/syslog-ng/syslog-ng.conf", "read"));
            if conf.to_ascii_lowercase().contains("network(") || conf.to_ascii_lowercase().contains("destination") {
                return ok("syslog-ng forwarding configured".into(), "/etc/syslog-ng/syslog-ng.conf".into(), "grep destination /etc/syslog-ng/syslog-ng.conf".into());
            }
            return nok("syslog-ng has no forwarding destination".into(), "/etc/syslog-ng/syslog-ng.conf".into(), "grep destination /etc/syslog-ng/syslog-ng.conf".into());
        }
        log.push(att("/etc/syslog-ng/syslog-ng.conf", "missing"));
        if let Some(jd) = ctx.read("/etc/systemd/journald.conf") {
            log.push(att("/etc/systemd/journald.conf", "read"));
            if jd.to_ascii_lowercase().contains("forwardtosyslog=yes") {
                return degraded("journald forwards to local syslog only; remote collector unverified");
            }
        }
        return degraded_from_attempts(log, "no log-forwarding configuration found");
    }
    if let Some(out) = cmd_log(ctx, &mut log, "sc", &["query", "Wecsvc"]) {
        match sc_state(&out) {
            Some("running") => return ok("Windows Event Collector service running".into(), "Wecsvc".into(), "sc query Wecsvc".into()),
            Some(_) => return nok("Windows Event Collector service not running".into(), "Wecsvc".into(), "sc query Wecsvc".into()),
            None => {}
        }
    }
    if let Some(out) = cmd_log(ctx, &mut log, "reg", &["query", r"HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog"]) {
        if !out.trim().is_empty() {
            return ok("EventLog forwarding policy key present".into(), "EventLog policy".into(), "reg query EventLog policy".into());
        }
    }
    degraded_from_attempts(log, "Windows log-forwarding configuration unreadable")
}

// ---- 014: firewall default-deny ------------------------------------------

/// Windows primary: `netsh advfirewall show allprofiles`.
/// Windows fallback: PowerShell `Get-NetFirewallProfile`.
/// Linux primary: `ufw status verbose` / `firewall-cmd --get-default-zone`.
/// Linux fallback: `iptables -L -n` policy.
fn firewall_default_deny(ctx: &mut ScanContext) -> CheckOutcome {
    if in_container(ctx) {
        return not_applicable(
            "the host firewall service is outside the container; default-deny policy is a host/namespace control",
        );
    }
    let mut log = Vec::new();
    if ctx.linux() {
        if let Some(out) = cmd_log(ctx, &mut log, "ufw", &["status", "verbose"]) {
            if out.to_ascii_lowercase().contains("deny (incoming)") || out.to_ascii_lowercase().contains("deny incoming") {
                return ok("ufw default incoming deny".into(), "ufw".into(), "ufw status verbose".into());
            }
            if out.to_ascii_lowercase().contains("default:") {
                return nok("ufw default incoming is not deny".into(), "ufw".into(), "ufw status verbose".into());
            }
        }
        if let Some(out) = cmd_log(ctx, &mut log, "firewall-cmd", &["--get-default-zone"]) {
            match out.trim() {
                "drop" | "block" => return ok(format!("firewalld default zone {}", out.trim()), "firewalld".into(), "firewall-cmd --get-default-zone".into()),
                "trusted" => return nok("firewalld default zone trusted (allow-all)".into(), "firewalld".into(), "firewall-cmd --get-default-zone".into()),
                z if !z.is_empty() => return degraded(&format!("firewalld default zone {z} — verify inbound rules")),
                _ => {}
            }
        }
        if let Some(out) = cmd_log(ctx, &mut log, "iptables", &["-L", "-n"]) {
            if out.contains("Chain INPUT (policy DROP)") {
                return ok("iptables INPUT policy DROP".into(), "iptables".into(), "iptables -L -n".into());
            }
            if out.contains("Chain INPUT (policy ACCEPT)") {
                return nok("iptables INPUT policy ACCEPT".into(), "iptables".into(), "iptables -L -n".into());
            }
        }
        return degraded_from_attempts(log, "no firewall subsystem readable");
    }
    if let Some(out) = cmd_log(ctx, &mut log, "netsh", &["advfirewall", "show", "allprofiles"]) {
        let lower = out.to_ascii_lowercase();
        let off = lower.lines().any(|l| l.trim_start().starts_with("state") && l.contains("off"));
        let allow_in = lower.contains("allowinbound");
        let saw_state = lower.lines().any(|l| l.trim_start().starts_with("state"));
        if off || allow_in {
            return nok("a firewall profile is OFF or allows inbound by default".into(), "netsh".into(), "netsh advfirewall show allprofiles".into());
        }
        if saw_state {
            return ok("all firewall profiles ON with inbound block".into(), "netsh".into(), "netsh advfirewall show allprofiles".into());
        }
    }
    if let Some(out) = cmd_log(ctx, &mut log, "powershell", &["-NoProfile", "-NonInteractive", "-Command", "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction | ConvertTo-Json"]) {
        let lower = out.to_ascii_lowercase();
        if lower.contains("false") {
            return nok("a firewall profile is disabled".into(), "Get-NetFirewallProfile".into(), "Get-NetFirewallProfile".into());
        }
        if lower.contains("block") {
            return ok("all firewall profiles block inbound by default".into(), "Get-NetFirewallProfile".into(), "Get-NetFirewallProfile".into());
        }
        return nok("firewall default inbound action is not block".into(), "Get-NetFirewallProfile".into(), "Get-NetFirewallProfile".into());
    }
    degraded_from_attempts(log, "firewall state unreadable")
}

// ---- 015: management listener binding ------------------------------------

/// Linux primary: `/etc/ssh/sshd_config` ListenAddress.
/// Linux fallback: `sshd -T` ListenAddress.
/// Windows primary: `netsh http show urlacl` (WinRM URLs).
/// Windows fallback: WSMan Listener registry.
fn mgmt_listener_binding(ctx: &mut ScanContext) -> CheckOutcome {
    let mut log = Vec::new();
    if ctx.linux() {
        let mut addrs: Vec<String> = Vec::new();
        if let Some(conf) = ctx.read("/etc/ssh/sshd_config") {
            log.push(att("/etc/ssh/sshd_config", "read"));
            for line in conf.lines() {
                let l = line.trim();
                if l.to_ascii_lowercase().starts_with("listenaddress") {
                    if let Some(a) = l.split_whitespace().nth(1) {
                        addrs.push(a.to_string());
                    }
                }
            }
            if addrs.iter().any(|a| a == "0.0.0.0" || a == "::" || a == "*") {
                return nok_at(ctx, "/etc/ssh/sshd_config", "ListenAddress", format!("sshd bound to wildcard: {}", addrs.join(", ")), "grep ListenAddress /etc/ssh/sshd_config".into());
            }
            if !addrs.is_empty() {
                return ok(format!("sshd bound to: {}", addrs.join(", ")), "/etc/ssh/sshd_config".into(), "grep ListenAddress /etc/ssh/sshd_config".into());
            }
            return degraded("no explicit ListenAddress — sshd defaults to all interfaces; verify firewall exposure");
        }
        log.push(att("/etc/ssh/sshd_config", "missing"));
        if let Some(out) = cmd_log(ctx, &mut log, "sshd", &["-T"]) {
            let addrs: Vec<&str> = out
                .lines()
                .filter_map(|l| l.to_ascii_lowercase().starts_with("listenaddress").then(|| l.split_whitespace().nth(1).unwrap_or("")))
                .collect();
            if addrs.iter().any(|a| *a == "0.0.0.0" || *a == "::") {
                return nok(format!("sshd bound to wildcard: {}", addrs.join(", ")), "sshd -T".into(), "sshd -T".into());
            }
            if !addrs.is_empty() {
                return ok(format!("sshd bound to: {}", addrs.join(", ")), "sshd -T".into(), "sshd -T".into());
            }
            return degraded("sshd -T reports no explicit ListenAddress");
        }
        return degraded_from_attempts(log, "sshd listener binding not readable");
    }
    if let Some(out) = cmd_log(ctx, &mut log, "netsh", &["http", "show", "urlacl"]) {
        let mut wildcard = false;
        let mut specific = false;
        for line in out.lines() {
            let l = line.trim();
            if l.contains(":5985/") || l.contains(":5986/") {
                if l.contains("http://+:") || l.contains("http://*:") {
                    wildcard = true;
                } else if l.contains("http://") {
                    specific = true;
                }
            }
        }
        if wildcard {
            return nok("WinRM listener reserved on wildcard host".into(), "netsh http urlacl".into(), "netsh http show urlacl".into());
        }
        if specific {
            return ok("WinRM listener bound to specific host(s)".into(), "netsh http urlacl".into(), "netsh http show urlacl".into());
        }
        return degraded("no WinRM listener reservation found");
    }
    if let Some(out) = cmd_log(ctx, &mut log, "reg", &["query", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Listener"]) {
        if !out.trim().is_empty() {
            return degraded("WinRM listener registry present; interface binding not resolvable read-only");
        }
    }
    degraded_from_attempts(log, "management listener binding unreadable")
}

// ---- 016: service-account privilege --------------------------------------

/// Linux primary: `/etc/passwd` + `/etc/group` intersection.
/// Linux fallback: `getent group sudo wheel admin`.
/// Windows primary: `net localgroup Administrators`.
fn service_account_privilege(ctx: &mut ScanContext) -> CheckOutcome {
    let mut log = Vec::new();
    if ctx.linux() {
        let passwd = ctx.read("/etc/passwd");
        if passwd.is_some() {
            log.push(att("/etc/passwd", "read"));
        } else {
            log.push(att("/etc/passwd", "missing"));
        }
        let group = ctx.read("/etc/group");
        if let (Some(passwd), Some(group)) = (passwd, group) {
            log.push(att("/etc/group", "read"));
            let svc: Vec<String> = passwd
                .lines()
                .filter_map(|l| {
                    let f: Vec<&str> = l.split(':').collect();
                    if f.len() < 7 {
                        return None;
                    }
                    let uid: u32 = f[2].parse().unwrap_or(9999);
                    let shell = f[6];
                    (uid < 1000 || shell.contains("nologin") || shell.ends_with("/false")).then(|| f[0].to_string())
                })
                .collect();
            let mut offenders: Vec<String> = Vec::new();
            for l in group.lines() {
                let f: Vec<&str> = l.split(':').collect();
                if f.len() < 4 {
                    continue;
                }
                if matches!(f[0], "sudo" | "wheel" | "admin") {
                    for m in f[3].split(',') {
                        if !m.is_empty() && svc.iter().any(|s| s == m) {
                            offenders.push(m.to_string());
                        }
                    }
                }
            }
            if offenders.is_empty() {
                return ok("no service account is a member of sudo/wheel/admin".into(), "/etc/group".into(), "grep -E '^(sudo|wheel|admin):' /etc/group".into());
            }
            let needle = offenders[0].clone();
            return nok_at(ctx, "/etc/group", &needle, format!("service accounts in privileged groups: {}", offenders.join(", ")), "grep -E '^(sudo|wheel|admin):' /etc/group".into());
        }
        if let Some(out) = cmd_log(ctx, &mut log, "getent", &["group", "sudo", "wheel", "admin"]) {
            if out.trim().is_empty() {
                return ok("no privileged group membership via getent".into(), "getent".into(), "getent group sudo wheel admin".into());
            }
            return nok("privileged group has members; verify none are service accounts".into(), "getent".into(), "getent group sudo wheel admin".into());
        }
        return degraded_from_attempts(log, "account/group files unreadable");
    }
    if let Some(out) = cmd_log(ctx, &mut log, "net", &["localgroup", "Administrators"]) {
        let lower = out.to_ascii_lowercase();
        for svc in ["iis_iusrs", "network service", "local service", "iis apppool"] {
            if lower.contains(svc) {
                return nok(format!("service account '{svc}' is a local administrator"), "net localgroup".into(), "net localgroup Administrators".into());
            }
        }
        return ok("no well-known service account in Administrators".into(), "net localgroup".into(), "net localgroup Administrators".into());
    }
    degraded_from_attempts(log, "local Administrators group unreadable")
}

// ---- 017: password/lockout policy ----------------------------------------

/// Linux primary: `/etc/security/pwquality.conf` + `faillock.conf`.
/// Linux fallback: `/etc/pam.d/system-auth` / `common-auth` faillock.
/// Windows primary: `net accounts`.
fn password_lockout_presence(ctx: &mut ScanContext) -> CheckOutcome {
    let mut log = Vec::new();
    if ctx.linux() {
        let pwq = ctx.read("/etc/security/pwquality.conf");
        let faillock = ctx.read("/etc/security/faillock.conf");
        let pam = ctx
            .read("/etc/pam.d/system-auth")
            .or_else(|| ctx.read("/etc/pam.d/common-auth"))
            .or_else(|| ctx.read("/etc/pam.d/password-auth"));
        if pwq.is_some() {
            log.push(att("/etc/security/pwquality.conf", "read"));
        }
        if faillock.is_some() {
            log.push(att("/etc/security/faillock.conf", "read"));
        }
        let minlen = pwq.as_deref().and_then(|t| {
            t.lines()
                .find(|l| l.trim_start().to_ascii_lowercase().starts_with("minlen"))
                .and_then(|l| l.split('=').nth(1))
                .and_then(|v| v.trim().split_whitespace().next())
                .and_then(|v| v.parse::<u32>().ok())
        });
        let deny = faillock.as_deref().and_then(|t| {
            t.lines()
                .find(|l| l.trim_start().to_ascii_lowercase().starts_with("deny"))
                .and_then(|l| l.split('=').nth(1))
                .and_then(|v| v.trim().parse::<u32>().ok())
        });
        let pam_faillock = pam
            .as_deref()
            .map(|t| t.contains("pam_faillock") || t.contains("pam_tally2"))
            .unwrap_or(false);
        if let Some(m) = minlen {
            if m < 8 {
                return nok_at(ctx, "/etc/security/pwquality.conf", "minlen", format!("password minlen={m} (< 8)"), "grep minlen /etc/security/pwquality.conf".into());
            }
            if deny.map(|d| d > 10).unwrap_or(false) {
                return nok_at(ctx, "/etc/security/faillock.conf", "deny", format!("lockout deny={}", deny.unwrap()), "grep deny /etc/security/faillock.conf".into());
            }
            if deny.map(|d| d > 0).unwrap_or(false) || pam_faillock {
                return ok(format!("minlen={m} with lockout policy present"), "/etc/security/pwquality.conf".into(), "grep -E 'minlen|deny' /etc/security/*.conf".into());
            }
            return degraded(&format!("minlen={m} but no lockout policy found"));
        }
        if pwq.is_none() {
            return degraded_from_attempts(log, "password policy files not readable");
        }
        return degraded_from_attempts(log, "password policy incomplete");
    }
    if let Some(out) = cmd_log(ctx, &mut log, "net", &["accounts"]) {
        let mut minlen = None;
        let mut lockout = None;
        for line in out.lines() {
            let lower = line.to_ascii_lowercase();
            if lower.contains("minimum password length") {
                minlen = parse_num(line);
            } else if lower.contains("lockout threshold") {
                lockout = parse_num(line);
            }
        }
        match (minlen, lockout) {
            (Some(m), Some(l)) if m >= 8 && l > 0 => ok(format!("min password length {m}, lockout threshold {l}"), "net accounts".into(), "net accounts".into()),
            (Some(m), Some(l)) => nok(format!("weak policy: minlen={m}, lockout={l}"), "net accounts".into(), "net accounts".into()),
            _ => degraded("net accounts output did not include policy fields"),
        }
    } else {
        degraded_from_attempts(log, "net accounts unavailable")
    }
}

// ---- 018: sudo / UAC ------------------------------------------------------

/// Linux primary: `/etc/sudoers` Defaults + NOPASSWD scan.
/// Linux fallback: `/etc/pam.d/su`.
/// Windows primary: Policies\\System EnableLUA / ConsentPromptBehaviorAdmin.
fn sudo_uac_presence(ctx: &mut ScanContext) -> CheckOutcome {
    let mut log = Vec::new();
    if ctx.linux() {
        if let Some(sudoers) = ctx.read("/etc/sudoers") {
            log.push(att("/etc/sudoers", "read"));
            let lower = sudoers.to_ascii_lowercase();
            if lower.contains("nopasswd:") && lower.contains("all") {
                return nok_at(ctx, "/etc/sudoers", "NOPASSWD", "sudoers grants NOPASSWD: ALL".into(), "grep -i nopasswd /etc/sudoers".into());
            }
            if sudoers.lines().any(|l| l.trim_start().starts_with("Defaults")) {
                return ok("sudoers present with Defaults hardening".into(), "/etc/sudoers".into(), "grep '^Defaults' /etc/sudoers".into());
            }
            return degraded("sudoers present but no Defaults lines found");
        }
        log.push(att("/etc/sudoers", "missing"));
        if let Some(su) = ctx.read("/etc/pam.d/su") {
            log.push(att("/etc/pam.d/su", "read"));
            if su.contains("pam_wheel") || su.contains("pam_rootok") {
                return ok("su mediated by PAM (pam_wheel/pam_rootok)".into(), "/etc/pam.d/su".into(), "grep pam_ /etc/pam.d/su".into());
            }
        }
        return degraded_from_attempts(log, "sudo/UAC policy not readable");
    }
    const SYS: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    if let Some(out) = cmd_log(ctx, &mut log, "reg", &["query", SYS, "/v", "EnableLUA"]) {
        if let Some(v) = reg_val(&out, "EnableLUA").and_then(|s| parse_num(&s)) {
            if v == 0 {
                return nok("UAC disabled (EnableLUA=0)".into(), SYS.into(), "reg query Policies\\System /v EnableLUA".into());
            }
            let consent = cmd_log(ctx, &mut log, "reg", &["query", SYS, "/v", "ConsentPromptBehaviorAdmin"]).and_then(|o| reg_val(&o, "ConsentPromptBehaviorAdmin")).and_then(|s| parse_num(&s));
            if consent.map(|c| c >= 2).unwrap_or(true) {
                return ok(format!("UAC enabled (ConsentPromptBehaviorAdmin={})", consent.map(|c| c.to_string()).unwrap_or_else(|| "default".into())), SYS.into(), "reg query Policies\\System".into());
            }
            return nok(format!("UAC prompt behavior weakened (ConsentPromptBehaviorAdmin={})", consent.unwrap_or(0)), SYS.into(), "reg query Policies\\System".into());
        }
    }
    degraded_from_attempts(log, "UAC policy unreadable")
}

// ---- 019: secure boot + TPM summary --------------------------------------

/// Summary only (detail owned by GEN-INV-012/013).
/// Linux x86_64: `mokutil --sb-state`; aarch64/arm: UEFI efivars presence.
/// Linux TPM: `/sys/class/tpm/tpm0`.
/// Windows: `Confirm-SecureBootUEFI` + `Get-Tpm`.
fn secureboot_tpm_summary(ctx: &mut ScanContext) -> CheckOutcome {
    if in_container(ctx) {
        return not_applicable(
            "Secure Boot and TPM are firmware/hardware controls; a container exposes neither",
        );
    }
    let mut log = Vec::new();
    let arch = ctx.platform.arch.to_ascii_lowercase();
    let sb: Option<bool>;
    let tpm: Option<bool>;
    if ctx.linux() {
        let arm = arch.contains("aarch64") || arch.contains("arm");
        if arm {
            // On ARM there is no mokutil; UEFI mode is the observable signal.
            if ctx.exists("/sys/firmware/efi") {
                log.push(att("/sys/firmware/efi", "present"));
                sb = None;
            } else if ctx.exists("/sys/firmware") {
                log.push(att("/sys/firmware/efi", "absent (legacy boot)"));
                sb = Some(false);
            } else {
                log.push(att("/sys/firmware/efi", "unreadable"));
                sb = None;
            }
        } else {
            sb = cmd_log(ctx, &mut log, "mokutil", &["--sb-state"]).map(|o| {
                !o.to_ascii_lowercase().contains("disabled")
            });
        }
        // Only claim "no TPM" when the kernel sysfs is actually observable.
        tpm = if ctx.exists("/sys") {
            let present = ctx.exists("/sys/class/tpm/tpm0") || ctx.exists("/sys/class/tpm");
            log.push(att("/sys/class/tpm", if present { "present" } else { "absent" }));
            Some(present)
        } else {
            log.push(att("/sys/class/tpm", "unreadable (/sys absent)"));
            None
        };
    } else {
        sb = cmd_log(ctx, &mut log, "powershell", &["-NoProfile", "-NonInteractive", "-Command", "Confirm-SecureBootUEFI"])
            .map(|o| o.trim().eq_ignore_ascii_case("true"));
        tpm = cmd_log(ctx, &mut log, "powershell", &["-NoProfile", "-NonInteractive", "-Command", "Get-Tpm | Select-Object TpmPresent | ConvertTo-Json"])
            .map(|o| o.to_ascii_lowercase().contains("true"));
    }
    match (sb, tpm) {
        (Some(true), Some(true)) => ok("Secure Boot enabled and TPM present".into(), "firmware".into(), "mokutil --sb-state; ls /sys/class/tpm".into()),
        (Some(false), _) => nok("Secure Boot disabled".into(), "firmware".into(), "mokutil --sb-state".into()),
        // A VM that exposes no TPM device has no virtual TPM to assess —
        // never report it as a missing-hardware failure.
        (_, Some(false)) if on_vm(ctx) => not_applicable(&format!(
            "this virtual machine ({}) exposes no TPM device (no virtual TPM configured)",
            hypervisor_label(ctx)
        )),
        (_, Some(false)) => nok("no TPM device detected".into(), "firmware".into(), "ls /sys/class/tpm".into()),
        _ if on_vm(ctx) => not_applicable(&format!(
            "this virtual machine ({}) exposes neither Secure Boot nor a TPM; no firmware control to evaluate",
            hypervisor_label(ctx)
        )),
        _ => degraded_from_attempts(log, "Secure Boot / TPM state not determinable"),
    }
}

// ---- 020: kernel link protections ----------------------------------------

/// Primary: `/proc/sys/fs/protected_*` via the shared sysctl helper.
/// Fallback: `sysctl -n` (inside the helper).
fn kernel_link_protection(ctx: &mut ScanContext) -> CheckOutcome {
    let mut log = Vec::new();
    let keys = [
        ("fs.protected_hardlinks", 1u64),
        ("fs.protected_symlinks", 1u64),
        ("fs.protected_fifos", 1u64),
        ("fs.protected_regular", 1u64),
    ];
    let mut bad: Vec<String> = Vec::new();
    let mut good: Vec<String> = Vec::new();
    for (key, want) in keys {
        match sysctl_value(ctx, key) {
            Some(v) => {
                log.push(att(&format!("sysctl {key}"), format!("value={}", v.trim())));
                match v.trim().parse::<u64>() {
                    Ok(n) if n >= want => good.push(format!("{key}={n}")),
                    Ok(n) => bad.push(format!("{key}={n} (expected >= {want})")),
                    Err(_) => bad.push(format!("{key}={} (unparseable)", v.trim())),
                }
            }
            None => log.push(att(&format!("sysctl {key}"), "missing")),
        }
    }
    if !bad.is_empty() {
        return nok(bad.join("; "), "/proc/sys/fs".into(), "sysctl fs.protected_*".into());
    }
    if good.len() == keys.len() {
        return ok(good.join("; "), "/proc/sys/fs".into(), "sysctl fs.protected_*".into());
    }
    degraded_from_attempts(log, "some fs.protected_* sysctls absent (kernel default applies)")
}

// ---- 021: filesystem free space ------------------------------------------

/// Linux primary: `findmnt` TARGET/AVAIL/SIZE/USE%.
/// Linux fallback: `stat -f` free-block ratio on `/`.
/// Windows primary: `wmic logicaldisk`.
/// Windows fallback: PowerShell `Get-CimInstance Win32_LogicalDisk`.
fn disk_free(ctx: &mut ScanContext) -> CheckOutcome {
    let mut log = Vec::new();
    if ctx.linux() {
        if let Some(out) = cmd_log(ctx, &mut log, "findmnt", &["-l", "-n", "-o", "TARGET,AVAIL,SIZE,USE%"]) {
            let mut worst: Option<(String, u64)> = None;
            for line in out.lines() {
                let f: Vec<&str> = line.split_whitespace().collect();
                if f.len() < 4 {
                    continue;
                }
                if let Some(pct) = f[3].strip_suffix('%').and_then(|p| p.parse::<u64>().ok()) {
                    if worst.as_ref().map(|(_, w)| pct > *w).unwrap_or(true) {
                        worst = Some((f[0].to_string(), pct));
                    }
                }
            }
            if let Some((mount, pct)) = worst {
                if pct >= 90 {
                    return nok(format!("{mount} is {pct}% full"), "findmnt".into(), "findmnt -l -n -o TARGET,AVAIL,SIZE,USE%".into());
                }
                return ok(format!("worst system mount {mount} at {pct}% full"), "findmnt".into(), "findmnt -l -n -o TARGET,AVAIL,SIZE,USE%".into());
            }
        }
        if let Some(out) = cmd_log(ctx, &mut log, "stat", &["-f", "-c", "%a %S %b", "/"]) {
            let nums: Vec<u64> = out.split_whitespace().filter_map(|t| t.parse().ok()).collect();
            if nums.len() >= 3 && nums[2] > 0 {
                let pct = 100 - (nums[0] * 100 / nums[2]);
                if pct >= 90 {
                    return nok(format!("/ is {pct}% full"), "stat -f".into(), "stat -f -c '%a %S %b' /".into());
                }
                return ok(format!("/ is {pct}% full"), "stat -f".into(), "stat -f -c '%a %S %b' /".into());
            }
        }
        return degraded_from_attempts(log, "filesystem usage not readable");
    }
    if let Some(out) = cmd_log(ctx, &mut log, "wmic", &["logicaldisk", "get", "caption,size,freespace"]) {
        let mut worst: Option<(String, u64)> = None;
        for line in out.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 3 {
                continue;
            }
            if let (Ok(size), Ok(free)) = (f[1].parse::<u64>(), f[2].parse::<u64>()) {
                if size > 0 && free <= size {
                    let used_pct = 100 - (free * 100 / size);
                    if worst.as_ref().map(|(_, w)| used_pct > *w).unwrap_or(true) {
                        worst = Some((f[0].to_string(), used_pct));
                    }
                }
            }
        }
        if let Some((drive, pct)) = worst {
            if pct >= 90 {
                return nok(format!("{drive} is {pct}% full"), "wmic logicaldisk".into(), "wmic logicaldisk get caption,size,freespace".into());
            }
            return ok(format!("worst drive {drive} at {pct}% full"), "wmic logicaldisk".into(), "wmic logicaldisk get caption,size,freespace".into());
        }
    }
    if let Some(out) = cmd_log(ctx, &mut log, "powershell", &["-NoProfile", "-NonInteractive", "-Command", "Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID,Size,FreeSpace | ConvertTo-Json"]) {
        if out.contains("FreeSpace") {
            return degraded("disk usage retrieved via CIM; inspect JSON for near-full volumes");
        }
    }
    degraded_from_attempts(log, "disk usage not readable")
}

// ---- 022: swap / pagefile ------------------------------------------------

/// Linux primary: `/proc/swaps`; fallback `/etc/fstab` swap entry.
/// Windows primary: `wmic computersystem AutomaticManagedPagefile`.
/// Windows fallback: Memory Management `PagingFiles` registry.
fn swap_pagefile(ctx: &mut ScanContext) -> CheckOutcome {
    if in_container(ctx) {
        return not_applicable(
            "swap/pagefile is configured by the host kernel; a container has no swap device of its own",
        );
    }
    let mut log = Vec::new();
    if ctx.linux() {
        if let Some(swaps) = ctx.read("/proc/swaps") {
            log.push(att("/proc/swaps", "read"));
            let entries = swaps.lines().skip(1).filter(|l| !l.trim().is_empty()).count();
            if entries > 0 {
                return ok(format!("{entries} active swap device(s)"), "/proc/swaps".into(), "cat /proc/swaps".into());
            }
            if let Some(fstab) = ctx.read("/etc/fstab") {
                log.push(att("/etc/fstab", "read"));
                if fstab.lines().any(|l| !l.trim_start().starts_with('#') && l.split_whitespace().nth(2) == Some("swap")) {
                    return ok("swap entry configured in /etc/fstab".into(), "/etc/fstab".into(), "grep swap /etc/fstab".into());
                }
            } else {
                log.push(att("/etc/fstab", "missing"));
            }
            return nok("no active swap and no fstab swap entry".into(), "/proc/swaps".into(), "cat /proc/swaps".into());
        }
        log.push(att("/proc/swaps", "missing"));
        if let Some(fstab) = ctx.read("/etc/fstab") {
            log.push(att("/etc/fstab", "read"));
            if fstab.lines().any(|l| !l.trim_start().starts_with('#') && l.split_whitespace().nth(2) == Some("swap")) {
                return ok("swap entry configured in /etc/fstab".into(), "/etc/fstab".into(), "grep swap /etc/fstab".into());
            }
            return nok("no swap configured".into(), "/etc/fstab".into(), "grep swap /etc/fstab".into());
        }
        return degraded_from_attempts(log, "swap configuration not readable");
    }
    if let Some(out) = cmd_log(ctx, &mut log, "wmic", &["computersystem", "get", "AutomaticManagedPagefile"]) {
        if out.to_ascii_lowercase().contains("true") {
            return ok("pagefile is automatically managed".into(), "wmic".into(), "wmic computersystem get AutomaticManagedPagefile".into());
        }
    }
    let mm = r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management";
    if let Some(out) = cmd_log(ctx, &mut log, "reg", &["query", mm, "/v", "PagingFiles"]) {
        let v = reg_val(&out, "PagingFiles").unwrap_or_default();
        if !v.trim().is_empty() {
            return ok(format!("pagefile configured: {}", v.trim()), mm.into(), "reg query Memory Management /v PagingFiles".into());
        }
        return nok("PagingFiles is empty and pagefile not auto-managed".into(), mm.into(), "reg query Memory Management /v PagingFiles".into());
    }
    degraded_from_attempts(log, "pagefile configuration not readable")
}

// ---- 023: core services --------------------------------------------------

/// Linux primary: `systemctl is-enabled` core units.
/// Windows primary: `sc query` core services.
fn core_services(ctx: &mut ScanContext) -> CheckOutcome {
    let mut log = Vec::new();
    if ctx.linux() {
        let mut bad: Vec<String> = Vec::new();
        let mut good: Vec<String> = Vec::new();
        for unit in ["sshd", "auditd", "rsyslog", "chronyd", "firewalld"] {
            if let Some(out) = cmd_log(ctx, &mut log, "systemctl", &["is-enabled", unit]) {
                if systemd_unit_good(&out) {
                    good.push(unit.to_string());
                } else {
                    bad.push(format!("{unit}={}", out.trim()));
                }
            }
        }
        if !bad.is_empty() {
            return nok(format!("core services not enabled: {}", bad.join(", ")), "systemctl".into(), "systemctl is-enabled <core>".into());
        }
        if !good.is_empty() {
            return ok(format!("core services enabled: {}", good.join(", ")), "systemctl".into(), "systemctl is-enabled <core>".into());
        }
        return degraded_from_attempts(log, "core service states unreadable (no systemd?)");
    }
    let mut running: Vec<String> = Vec::new();
    let mut stopped: Vec<String> = Vec::new();
    for svc in ["WinDefend", "EventLog", "wuauserv", "w32time", "TermService"] {
        if let Some(out) = cmd_log(ctx, &mut log, "sc", &["query", svc]) {
            match sc_state(&out) {
                Some("running") => running.push(svc.to_string()),
                Some(_) => stopped.push(svc.to_string()),
                None => {}
            }
        }
    }
    if !stopped.is_empty() {
        return nok(format!("core services not running: {}", stopped.join(", ")), "sc query".into(), "sc query <core>".into());
    }
    if !running.is_empty() {
        return ok(format!("core services running: {}", running.join(", ")), "sc query".into(), "sc query <core>".into());
    }
    degraded_from_attempts(log, "core service states unreadable")
}

// ---- 024: LDAP / Kerberos client config ----------------------------------

/// Linux primary: `/etc/krb5.conf` `default_realm`.
/// Linux fallback: `/etc/sssd/sssd.conf`, `realm list`.
/// Windows primary: `dsregcmd /status` join state.
/// Windows fallback: LSA Kerberos Domains registry.
fn ldap_kerberos_config(ctx: &mut ScanContext) -> CheckOutcome {
    let mut log = Vec::new();
    if ctx.linux() {
        if let Some(krb5) = ctx.read("/etc/krb5.conf") {
            log.push(att("/etc/krb5.conf", "read"));
            let realm = krb5
                .lines()
                .find(|l| l.trim_start().to_ascii_lowercase().starts_with("default_realm"))
                .and_then(|l| l.split('=').nth(1))
                .map(|v| v.trim().to_string())
                .unwrap_or_default();
            if !realm.is_empty() {
                return ok(format!("default_realm = {realm}"), "/etc/krb5.conf".into(), "grep default_realm /etc/krb5.conf".into());
            }
            if krb5.lines().any(|l| l.trim_start().to_ascii_lowercase().starts_with("default_realm")) {
                return nok_at(ctx, "/etc/krb5.conf", "default_realm", "default_realm is empty".into(), "grep default_realm /etc/krb5.conf".into());
            }
            return nok("krb5.conf present but no default_realm".into(), "/etc/krb5.conf".into(), "grep default_realm /etc/krb5.conf".into());
        }
        log.push(att("/etc/krb5.conf", "missing"));
        if let Some(sssd) = ctx.read("/etc/sssd/sssd.conf") {
            log.push(att("/etc/sssd/sssd.conf", "read"));
            if sssd.to_ascii_lowercase().contains("ldap_uri") || sssd.to_ascii_lowercase().contains("ipa") {
                return ok("sssd directory client configured".into(), "/etc/sssd/sssd.conf".into(), "grep -E 'ldap_uri|ipa' /etc/sssd/sssd.conf".into());
            }
            return degraded("sssd.conf present without ldap/ipa settings");
        }
        log.push(att("/etc/sssd/sssd.conf", "missing"));
        if let Some(out) = cmd_log(ctx, &mut log, "realm", &["list"]) {
            if !out.trim().is_empty() {
                return ok(format!("realm membership: {}", out.lines().next().unwrap_or("").trim()), "realm".into(), "realm list".into());
            }
            return nok("realm list is empty".into(), "realm".into(), "realm list".into());
        }
        return degraded_from_attempts(log, "directory/Kerberos client configuration not found");
    }
    if let Some(out) = cmd_log(ctx, &mut log, "dsregcmd", &["/status"]) {
        let lower = out.to_ascii_lowercase();
        if lower.contains("domainjoined : yes") || lower.contains("azureadjoined : yes") {
            return ok("host is domain/Azure AD joined".into(), "dsregcmd".into(), "dsregcmd /status".into());
        }
        if lower.contains("domainjoined : no") {
            return degraded("host is not domain-joined (workgroup); Kerberos not configured");
        }
    }
    if let Some(out) = cmd_log(ctx, &mut log, "reg", &["query", r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Domains"]) {
        if !out.trim().is_empty() {
            return ok("Kerberos domain configuration present".into(), "Lsa\\Kerberos\\Domains".into(), "reg query Lsa\\Kerberos\\Domains".into());
        }
    }
    degraded_from_attempts(log, "Kerberos/directory client configuration unreadable")
}
