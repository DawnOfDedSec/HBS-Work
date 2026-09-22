//! LIN-LOG: rsyslog/journald/logrotate posture (CIS 4.2.x).

use crate::checks::{degraded, err_outcome, nok, ok};
use crate::context::ScanContext;
use crate::model::{CheckOutcome, FallbackAttempt, RegisteredCheck};
use crate::platform::Os;

pub fn register(reg: &mut Vec<RegisteredCheck>) {
    use crate::check;
    check!(reg, "LIN-LOG-001", "rsyslog installed and enabled", "rsyslog must be present and enabled.", "Absent syslog daemons lose standard facility logging.", "Install/enable rsyslog (or document journald-only baseline).", Medium, "Logging", &["CIS 4.2.1.1"], linux, rsyslog_enabled);
    check!(reg, "LIN-LOG-002", "Logs forwarded to remote host", "Security events must reach a central collector.", "Local logs die with the machine; attackers wipe them.", "Configure rsyslog *.* @@loghost forwarding.", Medium, "Logging", &["CIS 4.2.1.4"], linux, remote_forwarding);
    check!(reg, "LIN-LOG-003", "Log file permissions restricted", "/var/log files must not be world-readable.", "World-readable logs leak credentials and user activity.", "chmod 640 /var/log/messages and peers; set $FileCreateMode 0640.", Medium, "Logging", &["CIS 4.2.1.5"], linux, logfile_perms);
    check!(reg, "LIN-LOG-004", "All standard rsyslog facilities configured", "auth, authpriv, daemon, syslog configured.", "Missing facilities leave whole event classes unlogged.", "Add auth,authpriv.* entries in rsyslog.conf/rsyslog.d.", Medium, "Logging", &["CIS 4.2.2.1"], linux, rsyslog_facilities);
    check!(reg, "LIN-LOG-005", "journald forwards to syslog", "journald should hand entries to rsyslog.", "Split stores complicate collection and retention.", "ForwardToSyslog=yes in journald.conf.", Low, "Logging", &["CIS 4.2.2.2"], linux, |c| journald_kv(c, "ForwardToSyslog", "yes"));
    check!(reg, "LIN-LOG-006", "journald compression enabled", "Compress journal storage.", "Uncompressed journals bloat /var/log and cost I/O.", "Compress=yes in journald.conf.", Low, "Logging", &["CIS 4.2.2.3"], linux, |c| journald_kv(c, "Compress", "yes"));
    check!(reg, "LIN-LOG-007", "journald persistent storage", "Journal survives reboot.", "Volatile journals lose pre-crash evidence.", "Storage=persistent in journald.conf.", Medium, "Logging", &["CIS 4.2.2.4"], linux, |c| journald_kv(c, "Storage", "persistent"));
    check!(reg, "LIN-LOG-008", "logrotate configured", "Log rotation must exist.", "Unrotated logs fill /var and erase old evidence on crash.", "Install/verify logrotate with weekly rotation.", Low, "Logging", &["CIS 4.2.4"], linux, logrotate_present);
    check!(reg, "LIN-LOG-009", "/var/log permissions sane", "/var/log must not be world-writable.", "World-writable log dirs let anyone forge/truncate logs.", "chmod 750 /var/log (or 0755 root-owned without group write).", Low, "Logging", &[], linux, varlog_dir_perms);
    check!(reg, "LIN-LOG-010", "rsyslog file create mode restricted", "Default creation mode must be 0640 or stricter.", "New log files inherit permissive modes otherwise.", "$FileCreateMode 0640 in rsyslog.conf.", Medium, "Logging", &["CIS 4.2.1.5"], linux, file_create_mode);
    check!(reg, "LIN-LOG-011", "journald rate limiting sane", "RateLimitBurst should not discard bursts wholesale.", "Zero limits allow log-flood DoS; tiny bursts drop evidence.", "RateLimitBurst >= 1000 with Interval tuned.", Low, "Logging", &["CIS 4.2.2"], linux, journald_rate_limit);
    check!(reg, "LIN-LOG-012", "Kernel audit config present (audit=1)", "Audit enabled at boot for systems using auditd.", "Boot-time audit off hides syscall-level auditing.", "audit=1 on kernel cmdline (when auditd in use).", Low, "Logging", &["CIS 4.1.1"], linux, kernel_audit_flag);
    check!(reg, "LIN-LOG-013", "Log retention configured", "logrotate retention must retain security logs sufficiently.", "One-week retention erases incident evidence.", "rotate 13+ weekly (90+ days) for security logs.", Low, "Logging", &["CIS 4.2.4"], linux, logrotate_retention);
    check!(reg, "LIN-LOG-014", "Syslog service running", "The chosen syslog daemon is actually running.", "Enabled-but-stopped logging is silent.", "systemctl start rsyslog.", Medium, "Logging", &["CIS 4.2.1.2"], linux, syslog_running);
}

fn linux(p: &crate::platform::PlatformInfo) -> bool {
    p.os == Os::Linux
}

fn rsyslog_enabled(ctx: &mut ScanContext) -> CheckOutcome {
    let mut log = Vec::new();
    if let Some(state) = ctx.cmd("systemctl", &["is-enabled", "rsyslog"]) {
        log.push(FallbackAttempt { source: "systemctl is-enabled rsyslog".into(), outcome: state.trim().to_string() });
        if state.trim() == "enabled" {
            return ok("rsyslog enabled".into(), "systemd".into(), "systemctl is-enabled rsyslog".into());
        }
        return nok(format!("rsyslog not enabled ({})", state.trim()), "systemd".into(), "systemctl is-enabled rsyslog".into());
    }
    log.push(FallbackAttempt { source: "systemctl".into(), outcome: "unavailable".into() });
    if ctx.exists("/etc/rsyslog.conf") {
        return degraded("rsyslog config exists but service state not queryable");
    }
    degraded("rsyslog not installed and service manager unavailable (container/minimal host)")
}

fn syslog_running(ctx: &mut ScanContext) -> CheckOutcome {
    if let Some(out) = ctx.cmd("systemctl", &["is-active", "rsyslog"]) {
        if out.trim() == "active" {
            return ok("rsyslog active".into(), "systemd".into(), "systemctl is-active rsyslog".into());
        }
        if let Some(j) = ctx.cmd("systemctl", &["is-active", "systemd-journald"]) {
            if j.trim() == "active" {
                return ok(format!("rsyslog {} but journald active", out.trim()), "systemd".into(), "systemctl is-active systemd-journald".into());
            }
        }
        return nok(format!("rsyslog {} and journald not active", out.trim()), "systemd".into(), "systemctl is-active rsyslog".into());
    }
    degraded("syslog service state not queryable")
}

fn remote_forwarding(ctx: &mut ScanContext) -> CheckOutcome {
    let mut sources = Vec::new();
    if let Some(conf) = ctx.read("/etc/rsyslog.conf") {
        sources.push(("file:/etc/rsyslog.conf", conf));
    }
    for d in ["/etc/rsyslog.d/50-default.conf", "/etc/rsyslog.d/remotelogging.conf"] {
        if let Some(c) = ctx.read(d) {
            sources.push((d, c));
        }
    }
    if sources.is_empty() {
        return degraded("no rsyslog configuration found (journald-only host?)");
    }
    let target = sources
        .iter()
        .find(|(_, c)| c.lines().any(|l| l.contains("@@") || l.trim_start().starts_with("@")));
    match target {
        Some((src, c)) => {
            let line = c.lines().find(|l| l.contains("@@") || l.trim_start().starts_with('@')).unwrap_or_default().trim();
            ok(format!("forwarding configured in {src}: {line}"), src.to_string(), "grep -E '@@|@ ' /etc/rsyslog.conf /etc/rsyslog.d/*".into())
        }
        None => nok(
            format!("no remote forwarding in {}", sources.iter().map(|(s, _)| *s).collect::<Vec<_>>().join(", ")),
            "/etc/rsyslog.conf".into(),
            "grep -E '@@|@ ' /etc/rsyslog.conf".into(),
        ),
    }
}

fn logfile_perms(ctx: &mut ScanContext) -> CheckOutcome {
    let files = ["/var/log/messages", "/var/log/syslog", "/var/log/auth.log", "/var/log/secure"];
    let mut seen = Vec::new();
    let mut bad = Vec::new();
    for f in files {
        if let Some(mode) = ctx.unix_mode(f) {
            seen.push(format!("{f}:{mode:o}"));
            if mode & 0o007 != 0 {
                bad.push(format!("{f} is world-accessible ({mode:o})"));
            }
        }
    }
    if seen.is_empty() {
        return degraded("no standard log files statable (journald-only host or no permission)");
    }
    if bad.is_empty() {
        ok(seen.join(" "), "/var/log".into(), "stat /var/log/messages".into())
    } else {
        nok(bad.join("; "), "/var/log".into(), "ls -l /var/log".into())
    }
}

fn rsyslog_facilities(ctx: &mut ScanContext) -> CheckOutcome {
    let mut conf = String::new();
    if let Some(c) = ctx.read("/etc/rsyslog.conf") {
        conf.push_str(&c);
    }
    if let Some(c) = ctx.read("/etc/rsyslog.d/50-default.conf") {
        conf.push_str(&c);
    }
    if conf.is_empty() {
        return degraded("rsyslog configuration not found");
    }
    let mut missing = Vec::new();
    for fac in ["auth,authpriv.*", "daemon.*", "syslog.*"] {
        let base = fac.split('.').next().unwrap_or(fac);
        if !conf.lines().any(|l| l.trim_start().starts_with(base)) {
            missing.push(fac);
        }
    }
    if missing.is_empty() {
        ok("auth/authpriv, daemon, syslog facilities configured".into(), "/etc/rsyslog.conf".into(), "grep -E 'auth|daemon|syslog' /etc/rsyslog.conf".into())
    } else {
        nok(format!("missing facilities: {}", missing.join(", ")), "/etc/rsyslog.conf".into(), "grep -E 'auth|daemon|syslog' /etc/rsyslog.conf".into())
    }
}

fn journald_kv(ctx: &mut ScanContext, key: &str, want: &str) -> CheckOutcome {
    if let Some(conf) = ctx.read("/etc/systemd/journald.conf") {
        let val = conf
            .lines()
            .map(str::trim_start)
            .filter(|l| !l.starts_with('#'))
            .find_map(|l| l.strip_prefix(&format!("{key}=")).map(str::to_string));
        let loc = "/etc/systemd/journald.conf";
        match val {
            Some(v) if v == want => ok(format!("{key}={v}"), loc.to_string(), format!("journalctl --help | grep {key}")),
            Some(v) => nok(format!("{key}={v} (expected {want})"), loc.to_string(), format!("grep {key} {loc}")),
            None => {
                let default = match key {
                    "ForwardToSyslog" => "no",
                    "Compress" => "no",
                    "Storage" => "auto",
                    _ => "kernel default",
                };
                nok(format!("{key} unset — default {default} applies (expected {want})"), loc.to_string(), format!("grep {key} {loc}"))
            }
        }
    } else {
        degraded("journald.conf not found")
    }
}

fn journald_rate_limit(ctx: &mut ScanContext) -> CheckOutcome {
    if let Some(conf) = ctx.read("/etc/systemd/journald.conf") {
        let burst = conf.lines().find_map(|l| l.trim_start().strip_prefix("RateLimitBurst=").and_then(|v| v.parse::<u64>().ok()));
        match burst {
            Some(b) if b >= 1000 => ok(format!("RateLimitBurst={b}"), "/etc/systemd/journald.conf".into(), "grep RateLimitBurst /etc/systemd/journald.conf".into()),
            Some(b) => nok(format!("RateLimitBurst={b} (< 1000 may drop bursts)"), "/etc/systemd/journald.conf".into(), "grep RateLimitBurst".into()),
            None => ok("RateLimitBurst unset (systemd default 1000/30s applies)".into(), "/etc/systemd/journald.conf".into(), "grep RateLimitBurst".into()),
        }
    } else {
        degraded("journald.conf not found")
    }
}

fn logrotate_present(ctx: &mut ScanContext) -> CheckOutcome {
    for p in ["/etc/logrotate.conf", "/etc/logrotate.d"] {
        if ctx.exists(p) {
            return ok(format!("logrotate present ({p})"), p.into(), "cat /etc/logrotate.conf".into());
        }
    }
    nok("no logrotate configuration found".into(), "/etc/logrotate.conf".into(), "ls /etc/logrotate*".into())
}

fn logrotate_retention(ctx: &mut ScanContext) -> CheckOutcome {
    if let Some(conf) = ctx.read("/etc/logrotate.conf") {
        let rot = conf.lines().find_map(|l| l.trim_start().strip_prefix("rotate ").and_then(|v| v.trim().parse::<u32>().ok()));
        let weekly = conf.lines().any(|l| l.trim() == "weekly");
        match rot {
            Some(n) if n >= 13 && weekly => ok(format!("rotate {n} weekly (~{n} weeks retention)"), "/etc/logrotate.conf".into(), "grep -E 'rotate|weekly'".into()),
            Some(n) => nok(format!("rotate {n} weekly={weekly} — under 90-day retention target"), "/etc/logrotate.conf".into(), "grep -E 'rotate|weekly'".into()),
            None => degraded("rotate count not explicit in logrotate.conf"),
        }
    } else {
        degraded("logrotate.conf not found")
    }
}

fn varlog_dir_perms(ctx: &mut ScanContext) -> CheckOutcome {
    match ctx.unix_mode("/var/log") {
        Some(mode) => {
            if mode & 0o002 != 0 || mode & 0o020 != 0 {
                nok(format!("/var/log mode {mode:o} is group/world writable"), "/var/log".into(), "stat /var/log".into())
            } else {
                ok(format!("/var/log mode {mode:o}"), "/var/log".into(), "stat -c '%a' /var/log".into())
            }
        }
        None => degraded("/var/log metadata not readable"),
    }
}

fn file_create_mode(ctx: &mut ScanContext) -> CheckOutcome {
    if let Some(conf) = ctx.read("/etc/rsyslog.conf") {
        let mode = conf
            .lines()
            .find_map(|l| l.trim_start().strip_prefix("$FileCreateMode").map(|r| r.trim().to_string()));
        match mode.as_deref() {
            Some(m) if m == "0640" || m == "0600" || m == "064" || m == "060" => ok(format!("$FileCreateMode {m}"), "/etc/rsyslog.conf".into(), "grep FileCreateMode /etc/rsyslog.conf".into()),
            Some(m) => nok(format!("$FileCreateMode {m} (expected 0640 or stricter)"), "/etc/rsyslog.conf".into(), "grep FileCreateMode".into()),
            None => nok("$FileCreateMode not set (default 0644 applies — too permissive)".into(), "/etc/rsyslog.conf".into(), "grep FileCreateMode".into()),
        }
    } else {
        degraded("rsyslog.conf not found")
    }
}

fn kernel_audit_flag(ctx: &mut ScanContext) -> CheckOutcome {
    if let Some(cmdline) = ctx.read("/proc/cmdline") {
        if cmdline.contains("audit=1") {
            ok("audit=1 on kernel cmdline".into(), "/proc/cmdline".into(), "cat /proc/cmdline".into())
        } else if cmdline.contains("audit=0") {
            nok("audit=0 disables boot-time auditing".into(), "/proc/cmdline".into(), "cat /proc/cmdline".into())
        } else {
            ok("audit flag unset (kernel default enabled)".into(), "/proc/cmdline".into(), "cat /proc/cmdline".into())
        }
    } else {
        degraded("/proc/cmdline not readable")
    }
}
