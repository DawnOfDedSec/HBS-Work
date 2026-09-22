//! LIN-AU: auditd daemon and rule coverage (CIS 4.1.x).

use crate::checks::{degraded, degraded_from_attempts, nok, ok};
use crate::context::ScanContext;
use crate::model::{CheckOutcome, FallbackAttempt, RegisteredCheck};
use crate::platform::Os;

pub fn register(reg: &mut Vec<RegisteredCheck>) {
    use crate::check;
    check!(reg, "LIN-AU-001", "auditd installed and enabled", "The audit daemon must be installed and enabled at boot.", "No auditd means no syscall-level audit trail for forensics.", "Install auditd; systemctl enable auditd.", Medium, "Audit", &["CIS 4.1.1.1-2"], linux, auditd_enabled);
    check!(reg, "LIN-AU-002", "auditd process running", "auditd must be running.", "Enabled-but-stopped auditd logs nothing.", "systemctl start auditd.", Medium, "Audit", &["CIS 4.1.2"], linux, |c| svc_active(c, "auditd"));
    check!(reg, "LIN-AU-003", "Audit log storage size adequate", "max_log_file should be sized for retention.", "Small logs rotate away evidence quickly.", "Set max_log_file >= 8 (MB) in auditd.conf.", Low, "Audit", &["CIS 4.1.2.1"], linux, |c| auditd_conf_num(c, "max_log_file", 8, true));
    check!(reg, "LIN-AU-004", "Audit log full action", "Action on full logs must keep the system monitored.", "rotate silently loses events; suspend loses everything.", "max_log_file_action = keep_logs (or rotate with space_left_action=email).", Medium, "Audit", &["CIS 4.1.2.2"], linux, auditd_full_action);
    check!(reg, "LIN-AU-005", "Space left action warns", "Disk pressure on audit logs must alert.", "Silent audit death under disk-full hides intrusions.", "space_left_action = email or exec.", Medium, "Audit", &["CIS 4.1.2.3"], linux, auditd_space_action);
    check!(reg, "LIN-AU-006", "Identity files changes audited", "passwd/group/shadow/sudoers changes must generate audit events.", "Account tampering must be visible.", "Add -w rules for /etc/passwd,/etc/group,/etc/shadow,/etc/sudoers.", Medium, "Audit", &["CIS 4.1.4"], linux, |c| audit_rules_watch(c, &["/etc/passwd", "/etc/group", "/etc/shadow", "/etc/sudoers"]));
    check!(reg, "LIN-AU-007", "Login/session events audited", "lastlog/faillog files must be watched.", "Logon tampering blinds correlation.", "Watch /var/log/faillog, /var/log/lastlog, /var/log/tallylog.", Medium, "Audit", &["CIS 4.1.9"], linux, |c| audit_rules_watch(c, &["/var/log/faillog", "/var/log/lastlog", "/var/log/tallylog"]));
    check!(reg, "LIN-AU-008", "Session file changes audited", "wtmp/btmp watches required.", "Session records are forensic anchors.", "Watch /var/run/utmp, /var/log/wtmp, /var/log/btmp.", Medium, "Audit", &["CIS 4.1.10"], linux, |c| audit_rules_watch(c, &["/var/run/utmp", "/var/log/wtmp", "/var/log/btmp"]));
    check!(reg, "LIN-AU-009", "Time-change events audited", "date/adjtime watches required.", "Time manipulation defeats log correlation.", "Watch /etc/localtime; -a time-change syscall rules.", Medium, "Audit", &["CIS 4.1.11"], linux, time_change_audited);
    check!(reg, "LIN-AU-010", "Perm-modification syscalls audited", "chmod/fchmod/chown family rules required.", "Permission changes on sensitive files are attack steps.", "Add -a always,exit -S rules for perm-mod syscalls.", Medium, "Audit", &["CIS 4.1.6"], linux, perm_mod_audited);
    check!(reg, "LIN-AU-011", "Immutable audit configuration", "-e 2 makes the rule set immutable until reboot.", "Attackers mute auditd rules freely without it.", "Finish rules with -e 2 (audit.rules).", Medium, "Audit", &["CIS 4.1.12"], linux, audit_immutable);
    check!(reg, "LIN-AU-012", "User/group deletion events audited", "delete syscall rules (unlink,unlinkat) required.", "Malware deletes payloads; missing rules hide it.", "Add -a always,exit -S unlink,unlinkat rules for 64/32-bit.", Low, "Audit", &["CIS 4.1.13"], linux, delete_audited);
}

fn linux(p: &crate::platform::PlatformInfo) -> bool {
    p.os == Os::Linux
}

fn audit_rules_text(ctx: &mut ScanContext) -> Option<String> {
    if let Some(out) = ctx.cmd("auditctl", &["-l"]) {
        if !out.trim().is_empty() {
            return Some(out);
        }
    }
    let mut combined = String::new();
    for p in ["/etc/audit/audit.rules", "/etc/audit/rules.d/audit.rules"] {
        if let Some(c) = ctx.read(p) {
            combined.push_str(&c);
        }
    }
    (!combined.is_empty()).then_some(combined)
}

fn auditd_conf_kv(ctx: &mut ScanContext, key: &str) -> Option<String> {
    ctx.read("/etc/audit/auditd.conf").and_then(|c| {
        c.lines()
            .map(str::trim_start)
            .find_map(|l| l.strip_prefix(key).and_then(|r| r.trim_start().strip_prefix('=').map(|v| v.trim().to_string())))
    })
}

fn auditd_enabled(ctx: &mut ScanContext) -> CheckOutcome {
    if let Some(state) = ctx.cmd("systemctl", &["is-enabled", "auditd"]) {
        if state.trim() == "enabled" {
            return ok("auditd enabled".into(), "systemd".into(), "systemctl is-enabled auditd".into());
        }
        return nok(format!("auditd not enabled ({})", state.trim()), "systemd".into(), "systemctl is-enabled auditd".into());
    }
    if ctx.exists("/etc/audit/auditd.conf") {
        return degraded("auditd config present but service state not queryable");
    }
    degraded_from_attempts(
        vec![
            FallbackAttempt { source: "systemctl is-enabled auditd".into(), outcome: "unavailable".into() },
            FallbackAttempt { source: "/etc/audit/auditd.conf".into(), outcome: "missing".into() },
        ],
        "auditd service state not queryable and /etc/audit/auditd.conf absent",
    )
}

fn svc_active(ctx: &mut ScanContext, svc: &str) -> CheckOutcome {
    if let Some(out) = ctx.cmd("systemctl", &["is-active", svc]) {
        if out.trim() == "active" {
            ok(format!("{svc} active"), "systemd".into(), format!("systemctl is-active {svc}"))
        } else {
            nok(format!("{svc} {}", out.trim()), "systemd".into(), format!("systemctl is-active {svc}"))
        }
    } else if ctx.exists(&format!("/var/run/{svc}.pid")) {
        ok(format!("{svc} pid file present"), "/var/run".into(), format!("ls /var/run/{svc}.pid"))
    } else {
        degraded(&format!("{svc} state not queryable (no systemd?)"))
    }
}

fn auditd_conf_num(ctx: &mut ScanContext, key: &str, min: u64, _at_least: bool) -> CheckOutcome {
    match auditd_conf_kv(ctx, key) {
        Some(v) => {
            let n: u64 = v.parse().unwrap_or(0);
            if n >= min {
                ok(format!("{key} = {n}"), "/etc/audit/auditd.conf".into(), format!("grep {key} /etc/audit/auditd.conf"))
            } else {
                nok(format!("{key} = {n} (< {min})"), "/etc/audit/auditd.conf".into(), format!("grep {key} /etc/audit/auditd.conf"))
            }
        }
        None => degraded(&format!("{key} not set in auditd.conf (or file absent) — auditd may be uninstalled")),
    }
}

fn auditd_full_action(ctx: &mut ScanContext) -> CheckOutcome {
    match auditd_conf_kv(ctx, "max_log_file_action") {
        Some(a) if a == "keep_logs" || a == "rotate" => ok(format!("max_log_file_action = {a}"), "/etc/audit/auditd.conf".into(), "grep max_log_file_action".into()),
        Some(a) => nok(format!("max_log_file_action = {a} (expected keep_logs/rotate)"), "/etc/audit/auditd.conf".into(), "grep max_log_file_action".into()),
        None => degraded("max_log_file_action not set — auditd may be uninstalled"),
    }
}

fn auditd_space_action(ctx: &mut ScanContext) -> CheckOutcome {
    match auditd_conf_kv(ctx, "space_left_action") {
        Some(a) if a == "email" || a == "exec" || a == "single" || a == "halt" => ok(format!("space_left_action = {a}"), "/etc/audit/auditd.conf".into(), "grep space_left_action".into()),
        Some(a) => nok(format!("space_left_action = {a} (expected email/exec or stricter)"), "/etc/audit/auditd.conf".into(), "grep space_left_action".into()),
        None => degraded("space_left_action not set — auditd may be uninstalled"),
    }
}

fn audit_rules_watch(ctx: &mut ScanContext, paths: &[&str]) -> CheckOutcome {
    let Some(rules) = audit_rules_text(ctx) else {
        return degraded("audit rules not readable (auditd absent or needs root — run with --elevate)");
    };
    let missing: Vec<&str> = paths
        .iter()
        .copied()
        .filter(|p| !rules.contains(p))
        .collect();
    let loc = "auditctl -l / /etc/audit/audit.rules".to_string();
    if missing.is_empty() {
        ok(format!("watches present: {}", paths.join(", ")), loc, "auditctl -l".into())
    } else {
        nok(format!("missing watches: {}", missing.join(", ")), loc, "auditctl -l | grep -w <path>".into())
    }
}

fn time_change_audited(ctx: &mut ScanContext) -> CheckOutcome {
    let Some(rules) = audit_rules_text(ctx) else {
        return degraded("audit rules not readable (needs root — run with --elevate)");
    };
    let has_watch = rules.contains("/etc/localtime");
    let has_syscalls = rules.contains("time-change") || (rules.contains("adjtimex") && rules.contains("settimeofday"));
    let loc = "audit rules".to_string();
    if has_watch && has_syscalls {
        ok("localtime watch + time-change syscalls present".into(), loc, "auditctl -l | grep time".into())
    } else if has_watch || has_syscalls {
        nok(format!("partial: watch={has_watch} syscalls={has_syscalls}"), loc, "auditctl -l | grep -E 'localtime|adjtimex'".into())
    } else {
        nok("no time-change auditing".into(), loc, "auditctl -l | grep -E 'localtime|adjtimex'".into())
    }
}

fn perm_mod_audited(ctx: &mut ScanContext) -> CheckOutcome {
    let Some(rules) = audit_rules_text(ctx) else {
        return degraded("audit rules not readable (needs root — run with --elevate)");
    };
    let mut have = 0;
    for sc in ["chmod", "fchmod", "fchmodat", "chown", "fchown", "fchownat", "lchown"] {
        if rules.contains(sc) {
            have += 1;
        }
    }
    let loc = "audit rules".to_string();
    if have >= 5 {
        ok(format!("{have}/7 perm-mod syscalls covered"), loc, "auditctl -l | grep -E 'chmod|chown'".into())
    } else {
        nok(format!("only {have}/7 perm-mod syscalls covered"), loc, "auditctl -l | grep -E 'chmod|chown'".into())
    }
}

fn delete_audited(ctx: &mut ScanContext) -> CheckOutcome {
    let Some(rules) = audit_rules_text(ctx) else {
        return degraded("audit rules not readable (needs root — run with --elevate)");
    };
    if rules.contains("unlink") || rules.contains("unlinkat") {
        ok("unlink/unlinkat rules present".into(), "audit rules".into(), "auditctl -l | grep unlink".into())
    } else {
        nok("no unlink/unlinkat rules".into(), "audit rules".into(), "auditctl -l | grep unlink".into())
    }
}

fn audit_immutable(ctx: &mut ScanContext) -> CheckOutcome {
    let Some(rules) = ctx.read("/etc/audit/audit.rules").or_else(|| ctx.read("/etc/audit/rules.d/audit.rules")) else {
        return degraded("audit.rules file not readable");
    };
    if rules.lines().any(|l| l.trim() == "-e 2") {
        ok("-e 2 immutability set".into(), "/etc/audit/audit.rules".into(), "grep -w '\\-e 2' /etc/audit/audit.rules".into())
    } else if rules.lines().any(|l| l.trim() == "-e 1") {
        nok("-e 1 (immutable until next reboot) — upgrade to -e 2".into(), "/etc/audit/audit.rules".into(), "grep '\\-e ' /etc/audit/audit.rules".into())
    } else {
        nok("audit rules not immutable (no -e 2)".into(), "/etc/audit/audit.rules".into(), "grep '\\-e ' /etc/audit/audit.rules".into())
    }
}
