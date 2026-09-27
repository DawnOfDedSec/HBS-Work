//! LIN-PAM: passwords, PAM and sudo (CIS 5.3/5.4).

use crate::checks::{degraded, degraded_from_attempts, nok, ok};
use crate::context::ScanContext;
use crate::model::{CheckOutcome, FallbackAttempt, RegisteredCheck};
use crate::platform::Os;

pub fn register(reg: &mut Vec<RegisteredCheck>) {
    use crate::check;
    check!(
        reg,
        "LIN-PAM-001",
        "Password minimum length >= 14",
        "pwquality minlen.",
        "Short passwords fall to GPU brute force in hours.",
        "minlen = 14 in /etc/security/pwquality.conf.",
        Medium,
        "Authentication",
        &["CIS 5.3.1"],
        linux,
        |c| pwquality_num(c, "minlen", 14, true)
    );
    check!(
        reg,
        "LIN-PAM-002",
        "Password character classes required",
        "minclass/credit settings.",
        "Single-class passwords are dictionary-trivial.",
        "minclass = 3 (or dcredit=ucredit=ocredit=lcredit=-1).",
        Medium,
        "Authentication",
        &["CIS 5.3.2"],
        linux,
        pwquality_classes
    );
    check!(
        reg,
        "LIN-PAM-003",
        "Password reuse limited",
        "remember >= 5.",
        "Password cycling defeats history policy.",
        "remember = 5 via pam_pwhistory.",
        Medium,
        "Authentication",
        &["CIS 5.3.3"],
        linux,
        pam_remember
    );
    check!(
        reg,
        "LIN-PAM-004",
        "Account lockout on failures",
        "pam_faillock deny <= 5.",
        "Unlimited attempts = infinite brute force.",
        "pam_faillock deny=5 unlock_time=900.",
        High,
        "Authentication",
        &["CIS 5.3.4"],
        linux,
        pam_faillock
    );
    check!(
        reg,
        "LIN-PAM-005",
        "Password max days <= 365",
        "PASS_MAX_DAYS.",
        "Ancient passwords outlive leaks.",
        "PASS_MAX_DAYS 90 (365 hard cap).",
        Medium,
        "Authentication",
        &["CIS 5.4.1.1"],
        linux,
        |c| login_defs_num(c, "PASS_MAX_DAYS", 365, true)
    );
    check!(
        reg,
        "LIN-PAM-006",
        "Password min days >= 7",
        "PASS_MIN_DAYS.",
        "Zero min-days lets users cycle back to favorites.",
        "PASS_MIN_DAYS 7.",
        Low,
        "Authentication",
        &["CIS 5.4.1.2"],
        linux,
        |c| login_defs_num(c, "PASS_MIN_DAYS", 7, false)
    );
    check!(
        reg,
        "LIN-PAM-007",
        "Password warning days >= 7",
        "PASS_WARN_AGE.",
        "Users need rotation lead time.",
        "PASS_WARN_AGE 7.",
        Low,
        "Authentication",
        &["CIS 5.4.1.3"],
        linux,
        |c| login_defs_num(c, "PASS_WARN_AGE", 7, false)
    );
    check!(
        reg,
        "LIN-PAM-008",
        "Strong password hashing (yescrypt/sha512)",
        "ENCRYPT_METHOD + pam_unix.",
        "MD5/DES hashes crack in seconds.",
        "ENCRYPT_METHOD YESCRYPT (or SHA512).",
        Medium,
        "Authentication",
        &["CIS 5.4.1.4"],
        linux,
        hashing_method
    );
    check!(
        reg,
        "LIN-PAM-009",
        "sudo commands use pty",
        "use_pty default.",
        "Without a pty, sudo input can be injected.",
        "Defaults use_pty in sudoers.",
        Medium,
        "Authentication",
        &["CIS 1.3.2"],
        linux,
        |c| sudoers_has(c, "use_pty")
    );
    check!(
        reg,
        "LIN-PAM-010",
        "sudo log file configured",
        "Defaults logfile.",
        "Unlogged sudo hides admin actions.",
        "Defaults logfile=\"/var/log/sudo.log\".",
        Low,
        "Authentication",
        &["CIS 1.3.3"],
        linux,
        sudoers_logfile
    );
    check!(
        reg,
        "LIN-PAM-011",
        "sudo timeout bounded",
        "timestamp_timeout <= 15.",
        "All-day sudo tickets extend compromise windows.",
        "Defaults timestamp_timeout=15.",
        Low,
        "Authentication",
        &["CIS 1.3.4"],
        linux,
        sudo_timeout
    );
    check!(
        reg,
        "LIN-PAM-012",
        "sudo per-tty tickets",
        "tty_tickets.",
        "One ticket across sessions widens replay.",
        "Defaults tty_tickets (default on; verify).",
        Low,
        "Authentication",
        &[],
        linux,
        |c| sudoers_has(c, "tty_tickets")
    );
    check!(
        reg,
        "LIN-PAM-013",
        "Login shell defined for users",
        "nologin/false shells only for system accounts.",
        "System accounts with shells are login paths.",
        "Set /usr/sbin/nologin for service accounts.",
        Medium,
        "Authentication",
        &["CIS 5.4.1.5"],
        linux,
        shells_sane
    );
    check!(
        reg,
        "LIN-PAM-014",
        "System accounts non-login",
        "uid < 1000 must not have shells.",
        "Daemon accounts with bash = dormant backdoor.",
        "usermod -s /usr/sbin/nologin <acct>.",
        Medium,
        "Authentication",
        &["CIS 5.4.1.5"],
        linux,
        system_acct_shells
    );
}

fn linux(p: &crate::platform::PlatformInfo) -> bool {
    p.os == Os::Linux
}

fn pwquality_kv(ctx: &mut ScanContext, key: &str) -> Option<String> {
    ctx.read("/etc/security/pwquality.conf").and_then(|c| {
        c.lines().map(str::trim_start).find_map(|l| {
            l.strip_prefix(key).and_then(|r| {
                r.trim_start()
                    .strip_prefix('=')
                    .map(|v| v.trim().to_string())
            })
        })
    })
}

fn pwquality_num(ctx: &mut ScanContext, key: &str, want: i64, at_least: bool) -> CheckOutcome {
    match pwquality_kv(ctx, key) {
        Some(v) => {
            let n: i64 = v.parse().unwrap_or(i64::MIN);
            let good = if at_least {
                n >= want
            } else {
                n <= want && n > 0
            };
            let loc = "/etc/security/pwquality.conf".to_string();
            if good {
                ok(
                    format!("{key} = {n}"),
                    loc,
                    format!("grep {key} /etc/security/pwquality.conf"),
                )
            } else {
                nok(
                    format!(
                        "{key} = {n} (want {} {want})",
                        if at_least { ">=" } else { "<=" }
                    ),
                    loc,
                    format!("grep {key} /etc/security/pwquality.conf"),
                )
            }
        }
        None => degraded(&format!(
            "{key} not set - distro default applies (often weaker than target)"
        )),
    }
}

fn pwquality_classes(ctx: &mut ScanContext) -> CheckOutcome {
    if ctx.read("/etc/security/pwquality.conf").is_none() {
        return degraded_from_attempts(
            vec![FallbackAttempt {
                source: "/etc/security/pwquality.conf".into(),
                outcome: "missing or unreadable".into(),
            }],
            "/etc/security/pwquality.conf missing - password class policy not readable",
        );
    }
    let minclass = pwquality_kv(ctx, "minclass");
    let credits = ["dcredit", "ucredit", "ocredit", "lcredit"]
        .iter()
        .filter_map(|k| pwquality_kv(ctx, k))
        .filter(|v| v.starts_with('-'))
        .count();
    let loc = "/etc/security/pwquality.conf".to_string();
    if minclass
        .as_deref()
        .map(|v| v.parse::<i64>().unwrap_or(0) >= 3)
        .unwrap_or(false)
        || credits >= 3
    {
        ok(
            format!("minclass={:?} credits-set={}", minclass, credits),
            loc,
            "grep -E 'minclass|credit' /etc/security/pwquality.conf".into(),
        )
    } else {
        nok(
            format!(
                "weak class enforcement (minclass={:?}, negative credits={})",
                minclass, credits
            ),
            loc,
            "grep -E 'minclass|credit' /etc/security/pwquality.conf".into(),
        )
    }
}

fn login_defs_num(ctx: &mut ScanContext, key: &str, want: i64, at_most: bool) -> CheckOutcome {
    if let Some(conf) = ctx.read("/etc/login.defs") {
        let v = conf
            .lines()
            .map(str::trim_start)
            .filter(|l| !l.starts_with('#'))
            .map(|l| l.split_whitespace().collect::<Vec<&str>>())
            .find(|p| p.len() >= 2 && p[0] == key)
            .and_then(|p| p[1].parse::<i64>().ok());
        let loc = "/etc/login.defs".to_string();
        match v {
            Some(n) => {
                let good = if at_most {
                    n <= want && n > 0
                } else {
                    n >= want
                };
                if good {
                    ok(
                        format!("{key} {n}"),
                        loc,
                        format!("grep {key} /etc/login.defs"),
                    )
                } else {
                    nok(
                        format!(
                            "{Key} {n} (want {cmp} {want})",
                            Key = key,
                            cmp = if at_most { "<=" } else { ">=" }
                        ),
                        loc,
                        format!("grep {key} /etc/login.defs"),
                    )
                }
            }
            None => nok(
                format!("{key} not set in /etc/login.defs (default applies)"),
                loc,
                format!("grep {key} /etc/login.defs"),
            ),
        }
    } else {
        degraded_from_attempts(
            vec![FallbackAttempt {
                source: "/etc/login.defs".into(),
                outcome: "missing".into(),
            }],
            "/etc/login.defs missing",
        )
    }
}

fn pam_files(ctx: &mut ScanContext) -> Vec<(String, String)> {
    let mut files = Vec::new();
    for p in [
        "/etc/pam.d/common-password",
        "/etc/pam.d/system-auth",
        "/etc/pam.d/password-auth",
    ] {
        if let Some(c) = ctx.read(p) {
            files.push((p.to_string(), c));
        }
    }
    files
}

fn pam_remember(ctx: &mut ScanContext) -> CheckOutcome {
    let files = pam_files(ctx);
    if files.is_empty() {
        return degraded("no PAM password policy files found (non-PAM distro?)");
    }
    let best = files
        .iter()
        .filter_map(|(p, c)| {
            c.lines()
                .find(|l| l.contains("pam_pwhistory") || l.contains("remember="))
                .map(|l| (p.clone(), l.trim().to_string()))
        })
        .last();
    let loc = "/etc/pam.d".to_string();
    match best {
        Some((p, line)) => {
            let n = line
                .split("remember=")
                .nth(1)
                .and_then(|r| r.split(&[',', ' '][..]).next())
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(0);
            if n >= 5 {
                ok(
                    format!("remember={n} ({p})", p = p),
                    loc,
                    "grep remember= /etc/pam.d/*".into(),
                )
            } else {
                nok(
                    format!("remember={n} < 5 ({line})"),
                    loc,
                    "grep remember= /etc/pam.d/*".into(),
                )
            }
        }
        None => nok(
            "no pam_pwhistory remember rule found".into(),
            loc,
            "grep remember= /etc/pam.d/*".into(),
        ),
    }
}

fn pam_faillock(ctx: &mut ScanContext) -> CheckOutcome {
    let files = pam_files(ctx);
    if files.is_empty() {
        return degraded("no PAM policy files found");
    }
    let mut deny_vals = Vec::new();
    for (p, c) in &files {
        for line in c.lines() {
            if line.contains("pam_faillock") || line.contains("pam_tally2") {
                let deny = line
                    .split("deny=")
                    .nth(1)
                    .and_then(|r| r.split(&[',', ' '][..]).next())
                    .and_then(|v| v.parse::<i64>().ok())
                    .unwrap_or(999);
                deny_vals.push((p.clone(), deny, line.trim().to_string()));
            }
        }
    }
    let loc = "/etc/pam.d".to_string();
    if deny_vals.is_empty() {
        return nok(
            "no faillock/tally lockout rule found".into(),
            loc,
            "grep -R faillock /etc/pam.d".into(),
        );
    }
    let worst = deny_vals.iter().map(|(_, d, _)| *d).max().unwrap_or(999);
    if worst <= 5 && worst > 0 {
        ok(
            deny_vals
                .iter()
                .map(|(p, d, l)| format!("{p}: deny={d} [{l}]"))
                .collect::<Vec<_>>()
                .join("; "),
            loc,
            "grep -R faillock /etc/pam.d".into(),
        )
    } else {
        nok(
            format!("weakest deny={worst} (> 5)"),
            loc,
            "grep -R 'deny=' /etc/pam.d".into(),
        )
    }
}

fn hashing_method(ctx: &mut ScanContext) -> CheckOutcome {
    if let Some(conf) = ctx.read("/etc/login.defs") {
        let m = conf
            .lines()
            .map(str::trim_start)
            .filter(|l| !l.starts_with('#'))
            .find_map(|l| {
                l.strip_prefix("ENCRYPT_METHOD")
                    .map(|r| r.trim().to_string())
            });
        let loc = "/etc/login.defs".to_string();
        match m.as_deref() {
            Some(v @ ("YESCRYPT" | "SHA512" | "YES" | "SHA256")) => ok(
                format!("ENCRYPT_METHOD {v}"),
                loc,
                "grep ENCRYPT_METHOD /etc/login.defs".into(),
            ),
            Some(v) => nok(
                format!("ENCRYPT_METHOD {v} (expected YESCRYPT/SHA512)"),
                loc,
                "grep ENCRYPT_METHOD /etc/login.defs".into(),
            ),
            None => nok(
                "ENCRYPT_METHOD unset - crypt(3) default (DES on legacy) may apply".into(),
                loc,
                "grep ENCRYPT_METHOD".into(),
            ),
        }
    } else {
        degraded("/etc/login.defs missing")
    }
}

fn sudoers_text(ctx: &mut ScanContext) -> Option<String> {
    let mut all = String::new();
    if let Some(c) = ctx.read("/etc/sudoers") {
        all.push_str(&c);
    }
    // sample a common drop-in
    if let Some(c) = ctx.read("/etc/sudoers.d/README") {
        all.push_str(&c);
    }
    (!all.is_empty()).then_some(all)
}

fn sudoers_has(ctx: &mut ScanContext, option: &str) -> CheckOutcome {
    match sudoers_text(ctx) {
        Some(s) => {
            let loc = "/etc/sudoers".to_string();
            if s.lines()
                .any(|l| l.trim_start().starts_with("Defaults") && l.contains(option))
            {
                ok(
                    format!("Defaults {option} present"),
                    loc,
                    format!("sudo grep 'Defaults.*{option}' /etc/sudoers"),
                )
            } else {
                nok(
                    format!("Defaults {option} not set"),
                    loc,
                    format!("sudo grep 'Defaults.*{option}' /etc/sudoers"),
                )
            }
        }
        None => degraded("/etc/sudoers not readable (needs root - run with --elevate)"),
    }
}

fn sudoers_logfile(ctx: &mut ScanContext) -> CheckOutcome {
    match sudoers_text(ctx) {
        Some(s) => {
            let loc = "/etc/sudoers".to_string();
            if s.lines()
                .any(|l| l.starts_with("Defaults") && l.contains("logfile"))
            {
                ok(
                    "sudo logfile configured".into(),
                    loc,
                    "sudo grep logfile /etc/sudoers".into(),
                )
            } else {
                nok(
                    "no sudo logfile configured".into(),
                    loc,
                    "sudo grep logfile /etc/sudoers".into(),
                )
            }
        }
        None => degraded("/etc/sudoers not readable (needs root - run with --elevate)"),
    }
}

fn sudo_timeout(ctx: &mut ScanContext) -> CheckOutcome {
    match sudoers_text(ctx) {
        Some(s) => {
            let loc = "/etc/sudoers".to_string();
            let t = s.lines().find_map(|l| {
                l.trim_start()
                    .strip_prefix("Defaults")
                    .and_then(|r| r.trim_start().strip_prefix("timestamp_timeout="))
                    .map(|v| v.trim().to_string())
            });
            match t {
                Some(v) => {
                    let n: f64 = v.parse().unwrap_or(f64::MAX);
                    if n <= 15.0 {
                        ok(
                            format!("timestamp_timeout={v}"),
                            loc,
                            "sudo grep timestamp_timeout".into(),
                        )
                    } else {
                        nok(
                            format!("timestamp_timeout={v} (> 15)"),
                            loc,
                            "sudo grep timestamp_timeout".into(),
                        )
                    }
                }
                None => nok(
                    "timestamp_timeout not set - default 15 (tty_tickets-dependent); verify".into(),
                    loc,
                    "sudo grep timestamp_timeout".into(),
                ),
            }
        }
        None => degraded("/etc/sudoers not readable (needs root)"),
    }
}

fn passwd_entries(ctx: &mut ScanContext) -> Vec<Vec<String>> {
    ctx.read("/etc/passwd")
        .map(|c| {
            c.lines()
                .filter_map(|l| {
                    let f: Vec<&str> = l.split(':').collect();
                    (f.len() >= 7).then(|| f.iter().map(|s| s.to_string()).collect())
                })
                .collect()
        })
        .unwrap_or_default()
}

fn shells_sane(ctx: &mut ScanContext) -> CheckOutcome {
    let entries = passwd_entries(ctx);
    if entries.is_empty() {
        return degraded("/etc/passwd not readable");
    }
    let bad: Vec<String> = entries
        .iter()
        .filter(|f| f[6].is_empty())
        .map(|f| f[0].clone())
        .collect();
    if bad.is_empty() {
        ok(
            format!("all {} users have shells defined", entries.len()),
            "/etc/passwd".into(),
            "awk -F: '$7==\"\" {print}' /etc/passwd".into(),
        )
    } else {
        nok(
            format!("users with empty shells: {}", bad.join(", ")),
            "/etc/passwd".into(),
            "awk -F: '$7==\"\"' /etc/passwd".into(),
        )
    }
}

fn system_acct_shells(ctx: &mut ScanContext) -> CheckOutcome {
    let entries = passwd_entries(ctx);
    if entries.is_empty() {
        return degraded("/etc/passwd not readable");
    }
    let login_shells = ["/bin/bash", "/bin/sh", "/bin/dash", "/bin/zsh", "/bin/ksh"];
    let bad: Vec<String> = entries
        .iter()
        .filter(|f| {
            let uid: u32 = f[2].parse().unwrap_or(u32::MAX);
            uid < 1000 && f[0] != "root" && login_shells.contains(&f[6].as_str())
        })
        .map(|f| format!("{} (uid={}, shell={})", f[0], f[2], f[6]))
        .collect();
    if bad.is_empty() {
        ok(
            "no system accounts with login shells".into(),
            "/etc/passwd".into(),
            "awk -F: '$3<1000 && $7~/bash|sh/ {print}' /etc/passwd".into(),
        )
    } else {
        nok(
            format!("system accounts with login shells: {}", bad.join(", ")),
            "/etc/passwd".into(),
            "awk -F: '$3<1000' /etc/passwd".into(),
        )
    }
}
