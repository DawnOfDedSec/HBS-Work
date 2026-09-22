//! LIN-NET: network kernel parameters (CIS 3.1/3.2 + threat-informed
//! additions). Every value: /proc/sys first, `sysctl -n` fallback.

use super::sysctl_value;
use crate::checks::{degraded, err_outcome, nok, ok};
use crate::context::ScanContext;
use crate::model::{CheckOutcome, FallbackAttempt, RegisteredCheck};
use crate::platform::Os;

pub fn register(reg: &mut Vec<RegisteredCheck>) {
    use crate::check;
    check!(reg, "LIN-NET-001", "IP forwarding disabled", "Routers forward packets between interfaces; servers must not.", "A forwarding host bridges network segments and bypasses segmentation controls.", "sysctl -w net.ipv4.ip_forward=0 (persist in sysctl.d).", Medium, "Network", &["CIS 3.1.1"], linux, |c| sysctl_eq(c, "net.ipv4.ip_forward", "0", false));
    check!(reg, "LIN-NET-002", "IPv6 forwarding disabled", "Same rationale for IPv6.", "IPv6 forwarding bypasses v4-only segmentation.", "sysctl net.ipv6.conf.all.forwarding=0.", Medium, "Network", &["CIS 3.1.2"], linux, |c| sysctl_eq(c, "net.ipv6.conf.all.forwarding", "0", false));
    check!(reg, "LIN-NET-003", "ICMP broadcast echoes ignored", "No smurf-amplification responses.", "Broadcast ICMP amplifies denial-of-service traffic.", "net.ipv4.icmp_echo_ignore_broadcasts=1.", Low, "Network", &["CIS 3.2.2"], linux, |c| sysctl_eq(c, "net.ipv4.icmp_echo_ignore_broadcasts", "1", true));
    check!(reg, "LIN-NET-004", "Bogus ICMP error responses ignored", "Ignore malformed ICMP errors.", "Bogus ICMP can crash or confuse legacy stacks.", "net.ipv4.icmp_ignore_bogus_error_responses=1.", Low, "Network", &["CIS 3.2.3"], linux, |c| sysctl_eq(c, "net.ipv4.icmp_ignore_bogus_error_responses", "1", true));
    check!(reg, "LIN-NET-005", "Reverse-path filtering (all)", "rp_filter drops packets with spoofed source routes.", "IP spoofing enables reflection and bypass attacks.", "net.ipv4.conf.all.rp_filter=1.", Medium, "Network", &["CIS 3.2.1"], linux, |c| sysctl_eq(c, "net.ipv4.conf.all.rp_filter", "1", true));
    check!(reg, "LIN-NET-006", "Reverse-path filtering (default)", "Default rp_filter for new interfaces.", "New interfaces inherit weak settings without this.", "net.ipv4.conf.default.rp_filter=1.", Medium, "Network", &["CIS 3.2.1"], linux, |c| sysctl_eq(c, "net.ipv4.conf.default.rp_filter", "1", true));
    check!(reg, "LIN-NET-007", "Source-routed packets refused (v4 all)", "Source routing lets senders dictate paths.", "Source-routed packets bypass firewall topology assumptions.", "net.ipv4.conf.all.accept_source_route=0.", Medium, "Network", &["CIS 3.2.4"], linux, |c| sysctl_eq(c, "net.ipv4.conf.all.accept_source_route", "0", false));
    check!(reg, "LIN-NET-008", "Source-routed packets refused (v4 default)", "Default for new interfaces.", "New interfaces must inherit the refusal.", "net.ipv4.conf.default.accept_source_route=0.", Medium, "Network", &["CIS 3.2.4"], linux, |c| sysctl_eq(c, "net.ipv4.conf.default.accept_source_route", "0", false));
    check!(reg, "LIN-NET-009", "Source-routed packets refused (v6 all+default)", "IPv6 source routing refusal.", "Same spoofing rationale over v6.", "net.ipv6.conf.all/default.accept_source_route=0.", Medium, "Network", &["CIS 3.2.5"], linux, |c| sysctl_pair(c, &["net.ipv6.conf.all.accept_source_route", "net.ipv6.conf.default.accept_source_route"], "0"));
    check!(reg, "LIN-NET-010", "ICMP redirects not accepted (v4 all+default)", "Redirects alter routing tables on attacker say-so.", "MITM attackers redirect traffic via ICMP redirects.", "net.ipv4.conf.{all,default}.accept_redirects=0.", Medium, "Network", &["CIS 3.2.6"], linux, |c| sysctl_pair(c, &["net.ipv4.conf.all.accept_redirects", "net.ipv4.conf.default.accept_redirects"], "0"));
    check!(reg, "LIN-NET-011", "ICMP redirects not accepted (v6 all+default)", "IPv6 variant.", "Same MITM rationale over v6.", "net.ipv6.conf.{all,default}.accept_redirects=0.", Medium, "Network", &["CIS 3.2.7"], linux, |c| sysctl_pair(c, &["net.ipv6.conf.all.accept_redirects", "net.ipv6.conf.default.accept_redirects"], "0"));
    check!(reg, "LIN-NET-012", "Secure ICMP redirects not accepted", "Even 'secure' redirects must be refused.", "Gateway-spoofed redirects reroute traffic.", "net.ipv4.conf.{all,default}.secure_redirects=0.", Medium, "Network", &["CIS 3.2.8"], linux, |c| sysctl_pair(c, &["net.ipv4.conf.all.secure_redirects", "net.ipv4.conf.default.secure_redirects"], "0"));
    check!(reg, "LIN-NET-013", "Suspicious packets logged (martians, all+default)", "log_martians records spoofed-source packets.", "Without martian logging, spoofing goes unseen.", "net.ipv4.conf.{all,default}.log_martians=1.", Low, "Network", &["CIS 3.2.9"], linux, |c| sysctl_pair(c, &["net.ipv4.conf.all.log_martians", "net.ipv4.conf.default.log_martians"], "1"));
    check!(reg, "LIN-NET-014", "ICMP redirects not sent", "Hosts must not emit redirects.", "Attacker-controlled hosts emitting redirects pivot MITM chains.", "net.ipv4.conf.{all,default}.send_redirects=0.", Medium, "Network", &["CIS 3.2.10"], linux, |c| sysctl_pair(c, &["net.ipv4.conf.all.send_redirects", "net.ipv4.conf.default.send_redirects"], "0"));
    check!(reg, "LIN-NET-015", "TCP SYN cookies enabled", "SYN cookies survive SYN floods.", "SYN floods exhaust the half-open backlog and deny service.", "net.ipv4.tcp_syncookies=1.", Medium, "Network", &["CIS 3.2.11"], linux, |c| sysctl_eq(c, "net.ipv4.tcp_syncookies", "1", true));
    check!(reg, "LIN-NET-016", "IPv6 router advertisements not accepted", "RA acceptance lets rogue routers announce routes.", "Rogue RAs hijack default routes on shared segments.", "net.ipv6.conf.{all,default}.accept_ra=0.", Medium, "Network", &["CIS 3.2.12"], linux, |c| sysctl_pair(c, &["net.ipv6.conf.all.accept_ra", "net.ipv6.conf.default.accept_ra"], "0"));
    check!(reg, "LIN-NET-017", "TCP SYN backlog sized", "Backlog hardening complements cookies.", "Tiny backlogs fold under modest floods.", "net.ipv4.tcp_max_syn_backlog >= 2048.", Low, "Network", &["CIS 3.2.12"], linux, syn_backlog);
    check!(reg, "LIN-NET-018", "Protected hardlinks enabled", "Hardlink creation restricted to owners.", "/tmp hardlink attacks against suid binaries.", "fs.protected_hardlinks=1.", Medium, "Network", &["CIS 1.1.18"], linux, |c| sysctl_eq(c, "fs.protected_hardlinks", "1", true));
    check!(reg, "LIN-NET-019", "Protected symlinks enabled", "Symlink following restricted in sticky dirs.", "/tmp symlink attacks overwrite privileged files.", "fs.protected_symlinks=1.", Medium, "Network", &["CIS 1.1.19"], linux, |c| sysctl_eq(c, "fs.protected_symlinks", "1", true));
    check!(reg, "LIN-NET-020", "Unprivileged BPF disabled", "Only root may load BPF programs.", "Unprivileged BPF has repeatedly enabled kernel LPE (CVE-2021-3490 lineage).", "kernel.unprivileged_bpf_disabled=1.", High, "Network", &["CIS 3.2.13", "MITRE T1068"], linux, |c| sysctl_eq(c, "kernel.unprivileged_bpf_disabled", "1", true));
}

fn linux(p: &crate::platform::PlatformInfo) -> bool {
    p.os == Os::Linux
}

/// Compare one sysctl to an expected value. `default_one` marks keys
/// that are 1 by default on modern kernels — absence is degraded (safe
/// default) rather than non-compliant.
fn sysctl_eq(ctx: &mut ScanContext, key: &str, want: &str, default_one: bool) -> CheckOutcome {
    let mut log = Vec::new();
    match sysctl_value(ctx, key) {
        Some(v) => {
            let loc = format!("/proc/sys/{}", key.replace('.', "/"));
            log.push(FallbackAttempt { source: loc.clone(), outcome: format!("value={}", v.trim()) });
            if v.trim() == want {
                ok(format!("{key}={}", v.trim()), loc, format!("sysctl {key}"))
            } else {
                nok(format!("{key}={} (expected {want})", v.trim()), loc, format!("sysctl {key}"))
            }
        }
        None => {
            log.push(FallbackAttempt { source: format!("/proc/sys/{}", key.replace('.', "/")).into(), outcome: "missing".into() });
            log.push(FallbackAttempt { source: format!("sysctl -n {key}").into(), outcome: "unavailable".into() });
            if default_one {
                degraded(&format!("{key} not readable; modern-kernel default is the secure value — verify manually"))
            } else {
                err_outcome(log)
            }
        }
    }
}

/// Two related sysctls that must both equal `want`.
fn sysctl_pair(ctx: &mut ScanContext, keys: &[&str], want: &str) -> CheckOutcome {
    let mut values = Vec::new();
    let mut missing = Vec::new();
    let mut log = Vec::new();
    for key in keys {
        match sysctl_value(ctx, key) {
            Some(v) => {
                log.push(FallbackAttempt { source: format!("sysctl {key}").into(), outcome: format!("value={}", v.trim()) });
                values.push((*key, v.trim().to_string()));
            }
            None => {
                log.push(FallbackAttempt { source: format!("sysctl {key}").into(), outcome: "missing".into() });
                missing.push(*key);
            }
        }
    }
    if !missing.is_empty() && values.is_empty() {
        return err_outcome(log);
    }
    let bad: Vec<String> = values
        .iter()
        .filter(|(_, v)| v != want)
        .map(|(k, v)| format!("{k}={v} (expected {want})"))
        .collect();
    if bad.is_empty() && missing.is_empty() {
        ok(values.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; "), "/proc/sys/net".into(), format!("sysctl {}", keys.join(" ")))
    } else if bad.is_empty() {
        degraded(&format!("{} not present (kernel default applies); verify", missing.join(", ")))
    } else {
        nok(bad.join("; "), "/proc/sys/net".into(), format!("sysctl {}", keys.join(" ")))
    }
}

fn syn_backlog(ctx: &mut ScanContext) -> CheckOutcome {
    match sysctl_value(ctx, "net.ipv4.tcp_max_syn_backlog") {
        Some(v) => {
            let n: u64 = v.trim().parse().unwrap_or(0);
            let loc = "/proc/sys/net/ipv4/tcp_max_syn_backlog".to_string();
            if n >= 2048 {
                ok(format!("tcp_max_syn_backlog={n}"), loc, "sysctl net.ipv4.tcp_max_syn_backlog".into())
            } else {
                nok(format!("tcp_max_syn_backlog={n} (expected >= 2048)"), loc, "sysctl net.ipv4.tcp_max_syn_backlog".into())
            }
        }
        None => degraded("tcp_max_syn_backlog not readable; kernel default (often 256/1280) may be below target"),
    }
}
