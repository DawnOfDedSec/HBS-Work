//! LIN-FW: host firewall posture (CIS 3.5). Service existence first,
//! config depth second; missing managers are N/A with evidence of all
//! probes.

use crate::checks::{degraded, degraded_from_attempts, in_container, nok, not_applicable, ok};
use crate::context::ScanContext;
use crate::model::{CheckOutcome, FallbackAttempt, RegisteredCheck};
use crate::platform::Os;

pub fn register(reg: &mut Vec<RegisteredCheck>) {
    use crate::check;
    check!(
        reg,
        "LIN-FW-001",
        "A host firewall service is running",
        "One of firewalld/ufw/nftables/iptables must be active.",
        "Every listening service is exposed without a local firewall.",
        "Enable and start firewalld/ufw/nftables.",
        High,
        "Firewall",
        &["CIS 3.5.1-3"],
        linux,
        fw_running
    );
    check!(
        reg,
        "LIN-FW-002",
        "Firewall enabled at boot",
        "The active firewall must also be enabled at boot.",
        "Reboots silently drop the protection otherwise.",
        "systemctl enable <firewall>.",
        Medium,
        "Firewall",
        &["CIS 3.5.1"],
        linux,
        fw_enabled
    );
    check!(
        reg,
        "LIN-FW-003",
        "Default zone denies traffic",
        "firewalld default zone should drop unmatched input.",
        "Accept-by-default zones let probes reach services.",
        "firewall-cmd --set-default-zone=drop (or restrictive custom zone).",
        Medium,
        "Firewall",
        &["CIS 3.5.2.2"],
        linux,
        fw_default_zone
    );
    check!(
        reg,
        "LIN-FW-004",
        "ufw default policy denies incoming",
        "ufw default incoming policy must be deny.",
        "Allow-by-default ufw protects nothing.",
        "ufw default deny incoming.",
        Medium,
        "Firewall",
        &["CIS 3.5.3.2.1"],
        linux,
        ufw_default_deny
    );
    check!(
        reg,
        "LIN-FW-005",
        "nftables ruleset is non-empty",
        "A loaded nftables ruleset must contain actual rules.",
        "Empty rulesets lull operators; nothing is filtered.",
        "nft list ruleset — define table/filter chains.",
        Medium,
        "Firewall",
        &["CIS 3.5.2.5"],
        linux,
        nft_ruleset
    );
}

fn linux(p: &crate::platform::PlatformInfo) -> bool {
    p.os == Os::Linux
}

fn active_firewall(ctx: &mut ScanContext) -> Option<(&'static str, String)> {
    for svc in ["firewalld", "ufw", "nftables"] {
        if let Some(out) = ctx.cmd("systemctl", &["is-active", svc]) {
            if out.trim() == "active" {
                return Some((svc, out.trim().to_string()));
            }
        }
    }
    if let Some(out) = ctx.cmd("iptables", &["-L", "-n"]) {
        if out.lines().count() > 3 {
            return Some(("iptables", format!("{} rules lines", out.lines().count())));
        }
    }
    None
}

const CONTAINER_REASON: &str =
    "host firewall service is outside the container; a container has no host firewall subsystem";

fn fw_running(ctx: &mut ScanContext) -> CheckOutcome {
    if in_container(ctx) {
        return not_applicable(CONTAINER_REASON);
    }
    let mut log = Vec::new();
    for svc in ["firewalld", "ufw", "nftables"] {
        match ctx.cmd("systemctl", &["is-active", svc]) {
            Some(out) => log.push(FallbackAttempt {
                source: format!("systemctl is-active {svc}").into(),
                outcome: out.trim().to_string(),
            }),
            None => log.push(FallbackAttempt {
                source: format!("systemctl is-active {svc}").into(),
                outcome: "unavailable".into(),
            }),
        }
    }
    match active_firewall(ctx) {
        Some((svc, detail)) => ok(
            format!("{svc} active ({detail})"),
            "systemd".into(),
            format!("systemctl is-active {svc}"),
        ),
        None => {
            if log.iter().any(|f| f.outcome == "unavailable") {
                degraded("firewall services not queryable (no systemd?); verify manually")
            } else {
                nok(
                    format!(
                        "no firewall service active — probes: {}",
                        log.iter()
                            .map(|f| format!("{}={}", f.source, f.outcome))
                            .collect::<Vec<_>>()
                            .join("; ")
                    ),
                    "systemd".into(),
                    "systemctl is-active firewalld ufw nftables".into(),
                )
            }
        }
    }
}

fn fw_enabled(ctx: &mut ScanContext) -> CheckOutcome {
    if in_container(ctx) {
        return not_applicable(CONTAINER_REASON);
    }
    let mut log = Vec::new();
    let mut queried = false;
    for svc in ["firewalld", "nftables", "ufw"] {
        match ctx.cmd("systemctl", &["is-enabled", svc]) {
            Some(out) => {
                queried = true;
                log.push(FallbackAttempt {
                    source: format!("systemctl is-enabled {svc}"),
                    outcome: out.trim().to_string(),
                });
                if out.trim() == "enabled" {
                    return ok(
                        format!("{svc} enabled at boot"),
                        "systemd".into(),
                        format!("systemctl is-enabled {svc}"),
                    );
                }
            }
            None => log.push(FallbackAttempt {
                source: format!("systemctl is-enabled {svc}"),
                outcome: "unavailable".into(),
            }),
        }
    }
    if !queried {
        return degraded_from_attempts(
            log,
            "firewall boot state not queryable (systemctl unavailable)",
        );
    }
    nok(
        "no firewall service is enabled at boot".into(),
        "systemd".into(),
        "systemctl is-enabled firewalld nftables ufw".into(),
    )
}

fn fw_default_zone(ctx: &mut ScanContext) -> CheckOutcome {
    if in_container(ctx) {
        return not_applicable(CONTAINER_REASON);
    }
    if let Some(out) = ctx.cmd("firewall-cmd", &["--get-default-zone"]) {
        let zone = out.trim();
        let loc = "firewalld config".to_string();
        if zone == "drop" || zone == "block" || zone == "public" {
            if zone == "public" {
                ok(
                    format!("default zone {zone} (public — verify only intended services allowed)"),
                    loc,
                    "firewall-cmd --get-default-zone".into(),
                )
            } else {
                ok(
                    format!("default zone {zone}"),
                    loc,
                    "firewall-cmd --get-default-zone".into(),
                )
            }
        } else {
            nok(
                format!("default zone {zone} is permissive (expected drop/block)"),
                loc,
                "firewall-cmd --get-default-zone".into(),
            )
        }
    } else {
        degraded("firewalld not present/queryable (check applies to firewalld hosts)")
    }
}

fn ufw_default_deny(ctx: &mut ScanContext) -> CheckOutcome {
    if in_container(ctx) {
        return not_applicable(CONTAINER_REASON);
    }
    if let Some(out) = ctx.cmd("ufw", &["status", "verbose"]) {
        let line = out.lines().find(|l| l.starts_with("Default:"));
        let loc = "ufw".to_string();
        match line {
            Some(l) if l.contains("deny (incoming)") || l.contains("deny incoming") => {
                ok(l.trim().to_string(), loc, "ufw status verbose".into())
            }
            Some(l) => nok(
                format!("ufw default policy: {}", l.trim()),
                loc,
                "ufw status verbose".into(),
            ),
            None => degraded("ufw verbose output unreadable"),
        }
    } else if let Some(defaults) = ctx.read("/etc/default/ufw") {
        let pol = defaults
            .lines()
            .find_map(|l| l.trim_start().strip_prefix("DEFAULT_INPUT_POLICY"))
            .map(|rest| {
                rest.trim()
                    .trim_start_matches('=')
                    .trim()
                    .trim_matches('"')
                    .to_string()
            });
        let loc = "/etc/default/ufw".to_string();
        match pol.as_deref() {
            Some("DROP") => ok(
                "DEFAULT_INPUT_POLICY=\"DROP\"".into(),
                loc,
                "grep DEFAULT_INPUT_POLICY /etc/default/ufw".into(),
            ),
            Some(p) => nok(
                format!("DEFAULT_INPUT_POLICY=\"{p}\" (expected DROP)"),
                loc,
                "grep DEFAULT_INPUT_POLICY /etc/default/ufw".into(),
            ),
            None => degraded("DEFAULT_INPUT_POLICY not set (ufw defaults apply)"),
        }
    } else {
        degraded("ufw not present (check applies to ufw hosts)")
    }
}

fn nft_ruleset(ctx: &mut ScanContext) -> CheckOutcome {
    if in_container(ctx) {
        return not_applicable(CONTAINER_REASON);
    }
    if let Some(out) = ctx.cmd("nft", &["list", "ruleset"]) {
        let rules = out
            .lines()
            .filter(|l| {
                l.contains("rule")
                    || l.trim_start().starts_with("ip ")
                    || l.trim_start().starts_with("tcp")
            })
            .count();
        let loc = "nftables".to_string();
        if rules > 0 {
            ok(
                format!("nftables ruleset with ~{rules} rule lines"),
                loc,
                "nft list ruleset".into(),
            )
        } else {
            nok(
                "nftables loaded but ruleset is empty".into(),
                loc,
                "nft list ruleset".into(),
            )
        }
    } else {
        degraded("nft not present/queryable (needs root; check applies to nftables hosts)")
    }
}
