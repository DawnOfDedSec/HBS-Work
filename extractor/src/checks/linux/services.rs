//! LIN-SV: legacy/inetd services and dangerous service packages
//! (CIS 2.x).

use crate::checks::{degraded, err_outcome, nok, ok};
use crate::context::ScanContext;
use crate::model::{CheckOutcome, FallbackAttempt, RegisteredCheck};
use crate::platform::{DistroFamily, Os};

pub fn register(reg: &mut Vec<RegisteredCheck>) {
    use crate::check;
    check!(reg, "LIN-SV-001", "xinetd not enabled", "The legacy inet super-server should not run.", "Every enabled legacy listener is unreviewed attack surface.", "systemctl disable --now xinetd; uninstall if unused.", Medium, "Services", &["CIS 2.1.1"], linux, |c| svc_disabled(c, "xinetd"));
    check!(reg, "LIN-SV-002", "inetd.conf services absent", "Classic inetd entries must not exist.", "telnet/finger/daytime via inetd are plaintext relic services.", "Remove /etc/inetd.conf entries; uninstall openbsd-inetd.", Medium, "Services", &["CIS 2.2.1"], linux, inetd_conf_absent);
    check!(reg, "LIN-SV-003", "time-sync services active", "chrony/ntp/systemd-timesyncd must be running.", "Clock drift breaks Kerberos, TLS and log correlation.", "Enable chronyd (or timesyncd); point at approved NTP.", Medium, "Services", &["CIS 2.1.3"], linux, time_sync_active);
    check!(reg, "LIN-SV-004", "MTA not listening on all interfaces", "The default MTA should be local-only unless it is a mail server.", "Internet-exposed MTAs inherit a long CVE tail and spam abuse.", "Configure postfix inet_interfaces=loopback-only or remove MTA.", Low, "Services", &["CIS 2.2.15"], linux, mta_local_only);
    check!(reg, "LIN-SV-005", "telnet client absent", "Cleartext remote-admin client invites credential capture.", "telnet traffic is fully readable on the wire.", "apt/dnf remove telnet.", Low, "Services", &["CIS 2.3.1"], linux, |c| pkg_absent(c, &["telnet"]));
    check!(reg, "LIN-SV-006", "rsh/trsh client family absent", "Legacy r-commands authenticate by trust, not secrets.", ".rhosts trust maps allow trivial impersonation.", "Remove rsh, rsh-server, rcp, rlogin packages.", Medium, "Services", &["CIS 2.3.3-5"], linux, |c| pkg_absent(c, &["rsh", "rsh-server", "rlogin", "rcp"]));
    check!(reg, "LIN-SV-007", "talk/talk-server absent", "Obsolete cleartext chat services.", "talk exposes sessions and is never legitimately used on servers.", "Remove talk/talk-server/ytalk.", Low, "Services", &["CIS 2.3.6-7"], linux, |c| pkg_absent(c, &["talk", "talk-server", "ntalk", "ytalk"]));
    check!(reg, "LIN-SV-008", "tftp/tftp-server absent", "Trivial FTP has no authentication or encryption.", "TFTP shares are anonymous read/write by config.", "Remove tftp/tftp-server; use SFTP instead.", Medium, "Services", &["CIS 2.3.9-10"], linux, |c| pkg_absent(c, &["tftp", "tftp-server", "atftp"]));
    check!(reg, "LIN-SV-009", "NIS components absent", "Network Information Service is unauthenticated cleartext.", "NIS maps leak password hashes; trusts are spoofable.", "Remove nis/ypbind/yp-tools.", Medium, "Services", &["CIS 2.4"], linux, |c| pkg_absent(c, &["nis", "ypbind", "yp-tools"]));
    check!(reg, "LIN-SV-010", "rsh-server absent", "rsh servers accept trust-based logins.", "Any compromise of a trusted host cascades.", "Remove rsh-server.", Medium, "Services", &["CIS 2.2.6"], linux, |c| pkg_absent(c, &["rsh-server", "rsh-redone-server"]));
}

fn linux(p: &crate::platform::PlatformInfo) -> bool {
    p.os == Os::Linux
}

fn svc_disabled(ctx: &mut ScanContext, svc: &str) -> CheckOutcome {
    let mut log = Vec::new();
    if let Some(state) = ctx.cmd("systemctl", &["is-enabled", svc]) {
        log.push(FallbackAttempt { source: format!("systemctl is-enabled {svc}").into(), outcome: state.clone() });
        if state.trim() == "disabled" || state.trim() == "not-found" || state.trim() == "masked" {
            return ok(format!("{svc} not enabled ({})", state.trim()), "systemd".into(), format!("systemctl is-enabled {svc}"));
        }
        return nok(format!("{svc} is enabled ({})", state.trim()), "systemd".into(), format!("systemctl is-enabled {svc}"));
    }
    log.push(FallbackAttempt { source: "systemctl".into(), outcome: "unavailable".into() });
    if ctx.exists("/etc/systemd/system") {
        return degraded(&format!("{svc} state not queryable; verify manually"));
    }
    err_outcome(log)
}

fn inetd_conf_absent(ctx: &mut ScanContext) -> CheckOutcome {
    if let Some(conf) = ctx.read("/etc/inetd.conf") {
        let entries = conf.lines().filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty()).count();
        if entries == 0 {
            ok("inetd.conf present but empty".into(), "/etc/inetd.conf".into(), "cat /etc/inetd.conf".into())
        } else {
            nok(format!("{entries} active inetd.conf entries"), "/etc/inetd.conf".into(), "grep -v '^#' /etc/inetd.conf".into())
        }
    } else {
        ok("no /etc/inetd.conf (inetd not configured)".into(), "/etc/inetd.conf".into(), "ls /etc/inetd.conf".into())
    }
}

fn time_sync_active(ctx: &mut ScanContext) -> CheckOutcome {
    for svc in ["chronyd", "systemd-timesyncd", "ntpd"] {
        if let Some(out) = ctx.cmd("systemctl", &["is-active", svc]) {
            if out.trim() == "active" {
                return ok(format!("{svc} active"), "systemd".into(), format!("systemctl is-active {svc}"));
            }
        }
    }
    nok("no time synchronization service is active".into(), "systemd".into(), "systemctl is-active chronyd systemd-timesyncd".into())
}

fn mta_local_only(ctx: &mut ScanContext) -> CheckOutcome {
    if let Some(maincf) = ctx.read("/etc/postfix/main.cf") {
        let inet = maincf
            .lines()
            .find_map(|l| l.trim_start().strip_prefix("inet_interfaces").map(|v| v.trim().trim_start_matches('=').trim().to_string()));
        match inet {
            Some(v) if v == "loopback-only" || v.contains("127.0.0.1") => ok(format!("postfix inet_interfaces={v}"), "/etc/postfix/main.cf".into(), "postconf inet_interfaces".into()),
            Some(v) => nok(format!("postfix inet_interfaces={v} (not loopback-only)"), "/etc/postfix/main.cf".into(), "postconf inet_interfaces".into()),
            None => degraded("postfix installed but inet_interfaces unset (distro default applies)"),
        }
    } else {
        ok("no postfix main.cf — MTA absent or non-postfix".into(), "/etc/postfix/main.cf".into(), "ls /etc/postfix".into())
    }
}

fn pkg_query(ctx: &mut ScanContext, pkg: &str) -> Option<String> {
    let family = ctx.platform.family;
    match family {
        DistroFamily::Debian => ctx.cmd("dpkg-query", &["-W", "-f=${Status}", pkg]),
        DistroFamily::Rhel | DistroFamily::Suse => ctx.cmd("rpm", &["-q", pkg]),
        DistroFamily::Alpine => ctx.cmd("apk", &["info", "-e", pkg]),
        DistroFamily::Arch => ctx.cmd("pacman", &["-Q", pkg]),
        DistroFamily::Unknown => None,
    }
}

fn pkg_absent(ctx: &mut ScanContext, pkgs: &[&str]) -> CheckOutcome {
    let mut installed = Vec::new();
    let mut log = Vec::new();
    for pkg in pkgs {
        match pkg_query(ctx, pkg) {
            Some(out) => {
                let present = out.contains("install ok installed")
                    || out.starts_with(pkg)
                    || out.trim() == *pkg
                    || out.contains("is installed");
                log.push(FallbackAttempt { source: format!("query {pkg}").into(), outcome: out.clone() });
                if present {
                    installed.push(*pkg);
                }
            }
            None => log.push(FallbackAttempt { source: format!("query {pkg}").into(), outcome: "not found / no manager".into() }),
        }
    }
    if ctx.platform.family == DistroFamily::Unknown {
        return degraded("package manager not identified; presence unknown");
    }
    if installed.is_empty() {
        ok("none of the target packages installed".into(), "package manager".into(), "see evidence".into())
    } else {
        nok(format!("installed: {}", installed.join(", ")), "package manager".into(), "see evidence".into())
    }
}
