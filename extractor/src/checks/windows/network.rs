//! WIN-NET: network hardening checks.
//!
//! Firewall profiles via query-only `netsh advfirewall show <profile>`
//! with `reg query ...\FirewallPolicy\<profile>` fallback. Everything
//! else is a read-only registry value comparison (RDP, WinRM, mDNS,
//! LLMNR, WPAD, LDAP signing, NTLM). Missing evidence degrades, never
//! errors.

use super::{reg_query_dword_with_log, reg_query_sz_with_log, QueryResult};
use crate::checks::{degraded, nok, ok};
use crate::context::ScanContext;
use crate::model::{CheckOutcome, FallbackAttempt, RegisteredCheck};
use crate::platform::Os;

#[derive(Debug, PartialEq, Eq, Default)]
pub struct NetshProfile {
    pub state_on: bool,
    pub inbound_block: bool,
}

/// Parse `netsh advfirewall show <profile>` output (English or numeric).
pub fn parse_netsh_profile(raw: &str) -> Option<NetshProfile> {
    let mut p = NetshProfile::default();
    let mut found = false;
    for line in raw.lines() {
        let u = line.trim().to_ascii_uppercase();
        if u.starts_with("FIREWALLPOLICY") || u.contains("FIREWALLPOLICY ") {
            // BlockInbound anywhere in the policy string.
            p.inbound_block = u.contains("BLOCKINBOUND");
            found = true;
            continue;
        }
        let mut fields = u.split_whitespace();
        while let Some(field) = fields.next() {
            if field == "STATE" || field == "STATE:" {
                // Value is the token after STATE (possibly with colon).
                if let Some(v) = fields.next() {
                    let v = v.trim_end_matches(':');
                    // "ON"/"OFF" or localized; fall back to not-found.
                    if v == "ON" {
                        p.state_on = true;
                        found = true;
                    } else if v == "OFF" {
                        p.state_on = false;
                        found = true;
                    }
                }
            }
        }
    }
    found.then_some(p)
}

fn firewall_reg_fallback(
    ctx: &mut ScanContext,
    profile_key: &str,
    attempts: &mut Vec<FallbackAttempt>,
) -> Option<NetshProfile> {
    let path = format!(
        r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profile_key}"
    );
    let enable = reg_query_dword_with_log(ctx, &path, "EnableFirewall");
    attempts.push(FallbackAttempt {
        source: format!("reg query {path}\\EnableFirewall"),
        outcome: match enable.value {
            Some(v) => format!("read EnableFirewall={v}"),
            None => "unavailable or missing".into(),
        },
    });
    let inbound = reg_query_dword_with_log(ctx, &path, "DefaultInboundAction");
    attempts.push(FallbackAttempt {
        source: format!("reg query {path}\\DefaultInboundAction"),
        outcome: match inbound.value {
            Some(v) => format!("read DefaultInboundAction={v}"),
            None => "unavailable or missing".into(),
        },
    });
    // 1 = firewall on; inbound 1 = Block. Absent inbound default = Block on
    // modern builds, but treat as unknown unless EnableFirewall read.
    enable.value.map(|v| NetshProfile {
        state_on: v == 1,
        inbound_block: inbound.value.map_or(true, |b| b == 1),
    })
}

/// NETSH_CMD: the `netsh advfirewall show <arg>` probe and REG_KEY: the
/// registry fallback path suffix.
fn firewall_check(ctx: &mut ScanContext, netsh_arg: &str, reg_key: &str) -> CheckOutcome {
    let mut attempts = Vec::new();
    match ctx.cmd("netsh", &["advfirewall", "show", netsh_arg]) {
        Some(raw) => match parse_netsh_profile(&raw) {
            Some(p) => {
                attempts.push(FallbackAttempt {
                    source: format!("netsh advfirewall show {netsh_arg}"),
                    outcome: format!(
                        "state={} inbound_block={}",
                        if p.state_on { "ON" } else { "OFF" },
                        p.inbound_block
                    ),
                });
                return finish_firewall(p, format!("netsh advfirewall show {netsh_arg}"), attempts);
            }
            None => attempts.push(FallbackAttempt {
                source: format!("netsh advfirewall show {netsh_arg}"),
                outcome: "unparseable (localized?) output".into(),
            }),
        },
        None => attempts.push(FallbackAttempt {
            source: format!("netsh advfirewall show {netsh_arg}"),
            outcome: "unavailable or blocked".into(),
        }),
    }
    match firewall_reg_fallback(ctx, reg_key, &mut attempts) {
        Some(p) => finish_firewall(
            p,
            format!("reg query ...\\FirewallPolicy\\{reg_key}"),
            attempts,
        ),
        None => {
            let mut o = degraded(&format!(
                "firewall profile {netsh_arg} unreadable through read-only sources"
            ));
            o.fallback_log = attempts;
            o
        }
    }
}

fn finish_firewall(p: NetshProfile, repro: String, attempts: Vec<FallbackAttempt>) -> CheckOutcome {
    let mut outcome = if p.state_on && p.inbound_block {
        ok(
            "firewall enabled, inbound default Block".into(),
            "firewall:profile".into(),
            repro,
        )
    } else if p.state_on {
        nok(
            "firewall enabled but inbound policy not Block".into(),
            "firewall:profile".into(),
            repro,
        )
    } else {
        nok(
            "firewall profile disabled".into(),
            "firewall:profile".into(),
            repro,
        )
    };
    outcome.fallback_log = attempts;
    outcome
}

/// How a registry DWORD value must compare.
#[derive(Clone, Copy)]
enum Want {
    Equals(u32),
    AtLeast(u32),
    /// Any value passes (only used alongside `not_contains` SZ checks).
    Any,
}

struct RegCheckDef {
    path: &'static str,
    name: &'static str,
    /// Optional SZ comparison: value must not contain this (TrustedHosts "*").
    not_contains: Option<&'static str>,
    want: Want,
}

fn reg_check(ctx: &mut ScanContext, def: &RegCheckDef) -> CheckOutcome {
    let mut attempts = Vec::new();
    if let Some(bad) = def.not_contains {
        // String comparison path.
        let q: QueryResult<String> = reg_query_sz_with_log(ctx, def.path, def.name);
        attempts.extend(q.attempts);
        let mut outcome = match q.value {
            Some(v) => {
                if v.contains(bad) {
                    nok(
                        format!("{0} = \"{v}\" (contains \"{bad}\")", def.name),
                        format!("registry:{}", def.path),
                        format!("reg query {} /v {}", def.path, def.name),
                    )
                } else {
                    ok(
                        format!("{0} = \"{v}\"", def.name),
                        format!("registry:{}", def.path),
                        format!("reg query {} /v {}", def.path, def.name),
                    )
                }
            }
            None => {
                let confirmed_absent = attempts
                    .iter()
                    .any(|a| a.source == "reg query" && a.outcome.contains("missing"));
                if confirmed_absent {
                    ok(
                        format!("{0} not configured (default-safe absent value)", def.name),
                        format!("registry:{}", def.path),
                        format!("reg query {} /v {}", def.path, def.name),
                    )
                } else {
                    degraded(&format!(
                        "{0} unreadable through read-only sources",
                        def.name
                    ))
                }
            }
        };
        outcome.fallback_log = attempts;
        return outcome;
    }
    let q = reg_query_dword_with_log(ctx, def.path, def.name);
    attempts.extend(q.attempts);
    let Some(v) = q.value else {
        let mut o = degraded(&format!(
            "{0} unreadable through read-only sources",
            def.name
        ));
        o.fallback_log = attempts;
        return o;
    };
    let pass = match def.want {
        Want::Equals(n) => v == n,
        Want::AtLeast(n) => v >= n,
        Want::Any => true,
    };
    let expected = match def.want {
        Want::Equals(n) => format!("= {n}"),
        Want::AtLeast(n) => format!(">= {n}"),
        Want::Any => "any".into(),
    };
    let mut outcome = if pass {
        ok(
            format!("{0} = {v} (expected {expected})", def.name),
            format!("registry:{}", def.path),
            format!("reg query {} /v {}", def.path, def.name),
        )
    } else {
        nok(
            format!("{0} = {v} (expected {expected})", def.name),
            format!("registry:{}", def.path),
            format!("reg query {} /v {}", def.path, def.name),
        )
    };
    outcome.fallback_log = attempts;
    outcome
}

const TS: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server";
const RDP_TCP: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp";
const TS_POLICIES: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";
const WINRM_SVC: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service";
const WINRM_CLI: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client";
const DNSCACHE: &str = r"HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters";
const DNSCLIENT_POL: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";
const INET_POL: &str = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings";
const WINHTTP: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp";
const LDAP: &str = r"HKLM\SYSTEM\CurrentControlSet\Services\LDAP";
const MSV1_0: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0";

fn win(p: &crate::platform::PlatformInfo) -> bool {
    p.os == Os::Windows
}

pub fn register(reg: &mut Vec<RegisteredCheck>) {
    use crate::check;
    check!(
        reg,
        "WIN-NET-001",
        "Domain firewall profile enabled",
        "The domain profile firewall is ON with inbound default Block.",
        "An offline-domain host without firewall accepts unsolicited inbound traffic.",
        "Enable the domain profile: netsh advfirewall set domainprofile state on.",
        High,
        "Network",
        &["CIS 9.1.1"],
        win,
        |ctx| firewall_check(ctx, "domainprofile", "DomainProfile")
    );
    check!(
        reg,
        "WIN-NET-002",
        "Private firewall profile enabled",
        "The private profile firewall is ON with inbound default Block.",
        "Private networks shift: a laptop moving networks keeps only this profile's rules.",
        "Enable the private profile: netsh advfirewall set privateprofile state on.",
        High,
        "Network",
        &["CIS 9.1.2"],
        win,
        |ctx| firewall_check(ctx, "privateprofile", "PrivateProfile")
    );
    check!(
        reg,
        "WIN-NET-003",
        "Public firewall profile enabled",
        "The public profile firewall is ON with inbound default Block.",
        "Public networks are untrusted; the strictest profile must stay on.",
        "Enable the public profile: netsh advfirewall set publicprofile state on.",
        High,
        "Network",
        &["CIS 9.1.3"],
        win,
        |ctx| firewall_check(ctx, "publicprofile", "PublicProfile")
    );
    check!(
        reg, "WIN-NET-004",
        "Inbound connections default to Block",
        "All firewall profiles default to blocking unsolicited inbound connections.",
        "Allow-by-default inbound flattens every other network control.",
        "Set default inbound to Block: netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound.",
        High, "Network", &["CIS 9.1.4"],
        win,
        |ctx| firewall_check(ctx, "allprofiles", "StandardProfile")
    );
    check!(
        reg, "WIN-NET-005",
        "mDNS disabled",
        "EnableMDNS under Dnscache parameters is 0.",
        "mDNS broadcasts hostnames/services to the local segment; WAAD-joined servers don't need it.",
        "Set HKLM\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters!EnableMDNS = 0.",
        Medium, "Network", &[],
        win,
        |ctx| reg_check(ctx, &RegCheckDef { path: DNSCACHE, name: "EnableMDNS", not_contains: None, want: Want::Equals(0) })
    );
    check!(
        reg,
        "WIN-NET-006",
        "LLMNR disabled",
        "EnableMulticast under the DNSClient policy key is 0.",
        "LLMNR lets any local host answer name queries: credential capture via responder attacks.",
        "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient!EnableMulticast = 0.",
        Medium,
        "Network",
        &[],
        win,
        |ctx| reg_check(
            ctx,
            &RegCheckDef {
                path: DNSCLIENT_POL,
                name: "EnableMulticast",
                not_contains: None,
                want: Want::Equals(0)
            }
        )
    );
    check!(
        reg,
        "WIN-NET-007",
        "WPAD AutoProxy cache disabled (policy)",
        "DisableAutoProxyCache under Internet Settings policy is 1.",
        "WPAD autodiscovery lets any network peer become the effective proxy.",
        "Set HKLM\\SOFTWARE\\Policies\\...\\Internet Settings!DisableAutoProxyCache = 1.",
        Medium,
        "Network",
        &[],
        win,
        |ctx| reg_check(
            ctx,
            &RegCheckDef {
                path: INET_POL,
                name: "DisableAutoProxyCache",
                not_contains: None,
                want: Want::Equals(1)
            }
        )
    );
    check!(
        reg, "WIN-NET-008",
        "WPAD disabled for WinHTTP",
        "WinHttpDisableWpad under the WinHttp key is 1.",
        "WinHTTP services resolving WPAD become proxy-relay targets without this.",
        "Set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\WinHttp!WinHttpDisableWpad = 1.",
        Medium, "Network", &[],
        win,
        |ctx| reg_check(ctx, &RegCheckDef { path: WINHTTP, name: "WinHttpDisableWpad", not_contains: None, want: Want::Equals(1) })
    );
    check!(
        reg, "WIN-NET-009",
        "RDP enabled/disabled state recorded (fDenyTSConnections)",
        "fDenyTSConnections records whether RDP is enabled on the host.",
        "RDP is the single most probed remote surface; its state must be a decision, not a default.",
        "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server!fDenyTSConnections = 1 to disable RDP.",
        Medium, "Network", &[],
        win,
        |ctx| reg_check(ctx, &RegCheckDef { path: TS, name: "fDenyTSConnections", not_contains: None, want: Want::Equals(1) })
    );
    check!(
        reg,
        "WIN-NET-010",
        "RDP Network Level Authentication required",
        "UserAuthentication under RDP-Tcp is 1.",
        "Without NLA, unauthenticated sessions reach the logon UI: pre-auth attack surface.",
        "Set HKLM\\...\\WinStations\\RDP-Tcp!UserAuthentication = 1.",
        High,
        "Network",
        &["CIS 18.9.47.5.1"],
        win,
        |ctx| reg_check(
            ctx,
            &RegCheckDef {
                path: RDP_TCP,
                name: "UserAuthentication",
                not_contains: None,
                want: Want::Equals(1)
            }
        )
    );
    check!(
        reg,
        "WIN-NET-011",
        "RDP SecurityLayer requires TLS/NLA",
        "SecurityLayer under RDP-Tcp is 1 or higher.",
        "SecurityLayer 0 permits legacy RDP encryption without TLS.",
        "Set HKLM\\...\\WinStations\\RDP-Tcp!SecurityLayer = 1 (or 2 for TLS-only).",
        High,
        "Network",
        &[],
        win,
        |ctx| reg_check(
            ctx,
            &RegCheckDef {
                path: RDP_TCP,
                name: "SecurityLayer",
                not_contains: None,
                want: Want::AtLeast(1)
            }
        )
    );
    check!(
        reg,
        "WIN-NET-012",
        "RDP minimum encryption level Client Compatible or higher",
        "MinEncryptionLevel under RDP-Tcp is 2 or higher.",
        "Low encryption leaves RDP sessions readable on the wire.",
        "Set HKLM\\...\\WinStations\\RDP-Tcp!MinEncryptionLevel = 2 (or 3 for High).",
        Medium,
        "Network",
        &[],
        win,
        |ctx| reg_check(
            ctx,
            &RegCheckDef {
                path: RDP_TCP,
                name: "MinEncryptionLevel",
                not_contains: None,
                want: Want::AtLeast(2)
            }
        )
    );
    check!(
        reg,
        "WIN-NET-013",
        "RDP clipboard redirection disabled",
        "fDisableClip under Terminal Services policies is 1.",
        "Clipboard redirection exfiltrates data and pastes malicious content into sessions.",
        "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services!fDisableClip = 1.",
        Medium,
        "Network",
        &[],
        win,
        |ctx| reg_check(
            ctx,
            &RegCheckDef {
                path: TS_POLICIES,
                name: "fDisableClip",
                not_contains: None,
                want: Want::Equals(1)
            }
        )
    );
    check!(
        reg, "WIN-NET-014",
        "RDP drive redirection disabled",
        "fDisableCdm under Terminal Services policies is 1.",
        "Mapped client drives turn one compromised RDP session into file-system access on every client.",
        "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services!fDisableCdm = 1.",
        Medium, "Network", &[],
        win,
        |ctx| reg_check(ctx, &RegCheckDef { path: TS_POLICIES, name: "fDisableCdm", not_contains: None, want: Want::Equals(1) })
    );
    check!(
        reg,
        "WIN-NET-015",
        "WinRM unencrypted traffic disallowed",
        "AllowUnencrypted under WinRM Service policy is 0.",
        "Unencrypted WinRM carries session credentials in cleartext.",
        "Set HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service!AllowUnencrypted = 0.",
        High,
        "Network",
        &["CIS 18.9.97.2.1"],
        win,
        |ctx| reg_check(
            ctx,
            &RegCheckDef {
                path: WINRM_SVC,
                name: "AllowUnencrypted",
                not_contains: None,
                want: Want::Equals(0)
            }
        )
    );
    check!(
        reg,
        "WIN-NET-016",
        "WinRM TrustedHosts not wildcarded",
        "TrustedHosts under WinRM Client policy does not contain *.",
        "A wildcard TrustedHosts list makes every host a trusted target for delegated credentials.",
        "Set explicit host entries or remove HKLM\\...\\WinRM\\Client!TrustedHosts.",
        Medium,
        "Network",
        &[],
        win,
        |ctx| reg_check(
            ctx,
            &RegCheckDef {
                path: WINRM_CLI,
                name: "TrustedHosts",
                not_contains: Some("*"),
                want: Want::Any
            }
        )
    );
    check!(
        reg,
        "WIN-NET-017",
        "LDAP client signing required",
        "LDAPClientIntegrity under the LDAP service key is 1 or higher.",
        "Unsigned LDAP traffic is interceptable for credential relay.",
        "Set HKLM\\SYSTEM\\CurrentControlSet\\Services\\LDAP!LDAPClientIntegrity = 1 (or 2).",
        High,
        "Network",
        &[],
        win,
        |ctx| reg_check(
            ctx,
            &RegCheckDef {
                path: LDAP,
                name: "LDAPClientIntegrity",
                not_contains: None,
                want: Want::AtLeast(1)
            }
        )
    );
    check!(
        reg, "WIN-NET-018",
        "Outgoing NTLM restricted",
        "RestrictSendingNTLMTraffic under MSV1_0 is 1 or higher.",
        "NTLM relay remains a top-tier domain compromise path; restricting it forces Kerberos.",
        "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0!RestrictSendingNTLMTraffic = 1 (or 2 to deny all).",
        Medium, "Network", &[],
        win,
        |ctx| reg_check(ctx, &RegCheckDef { path: MSV1_0, name: "RestrictSendingNTLMTraffic", not_contains: None, want: Want::AtLeast(1) })
    );
}
