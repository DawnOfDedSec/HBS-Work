//! WIN-NET (Task 37): network hardening checks.
//!
//! Firewall evidence from query-only `netsh advfirewall show <profile>`
//! with `reg query EnableFirewall` fallback; remaining checks are
//! read-only registry value comparisons. Missing evidence degrades,
//! never errors.

use hbs_extractor::checks::windows::network::{parse_netsh_profile, NetshProfile};
use hbs_extractor::checks::{register_all, windows};
use hbs_extractor::context::ScanContext;
use hbs_extractor::engine::run_all;
use hbs_extractor::evidence::CmdInjector;
use hbs_extractor::model::{CheckResult, RegisteredCheck, Status};
use hbs_extractor::platform::{detect, Os};

const NETSH_ON: &str = "DomainProfile State:\nState                             ON\nFirewallPolicy                    BlockInbound,AllowOutbound\n";
const NETSH_OFF: &str = "DomainProfile State:\nState                             OFF\n";

fn windows_ctx(injector: CmdInjector) -> ScanContext {
    let mut platform = detect();
    platform.os = Os::Windows;
    ScanContext::new(platform, true).with_injector(injector)
}

fn run_one(ctx: &mut ScanContext, id: &str) -> CheckResult {
    let mut registry: Vec<RegisteredCheck> = Vec::new();
    register_all(&mut registry);
    let subset: Vec<_> = registry.into_iter().filter(|c| c.tc.id == id).collect();
    assert!(!subset.is_empty(), "Check {id} not found in registry");
    run_all(&subset, ctx).remove(0)
}

/// Match netsh profile queries and reg queries by substring.
fn net_injector(responses: &'static [(&'static str, Option<&'static str>)]) -> CmdInjector {
    Box::new(move |program, args| match (program, args) {
        ("netsh", _) => {
            let joined = args.join(" ");
            for (needle, out) in responses {
                if joined.contains(needle) {
                    return out.map(str::to_owned);
                }
            }
            None
        }
        ("reg", a) if a.first() == Some(&"query") => {
            let joined = a.join(" ");
            for (needle, out) in responses {
                if joined.contains(needle) {
                    return out.map(str::to_owned);
                }
            }
            None
        }
        ("powershell", _) => {
            let script = args.last().copied().unwrap_or("");
            for (needle, out) in responses {
                if script.contains(needle) {
                    return out.map(str::to_owned);
                }
            }
            None
        }
        _ => None,
    })
}

#[test]
fn registers_eighteen_stable_network_ids() {
    let mut registry = Vec::new();
    windows::network::register(&mut registry);
    let ids: Vec<_> = registry.iter().map(|c| c.tc.id).collect();
    assert_eq!(
        ids,
        (1..=18)
            .map(|n| format!("WIN-NET-{n:03}"))
            .collect::<Vec<_>>()
    );
}

#[test]
fn parse_netsh_profile_reads_state_and_inbound() {
    let on = parse_netsh_profile(NETSH_ON).expect("parses ON profile");
    assert_eq!(
        on,
        NetshProfile {
            state_on: true,
            inbound_block: true
        }
    );

    let off = parse_netsh_profile(NETSH_OFF).unwrap();
    assert!(!off.state_on);

    assert!(parse_netsh_profile("garbage localized output").is_none());
}

#[test]
fn firewall_profiles_on_pass_off_fail() {
    let good: &'static [(&'static str, Option<&'static str>)] = &[
        ("domainprofile", Some(NETSH_ON)),
        ("privateprofile", Some(NETSH_ON)),
        ("publicprofile", Some(NETSH_ON)),
        ("allprofiles", Some(NETSH_ON)),
    ];
    let mut ctx = windows_ctx(net_injector(good));
    for id in ["WIN-NET-001", "WIN-NET-002", "WIN-NET-003", "WIN-NET-004"] {
        let res = run_one(&mut ctx, id);
        assert_eq!(res.status, Status::Compliant, "{id}: {}", res.evidence);
    }

    let bad: &'static [(&'static str, Option<&'static str>)] =
        &[("domainprofile", Some(NETSH_OFF))];
    let mut ctx2 = windows_ctx(net_injector(bad));
    let res2 = run_one(&mut ctx2, "WIN-NET-001");
    assert_eq!(res2.status, Status::NonCompliant, "{}", res2.evidence);
}

#[test]
fn firewall_falls_back_to_registry_when_netsh_blocked() {
    // netsh unavailable; registry EnableFirewall=1 and
    // DefaultInboundAction=1 (Block) -> still Compliant.
    let reg_only: &'static [(&'static str, Option<&'static str>)] = &[
        (
            "FirewallPolicy\\DomainProfile",
            Some("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile\n    EnableFirewall    REG_DWORD    0x1\n    DefaultInboundAction    REG_DWORD    0x1\n"),
        ),
        (
            "FirewallPolicy\\PrivateProfile",
            Some("    EnableFirewall    REG_DWORD    0x1\n    DefaultInboundAction    REG_DWORD    0x1\n"),
        ),
        (
            "FirewallPolicy\\PublicProfile",
            Some("    EnableFirewall    REG_DWORD    0x1\n    DefaultInboundAction    REG_DWORD    0x1\n"),
        ),
        (
            "FirewallPolicy\\StandardProfile",
            Some("    EnableFirewall    REG_DWORD    0x1\n    DefaultInboundAction    REG_DWORD    0x1\n"),
        ),
    ];
    let mut ctx = windows_ctx(net_injector(reg_only));
    for id in ["WIN-NET-001", "WIN-NET-002", "WIN-NET-003", "WIN-NET-004"] {
        let res = run_one(&mut ctx, id);
        assert_eq!(res.status, Status::Compliant, "{id}: {}", res.evidence);
    }

    // Everything blocked -> DegradedPartial, never Error.
    let mut ctx2 = windows_ctx(Box::new(|_, _| None));
    for i in 1..=4 {
        let id = format!("WIN-NET-{i:03}");
        let res2 = run_one(&mut ctx2, &id);
        assert_eq!(res2.status, Status::DegradedPartial, "{id}");
    }
}

#[test]
fn registry_hardening_values_evaluated() {
    // WIN-NET-005 EnableMDNS=0 -> Compliant; 1 -> NonCompliant.
    let mdns_off: &'static [(&'static str, Option<&'static str>)] = &[(
        "Dnscache\\Parameters",
        Some("    EnableMDNS    REG_DWORD    0x0\n"),
    )];
    let mut ctx = windows_ctx(net_injector(mdns_off));
    assert_eq!(run_one(&mut ctx, "WIN-NET-005").status, Status::Compliant);

    let mdns_on: &'static [(&'static str, Option<&'static str>)] = &[(
        "Dnscache\\Parameters",
        Some("    EnableMDNS    REG_DWORD    0x1\n"),
    )];
    let mut ctx2 = windows_ctx(net_injector(mdns_on));
    assert_eq!(
        run_one(&mut ctx2, "WIN-NET-005").status,
        Status::NonCompliant
    );

    // WIN-NET-011 SecurityLayer=2 (AtLeast 1) -> Compliant; 0 -> fail.
    let sec_hi: &'static [(&'static str, Option<&'static str>)] =
        &[("RDP-Tcp", Some("    SecurityLayer    REG_DWORD    0x2\n"))];
    let mut ctx3 = windows_ctx(net_injector(sec_hi));
    assert_eq!(run_one(&mut ctx3, "WIN-NET-011").status, Status::Compliant);

    let sec_off: &'static [(&'static str, Option<&'static str>)] =
        &[("RDP-Tcp", Some("    SecurityLayer    REG_DWORD    0x0\n"))];
    let mut ctx4 = windows_ctx(net_injector(sec_off));
    assert_eq!(
        run_one(&mut ctx4, "WIN-NET-011").status,
        Status::NonCompliant
    );
}

#[test]
fn trusted_hosts_wildcard_fails_absent_passes() {
    // WIN-NET-016: "*" -> NonCompliant.
    let wild: &'static [(&'static str, Option<&'static str>)] =
        &[("WinRM\\Client", Some("    TrustedHosts    REG_SZ    *\n"))];
    let mut ctx = windows_ctx(net_injector(wild));
    assert_eq!(
        run_one(&mut ctx, "WIN-NET-016").status,
        Status::NonCompliant
    );

    // Absent value = default-safe -> Compliant.
    let none: &'static [(&'static str, Option<&'static str>)] = &[(
        "WinRM\\Client",
        Some("\r\nERROR: The system was unable to find the specified registry key or value.\r\n"),
    )];
    let mut ctx2 = windows_ctx(net_injector(none));
    assert_eq!(run_one(&mut ctx2, "WIN-NET-016").status, Status::Compliant);
}

#[test]
fn missing_registry_evidence_degrades() {
    let mut ctx = windows_ctx(Box::new(|_, _| None));
    for i in 5..=18 {
        let id = format!("WIN-NET-{i:03}");
        let res = run_one(&mut ctx, &id);
        assert_eq!(
            res.status,
            Status::DegradedPartial,
            "{id}: {:?}",
            res.status
        );
    }
}

#[test]
fn network_checks_query_only_verbs() {
    let good: &'static [(&'static str, Option<&'static str>)] = &[
        ("domainprofile", Some(NETSH_ON)),
        ("privateprofile", Some(NETSH_ON)),
        ("publicprofile", Some(NETSH_ON)),
        ("allprofiles", Some(NETSH_ON)),
        ("EnableMDNS", Some("    EnableMDNS    REG_DWORD    0x0\n")),
        (
            "EnableMulticast",
            Some("    EnableMulticast    REG_DWORD    0x0\n"),
        ),
        (
            "DisableAutoProxyCache",
            Some("    DisableAutoProxyCache    REG_DWORD    0x1\n"),
        ),
        (
            "WinHttp",
            Some("    WinHttpDisableWpad    REG_DWORD    0x1\n"),
        ),
        (
            "fDenyTSConnections",
            Some("    fDenyTSConnections    REG_DWORD    0x1\n"),
        ),
        (
            "UserAuthentication",
            Some("    UserAuthentication    REG_DWORD    0x1\n"),
        ),
        (
            "SecurityLayer",
            Some("    SecurityLayer    REG_DWORD    0x2\n"),
        ),
        (
            "MinEncryptionLevel",
            Some("    MinEncryptionLevel    REG_DWORD    0x3\n"),
        ),
        (
            "fDisableClip",
            Some("    fDisableClip    REG_DWORD    0x1\n"),
        ),
        ("fDisableCdm", Some("    fDisableCdm    REG_DWORD    0x1\n")),
        (
            "WinRM\\Service",
            Some("    AllowUnencrypted    REG_DWORD    0x0\n"),
        ),
        (
            "WinRM\\Client",
            Some("    TrustedHosts    REG_SZ    10.0.0.5\n"),
        ),
        (
            "Services\\LDAP",
            Some("    LDAPClientIntegrity    REG_DWORD    0x2\n"),
        ),
        (
            "MSV1_0",
            Some("    RestrictSendingNTLMTraffic    REG_DWORD    0x2\n"),
        ),
    ];
    let mut ctx = windows_ctx(net_injector(good));
    for i in 1..=18 {
        run_one(&mut ctx, &format!("WIN-NET-{i:03}"));
    }
    let bad: Vec<_> = ctx
        .audit
        .commands
        .iter()
        .filter(|c| !(c.starts_with("netsh ") || c.starts_with("reg query ")))
        .collect();
    assert!(bad.is_empty(), "unexpected commands: {bad:?}");
}
