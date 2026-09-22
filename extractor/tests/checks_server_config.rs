//! GEN-SRV server-configuration review tests.
//!
//! Coverage per check (where practical): compliant, noncompliant,
//! primary-absent-then-fallback-success, and all-unavailable ->
//! `DegradedPartial` (never `Error`, never a false pass). File-based
//! non-compliant results must carry a pinpoint evidence block; command
//! sources legitimately omit coordinates.

use std::path::{Path, PathBuf};

use hbs_extractor::checks::register_all;
use hbs_extractor::context::ScanContext;
use hbs_extractor::engine::run_all;
use hbs_extractor::evidence::CmdInjector;
use hbs_extractor::model::{CheckResult, RegisteredCheck, Status};
use hbs_extractor::platform::{detect, DistroFamily, EnvironmentInfo, Os, PlatformInfo};

const ALL_IDS: &[&str] = &[
    "GEN-SRV-001", "GEN-SRV-002", "GEN-SRV-003", "GEN-SRV-004", "GEN-SRV-005",
    "GEN-SRV-006", "GEN-SRV-007", "GEN-SRV-008", "GEN-SRV-009", "GEN-SRV-010",
    "GEN-SRV-011", "GEN-SRV-012", "GEN-SRV-013", "GEN-SRV-014", "GEN-SRV-015",
    "GEN-SRV-016", "GEN-SRV-017", "GEN-SRV-018", "GEN-SRV-019", "GEN-SRV-020",
    "GEN-SRV-021", "GEN-SRV-022", "GEN-SRV-023", "GEN-SRV-024",
];

fn platform(os: Os) -> PlatformInfo {
    let mut p = detect();
    p.os = os;
    p.arch = "x86_64".into();
    p.family = if os == Os::Linux { DistroFamily::Debian } else { DistroFamily::Unknown };
    // Pin the environment so these tests never inherit the build host's
    // bare-metal/VM classification.
    p.environment = EnvironmentInfo::default();
    p
}

fn linux_ctx(root: &str, inj: CmdInjector) -> ScanContext {
    ScanContext::new(platform(Os::Linux), false)
        .with_root_prefix(root)
        .with_injector(inj)
}

fn windows_ctx(root: &str, inj: CmdInjector) -> ScanContext {
    ScanContext::new(platform(Os::Windows), false)
        .with_root_prefix(root)
        .with_injector(inj)
}

fn none() -> CmdInjector {
    Box::new(|_, _| None)
}

fn run_one(ctx: &mut ScanContext, id: &str) -> CheckResult {
    let mut reg: Vec<RegisteredCheck> = Vec::new();
    register_all(&mut reg);
    let subset: Vec<RegisteredCheck> = reg.into_iter().filter(|c| c.tc.id == id).collect();
    assert_eq!(subset.len(), 1, "check {id} must be registered exactly once");
    run_all(&subset, ctx).remove(0)
}

fn temp_root(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("hbs-srv-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn put(root: &Path, rel: &str, content: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, content).unwrap();
}

// ---------------------------------------------------------------------------
// Catalog-wide invariants
// ---------------------------------------------------------------------------

#[test]
fn all_checks_degrade_when_evidence_unavailable() {
    let mut problems = Vec::new();
    for id in ALL_IDS {
        let r = if *id == "GEN-SRV-007" {
            run_one(&mut windows_ctx("tests/fixtures/empty-root", none()), id)
        } else {
            run_one(&mut linux_ctx("tests/fixtures/empty-root", none()), id)
        };
        if r.status != Status::DegradedPartial {
            problems.push(format!("{id}: expected DegradedPartial, got {:?} ({})", r.status, r.evidence));
        }
        if r.status == Status::Error {
            problems.push(format!("{id}: must never be Error"));
        }
    }
    assert!(problems.is_empty(), "degradation invariants:\n{}", problems.join("\n"));
}

#[test]
fn every_registered_id_is_unique_and_well_formed() {
    let mut reg: Vec<RegisteredCheck> = Vec::new();
    register_all(&mut reg);
    let srv: Vec<&RegisteredCheck> = reg.iter().filter(|c| c.tc.id.starts_with("GEN-SRV-")).collect();
    assert_eq!(srv.len(), 24, "expected 24 GEN-SRV checks");
    for c in &srv {
        let parts: Vec<&str> = c.tc.id.split('-').collect();
        assert_eq!(parts.len(), 3, "id shape {}", c.tc.id);
        assert_eq!(parts[0], "GEN");
        assert_eq!(parts[1], "SRV");
        assert_eq!(parts[2].len(), 3);
    }
}

// ---------------------------------------------------------------------------
// 001 time sync source
// ---------------------------------------------------------------------------

#[test]
fn time_sync_source_compliant_and_noncompliant_with_block() {
    let r = run_one(&mut linux_ctx("tests/fixtures/srv-good", none()), "GEN-SRV-001");
    assert_eq!(r.status, Status::Compliant, "{}", r.evidence);

    let r = run_one(&mut linux_ctx("tests/fixtures/srv-bad", none()), "GEN-SRV-001");
    assert_eq!(r.status, Status::NonCompliant, "{}", r.evidence);
    assert_eq!(r.evidence_blocks.len(), 1);
    assert!(r.evidence_blocks[0].path.ends_with("chrony.conf"));
    assert_eq!(r.evidence_blocks[0].line, 1);
}

#[test]
fn time_sync_source_falls_back_to_timedatectl_and_logs_order() {
    let inj: CmdInjector = Box::new(|prog, _args| {
        if prog == "timedatectl" {
            Some("NTPSynchronized=yes\nServerAddress=10.0.0.1".into())
        } else {
            None
        }
    });
    let mut ctx = linux_ctx("tests/fixtures/empty-root", inj);
    let r = run_one(&mut ctx, "GEN-SRV-001");
    assert_eq!(r.status, Status::Compliant, "{}", r.evidence);
    assert!(r.evidence.contains("10.0.0.1"));

    // With every source unavailable the ordered chain is preserved in the
    // fallback log: config primaries first, live queries after.
    let mut ctx = linux_ctx("tests/fixtures/empty-root", none());
    let r = run_one(&mut ctx, "GEN-SRV-001");
    assert_eq!(r.status, Status::DegradedPartial);
    let pos_cfg = r.fallback_log.iter().position(|f| f.source == "/etc/chrony.conf").unwrap();
    let pos_cmd = r.fallback_log.iter().position(|f| f.source.starts_with("timedatectl")).unwrap();
    assert!(pos_cfg < pos_cmd, "primary must be attempted before fallback");
}

// ---------------------------------------------------------------------------
// 002 clock drift
// ---------------------------------------------------------------------------

#[test]
fn clock_drift_bounds_offset() {
    let inj: CmdInjector = Box::new(|prog, _| {
        if prog == "chronyc" {
            Some("Reference ID    : 0A000001 (ntp)\nSystem time     : 0.000123456 seconds fast of NTP time\nLeap status     : Normal".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-002").status, Status::Compliant);

    let inj: CmdInjector = Box::new(|prog, _| {
        if prog == "chronyc" {
            Some("System time     : 5.500000000 seconds fast of NTP time\nLeap status     : Normal".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-002").status, Status::NonCompliant);
}

#[test]
fn clock_drift_falls_back_to_timedatectl() {
    let inj: CmdInjector = Box::new(|prog, _| {
        if prog == "timedatectl" {
            Some("System clock synchronized: yes".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-002").status, Status::Compliant);
}

// ---------------------------------------------------------------------------
// 003 / 004 DNS
// ---------------------------------------------------------------------------

#[test]
fn dns_redundancy_compliant_noncompliant_and_fallback() {
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/srv-good", none()), "GEN-SRV-003").status, Status::Compliant);
    let bad = run_one(&mut linux_ctx("tests/fixtures/srv-bad", none()), "GEN-SRV-003");
    assert_eq!(bad.status, Status::NonCompliant);
    assert_eq!(bad.evidence_blocks.len(), 1);

    let root = temp_root("dns-resolved");
    put(&root, "etc/systemd/resolved.conf", "[Resolve]\nDNS=10.0.0.53 10.0.0.54\n");
    let r = run_one(&mut linux_ctx(&root.to_string_lossy(), none()), "GEN-SRV-003");
    assert_eq!(r.status, Status::Compliant, "{}", r.evidence);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn dns_not_public_only_flags_public_only() {
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/srv-good", none()), "GEN-SRV-004").status, Status::Compliant);
    let bad = run_one(&mut linux_ctx("tests/fixtures/srv-bad", none()), "GEN-SRV-004");
    assert_eq!(bad.status, Status::NonCompliant);
    assert_eq!(bad.evidence_blocks.len(), 1);
}

#[test]
fn dns_redundancy_windows_netsh() {
    let inj: CmdInjector = Box::new(|prog, args| {
        if prog == "netsh" && args.contains(&"dns") {
            Some("DNS servers configured through DHCP: 10.0.0.53, 10.0.0.54".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut windows_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-003").status, Status::Compliant);
}

// ---------------------------------------------------------------------------
// 005 default route
// ---------------------------------------------------------------------------

#[test]
fn default_route_compliant_and_fallback() {
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/srv-good", none()), "GEN-SRV-005").status, Status::Compliant);
    let inj: CmdInjector = Box::new(|prog, _| {
        if prog == "ip" {
            Some("default via 10.0.0.1 dev eth0".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-005").status, Status::Compliant);
}

#[test]
fn default_route_windows_noncompliant() {
    let inj: CmdInjector = Box::new(|prog, _| {
        if prog == "route" {
            Some("Network Destination        Netmask          Gateway       Interface  Metric\n127.0.0.0 255.0.0.0 On-link 127.0.0.1 331".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut windows_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-005").status, Status::NonCompliant);
}

// ---------------------------------------------------------------------------
// 006 pending reboot
// ---------------------------------------------------------------------------

#[test]
fn pending_reboot_compliant_and_noncompliant_with_block() {
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/srv-good", none()), "GEN-SRV-006").status, Status::Compliant);
    let bad = run_one(&mut linux_ctx("tests/fixtures/srv-bad", none()), "GEN-SRV-006");
    assert_eq!(bad.status, Status::NonCompliant, "{}", bad.evidence);
    assert_eq!(bad.evidence_blocks.len(), 1);
}

#[test]
fn pending_reboot_windows_fallback_test_path() {
    let inj: CmdInjector = Box::new(|prog, args| {
        if prog == "powershell" && args.iter().any(|a| a.contains("Test-Path")) {
            Some("False".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut windows_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-006").status, Status::Compliant);
}

// ---------------------------------------------------------------------------
// 007 OS build support (Windows only)
// ---------------------------------------------------------------------------

#[test]
fn os_build_support_reads_build_number() {
    let inj: CmdInjector = Box::new(|prog, args| {
        if prog == "reg" {
            if args.iter().any(|a| a.contains("CurrentBuildNumber")) {
                Some("CurrentBuildNumber    REG_SZ    19045".into())
            } else if args.iter().any(|a| a.contains("ProductName")) {
                Some("ProductName    REG_SZ    Windows 10 Pro".into())
            } else {
                None
            }
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut windows_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-007").status, Status::Compliant);

    let inj: CmdInjector = Box::new(|prog, args| {
        if prog == "reg" && args.iter().any(|a| a.contains("CurrentBuildNumber")) {
            Some("CurrentBuildNumber    REG_SZ    10240".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut windows_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-007").status, Status::NonCompliant);
}

#[test]
fn os_build_support_falls_back_to_systeminfo() {
    let inj: CmdInjector = Box::new(|prog, _| {
        if prog == "systeminfo" {
            Some("OS Name: Microsoft Windows Server 2019\nOS Version: 10.0.17763 N/A Build 17763".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut windows_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-007").status, Status::Compliant);
}

// ---------------------------------------------------------------------------
// 008 automatic updates
// ---------------------------------------------------------------------------

#[test]
fn auto_updates_compliant_noncompliant_and_fallback() {
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/srv-good", none()), "GEN-SRV-008").status, Status::Compliant);
    let bad = run_one(&mut linux_ctx("tests/fixtures/srv-bad", none()), "GEN-SRV-008");
    assert_eq!(bad.status, Status::NonCompliant);
    assert_eq!(bad.evidence_blocks.len(), 1);

    let inj: CmdInjector = Box::new(|prog, args| {
        if prog == "systemctl" && args.contains(&"unattended-upgrades") {
            Some("enabled".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-008").status, Status::Compliant);
}

#[test]
fn auto_updates_windows_policy() {
    let inj: CmdInjector = Box::new(|prog, args| {
        if prog == "reg" && args.iter().any(|a| a.contains("NoAutoUpdate")) {
            Some("NoAutoUpdate    REG_DWORD    0x1".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut windows_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-008").status, Status::NonCompliant);
}

// ---------------------------------------------------------------------------
// 009 TLS / legacy protocols
// ---------------------------------------------------------------------------

#[test]
fn tls_legacy_compliant_noncompliant_and_crypto_policy_fallback() {
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/srv-good", none()), "GEN-SRV-009").status, Status::Compliant);
    let bad = run_one(&mut linux_ctx("tests/fixtures/srv-bad", none()), "GEN-SRV-009");
    assert_eq!(bad.status, Status::NonCompliant);
    assert_eq!(bad.evidence_blocks.len(), 1);

    let root = temp_root("crypto-policy");
    put(&root, "etc/crypto-policies/config", "DEFAULT\n");
    assert_eq!(run_one(&mut linux_ctx(&root.to_string_lossy(), none()), "GEN-SRV-009").status, Status::Compliant);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn tls_legacy_windows_schannel() {
    let inj: CmdInjector = Box::new(|prog, args| {
        if prog != "reg" {
            return None;
        }
        let key = args.iter().find(|a| a.contains("Protocols"))?;
        if key.contains("SSL 3.0") {
            Some("Enabled    REG_DWORD    0x1".into())
        } else if key.contains("TLS 1.2") {
            Some("Enabled    REG_DWORD    0x1".into())
        } else {
            Some("Enabled    REG_DWORD    0x0".into())
        }
    });
    assert_eq!(run_one(&mut windows_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-009").status, Status::NonCompliant);
}

// ---------------------------------------------------------------------------
// 010 certificate trust store
// ---------------------------------------------------------------------------

#[test]
fn cert_inventory_stale_bundle_fails() {
    let fresh = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let inj: CmdInjector = Box::new(move |prog, args| {
        if prog == "stat" && args.iter().any(|a| a.contains("ca-certificates.crt")) {
            Some(format!("{fresh}"))
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-010").status, Status::Compliant);

    let inj: CmdInjector = Box::new(|prog, args| {
        if prog == "stat" && args.iter().any(|a| a.contains("ca-certificates.crt")) {
            Some("100000".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-010").status, Status::NonCompliant);
}

#[test]
fn cert_inventory_falls_back_to_rhel_bundle() {
    let fresh = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let inj: CmdInjector = Box::new(move |prog, args| {
        if prog == "stat" && args.iter().any(|a| a.contains("ca-bundle.crt")) {
            Some(format!("{fresh}"))
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-010").status, Status::Compliant);
}

// ---------------------------------------------------------------------------
// 011 backup agent
// ---------------------------------------------------------------------------

#[test]
fn backup_agent_compliant_and_fallback() {
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/srv-good", none()), "GEN-SRV-011").status, Status::Compliant);
    let inj: CmdInjector = Box::new(|prog, args| {
        if prog == "systemctl" && args.contains(&"bacula-fd") {
            Some("active".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-011").status, Status::Compliant);
}

#[test]
fn backup_agent_windows_stopped_fails() {
    let inj: CmdInjector = Box::new(|prog, args| {
        if prog == "sc" && args.contains(&"wbengine") {
            Some("SERVICE_NAME: wbengine\n        STATE              : 1  STOPPED".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut windows_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-011").status, Status::NonCompliant);
}

// ---------------------------------------------------------------------------
// 012 log retention
// ---------------------------------------------------------------------------

#[test]
fn log_retention_compliant_noncompliant_and_journald_fallback() {
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/srv-good", none()), "GEN-SRV-012").status, Status::Compliant);
    let bad = run_one(&mut linux_ctx("tests/fixtures/srv-bad", none()), "GEN-SRV-012");
    assert_eq!(bad.status, Status::NonCompliant);
    assert_eq!(bad.evidence_blocks.len(), 1);

    let root = temp_root("journald-retention");
    put(&root, "etc/systemd/journald.conf", "[Journal]\nMaxRetentionSec=90day\n");
    assert_eq!(run_one(&mut linux_ctx(&root.to_string_lossy(), none()), "GEN-SRV-012").status, Status::Compliant);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn log_retention_windows_maxsize() {
    let inj: CmdInjector = Box::new(|prog, args| {
        if prog == "reg" && args.iter().any(|a| a.contains("MaxSize")) {
            Some("MaxSize    REG_DWORD    0x1000".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut windows_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-012").status, Status::NonCompliant);
}

// ---------------------------------------------------------------------------
// 013 remote log forwarding
// ---------------------------------------------------------------------------

#[test]
fn remote_log_forwarding_compliant_noncompliant_and_syslogng_fallback() {
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/srv-good", none()), "GEN-SRV-013").status, Status::Compliant);
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/srv-bad", none()), "GEN-SRV-013").status, Status::NonCompliant);

    let root = temp_root("syslog-ng");
    put(&root, "etc/syslog-ng/syslog-ng.conf", "destination d_remote { network(\"10.0.0.9\" port(514)); };\n");
    assert_eq!(run_one(&mut linux_ctx(&root.to_string_lossy(), none()), "GEN-SRV-013").status, Status::Compliant);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn remote_log_forwarding_windows_wecsvc() {
    let inj: CmdInjector = Box::new(|prog, args| {
        if prog == "sc" && args.contains(&"Wecsvc") {
            Some("STATE              : 4  RUNNING".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut windows_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-013").status, Status::Compliant);
}

// ---------------------------------------------------------------------------
// 014 firewall default deny
// ---------------------------------------------------------------------------

#[test]
fn firewall_default_deny_compliant_and_fallback() {
    let inj: CmdInjector = Box::new(|prog, _| {
        if prog == "ufw" {
            Some("Status: active\nDefault: deny (incoming), allow (outgoing)".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-014").status, Status::Compliant);

    let inj: CmdInjector = Box::new(|prog, _| {
        if prog == "firewall-cmd" {
            Some("drop".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-014").status, Status::Compliant);
}

#[test]
fn firewall_default_deny_windows_off_fails() {
    let inj: CmdInjector = Box::new(|prog, _| {
        if prog == "netsh" {
            Some("Domain Profile Settings:\nState                                 OFF\nFirewall Policy                       BlockInbound,AllowOutbound".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut windows_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-014").status, Status::NonCompliant);
}

// ---------------------------------------------------------------------------
// 015 management listener binding
// ---------------------------------------------------------------------------

#[test]
fn mgmt_listener_binding_compliant_noncompliant_and_sshd_t_fallback() {
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/srv-good", none()), "GEN-SRV-015").status, Status::Compliant);
    let bad = run_one(&mut linux_ctx("tests/fixtures/srv-bad", none()), "GEN-SRV-015");
    assert_eq!(bad.status, Status::NonCompliant);
    assert_eq!(bad.evidence_blocks.len(), 1);

    let inj: CmdInjector = Box::new(|prog, args| {
        if prog == "sshd" && args.contains(&"-T") {
            Some("listenaddress 10.0.0.5:22".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-015").status, Status::Compliant);
}

#[test]
fn mgmt_listener_binding_windows_wildcard_fails() {
    let inj: CmdInjector = Box::new(|prog, args| {
        if prog == "netsh" && args.iter().any(|a| *a == "urlacl") {
            Some("Reserved URL : http://+:5985/wsman/".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut windows_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-015").status, Status::NonCompliant);
}

// ---------------------------------------------------------------------------
// 016 service account privilege
// ---------------------------------------------------------------------------

#[test]
fn service_account_privilege_compliant_noncompliant_and_getent_fallback() {
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/srv-good", none()), "GEN-SRV-016").status, Status::Compliant);
    let bad = run_one(&mut linux_ctx("tests/fixtures/srv-bad", none()), "GEN-SRV-016");
    assert_eq!(bad.status, Status::NonCompliant);
    assert_eq!(bad.evidence_blocks.len(), 1);

    let inj: CmdInjector = Box::new(|prog, _| {
        if prog == "getent" {
            Some("sudo:x:27:svc-web".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-016").status, Status::NonCompliant);
}

#[test]
fn service_account_privilege_windows_admins() {
    let inj: CmdInjector = Box::new(|prog, _| {
        if prog == "net" {
            Some("Alias name     Administrators\nIIS_IUSRS".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut windows_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-016").status, Status::NonCompliant);
}

// ---------------------------------------------------------------------------
// 017 password / lockout policy
// ---------------------------------------------------------------------------

#[test]
fn password_lockout_compliant_noncompliant_and_pam_fallback() {
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/srv-good", none()), "GEN-SRV-017").status, Status::Compliant);
    let bad = run_one(&mut linux_ctx("tests/fixtures/srv-bad", none()), "GEN-SRV-017");
    assert_eq!(bad.status, Status::NonCompliant);
    assert_eq!(bad.evidence_blocks.len(), 1);

    let root = temp_root("pam-faillock");
    put(&root, "etc/security/pwquality.conf", "minlen = 12\n");
    put(&root, "etc/pam.d/common-auth", "auth required pam_faillock.so deny=5\n");
    assert_eq!(run_one(&mut linux_ctx(&root.to_string_lossy(), none()), "GEN-SRV-017").status, Status::Compliant);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn password_lockout_windows_weak_fails() {
    let inj: CmdInjector = Box::new(|prog, _| {
        if prog == "net" {
            Some("Minimum password length:                  4\nLockout threshold:                        0".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut windows_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-017").status, Status::NonCompliant);
}

// ---------------------------------------------------------------------------
// 018 sudo / UAC
// ---------------------------------------------------------------------------

#[test]
fn sudo_uac_compliant_noncompliant_and_pam_su_fallback() {
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/srv-good", none()), "GEN-SRV-018").status, Status::Compliant);
    let bad = run_one(&mut linux_ctx("tests/fixtures/srv-bad", none()), "GEN-SRV-018");
    assert_eq!(bad.status, Status::NonCompliant);
    assert_eq!(bad.evidence_blocks.len(), 1);

    let root = temp_root("pam-su");
    put(&root, "etc/pam.d/su", "auth required pam_wheel.so use_uid\n");
    assert_eq!(run_one(&mut linux_ctx(&root.to_string_lossy(), none()), "GEN-SRV-018").status, Status::Compliant);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn sudo_uac_windows_lua_disabled_fails() {
    let inj: CmdInjector = Box::new(|prog, args| {
        if prog == "reg" && args.iter().any(|a| a.contains("EnableLUA")) {
            Some("EnableLUA    REG_DWORD    0x0".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut windows_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-018").status, Status::NonCompliant);
}

// ---------------------------------------------------------------------------
// 019 secure boot + TPM summary
// ---------------------------------------------------------------------------

#[test]
fn secureboot_tpm_compliant_and_tpm_missing_fails() {
    let inj: CmdInjector = Box::new(|prog, _| {
        if prog == "mokutil" {
            Some("SecureBoot enabled".into())
        } else {
            None
        }
    });
    let r = run_one(&mut linux_ctx("tests/fixtures/srv-good", inj), "GEN-SRV-019");
    assert_eq!(r.status, Status::Compliant, "{}", r.evidence);

    let root = temp_root("no-tpm");
    put(&root, "sys/.keep", "");
    let inj: CmdInjector = Box::new(|prog, _| {
        if prog == "mokutil" {
            Some("SecureBoot enabled".into())
        } else {
            None
        }
    });
    let r = run_one(&mut linux_ctx(&root.to_string_lossy(), inj), "GEN-SRV-019");
    assert_eq!(r.status, Status::NonCompliant, "{}", r.evidence);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn secureboot_tpm_windows_disabled_fails() {
    let inj: CmdInjector = Box::new(|prog, args| {
        if prog == "powershell" && args.iter().any(|a| a.contains("Confirm-SecureBootUEFI")) {
            Some("False".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut windows_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-019").status, Status::NonCompliant);
}

// ---------------------------------------------------------------------------
// 020 kernel link protections
// ---------------------------------------------------------------------------

#[test]
fn kernel_link_protection_compliant_noncompliant_and_sysctl_fallback() {
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/srv-good", none()), "GEN-SRV-020").status, Status::Compliant);

    let inj: CmdInjector = Box::new(|prog, args| {
        if prog == "sysctl" {
            if args.iter().any(|a| a.contains("protected_hardlinks")) {
                Some("0".into())
            } else {
                Some("1".into())
            }
        } else {
            None
        }
    });
    let r = run_one(&mut linux_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-020");
    assert_eq!(r.status, Status::NonCompliant, "{}", r.evidence);
}

// ---------------------------------------------------------------------------
// 021 disk free
// ---------------------------------------------------------------------------

#[test]
fn disk_free_compliant_noncompliant_and_stat_fallback() {
    let inj: CmdInjector = Box::new(|prog, _| {
        if prog == "findmnt" {
            Some("/ 100G 20G 20%\n/var 50G 5G 10%".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-021").status, Status::Compliant);

    let inj: CmdInjector = Box::new(|prog, _| {
        if prog == "findmnt" {
            Some("/ 1G 100G 95%".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-021").status, Status::NonCompliant);

    // stat -f fallback: %a free blocks, %S block size, %b total blocks.
    let inj: CmdInjector = Box::new(|prog, _| {
        if prog == "stat" {
            Some("50000 4096 100000".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-021").status, Status::Compliant);
}

#[test]
fn disk_free_windows_near_full_fails() {
    let inj: CmdInjector = Box::new(|prog, _| {
        if prog == "wmic" {
            Some("Caption  Size           FreeSpace\nC:       100000000      1000000".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut windows_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-021").status, Status::NonCompliant);
}

// ---------------------------------------------------------------------------
// 022 swap / pagefile
// ---------------------------------------------------------------------------

#[test]
fn swap_pagefile_compliant_noncompliant_and_fstab_fallback() {
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/srv-good", none()), "GEN-SRV-022").status, Status::Compliant);

    let root = temp_root("swap-fstab");
    put(&root, "etc/fstab", "/dev/sda2 none swap sw 0 0\n");
    assert_eq!(run_one(&mut linux_ctx(&root.to_string_lossy(), none()), "GEN-SRV-022").status, Status::Compliant);
    let _ = std::fs::remove_dir_all(&root);

    let root = temp_root("swap-none");
    put(&root, "proc/swaps", "Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n");
    assert_eq!(run_one(&mut linux_ctx(&root.to_string_lossy(), none()), "GEN-SRV-022").status, Status::NonCompliant);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn swap_pagefile_windows_empty_fails() {
    let inj: CmdInjector = Box::new(|prog, args| {
        if prog == "wmic" {
            Some("AutomaticManagedPagefile\nFALSE".into())
        } else if prog == "reg" && args.iter().any(|a| a.contains("PagingFiles")) {
            Some("PagingFiles    REG_MULTI_SZ".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut windows_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-022").status, Status::NonCompliant);
}

// ---------------------------------------------------------------------------
// 023 core services
// ---------------------------------------------------------------------------

#[test]
fn core_services_compliant_and_noncompliant() {
    let inj: CmdInjector = Box::new(|prog, _| {
        if prog == "systemctl" {
            Some("enabled".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-023").status, Status::Compliant);

    let inj: CmdInjector = Box::new(|prog, args| {
        if prog == "systemctl" && args.contains(&"auditd") {
            Some("disabled".into())
        } else if prog == "systemctl" {
            Some("enabled".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-023").status, Status::NonCompliant);
}

#[test]
fn core_services_windows_stopped_fails() {
    let inj: CmdInjector = Box::new(|prog, args| {
        if prog == "sc" && args.contains(&"WinDefend") {
            Some("STATE              : 1  STOPPED".into())
        } else if prog == "sc" {
            Some("STATE              : 4  RUNNING".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut windows_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-023").status, Status::NonCompliant);
}

// ---------------------------------------------------------------------------
// 024 LDAP / Kerberos client config
// ---------------------------------------------------------------------------

#[test]
fn ldap_kerberos_compliant_noncompliant_and_realm_fallback() {
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/srv-good", none()), "GEN-SRV-024").status, Status::Compliant);
    let bad = run_one(&mut linux_ctx("tests/fixtures/srv-bad", none()), "GEN-SRV-024");
    assert_eq!(bad.status, Status::NonCompliant);
    assert_eq!(bad.evidence_blocks.len(), 1);

    let inj: CmdInjector = Box::new(|prog, _| {
        if prog == "realm" {
            Some("example.com".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut linux_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-024").status, Status::Compliant);
}

#[test]
fn ldap_kerberos_windows_joined() {
    let inj: CmdInjector = Box::new(|prog, _| {
        if prog == "dsregcmd" {
            Some("+----------------------------------------------------------------------+\n| DomainJoined : YES".into())
        } else {
            None
        }
    });
    assert_eq!(run_one(&mut windows_ctx("tests/fixtures/empty-root", inj), "GEN-SRV-024").status, Status::Compliant);
}
