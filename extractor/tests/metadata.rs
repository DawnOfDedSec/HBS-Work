//! Metadata collection: fallback chains, per-field isolation, and the
//! guarantee that every expected key is always present.

use hbs_extractor::context::ScanContext;
use hbs_extractor::evidence::CmdInjector;
use hbs_extractor::metadata::{collect, METADATA_KEYS};
use hbs_extractor::platform::{detect, DistroFamily, Os};
use serde_json::Value;
use std::path::{Path, PathBuf};

fn linux_platform() -> hbs_extractor::platform::PlatformInfo {
    let mut p = detect();
    p.os = Os::Linux;
    p.family = DistroFamily::Debian;
    p.distro = Some("Ubuntu".into());
    p.distro_version = Some("24.04".into());
    p
}

fn ctx_with(root: &str, injector: CmdInjector) -> ScanContext {
    ScanContext::new(linux_platform(), false)
        .with_root_prefix(root)
        .with_injector(injector)
}

fn temp_root(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("hbs-meta-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn put(root: &Path, rel: &str, content: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, content).unwrap();
}

fn attempts(m: &Value) -> &Vec<Value> {
    m["_collection"]["attempts"].as_array().expect("attempts array")
}

fn attempt_sources<'a>(m: &'a Value, field: &str) -> Vec<&'a str> {
    attempts(m)
        .iter()
        .filter(|a| a["field"] == field)
        .filter_map(|a| a["source"].as_str())
        .collect()
}

#[test]
fn linux_metadata_from_fixtures() {
    let ctx = ScanContext::new(linux_platform(), false)
        .with_root_prefix("tests/fixtures/meta-root")
        .with_injector(Box::new(|prog, args| match (prog, args.first()) {
            ("uname", Some(&"-r")) => Some("6.8.0-49-generic".into()),
            ("lspci", _) => Some("3B:00.0 3D controller [0302]: NVIDIA Corporation GA102GL [A10G] [10de:2236]".into()),
            ("systemctl", _) if args.contains(&"list-units") => Some("a.service loaded active running\nb.service loaded active running\nc.service loaded active running".into()),
            _ => None,
        }));
    let m = collect(&mut { ctx });
    assert_eq!(m["hostname"], "web01");
    // File-only FQDN: /etc/hostname + resolv.conf `search corp.example`.
    assert_eq!(m["fqdn"], "web01.corp.example");
    assert_eq!(m["machine_id"], "a1b2c3d4e5f60718".to_string() + "2930a1b2c3d4e5f6");
    assert_eq!(m["kernel"], "6.8.0-49-generic");
    assert_eq!(m["os_name"], "Ubuntu");
    assert_eq!(m["uptime_seconds"].as_u64().unwrap() > 0, true);
    assert!(m["memory_mb"].as_u64().unwrap() > 0);
    let users = m["users"].as_array().unwrap();
    assert!(users.iter().any(|u| u["name"] == "root" && u["privileged"] == true));
    assert!(users.iter().any(|u| u["name"] == "web"));
    assert_eq!(m["elevated"], false);
    // exhaustive hardware + system inventory
    assert_eq!(m["motherboard"]["vendor"], "Supermicro");
    assert_eq!(m["motherboard"]["name"], "X10DRH-iT");
    assert_eq!(m["bios"]["vendor"], "American Megatrends");
    assert_eq!(m["bios"]["version"], "3.4");
    assert_eq!(m["product"]["name"], "XYZ Server");
    let gpu_name = m["gpu"][0]["name"].as_str().unwrap_or_default().to_string();
    assert!(gpu_name.contains("NVIDIA") && gpu_name.contains("A10G"), "gpu name: {gpu_name}");
    assert!(m["gpu"].as_array().unwrap().len() >= 1);
    assert_eq!(m["cpu"]["cores"], 8);
    assert_eq!(m["cpu"]["model"], "Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz");
    assert_eq!(m["cpu"]["microcode"], "0xb40006a3");
    assert!(m["memory"]["swap_total_mb"].as_u64().unwrap() > 0);
    assert!(m["memory"]["available_mb"].as_u64().unwrap() > 0);
    assert_eq!(m["storage"][0]["device"], "sda");
    assert_eq!(m["storage"][0]["model"], "SAMSUNG MZ7LM960");
    assert_eq!(m["network"]["interfaces"][0]["name"], "eth0");
    assert_eq!(m["network"]["interfaces"][0]["mac"], "52:54:00:ab:cd:ef");
    assert!(m["kernel_info"]["version"].as_str().unwrap_or_default().contains("#56-Ubuntu SMP"));
    assert!(m["kernel_info"]["modules"].as_u64().unwrap() >= 1);
    assert_eq!(m["services_count"].as_u64().unwrap(), 3);
    assert_eq!(m["processes"].as_u64().unwrap(), 180);

    // The FQDN chain is file-only and records its source attempts.
    let fqdn_sources = attempt_sources(&m, "fqdn");
    assert!(
        fqdn_sources.iter().any(|s| s.contains("/etc/resolv.conf")),
        "file-only fqdn source missing: {fqdn_sources:?}"
    );
    assert!(
        !fqdn_sources.iter().any(|s| s.contains("-f")),
        "DNS-resolving hostname -f must never be attempted: {fqdn_sources:?}"
    );
    // Attempts are exposed and bounded.
    let all = attempts(&m);
    assert!(!all.is_empty());
    assert!(all.len() <= 400);
}

#[test]
fn windows_metadata_from_injected_sources() {
    let mut p = detect();
    p.os = Os::Windows;
    p.kernel = "10.0.26100".into();
    let ctx = ScanContext::new(p, true)
        .with_root_prefix("tests/fixtures/meta-win")
        .with_injector(Box::new(|prog, args| match (prog, args.first()) {
            ("hostname", _) => Some("WIN-DC01".into()),
            ("powershell", _) => {
                let joined = args.join(" ");
                if joined.contains("MachineGuid") {
                    Some("fedcba9876543210-XYZ".into())
                } else if joined.contains("Get-HotFix") {
                    Some("[{\"HotFixID\":\"KB5044284\",\"InstalledOn\":\"2025-11-12\"}]".into())
                } else if joined.contains("COMPUTERNAME") {
                    Some("WIN-DC01".into())
                } else {
                    None
                }
            }
            _ => None,
        }));
    let m = collect(&mut { ctx });
    assert_eq!(m["hostname"], "WIN-DC01");
    assert_eq!(m["machine_id"], "fedcba9876543210-XYZ");
    assert_eq!(m["elevated"], true);
    assert!(m["patch_level"]["hotfix_count"].as_u64().unwrap() >= 1);
    assert!(!attempts(&m).is_empty());
}

/// With an empty fixture root and no injector, `collect` must still return
/// every expected key (values may be null) and must never panic.
#[test]
fn empty_root_yields_every_key_without_panic() {
    let root = temp_root("empty-none");
    let mut ctx = ScanContext::new(linux_platform(), false)
        .with_root_prefix(&root.to_string_lossy());
    let m = collect(&mut ctx);
    let obj = m.as_object().expect("metadata object");
    for key in METADATA_KEYS {
        assert!(obj.contains_key(*key), "missing key {key}");
    }
    assert!(obj.contains_key("_collection"));
    let _ = std::fs::remove_dir_all(&root);
}

/// When the primary source is absent the fallback resolves the field and
/// both attempts are recorded.
#[test]
fn primary_absent_resolves_via_fallback_and_records_both() {
    let root = temp_root("fallback");
    // Only the fallback hostname file exists.
    put(&root, "proc/sys/kernel/hostname", "fallbackhost\n");
    let mut ctx = ctx_with(&root.to_string_lossy(), Box::new(|_, _| None));
    let m = collect(&mut ctx);
    assert_eq!(m["hostname"], "fallbackhost");
    let sources = attempt_sources(&m, "hostname");
    assert!(
        sources.iter().any(|s| *s == "/etc/hostname"),
        "primary attempt missing: {sources:?}"
    );
    assert!(
        sources.iter().any(|s| *s == "/proc/sys/kernel/hostname"),
        "fallback attempt missing: {sources:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// A field whose sources all fail yields null, records the failures, and
/// leaves sibling fields untouched.
#[test]
fn all_sources_fail_isolates_siblings() {
    let root = temp_root("isolation");
    let mut ctx = ctx_with(
        &root.to_string_lossy(),
        Box::new(|prog, args| match (prog, args.first()) {
            ("uname", Some(&"-r")) => Some("6.8.0-49-generic".into()),
            _ => None,
        }),
    );
    let m = collect(&mut ctx);

    // Kernel resolves through the injected command...
    assert_eq!(m["kernel"], "6.8.0-49-generic");
    // ...while machine_id has no source here and becomes an explicit null.
    assert!(m["machine_id"].is_null());
    assert!(m["fqdn"].is_null());

    let machine_id_sources = attempt_sources(&m, "machine_id");
    assert!(
        machine_id_sources.len() >= 2,
        "expected several failed machine_id attempts: {machine_id_sources:?}"
    );
    // The sibling kernel field still resolved via its own chain.
    let kernel_sources = attempt_sources(&m, "kernel");
    assert!(kernel_sources.iter().any(|s| s.contains("uname -r")));
    let _ = std::fs::remove_dir_all(&root);
}
