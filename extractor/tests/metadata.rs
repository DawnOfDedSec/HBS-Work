use hbs_extractor::context::ScanContext;
use hbs_extractor::metadata::collect;
use hbs_extractor::platform::{detect, DistroFamily, Os};

fn ctx() -> ScanContext {
    let mut p = detect();
    p.os = Os::Linux;
    p.family = DistroFamily::Debian;
    p.distro = Some("Ubuntu".into());
    p.distro_version = Some("24.04".into());
    ScanContext::new(p, false)
        .with_root_prefix("tests/fixtures/meta-root")
        .with_injector(Box::new(|prog, args| match (prog, args.first()) {
            ("hostname", Some(&"-f")) => Some("web01.corp.example".into()),
            ("uname", Some(&"-r")) => Some("6.8.0-49-generic".into()),
            ("lspci", _) => Some("3B:00.0 3D controller [0302]: NVIDIA Corporation GA102GL [A10G] [10de:2236]".into()),
            ("systemctl", _) if args.contains(&"list-units") => Some("a.service loaded active running\nb.service loaded active running\nc.service loaded active running".into()),
            _ => None,
        }))
}

#[test]
fn linux_metadata_from_fixtures() {
    let m = collect(&mut ctx());
    assert_eq!(m["hostname"], "web01");
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
}

#[test]
fn windows_metadata_from_injected_sources() {
    let mut p = detect();
    p.os = Os::Windows;
    p.kernel = "10.0.26100".into();
    let ctx = ScanContext::new(p, true)
        .with_root_prefix("tests/fixtures/meta-win")
        .with_injector(Box::new(|prog, args| match (prog, args) {
            ("hostname", _) => Some("WIN-DC01".into()),
            ("powershell", ps) => {
                let joined = ps.join(" ");
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
}
