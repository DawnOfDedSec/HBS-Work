//! Environment classification (bare metal / VM / container / WSL).
//!
//! Every scenario is simulated through a fixture root plus a command
//! injector, so detection is deterministic on any build host and no real
//! host state is read or spawned. Assertions check the classification
//! *and* the independent signals recorded for it.

use std::path::{Path, PathBuf};

use hbs_extractor::context::ScanContext;
use hbs_extractor::evidence::CmdInjector;
use hbs_extractor::platform::{detect, detect_environment, DistroFamily, Environment, Os};

fn temp_root(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("hbs-env-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn put(root: &Path, rel: &str, content: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, content).unwrap();
}

fn linux_ctx(root: &Path, injector: CmdInjector) -> ScanContext {
    let mut p = detect();
    p.os = Os::Linux;
    p.family = DistroFamily::Debian;
    p.arch = "x86_64".into();
    ScanContext::new(p, false)
        .with_root_prefix(&root.to_string_lossy())
        .with_injector(injector)
}

fn detect_virt(value: Option<&'static str>) -> CmdInjector {
    Box::new(move |prog, _args| {
        if prog == "systemd-detect-virt" {
            value.map(str::to_string)
        } else {
            None
        }
    })
}

#[test]
fn container_detected_from_multiple_signals() {
    let root = temp_root("container");
    put(
        &root,
        "proc/1/cgroup",
        "12:cpuset:/docker/abc123\n11:memory:/containerd\n",
    );
    put(&root, ".dockerenv", "");
    put(
        &root,
        "proc/self/mountinfo",
        "36 35 98:0 / / rw,relatime - overlay overlay rw,lowerdir=/lower,upperdir=/upper\n",
    );

    let mut ctx = linux_ctx(&root, detect_virt(Some("docker")));
    let env = ctx.refresh_environment();

    assert_eq!(env.kind, Environment::Container);
    assert!(ctx.is_container(), "context should report a container");
    assert!(
        env.signals.iter().any(|s| s.contains("/.dockerenv")),
        "signals: {:?}",
        env.signals
    );
    assert!(
        env.signals
            .iter()
            .any(|s| s.contains("/proc/1/cgroup: docker")),
        "signals: {:?}",
        env.signals
    );
    assert!(
        env.signals.iter().any(|s| s.contains("overlay")),
        "signals: {:?}",
        env.signals
    );
    assert!(
        env.signals
            .iter()
            .any(|s| s.contains("systemd-detect-virt: docker")),
        "signals: {:?}",
        env.signals
    );
    // Multiple independent signals, never a single probe.
    assert!(
        env.signals.len() >= 3,
        "expected several signals: {:?}",
        env.signals
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn virtual_machine_detected_from_dmi_and_detect_virt() {
    let root = temp_root("vm");
    put(&root, "sys/class/dmi/id/sys_vendor", "VMware, Inc.\n");
    put(
        &root,
        "sys/class/dmi/id/product_name",
        "VMware Virtual Platform\n",
    );

    let mut ctx = linux_ctx(&root, detect_virt(Some("vmware")));
    let env = ctx.refresh_environment();

    assert_eq!(env.kind, Environment::VirtualMachine);
    assert_eq!(env.hypervisor.as_deref(), Some("VMware"));
    assert!(ctx.is_vm());
    assert!(
        env.signals.iter().any(|s| s.starts_with("dmi sys_vendor:")),
        "signals: {:?}",
        env.signals
    );
    assert!(
        env.signals
            .iter()
            .any(|s| s.contains("systemd-detect-virt: vmware")),
        "signals: {:?}",
        env.signals
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn bare_metal_when_no_virtualization_marker() {
    let root = temp_root("bare");
    // `systemd-detect-virt` returning "none" is the authoritative
    // physical signal; the fixture itself carries no virt markers.
    let mut ctx = linux_ctx(&root, detect_virt(Some("none")));
    let env = ctx.refresh_environment();

    assert_eq!(env.kind, Environment::BareMetal);
    assert!(env.hypervisor.is_none());
    assert!(!ctx.is_container());
    assert!(!ctx.is_vm());
    assert!(
        env.signals
            .iter()
            .any(|s| s.contains("systemd-detect-virt: none")),
        "signals: {:?}",
        env.signals
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn wsl_detected_from_proc_version() {
    let root = temp_root("wsl");
    put(
        &root,
        "proc/version",
        "Linux version 5.15.90.1-microsoft-standard-WSL2 (gcc ...)\n",
    );

    let mut ctx = linux_ctx(&root, detect_virt(Some("wsl")));
    let env = ctx.refresh_environment();

    assert_eq!(env.kind, Environment::Wsl);
    assert!(
        env.signals.iter().any(|s| s.contains("Microsoft/WSL")),
        "signals: {:?}",
        env.signals
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn unknown_when_no_signal_is_observable() {
    let root = temp_root("nothing");
    // Degrade-safe: no readable marker and no injected command answer.
    let mut ctx = linux_ctx(&root, Box::new(|_, _| None));
    let env = detect_environment(&mut ctx);

    assert_eq!(env.kind, Environment::Unknown);
    assert!(env.hypervisor.is_none());
    assert!(
        env.signals
            .iter()
            .any(|s| s.contains("no environment signals")),
        "signals: {:?}",
        env.signals
    );

    let _ = std::fs::remove_dir_all(&root);
}
