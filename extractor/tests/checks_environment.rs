//! Environment-aware catalog semantics.
//!
//! With a simulated container environment, controls that genuinely cannot
//! exist (firmware, TPM, bootloader, kernel modules/lockdown, host
//! firewall, host partition layout, swap) must be `NotApplicable` - never
//! `NonCompliant` and never `Error`. Ordinary controls must still
//! evaluate normally, so the environment gate is not a blanket skip.

use std::path::{Path, PathBuf};

use hbs_extractor::checks::register_all;
use hbs_extractor::context::ScanContext;
use hbs_extractor::engine::run_all;
use hbs_extractor::evidence::CmdInjector;
use hbs_extractor::model::{CheckResult, RegisteredCheck, Status};
use hbs_extractor::platform::{detect, DistroFamily, Os};

/// Host-only controls that cannot exist inside a container.
const CONTAINER_IMPOSSIBLE_IDS: &[&str] = &[
    "GEN-INV-012",
    "GEN-INV-013",
    "GEN-INV-017",
    "GEN-INV-021",
    "GEN-SRV-014",
    "GEN-SRV-019",
    "GEN-SRV-022",
    "LIN-FW-001",
    "LIN-FW-002",
    "LIN-FW-003",
    "LIN-FW-004",
    "LIN-FW-005",
    "LIN-FS-001",
    "LIN-FS-002",
    "LIN-FS-003",
    "LIN-FS-004",
    "LIN-FS-005",
    "LIN-FS-006",
    "LIN-FS-007",
    "LIN-FS-008",
    "LIN-FS-009",
    "LIN-FS-010",
    "LIN-FS-011",
    "LIN-FS-012",
    "LIN-FS-013",
    "LIN-FS-015",
    "LIN-TH-010",
    "LIN-TH-011",
    "LIN-TH-037",
];

fn temp_root(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("hbs-checkenv-{}-{}", tag, std::process::id()));
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

fn container_root(tag: &str) -> PathBuf {
    let root = temp_root(tag);
    put(&root, "proc/1/cgroup", "12:cpuset:/docker/abc123\n");
    put(&root, ".dockerenv", "");
    root
}

fn run_one(ctx: &mut ScanContext, id: &str) -> CheckResult {
    let mut reg: Vec<RegisteredCheck> = Vec::new();
    register_all(&mut reg);
    let subset: Vec<RegisteredCheck> = reg.into_iter().filter(|c| c.tc.id == id).collect();
    assert_eq!(
        subset.len(),
        1,
        "check {id} must be registered exactly once"
    );
    run_all(&subset, ctx).remove(0)
}

#[test]
fn container_host_only_controls_are_not_applicable() {
    let root = container_root("host-only");
    let injector: CmdInjector = Box::new(|prog, _| {
        if prog == "systemd-detect-virt" {
            Some("docker".into())
        } else {
            None
        }
    });
    let mut ctx = linux_ctx(&root, injector);
    let env = ctx.refresh_environment();
    assert!(env.is_container(), "test setup: {:?}", env);

    let mut problems = Vec::new();
    for id in CONTAINER_IMPOSSIBLE_IDS {
        let r = run_one(&mut ctx, id);
        match r.status {
            Status::NotApplicable => {}
            other => problems.push(format!(
                "{id}: expected NotApplicable, got {other:?} - {}",
                r.evidence
            )),
        }
        if r.status == Status::Error {
            problems.push(format!("{id}: returned Error - {}", r.evidence));
        }
        if r.status == Status::NonCompliant {
            problems.push(format!("{id}: false NonCompliant - {}", r.evidence));
        }
    }

    let _ = std::fs::remove_dir_all(&root);
    assert!(
        problems.is_empty(),
        "container host-only control failures:\n{}",
        problems.join("\n")
    );
}

#[test]
fn container_non_hardware_control_still_evaluates() {
    let root = container_root("normal-control");
    put(
        &root,
        "etc/passwd",
        "root:x:0:0:root:/root:/bin/bash\nsvc:x:999:999::/:/sbin/nologin\n",
    );
    let injector: CmdInjector = Box::new(|prog, _| {
        if prog == "systemd-detect-virt" {
            Some("docker".into())
        } else {
            None
        }
    });
    let mut ctx = linux_ctx(&root, injector);
    assert!(ctx.refresh_environment().is_container());

    // A non-hardware inventory control must not be suppressed by the
    // container classification.
    let r = run_one(&mut ctx, "GEN-INV-003");
    assert_eq!(r.status, Status::Compliant, "{}", r.evidence);
    assert!(r.evidence.contains("root"));

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn vm_without_virtual_firmware_is_not_applicable_not_noncompliant() {
    let root = temp_root("vm-firmware");
    put(&root, "sys/class/dmi/id/sys_vendor", "VMware, Inc.\n");
    put(
        &root,
        "sys/class/dmi/id/product_name",
        "VMware Virtual Platform\n",
    );
    let injector: CmdInjector = Box::new(|prog, _| {
        if prog == "systemd-detect-virt" {
            Some("vmware".into())
        } else {
            None
        }
    });
    let mut ctx = linux_ctx(&root, injector);
    let env = ctx.refresh_environment();
    assert_eq!(env.hypervisor.as_deref(), Some("VMware"));

    // No virtual TPM and no Secure Boot interface exposed -> N/A (never a
    // fabricated "no TPM"/"Secure Boot disabled" failure).
    for id in ["GEN-INV-013", "GEN-SRV-019"] {
        let r = run_one(&mut ctx, id);
        assert_eq!(r.status, Status::NotApplicable, "{id}: {}", r.evidence);
        assert!(
            r.evidence.contains("VMware"),
            "{id} evidence should name the hypervisor: {}",
            r.evidence
        );
    }

    let _ = std::fs::remove_dir_all(&root);
}
