//! Whole-catalog audit (Task 16 Step 1 / Task 40).
//!
//! Builds the real catalog, checks ID hygiene, then runs every check twice
//! — once as Linux, once as Windows — against an empty temp root with a
//! command injector that returns `None` for everything. No process is
//! spawned and no host file is read: every source is missing, so the only
//! acceptable outcomes are Compliant / NonCompliant / NotApplicable /
//! DegradedPartial. `Status::Error` is reserved for internal invariant
//! failures, panics, or corrupt parser/input and must never appear here.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use hbs_extractor::checks::register_all;
use hbs_extractor::context::ScanContext;
use hbs_extractor::engine::run_all;
use hbs_extractor::model::{CheckResult, RegisteredCheck, Status};
use hbs_extractor::platform::{DistroFamily, Environment, EnvironmentInfo, Os, PlatformInfo};

/// The toy seed check (`GEN-TOY-001`, plus any future `T-*` scratch ids)
/// is not part of the shipped catalog.
fn is_toy(id: &str) -> bool {
    id.starts_with("T-") || id.contains("TOY")
}

/// `^(LIN|WIN|GEN)-[A-Z]+-[0-9]{3}$`
fn id_is_well_formed(id: &str) -> bool {
    let mut parts = id.split('-');
    let (Some(prefix), Some(section), Some(number), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    matches!(prefix, "LIN" | "WIN" | "GEN")
        && !section.is_empty()
        && section.chars().all(|c| c.is_ascii_uppercase())
        && number.len() == 3
        && number.chars().all(|c| c.is_ascii_digit())
}

fn platform(os: Os) -> PlatformInfo {
    platform_env(os, EnvironmentInfo::default())
}

fn platform_env(os: Os, environment: EnvironmentInfo) -> PlatformInfo {
    PlatformInfo {
        os,
        arch: "x86_64".into(),
        kernel: "catalog-audit".into(),
        distro: None,
        distro_version: None,
        family: if os == Os::Linux {
            DistroFamily::Debian
        } else {
            DistroFamily::Unknown
        },
        virtualized: None,
        environment,
    }
}

fn container_environment() -> EnvironmentInfo {
    EnvironmentInfo {
        kind: Environment::Container,
        signals: vec!["/.dockerenv present".into(), "/proc/1/cgroup: docker".into()],
        hypervisor: None,
    }
}

/// An empty directory unique to this process, so no real host path is
/// ever read while the catalog runs.
fn empty_root() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hbs-catalog-audit-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create empty catalog root");
    dir
}

fn catalog() -> Vec<RegisteredCheck> {
    let mut reg: Vec<RegisteredCheck> = Vec::new();
    register_all(&mut reg);
    reg.retain(|c| !is_toy(c.tc.id));
    reg
}

fn run_catalog(os: Os, root: &Path) -> Vec<CheckResult> {
    run_catalog_env(platform(os), root)
}

fn run_catalog_env(platform: PlatformInfo, root: &Path) -> Vec<CheckResult> {
    let reg = catalog();
    let mut ctx = ScanContext::new(platform, false)
        .with_root_prefix(&root.to_string_lossy())
        // No source can succeed: nothing is spawned and no host file is read.
        .with_injector(Box::new(|_, _| None));
    run_all(&reg, &mut ctx)
}

/// Controls that genuinely cannot exist inside a container: they must be
/// `NotApplicable`, never `NonCompliant` and never `Error`.
const CONTAINER_IMPOSSIBLE_IDS: &[&str] = &[
    // firmware / hardware
    "GEN-INV-012", // Secure Boot
    "GEN-INV-013", // TPM
    "GEN-INV-021", // kernel modules
    "GEN-SRV-019", // secure boot + TPM summary
    // host firewall
    "GEN-INV-017",
    "GEN-SRV-014",
    "LIN-FW-001",
    "LIN-FW-002",
    "LIN-FW-003",
    "LIN-FW-004",
    "LIN-FW-005",
    // bootloader / kernel
    "LIN-FS-012",
    "LIN-FS-013",
    "LIN-TH-010", // kernel lockdown
    "LIN-TH-011", // module signature enforcement
    "LIN-TH-037", // kernel cmdline
    // host partition layout / swap
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
    "LIN-FS-015",
    "GEN-SRV-022",
];

#[test]
fn whole_catalog_ids_are_unique_and_well_formed() {
    let reg = catalog();
    assert!(!reg.is_empty(), "catalog must register at least one check");

    let mut seen: HashSet<&'static str> = HashSet::new();
    for c in &reg {
        assert!(
            id_is_well_formed(c.tc.id),
            "check id does not match ^(LIN|WIN|GEN)-[A-Z]+-[0-9]{{3}}$: {}",
            c.tc.id
        );
        assert!(seen.insert(c.tc.id), "duplicate check id: {}", c.tc.id);
    }
}

#[test]
fn whole_catalog_never_errors_and_evidence_invariants_hold() {
    let root = empty_root();
    let mut problems: Vec<String> = Vec::new();

    for os in [Os::Linux, Os::Windows] {
        let results = run_catalog(os, &root);
        assert!(!results.is_empty(), "no results for {os:?}");

        for r in &results {
            // Availability/parse failures are DegradedPartial, never Error.
            if r.status == Status::Error {
                problems.push(format!(
                    "[{os:?}] {} returned Error: {}",
                    r.id, r.evidence
                ));
            }

            if r.status == Status::DegradedPartial {
                let has_reason = r
                    .degraded_reason
                    .as_deref()
                    .map(|s| !s.trim().is_empty())
                    .unwrap_or(false);
                if !(has_reason || !r.evidence.trim().is_empty()) {
                    problems.push(format!(
                        "[{os:?}] {} DegradedPartial without degraded_reason or evidence",
                        r.id
                    ));
                }
            }

            // Locatable-evidence invariant: a failing finding must carry a
            // pinpoint evidence block.
            if r.status == Status::NonCompliant && r.evidence_blocks.is_empty() {
                problems.push(format!(
                    "[{os:?}] {} NonCompliant without an evidence block: {}",
                    r.id, r.evidence
                ));
            }
        }
    }

    let _ = std::fs::remove_dir_all(&root);
    assert!(
        problems.is_empty(),
        "whole-catalog audit failures:\n{}",
        problems.join("\n")
    );
}

/// Whole catalog under a simulated container: host-only controls must be
/// `NotApplicable` (not a fabricated failure), and nothing may `Error`.
#[test]
fn whole_catalog_container_environment_not_applicable_for_host_only_controls() {
    let root = empty_root();
    let results = run_catalog_env(platform_env(Os::Linux, container_environment()), &root);
    assert!(!results.is_empty());

    let mut by_id: std::collections::HashMap<&str, &CheckResult> = std::collections::HashMap::new();
    let mut problems: Vec<String> = Vec::new();

    for r in &results {
        if r.status == Status::Error {
            problems.push(format!("container run: {} returned Error: {}", r.id, r.evidence));
        }
        if r.status == Status::NonCompliant && CONTAINER_IMPOSSIBLE_IDS.contains(&r.id.as_str()) {
            problems.push(format!(
                "container run: host-only control {} was NonCompliant: {}",
                r.id, r.evidence
            ));
        }
        by_id.insert(r.id.as_str(), r);
    }

    for id in CONTAINER_IMPOSSIBLE_IDS {
        match by_id.get(id) {
            Some(r) if r.status == Status::NotApplicable => {}
            Some(r) => problems.push(format!(
                "container run: {} expected NotApplicable, got {:?}: {}",
                id, r.status, r.evidence
            )),
            None => problems.push(format!("container run: {id} produced no result")),
        }
    }

    let _ = std::fs::remove_dir_all(&root);
    assert!(
        problems.is_empty(),
        "container whole-catalog audit failures:\n{}",
        problems.join("\n")
    );
}
