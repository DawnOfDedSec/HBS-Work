//! Windows-only tests that the native in-process fallbacks are wired into
//! the ordered evidence chains and that they are never consulted in a
//! deterministic/injected run.
#![cfg(windows)]

use hbs_extractor::checks::{register_all, windows};
use hbs_extractor::context::ScanContext;
use hbs_extractor::engine::run_all;
use hbs_extractor::model::{CheckResult, RegisteredCheck, Status};
use hbs_extractor::platform::{detect, Os};

const CURRENT_VERSION: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";

/// A Windows context whose external commands always fail. `native`
/// controls whether the in-process API fallbacks may run.
fn windows_ctx(native: bool) -> ScanContext {
    let mut platform = detect();
    platform.os = Os::Windows;
    ScanContext::new(platform, true)
        .with_injector(Box::new(|_, _| None))
        .with_native_fallbacks(native)
}

fn run_one(ctx: &mut ScanContext, id: &str) -> CheckResult {
    let mut registry: Vec<RegisteredCheck> = Vec::new();
    register_all(&mut registry);
    let subset: Vec<_> = registry.into_iter().filter(|c| c.tc.id == id).collect();
    assert_eq!(subset.len(), 1, "Check {id} registration count");
    run_all(&subset, ctx).remove(0)
}

#[test]
fn registry_query_helpers_end_in_the_native_fallback() {
    let mut ctx = windows_ctx(true);

    let dword =
        windows::reg_query_dword_with_log(&mut ctx, CURRENT_VERSION, "CurrentMajorVersionNumber");
    assert!(
        dword.value.is_some(),
        "native DWORD read failed: {:?}",
        dword.attempts
    );
    assert!(
        dword.attempts.iter().any(|a| a.source == "native registry"),
        "native attempt missing: {:?}",
        dword.attempts
    );

    let string = windows::reg_query_sz_with_log(&mut ctx, CURRENT_VERSION, "ProductName");
    assert!(
        string.value.is_some(),
        "native SZ read failed: {:?}",
        string.attempts
    );
    assert!(
        string
            .attempts
            .iter()
            .any(|a| a.source == "native registry"),
        "native attempt missing: {:?}",
        string.attempts
    );
}

#[test]
fn ifeo_packages_and_users_resolve_via_native_sources() {
    let mut ctx = windows_ctx(true);

    let ifeo = run_one(&mut ctx, "WIN-TH-015");
    assert_ne!(ifeo.status, Status::Error, "{}", ifeo.evidence);
    assert!(
        ifeo.fallback_log
            .iter()
            .any(|a| a.source.contains("native registry IFEO")),
        "native IFEO attempt missing: {:?}",
        ifeo.fallback_log
    );

    let packages = run_one(&mut ctx, "GEN-INV-002");
    assert_eq!(packages.status, Status::Compliant, "{}", packages.evidence);
    assert!(
        packages
            .fallback_log
            .iter()
            .any(|a| a.source == "native registry Uninstall keys"),
        "native Uninstall attempt missing: {:?}",
        packages.fallback_log
    );

    let users = run_one(&mut ctx, "GEN-INV-003");
    assert_eq!(users.status, Status::Compliant, "{}", users.evidence);
    assert!(
        users
            .fallback_log
            .iter()
            .any(|a| a.source == "native NetUserEnum/NetLocalGroupEnum"),
        "native account attempt missing: {:?}",
        users.fallback_log
    );
}

#[test]
fn injected_context_never_reaches_the_native_fallbacks() {
    let mut ctx = windows_ctx(false);

    for id in ["WIN-TH-015", "GEN-INV-002", "GEN-INV-003"] {
        let result = run_one(&mut ctx, id);
        assert_eq!(
            result.status,
            Status::DegradedPartial,
            "{id}: {}",
            result.evidence
        );
        assert!(
            result
                .fallback_log
                .iter()
                .any(|a| a.outcome.contains("skipped (injected context)")),
            "{id} must record the skipped native attempt: {:?}",
            result.fallback_log
        );
    }
}
