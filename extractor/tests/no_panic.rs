//! `metadata::collect` must be total: with an empty fixture root and a
//! deny-all injector it returns every expected key and never panics, on
//! either OS collector.

use hbs_extractor::context::ScanContext;
use hbs_extractor::metadata::{collect, METADATA_KEYS};
use hbs_extractor::platform::{detect, DistroFamily, Os};

fn run_collect(os: Os) {
    let mut p = detect();
    p.os = os;
    p.family = DistroFamily::Unknown;
    let root = std::env::temp_dir().join(format!("hbs-nopanic-{:?}-{}", os, std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();

    let mut ctx = ScanContext::new(p, false)
        .with_root_prefix(&root.to_string_lossy())
        .with_injector(Box::new(|_, _| None));

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| collect(&mut ctx)));
    let m = result.expect("metadata::collect panicked");
    let obj = m.as_object().expect("metadata must be a JSON object");
    for key in METADATA_KEYS {
        assert!(obj.contains_key(*key), "missing key {key}");
    }
    assert!(obj.contains_key("_collection"));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn collect_never_panics_on_linux() {
    run_collect(Os::Linux);
}

#[test]
fn collect_never_panics_on_windows() {
    run_collect(Os::Windows);
}
