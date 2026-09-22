//! Report assembly: folds scan context, metadata, results, self-audit
//! and timing into the schema-versioned Report document that gets
//! zstd-compressed and sealed.

use crate::model::{CheckResult, Report, SelfAudit, Summary};
use serde_json::{json, Map, Value};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SCHEMA_VERSION: u16 = 1;

pub fn build(
    scan_extra: Value,
    metadata: Value,
    results: Vec<CheckResult>,
    audit: SelfAudit,
    started: SystemTime,
    duration_ms: u64,
    version: &str,
) -> Report {
    let mut scan = match scan_extra {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    let elevated = scan
        .get("privileged")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    scan.insert("schemaVersion".into(), json!(SCHEMA_VERSION));
    scan.insert("extractorVersion".into(), json!(version));
    scan.insert("privilege".into(), json!(if elevated { "elevated" } else { "degraded" }));
    scan.insert(
        "startedUnix".into(),
        json!(started.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)),
    );
    scan.insert("durationMs".into(), json!(duration_ms));

    // Privilege auditing fields (spec §4.2)
    let status_str = scan
        .get("elevationStatus")
        .and_then(Value::as_str)
        .unwrap_or("not-needed")
        .to_string();
    let requested = status_str == "requested" || status_str == "granted" || status_str == "refused";
    let granted = status_str == "granted";
    let refused = status_str == "refused";
    scan.entry("elevationStatus").or_insert_with(|| json!(status_str));
    scan.entry("privilegeRequested").or_insert_with(|| json!(requested));
    scan.entry("privilegeGranted").or_insert_with(|| json!(granted));
    scan.entry("privilegeRefused").or_insert_with(|| json!(refused));

    let summary = crate::engine::summarize(&results);
    Report {
        schema_version: SCHEMA_VERSION,
        scan: Value::Object(scan),
        metadata,
        results,
        summary,
        self_audit: audit,
    }
}

/// Convenience for tests and callers wanting the summary alone.
pub fn summary_of(results: &[CheckResult]) -> Summary {
    crate::engine::summarize(results)
}
