//! Report assembly: folds scan context, metadata, results, self-audit,
//! diagnostics and timing into the schema-versioned Report document that
//! gets zstd-compressed and sealed.
//!
//! The diagnostics block is derived here from the same inputs, so a
//! caller cannot accidentally omit it: every sealed report carries a
//! complete, redacted, bounded audit trail plus a human-readable log.

use crate::model::{
    bounded_redact, CheckResult, Diagnostics, MissingData, Report, SelfAudit, Status, Summary,
};
use serde_json::{json, Map, Value};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SCHEMA_VERSION: u16 = 1;

/// Cap on the human-readable log lines stored in diagnostics.
pub const MAX_DIAG_LOG_LINES: usize = 5000;
/// Cap on metadata attempts echoed into diagnostics.
const MAX_DIAG_METADATA_ATTEMPTS: usize = 500;
/// Cap on exhausted-source entries per missing-data row.
const MAX_DIAG_SOURCES: usize = 100;

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
    scan.insert(
        "privilege".into(),
        json!(if elevated { "elevated" } else { "degraded" }),
    );
    scan.insert(
        "startedUnix".into(),
        json!(started
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)),
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
    scan.entry("elevationStatus")
        .or_insert_with(|| json!(status_str));
    scan.entry("privilegeRequested")
        .or_insert_with(|| json!(requested));
    scan.entry("privilegeGranted")
        .or_insert_with(|| json!(granted));
    scan.entry("privilegeRefused")
        .or_insert_with(|| json!(refused));

    let summary = crate::engine::summarize(&results);
    let diagnostics = build_diagnostics(&scan, &metadata, &results, version, duration_ms);
    Report {
        schema_version: SCHEMA_VERSION,
        scan: Value::Object(scan),
        metadata,
        results,
        summary,
        self_audit: audit,
        diagnostics,
    }
}

/// Convenience for tests and callers wanting the summary alone.
pub fn summary_of(results: &[CheckResult]) -> Summary {
    crate::engine::summarize(results)
}

fn status_name(s: Status) -> &'static str {
    match s {
        Status::Compliant => "Compliant",
        Status::NonCompliant => "NonCompliant",
        Status::NotApplicable => "NotApplicable",
        Status::Error => "Error",
        Status::DegradedPartial => "DegradedPartial",
    }
}

fn build_diagnostics(
    scan: &Map<String, Value>,
    metadata: &Value,
    results: &[CheckResult],
    version: &str,
    duration_ms: u64,
) -> Diagnostics {
    let environment = json!({
        "kind": scan.get("environment").cloned().unwrap_or(Value::Null),
        "hypervisor": scan.get("hypervisor").cloned().unwrap_or(Value::Null),
        "signals": scan.get("environmentSignals").cloned().unwrap_or_else(|| json!([])),
    });
    let catalog_fingerprint = scan
        .get("catalogFingerprint")
        .and_then(Value::as_str)
        .map(bounded_redact);
    let privilege = json!({
        "status": scan.get("elevationStatus").cloned().unwrap_or_else(|| json!("not-needed")),
        "requested": scan.get("privilegeRequested").and_then(Value::as_bool).unwrap_or(false),
        "granted": scan.get("privilegeGranted").and_then(Value::as_bool).unwrap_or(false),
        "refused": scan.get("privilegeRefused").and_then(Value::as_bool).unwrap_or(false),
        "privileged": scan.get("privileged").and_then(Value::as_bool).unwrap_or(false),
    });
    let peak_rss_kb = scan.get("peakRssKb").and_then(Value::as_u64).unwrap_or(0);
    let phase_durations_ms = scan
        .get("phaseDurationsMs")
        .cloned()
        .unwrap_or_else(|| json!({}));

    // Every result that could not be fully assessed, with the reason and
    // the list of sources that were exhausted trying.
    let missing_data: Vec<MissingData> = results
        .iter()
        .filter(|r| {
            matches!(
                r.status,
                Status::DegradedPartial | Status::NotApplicable | Status::Error
            )
        })
        .map(|r| {
            let reason = r
                .degraded_reason
                .as_deref()
                .or_else(|| (!r.evidence.is_empty()).then_some(r.evidence.as_str()))
                .map(bounded_redact);
            let exhausted_sources: Vec<String> = r
                .fallback_log
                .iter()
                .take(MAX_DIAG_SOURCES)
                .map(|f| bounded_redact(&f.source))
                .collect();
            MissingData {
                check_id: r.id.clone(),
                status: status_name(r.status).to_string(),
                reason,
                exhausted_sources,
            }
        })
        .collect();

    let metadata_attempts = redact_attempts_value(
        metadata
            .get("_collection")
            .and_then(|c| c.get("attempts"))
            .cloned()
            .unwrap_or_else(|| json!([])),
    );

    let log = build_log(scan, metadata, results, version, duration_ms);

    Diagnostics {
        environment,
        catalog_fingerprint,
        extractor_version: version.to_string(),
        privilege,
        peak_rss_kb,
        scan_duration_ms: duration_ms,
        phase_durations_ms,
        missing_data,
        metadata_attempts,
        log,
    }
}

/// Re-redact and bound the metadata attempt array defensively.
fn redact_attempts_value(v: Value) -> Value {
    match v {
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .take(MAX_DIAG_METADATA_ATTEMPTS)
                .map(|mut item| {
                    if let Value::Object(m) = &mut item {
                        for key in ["field", "source", "outcome"] {
                            if let Some(Value::String(s)) = m.get(key) {
                                let r = bounded_redact(s);
                                m.insert(key.to_string(), Value::String(r));
                            }
                        }
                    }
                    item
                })
                .collect(),
        ),
        other => other,
    }
}

/// Build the CLI-style, bounded, redacted scan log. A phase/timing
/// preamble followed by one `✓/✗/⚠ id title [severity] (reason)` line per
/// result, so the decrypted report reads top-to-bottom.
fn build_log(
    scan: &Map<String, Value>,
    metadata: &Value,
    results: &[CheckResult],
    version: &str,
    duration_ms: u64,
) -> Vec<String> {
    let mut log: Vec<String> = Vec::new();
    let env_kind = scan
        .get("environment")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let hv = scan
        .get("hypervisor")
        .and_then(Value::as_str)
        .unwrap_or("none");
    let signals = scan
        .get("environmentSignals")
        .and_then(Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0);
    log.push(format!(
        "\u{2713} hbs-extractor {version} scan log (schema {SCHEMA_VERSION})"
    ));
    log.push(format!(
        "\u{2713} environment: {env_kind} (hypervisor={hv}, {signals} signals)"
    ));
    log.push(format!(
        "\u{2713} platform: {} {}",
        scan.get("platform").and_then(Value::as_str).unwrap_or("?"),
        scan.get("arch").and_then(Value::as_str).unwrap_or("?")
    ));
    let elevation = scan
        .get("elevationStatus")
        .and_then(Value::as_str)
        .unwrap_or("not-needed");
    log.push(format!(
        "\u{2713} privilege: {elevation} (requested={} granted={} refused={})",
        scan.get("privilegeRequested")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        scan.get("privilegeGranted")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        scan.get("privilegeRefused")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    ));
    if let Some(fp) = scan.get("catalogFingerprint").and_then(Value::as_str) {
        log.push(format!("\u{2713} catalog fingerprint: {fp}"));
    }
    let fields = metadata.as_object().map(|o| o.len()).unwrap_or(0);
    let attempts = metadata
        .get("_collection")
        .and_then(|c| c.get("attempts"))
        .and_then(Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0);
    log.push(format!(
        "\u{2713} metadata: {fields} fields, {attempts} collection attempts"
    ));
    log.push(format!("\u{2713} scan duration: {duration_ms} ms"));
    if let Some(Value::Object(phases)) = scan.get("phaseDurationsMs") {
        let mut names: Vec<&String> = phases.keys().collect();
        names.sort();
        for name in names {
            if let Some(ms) = phases.get(name).and_then(Value::as_u64) {
                log.push(format!("\u{2713} phase {name}: {ms} ms"));
            }
        }
    }
    let s = crate::engine::summarize(results);
    log.push(format!(
        "\u{2713} results: {} compliant / {} non-compliant / {} degraded / {} errors / {} n/a",
        s.compliant, s.non_compliant, s.degraded, s.error, s.not_applicable
    ));
    for r in results {
        log.push(crate::cli::fmt_check_line(r));
    }

    let omitted = log.len().saturating_sub(MAX_DIAG_LOG_LINES);
    let mut lines: Vec<String> = log
        .into_iter()
        .take(MAX_DIAG_LOG_LINES)
        .map(|l| bounded_redact(&l))
        .collect();
    if omitted > 0 {
        lines.push(bounded_redact(&format!(
            "(!) log truncated; {omitted} further lines omitted"
        )));
    }
    lines
}
