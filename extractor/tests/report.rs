use hbs_extractor::model::{CheckResult, SelfAudit, Severity, Status};
use hbs_extractor::report::build;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

fn sample_result() -> CheckResult {
    CheckResult {
        id: "T-1".into(),
        title: "t".into(),
        status: Status::Compliant,
        severity: Severity::Low,
        category: "C".into(),
        description: "d".into(),
        impact: "i".into(),
        recommendation: "r".into(),
        references: vec![],
        evidence: "e".into(),
        location: "l".into(),
        repro: "rp".into(),
        degraded_reason: None,
        fallback_log: vec![],
        evidence_blocks: vec![],
        run_context: hbs_extractor::model::RunContext { user: "test".into(), uid: Some(1000), elevated: false },
        duration_ms: 1,
    }
}

#[test]
fn report_carries_scan_block_and_schema() {
    let started = SystemTime::now() - std::time::Duration::from_secs(5);
    let scan_extra = json!({
        "extractor_id": "12345678-1234-1234-1234-123456789abc",
        "machine_id": "a1b2c3d4e5f60718",
        "hostname": "web01",
        "platform": "Linux",
        "arch": "x86_64",
    });
    let r = build(
        scan_extra,
        json!({"os_name": "Ubuntu"}),
        vec![sample_result()],
        SelfAudit { commands: vec!["uname -r".into()], files_read: vec![] },
        started,
        5000,
        "0.1.0-test",
    );
    assert_eq!(r.schema_version, 1);
    assert_eq!(r.scan["extractor_id"], "12345678-1234-1234-1234-123456789abc");
    assert_eq!(r.scan["hostname"], "web01");
    assert_eq!(r.scan["extractorVersion"], "0.1.0-test");
    assert_eq!(r.scan["privilege"], "degraded");
    assert_eq!(r.scan["durationMs"], 5000);
    assert!(r.scan["startedUnix"].as_u64().unwrap() > 1_500_000_000);
    assert_eq!(r.results.len(), 1);
    assert_eq!(r.summary.compliant, 1);
    assert_eq!(r.self_audit.commands, vec!["uname -r".to_string()]);
    // Full document serializes cleanly (this is what gets sealed).
    let doc = serde_json::to_vec(&r).unwrap();
    assert!(doc.len() > 100);
}

#[test]
fn report_elevated_privilege_flag() {
    let mut scan_extra = json!({});
    scan_extra["privileged"] = json!(true);
    let r = build(scan_extra, json!({}), vec![], SelfAudit::default(), UNIX_EPOCH, 0, "v");
    assert_eq!(r.scan["privilege"], "elevated");
}
