use hbs_extractor::model::*;

#[test]
fn severity_serde_roundtrip() {
    assert_eq!(serde_json::to_string(&Severity::High).unwrap(), "\"High\"");
    assert_eq!(Severity::Critical.weight(), 10);
    assert_eq!(Severity::Informational.weight(), 0);
}

#[test]
fn check_result_serializes_all_fields() {
    let r = CheckResult {
        id: "LIN-SSH-001".into(),
        title: "t".into(),
        status: Status::NonCompliant,
        severity: Severity::High,
        category: "SSH".into(),
        description: "d".into(),
        impact: "i".into(),
        recommendation: "r".into(),
        references: vec!["CIS 5.2.8".into()],
        evidence: "PermitRootLogin yes".into(),
        location: "/etc/ssh/sshd_config".into(),
        repro: "grep PermitRootLogin /etc/ssh/sshd_config".into(),
        degraded_reason: None,
        fallback_log: vec![FallbackAttempt {
            source: "file".into(),
            outcome: "ok".into(),
        }],
        evidence_blocks: vec![],
        run_context: hbs_extractor::model::RunContext { user: "test".into(), uid: Some(1000), elevated: false },
        duration_ms: 3,
    };
    let v: serde_json::Value = serde_json::to_value(&r).unwrap();
    assert_eq!(v["status"], "NonCompliant");
    assert_eq!(v["fallbackLog"][0]["source"], "file");
    assert_eq!(v["durationMs"], 3);
    assert_eq!(v["degradedReason"], serde_json::Value::Null);
}

#[test]
fn status_and_summary_counts_serialize() {
    let s = Summary {
        compliant: 2,
        non_compliant: 1,
        not_applicable: 1,
        error: 0,
        degraded: 0,
        informational: 0,
    };
    let v: serde_json::Value = serde_json::to_value(&s).unwrap();
    assert_eq!(v["nonCompliant"], 1);
    assert_eq!(
        serde_json::to_string(&Status::DegradedPartial).unwrap(),
        "\"DegradedPartial\""
    );
}
