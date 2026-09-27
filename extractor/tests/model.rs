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
        run_context: hbs_extractor::model::RunContext {
            user: "test".into(),
            uid: Some(1000),
            elevated: false,
        },
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

#[test]
fn audit_kind_and_status_serialize_lowercase() {
    assert_eq!(serde_json::to_string(&AuditKind::File).unwrap(), "\"file\"");
    assert_eq!(
        serde_json::to_string(&AuditKind::Command).unwrap(),
        "\"command\""
    );
    assert_eq!(
        serde_json::to_string(&AuditKind::Registry).unwrap(),
        "\"registry\""
    );
    assert_eq!(serde_json::to_string(&AuditKind::Api).unwrap(), "\"api\"");
    assert_eq!(serde_json::to_string(&AuditStatus::Ok).unwrap(), "\"ok\"");
    assert_eq!(
        serde_json::to_string(&AuditStatus::Missing).unwrap(),
        "\"missing\""
    );
    assert_eq!(
        serde_json::to_string(&AuditStatus::Denied).unwrap(),
        "\"denied\""
    );
    assert_eq!(
        serde_json::to_string(&AuditStatus::Timeout).unwrap(),
        "\"timeout\""
    );
    assert_eq!(
        serde_json::to_string(&AuditStatus::Rejected).unwrap(),
        "\"rejected\""
    );
    assert_eq!(
        serde_json::to_string(&AuditStatus::NonZero).unwrap(),
        "\"nonzero\""
    );
    assert_eq!(
        serde_json::to_string(&AuditStatus::Malformed).unwrap(),
        "\"malformed\""
    );
    assert_eq!(
        serde_json::to_string(&AuditStatus::Cached).unwrap(),
        "\"cached\""
    );
    assert_eq!(
        serde_json::to_string(&AuditStatus::Error).unwrap(),
        "\"error\""
    );
}

#[test]
fn audit_attempt_serde_roundtrip_camelcase() {
    let a = AuditAttempt {
        seq: 7,
        kind: AuditKind::Command,
        source: "uname -r".into(),
        outcome: "exit 0; 12 bytes".into(),
        status: AuditStatus::Ok,
        exit_code: Some(0),
        bytes: Some(12),
        duration_ms: Some(3),
        cached: false,
        note: None,
        evidence_ref: Some("LIN-1:4".into()),
    };
    let v: serde_json::Value = serde_json::to_value(&a).unwrap();
    assert_eq!(v["seq"], 7);
    assert_eq!(v["kind"], "command");
    assert_eq!(v["source"], "uname -r");
    assert_eq!(v["status"], "ok");
    assert_eq!(v["exitCode"], 0);
    assert_eq!(v["bytes"], 12);
    assert_eq!(v["durationMs"], 3);
    assert_eq!(v["cached"], false);
    assert_eq!(v["evidenceRef"], "LIN-1:4");
    assert_eq!(v["note"], serde_json::Value::Null);
    let back: AuditAttempt = serde_json::from_value(v).unwrap();
    assert_eq!(back.kind, AuditKind::Command);
    assert_eq!(back.status, AuditStatus::Ok);
    assert_eq!(back.exit_code, Some(0));
    assert_eq!(back.bytes, Some(12));
    assert_eq!(back.duration_ms, Some(3));
    assert_eq!(back.evidence_ref.as_deref(), Some("LIN-1:4"));
}

#[test]
fn self_audit_attempts_are_bounded_and_redacted() {
    let mut audit = SelfAudit::default();
    let idx = audit.begin_attempt(AuditKind::File, "/etc/password=SuperSecret123");
    audit.finish_attempt(idx, |a| {
        a.status = AuditStatus::Denied;
        a.outcome = "permission denied".into();
    });
    let v: serde_json::Value = serde_json::to_value(&audit).unwrap();
    assert_eq!(v["attempts"][0]["status"], "denied");
    assert!(!v.to_string().contains("SuperSecret123"), "{v}");
    // begin_attempt returns None once the cap is hit.
    let mut full = SelfAudit::default();
    for _ in 0..MAX_AUDIT_ATTEMPTS {
        full.begin_attempt(AuditKind::File, "/x");
    }
    assert_eq!(full.attempts.len(), MAX_AUDIT_ATTEMPTS);
    assert!(full.begin_attempt(AuditKind::File, "/y").is_none());
    assert!(!full.warnings.is_empty());
}
