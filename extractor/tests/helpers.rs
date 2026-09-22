use hbs_extractor::checks::{degraded, degraded_from_attempts, nok, ok};
use hbs_extractor::model::{FallbackAttempt, Status};

#[test]
fn ok_maps_to_compliant() {
    let o = ok("PermitRootLogin no".into(), "/etc/ssh/sshd_config".into(), "sshd -T | grep permitrootlogin".into());
    assert_eq!(o.status, Status::Compliant);
    assert_eq!(o.evidence, "PermitRootLogin no");
    assert!(o.recommendation_override.is_none());
    assert!(o.degraded_reason.is_none());
}

#[test]
fn nok_maps_to_non_compliant() {
    let o = nok("PermitRootLogin yes".into(), "/etc/ssh/sshd_config".into(), "grep PermitRootLogin /etc/ssh/sshd_config".into());
    assert_eq!(o.status, Status::NonCompliant);
}

#[test]
fn degraded_maps_with_reason() {
    let o = degraded("value absent; OpenSSH defaults apply");
    assert_eq!(o.status, Status::DegradedPartial);
    assert!(o.degraded_reason.unwrap().contains("absent"));
    assert!(o.evidence.contains("absent"));
}

#[test]
fn degraded_from_attempts_lists_every_fallback() {
    let log = vec![
        FallbackAttempt { source: "file:/etc/audit/audit.rules".into(), outcome: "missing".into() },
        FallbackAttempt { source: "cmd:auditctl -l".into(), outcome: "unavailable (needs root)".into() },
    ];
    let o = degraded_from_attempts(log, "audit.rules missing and auditctl unavailable");
    assert_eq!(o.status, Status::DegradedPartial);
    assert!(o.evidence.contains("degraded: audit.rules missing and auditctl unavailable"));
    assert!(o.evidence.contains("file:/etc/audit/audit.rules (missing)"));
    assert!(o.evidence.contains("cmd:auditctl -l (unavailable"));
    assert_eq!(o.degraded_reason.as_deref(), Some("audit.rules missing and auditctl unavailable"));
    assert_eq!(o.fallback_log.len(), 2);
}
