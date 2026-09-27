//! Structured audit trail + diagnostics: the sealed report must contain
//! enough detail (attempts, missing-data reasons, a human log, evidence
//! back-references) to debug any missing value after decryption.

use hbs_extractor::context::ScanContext;
use hbs_extractor::engine::run_all;
use hbs_extractor::evidence::{read_file_capped, run_command, CmdInjector};
use hbs_extractor::model::{
    AuditKind, AuditStatus, CheckOutcome, RegisteredCheck, SelfAudit, Severity, Testcase,
};
use hbs_extractor::platform::{detect, DistroFamily, Os};
use hbs_extractor::report::build;
use serde_json::json;
use std::path::PathBuf;

fn linux_platform() -> hbs_extractor::platform::PlatformInfo {
    let mut p = detect();
    p.os = Os::Linux;
    p.family = DistroFamily::Debian;
    p
}

fn fixture_ctx() -> ScanContext {
    ScanContext::new(linux_platform(), false).with_root_prefix("tests/fixtures/context-root")
}

#[test]
fn missing_file_records_missing_status_and_no_bytes() {
    let mut audit = SelfAudit::default();
    let p = PathBuf::from("/definitely/not/here/password=TopSecretValue99");
    assert!(read_file_capped(&p, &mut audit).is_none());
    assert_eq!(audit.attempts.len(), 1);
    let a = &audit.attempts[0];
    assert_eq!(a.kind, AuditKind::File);
    assert_eq!(a.status, AuditStatus::Missing);
    assert_eq!(a.bytes, None);
    assert_eq!(a.seq, 1);
    // The secret-like path is redacted before storage.
    let wire = serde_json::to_string(a).unwrap();
    assert!(!wire.contains("TopSecretValue99"), "{wire}");
    assert!(wire.contains("masked"), "{wire}");
    // Only successful reads appear in the compact list.
    assert!(audit.files_read.is_empty());
}

#[test]
fn command_records_exit_code_and_duration() {
    let mut audit = SelfAudit::default();
    let inj: Option<CmdInjector> = Some(Box::new(|_, _| Some("Linux".into())));
    let out = run_command("uname", &["-s"], 1000, &mut audit, &inj).unwrap();
    assert_eq!(out, "Linux");
    let a = &audit.attempts[0];
    assert_eq!(a.kind, AuditKind::Command);
    assert_eq!(a.status, AuditStatus::Ok);
    assert_eq!(a.exit_code, Some(0));
    assert!(a.duration_ms.is_some());
    assert_eq!(a.bytes, Some(5));
    assert!(!a.cached);
    assert_eq!(audit.commands, vec!["uname -s".to_string()]);
}

#[test]
fn rejected_command_is_never_spawned() {
    let mut audit = SelfAudit::default();
    // The injector panics if consulted: a denylisted command must be
    // refused before any spawn/injection.
    let inj: Option<CmdInjector> = Some(Box::new(|prog, _| panic!("must not spawn {prog}")));
    assert!(run_command("net", &["start", "Spooler"], 1000, &mut audit, &inj).is_none());
    assert_eq!(audit.attempts.len(), 1);
    assert_eq!(audit.attempts[0].status, AuditStatus::Rejected);
    assert!(audit.attempts[0].source.contains("net start Spooler"));
    assert!(audit.commands.is_empty());
}

#[test]
fn cache_hit_records_cached_and_preserves_original() {
    let mut ctx = fixture_ctx();
    assert!(ctx.read("/etc/login.defs").is_some());
    assert!(ctx.read("/etc/login.defs").is_some());
    // Compact list still logs the read once ...
    assert_eq!(ctx.audit.files_read.len(), 1);
    // ... but both attempts are present, the second flagged cached.
    assert_eq!(ctx.audit.attempts.len(), 2);
    assert_eq!(ctx.audit.attempts[0].status, AuditStatus::Ok);
    assert!(!ctx.audit.attempts[0].cached);
    assert_eq!(ctx.audit.attempts[1].status, AuditStatus::Cached);
    assert!(ctx.audit.attempts[1].cached);
    assert_eq!(ctx.audit.attempts[0].source, ctx.audit.attempts[1].source);
}

fn toy_tc(id: &'static str) -> Testcase {
    Testcase {
        id,
        title: "toy",
        description: "toy check",
        impact: "toy impact",
        recommendation: "toy rec",
        severity: Severity::Medium,
        category: "Test",
        references: &[],
    }
}

fn evidence_check(ctx: &mut ScanContext) -> CheckOutcome {
    let block = hbs_extractor::checks::evidence_at(ctx, "/etc/login.defs", "PASS_MAX_DAYS");
    let o = hbs_extractor::checks::nok(
        "PASS_MAX_DAYS is 90".into(),
        "/etc/login.defs".into(),
        "cat /etc/login.defs".into(),
    );
    hbs_extractor::checks::with_block(o, block)
}

fn degraded_check(_ctx: &mut ScanContext) -> CheckOutcome {
    hbs_extractor::checks::degraded("value absent on this host")
}

#[test]
fn assembled_report_carries_attempts_missing_data_log_and_evidence() {
    let mut ctx = fixture_ctx();
    let mut reg: Vec<RegisteredCheck> = Vec::new();
    reg.push(RegisteredCheck {
        tc: toy_tc("TOY-EVIDENCE"),
        applies: |_| true,
        admin: false,
        run: evidence_check,
    });
    reg.push(RegisteredCheck {
        tc: toy_tc("TOY-DEGRADED"),
        applies: |_| true,
        admin: false,
        run: degraded_check,
    });
    let results = run_all(&reg, &mut ctx);
    let audit = std::mem::take(&mut ctx.audit);

    let rep = build(
        json!({
            "platform": "Linux",
            "arch": "x86_64",
            "environment": "BareMetal",
            "hypervisor": null,
            "environmentSignals": ["bare metal (explicit)"],
            "peakRssKb": 2048,
            "catalogFingerprint": "fnv1a64:deadbeefdeadbeef",
            "phaseDurationsMs": { "metadata": 11, "checks": 29 },
        }),
        json!({ "_collection": { "attempts": [] } }),
        results,
        audit,
        std::time::UNIX_EPOCH,
        42,
        "0.1.0-test",
    );
    let v = serde_json::to_value(&rep).unwrap();

    // selfAudit.attempts exists and is linked to the evidence finding.
    let attempts = v["selfAudit"]["attempts"].as_array().unwrap();
    assert!(!attempts.is_empty(), "{v}");
    assert!(
        attempts
            .iter()
            .any(|a| a["evidenceRef"] == "TOY-EVIDENCE:1"),
        "no back-reference: {attempts:?}"
    );

    // The locatable non-compliant result carries its evidence block.
    let blocks = v["results"][0]["evidenceBlocks"].as_array().unwrap();
    assert_eq!(blocks[0]["line"], 1);
    assert_eq!(blocks[0]["path"], "/etc/login.defs");

    // diagnostics.missingData surfaces the degraded check.
    let md = v["diagnostics"]["missingData"].as_array().unwrap();
    assert!(
        md.iter()
            .any(|m| m["checkId"] == "TOY-DEGRADED" && m["status"] == "DegradedPartial"),
        "{md:?}"
    );

    // diagnostics.log is a bounded, CLI-style array.
    let log = v["diagnostics"]["log"].as_array().unwrap();
    assert!(log.len() >= 4, "{log:?}");
    assert!(log
        .iter()
        .any(|l| l.as_str().unwrap_or("").contains("scan duration")));
    assert!(log
        .iter()
        .any(|l| l.as_str().unwrap_or("").contains("TOY-DEGRADED")));

    // diagnostics environment/privilege/phase/timing metadata.
    assert_eq!(v["diagnostics"]["extractorVersion"], "0.1.0-test");
    assert_eq!(v["diagnostics"]["scanDurationMs"], 42);
    assert_eq!(v["diagnostics"]["peakRssKb"], 2048);
    assert_eq!(
        v["diagnostics"]["catalogFingerprint"],
        "fnv1a64:deadbeefdeadbeef"
    );
    assert_eq!(v["diagnostics"]["phaseDurationsMs"]["checks"], 29);
    assert_eq!(v["diagnostics"]["environment"]["kind"], "BareMetal");

    // And the whole document still serializes (this is what gets sealed).
    let doc = serde_json::to_vec(&rep).unwrap();
    assert!(doc.len() > 100);
}

#[test]
fn secrets_in_paths_args_and_outcomes_never_reach_report_json() {
    let mut audit = SelfAudit::default();

    // Secret in a file path (missing read).
    let p = PathBuf::from("/srv/app/password=PathSecret123");
    assert!(read_file_capped(&p, &mut audit).is_none());

    // Secret in command arguments (allowlisted `stat`; injected output).
    let inj: Option<CmdInjector> = Some(Box::new(|_, _| Some("ok".into())));
    let _ = run_command(
        "stat",
        &["-c", "token=CmdSecret456", "/etc/passwd"],
        1000,
        &mut audit,
        &inj,
    );

    // Secret-like outcome/note stored through the public choke point.
    let idx = audit.begin_attempt(AuditKind::Command, "openssl version");
    audit.finish_attempt(idx, |a| {
        a.status = AuditStatus::Ok;
        a.outcome = "token=OutcomeSecret789".into();
        a.note = Some("apikey=NoteSecret000".into());
    });

    let rep = build(
        json!({}),
        json!({}),
        vec![],
        audit,
        std::time::UNIX_EPOCH,
        0,
        "v",
    );
    let doc = serde_json::to_string(&rep).unwrap();
    for secret in [
        "PathSecret123",
        "CmdSecret456",
        "OutcomeSecret789",
        "NoteSecret000",
    ] {
        assert!(
            !doc.contains(secret),
            "secret {secret} survived redaction: {doc}"
        );
    }
}
