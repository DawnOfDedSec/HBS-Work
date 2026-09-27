//! Core data model: severities, statuses, testcase definitions, per-run
//! results, and the sealed report's JSON shape. Everything the engine,
//! checks, and report assembly pass around lives here.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl Severity {
    /// Risk-score weight per the spec's metrics model.
    pub fn weight(self) -> u32 {
        match self {
            Severity::Critical => 10,
            Severity::High => 6,
            Severity::Medium => 3,
            Severity::Low => 1,
            Severity::Informational => 0,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "Critical",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
            Severity::Informational => "Informational",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Status {
    Compliant,
    NonCompliant,
    NotApplicable,
    Error,
    DegradedPartial,
}

/// Static definition of one testcase: identical text on every run.
#[derive(Clone, Debug)]
pub struct Testcase {
    pub id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub impact: &'static str,
    pub recommendation: &'static str,
    pub severity: Severity,
    pub category: &'static str,
    pub references: &'static [&'static str],
}

/// One alternative evidence source attempt, in the order tried.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FallbackAttempt {
    pub source: String,
    pub outcome: String,
}

/// Nessus-style pinpoint evidence: the file path (rendered as a header
/// above the block), 1-based line and column where the issue starts,
/// and the surrounding context window (target line ±3, already
/// redacted extractor-side).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceBlock {
    pub path: String,
    pub line: u32,
    pub col: u32,
    pub context: Vec<String>,
    pub target_index: u32,
    /// stat metadata of the evidence file at check time (null when
    /// unknown): mode bits, owner uid/gid (unix).
    pub file_mode: Option<u32>,
    pub file_uid: Option<u32>,
    pub file_gid: Option<u32>,
}

/// Who ran the check and with what privileges - recorded per testcase
/// so every finding carries its own trust context.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunContext {
    pub user: String,
    pub uid: Option<u32>,
    pub elevated: bool,
}

/// Which read-only evidence channel an audit attempt used. Serialized
/// lowercase (`file`, `command`, `registry`, `api`) so the sealed log is
/// easy to filter from the dashboard.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditKind {
    File,
    Command,
    Registry,
    Api,
}

/// Terminal classification for one audit attempt (lowercase in JSON).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditStatus {
    /// Completed and produced usable output.
    Ok,
    /// Source does not exist.
    Missing,
    /// Access refused by the OS (permission denied).
    Denied,
    /// Command exceeded its wall-clock budget.
    Timeout,
    /// Refused by the allowlist before any open/spawn.
    Rejected,
    /// Command spawned but exited non-zero.
    NonZero,
    /// Source returned output the collector could not parse.
    Malformed,
    /// Served from the per-run read cache.
    Cached,
    /// Unexpected internal failure.
    Error,
}

/// Cap on structured audit attempts so a hostile target cannot balloon
/// the sealed report by inviting unbounded reads/spawns.
pub const MAX_AUDIT_ATTEMPTS: usize = 5000;
/// Cap on recorded audit warnings.
pub const MAX_AUDIT_WARNINGS: usize = 200;
/// Per-string cap (chars) for anything stored in the structured audit.
pub const MAX_AUDIT_STRING: usize = 512;

/// One structured read/exec attempt: what was tried, how it ended, and
/// which finding (if any) it backs. Every string is redacted and capped
/// before storage; `seq` is 1-based and monotonic in collection order.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditAttempt {
    pub seq: u32,
    pub kind: AuditKind,
    pub source: String,
    pub outcome: String,
    pub status: AuditStatus,
    pub exit_code: Option<i32>,
    pub bytes: Option<u64>,
    pub duration_ms: Option<u64>,
    pub cached: bool,
    pub note: Option<String>,
    /// `<checkId>:<line>` back-reference when this attempt produced an
    /// evidence block for a finding.
    pub evidence_ref: Option<String>,
}

/// Redact then char-safely truncate a string for structured-audit storage.
pub fn bounded_redact(s: &str) -> String {
    let redacted = crate::redact::redact(s);
    if redacted.chars().count() <= MAX_AUDIT_STRING {
        return redacted;
    }
    let cut: String = redacted
        .chars()
        .take(MAX_AUDIT_STRING.saturating_sub(1))
        .collect();
    format!("{cut}\u{2026}")
}

/// What a check fn returns for the engine to fold into a CheckResult.
#[derive(Clone, Debug)]
pub struct CheckOutcome {
    pub status: Status,
    pub evidence: String,
    pub location: String,
    pub repro: String,
    pub recommendation_override: Option<String>,
    pub degraded_reason: Option<String>,
    pub fallback_log: Vec<FallbackAttempt>,
    pub evidence_blocks: Vec<EvidenceBlock>,
}

/// Signature every check function implements.
pub type CheckFn = fn(&mut crate::context::ScanContext) -> CheckOutcome;

/// One catalog entry: static testcase definition + applicability
/// predicate + the check itself + whether it requires admin rights.
/// Admin-only checks run ONLY when elevated; otherwise they are
/// skipped with an explicit "requires elevation" reason (never fail,
/// never silently downgrade).
#[derive(Clone)]
pub struct RegisteredCheck {
    pub tc: Testcase,
    pub applies: fn(&crate::platform::PlatformInfo) -> bool,
    pub admin: bool,
    pub run: CheckFn,
}

/// Full per-testcase result row as stored in the sealed report.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckResult {
    pub id: String,
    pub title: String,
    pub status: Status,
    pub severity: Severity,
    pub category: String,
    pub description: String,
    pub impact: String,
    pub recommendation: String,
    pub references: Vec<String>,
    pub evidence: String,
    pub location: String,
    pub repro: String,
    pub degraded_reason: Option<String>,
    pub fallback_log: Vec<FallbackAttempt>,
    pub evidence_blocks: Vec<EvidenceBlock>,
    pub run_context: RunContext,
    pub duration_ms: u64,
}

/// Every command executed and file read during the scan (blue-team
/// transparency evidence). `commands`/`files_read` are the compact
/// compatibility lists (successful operations only); `attempts` is the
/// complete structured trail including misses, denials, cache hits and
/// allowlist refusals.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SelfAudit {
    pub commands: Vec<String>,
    pub files_read: Vec<String>,
    pub attempts: Vec<AuditAttempt>,
    pub warnings: Vec<String>,
}

impl SelfAudit {
    /// Record the *start* of an attempt, before any open/spawn/validation.
    /// Returns the index to hand to [`Self::finish_attempt`]; `None` once
    /// the attempt cap is reached (a redacted warning is recorded once).
    pub fn begin_attempt(&mut self, kind: AuditKind, source: &str) -> Option<usize> {
        if self.attempts.len() >= MAX_AUDIT_ATTEMPTS {
            self.warn("audit attempt cap reached; further attempts omitted");
            return None;
        }
        let seq = self.attempts.len() as u32 + 1;
        self.attempts.push(AuditAttempt {
            seq,
            kind,
            source: bounded_redact(source),
            outcome: String::new(),
            status: AuditStatus::Error,
            exit_code: None,
            bytes: None,
            duration_ms: None,
            cached: false,
            note: None,
            evidence_ref: None,
        });
        Some(self.attempts.len() - 1)
    }

    /// Update a previously begun attempt. Redacts `outcome`/`note`/
    /// `evidence_ref` at the same choke point. No-op on `None`/cap.
    pub fn finish_attempt<F: FnOnce(&mut AuditAttempt)>(&mut self, idx: Option<usize>, f: F) {
        if let Some(a) = idx.and_then(|i| self.attempts.get_mut(i)) {
            f(a);
            let outcome = bounded_redact(&a.outcome);
            a.outcome = outcome;
            if let Some(note) = a.note.clone() {
                a.note = Some(bounded_redact(&note));
            }
            if let Some(ev) = a.evidence_ref.clone() {
                a.evidence_ref = Some(bounded_redact(&ev));
            }
        }
    }

    /// Append a redacted, deduplicated warning (bounded).
    pub fn warn(&mut self, msg: &str) {
        if self.warnings.len() >= MAX_AUDIT_WARNINGS {
            return;
        }
        let r = bounded_redact(msg);
        if !self.warnings.contains(&r) {
            self.warnings.push(r);
        }
    }
}

/// Aggregate counts for the report summary block.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub compliant: u32,
    pub non_compliant: u32,
    pub not_applicable: u32,
    pub error: u32,
    pub degraded: u32,
    pub informational: u32,
}

/// One result that could not be fully assessed, surfaced for triage.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MissingData {
    pub check_id: String,
    pub status: String,
    pub reason: Option<String>,
    pub exhausted_sources: Vec<String>,
}

/// Diagnostics block: everything an analyst needs to explain a missing
/// value without re-running the scan, all inside the sealed report.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Diagnostics {
    /// Environment kind, hypervisor, and independent detection signals.
    pub environment: serde_json::Value,
    /// Stable fingerprint of the check catalog, when supplied.
    pub catalog_fingerprint: Option<String>,
    pub extractor_version: String,
    /// Requested/granted/refused/not-needed privilege state.
    pub privilege: serde_json::Value,
    pub peak_rss_kb: u64,
    pub scan_duration_ms: u64,
    /// Per-phase wall-clock durations (metadata, checks, …).
    pub phase_durations_ms: serde_json::Value,
    /// Every DegradedPartial / NotApplicable / Error result with its
    /// reason and the list of exhausted fallback sources.
    pub missing_data: Vec<MissingData>,
    /// `metadata._collection.attempts`, carried here for one-stop triage.
    pub metadata_attempts: serde_json::Value,
    /// Human-readable, bounded scan log (CLI-style lines + preamble).
    pub log: Vec<String>,
}

/// The complete sealed-report JSON document.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub schema_version: u16,
    pub scan: serde_json::Value,
    pub metadata: serde_json::Value,
    pub results: Vec<CheckResult>,
    pub summary: Summary,
    pub self_audit: SelfAudit,
    pub diagnostics: Diagnostics,
}
