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

/// Who ran the check and with what privileges — recorded per testcase
/// so every finding carries its own trust context.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunContext {
    pub user: String,
    pub uid: Option<u32>,
    pub elevated: bool,
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
/// transparency evidence).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SelfAudit {
    pub commands: Vec<String>,
    pub files_read: Vec<String>,
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
}
