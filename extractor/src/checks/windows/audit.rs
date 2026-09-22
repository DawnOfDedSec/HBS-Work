//! WIN-AU: Windows audit policy checks using read-only evidence.
//!
//! Evaluated strictly via read-only `auditpol /get ... /r` queries.
//! Never exports files or calls `secedit /export`.
//! Missing or unprivileged queries degrade gracefully to `DegradedPartial`.

use crate::checks::{degraded, nok, ok};
use crate::context::ScanContext;
use crate::model::{CheckOutcome, FallbackAttempt, RegisteredCheck};
use crate::platform::Os;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditRequirement {
    SuccessAndFailure,
    Success,
    Failure,
}

impl AuditRequirement {
    pub fn name(self) -> &'static str {
        match self {
            AuditRequirement::SuccessAndFailure => "Success and Failure",
            AuditRequirement::Success => "Success",
            AuditRequirement::Failure => "Failure",
        }
    }

    pub fn is_satisfied_by(self, inclusion: &str) -> bool {
        let lower = inclusion.to_ascii_lowercase();
        if lower.contains("no auditing")
            || lower.contains("keine überwachung")
            || lower.contains("aucun audit")
        {
            return false;
        }
        match self {
            AuditRequirement::SuccessAndFailure => {
                let has_success = lower.contains("success")
                    || lower.contains("erfolg")
                    || lower.contains("succès");
                let has_failure = lower.contains("failure")
                    || lower.contains("fehler")
                    || lower.contains("échec");
                (has_success && has_failure) || lower == "3"
            }
            AuditRequirement::Success => {
                lower.contains("success")
                    || lower.contains("erfolg")
                    || lower.contains("succès")
                    || lower == "1"
                    || lower == "3"
            }
            AuditRequirement::Failure => {
                lower.contains("failure")
                    || lower.contains("fehler")
                    || lower.contains("échec")
                    || lower == "2"
                    || lower == "3"
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct AuditPolicyRecord {
    pub subcategory: String,
    pub guid: String,
    pub inclusion: String,
    pub exclusion: String,
}

#[derive(Clone, Copy, Debug)]
pub struct AuditCheckDef {
    pub id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub rationale: &'static str,
    pub remediation: &'static str,
    pub severity: crate::model::Severity,
    pub benchmarks: &'static [&'static str],
    pub subcategory: &'static str,
    pub guid: &'static str,
    pub requirement: AuditRequirement,
}

pub const AUDIT_CHECKS: &[AuditCheckDef] = &[
    AuditCheckDef {
        id: "WIN-AU-001",
        title: "Audit Logon",
        description: "Logon events record successful and failed authentication attempts.",
        rationale: "Without logon auditing, credential brute-forcing, password spraying, and unauthorized access cannot be detected.",
        remediation: "Set 'Audit Logon' subcategory to 'Success and Failure' via auditpol or group policy.",
        severity: crate::model::Severity::Medium,
        benchmarks: &["CIS 17.5.1"],
        subcategory: "Logon",
        guid: "{0CCE9215-69AE-11D9-BED3-505054503030}",
        requirement: AuditRequirement::SuccessAndFailure,
    },
    AuditCheckDef {
        id: "WIN-AU-002",
        title: "Audit Logoff",
        description: "Logoff events track user session termination.",
        rationale: "Tracking session end times helps reconstruct user activity timelines during incident analysis.",
        remediation: "Set 'Audit Logoff' subcategory to 'Success' via auditpol or group policy.",
        severity: crate::model::Severity::Low,
        benchmarks: &["CIS 17.5.2"],
        subcategory: "Logoff",
        guid: "{0CCE9216-69AE-11D9-BED3-505054503030}",
        requirement: AuditRequirement::Success,
    },
    AuditCheckDef {
        id: "WIN-AU-003",
        title: "Audit Account Logon",
        description: "Credential validation audits tickets and authentication requests on domain controllers and local SAM.",
        rationale: "Credential validation is essential for detecting Kerberoasting, pass-the-hash, and invalid authentication attempts.",
        remediation: "Set 'Audit Credential Validation' subcategory to 'Success and Failure'.",
        severity: crate::model::Severity::High,
        benchmarks: &["CIS 17.1.1"],
        subcategory: "Credential Validation",
        guid: "{0CCE923F-69AE-11D9-BED3-505054503030}",
        requirement: AuditRequirement::SuccessAndFailure,
    },
    AuditCheckDef {
        id: "WIN-AU-004",
        title: "Audit User Account Management",
        description: "User account management tracks user creation, modification, password changes, and account status.",
        rationale: "Rogue user creation and unauthorized account manipulation are key indicators of compromise.",
        remediation: "Set 'Audit User Account Management' subcategory to 'Success and Failure'.",
        severity: crate::model::Severity::High,
        benchmarks: &["CIS 17.2.1"],
        subcategory: "User Account Management",
        guid: "{0CCE9235-69AE-11D9-BED3-505054503030}",
        requirement: AuditRequirement::SuccessAndFailure,
    },
    AuditCheckDef {
        id: "WIN-AU-005",
        title: "Audit Security Group Management",
        description: "Security group management tracks additions, removals, and changes to privileged and local security groups.",
        rationale: "Adversaries add compromised accounts to privileged groups to maintain persistence and escalate privilege.",
        remediation: "Set 'Audit Security Group Management' subcategory to 'Success and Failure'.",
        severity: crate::model::Severity::High,
        benchmarks: &["CIS 17.2.2"],
        subcategory: "Security Group Management",
        guid: "{0CCE9237-69AE-11D9-BED3-505054503030}",
        requirement: AuditRequirement::SuccessAndFailure,
    },
    AuditCheckDef {
        id: "WIN-AU-006",
        title: "Audit Audit Policy Change",
        description: "Policy change events log modifications to audit configuration and system audit policies.",
        rationale: "Attackers attempt to disable audit logging or modify policy to conceal their activity.",
        remediation: "Set 'Audit Audit Policy Change' subcategory to 'Success and Failure'.",
        severity: crate::model::Severity::High,
        benchmarks: &["CIS 17.6.1"],
        subcategory: "Audit Policy Change",
        guid: "{0CCE922F-69AE-11D9-BED3-505054503030}",
        requirement: AuditRequirement::SuccessAndFailure,
    },
    AuditCheckDef {
        id: "WIN-AU-007",
        title: "Audit Sensitive Privilege Use",
        description: "Sensitive privilege use audits the exercise of sensitive user rights such as TakeOwnership or Debug.",
        rationale: "Failed sensitive privilege use reveals attempts to exercise unauthorized elevated capabilities.",
        remediation: "Set 'Audit Sensitive Privilege Use' subcategory to 'Failure'.",
        severity: crate::model::Severity::Medium,
        benchmarks: &["CIS 17.7.1"],
        subcategory: "Sensitive Privilege Use",
        guid: "{0CCE9228-69AE-11D9-BED3-505054503030}",
        requirement: AuditRequirement::Failure,
    },
    AuditCheckDef {
        id: "WIN-AU-008",
        title: "Audit Process Creation",
        description: "Process creation audits each new process invoked on the operating system.",
        rationale: "Process creation logs are fundamental forensic telemetry for malware execution and living-off-the-land techniques.",
        remediation: "Set 'Audit Process Creation' subcategory to 'Success'.",
        severity: crate::model::Severity::Medium,
        benchmarks: &["CIS 17.8.1"],
        subcategory: "Process Creation",
        guid: "{0CCE922B-69AE-11D9-BED3-505054503030}",
        requirement: AuditRequirement::Success,
    },
    AuditCheckDef {
        id: "WIN-AU-009",
        title: "Audit File Share Access",
        description: "File share auditing logs access to SMB and network file shares.",
        rationale: "Failed file share access indicates lateral movement or enumeration attempts across shares.",
        remediation: "Set 'Audit File Share' subcategory to 'Failure'.",
        severity: crate::model::Severity::Low,
        benchmarks: &["CIS 17.4.1"],
        subcategory: "File Share",
        guid: "{0CCE9224-69AE-11D9-BED3-505054503030}",
        requirement: AuditRequirement::Failure,
    },
    AuditCheckDef {
        id: "WIN-AU-010",
        title: "Audit Security System Extension",
        description: "Security system extension audits loading of SSP/AP security packages and LSA extensions.",
        rationale: "Adversaries install malicious SSPs to dump credentials and intercept logon data.",
        remediation: "Set 'Audit Security System Extension' subcategory to 'Success and Failure'.",
        severity: crate::model::Severity::Medium,
        benchmarks: &["CIS 17.9.1"],
        subcategory: "Security System Extension",
        guid: "{0CCE9211-69AE-11D9-BED3-505054503030}",
        requirement: AuditRequirement::SuccessAndFailure,
    },
];

pub fn register(reg: &mut Vec<RegisteredCheck>) {
    use crate::check;
    check!(
        reg,
        "WIN-AU-001",
        "Audit Logon",
        "Logon events record successful and failed authentication attempts.",
        "Without logon auditing, credential brute-forcing, password spraying, and unauthorized access cannot be detected.",
        "Set 'Audit Logon' subcategory to 'Success and Failure' via auditpol or group policy.",
        Medium,
        "Audit Policy",
        &["CIS 17.5.1"],
        win,
        |ctx| audit_check(ctx, &AUDIT_CHECKS[0])
    );
    check!(
        reg,
        "WIN-AU-002",
        "Audit Logoff",
        "Logoff events track user session termination.",
        "Tracking session end times helps reconstruct user activity timelines during incident analysis.",
        "Set 'Audit Logoff' subcategory to 'Success' via auditpol or group policy.",
        Low,
        "Audit Policy",
        &["CIS 17.5.2"],
        win,
        |ctx| audit_check(ctx, &AUDIT_CHECKS[1])
    );
    check!(
        reg,
        "WIN-AU-003",
        "Audit Account Logon",
        "Credential validation audits tickets and authentication requests on domain controllers and local SAM.",
        "Credential validation is essential for detecting Kerberoasting, pass-the-hash, and invalid authentication attempts.",
        "Set 'Audit Credential Validation' subcategory to 'Success and Failure'.",
        High,
        "Audit Policy",
        &["CIS 17.1.1"],
        win,
        |ctx| audit_check(ctx, &AUDIT_CHECKS[2])
    );
    check!(
        reg,
        "WIN-AU-004",
        "Audit User Account Management",
        "User account management tracks user creation, modification, password changes, and account status.",
        "Rogue user creation and unauthorized account manipulation are key indicators of compromise.",
        "Set 'Audit User Account Management' subcategory to 'Success and Failure'.",
        High,
        "Audit Policy",
        &["CIS 17.2.1"],
        win,
        |ctx| audit_check(ctx, &AUDIT_CHECKS[3])
    );
    check!(
        reg,
        "WIN-AU-005",
        "Audit Security Group Management",
        "Security group management tracks additions, removals, and changes to privileged and local security groups.",
        "Adversaries add compromised accounts to privileged groups to maintain persistence and escalate privilege.",
        "Set 'Audit Security Group Management' subcategory to 'Success and Failure'.",
        High,
        "Audit Policy",
        &["CIS 17.2.2"],
        win,
        |ctx| audit_check(ctx, &AUDIT_CHECKS[4])
    );
    check!(
        reg,
        "WIN-AU-006",
        "Audit Audit Policy Change",
        "Policy change events log modifications to audit configuration and system audit policies.",
        "Attackers attempt to disable audit logging or modify policy to conceal their activity.",
        "Set 'Audit Audit Policy Change' subcategory to 'Success and Failure'.",
        High,
        "Audit Policy",
        &["CIS 17.6.1"],
        win,
        |ctx| audit_check(ctx, &AUDIT_CHECKS[5])
    );
    check!(
        reg,
        "WIN-AU-007",
        "Audit Sensitive Privilege Use",
        "Sensitive privilege use audits the exercise of sensitive user rights such as TakeOwnership or Debug.",
        "Failed sensitive privilege use reveals attempts to exercise unauthorized elevated capabilities.",
        "Set 'Audit Sensitive Privilege Use' subcategory to 'Failure'.",
        Medium,
        "Audit Policy",
        &["CIS 17.7.1"],
        win,
        |ctx| audit_check(ctx, &AUDIT_CHECKS[6])
    );
    check!(
        reg,
        "WIN-AU-008",
        "Audit Process Creation",
        "Process creation audits each new process invoked on the operating system.",
        "Process creation logs are fundamental forensic telemetry for malware execution and living-off-the-land techniques.",
        "Set 'Audit Process Creation' subcategory to 'Success'.",
        Medium,
        "Audit Policy",
        &["CIS 17.8.1"],
        win,
        |ctx| audit_check(ctx, &AUDIT_CHECKS[7])
    );
    check!(
        reg,
        "WIN-AU-009",
        "Audit File Share Access",
        "File share auditing logs access to SMB and network file shares.",
        "Failed file share access indicates lateral movement or enumeration attempts across shares.",
        "Set 'Audit File Share' subcategory to 'Failure'.",
        Low,
        "Audit Policy",
        &["CIS 17.4.1"],
        win,
        |ctx| audit_check(ctx, &AUDIT_CHECKS[8])
    );
    check!(
        reg,
        "WIN-AU-010",
        "Audit Security System Extension",
        "Security system extension audits loading of SSP/AP security packages and LSA extensions.",
        "Adversaries install malicious SSPs to dump credentials and intercept logon data.",
        "Set 'Audit Security System Extension' subcategory to 'Success and Failure'.",
        Medium,
        "Audit Policy",
        &["CIS 17.9.1"],
        win,
        |ctx| audit_check(ctx, &AUDIT_CHECKS[9])
    );
}

fn win(p: &crate::platform::PlatformInfo) -> bool {
    p.os == Os::Windows
}

fn split_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for ch in line.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                fields.push(current.trim().trim_matches('"').to_string());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    fields.push(current.trim().trim_matches('"').to_string());
    fields
}

pub fn parse_auditpol_csv(raw: &str) -> Vec<AuditPolicyRecord> {
    let mut records = Vec::new();
    let mut lines = raw.lines().map(str::trim).filter(|l| !l.is_empty());

    let first_line = match lines.next() {
        Some(l) => l,
        None => return records,
    };

    let header = split_csv_line(first_line);
    let subcat_idx = header
        .iter()
        .position(|h| h.eq_ignore_ascii_case("Subcategory"));
    let guid_idx = header
        .iter()
        .position(|h| h.eq_ignore_ascii_case("Subcategory GUID") || h.eq_ignore_ascii_case("GUID"));
    let incl_idx = header
        .iter()
        .position(|h| h.eq_ignore_ascii_case("Inclusion Setting") || h.contains("Setting"));

    // Check if first line was actually a data line (no recognizable header words)
    let is_header = subcat_idx.is_some() || guid_idx.is_some() || incl_idx.is_some()
        || first_line.to_ascii_lowercase().contains("machine")
        || first_line.to_ascii_lowercase().contains("computer");

    let parse_row = |fields: &[String], subcat_col: usize, guid_col: usize, incl_col: usize| {
        let subcat = fields.get(subcat_col)?.trim().to_string();
        let guid = fields.get(guid_col)?.trim().to_string();
        let inclusion = fields.get(incl_col)?.trim().to_string();
        let exclusion = fields.get(incl_col + 1).cloned().unwrap_or_default();
        Some(AuditPolicyRecord {
            subcategory: subcat,
            guid,
            inclusion,
            exclusion,
        })
    };

    // Determine default positional indices if header did not match English keywords
    let (default_subcat, default_guid, default_incl) = if header.len() >= 8 {
        (4, 5, 6)
    } else {
        (2, 3, 4)
    };

    let subcat_col = subcat_idx.unwrap_or(default_subcat);
    let guid_col = guid_idx.unwrap_or(default_guid);
    let incl_col = incl_idx.unwrap_or(default_incl);

    if !is_header {
        if let Some(record) = parse_row(&header, subcat_col, guid_col, incl_col) {
            records.push(record);
        }
    }

    for line in lines {
        let fields = split_csv_line(line);
        if let Some(record) = parse_row(&fields, subcat_col, guid_col, incl_col) {
            records.push(record);
        }
    }

    records
}

fn normalize_guid(guid: &str) -> String {
    guid.trim()
        .trim_matches(|c| c == '{' || c == '}')
        .to_ascii_uppercase()
}

fn matches_check(record: &AuditPolicyRecord, def: &AuditCheckDef) -> bool {
    let clean_record_guid = normalize_guid(&record.guid);
    let clean_def_guid = normalize_guid(def.guid);

    if !clean_record_guid.is_empty() && clean_record_guid == clean_def_guid {
        return true;
    }

    record
        .subcategory
        .trim()
        .eq_ignore_ascii_case(def.subcategory)
}

fn audit_check(ctx: &mut ScanContext, def: &AuditCheckDef) -> CheckOutcome {
    let mut attempts = Vec::new();

    // 1. Direct subcategory query by name
    let subcat_arg = format!("/subcategory:{}", def.subcategory);
    if let Some(raw) = ctx.cmd("auditpol", &["/get", &subcat_arg, "/r"]) {
        attempts.push(FallbackAttempt {
            source: format!("auditpol /get {subcat_arg} /r"),
            outcome: "read auditpol output".into(),
        });
        let records = parse_auditpol_csv(&raw);
        if let Some(record) = records.iter().find(|r| matches_check(r, def)) {
            return evaluate_record(record, def, attempts);
        }
    } else {
        attempts.push(FallbackAttempt {
            source: format!("auditpol /get {subcat_arg} /r"),
            outcome: "unavailable or privilege not held".into(),
        });
    }

    // 2. Direct subcategory query by GUID
    let guid_arg = format!("/subcategory:{}", def.guid);
    if let Some(raw) = ctx.cmd("auditpol", &["/get", &guid_arg, "/r"]) {
        attempts.push(FallbackAttempt {
            source: format!("auditpol /get {guid_arg} /r"),
            outcome: "read auditpol output".into(),
        });
        let records = parse_auditpol_csv(&raw);
        if let Some(record) = records.iter().find(|r| matches_check(r, def)) {
            return evaluate_record(record, def, attempts);
        }
    } else {
        attempts.push(FallbackAttempt {
            source: format!("auditpol /get {guid_arg} /r"),
            outcome: "unavailable or privilege not held".into(),
        });
    }

    // 3. Category wildcard query fallback
    if let Some(raw) = ctx.cmd("auditpol", &["/get", "/category:*", "/r"]) {
        attempts.push(FallbackAttempt {
            source: "auditpol /get /category:* /r".into(),
            outcome: "read auditpol category dump".into(),
        });
        let records = parse_auditpol_csv(&raw);
        if let Some(record) = records.iter().find(|r| matches_check(r, def)) {
            return evaluate_record(record, def, attempts);
        }
    } else {
        attempts.push(FallbackAttempt {
            source: "auditpol /get /category:* /r".into(),
            outcome: "unavailable or privilege not held".into(),
        });
    }

    // Degraded fallback: never return Error
    let mut outcome = degraded("audit policy unavailable or required privilege not held");
    outcome.fallback_log = attempts;
    outcome
}

fn evaluate_record(
    record: &AuditPolicyRecord,
    def: &AuditCheckDef,
    attempts: Vec<FallbackAttempt>,
) -> CheckOutcome {
    let satisfies = def.requirement.is_satisfied_by(&record.inclusion);
    let expected = def.requirement.name();
    let actual = &record.inclusion;

    let mut outcome = if satisfies {
        ok(
            format!("Audit setting for '{}' is '{}'", def.subcategory, actual),
            format!("auditpol:{}", def.subcategory),
            format!("auditpol /get /subcategory:\"{}\" /r", def.subcategory),
        )
    } else {
        nok(
            format!(
                "Audit setting for '{}' is '{}' (expected '{}')",
                def.subcategory, actual, expected
            ),
            format!("auditpol:{}", def.subcategory),
            format!("auditpol /get /subcategory:\"{}\" /r", def.subcategory),
        )
    };

    outcome.fallback_log = attempts;
    outcome
}
