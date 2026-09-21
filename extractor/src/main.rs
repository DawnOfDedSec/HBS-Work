//! hbs-extractor CLI: parse args, read the issued keyslot, (offer)
//! elevation, run the read-only scan, seal the report, optionally push.

use clap::{ArgGroup, Parser};
use hbs_extractor::checks::register_all;
use hbs_extractor::context::ScanContext;
use hbs_extractor::crypto;
use hbs_extractor::engine::run_all;
use hbs_extractor::keyslot::{self, SlotData};
use hbs_extractor::metadata;
use hbs_extractor::model::{RegisteredCheck, Severity, Status};
use hbs_extractor::platform;
use hbs_extractor::report;
use serde_json::json;
use std::io::Write as _;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser, Debug)]
#[command(
    name = "hbs-extractor",
    version = VERSION,
    about = "HBS read-only configuration security extractor",
    group(ArgGroup::new("output").args(["out"]))
)]
struct Args {
    /// List every registered testcase and exit
    #[arg(long)]
    list_checks: bool,
    /// Run only these check IDs (comma-separated)
    #[arg(long, value_delimiter = ',')]
    only: Vec<String>,
    /// Run only this category
    #[arg(long)]
    category: Option<String>,
    /// Skip checks below this severity
    #[arg(long)]
    min_severity: Option<String>,
    /// Output path for the sealed report
    #[arg(long)]
    out: Option<String>,
    /// Also push the sealed report to this dashboard URL
    #[arg(long)]
    push: Option<String>,
    /// Do not attempt privilege elevation
    #[arg(long)]
    no_elevate: bool,
    /// Do not pause at the end (scripted runs)
    #[arg(long)]
    no_pause: bool,
    /// Suppress progress output
    #[arg(long)]
    quiet: bool,
    /// Internal: this process was relaunched elevated
    #[arg(long, hide = true)]
    elevated_child: bool,
    /// Debug builds only: synthetic slot so the loop runs without a
    /// dashboard-issued binary. Never compiled into release builds.
    #[arg(long, hide = true)]
    dev_insecure_key: Option<String>,
}

fn severity_from_str(s: &str) -> Option<Severity> {
    match s.to_lowercase().as_str() {
        "critical" => Some(Severity::Critical),
        "high" => Some(Severity::High),
        "medium" => Some(Severity::Medium),
        "low" => Some(Severity::Low),
        "informational" | "info" => Some(Severity::Informational),
        _ => None,
    }
}

fn severity_rank(s: Severity) -> u8 {
    match s {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Informational => 1,
    }
}

fn main() {
    let args = Args::parse();
    platform::lower_own_priority();

    if args.list_checks {
        let mut reg: Vec<RegisteredCheck> = Vec::new();
        register_all(&mut reg);
        for rc in &reg {
            println!("{:<14} {:<14} {:<14} {}", rc.tc.id, rc.tc.severity.as_str(), rc.tc.category, rc.tc.title);
        }
        return;
    }

    // 1. Keyslot: refuse to run when unissued or expired.
    let slot = resolve_slot(&args).unwrap_or_else(|msg| {
        eprintln!("hbs-extractor: {msg}");
        std::process::exit(2);
    });
    if let Err(e) = keyslot::check_expiry(&slot) {
        eprintln!("hbs-extractor: {e}");
        std::process::exit(2);
    }

    // 1b. Offer UAC elevation (never required; declined = degraded).
    if !args.elevated_child && hbs_extractor::elevate::request_relaunch(args.no_elevate) {
        return; // elevated child took over; parent exits quietly
    }

    // 2. Platform + privileges.
    let pinfo = platform::detect();
    let elevated = hbs_extractor::elevate::is_elevated();

    // 3. Registry + filters.
    let mut reg: Vec<RegisteredCheck> = Vec::new();
    register_all(&mut reg);
    let min_rank = args
        .min_severity
        .as_deref()
        .and_then(severity_from_str)
        .map(severity_rank);
    let reg: Vec<RegisteredCheck> = reg
        .into_iter()
        .filter(|rc| args.only.is_empty() || args.only.iter().any(|id| id == rc.tc.id))
        .filter(|rc| args.category.as_deref().map(|c| rc.tc.category == c).unwrap_or(true))
        .filter(|rc| min_rank.map(|r| severity_rank(rc.tc.severity) >= r).unwrap_or(true))
        .collect();
    if reg.is_empty() {
        eprintln!("hbs-extractor: no testcases match the given filters");
        std::process::exit(3);
    }

    // 4. Scan.
    let started = std::time::Instant::now();
    let started_at = std::time::SystemTime::now();
    let mut ctx = ScanContext::new(pinfo.clone(), elevated);
    let meta = metadata::collect(&mut ctx);
    let host_display = meta
        .get("hostname")
        .and_then(|v| v.as_str())
        .unwrap_or("host")
        .to_string();
    println!(
        "hbs-extractor {} — read-only scan of {} ({})",
        VERSION,
        host_display,
        if elevated { "elevated" } else { "degraded (no admin)" }
    );
    let mut results = run_all(&reg, &mut ctx);
    let audit = std::mem::take(&mut ctx.audit);
    if !args.quiet {
        for r in &results {
            println!("{}", cli_line(r));
        }
    }

    // 5. Report + seal.
    let hostname = meta.get("hostname").and_then(|v| v.as_str()).unwrap_or("host").to_string();
    let machine_id = meta.get("machine_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let scan_extra = json!({
        "extractorId": keyslot::hex_id(&slot.extractor_id),
        "campaignId": keyslot::hex_id(&slot.campaign_id),
        "keyId": slot.key_id,
        "machineId": machine_id,
        "hostname": hostname,
        "platform": format!("{:?}", pinfo.os),
        "osName": meta.get("os_name").cloned().unwrap_or(json!(null)),
        "osVersion": meta.get("os_version").cloned().unwrap_or(json!(null)),
        "arch": pinfo.arch,
        "privileged": elevated,
    });
    let rep = report::build(
        scan_extra,
        meta,
        std::mem::take(&mut results),
        audit,
        started_at,
        started.elapsed().as_millis() as u64,
        VERSION,
    );
    let doc = serde_json::to_vec(&rep).expect("report serializes");
    let envelope = crypto::seal(&doc, &slot.recipient_pub, slot.key_id, crypto::SUITE_CHACHA20POLY1305)
        .unwrap_or_else(|e| {
            eprintln!("hbs-extractor: sealing failed: {e}");
            std::process::exit(3);
        });

    let path = args.out.clone().unwrap_or_else(|| {
        let stamp = chrono_like_stamp();
        format!("hbs-report-{}-{}.hbs", hostname, stamp)
    });
    std::fs::write(&path, &envelope).unwrap_or_else(|e| {
        eprintln!("hbs-extractor: cannot write {path}: {e}");
        std::process::exit(3);
    });
    println!(
        "scan complete: {} compliant / {} failed / {} errors — sealed report: {path}",
        rep.summary.compliant, rep.summary.non_compliant, rep.summary.error
    );

    // 6. Optional push.
    if let Some(url) = &args.push {
        match push(url, &envelope, &slot) {
            Ok(status) => println!("pushed to {url}: {status}"),
            Err(e) => {
                eprintln!("push failed: {e}");
                std::process::exit(3);
            }
        }
    }

    pause_if_interactive(&args);
}

fn cli_line(r: &hbs_extractor::model::CheckResult) -> String {
    let icon = match r.status {
        Status::Compliant => "[ok]",
        Status::NonCompliant => "[FAIL]",
        Status::NotApplicable => "[n/a]",
        Status::Error => "[err]",
        Status::DegradedPartial => "[deg]",
    };
    format!("{} {:<14} {:<10} {}", icon, r.id, r.severity.as_str(), r.title)
}

fn resolve_slot(args: &Args) -> Result<SlotData, String> {
    #[cfg(debug_assertions)]
    if let Some(hexkey) = &args.dev_insecure_key {
        return dev_slot(hexkey);
    }
    keyslot::read_own_slot().map_err(|e| format!("keyslot: {e:#}"))
}

#[cfg(debug_assertions)]
fn dev_slot(hexkey: &str) -> Result<SlotData, String> {
    let bytes = hex::decode(hexkey).map_err(|e| format!("--dev-insecure-key: {e}"))?;
    let key: [u8; 32] = bytes.try_into().map_err(|_| "--dev-insecure-key: need 64 hex chars".to_string())?;
    Ok(SlotData {
        key_id: 1,
        campaign_id: [0x11; 16],
        extractor_id: [0x22; 16],
        expiry_unix: 4_102_444_800,
        issued_at_unix: 0,
        recipient_pub: key,
    })
}

fn push(url: &str, envelope: &[u8], slot: &SlotData) -> Result<u16, String> {
    let resp = ureq::post(url)
        .set("X-HBS-Extractor", &keyslot::hex_id(&slot.extractor_id))
        .send_bytes(envelope)
        .map_err(|e| e.to_string())?;
    Ok(resp.status())
}

fn chrono_like_stamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // YYYYmmddTHHMMSS from unix seconds (UTC) without a chrono dep:
    // days-since-epoch civil-date algorithm (Howard Hinnant).
    let days = now / 86400;
    let secs = now % 86400;
    let (y, m, d) = civil_from_days(days as i64);
    format!("{y:04}{m:02}{d:02}T{:02}{:02}{:02}", secs / 3600, (secs % 3600) / 60, secs % 60)
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn pause_if_interactive(args: &Args) {
    if args.no_pause || args.quiet {
        return;
    }
    if !console::Term::stdout().features().is_attended() {
        return;
    }
    print!("Press Enter to close…");
    let _ = std::io::stdout().flush();
    let _ = std::io::stdin().read_line(&mut String::new());
}
