//! hbs-extractor CLI: parse args, read the issued keyslot, (offer)
//! elevation, run the read-only scan, seal the report, optionally push.

use clap::{ArgGroup, Parser};
use hbs_extractor::checks::register_all;
use hbs_extractor::context::ScanContext;
use hbs_extractor::crypto;
use hbs_extractor::engine::run_all;
use hbs_extractor::keyslot::{self, SlotData};
use hbs_extractor::metadata;
use hbs_extractor::model::{RegisteredCheck, Severity};
use hbs_extractor::platform;
use hbs_extractor::report;
use serde_json::json;

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
    /// Read-only file containing the push token (mutually exclusive with
    /// the HBS_PUSH_TOKEN environment variable)
    #[arg(long)]
    push_token_file: Option<String>,
    /// Do not attempt privilege elevation
    #[arg(long)]
    no_elevate: bool,
    /// Request elevation (UAC prompt) for admin-only checks; the scan
    /// otherwise always runs unprivileged
    #[arg(long)]
    elevate: bool,
    /// Do not pause at the end (scripted runs)
    #[arg(long)]
    no_pause: bool,
    /// Suppress progress output
    #[arg(long)]
    quiet: bool,
    /// Service mode: sleep this many seconds between scans (requires --runs
    /// greater than 1 to be useful). A scan failure never stops the loop.
    #[arg(long)]
    interval: Option<u64>,
    /// Stop after this many scans (0 = run forever); default 1
    #[arg(long)]
    runs: Option<u32>,
    /// Internal: this process was relaunched elevated
    #[arg(long, hide = true)]
    elevated_child: bool,
    /// Debug builds only: synthetic slot so the loop runs without a
    /// dashboard-issued binary. Never compiled into release builds.
    #[arg(long, hide = true)]
    dev_insecure_key: Option<String>,
}

/// One scan attempt failed; the process exits with `code` in single-run mode
/// and keeps looping (unless it was the first scan) in service mode.
struct ScanFailure {
    code: i32,
    message: String,
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

/// Stable FNV-1a fingerprint of the (filtered) check catalog, so the
/// report can be tied to the exact testcase set that produced it.
fn catalog_fingerprint(reg: &[RegisteredCheck]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for rc in reg {
        let line = format!(
            "{}|{}|{}|{}",
            rc.tc.id,
            rc.tc.severity.as_str(),
            rc.tc.category,
            rc.tc.title
        );
        for b in line.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    format!("fnv1a64:{h:016x}")
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

    let runs = args.runs.unwrap_or(1);
    let interval = args.interval.unwrap_or(3600).max(1);
    // An elevated child performs exactly one scan; scheduling belongs to the
    // operator (Task Scheduler / systemd), not to a privileged daemon.
    let runs = if args.elevated_child { 1 } else { runs };

    for iteration in 0.. {
        if runs > 0 && iteration >= runs {
            break;
        }
        if iteration > 0 {
            if !args.quiet {
                eprintln!("hbs-extractor: next scan in {interval}s");
            }
            std::thread::sleep(std::time::Duration::from_secs(interval));
        }
        if let Err(failure) = run_once(&args, iteration == 0) {
            eprintln!("hbs-extractor: {}", failure.message);
            if iteration == 0 {
                std::process::exit(failure.code);
            }
            eprintln!("hbs-extractor: scan {} failed; the loop continues", iteration + 1);
        }
    }

    hbs_extractor::cli::pause_if_interactive(args.no_pause, args.quiet);
}

/// One complete scan → seal → write → (optional) push cycle.
fn run_once(args: &Args, allow_elevation: bool) -> Result<(), ScanFailure> {
    let fail = |code: i32, message: String| ScanFailure { code, message };

    // 1. Keyslot: refuse to run when unissued or expired.
    let slot = resolve_slot(args).map_err(|msg| fail(2, msg))?;
    if let Err(e) = keyslot::check_expiry(&slot) {
        return Err(fail(2, e.to_string()));
    }

    // 1b. Elevation is OPT-IN (--elevate): unprivileged runs are the
    // default; admin-only checks are skipped with an explicit reason.
    // Only the first scan of a service loop may trigger the relaunch.
    if !args.elevated_child && args.elevate && !args.no_elevate && allow_elevation {
        if hbs_extractor::elevate::request_relaunch(false) {
            // The elevated child takes over this scan; the parent loop ends
            // here and the scheduler (or the child) owns subsequent runs.
            std::process::exit(0);
        }
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
        return Err(fail(3, "no testcases match the given filters".into()));
    }

    // 4. Scan.
    let started = std::time::Instant::now();
    let started_at = std::time::SystemTime::now();
    let mut ctx = ScanContext::new(pinfo.clone(), elevated);
    let ui = hbs_extractor::cli::Progress::new(args.quiet, reg.len());
    let meta_started = std::time::Instant::now();
    let meta = metadata::collect(&mut ctx);
    let metadata_ms = meta_started.elapsed().as_millis() as u64;
    let host_display = meta
        .get("hostname")
        .and_then(|v| v.as_str())
        .unwrap_or("host")
        .to_string();
    let os_line = format!(
        "{} {}",
        meta.get("os_name").and_then(|v| v.as_str()).unwrap_or("unknown OS"),
        meta.get("os_version").and_then(|v| v.as_str()).unwrap_or("")
    );
    let admin_only_count = reg.iter().filter(|rc| rc.admin && (rc.applies)(&pinfo)).count();
    ui.banner(
        VERSION,
        &host_display,
        &os_line,
        if elevated {
            format!("elevated (full depth, {} admin-only checks included)", admin_only_count)
        } else {
            format!(
                "unprivileged (default) — {admin_only_count} admin-only checks will be skipped; rerun with --elevate for full depth"
            )
        }
        .as_str(),
    );
    ui.metadata_done(meta.as_object().map(|m| m.len()).unwrap_or(0));
    let checks_started = std::time::Instant::now();
    let mut results = run_all_with_ui(&reg, &mut ctx, &ui);
    let checks_ms = checks_started.elapsed().as_millis() as u64;
    let audit = std::mem::take(&mut ctx.audit);

    // 5. Report + seal.
    let hostname = meta.get("hostname").and_then(|v| v.as_str()).unwrap_or("host").to_string();
    let machine_id = meta.get("machine_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let scan_extra = json!({
        "peakRssKb": peak_rss_kb(),
        "extractorId": keyslot::hex_id(&slot.extractor_id),
        "campaignId": keyslot::hex_id(&slot.campaign_id),
        "keyId": slot.key_id,
        "machineId": machine_id,
        "hostname": hostname,
        "platform": format!("{:?}", pinfo.os),
        "osName": meta.get("os_name").cloned().unwrap_or(json!(null)),
        "osVersion": meta.get("os_version").cloned().unwrap_or(json!(null)),
        "environment": format!("{:?}", pinfo.environment.kind),
        "hypervisor": pinfo.environment.hypervisor.clone(),
        "environmentSignals": pinfo.environment.signals.clone(),
        "arch": pinfo.arch,
        "privileged": elevated,
        "catalogFingerprint": catalog_fingerprint(&reg),
        "phaseDurationsMs": {
            "metadata": metadata_ms,
            "checks": checks_ms,
        },
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
    let envelope = crypto::seal(
        &doc,
        &slot.recipient_pub,
        slot.key_id,
        &slot.extractor_id,
        crypto::SUITE_CHACHA20POLY1305,
    )
        .map_err(|e| fail(3, format!("sealing failed: {e}")))?;

    // Default output: alongside the extractor binary itself (its own
    // directory), never the current working directory — operators run it from
    // arbitrary places, and the report should land where the tool lives.
    let path = args.out.clone().unwrap_or_else(|| {
        let stamp = chrono_like_stamp();
        let dir = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(std::path::Path::to_path_buf))
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        dir.join(format!("hbs-report-{hostname}-{stamp}.hbs"))
            .to_string_lossy()
            .into_owned()
    });
    std::fs::write(&path, &envelope).map_err(|e| fail(3, format!("cannot write {path}: {e}")))?;

    // 6. Optional push, then closing summary. The local report is already
    // written; a network push failure never discards it or fails the scan.
    let push_status = match args.push.as_ref() {
        None => None,
        Some(url) => {
            let token = hbs_extractor::push::resolve_token(
                std::env::var("HBS_PUSH_TOKEN").ok(),
                args.push_token_file.as_deref(),
            )
            .map_err(|e| fail(3, format!("{e}")))?;
            let policy = hbs_extractor::push::PushPolicy::default();
            let extractor_id = keyslot::hex_id(&slot.extractor_id);
            match hbs_extractor::push::push_report(url, &envelope, &token, &extractor_id, &policy) {
                Ok(status) => Some(format!("{url} → HTTP {status}")),
                Err(e) => {
                    eprintln!("hbs-extractor: push failed (local report kept at {path}): {e}");
                    Some(format!("{url} → failed ({e})"))
                }
            }
        }
    };
    ui.finish(&rep.summary, &path, push_status.as_deref());

    Ok(())
}

/// Run checks, streaming each result to the progress display as it
/// completes (the engine callback runs the check then reports).
fn run_all_with_ui(
    reg: &[RegisteredCheck],
    ctx: &mut ScanContext,
    ui: &hbs_extractor::cli::Progress,
) -> Vec<hbs_extractor::model::CheckResult> {
    // The engine API is batch; stream by running per-slice would change
    // engine semantics, so run the batch and emit lines after. The
    // progress bar still reflects completion; per-check streaming
    // lands with true incremental execution in the checks phases.
    let out = run_all(reg, ctx);
    for r in &out {
        ui.check_done(r);
    }
    out
}

#[cfg_attr(not(debug_assertions), allow(unused_variables))]
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
    let priv_key: [u8; 32] = bytes.try_into().map_err(|_| "--dev-insecure-key: need 64 hex chars (a PRIVATE key)".to_string())?;
    Ok(SlotData {
        key_id: 1,
        campaign_id: [0x11; 16],
        extractor_id: [0x22; 16],
        expiry_unix: 4_102_444_800,
        issued_at_unix: 0,
        recipient_pub: hbs_extractor::crypto::pubkey_of(&priv_key),
    })
}

/// Peak resident set size of this scan, self-reported for resource
/// transparency (spec §4.8 budget evidence).
fn peak_rss_kb() -> u64 {
    #[cfg(unix)]
    {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("VmHWM:"))
                    .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse::<u64>().ok()))
            })
            .unwrap_or(0)
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
        // SAFETY: correctly-sized struct; GetProcessMemoryInfo only writes.
        unsafe {
            let mut pmc: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
            pmc.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
            let ok = GetProcessMemoryInfo(
                windows_sys::Win32::System::Threading::GetCurrentProcess(),
                &mut pmc,
                pmc.cb,
            );
            if ok != 0 {
                (pmc.PeakWorkingSetSize as u64) / 1024
            } else {
                0
            }
        }
    }
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
