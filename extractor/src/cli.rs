//! Terminal UX: banner, progress bar with streaming per-check lines,
//! live counters, closing summary, pause-on-double-click, and a plain
//! non-TTY mode. Identical behavior on every OS/arch (spec §4.1).

use crate::model::{CheckResult, Severity, Status, Summary};
use console::{style, Term};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::io::Write as _;

/// One line per completed check — the unit-testable core of the
/// display. Icons: pass ✓ / fail ✗ / degraded ⚠ / error ! / n/a -.
/// Failed checks carry a bracketed severity tag.
pub fn fmt_check_line(r: &CheckResult) -> String {
    let icon = match r.status {
        Status::Compliant => '\u{2713}',
        Status::NonCompliant => '\u{2717}',
        Status::DegradedPartial => '\u{26a0}',
        Status::Error => '!',
        Status::NotApplicable => '-',
    };
    let sev = if matches!(r.status, Status::NonCompliant | Status::DegradedPartial) {
        format!(" [{}]", r.severity.as_str())
    } else {
        String::new()
    };
    let deg = match (&r.status, &r.degraded_reason) {
        (Status::DegradedPartial, Some(reason)) => format!(" ({reason})"),
        _ => String::new(),
    };
    format!("{icon} {} {}{sev}{deg}", r.id, r.title)
}

pub struct Progress {
    quiet: bool,
    attended: bool,
    mp: MultiProgress,
    bar: ProgressBar,
    counters: std::sync::Arc<std::sync::Mutex<(u32, u32, u32, u32, u32, u32)>>,
}

impl Progress {
    pub fn new(quiet: bool, total: usize) -> Self {
        let attended = Term::stdout().features().is_attended();
        let mp = MultiProgress::new();
        let bar = mp.add(ProgressBar::new(total as u64));
        bar.set_style(
            ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{bar:38.cyan/blue}] {pos}/{len} checks ({per_sec})")
                .unwrap_or_else(|_| ProgressStyle::default_bar())
                .progress_chars("== "),
        );
        if quiet || !attended {
            bar.set_draw_target(indicatif::ProgressDrawTarget::hidden());
        }
        Progress {
            quiet,
            attended,
            mp,
            bar,
            counters: std::sync::Arc::new(std::sync::Mutex::new((0, 0, 0, 0, 0, 0))),
        }
    }

    pub fn banner(&self, version: &str, host: &str, os_line: &str, privilege: &str) {
        if self.quiet {
            println!("hbs-extractor {version} — {host} ({privilege})");
            return;
        }
        let box_line = |label: &str, pad: usize| format!("│ {label:<pad$} │", label = label, pad = pad);
        let panel = format!(
            "\n╭──────────────────────────────────────────────╮\n{}\n{}\n{}\n{}\n╰──────────────────────────────────────────────╯",
            box_line(&format!("hbs-extractor {version}  ·  read-only scanner"), 44),
            box_line(host, 44),
            box_line(os_line, 44),
            box_line(&format!("privileges: {privilege}"), 44),
        );
        println!("{}", style(panel).cyan());
    }

    pub fn metadata_done(&self, fields: usize) {
        if !self.quiet {
            println!(
                "{} system metadata collected ({fields} fields)",
                '\u{2713}'
            );
        }
    }

    pub fn check_done(&self, r: &CheckResult) {
        self.bar.inc(1);
        let mut c = self.counters.lock().unwrap();
        match r.status {
            Status::Compliant => c.0 += 1,
            Status::NonCompliant => c.1 += 1,
            Status::DegradedPartial => c.2 += 1,
            Status::Error => c.3 += 1,
            Status::NotApplicable => c.4 += 1,
        }
        if r.severity == Severity::Informational {
            c.5 += 1;
        }
        let line = fmt_check_line(r);
        if self.quiet || !self.attended {
            println!("{line}");
        } else {
            let colored = match r.status {
                Status::NonCompliant => style(line).red().to_string(),
                Status::DegradedPartial => style(line).yellow().to_string(),
                Status::Compliant => style(line).green().to_string(),
                Status::Error => style(line).bright().red().to_string(),
                Status::NotApplicable => style(line).dim().to_string(),
            };
            let _ = self.mp.println(colored);
        }
    }

    pub fn finish(&self, s: &Summary, path: &str, push_status: Option<&str>) {
        self.bar.finish_and_clear();
        println!(
            "\nresults: {} compliant / {} non-compliant / {} degraded / {} errors / {} n/a",
            s.compliant, s.non_compliant, s.degraded, s.error, s.not_applicable
        );
        println!("sealed report: {}", style(path).bold());
        if let Some(p) = push_status {
            println!("push: {p}");
        }
    }
}

/// Pause before exit when launched interactively (Windows double-click
/// support). Skipped for --no-pause, --quiet, and non-attended terms.
pub fn pause_if_interactive(no_pause: bool, quiet: bool) {
    if no_pause || quiet || !Term::stdout().features().is_attended() {
        return;
    }
    print!("Press Enter to close…");
    let _ = std::io::stdout().flush();
    let _ = std::io::stdin().read_line(&mut String::new());
}
