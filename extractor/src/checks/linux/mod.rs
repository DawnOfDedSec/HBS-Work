//! Linux check modules. Shared helpers live here; one file per CIS
//! section below.

pub mod firewall;
pub mod auditd;
pub mod fsck;
pub mod logging;
pub mod network;
pub mod pam;
pub mod services;
pub mod users;
pub mod ssh;
pub mod threat;

use crate::context::ScanContext;

/// Options string for the mount covering `path` (exact mount-point
/// match, longest-prefix fallback), from /proc/mounts.
pub fn mount_opts(ctx: &mut ScanContext, path: &str) -> Option<String> {
    let mounts = ctx.read("/proc/mounts")?;
    let mut best: Option<(usize, String)> = None;
    for line in mounts.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 {
            continue;
        }
        let mp = f[1];
        if path == mp || path.starts_with(&format!("{mp}/")) {
            let len = mp.len();
            if best.as_ref().map(|(l, _)| len > *l).unwrap_or(true) {
                best = Some((len, f[3].to_string()));
            }
        }
    }
    best.map(|(_, opts)| opts)
}

/// True when the mount option is present (e.g. "nodev", "nosuid").
pub fn has_opt(opts: &str, opt: &str) -> bool {
    opts.split(',').any(|o| o == opt)
}

/// Last uncommented `Key value` assignment in a config file body.
pub fn last_kv(text: &str, key: &str) -> Option<String> {
    text.lines()
        .map(|l| l.trim_start())
        .filter(|l| !l.starts_with('#') && !l.starts_with(';'))
        .filter_map(|l| l.split_whitespace().next().map(|k| (k, l)))
        .filter(|(k, _)| k.eq_ignore_ascii_case(key))
        .filter_map(|(_, l)| l.split_whitespace().nth(1).map(str::to_string))
        .next_back()
}

/// sysctl value: /proc/sys path first, `sysctl -n` fallback.
pub fn sysctl_value(ctx: &mut ScanContext, key: &str) -> Option<String> {
    let proc_path = format!("/proc/sys/{}", key.replace('.', "/"));
    if let Some(v) = ctx.read(&proc_path) {
        let t = v.trim().to_string();
        if !t.is_empty() {
            return Some(t);
        }
    }
    ctx.cmd("sysctl", &["-n", key])
        .filter(|o| !o.trim().is_empty())
}

/// First existing path among candidates.
pub fn first_existing<'a>(ctx: &mut ScanContext, candidates: &[&'a str]) -> Option<&'a str> {
    candidates.iter().copied().find(|p| ctx.exists(p))
}
