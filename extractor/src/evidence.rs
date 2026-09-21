//! Read-only evidence collection: capped file reads and allowlisted
//! query-command execution with timeouts. This module is where the
//! spec's read-only guarantee is enforced — nothing else in the crate
//! may open files or spawn processes directly.

use crate::model::SelfAudit;
use std::io::Read;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// Hard cap on any single file read (spec §4.8: bounded reads).
pub const MAX_READ: usize = 1024 * 1024;

/// Programs the extractor may execute. Every entry is a query-style
/// tool; anything not listed is refused without spawning.
pub const COMMAND_ALLOWLIST: &[&str] = &[
    // cross-platform / linux
    "uname", "hostname", "id", "getent", "systemd-detect-virt", "ss",
    "ip", "sysctl", "dpkg-query", "rpm", "apk", "pacman", "zypper",
    "chkconfig", "systemctl", "timedatectl", "localectl", "docker",
    "lsb_release", "last", "uptime", "ufw", "firewall-cmd", "nft",
    "iptables", "auditctl", "package", "at", "atq", "getcap", "debsums",
    "dnf", "apt-get", "mount", "findmnt", "mokutil", "bootctl",
    "chronyc", "showmount", "lsmod", "crontab", "realm",
    // windows
    "systeminfo", "reg", "auditpol", "secedit", "net", "wmic", "sc",
    "wevtutil", "powershell", "pwsh", "manage-bde", "dsregcmd",
    "cmdkey", "tzutil", "driverquery", "schtasks", "netsh", "whoami",
    "arp", "route", "nslookup", "qwinsta",
];

/// Programs whose FIRST argument must be one of the listed verbs.
const RESTRICTED_VERBS: &[(&str, &[&str])] = &[
    ("reg", &["query"]),
    ("auditpol", &["/get"]),
    ("secedit", &["/export"]),
    ("sc", &["qc", "query", "queryex"]),
    ("wevtutil", &["gl", "el", "qe", "gli"]),
    ("docker", &["ps", "inspect", "version", "info"]),
    ("net", &["accounts", "share", "user", "localgroup", "group", "session", "stop", "start", "use"]),
    ("netsh", &["advfirewall", "interface", "winhttp", "rpc", "http"]),
    ("powershell", &["-NoProfile"]),
    ("pwsh", &["-NoProfile"]),
    ("schtasks", &["/query"]),
    ("apt-get", &["-s"]),
    ("manage-bde", &["-status"]),
    ("cmdkey", &["/list"]),
    ("dsregcmd", &["/status"]),
    ("wmic", &["qfe", "csproduct", "os", "computersystem", "cpu", "bios", "logicaldisk"]),
    ("ufw", &["status"]),
    ("systemctl", &["is-active", "is-enabled", "cat", "show", "list-units", "list-timers", "list-unit-files"]),
    ("ss", &["-tulpn", "-tulpn4", "-tulpn6", "-tuln", "-tulnp", "-tulpne"]),
    ("iptables", &["-L", "-S"]),
    ("nft", &["list"]),
    ("auditctl", &["-l", "-s"]),
    ("firewall-cmd", &["--state", "--get-default-zone", "--list-all", "--list-services"]),
    ("dnf", &["updateinfo", "repoquery"]),
    ("at", &["-l"]),
    ("mokutil", &["--sb-state"]),
    ("last", &["-n", "-F"]),
];

/// Read a file read-only, at most [`MAX_READ`] bytes, lossily decoded.
/// Records the successful read in the self-audit log. Any error
/// (missing, permission, ...) yields None — callers turn that into a
/// fallback-log entry, never an abort.
pub fn read_file_capped(path: &Path, audit: &mut SelfAudit) -> Option<String> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; MAX_READ];
    let mut total = 0usize;
    loop {
        match f.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                if total == MAX_READ {
                    break;
                }
            }
            Err(_) => return None,
        }
    }
    buf.truncate(total);
    audit.files_read.push(path.to_string_lossy().into_owned());
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// Byte-for-byte variant of [`read_file_capped`] (registry hives,
/// binary magic checks).
pub fn read_bytes_capped(path: &Path, audit: &mut SelfAudit) -> Option<Vec<u8>> {
    let s = read_file_capped(path, audit)?;
    Some(s.into_bytes())
}

pub type CmdInjector = Box<dyn Fn(&str, &[&str]) -> Option<String>>;

fn allowed(program: &str, args: &[&str]) -> bool {
    if !COMMAND_ALLOWLIST.contains(&program) {
        return false;
    }
    for (p, verbs) in RESTRICTED_VERBS {
        if *p == program {
            return match args.first() {
                Some(a) => verbs.contains(a),
                None => false,
            };
        }
    }
    true
}

/// Run an allowlisted program with a hard timeout; kill on expiry.
/// Returns trimmed stdout on exit code 0, else None. The executed
/// command line is recorded in the self-audit log (attempts that fail
/// validation are never spawned and never logged).
pub fn run_command(
    program: &str,
    args: &[&str],
    timeout_ms: u64,
    audit: &mut SelfAudit,
    injector: &Option<CmdInjector>,
) -> Option<String> {
    if !allowed(program, args) {
        return None;
    }
    let cmdline = format!("{} {}", program, args.join(" "));
    if let Some(f) = injector {
        audit.commands.push(cmdline);
        return f(program, args);
    }
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    #[cfg(windows)]
    {
        // SAFETY: plain flag constant, no pointer arguments.
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let mut child = cmd.spawn().ok()?;
    let status = wait_timeout::ChildExt::wait_timeout(&mut child, Duration::from_millis(timeout_ms));
    match status {
        Ok(Some(st)) if st.success() => {
            let mut out = String::new();
            if let Some(mut s) = child.stdout.take() {
                let _ = s.take(MAX_READ as u64).read_to_string(&mut out);
            }
            audit.commands.push(cmdline);
            Some(out.trim().to_string())
        }
        _ => {
            let _ = child.kill();
            let _ = child.wait();
            None
        }
    }
}
