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
    "sshd", "ssh", "zgrep", "stat", "sha256sum", "gpg", "openssl", "lspci", "lsusb",
    // windows
    "systeminfo", "reg", "auditpol", "net", "wmic", "sc",
    "wevtutil", "powershell", "pwsh", "manage-bde", "dsregcmd",
    "cmdkey", "tzutil", "driverquery", "schtasks", "netsh", "whoami",
    "arp", "route", "qwinsta",
];

/// Programs whose FIRST argument must be one of the listed verbs.
const RESTRICTED_VERBS: &[(&str, &[&str])] = &[
    ("sc", &["qc", "query", "queryex"]),
    ("wevtutil", &["gl", "el", "qe", "gli"]),
    ("docker", &["ps", "inspect", "version", "info"]),
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
    ("sshd", &["-T", "-V"]),
    ("lspci", &["-mm", "-nn", "-v"]),
    ("lsusb", &["-v", "-t"]),
    ("ssh", &["-V"]),
    ("stat", &["-c", "-f", "--format"]),
    ("sha256sum", &["-c", "--check"]),
    ("zgrep", &["-i", "-E", "-h"]),
    ("openssl", &["version"]),
    ("crontab", &["-l"]),
    ("getcap", &["-r"]),
    ("findmnt", &["-l", "-n", "-T", "--target", "-rn"]),
    ("mount", &["-l"]),
    ("lsmod", &[]),
    ("atq", &[]),
    ("id", &["-u", "-g", "-n", "-G"]),
    ("whoami", &["/priv", "/all", "/user", "/groups"]),
    ("uname", &["-s", "-r", "-m", "-a", "-n"]),
    ("hostname", &["-f", "-s", "-A", "-I"]),
    ("systemd-detect-virt", &[]),
    ("uptime", &[]),
    ("lsb_release", &["-a", "-d", "-i", "-r"]),
    ("timedatectl", &["status", "show"]),
    ("localectl", &["status"]),
    ("getent", &["passwd", "group", "shadow", "hosts", "initgroups"]),
    ("dpkg-query", &["-W", "-L", "-S", "-l"]),
    ("rpm", &["-q", "-qa", "-qf", "-V", "-Vv", "--query", "--last"]),
    ("apk", &["info", "list", "version"]),
    ("pacman", &["-Q", "-Qi", "-Ql", "-Qo"]),
    ("zypper", &["--no-gpg-checks", "search", "info", "lp"]),
    ("chkconfig", &["--list"]),
    ("package", &[]),
    ("debsums", &["-s", "-c", "-a"]),
    ("bootctl", &["status"]),
    ("chronyc", &["tracking", "sources", "sourcestats"]),
    ("showmount", &["-e"]),
    ("driverquery", &["/v", "/si"]),
    ("arp", &["-a"]),
    ("route", &["print"]),
    ("qwinsta", &[]),
    ("tzutil", &["/g"]),
    ("ip", &["addr", "link", "route", "-br", "a"]),
    ("sysctl", &["-n", "-a", "-e"]),
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
    match program {
        "powershell" | "pwsh" => powershell_query_only(args),
        "net" => net_query_only(args),
        "netsh" => netsh_query_only(args),
        "reg" => reg_query_only(args),
        "auditpol" => auditpol_query_only(args),
        _ => {
            for (p, verbs) in RESTRICTED_VERBS {
                if *p == program {
                    if verbs.is_empty() {
                        return args.is_empty();
                    }
                    if program == "whoami" && args.is_empty() {
                        return true;
                    }
                    return matches!(args.first(), Some(a) if verbs.contains(a));
                }
            }
            true
        }
    }
}

fn reg_query_only(args: &[&str]) -> bool {
    if !matches!(args.first(), Some(&"query")) {
        return false;
    }
    !args.iter().any(|arg| {
        let l = arg.to_ascii_lowercase();
        l.contains('>') || l.contains('<') || l.contains('|') || l.contains('&') || l.contains(';')
    })
}

fn auditpol_query_only(args: &[&str]) -> bool {
    if !matches!(args.first(), Some(&"/get")) {
        return false;
    }
    !args.iter().any(|arg| {
        let l = arg.to_ascii_lowercase();
        l.contains('>') || l.contains('<') || l.contains('|') || l.contains('&') || l.contains(';')
    })
}

fn net_query_only(args: &[&str]) -> bool {
    match args.first().copied() {
        Some("accounts") => args.len() == 1,
        Some("user") => {
            args.len() == 1
                || (args.len() == 2 && !args[1].starts_with('/') && !args[1].contains('='))
        }
        Some("share") => {
            args.len() == 1
                || (args.len() == 2 && !args[1].starts_with('/') && !args[1].contains('='))
        }
        Some("localgroup") => {
            args.len() == 1
                || (args.len() == 2 && !args[1].starts_with('/') && !args[1].contains('='))
        }
        Some("group") => {
            args.len() == 1
                || (args.len() == 2 && !args[1].starts_with('/') && !args[1].contains('='))
        }
        Some("session") => args.len() == 1,
        _ => false,
    }
}

fn netsh_query_only(args: &[&str]) -> bool {
    let Some(subsystem) = args.first().copied() else {
        return false;
    };
    if !matches!(
        subsystem,
        "advfirewall" | "interface" | "winhttp" | "rpc" | "http"
    ) {
        return false;
    }
    if !args.iter().any(|arg| arg.eq_ignore_ascii_case("show")) {
        return false;
    }
    !args.iter().any(|arg| {
        let l = arg.to_ascii_lowercase();
        matches!(
            l.as_str(),
            "set" | "add" | "delete" | "del" | "reset" | "export" | "dump" | "install" | "uninstall"
        ) || l.contains('>') || l.contains('<') || l.contains('|') || l.contains('&') || l.contains(';')
    })
}

fn powershell_query_only(args: &[&str]) -> bool {
    let mut command_idx = None;
    for (i, arg) in args.iter().enumerate() {
        if arg.eq_ignore_ascii_case("-command") || arg.eq_ignore_ascii_case("-c") {
            command_idx = Some(i);
            break;
        }
        let lower = arg.to_ascii_lowercase();
        if !matches!(
            lower.as_str(),
            "-noprofile" | "-noninteractive" | "-executionpolicy" | "bypass"
        ) {
            return false;
        }
    }
    let Some(idx) = command_idx else {
        return false;
    };
    if idx + 2 != args.len() {
        return false;
    }
    let script = args[idx + 1].trim();
    validate_powershell_script(script)
}

fn validate_powershell_script(script: &str) -> bool {
    if script.is_empty() {
        return false;
    }
    if script.contains('>')
        || script.contains('<')
        || script.contains('`')
        || script.contains(';')
        || script.contains('\n')
        || script.contains('\r')
    {
        return false;
    }
    let lower = script.to_ascii_lowercase();
    if lower.contains("http:")
        || lower.contains("https:")
        || lower.contains("ftp:")
        || lower.contains(r"\\")
    {
        return false;
    }
    if let Some(var) = lower.strip_prefix("$env:") {
        return !var.is_empty() && var.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    }

    let inner = if script.starts_with('(') {
        let mut depth = 0;
        let mut close_idx = None;
        for (i, c) in script.char_indices() {
            if c == '(' {
                depth += 1;
            } else if c == ')' {
                depth -= 1;
                if depth == 0 {
                    close_idx = Some(i);
                    break;
                }
            }
        }
        let Some(c_idx) = close_idx else {
            return false;
        };
        let remainder = script[c_idx + 1..].trim();
        if !remainder.is_empty() {
            if !remainder.starts_with('.') {
                return false;
            }
            let prop = &remainder[1..];
            let prop_clean = prop.trim_matches('\'').trim_matches('"');
            if prop_clean.is_empty()
                || !prop_clean
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                return false;
            }
        }
        &script[1..c_idx]
    } else {
        script
    };

    let stages: Vec<&str> = inner.split('|').map(str::trim).collect();
    if stages.is_empty() {
        return false;
    }

    const ALLOWED_HEADS: &[&str] = &[
        "get-itemproperty",
        "get-ciminstance",
        "get-wmiobject",
        "get-hotfix",
        "get-tpm",
        "confirm-securebootuefi",
        "get-service",
        "get-acl",
        "get-process",
        "get-mppreference",
        "get-mpcomputerstatus",
        "get-netfirewallprofile",
        "get-netfirewallrule",
        "test-path",
    ];

    const ALLOWED_TRANSFORMERS: &[&str] = &[
        "select-object",
        "sort-object",
        "where-object",
        "foreach-object",
        "convertto-json",
        "convertto-csv",
        "measure-object",
        "group-object",
        "out-string",
    ];

    let stage0_cmd = stage_command_name(stages[0]);
    if !ALLOWED_HEADS.contains(&stage0_cmd.as_str()) {
        return false;
    }

    for stage in &stages[1..] {
        let cmd = stage_command_name(stage);
        if !ALLOWED_TRANSFORMERS.contains(&cmd.as_str()) {
            return false;
        }
    }

    true
}

fn stage_command_name(stage: &str) -> String {
    stage
        .trim_start_matches('(')
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
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
            if let Some(s) = child.stdout.take() {
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
