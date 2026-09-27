//! Read-only evidence collection: capped file reads and allowlisted
//! query-command execution with timeouts. This module is where the
//! spec's read-only guarantee is enforced — nothing else in the crate
//! may open files or spawn processes directly.

use crate::model::{AuditKind, AuditStatus, SelfAudit};
use crate::redact::redact;
use std::io::Read;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// Hard cap on any single file read (spec §4.8: bounded reads).
pub const MAX_READ: usize = 1024 * 1024;

/// Programs the extractor may execute. Every entry is a query-style
/// tool; anything not listed is refused without spawning. The list is
/// deliberately free of DNS/network-resolution tools (`nslookup`, `dig`,
/// `host`, `showmount`, `ping`, `nc`, `curl`, …); `tests/no_egress.rs`
/// pins that property.
pub const COMMAND_ALLOWLIST: &[&str] = &[
    // cross-platform / linux
    "uname",
    "hostname",
    "id",
    "getent",
    "systemd-detect-virt",
    "ss",
    "ip",
    "sysctl",
    "dpkg-query",
    "rpm",
    "apk",
    "pacman",
    "zypper",
    "chkconfig",
    "systemctl",
    "timedatectl",
    "localectl",
    "docker",
    "lsb_release",
    "last",
    "uptime",
    "ufw",
    "firewall-cmd",
    "nft",
    "iptables",
    "auditctl",
    "package",
    "at",
    "atq",
    "getcap",
    "debsums",
    "dnf",
    "apt-get",
    "mount",
    "findmnt",
    "mokutil",
    "bootctl",
    "chronyc",
    "lsmod",
    "crontab",
    "realm",
    "free",
    "lscpu",
    "sshd",
    "ssh",
    "zgrep",
    "stat",
    "sha256sum",
    "openssl",
    "lspci",
    "lsusb",
    // windows
    "systeminfo",
    "reg",
    "auditpol",
    "net",
    "wmic",
    "sc",
    "wevtutil",
    "powershell",
    "pwsh",
    "manage-bde",
    "dsregcmd",
    "cmdkey",
    "tzutil",
    "driverquery",
    "schtasks",
    "netsh",
    "whoami",
    "arp",
    "route",
    "qwinsta",
];

/// Program names that must never appear in [`COMMAND_ALLOWLIST`] because
/// they resolve names or open network connections. Kept here so the
/// no-egress test and the allowlist stay in sync.
pub const FORBIDDEN_NETWORK_PROGRAMS: &[&str] = &[
    "nslookup",
    "dig",
    "delv",
    "host",
    "drill",
    "kdig",
    "showmount",
    "rpcinfo",
    "rpcclient",
    "smbclient",
    "smbstatus",
    "nfsstat",
    "ping",
    "ping6",
    "traceroute",
    "tracepath",
    "mtr",
    "nc",
    "ncat",
    "netcat",
    "socat",
    "telnet",
    "ftp",
    "sftp",
    "scp",
    "curl",
    "wget",
    "sshfs",
    "mount.nfs",
    "gpg",
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
    (
        "wmic",
        &[
            "qfe",
            "csproduct",
            "os",
            "computersystem",
            "cpu",
            "bios",
            "logicaldisk",
        ],
    ),
    ("ufw", &["status"]),
    (
        "systemctl",
        &[
            "is-active",
            "is-enabled",
            "cat",
            "show",
            "list-units",
            "list-timers",
            "list-unit-files",
        ],
    ),
    (
        "ss",
        &["-tulpn", "-tulpn4", "-tulpn6", "-tuln", "-tulnp", "-tulpne"],
    ),
    ("nft", &["list"]),
    ("auditctl", &["-l", "-s"]),
    (
        "firewall-cmd",
        &[
            "--state",
            "--get-default-zone",
            "--list-all",
            "--list-services",
        ],
    ),
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
    ("systemd-detect-virt", &[]),
    ("uptime", &[]),
    ("lsb_release", &["-a", "-d", "-i", "-r"]),
    ("timedatectl", &["status", "show"]),
    ("localectl", &["status"]),
    ("getent", &["passwd", "group", "shadow", "initgroups"]),
    ("dpkg-query", &["-W", "-L", "-S", "-l"]),
    (
        "rpm",
        &["-q", "-qa", "-qf", "-V", "-Vv", "--query", "--last"],
    ),
    ("apk", &["info", "list", "version"]),
    ("pacman", &["-Q", "-Qi", "-Ql", "-Qo"]),
    ("zypper", &["--no-gpg-checks", "search", "info", "lp"]),
    ("chkconfig", &["--list"]),
    ("package", &[]),
    ("debsums", &["-s", "-c", "-a"]),
    ("bootctl", &["status"]),
    ("chronyc", &["tracking", "sources", "sourcestats"]),
    ("realm", &["list"]),
    ("systeminfo", &[]),
    ("driverquery", &["/v", "/si"]),
    ("arp", &["-an"]),
    ("route", &["print"]),
    ("qwinsta", &[]),
    ("tzutil", &["/g"]),
    ("ip", &["addr", "link", "route", "-br", "a"]),
    ("sysctl", &["-n", "-a", "-e"]),
    ("free", &["-m"]),
    ("lscpu", &[]),
];

/// Human label for an attempt status (stored as the attempt `outcome`
/// when there is no richer detail).
fn outcome_label(s: AuditStatus) -> &'static str {
    match s {
        AuditStatus::Ok => "ok",
        AuditStatus::Missing => "not found or unreadable",
        AuditStatus::Denied => "permission denied",
        AuditStatus::Timeout => "timeout",
        AuditStatus::Rejected => "refused by allowlist",
        AuditStatus::NonZero => "non-zero exit",
        AuditStatus::Malformed => "unparseable output",
        AuditStatus::Cached => "cache hit",
        AuditStatus::Error => "error",
    }
}

/// Read a file read-only, at most [`MAX_READ`] bytes, lossily decoded.
/// Records a structured attempt (before the open, updated after) plus the
/// compact `files_read` list on success. Any error (missing, permission,
/// ...) yields None — callers turn that into a fallback-log entry, never
/// an abort.
pub fn read_file_capped(path: &Path, audit: &mut SelfAudit) -> Option<String> {
    let source = path.to_string_lossy().into_owned();
    read_file_capped_as(path, &source, audit)
}

/// Like [`read_file_capped`] but records `source` (a logical path) in the
/// audit instead of the on-disk path — used by [`crate::context::ScanContext`]
/// so cache-hit attempts, evidence blocks, and the compact list all share
/// one stable logical source.
pub fn read_file_capped_as(path: &Path, source: &str, audit: &mut SelfAudit) -> Option<String> {
    let idx = audit.begin_attempt(AuditKind::File, source);
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            let status = match e.kind() {
                std::io::ErrorKind::NotFound => AuditStatus::Missing,
                std::io::ErrorKind::PermissionDenied => AuditStatus::Denied,
                _ => AuditStatus::Error,
            };
            let note = e.to_string();
            audit.finish_attempt(idx, |a| {
                a.status = status;
                a.outcome = outcome_label(status).to_string();
                a.note = Some(note);
            });
            return None;
        }
    };
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
            Err(e) => {
                let note = e.to_string();
                audit.finish_attempt(idx, |a| {
                    a.status = AuditStatus::Error;
                    a.outcome = "read error".to_string();
                    a.note = Some(note);
                });
                return None;
            }
        }
    }
    buf.truncate(total);
    let out = String::from_utf8_lossy(&buf).into_owned();
    audit.files_read.push(redact(source));
    audit.finish_attempt(idx, |a| {
        a.status = AuditStatus::Ok;
        a.bytes = Some(total as u64);
        a.outcome = format!("read {total} bytes");
    });
    Some(out)
}

/// Byte-for-byte variant of [`read_file_capped`] (registry hives,
/// binary magic checks).
pub fn read_bytes_capped(path: &Path, audit: &mut SelfAudit) -> Option<Vec<u8>> {
    let s = read_file_capped(path, audit)?;
    Some(s.into_bytes())
}

pub type CmdInjector = Box<dyn Fn(&str, &[&str]) -> Option<String>>;

/// Whether `program arg...` may be spawned. This is the single choke
/// point: every command run by the extractor is gated here, before any
/// process is created. Besides the per-program verb rules it centrally
/// refuses any argument that names a remote target, so no allowlisted
/// tool can be pointed at another host (see [`has_remote_target`]).
pub fn allowed(program: &str, args: &[&str]) -> bool {
    if !COMMAND_ALLOWLIST.contains(&program) {
        return false;
    }
    if args.iter().any(|a| has_remote_target(a)) {
        return false;
    }
    // `/s <host>` selects a remote system for `systeminfo`, `driverquery`,
    // and `schtasks`; `reg query /s` instead recurses subkeys locally, so
    // the switch is only remote for programs other than `reg`.
    if program != "reg" && args.iter().any(|a| *a == "/s") {
        return false;
    }
    match program {
        "powershell" | "pwsh" => powershell_query_only(args),
        "net" => net_query_only(args),
        "netsh" => netsh_query_only(args),
        "reg" => reg_query_only(args),
        "auditpol" => auditpol_query_only(args),
        "hostname" => hostname_query_only(args),
        "iptables" => iptables_query_only(args),
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

/// True when an argument names a remote target: an SMB/UNC path
/// (`\\host`), a network path (`//host`), an scp-style `user@host`, or a
/// PowerShell/CIM remote-session switch. Case-insensitive for the
/// switches. Refused centrally, before any process is spawned.
fn has_remote_target(arg: &str) -> bool {
    if arg.contains(r"\\") || arg.contains("//") {
        return true;
    }
    let lower = arg.to_ascii_lowercase();
    const REMOTE_SWITCHES: &[&str] = &[
        "/node:",
        "/server:",
        "/r:",
        "-computername",
        "-session",
        "-credential",
        "-cimsession",
        "-asjob",
        "-throttlelimit",
    ];
    if REMOTE_SWITCHES.iter().any(|s| lower.contains(s)) {
        return true;
    }
    // scp form: `@host` or `@[ipv6]`.
    let bytes = arg.as_bytes();
    bytes.iter().enumerate().any(|(i, b)| {
        *b == b'@'
            && bytes.get(i + 1).map_or(false, |n| {
                n.is_ascii_alphanumeric() || *n == b'[' || *n == b'.'
            })
    })
}

/// `hostname` may only report the local name: no arguments (short name)
/// or `-s` (also short name). `-f`/`-A`/`-I` are refused because they
/// perform name resolution or interface discovery.
fn hostname_query_only(args: &[&str]) -> bool {
    args.is_empty() || args == ["-s"]
}

/// `iptables` listing is allowed only with numeric output: `-n` (no
/// reverse DNS lookup) together with `-L`/`-S`. State-changing commands
/// (`-A`, `-F`, `-P`, …) are refused.
fn iptables_query_only(args: &[&str]) -> bool {
    let has_numeric = args.iter().any(|a| *a == "-n" || *a == "--numeric");
    let has_list = args
        .iter()
        .any(|a| *a == "-L" || *a == "-S" || *a == "--list" || *a == "--list-rules");
    if !has_numeric || !has_list {
        return false;
    }
    const CHANGING: &[&str] = &[
        "-A",
        "--append",
        "-D",
        "--delete",
        "-I",
        "--insert",
        "-R",
        "--replace",
        "-F",
        "--flush",
        "-Z",
        "--zero",
        "-N",
        "--new-chain",
        "-X",
        "--delete-chain",
        "-P",
        "--policy",
        "-E",
        "--rename-chain",
    ];
    !args.iter().any(|a| {
        CHANGING.contains(a)
            || a.contains('>')
            || a.contains('<')
            || a.contains('|')
            || a.contains('&')
            || a.contains(';')
    })
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
    let Some(verb) = args.first().copied() else {
        return false;
    };
    let name_arg_ok = |a: &str| !a.starts_with('/') && !a.contains('=');
    match verb {
        // Pure local queries.
        "accounts" | "session" | "statistics" | "config" => {
            args.len() == 1 || (args.len() == 2 && name_arg_ok(args[1]))
        }
        // Enumerate or inspect a named local object.
        "user" | "share" | "localgroup" => {
            args.len() == 1 || (args.len() == 2 && name_arg_ok(args[1]))
        }
        // `view`, `use`, `time`, `send`, `start`, `stop`, `group`, … all
        // reach the network or change state and are refused.
        _ => false,
    }
}

fn netsh_query_only(args: &[&str]) -> bool {
    let Some(subsystem) = args.first().copied() else {
        return false;
    };
    if args.iter().any(|arg| {
        let l = arg.to_ascii_lowercase();
        matches!(
            l.as_str(),
            "set"
                | "add"
                | "delete"
                | "del"
                | "reset"
                | "export"
                | "dump"
                | "install"
                | "uninstall"
        ) || l.contains('>')
            || l.contains('<')
            || l.contains('|')
            || l.contains('&')
            || l.contains(';')
    }) {
        return false;
    }
    let has_show = args.iter().any(|a| a.eq_ignore_ascii_case("show"));
    match subsystem {
        // Firewall profiles.
        "advfirewall" => has_show,
        // Only the local ip/ipv4 query contexts the catalog reads;
        // `portproxy` (and other proxy/relay verbs) are refused.
        "interface" => has_show && matches!(args.get(1).copied(), Some("ip") | Some("ipv4")),
        // Local HTTP URL reservations and WLAN profiles.
        "http" | "wlan" => has_show,
        _ => false,
    }
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

/// Validate a PowerShell script that will be passed to `-Command`. Only
/// query-shaped pipelines ending in read-only cmdlets are accepted; any
/// write, network, redirection, or remote-session capability is refused.
/// Exposed for the no-egress test.
pub fn validate_powershell_script(script: &str) -> bool {
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
    // Remote-session/target switches: `Get-WmiObject`/`Get-CimInstance`
    // (and friends) must never be pointed at another host.
    if lower.contains("-computername")
        || lower.contains("-session")
        || lower.contains("-credential")
        || lower.contains("-asjob")
        || lower.contains("-throttlelimit")
        || lower.contains("-cimsession")
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
        "get-childitem",
        "get-localuser",
        "get-localgroup",
        "get-localgroupmember",
        "get-scheduledtask",
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
/// Returns trimmed stdout on exit code 0, else None. Every attempt is
/// recorded structurally (before validation/spawn, updated after):
/// allowlist refusals never spawn. The compact `commands` list holds only
/// successfully executed commands.
pub fn run_command(
    program: &str,
    args: &[&str],
    timeout_ms: u64,
    audit: &mut SelfAudit,
    injector: &Option<CmdInjector>,
) -> Option<String> {
    let cmdline = format!("{} {}", program, args.join(" "));
    let idx = audit.begin_attempt(AuditKind::Command, &cmdline);
    if !allowed(program, args) {
        audit.finish_attempt(idx, |a| {
            a.status = AuditStatus::Rejected;
            a.outcome = "refused by allowlist; not spawned".to_string();
        });
        return None;
    }
    let started = std::time::Instant::now();
    if let Some(f) = injector {
        let out = f(program, args);
        audit.commands.push(redact(&cmdline));
        let elapsed = started.elapsed().as_millis() as u64;
        let bytes = out.as_ref().map(|s| s.len() as u64);
        audit.finish_attempt(idx, |a| {
            a.exit_code = Some(0);
            a.bytes = bytes;
            a.duration_ms = Some(elapsed);
            match bytes {
                Some(n) => {
                    a.status = AuditStatus::Ok;
                    a.outcome = format!("injected; {n} bytes");
                }
                None => {
                    a.status = AuditStatus::Missing;
                    a.outcome = "injected; no output".to_string();
                }
            }
        });
        return out;
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
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let note = e.to_string();
            audit.finish_attempt(idx, |a| {
                a.status = AuditStatus::Missing;
                a.outcome = "spawn failed; command unavailable".to_string();
                a.note = Some(note);
            });
            return None;
        }
    };
    let status =
        wait_timeout::ChildExt::wait_timeout(&mut child, Duration::from_millis(timeout_ms));
    match status {
        Ok(Some(st)) if st.success() => {
            let mut out = String::new();
            if let Some(s) = child.stdout.take() {
                let _ = s.take(MAX_READ as u64).read_to_string(&mut out);
            }
            audit.commands.push(redact(&cmdline));
            let elapsed = started.elapsed().as_millis() as u64;
            let code = st.code();
            let bytes = out.trim().len() as u64;
            audit.finish_attempt(idx, |a| {
                a.status = AuditStatus::Ok;
                a.exit_code = code;
                a.bytes = Some(bytes);
                a.duration_ms = Some(elapsed);
                a.outcome = format!("exit {}; {bytes} bytes", code_str(code));
            });
            Some(out.trim().to_string())
        }
        Ok(Some(st)) => {
            let code = st.code();
            let elapsed = started.elapsed().as_millis() as u64;
            let _ = child.kill();
            let _ = child.wait();
            audit.finish_attempt(idx, |a| {
                a.status = AuditStatus::NonZero;
                a.exit_code = code;
                a.duration_ms = Some(elapsed);
                a.outcome = format!("exit {}", code_str(code));
            });
            None
        }
        Ok(None) => {
            let elapsed = started.elapsed().as_millis() as u64;
            let _ = child.kill();
            let _ = child.wait();
            audit.finish_attempt(idx, |a| {
                a.status = AuditStatus::Timeout;
                a.duration_ms = Some(elapsed);
                a.outcome = format!("timeout after {timeout_ms} ms");
            });
            None
        }
        Err(e) => {
            let elapsed = started.elapsed().as_millis() as u64;
            let note = e.to_string();
            let _ = child.kill();
            let _ = child.wait();
            audit.finish_attempt(idx, |a| {
                a.status = AuditStatus::Error;
                a.duration_ms = Some(elapsed);
                a.outcome = "wait error".to_string();
                a.note = Some(note);
            });
            None
        }
    }
}

fn code_str(code: Option<i32>) -> String {
    code.map(|c| c.to_string())
        .unwrap_or_else(|| "?".to_string())
}
