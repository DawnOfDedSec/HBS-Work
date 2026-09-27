//! LIN-TH (part 1): threat-informed checks grounded in recent attack
//! patterns — kernel attack-surface kill-switches and persistence
//! hunting (spec §5, threat-informed layer).

use crate::checks::linux::network::{sysctl_eq, sysctl_num_at_least};
use crate::checks::{
    degraded, degraded_from_attempts, in_container, nok, not_applicable, ok, with_block,
};
use crate::context::ScanContext;
use crate::model::{CheckOutcome, FallbackAttempt, RegisteredCheck};
use crate::platform::Os;

pub fn register(reg: &mut Vec<RegisteredCheck>) {
    use crate::check;
    // ---- kernel attack surface ----
    check!(reg, "LIN-TH-001", "Unprivileged BPF disabled", "kernel.unprivileged_bpf_disabled=1.", "Unprivileged BPF is the precondition of repeated kernel LPE chains (CVE-2021-3490 lineage).", "sysctl kernel.unprivileged_bpf_disabled=1.", High, "Threat", &["MITRE T1068"], linux, |c| sysctl_eq(c, "kernel.unprivileged_bpf_disabled", "1", false));
    check!(reg, "LIN-TH-002", "Unprivileged user namespaces restricted", "userns must be off, capped, or AppArmor-restricted.", "userns is the precondition of the nf_tables LPE exploit family and +262% kernel attack surface (Edera research).", "sysctl kernel.unprivileged_userns_clone=0 / user.max_user_namespaces=0, or Ubuntu's apparmor_restrict_unprivileged_userns=1.", High, "Threat", &["MITRE T1068"], linux, userns_restricted);
    check!(reg, "LIN-TH-003", "io_uring disabled for unprivileged use", "kernel.io_uring_disabled=2 (or 1).", "io_uring bypasses the normal syscall path and was disabled by Google in production; malware increasingly abuses it.", "sysctl kernel.io_uring_disabled=2.", Medium, "Threat", &["MITRE T1068"], linux, |c| sysctl_num_at_least(c, "kernel.io_uring_disabled", 1));
    check!(
        reg,
        "LIN-TH-004",
        "Kernel pointer restriction (kptr_restrict=2)",
        "Hide kernel addresses.",
        "kptr leaks defeat KASLR and enable ROP chain targeting.",
        "sysctl kernel.kptr_restrict=2.",
        Medium,
        "Threat",
        &["MITRE T1592"],
        linux,
        |c| sysctl_eq(c, "kernel.kptr_restrict", "2", false)
    );
    check!(
        reg,
        "LIN-TH-005",
        "dmesg restricted",
        "kernel.dmesg_restrict=1.",
        "Unrestricted dmesg leaks kernel addresses and security tooling state.",
        "sysctl kernel.dmesg_restrict=1.",
        Low,
        "Threat",
        &[],
        linux,
        |c| sysctl_eq(c, "kernel.dmesg_restrict", "1", true)
    );
    check!(reg, "LIN-TH-006", "ptrace scope restricted (Yama)", "kernel.yama.ptrace_scope >= 1.", "Unrestricted ptrace lets any process inject into same-user processes (credential theft from agents/ssh).", "sysctl kernel.yama.ptrace_scope=1 (or 2).", Medium, "Threat", &["MITRE T1055"], linux, |c| sysctl_num_at_least(c, "kernel.yama.ptrace_scope", 1));
    check!(
        reg,
        "LIN-TH-007",
        "perf_event_paranoid >= 2",
        "Restrict perf counters.",
        "perf interfaces have repeatedly leaked kernel memory.",
        "sysctl kernel.perf_event_paranoid=2 (or 3).",
        Low,
        "Threat",
        &[],
        linux,
        |c| sysctl_num_at_least(c, "kernel.perf_event_paranoid", 2)
    );
    check!(
        reg,
        "LIN-TH-008",
        "kexec_load disabled",
        "kernel.kexec_load_disabled=1.",
        "kexec permits live-patched kernel boot, defeating integrity.",
        "sysctl kernel.kexec_load_disabled=1.",
        Low,
        "Threat",
        &[],
        linux,
        |c| sysctl_eq(c, "kernel.kexec_load_disabled", "1", false)
    );
    check!(
        reg,
        "LIN-TH-009",
        "BPF JIT hardening",
        "net.core.bpf_jit_harden=2.",
        "JIT spraying enables code-exec from unprivileged eBPF.",
        "sysctl net.core.bpf_jit_harden=2.",
        Low,
        "Threat",
        &[],
        linux,
        |c| sysctl_eq(c, "net.core.bpf_jit_harden", "2", true)
    );
    check!(
        reg,
        "LIN-TH-010",
        "Kernel lockdown mode",
        "lockdown=confidentiality (or integrity).",
        "Lockdown blocks even root from tampering with the running kernel.",
        "Enable lockdown via Secure Boot + kernel config.",
        Medium,
        "Threat",
        &[],
        linux,
        lockdown_mode
    );
    check!(
        reg,
        "LIN-TH-011",
        "Module signature enforcement",
        "CONFIG_MODULE_SIG_FORCE.",
        "Unsigned module loading defeats all kernel integrity.",
        "Enable module signing + force in kernel config.",
        Medium,
        "Threat",
        &[],
        linux,
        module_sig_force
    );
    check!(
        reg,
        "LIN-TH-012",
        "SUID core dumps disabled",
        "fs.suid_dumpable=0.",
        "SUID core dumps leak privileged memory.",
        "sysctl fs.suid_dumpable=0.",
        Medium,
        "Threat",
        &[],
        linux,
        |c| sysctl_eq(c, "fs.suid_dumpable", "0", false)
    );
    // ---- persistence hunting ----
    check!(
        reg,
        "LIN-TH-013",
        "ld.so.preload clean",
        "/etc/ld.so.preload absent or empty.",
        "Preload backdoors hook libc for every process (classic rootkit step).",
        "Inspect and empty /etc/ld.so.preload; audit the file.",
        High,
        "Threat",
        &["MITRE T1546"],
        linux,
        ld_preload_clean
    );
    check!(
        reg,
        "LIN-TH-014",
        "systemd units reference sane paths",
        "No unit ExecStart in /tmp,/dev/shm,/proc.",
        "Temp-dir ExecStart is a hallmark of dropped persistence.",
        "Investigate and remove offending units; keep units under /etc and /usr.",
        High,
        "Threat",
        &["MITRE T1543"],
        linux,
        systemd_paths
    );
    check!(
        reg,
        "LIN-TH-015",
        "systemd timers sweep",
        "Timers reference existing binaries outside temp.",
        "Rogue timers re-arm malware.",
        "Review list-timers output against the package database.",
        Medium,
        "Threat",
        &["MITRE T1053"],
        linux,
        |c| systemd_temp_refs(c, "timer")
    );
    check!(
        reg,
        "LIN-TH-016",
        "udev rules clean",
        "No RUN+= programs in temp dirs.",
        "udev hooks execute as root on device events.",
        "Audit /etc/udev/rules.d RUN entries.",
        Medium,
        "Threat",
        &["MITRE T1546"],
        linux,
        udev_clean
    );
    check!(
        reg,
        "LIN-TH-017",
        "cron entries reference sane paths",
        "No cron command in /tmp,/dev/shm.",
        "Cron is the #1 legacy persistence slot.",
        "Audit all five cron locations; remove temp-dir entries.",
        High,
        "Threat",
        &["MITRE T1053"],
        linux,
        cron_temp_refs
    );
    check!(
        reg,
        "LIN-TH-018",
        "at jobs sweep",
        "No at-queue entries targeting temp dirs.",
        "at is a quieter persistence sibling of cron.",
        "Audit atq output.",
        Low,
        "Threat",
        &["MITRE T1053"],
        linux,
        at_sweep
    );
    check!(
        reg,
        "LIN-TH-019",
        "root authorized_keys absent or accounted",
        "Root SSH trust file must be deliberate.",
        "Adding a root authorized_keys is the easiest post-exploit persistence.",
        "Remove root key trust; admins sudo from named accounts.",
        High,
        "Threat",
        &["MITRE T1098"],
        linux,
        root_authorized_keys
    );
    check!(
        reg,
        "LIN-TH-020",
        "Shell rc tampering sweep",
        "Root/user rc files contain no temp-dir executions.",
        "rc-file backdoors run at every login.",
        "Review rc files for curl|sh, /tmp execs, base64 blobs.",
        Medium,
        "Threat",
        &["MITRE T1546"],
        linux,
        rc_sweep
    );
    check!(
        reg,
        "LIN-TH-021",
        "PAM modules package-owned",
        "Every pam .so maps to a package.",
        "Dropped PAM modules harvest every password on the host.",
        "dpkg -S/rpm -qf every module in /lib/security (needs root).",
        High,
        "Threat",
        &["MITRE T1556"],
        linux,
        pam_owned
    );
    check!(
        reg,
        "LIN-TH-022",
        "SUID inventory flagged",
        "SUID binaries outside package ownership are listed.",
        "Unknown SUID binaries are instant privilege escalation.",
        "Audit every SUID; remove unnecessary ones (needs root for full sweep).",
        High,
        "Threat",
        &["MITRE T1548"],
        linux,
        suid_inventory
    );
    check!(
        reg,
        "LIN-TH-023",
        "File capabilities inventory",
        "cap_setuid/cap_dac_override holders listed.",
        "Capabilities grant root-equivalent powers without SUID visibility.",
        "Audit getcap output; drop unneeded caps.",
        Medium,
        "Threat",
        &["MITRE T1548"],
        linux,
        cap_inventory
    );
    check!(
        reg,
        "LIN-TH-024",
        "Hidden uid-0 or duplicate accounts",
        "Beyond CIS: dupes hidden in aliases.",
        "Duplicate/hidden uid-0 accounts survive casual review.",
        "Reconcile passwd against expected account list.",
        High,
        "Threat",
        &["MITRE T1136"],
        linux,
        hidden_accounts
    );
    check!(
        reg,
        "LIN-TH-025",
        "sudoers NOPASSWD grants audited",
        "NOPASSWD: ALL grants listed.",
        "Passwordless full sudo turns any user compromise into root.",
        "Replace with command-scoped grants or require passwords.",
        High,
        "Threat",
        &["MITRE T1548"],
        linux,
        sudo_nopasswd
    );
    check!(
        reg,
        "LIN-TH-026",
        "OpenSSH version currency",
        "Server >= 9.8p1 or distro-patched.",
        "regreSSHion (CVE-2024-6387) class bugs affect older OpenSSH.",
        "Patch OpenSSH to current distro release.",
        Medium,
        "Threat",
        &["CVE-2024-6387"],
        linux,
        ssh_version
    );
}

fn linux(p: &crate::platform::PlatformInfo) -> bool {
    p.os == Os::Linux
}

fn userns_restricted(ctx: &mut ScanContext) -> CheckOutcome {
    let keys = [
        "kernel.unprivileged_userns_clone",
        "user.max_user_namespaces",
        "kernel.apparmor_restrict_unprivileged_userns",
    ];
    let mut log = Vec::new();
    let mut restricted = false;
    let mut any_value = false;
    for key in keys {
        match super::sysctl_value(ctx, key) {
            Some(v) => {
                any_value = true;
                log.push(FallbackAttempt {
                    source: format!("sysctl {key}"),
                    outcome: format!("value={v}"),
                });
                let is_restrict = if key == "kernel.apparmor_restrict_unprivileged_userns" {
                    v == "1"
                } else {
                    v == "0"
                };
                if is_restrict {
                    restricted = true;
                }
            }
            None => log.push(FallbackAttempt {
                source: format!("sysctl {key}"),
                outcome: "missing".into(),
            }),
        }
    }
    if restricted {
        ok(
            "unprivileged userns restricted (clone=0 / max=0 / apparmor-restricted)".into(),
            "/proc/sys".into(),
            "sysctl kernel.unprivileged_userns_clone user.max_user_namespaces".into(),
        )
    } else if !any_value {
        degraded_from_attempts(log, "user-namespace sysctls not readable on this kernel")
    } else {
        nok("unprivileged user namespaces are UNRESTRICTED — precondition of recent kernel LPE chains".into(), "/proc/sys".into(), "sysctl kernel.unprivileged_userns_clone".into())
    }
}

fn lockdown_mode(ctx: &mut ScanContext) -> CheckOutcome {
    if in_container(ctx) {
        return not_applicable(
            "kernel lockdown is a property of the shared host kernel; a container cannot set or observe it as its own control",
        );
    }
    if let Some(l) = ctx.read("/sys/kernel/security/lockdown") {
        let t = l.trim();
        if t.contains("[confidentiality]") {
            ok(
                "kernel lockdown: confidentiality".into(),
                "/sys/kernel/security/lockdown".into(),
                "cat /sys/kernel/security/lockdown".into(),
            )
        } else if t.contains("[integrity]") {
            ok(
                "kernel lockdown: integrity".into(),
                "/sys/kernel/security/lockdown".into(),
                "cat /sys/kernel/security/lockdown".into(),
            )
        } else {
            nok(
                format!("lockdown not active ({t})"),
                "/sys/kernel/security/lockdown".into(),
                "cat /sys/kernel/security/lockdown".into(),
            )
        }
    } else {
        degraded("lockdown status not exposed (not booted with lockdown)")
    }
}

fn module_sig_force(ctx: &mut ScanContext) -> CheckOutcome {
    if in_container(ctx) {
        return not_applicable(
            "module signature enforcement is a property of the shared host kernel; a container cannot load modules or enforce signing",
        );
    }
    let kernel = super::sysctl_value(ctx, "kernel.tainted").map(|_| ());
    let _ = kernel;
    if let Some(cfg) = ctx.read("/boot/config-6.8.0-49-generic") {
        // sample path only; real hosts vary
        return check_sig_cfg(&cfg);
    }
    if let Some(kv) = ctx.cmd("uname", &["-r"]) {
        if let Some(cfg) = ctx.read(&format!("/boot/config-{kv}")) {
            return check_sig_cfg(&cfg);
        }
    }
    degraded("kernel config not readable (needs /boot access); verify CONFIG_MODULE_SIG_FORCE")
}

fn check_sig_cfg(cfg: &str) -> CheckOutcome {
    let sig = cfg.lines().find(|l| l.contains("CONFIG_MODULE_SIG_FORCE"));
    let set = cfg.lines().find(|l| l.contains("CONFIG_MODULE_SIG="));
    match (sig, set) {
        (Some(s), _) if s.contains("=y") => ok(
            "CONFIG_MODULE_SIG_FORCE=y".into(),
            "/boot/config".into(),
            "grep MODULE_SIG /boot/config-$(uname -r)".into(),
        ),
        (_, Some(s)) if s.contains("=y") => nok(
            "module signing on but NOT forced".into(),
            "/boot/config".into(),
            "grep MODULE_SIG_FORCE".into(),
        ),
        _ => nok(
            "module signatures not enforced".into(),
            "/boot/config".into(),
            "grep MODULE_SIG".into(),
        ),
    }
}

fn ld_preload_clean(ctx: &mut ScanContext) -> CheckOutcome {
    match ctx.read("/etc/ld.so.preload") {
        None => ok(
            "/etc/ld.so.preload absent (clean)".into(),
            "/etc/ld.so.preload".into(),
            "cat /etc/ld.so.preload".into(),
        ),
        Some(c) => {
            let entries: Vec<&str> = c
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect();
            if entries.is_empty() {
                ok(
                    "ld.so.preload present but empty".into(),
                    "/etc/ld.so.preload".into(),
                    "cat /etc/ld.so.preload".into(),
                )
            } else {
                with_block(
                    nok(
                        format!("PRELOADED LIBRARIES: {}", entries.join(", ")),
                        "/etc/ld.so.preload".into(),
                        "cat /etc/ld.so.preload".into(),
                    ),
                    crate::checks::evidence_at(ctx, "/etc/ld.so.preload", entries[0]),
                )
            }
        }
    }
}

fn systemd_paths(ctx: &mut ScanContext) -> CheckOutcome {
    systemd_temp_refs(ctx, "service")
}

fn systemd_temp_refs(ctx: &mut ScanContext, unit_type: &str) -> CheckOutcome {
    let Some(out) = ctx.cmd(
        "systemctl",
        &[
            "list-units",
            &format!("--type={unit_type}"),
            "--no-legend",
            "--all",
        ],
    ) else {
        return degraded("systemctl not queryable (no systemd?)");
    };
    let mut suspicious = Vec::new();
    let units: Vec<String> = out
        .lines()
        .filter_map(|l| l.split_whitespace().next().map(str::to_string))
        .take(400)
        .collect();
    for unit in &units {
        if let Some(cat) = ctx.cmd("systemctl", &["cat", unit]) {
            for line in cat.lines() {
                let t = line.trim();
                if (t.starts_with("ExecStart") || t.starts_with("ExecStop") || t.contains("RUN+="))
                    && (t.contains("/tmp/") || t.contains("/dev/shm") || t.contains("/run/user"))
                {
                    suspicious.push(format!("{unit}: {}", crate::redact::redact(t)));
                }
            }
        }
    }
    if suspicious.is_empty() {
        ok(
            format!(
                "{} systemd {}s checked; no temp-dir exec",
                units.len(),
                unit_type
            ),
            "systemd".into(),
            "systemctl list-units; systemctl cat <unit>".into(),
        )
    } else {
        nok(
            suspicious.join("; "),
            "systemd".into(),
            "systemctl cat <unit>".into(),
        )
    }
}

fn udev_clean(ctx: &mut ScanContext) -> CheckOutcome {
    let mut bad = Vec::new();
    for d in ["/etc/udev/rules.d", "/lib/udev/rules.d"] {
        let listing = std::fs::read_dir(ctx.path(d));
        if let Ok(rd) = listing {
            for e in rd.filter_map(|e| e.ok()) {
                let name = e.file_name().to_string_lossy().to_string();
                let p = format!("{d}/{name}");
                if let Some(c) = ctx.read(&p) {
                    for line in c.lines() {
                        let t = line.trim();
                        if t.starts_with("RUN+=")
                            && (t.contains("/tmp/")
                                || t.contains("/dev/shm")
                                || t.contains("/home/"))
                        {
                            bad.push(format!("{p}: {}", crate::redact::redact(t)));
                        }
                    }
                }
            }
        }
    }
    if bad.is_empty() {
        ok(
            "udev rules clean (no temp-dir RUN entries)".into(),
            "/etc/udev/rules.d".into(),
            "grep -R 'RUN+=' /etc/udev/rules.d".into(),
        )
    } else {
        nok(
            bad.join("; "),
            "/etc/udev/rules.d".into(),
            "grep -R 'RUN+=' /etc/udev/rules.d".into(),
        )
    }
}

const TEMP_MARKERS: [&str; 4] = ["/tmp/", "/dev/shm", "/var/tmp/", "/run/user"];

fn looks_temp(cmdline: &str) -> bool {
    TEMP_MARKERS.iter().any(|m| cmdline.contains(m))
}

fn cron_temp_refs(ctx: &mut ScanContext) -> CheckOutcome {
    let mut sources = Vec::new();
    for p in ["/etc/crontab", "/etc/cron.d"] {
        if ctx.exists(p) {
            sources.push(p.to_string());
        }
    }
    let mut bad = Vec::new();
    for p in &sources {
        if p.ends_with("cron.d") {
            let rd = std::fs::read_dir(ctx.path(p));
            if let Ok(rd) = rd {
                for e in rd.filter_map(|e| e.ok()) {
                    let f = format!("{}/{}", p, e.file_name().to_string_lossy());
                    if let Some(c) = ctx.read(&f) {
                        scan_cron(&c, &f, &mut bad);
                    }
                }
            }
        } else if let Some(c) = ctx.read(p) {
            scan_cron(&c, p, &mut bad);
        }
    }
    if bad.is_empty() {
        ok(
            format!("cron files clean across {} sources", sources.len()),
            "/etc/cron*".into(),
            "grep -R -E '/tmp|/dev/shm' /etc/cron*".into(),
        )
    } else {
        nok(
            bad.join("; "),
            "/etc/cron*".into(),
            "grep -R -E '/tmp|/dev/shm' /etc/cron*".into(),
        )
    }
}

fn scan_cron(content: &str, from: &str, bad: &mut Vec<String>) {
    for line in content.lines() {
        let t = line.trim();
        if t.starts_with('#') || t.is_empty() {
            continue;
        }
        // cron line: schedule fields then command (command = 6th+ field for crontab, varies)
        let cmd_start = t.char_indices().nth(0);
        let _ = cmd_start;
        if looks_temp(t) {
            bad.push(format!("{from}: {}", crate::redact::redact(t)));
        }
    }
}

fn at_sweep(ctx: &mut ScanContext) -> CheckOutcome {
    if let Some(out) = ctx.cmd("at", &["-l"]) {
        if out.trim().is_empty() {
            ok("no at jobs queued".into(), "at -l".into(), "at -l".into())
        } else {
            let flagged: Vec<&str> = out.lines().filter(|l| looks_temp(l)).collect();
            if flagged.is_empty() {
                ok(
                    format!("{} at jobs queued; none temp-dir", out.lines().count()),
                    "at -l".into(),
                    "at -l".into(),
                )
            } else {
                nok(
                    format!("at jobs referencing temp dirs: {}", flagged.join("; ")),
                    "at -l".into(),
                    "at -l".into(),
                )
            }
        }
    } else {
        degraded("at not installed (clean by absence)")
    }
}

fn root_authorized_keys(ctx: &mut ScanContext) -> CheckOutcome {
    match ctx.read("/root/.ssh/authorized_keys") {
        None => ok(
            "/root/.ssh/authorized_keys absent".into(),
            "/root/.ssh/authorized_keys".into(),
            "sudo ls /root/.ssh".into(),
        ),
        Some(c) => {
            let keys = c
                .lines()
                .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
                .count();
            nok(
                format!(
                    "root authorized_keys contains {keys} key(s) — must be deliberate and reviewed"
                ),
                "/root/.ssh/authorized_keys".into(),
                "sudo cat /root/.ssh/authorized_keys | wc -l".into(),
            )
        }
    }
}

fn rc_sweep(ctx: &mut ScanContext) -> CheckOutcome {
    let mut bad = Vec::new();
    for p in [
        "/root/.bashrc",
        "/root/.profile",
        "/etc/profile",
        "/etc/bash.bashrc",
    ] {
        if let Some(c) = ctx.read(p) {
            for line in c.lines() {
                let t = line.trim();
                if t.starts_with('#') {
                    continue;
                }
                if looks_temp(t) || t.contains("curl") && t.contains('|') && t.contains("sh") {
                    bad.push(format!("{p}: {}", crate::redact::redact(t)));
                }
            }
        }
    }
    if bad.is_empty() {
        ok(
            "shell rc files clean of temp-dir/curl-pipe execution".into(),
            "rc files".into(),
            "grep -E '/tmp|curl.*\\|' /root/.bashrc /etc/profile".into(),
        )
    } else {
        nok(bad.join("; "), "rc files".into(), "see evidence".into())
    }
}

/// PAM module directories for the running architecture, most specific
/// first, then distro-generic fallbacks. Driven by `ctx.platform.arch` so
/// arm64/armv7 hosts are not assumed to be x86_64.
fn pam_module_dirs(arch: &str) -> Vec<&'static str> {
    let a = arch.to_ascii_lowercase();
    let mut dirs: Vec<&'static str> = Vec::new();
    if a.contains("x86_64") || a.contains("amd64") {
        dirs.push("/lib/x86_64-linux-gnu/security");
        dirs.push("/usr/lib/x86_64-linux-gnu/security");
    } else if a.contains("aarch64") || a.contains("arm64") {
        dirs.push("/lib/aarch64-linux-gnu/security");
        dirs.push("/usr/lib/aarch64-linux-gnu/security");
    } else if a.starts_with("arm") || a.contains("armv") {
        dirs.push("/lib/arm-linux-gnueabihf/security");
        dirs.push("/usr/lib/arm-linux-gnueabihf/security");
    } else if a.contains("i686") || a == "x86" {
        dirs.push("/lib/i386-linux-gnu/security");
        dirs.push("/usr/lib/i386-linux-gnu/security");
    }
    dirs.push("/lib/security");
    dirs.push("/usr/lib/security");
    dirs.push("/lib64/security");
    dirs
}

fn pam_owned(ctx: &mut ScanContext) -> CheckOutcome {
    let dirs = pam_module_dirs(&ctx.platform.arch);
    let target = match dirs.into_iter().find(|d| ctx.exists(*d)) {
        Some(d) => d,
        None => return degraded("PAM module directory not found"),
    };
    let rd = std::fs::read_dir(ctx.path(target));
    let mut unknown = Vec::new();
    let mut checked = 0;
    if let Ok(rd) = rd {
        for e in rd.filter_map(|e| e.ok()) {
            let name = e.file_name().to_string_lossy().to_string();
            if !name.ends_with(".so") {
                continue;
            }
            checked += 1;
            let owned = match ctx.platform.family {
                crate::platform::DistroFamily::Debian => ctx
                    .cmd("dpkg-query", &["-S", &format!("{target}/{name}")])
                    .is_some(),
                _ => ctx
                    .cmd("rpm", &["-qf", &format!("{target}/{name}")])
                    .map(|o| !o.contains("not owned"))
                    .unwrap_or(false),
            };
            if !owned {
                unknown.push(name);
            }
        }
    }
    if checked == 0 {
        return degraded("no PAM modules enumerable (needs root?)");
    }
    if unknown.is_empty() {
        ok(
            format!("{checked} PAM modules all package-owned"),
            target.into(),
            format!("dpkg -S {target}/*.so").into(),
        )
    } else {
        nok(
            format!(
                "PAM modules NOT owned by any package: {}",
                unknown.join(", ")
            ),
            target.into(),
            "see evidence".into(),
        )
    }
}

fn suid_inventory(ctx: &mut ScanContext) -> CheckOutcome {
    // bounded walk of common binary dirs (full / sweep needs root and time)
    let mut suids = Vec::new();
    for dir in [
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/bin",
        "/sbin",
    ] {
        if let Ok(rd) = std::fs::read_dir(ctx.path(dir)) {
            for e in rd.filter_map(|e| e.ok()) {
                let p = format!("{}/{}", dir, e.file_name().to_string_lossy());
                if let Some(mode) = ctx.unix_mode(&p) {
                    if mode & 0o4000 != 0 {
                        suids.push(p);
                    }
                }
            }
        }
    }
    if suids.is_empty() {
        return degraded("no SUID binaries enumerable in standard dirs (unprivileged stat may mask; run with --elevate)");
    }
    let mut unknown = Vec::new();
    for p in &suids {
        let owned = match ctx.platform.family {
            crate::platform::DistroFamily::Debian => ctx.cmd("dpkg-query", &["-S", p]).is_some(),
            _ => ctx
                .cmd("rpm", &["-qf", p])
                .map(|o| !o.contains("not owned"))
                .unwrap_or(false),
        };
        if !owned {
            unknown.push(p.clone());
        }
    }
    let evd = format!(
        "{} SUID binaries in standard dirs; {} not package-owned: {}",
        suids.len(),
        unknown.len(),
        if unknown.is_empty() {
            "none".into()
        } else {
            unknown.join(", ")
        }
    );
    if unknown.is_empty() {
        ok(
            evd,
            "filesystem".into(),
            "find /usr -perm -4000 2>/dev/null".into(),
        )
    } else {
        nok(evd, "filesystem".into(), "find / -perm -4000".into())
    }
}

fn cap_inventory(ctx: &mut ScanContext) -> CheckOutcome {
    if let Some(out) = ctx.cmd("getcap", &["-r", "/usr", "/bin", "/sbin"]) {
        let interesting = out
            .lines()
            .filter(|l| {
                l.contains("cap_setuid")
                    || l.contains("cap_dac_override")
                    || l.contains("cap_sys_admin")
            })
            .count();
        let total = out.lines().count();
        if interesting > 0 {
            nok(format!("{total} capability holders, {interesting} with dangerous caps (setuid/dac_override/sys_admin)"), "getcap".into(), "getcap -r / 2>/dev/null".into())
        } else {
            ok(
                format!("{total} capability holders, none dangerous"),
                "getcap".into(),
                "getcap -r /".into(),
            )
        }
    } else {
        degraded("getcap not available")
    }
}

fn hidden_accounts(ctx: &mut ScanContext) -> CheckOutcome {
    let Some(passwd) = ctx.read("/etc/passwd") else {
        return degraded("/etc/passwd not readable");
    };
    let mut uid_counts = std::collections::HashMap::new();
    let mut names = Vec::new();
    for line in passwd.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() >= 3 {
            if f[2] == "0" {
                names.push(f[0].to_string());
            }
            *uid_counts.entry(f[2].to_string()).or_insert(0) += 1;
        }
    }
    let uid0: Vec<String> = names.iter().filter(|n| *n != "root").cloned().collect();
    let dups: Vec<String> = uid_counts
        .iter()
        .filter(|(_, c)| **c > 1)
        .map(|(u, _)| u.clone())
        .collect();
    if uid0.is_empty() && dups.is_empty() {
        ok(
            "no hidden uid-0 and no duplicate UID accounts".into(),
            "/etc/passwd".into(),
            "awk -F: '$3==0' /etc/passwd".into(),
        )
    } else {
        let mut parts = Vec::new();
        if !uid0.is_empty() {
            parts.push(format!("non-root uid-0: {}", uid0.join(", ")));
        }
        if !dups.is_empty() {
            parts.push(format!("duplicate UIDs: {}", dups.join(", ")));
        }
        nok(
            parts.join("; "),
            "/etc/passwd".into(),
            "awk -F: '{print $3}' /etc/passwd | sort | uniq -d".into(),
        )
    }
}

fn sudo_nopasswd(ctx: &mut ScanContext) -> CheckOutcome {
    let Some(sudoers) = ctx.read("/etc/sudoers") else {
        return degraded("/etc/sudoers not readable (needs root — run with --elevate)");
    };
    let mut grants = Vec::new();
    let mut sources = vec![("/etc/sudoers".to_string(), sudoers)];
    let rd = std::fs::read_dir(ctx.path("/etc/sudoers.d"));
    if let Ok(rd) = rd {
        for e in rd.filter_map(|e| e.ok()) {
            let f = format!("/etc/sudoers.d/{}", e.file_name().to_string_lossy());
            if let Some(c) = ctx.read(&f) {
                sources.push((f, c));
            }
        }
    }
    for (from, c) in &sources {
        for line in c.lines() {
            let t = line.trim();
            if t.starts_with('#') {
                continue;
            }
            if t.contains("NOPASSWD:") && (t.contains("ALL") || t.contains("(ALL)")) {
                grants.push(format!("{from}: {}", crate::redact::redact(t)));
            }
        }
    }
    if grants.is_empty() {
        ok(
            "no NOPASSWD: ALL sudo grants".into(),
            "/etc/sudoers".into(),
            "sudo grep -R NOPASSWD /etc/sudoers /etc/sudoers.d".into(),
        )
    } else {
        nok(
            grants.join("; "),
            "/etc/sudoers".into(),
            "sudo grep -R NOPASSWD /etc/sudoers*".into(),
        )
    }
}

fn ssh_version(ctx: &mut ScanContext) -> CheckOutcome {
    let v = ctx.cmd("sshd", &["-V"]).or_else(|| ctx.cmd("ssh", &["-V"]));
    let Some(v) = v else {
        return degraded("OpenSSH version not queryable");
    };
    // OpenSSH_9.6p1 Ubuntu-3ubuntu13 ...
    let ver = v
        .split_whitespace()
        .find(|t| t.starts_with("OpenSSH_"))
        .map(|t| t.trim_start_matches("OpenSSH_").to_string())
        .unwrap_or_default();
    let (major, minor) = parse_version(&ver);
    match (major, minor) {
        (Some(maj), Some(min)) if (maj as f64 + min as f64 / 100.0) >= 9.08 => {
            ok(format!("OpenSSH {ver}"), "sshd -V".into(), "sshd -V".into())
        }
        (Some(_), Some(_)) => nok(
            format!(
                "OpenSSH {ver} < 9.8p1 — verify distro backports (regreSSHion CVE-2024-6387 class)",
                ver = ver
            ),
            "sshd -V".into(),
            "sshd -V; check distro advisories".into(),
        ),
        _ => degraded(&format!("OpenSSH version unparseable: {v}")),
    }
}

fn parse_version(v: &str) -> (Option<u32>, Option<u32>) {
    let core = v.split(' ').next().unwrap_or("");
    let mut parts = core.split(|c| c == 'p' || c == '.');
    let maj = parts.next().and_then(|p| p.parse().ok());
    let min = parts.next().and_then(|p| p.parse().ok());
    (maj, min)
}
