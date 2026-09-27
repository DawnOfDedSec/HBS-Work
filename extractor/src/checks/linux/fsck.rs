//! LIN-FS: filesystem & partition hardening (CIS 1.1.x).

use super::{has_opt, mount_opts};
use crate::checks::{degraded, degraded_from_attempts, in_container, nok, not_applicable, ok};
use crate::context::ScanContext;
use crate::model::{CheckOutcome, FallbackAttempt, RegisteredCheck};

pub fn register(reg: &mut Vec<RegisteredCheck>) {
    use crate::check;
    check!(reg, "LIN-FS-001", "/tmp configured as separate mount", "A dedicated /tmp (partition or tmpfs) prevents resource-exhaustion of / and confines temp-file attacks.", "Shared-root /tmp lets temp fills take down the whole filesystem and eases symlink attacks against system files.", "Configure /tmp as its own partition or tmpfs mount in /etc/fstab.", Medium, "Filesystem", &["CIS 1.1.1"], linux, tmp_separate);
    check!(
        reg,
        "LIN-FS-002",
        "/tmp mounted with nodev",
        "nodev prevents device files in world-writable /tmp from being used to reach raw devices.",
        "Device nodes in /tmp give unprivileged users raw device access (disk/memory).",
        "Add nodev to the /tmp mount options in /etc/fstab.",
        Medium,
        "Filesystem",
        &["CIS 1.1.2"],
        linux,
        |c| opt_check(c, "/tmp", "nodev")
    );
    check!(
        reg,
        "LIN-FS-003",
        "/tmp mounted with nosuid",
        "nosuid prevents setuid binaries planted in /tmp from elevating.",
        "SUID payloads dropped in /tmp are a classic local privesc.",
        "Add nosuid to the /tmp mount options.",
        Medium,
        "Filesystem",
        &["CIS 1.1.3"],
        linux,
        |c| opt_check(c, "/tmp", "nosuid")
    );
    check!(
        reg,
        "LIN-FS-004",
        "/tmp mounted with noexec",
        "noexec prevents executing binaries directly from /tmp.",
        "Payloads downloaded to /tmp run directly without it.",
        "Add noexec to /tmp options where applications allow it.",
        Low,
        "Filesystem",
        &["CIS 1.1.4"],
        linux,
        |c| opt_check(c, "/tmp", "noexec")
    );
    check!(
        reg,
        "LIN-FS-005",
        "/dev/shm mounted with nodev,nosuid,noexec",
        "Shared memory must not allow devices, SUID or execution.",
        "Compilers/wrappers and container escapes routinely abuse /dev/shm.",
        "Mount /dev/shm tmpfs with nodev,nosuid,noexec.",
        Medium,
        "Filesystem",
        &["CIS 1.1.6-8"],
        linux,
        devshm_opts
    );
    check!(
        reg,
        "LIN-FS-006",
        "/var configured as separate mount",
        "/var holds logs, spools and caches that can fill disks.",
        "Full / on a shared mount starves the OS and audit trail.",
        "Give /var its own partition.",
        Low,
        "Filesystem",
        &["CIS 1.1.9"],
        linux,
        |c| separate_check(c, "/var", "CIS 1.1.9")
    );
    check!(
        reg,
        "LIN-FS-007",
        "/var/tmp configured as separate mount",
        "/var/tmp persists across reboots and needs containment.",
        "Persistent temp storage outside a dedicated mount evades size/option controls.",
        "Mount /var/tmp separately with nodev,nosuid,noexec.",
        Low,
        "Filesystem",
        &["CIS 1.1.11"],
        linux,
        |c| separate_check(c, "/var/tmp", "CIS 1.1.11")
    );
    check!(
        reg,
        "LIN-FS-008",
        "/var/tmp mounted with nodev,nosuid,noexec",
        "Same rationale as /tmp options, for the persistent variant.",
        "See LIN-FS-002..004.",
        "Add nodev,nosuid,noexec to /var/tmp.",
        Medium,
        "Filesystem",
        &["CIS 1.1.12-14"],
        linux,
        var_tmp_opts
    );
    check!(
        reg,
        "LIN-FS-009",
        "/home configured as separate mount",
        "User data must not share the root filesystem.",
        "User fills and malicious file floods take down the OS with shared /home.",
        "Give /home its own partition with nodev.",
        Low,
        "Filesystem",
        &["CIS 1.1.15"],
        linux,
        |c| separate_check(c, "/home", "CIS 1.1.15")
    );
    check!(
        reg,
        "LIN-FS-010",
        "/home mounted with nodev",
        "Device files should never live in user homes.",
        "Users planting device nodes in $HOME reach raw devices.",
        "Add nodev to /home options.",
        Medium,
        "Filesystem",
        &["CIS 1.1.16"],
        linux,
        |c| opt_check(c, "/home", "nodev")
    );
    check!(reg, "LIN-FS-011", "/etc/fstab options match live mounts", "fstab entries for temp filesystems should carry the hardening options so reboots preserve them.", "Options applied only at runtime vanish on reboot.", "Mirror nodev/nosuid/noexec into /etc/fstab entries.", Low, "Filesystem", &["CIS 1.1.1"], linux, fstab_consistency);
    check!(
        reg,
        "LIN-FS-012",
        "Bootloader config permissions",
        "grub.cfg must be root-owned and not group/world writable.",
        "Editable bootloader config = kernel-parameter tampering (init=/bin/sh at boot).",
        "chown root:root <grub.cfg>; chmod og-wx (target 0600).",
        High,
        "Filesystem",
        &["CIS 1.4.1"],
        linux,
        bootloader_perms
    );
    check!(
        reg,
        "LIN-FS-013",
        "Bootloader password set",
        "A grub password blocks interactive boot-parameter editing.",
        "Physical/console attackers drop to a root shell via kernel args.",
        "Set password_pbkdf2 in grub config (grub-mkpasswd-pbkdf2).",
        High,
        "Filesystem",
        &["CIS 1.4.3"],
        linux,
        bootloader_password
    );
    check!(
        reg,
        "LIN-FS-014",
        "Core dump storage restricted",
        "SUID binaries must not dump core; core_pattern must not pipe to arbitrary programs.",
        "Cores leak secrets from process memory; pipe-to-program is code execution as root.",
        "Set fs.suid_dumpable=0 and a safe core_pattern (or systemd coredump).",
        Medium,
        "Filesystem",
        &["CIS 1.5.1", "1.5.2"],
        linux,
        core_dumps
    );
    check!(
        reg,
        "LIN-FS-015",
        "swap devices encrypted where present",
        "Swap should be encrypted or absent on sensitive hosts.",
        "Memory pages holding secrets persist in plaintext swap.",
        "Encrypt swap (random at boot) or disable if infeasible.",
        Low,
        "Filesystem",
        &["CIS 1.1.10"],
        linux,
        swap_encrypted
    );
}

fn linux(p: &crate::platform::PlatformInfo) -> bool {
    p.os == crate::platform::Os::Linux
}

fn tmp_separate(ctx: &mut ScanContext) -> CheckOutcome {
    separate_check(ctx, "/tmp", "CIS 1.1.1")
}

fn container_mount_reason(path: &str) -> String {
    format!(
        "{path} partition layout is a host-level property; container mounts are namespaces, not separate partitions"
    )
}

fn separate_check(ctx: &mut ScanContext, path: &str, cis: &str) -> CheckOutcome {
    if in_container(ctx) {
        return not_applicable(&container_mount_reason(path));
    }
    match mount_opts(ctx, path) {
        Some(opts) => ok(
            format!("{path} is a separate mount ({opts})"),
            "/proc/mounts".into(),
            format!("findmnt {path}"),
        ),
        None => {
            if ctx.read("/proc/mounts").is_some() {
                nok(
                    format!("{path} is NOT a separate mount (shares root filesystem)"),
                    "/proc/mounts".into(),
                    format!("findmnt --kernel {path} # cited by {cis}"),
                )
            } else {
                degraded_from_attempts(
                    vec![FallbackAttempt {
                        source: "/proc/mounts".into(),
                        outcome: "missing".into(),
                    }],
                    "/proc/mounts missing",
                )
            }
        }
    }
}

fn opt_check(ctx: &mut ScanContext, path: &str, opt: &str) -> CheckOutcome {
    if in_container(ctx) {
        return not_applicable(&container_mount_reason(path));
    }
    match mount_opts(ctx, path) {
        Some(opts) if has_opt(&opts, opt) => ok(
            format!("{path} mounted with {opt} (options: {opts})"),
            "/proc/mounts".into(),
            format!("findmnt {path} -o OPTIONS"),
        ),
        Some(opts) => nok(
            format!("{path} mounted WITHOUT {opt} (options: {opts})"),
            "/proc/mounts".into(),
            format!("findmnt {path} -o OPTIONS"),
        ),
        None => degraded(&format!(
            "{path} is not a separate mount; {opt} does not apply"
        )),
    }
}

fn devshm_opts(ctx: &mut ScanContext) -> CheckOutcome {
    multi_opt(ctx, "/dev/shm", &["nodev", "nosuid", "noexec"])
}

fn var_tmp_opts(ctx: &mut ScanContext) -> CheckOutcome {
    multi_opt(ctx, "/var/tmp", &["nodev", "nosuid", "noexec"])
}

fn multi_opt(ctx: &mut ScanContext, path: &str, opts: &[&str]) -> CheckOutcome {
    if in_container(ctx) {
        return not_applicable(&container_mount_reason(path));
    }
    match mount_opts(ctx, path) {
        Some(mount) => {
            let missing: Vec<&str> = opts
                .iter()
                .copied()
                .filter(|o| !has_opt(&mount, o))
                .collect();
            if missing.is_empty() {
                ok(
                    format!("{path} options: {mount}"),
                    "/proc/mounts".into(),
                    format!("findmnt {path}"),
                )
            } else {
                nok(
                    format!(
                        "{path} missing options: {} (has: {mount})",
                        missing.join(",")
                    ),
                    "/proc/mounts".into(),
                    format!("findmnt {path} -o OPTIONS"),
                )
            }
        }
        None => degraded(&format!(
            "{path} not a separate mount; options do not apply"
        )),
    }
}

fn fstab_consistency(ctx: &mut ScanContext) -> CheckOutcome {
    if in_container(ctx) {
        return not_applicable(
            "/etc/fstab partition hardening is a host-level property; a container does not own the host fstab",
        );
    }
    let mut log = Vec::new();
    let Some(fstab) = ctx.read("/etc/fstab") else {
        log.push(FallbackAttempt {
            source: "/etc/fstab".into(),
            outcome: "missing".into(),
        });
        return degraded_from_attempts(log, "/etc/fstab missing");
    };
    log.push(FallbackAttempt {
        source: "/etc/fstab".into(),
        outcome: format!(
            "{} entries",
            fstab.lines().filter(|l| !l.starts_with('#')).count()
        )
        .into(),
    });
    let mut problems = Vec::new();
    for path in ["/tmp", "/var/tmp", "/dev/shm"] {
        let live = mount_opts(ctx, path);
        let entry = fstab.lines().find(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            f.len() >= 4 && f[1] == path && !l.starts_with('#')
        });
        match (live, entry) {
            (Some(_), None) => problems.push(format!(
                "{path} mounted but absent from fstab (options lost on reboot)"
            )),
            (Some(_), Some(e)) => {
                let opts = e.split_whitespace().nth(3).unwrap_or("");
                for o in ["nodev", "nosuid", "noexec"] {
                    if !has_opt(opts, o) && path != "/dev/shm" && o == "noexec" {
                        continue; // noexec optional outside tmp
                    }
                }
            }
            _ => {}
        }
    }
    if problems.is_empty() {
        ok(
            "fstab consistent with live mounts for temp filesystems".into(),
            "/etc/fstab".into(),
            "cat /etc/fstab".into(),
        )
    } else {
        nok(
            problems.join("; "),
            "/etc/fstab".into(),
            "diff live mounts against /etc/fstab".into(),
        )
    }
}

fn bootloader_perms(ctx: &mut ScanContext) -> CheckOutcome {
    if in_container(ctx) {
        return not_applicable(
            "the bootloader belongs to the host; a container has no grub.cfg to protect",
        );
    }
    let candidates = [
        "/boot/grub2/grub.cfg",
        "/boot/grub/grub.cfg",
        "/boot/grub2/user.cfg",
    ];
    let Some(path) = super::first_existing(ctx, &candidates) else {
        return degraded("no grub.cfg found (systemd-boot or non-grub host)");
    };
    let Some(mode) = ctx.unix_mode(path) else {
        return degraded(&format!(
            "{path} metadata unreadable; check manually: stat {path}"
        ));
    };
    let world_writable = mode & 0o002 != 0;
    let group_writable = mode & 0o020 != 0;
    if world_writable || group_writable {
        nok(
            format!("{path} mode {mode:o} is group/world writable"),
            path.into(),
            format!("stat -c '%a' {path}"),
        )
    } else {
        ok(
            format!(
                "{path} mode {mode:o} (not group/world writable)",
                mode = mode
            ),
            path.into(),
            format!("stat -c '%a' {path}"),
        )
    }
}

fn bootloader_password(ctx: &mut ScanContext) -> CheckOutcome {
    if in_container(ctx) {
        return not_applicable(
            "the bootloader belongs to the host; a container has no bootloader password to set",
        );
    }
    let candidates = ["/boot/grub2/grub.cfg", "/boot/grub/grub.cfg"];
    let mut log = Vec::new();
    let Some(path) = super::first_existing(ctx, &candidates) else {
        return CheckOutcome {
            status: crate::model::Status::NotApplicable,
            evidence: "no grub.cfg on this host (non-grub or container boot)".into(),
            location: String::new(),
            repro: String::new(),
            recommendation_override: None,
            degraded_reason: None,
            fallback_log: Vec::new(),
            evidence_blocks: Vec::new(),
        };
    };
    let Some(cfg) = ctx.read(path) else {
        log.push(FallbackAttempt {
            source: path.into(),
            outcome: "unreadable".into(),
        });
        return degraded_from_attempts(log, &format!("{path} unreadable"));
    };
    if cfg.contains("password_pbkdf2") || cfg.contains("password bcrypt") {
        ok(
            "bootloader password present".into(),
            path.into(),
            format!("grep password {path}"),
        )
    } else {
        nok(
            "no bootloader password set - console users can edit kernel parameters".into(),
            path.into(),
            format!("grep -c password {path}"),
        )
    }
}

fn core_dumps(ctx: &mut ScanContext) -> CheckOutcome {
    let mut findings = Vec::new();
    let dumpable = super::sysctl_value(ctx, "fs.suid_dumpable");
    match dumpable.as_deref() {
        Some("0") => findings.push("fs.suid_dumpable=0".into()),
        Some(v) => findings.push(format!("fs.suid_dumpable={v} (expected 0)")),
        None => findings.push("fs.suid_dumpable unknown".into()),
    }
    if let Some(pattern) = ctx.read("/proc/sys/kernel/core_pattern") {
        let p = pattern.trim();
        if p.starts_with('|') && !p.contains("systemd-coredump") {
            findings.push(format!("core_pattern pipes to program: {p}"));
        } else {
            findings.push(format!("core_pattern={p}"));
        }
    }
    let bad = findings
        .iter()
        .any(|f| f.contains("expected 0") || f.contains("pipes to"));
    if bad {
        nok(
            findings.join("; "),
            "/proc/sys/fs/suid_dumpable, core_pattern".into(),
            "sysctl fs.suid_dumpable; cat /proc/sys/kernel/core_pattern".into(),
        )
    } else {
        ok(
            findings.join("; "),
            "/proc/sys/fs/suid_dumpable".into(),
            "sysctl fs.suid_dumpable".into(),
        )
    }
}

fn swap_encrypted(ctx: &mut ScanContext) -> CheckOutcome {
    if in_container(ctx) {
        return not_applicable(
            "swap is configured by the host kernel; a container has no swap device of its own",
        );
    }
    if let Some(mounts) = ctx.read("/proc/swaps") {
        let swaps: Vec<&str> = mounts
            .lines()
            .skip(1)
            .filter(|l| !l.trim().is_empty())
            .collect();
        if swaps.is_empty() {
            return ok(
                "no swap configured".into(),
                "/proc/swaps".into(),
                "cat /proc/swaps".into(),
            );
        }
        let encrypted = swaps
            .iter()
            .all(|s| s.contains("/dev/mapper/") || s.contains("crypt"));
        if encrypted {
            ok(
                format!("swap encrypted: {}", swaps.len()),
                "/proc/swaps".into(),
                "cat /proc/swaps".into(),
            )
        } else {
            nok(
                format!("plaintext swap devices present: {}", swaps.join("; ")),
                "/proc/swaps".into(),
                "cat /proc/swaps".into(),
            )
        }
    } else {
        degraded("/proc/swaps not readable; swap state unknown")
    }
}
