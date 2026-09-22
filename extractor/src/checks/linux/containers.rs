//! LIN-TH (part 2): container escape surfaces, EOL detection and
//! patch currency (supply-chain lessons from the xz backdoor era).

use crate::checks::{degraded, in_container, nok, not_applicable, ok};
use crate::context::ScanContext;
use crate::model::{CheckOutcome, RegisteredCheck};
use crate::platform::Os;

pub fn register(reg: &mut Vec<RegisteredCheck>) {
    use crate::check;
    check!(reg, "LIN-TH-027", "docker group membership", "Users in docker must be deliberate (docker = root).", "docker group members escalate to root via socket mounts.", "Remove casual users from docker group.", High, "Threat", &["MITRE T1611"], linux, docker_group);
    check!(reg, "LIN-TH-028", "Container runtime socket permissions", "docker/containerd sockets must be 0660 root:daemon.", "World-writable runtime sockets let anyone spawn privileged containers.", "chmod 660 /var/run/docker.sock; strict ACLs.", High, "Threat", &["MITRE T1611"], linux, runtime_sockets);
    check!(reg, "LIN-TH-029", "Docker daemon not running privileged", "No --privileged daemon flags.", "Privileged daemons hand containers the host kernel.", "Remove --privileged and insecure flags from daemon config.", High, "Threat", &["MITRE T1611"], linux, daemon_privileged);
    check!(reg, "LIN-TH-030", "/proc mounted with hidepid where supported", "hidepid=2 restricts process visibility.", "Cross-user process snooping leaks env vars and secrets.", "Mount /proc with hidepid=2 (where supported).", Low, "Threat", &[], linux, hidepid);
    check!(reg, "LIN-TH-031", "No privileged containers", "docker ps + inspect shows none privileged.", "Privileged containers ARE the host.", "Drop --privileged from every container.", High, "Threat", &["MITRE T1611"], linux, privileged_containers);
    check!(reg, "LIN-TH-032", "Distro not end-of-life", "OS within vendor support.", "EOL systems (CentOS 7 etc.) receive no security patches — permanent exposure.", "Migrate to a supported release before vendor EOL.", High, "Threat", &[], linux, distro_eol);
    check!(reg, "LIN-TH-033", "Security patch backlog bounded", "Pending security updates enumerated.", "Known-CVE exposure grows with backlog age.", "Patch within policy; clear backlogs over 30 days.", Medium, "Threat", &["CIS 1.9"], linux, patch_backlog);
    check!(reg, "LIN-TH-034", "Kernel near current distro release", "Running kernel close to latest installed.", "Old running kernels retain patched CVEs (reboot debt).", "Reboot into the latest installed kernel.", Low, "Threat", &[], linux, kernel_currency);
    check!(reg, "LIN-TH-035", "OpenSSH/service versions not end-of-life", "Key services within supported versions.", "EOL OpenSSH/nginx builds accumulate unpatched CVEs.", "Track and upgrade key services on vendor timelines.", Low, "Threat", &["CVE-2024-6387"], linux, service_currency);
    check!(reg, "LIN-TH-036", "Third-party repositories reviewed", "Configured non-official repos listed.", "Every third-party repo is supply-chain trust (xz lesson).", "Minimize repos; pin and audit keys.", Medium, "Threat", &["MITRE T1195"], linux, third_party_repos);
    check!(reg, "LIN-TH-037", "Kernel cmdline free of debug escapes", "No init=/bin/sh or debug boot flags in production.", "init= shells bypass every control at boot.", "Remove debug/init overrides from bootloader config.", Medium, "Threat", &[], linux, cmdline_clean);
    check!(reg, "LIN-TH-038", "ld.so.conf.d entries package-owned", "No stray library search paths.", "Dropped .conf entries hijack library resolution (xz-style).", "Audit /etc/ld.so.conf.d against packages.", Medium, "Threat", &["MITRE T1574"], linux, ldso_conf_owned);
    check!(reg, "LIN-TH-039", "xz/liblzma version outside backdoor band", "Not 5.6.0/5.6.1.", "CVE-2024-3094 shipped a targeted sshd backdoor in those versions.", "Upgrade/downgrade xz outside the affected band.", High, "Threat", &["CVE-2024-3094"], linux, xz_backdoor);
    check!(reg, "LIN-TH-040", "Package integrity spot check", "Core package verification (rpm -V / debsums).", "Silent file tampering signals compromise long before alerts.", "Run verification periodically; investigate mismatches.", Medium, "Threat", &["MITRE T1565"], linux, pkg_integrity);
}

fn linux(p: &crate::platform::PlatformInfo) -> bool {
    p.os == Os::Linux
}

fn docker_group(ctx: &mut ScanContext) -> CheckOutcome {
    if let Some(group) = ctx.read("/etc/group") {
        let members: Vec<&str> = group
            .lines()
            .filter(|l| l.starts_with("docker:") || l.starts_with("podman:"))
            .filter_map(|l| l.split(':').nth(3))
            .flat_map(|m| m.split(','))
            .filter(|m| !m.is_empty())
            .collect();
        if members.is_empty() {
            ok("no interactive users in docker/podman group".into(), "/etc/group".into(), "grep docker /etc/group".into())
        } else {
            nok(format!("docker-equivalent group members: {}", members.join(", ")), "/etc/group".into(), "grep -E '^(docker|podman):' /etc/group".into())
        }
    } else {
        degraded("/etc/group not readable")
    }
}

fn runtime_sockets(ctx: &mut ScanContext) -> CheckOutcome {
    let mut bad = Vec::new();
    let mut seen = 0;
    for s in ["/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock", "/run/podman/podman.sock"] {
        if let Some(mode) = ctx.unix_mode(s) {
            seen += 1;
            if mode & 0o007 != 0 {
                bad.push(format!("{s} is {mode:o} (world-accessible)"));
            }
        }
    }
    if seen == 0 {
        return degraded("no container runtime sockets found (docker absent or needs root)");
    }
    if bad.is_empty() {
        ok(format!("{seen} runtime sockets checked"), "runtime sockets".into(), "ls -l /var/run/docker.sock".into())
    } else {
        nok(bad.join("; "), "runtime sockets".into(), "ls -l /var/run/docker.sock".into())
    }
}

fn daemon_privileged(ctx: &mut ScanContext) -> CheckOutcome {
    if let Some(cat) = ctx.cmd("systemctl", &["cat", "docker"]) {
        let insecure = cat.lines().any(|l| l.contains("--privileged") || l.contains("--insecure-registry") || l.contains("iptables=false"));
        if insecure {
            nok(format!("docker daemon flags include insecure options: {}", cat.lines().filter(|l| l.contains("--privileged") || l.contains("--insecure-registry") || l.contains("iptables=false")).map(|l| l.trim()).collect::<Vec<_>>().join("; ")), "docker.service".into(), "systemctl cat docker".into())
        } else {
            ok("docker daemon flags clean".into(), "docker.service".into(), "systemctl cat docker".into())
        }
    } else if let Some(conf) = ctx.read("/etc/docker/daemon.json") {
        let insecure = conf.contains("\"privileged\"") || conf.contains("\"insecure-registries\"");
        if insecure {
            nok(format!("daemon.json contains insecure options"), "/etc/docker/daemon.json".into(), "cat /etc/docker/daemon.json".into())
        } else {
            ok("daemon.json clean".into(), "/etc/docker/daemon.json".into(), "cat /etc/docker/daemon.json".into())
        }
    } else {
        degraded("docker daemon configuration not queryable")
    }
}

fn hidepid(ctx: &mut ScanContext) -> CheckOutcome {
    if let Some(mounts) = ctx.read("/proc/mounts") {
        let proc_mount = mounts.lines().find(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            f.len() >= 4 && f[1] == "/proc"
        });
        match proc_mount {
            Some(l) => {
                let opts = l.split_whitespace().nth(3).unwrap_or("");
                if opts.contains("hidepid=2") || opts.contains("hidepid=1") {
                    ok(format!("/proc options: {opts}"), "/proc/mounts".into(), "findmnt -o OPTIONS /proc".into())
                } else {
                    nok(format!("/proc mounted without hidepid ({opts})"), "/proc/mounts".into(), "findmnt -o OPTIONS /proc".into())
                }
            }
            None => degraded("/proc not found in mounts"),
        }
    } else {
        degraded("/proc/mounts not readable")
    }
}

fn privileged_containers(ctx: &mut ScanContext) -> CheckOutcome {
    if let Some(ps) = ctx.cmd("docker", &["ps", "--format", "{{.Names}}"]) {
        let mut privileged = Vec::new();
        for name in ps.lines().filter(|l| !l.trim().is_empty()) {
            if let Some(ins) = ctx.cmd("docker", &["inspect", "--format", "{{.HostConfig.Privileged}}", name]) {
                if ins.trim() == "true" {
                    privileged.push(name.to_string());
                }
            }
        }
        if privileged.is_empty() {
            ok(format!("{} running containers; none privileged", ps.lines().count()), "docker inspect".into(), "docker ps -a".into())
        } else {
            nok(format!("PRIVILEGED containers: {}", privileged.join(", ")), "docker inspect".into(), "docker inspect <name>".into())
        }
    } else {
        degraded("docker daemon not queryable (absent or needs root)")
    }
}

/// Known EOL horizons (unix dates approximated by year/month).
const EOL_MAP: &[(&str, &str)] = &[
    ("centos 7", "2024-06-30"),
    ("centos 8", "2021-12-31"),
    ("ubuntu 18.04", "2023-05-31"),
    ("ubuntu 20.04", "2025-04-30"),
    ("ubuntu 21.04", "2022-01-20"),
    ("ubuntu 22.04", "2027-04-30"),
    ("ubuntu 24.04", "2029-04-30"),
    ("debian 9", "2022-06-30"),
    ("debian 10", "2024-06-30"),
    ("debian 11", "2026-08-31"),
    ("debian 12", "2028-06-30"),
    ("red hat enterprise linux 6", "2020-11-30"),
    ("red hat enterprise linux 7", "2024-06-30"),
    ("windows server 2012", "2023-10-10"),
    ("windows server 2016", "2027-01-12"),
    ("windows server 2019", "2029-01-09"),
];

fn distro_eol(ctx: &mut ScanContext) -> CheckOutcome {
    let name = ctx.platform.distro.clone().unwrap_or_default().to_lowercase();
    let ver = ctx.platform.distro_version.clone().unwrap_or_default();
    let mut matched: Option<(&str, &str)> = None;
    for (key, eol) in EOL_MAP {
        if name.contains(key) || (name.contains(key.split(' ').next().unwrap_or("")) && !ver.is_empty() && key.contains(&ver)) {
            matched = Some((key, eol));
            break;
        }
    }
    let Some((key, eol)) = matched else {
        return degraded(&format!("no EOL data for '{name} {ver}' — verify support status"));
    };
    let now = chrono_now_ym();
    if now.as_deref() > Some(eol) {
        nok(format!("{key} reached EOL on {eol} (now {}) — unsupported", now.unwrap_or_default()), "/etc/os-release".into(), "cat /etc/os-release".into())
    } else {
        ok(format!("{key} supported until {eol}", key = key), "/etc/os-release".into(), "cat /etc/os-release".into())
    }
}

fn chrono_now_ym() -> Option<String> {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
    let days = secs / 86400;
    // civil from days (Howard Hinnant's algorithm)
    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    Some(format!("{y:04}-{m:02}-{d:02}"))
}

fn patch_backlog(ctx: &mut ScanContext) -> CheckOutcome {
    match ctx.platform.family {
        crate::platform::DistroFamily::Debian => {
            if let Some(sim) = ctx.cmd("apt-get", &["-s", "upgrade"]) {
                let security = sim.lines().filter(|l| l.contains("-security")).count();
                let total = sim.lines().filter(|l| l.starts_with("Inst ")).count();
                if security == 0 && total == 0 {
                    ok("no pending updates".into(), "apt-get -s upgrade".into(), "apt-get -s upgrade".into())
                } else if security == 0 {
                    ok(format!("{total} non-security updates pending"), "apt-get -s upgrade".into(), "apt-get -s upgrade".into())
                } else {
                    nok(format!("{security} security updates pending (of {total})"), "apt-get -s upgrade".into(), "apt-get -s upgrade".into())
                }
            } else {
                degraded("apt-get simulation unavailable (needs root on minimal images)")
            }
        }
        crate::platform::DistroFamily::Rhel | crate::platform::DistroFamily::Suse => {
            if let Some(out) = ctx.cmd("dnf", &["updateinfo", "list", "available"]) {
                let sec = out.lines().filter(|l| l.contains("Security")).count();
                if sec == 0 {
                    ok("no security advisories pending".into(), "dnf updateinfo".into(), "dnf updateinfo list available".into())
                } else {
                    nok(format!("{sec} security advisories pending"), "dnf updateinfo".into(), "dnf updateinfo list available".into())
                }
            } else {
                degraded("dnf updateinfo unavailable")
            }
        }
        _ => degraded("patch backlog enumeration needs apt/dnf family"),
    }
}

fn kernel_currency(ctx: &mut ScanContext) -> CheckOutcome {
    let running = ctx.platform.kernel.clone();
    if running.is_empty() {
        return degraded("running kernel unknown");
    }
    let rd = std::fs::read_dir(ctx.path("/boot"));
    let mut versions: Vec<String> = Vec::new();
    if let Ok(rd) = rd {
        for e in rd.filter_map(|e| e.ok()) {
            let n = e.file_name().to_string_lossy().to_string();
            if let Some(v) = n.strip_prefix("vmlinuz-") {
                versions.push(v.to_string());
            }
        }
    }
    if versions.is_empty() {
        return degraded("no vmlinuz files enumerable in /boot");
    }
    versions.sort();
    let latest = versions.last().unwrap().clone();
    if running.trim() == latest {
        ok(format!("running kernel {running} = newest installed {latest}"), "/boot + uname".into(), "ls /boot | grep vmlinuz; uname -r".into())
    } else {
        nok(format!("running {running} but newest installed is {latest} — reboot debt"), "/boot".into(), "ls /boot; uname -r".into())
    }
}

fn service_currency(ctx: &mut ScanContext) -> CheckOutcome {
    let ssh = ctx.cmd("sshd", &["-V"]).or_else(|| ctx.cmd("ssh", &["-V"]));
    let Some(v) = ssh else {
        return degraded("service versions not queryable");
    };
    if v.contains("OpenSSH_7.") || v.contains("OpenSSH_8.2") || v.contains("OpenSSH_8.3") || v.contains("OpenSSH_8.4") {
        nok(format!("service version EOL/old: {}", crate::redact::redact(v.trim())), "sshd -V".into(), "sshd -V".into())
    } else {
        ok(crate::redact::redact(v.trim()), "sshd -V".into(), "sshd -V".into())
    }
}

fn third_party_repos(ctx: &mut ScanContext) -> CheckOutcome {
    let mut repos = Vec::new();
    let rd = std::fs::read_dir(ctx.path("/etc/apt/sources.list.d"));
    if let Ok(rd) = rd {
        for e in rd.filter_map(|e| e.ok()) {
            let n = e.file_name().to_string_lossy().to_string();
            if n.ends_with(".list") || n.ends_with(".sources") {
                repos.push(format!("/etc/apt/sources.list.d/{n}"));
            }
        }
    }
    let rd = std::fs::read_dir(ctx.path("/etc/yum.repos.d"));
    if let Ok(rd) = rd {
        for e in rd.filter_map(|e| e.ok()) {
            let n = e.file_name().to_string_lossy().to_string();
            if n.ends_with(".repo") {
                repos.push(format!("/etc/yum.repos.d/{n}"));
            }
        }
    }
    if repos.is_empty() {
        ok("no third-party repositories configured".into(), "repo dirs".into(), "ls /etc/apt/sources.list.d /etc/yum.repos.d".into())
    } else {
        nok(format!("third-party repositories present (supply-chain surface): {}", repos.join(", ")), "repo dirs".into(), "see evidence".into())
    }
}

fn cmdline_clean(ctx: &mut ScanContext) -> CheckOutcome {
    if in_container(ctx) {
        return not_applicable(
            "the kernel command line belongs to the shared host kernel; a container cannot set or own boot parameters",
        );
    }
    if let Some(cmdline) = ctx.read("/proc/cmdline") {
        let bad = ["init=/bin/sh", "init=/bin/bash", "systemd.unit=emergency", "rd.break", "debug"];
        let hits: Vec<&str> = bad.iter().copied().filter(|b| cmdline.contains(b)).collect();
        if hits.is_empty() {
            ok(format!("kernel cmdline clean: {}", cmdline.trim()), "/proc/cmdline".into(), "cat /proc/cmdline".into())
        } else {
            nok(format!("debug/boot-escape flags present: {}", hits.join(", ")), "/proc/cmdline".into(), "cat /proc/cmdline".into())
        }
    } else {
        degraded("/proc/cmdline not readable")
    }
}

fn ldso_conf_owned(ctx: &mut ScanContext) -> CheckOutcome {
    let rd = std::fs::read_dir(ctx.path("/etc/ld.so.conf.d"));
    let mut unknown = Vec::new();
    let mut checked = 0;
    if let Ok(rd) = rd {
        for e in rd.filter_map(|e| e.ok()) {
            let name = e.file_name().to_string_lossy().to_string();
            if !name.ends_with(".conf") {
                continue;
            }
            checked += 1;
            let p = format!("/etc/ld.so.conf.d/{name}");
            let owned = match ctx.platform.family {
                crate::platform::DistroFamily::Debian => ctx.cmd("dpkg-query", &["-S", &p]).is_some(),
                _ => ctx.cmd("rpm", &["-qf", &p]).map(|o| !o.contains("not owned")).unwrap_or(false),
            };
            if !owned {
                unknown.push(name);
            }
        }
    }
    if checked == 0 {
        return degraded("ld.so.conf.d not enumerable");
    }
    if unknown.is_empty() {
        ok(format!("{checked} ld.so.conf.d entries all package-owned"), "/etc/ld.so.conf.d".into(), "dpkg -S /etc/ld.so.conf.d/*".into())
    } else {
        nok(format!("ld.so.conf entries NOT package-owned: {}", unknown.join(", ")), "/etc/ld.so.conf.d".into(), "see evidence".into())
    }
}

fn xz_backdoor(ctx: &mut ScanContext) -> CheckOutcome {
    let version = match ctx.platform.family {
        crate::platform::DistroFamily::Debian => ctx.cmd("dpkg-query", &["-W", "-f=${Version}", "liblzma5"]),
        _ => ctx.cmd("rpm", &["-q", "xz-libs"]).or_else(|| ctx.cmd("rpm", &["-q", "liblzma5"])),
    };
    let Some(v) = version else {
        return degraded("liblzma version not queryable");
    };
    if v.contains("5.6.0") || v.contains("5.6.1") {
        nok(format!("liblzma {v} is in the CVE-2024-3094 backdoor band (5.6.0/5.6.1)", v = crate::redact::redact(&v)), "package database".into(), "dpkg -l liblzma5 / rpm -q xz-libs".into())
    } else {
        ok(format!("liblzma outside affected band: {}", crate::redact::redact(v.trim())), "package database".into(), "dpkg -l liblzma5".into())
    }
}

fn pkg_integrity(ctx: &mut ScanContext) -> CheckOutcome {
    match ctx.platform.family {
        crate::platform::DistroFamily::Debian => {
            if let Some(out) = ctx.cmd_timeout("debsums", &["-s", "bash", "coreutils", "libc6"], 5000) {
                if out.trim().is_empty() {
                    ok("core package file digests match".into(), "debsums".into(), "debsums -s bash coreutils libc6".into())
                } else {
                    nok(format!("digest mismatches: {}", crate::redact::redact(&out)), "debsums".into(), "debsums -s".into())
                }
            } else {
                degraded("debsums unavailable (install debsums or run rpm -V equivalent)")
            }
        }
        _ => {
            if let Some(out) = ctx.cmd_timeout("rpm", &["-V", "basesystem", "bash", "coreutils"], 5000) {
                if out.trim().is_empty() {
                    ok("core package verification clean".into(), "rpm -V".into(), "rpm -V basesystem bash".into())
                } else {
                    nok(format!("rpm verification mismatches: {}", crate::redact::redact(&out)), "rpm -V".into(), "rpm -V <pkg>".into())
                }
            } else {
                degraded("rpm -V unavailable")
            }
        }
    }
}
