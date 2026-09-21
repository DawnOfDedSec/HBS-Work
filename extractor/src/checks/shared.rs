//! GEN-INV: shared informational inventory — context evidence, never
//! pass/fail (spec §5). Collected on every OS where the sources exist.

use crate::checks::{degraded, err_outcome, ok};
use crate::context::ScanContext;
use crate::model::{CheckOutcome, FallbackAttempt, RegisteredCheck};
use crate::platform::Os;

pub fn register(reg: &mut Vec<RegisteredCheck>) {
    use crate::check;
    check!(reg, "GEN-INV-001", "Listening ports inventory", "Enumerate all listening TCP/UDP sockets with owning processes where visible.", "Unknown open services are unmanaged attack surface.", "Review every listening port against the asset register; close unused services.", Informational, "Inventory", &["CIS 3.3"], |_| true, listening_ports);
    check!(reg, "GEN-INV-002", "Installed packages inventory", "Enumerate installed packages via the distro package manager.", "Unmanaged or outdated packages are invisible to patch management.", "Reconcile installed packages against approved software lists.", Informational, "Inventory", &[], |_| true, installed_packages);
    check!(reg, "GEN-INV-003", "Users and groups inventory", "Enumerate local users and groups with UIDs/GIDs.", "Forgotten accounts are common persistence and privilege-abuse paths.", "Remove or disable accounts that no longer map to people or services.", Informational, "Inventory", &["CIS 6.1"], |_| true, users_groups);
    check!(reg, "GEN-INV-004", "Scheduled tasks inventory", "Enumerate cron jobs / scheduled tasks.", "Scheduled tasks are a primary persistence mechanism.", "Validate every task's author, action and schedule.", Informational, "Inventory", &["MITRE T1053"], |_| true, scheduled_tasks);
    check!(reg, "GEN-INV-005", "Autorun / persistence locations inventory", "Enumerate rc.local, systemd user units, RUN keys, startup folders.", "Autorun locations are abused for persistence.", "Every autorun entry should map to a known package or admin action.", Informational, "Inventory", &["MITRE T1547"], |_| true, autoruns);
    check!(reg, "GEN-INV-006", "Open shares inventory", "List exported filesystems (NFS exports / SMB shares).", "Over-broad shares leak data across trust boundaries.", "Restrict share permissions to required principals.", Informational, "Inventory", &["CIS 2.2.16"], |_| true, open_shares);
    check!(reg, "GEN-INV-007", "Patch currency", "How long since the last OS/package update.", "Long update gaps correlate with known-CVE exposure.", "Patch within your policy window; investigate gaps over 90 days.", Informational, "Inventory", &["CIS 1.9"], |_| true, patch_currency);
    check!(reg, "GEN-INV-008", "Virtualization platform detection", "Identify hypervisor/cloud platform the host runs on.", "Context for asset classification and snapshot/escape risks.", "Track platform-specific hardening guidance.", Informational, "Inventory", &[], |_| true, virt_platform);
    check!(reg, "GEN-INV-009", "Time synchronization", "Clock source and drift.", "Kerberos, TLS and log correlation break on bad clocks.", "Sync to approved NTP sources with drift alerting.", Informational, "Inventory", &["CIS 2.1.3"], |_| true, time_sync);
    check!(reg, "GEN-INV-010", "DNS resolver configuration", "Configured DNS resolvers.", "Uncontrolled resolvers enable hijack and exfil paths.", "Point hosts at approved internal resolvers.", Informational, "Inventory", &[], |_| true, dns_config);
    check!(reg, "GEN-INV-011", "Log forwarding agent presence", "Detect rsyslog forwarding / Windows event forwarding.", "Local-only logs die with the machine.", "Forward security-relevant logs to a central store.", Informational, "Inventory", &["CIS 8.1"], |_| true, log_forwarding);
    check!(reg, "GEN-INV-012", "Secure Boot state", "Whether Secure Boot is enabled.", "Disabled Secure Boot permits unsigned boot components.", "Enable Secure Boot where firmware and OS support it.", Informational, "Inventory", &[], |_| true, secure_boot);
    check!(reg, "GEN-INV-013", "TPM state", "Trusted Platform Module presence and readiness.", "TPM underpins disk encryption and credential guarding.", "Provision TPM 2.0 and use it for BitLocker/Credential Guard.", Informational, "Inventory", &[], |_| true, tpm_state);
    check!(reg, "GEN-INV-014", "FIPS mode", "Whether the crypto stack runs in FIPS mode.", "Regulated environments require FIPS-validated crypto.", "Enable FIPS mode where compliance requires it.", Informational, "Inventory", &["FIPS 140-3"], |_| true, fips_mode);
    check!(reg, "GEN-INV-015", "Audit subsystem coverage score", "Count of active audit rules / audited subcategories.", "Audit gaps blind detection and forensics.", "Audit per CIS 4.1 / 17.x minimum coverage.", Informational, "Inventory", &["CIS 4.1"], |_| true, audit_coverage);
    check!(reg, "GEN-INV-016", "Privileged group inventory", "Members of sudo/wheel/administrator groups.", "Privilege sprawl multiplies compromise impact.", "Keep administrative membership minimal and reviewed.", Informational, "Inventory", &["CIS 6.2"], |_| true, priv_groups);
    check!(reg, "GEN-INV-017", "Effective firewall profile", "Which firewall service is active and how it is configured.", "An inactive or permissive firewall exposes every listening service.", "Run a supported host firewall with default-deny inbound.", Informational, "Inventory", &["CIS 3.5"], |_| true, firewall_profile);
    check!(reg, "GEN-INV-018", "Cloud agent / cloud-init presence", "Detect cloud-init, EC2Launch, WALA or cloud CLIs.", "Cloud bootstrap agents are powerful and often forgotten.", "Restrict and update cloud agents; remove on bare metal.", Informational, "Inventory", &[], |_| true, cloud_agents);
    check!(reg, "GEN-INV-019", "EDR / AV agent presence", "Detect endpoint protection agents and their state.", "Unprotected hosts extend dwell time to months.", "Deploy supported EDR/AV with tamper protection.", Informational, "Inventory", &["CIS 10.1"], |_| true, edr_presence);
    check!(reg, "GEN-INV-020", "Backup agent and last success", "Detect backup clients and their last successful run.", "Unverified backups turn incidents into total losses.", "Verify backups on schedule with restore tests.", Informational, "Inventory", &["CIS 11.1"], |_| true, backup_agent);
    check!(reg, "GEN-INV-021", "Kernel module / driver inventory", "List loaded kernel modules or drivers.", "Signed-but-vulnerable drivers enable BYOVD attacks.", "Blocklist vulnerable drivers; monitor module churn.", Informational, "Inventory", &["MITRE T1068"], |_| true, kernel_modules);
    check!(reg, "GEN-INV-022", "Management service presence", "sshd, WinRM, RDP and remote-management exposure summary.", "Remote management is the most-targeted surface.", "Constrain management protocols to jump hosts and MFA.", Informational, "Inventory", &["CIS 2.2"], |_| true, mgmt_services);
    check!(reg, "GEN-INV-023", "Locale and timezone", "Active locale and timezone.", "Context for log correlation across regions.", "Standardize timezones where operationally feasible.", Informational, "Inventory", &[], |_| true, locale_tz);
    check!(reg, "GEN-INV-024", "Disk and mount inventory", "Block-ish view of mounts/filesystems and sizes.", "Fill-up and noexec/nosuid context for other checks.", "Separate /var and /tmp; monitor growth.", Informational, "Inventory", &[], |_| true, disks);
    check!(reg, "GEN-INV-025", "Host identity and domain join", "machine-id, hostname and domain-join state.", "Identity context for report routing and AD checks.", "Track identity sources for access reviews.", Informational, "Inventory", &[], |_| true, host_identity);
}

fn linux_only(ctx: &ScanContext) -> bool {
    ctx.platform.os == Os::Linux
}

fn inv_ok(evidence: String, location: String, repro: String) -> CheckOutcome {
    ok(evidence, location, repro)
}

fn one_fallback(source: &str, outcome: &str) -> Vec<FallbackAttempt> {
    vec![FallbackAttempt { source: source.into(), outcome: outcome.into() }]
}

fn listening_ports(ctx: &mut ScanContext) -> CheckOutcome {
    let mut log: Vec<FallbackAttempt> = Vec::new();
    if let Some(out) = ctx.cmd("ss", &["-tulpn"]) {
        log.push(FallbackAttempt { source: "ss -tulpn".into(), outcome: "read".into() });
        return inv_ok(out.lines().take(200).collect::<Vec<_>>().join("\n"), "ss -tulpn".into(), "ss -tulpn".into());
    }
    log.push(FallbackAttempt { source: "ss -tulpn".into(), outcome: "unavailable".into() });
    if linux_only(ctx) {
        if let Some(proc_net) = ctx.read("/proc/net/tcp") {
            log.push(FallbackAttempt { source: "/proc/net/tcp".into(), outcome: format!("parsed {} entries", proc_net.lines().count().saturating_sub(1)) });
            let ports: Vec<String> = proc_net
                .lines()
                .skip(1)
                .filter_map(|l| l.split_whitespace().nth(1))
                .filter_map(|a| a.split(':').nth(1))
                .map(|p| u16::from_str_radix(p, 16).map(|v| v.to_string()).unwrap_or_default())
                .filter(|s| !s.is_empty())
                .collect();
            return CheckOutcome { status: crate::model::Status::DegradedPartial, evidence: format!("listening TCP ports (no process info): {}", ports.join(", ")), location: "/proc/net/tcp".into(), repro: "cat /proc/net/tcp".into(), recommendation_override: None, degraded_reason: Some("ss unavailable; /proc/net/tcp lacks process attribution".into()), fallback_log: log };
        }
        log.push(FallbackAttempt { source: "/proc/net/tcp".into(), outcome: "missing".into() });
    }
    if !linux_only(ctx) {
        if let Some(_out) = ctx.cmd("netsh", &["advfirewall", "show", "allprofiles"]) {
            log.push(FallbackAttempt { source: "netsh advfirewall".into(), outcome: "firewall profiles only (port list needs admin)".into() });
            return degraded("port enumeration without admin rights is limited; firewall profiles captured");
        }
    }
    err_outcome(log)
}

fn installed_packages(ctx: &mut ScanContext) -> CheckOutcome {
    let attempts: [(&str, &str, &[&str]); 5] = [
        ("dpkg-query -W", "dpkg-query", &["-W"]),
        ("rpm -qa", "rpm", &["-qa"]),
        ("apk info", "apk", &["info"]),
        ("pacman -Q", "pacman", &["-Q"]),
        ("powershell Get-Package", "powershell", &["-NoProfile", "-NonInteractive", "-Command", "Get-Package | Select-Object -ExpandProperty Name"]),
    ];
    let mut log = Vec::new();
    for (label, prog, args) in attempts {
        if let Some(out) = ctx.cmd(prog, args) {
            let count = out.lines().filter(|l| !l.trim().is_empty()).count();
            log.push(FallbackAttempt { source: label.into(), outcome: format!("{count} packages").into() });
            let sample: Vec<&str> = out.lines().take(20).collect();
            return inv_ok(format!("{count} packages installed; first entries: {}", sample.join(", ")), label.into(), label.into());
        }
        log.push(FallbackAttempt { source: label.into(), outcome: "unavailable".into() });
    }
    err_outcome(log)
}

fn users_groups(ctx: &mut ScanContext) -> CheckOutcome {
    let mut log = Vec::new();
    if linux_only(ctx) {
        if let Some(passwd) = ctx.read("/etc/passwd") {
            log.push(FallbackAttempt { source: "/etc/passwd".into(), outcome: "read".into() });
            let count = passwd.lines().count();
            let names: Vec<&str> = passwd.lines().filter_map(|l| l.split(':').next()).take(20).collect();
            return inv_ok(format!("{count} local users: {}", names.join(", ")), "/etc/passwd".into(), "cat /etc/passwd".into());
        }
        log.extend(one_fallback("/etc/passwd", "missing"));
        if let Some(out) = ctx.cmd("getent", &["passwd"]) {
            log.push(FallbackAttempt { source: "getent passwd".into(), outcome: "read".into() });
            return inv_ok(format!("{} users via getent", out.lines().count()), "getent passwd".into(), "getent passwd".into());
        }
        log.push(FallbackAttempt { source: "getent passwd".into(), outcome: "unavailable".into() });
    } else if let Some(out) = ctx.cmd("net", &["user"]) {
        log.push(FallbackAttempt { source: "net user".into(), outcome: "read".into() });
        return inv_ok(out.lines().skip(4).take(30).collect::<Vec<_>>().join(" "), "net user".into(), "net user".into());
    } else {
        log.extend(one_fallback("net user", "unavailable"));
    }
    err_outcome(log)
}

fn scheduled_tasks(ctx: &mut ScanContext) -> CheckOutcome {
    let mut log = Vec::new();
    if linux_only(ctx) {
        let mut found = Vec::new();
        for d in ["/etc/crontab", "/etc/anacrontab"] {
            if let Some(c) = ctx.read(d) {
                log.push(FallbackAttempt { source: d.into(), outcome: "read".into() });
                found.push(format!("{d}: {} entries", c.lines().filter(|l| !l.starts_with('#')).count()));
            }
        }
        if let Some(out) = ctx.cmd("systemctl", &["list-timers"]) {
            log.push(FallbackAttempt { source: "systemctl list-timers".into(), outcome: "read".into() });
            found.push(format!("systemd timers: {} lines", out.lines().count()));
        }
        if !found.is_empty() {
            return inv_ok(found.join("; "), "/etc/crontab, systemctl".into(), "crontab -l; systemctl list-timers".into());
        }
    } else if let Some(out) = ctx.cmd("schtasks", &["/query", "/fo", "csv", "/v"]) {
        log.push(FallbackAttempt { source: "schtasks /query".into(), outcome: format!("{} lines", out.lines().count()).into() });
        let count = out.lines().count().saturating_sub(1);
        return inv_ok(format!("{count} scheduled tasks"), "schtasks".into(), "schtasks /query /fo csv".into());
    } else {
        log.extend(one_fallback("schtasks /query", "unavailable"));
    }
    err_outcome(log)
}

fn autoruns(ctx: &mut ScanContext) -> CheckOutcome {
    let mut log = Vec::new();
    let mut found = Vec::new();
    if linux_only(ctx) {
        if let Some(c) = ctx.read("/etc/rc.local") {
            log.push(FallbackAttempt { source: "/etc/rc.local".into(), outcome: "read".into() });
            found.push(format!("rc.local: {} non-comment lines", c.lines().filter(|l| !l.trim_start().starts_with('#')).count()));
        }
        for u in ["/etc/systemd/system", "/home"] {
            if ctx.exists(u) {
                found.push(format!("{u}: present"));
            }
        }
    } else {
        for key in [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        ] {
            if let Some(out) = ctx.cmd("reg", &["query", key]) {
                log.push(FallbackAttempt { source: format!("reg query {key}").into(), outcome: "read".into() });
                let vals = out.lines().filter(|l| l.contains("REG_")).count();
                found.push(format!("{key}: {vals} values"));
            }
        }
    }
    if !found.is_empty() {
        return inv_ok(found.join("; "), "autorun locations".into(), "see evidence locations".into());
    }
    log.push(FallbackAttempt { source: "autorun locations".into(), outcome: "none readable".into() });
    err_outcome(log)
}

fn open_shares(ctx: &mut ScanContext) -> CheckOutcome {
    let mut log = Vec::new();
    if linux_only(ctx) {
        if let Some(exports) = ctx.read("/etc/exports") {
            log.push(FallbackAttempt { source: "/etc/exports".into(), outcome: "read".into() });
            let entries = exports.lines().filter(|l| !l.trim_start().starts_with('#')).count();
            return inv_ok(format!("{entries} NFS exports"), "/etc/exports".into(), "cat /etc/exports".into());
        }
        log.push(FallbackAttempt { source: "/etc/exports".into(), outcome: "missing (no NFS exports configured)".into() });
        return inv_ok("no /etc/exports file — no NFS shares configured".into(), "/etc/exports".into(), "cat /etc/exports".into());
    }
    if let Some(out) = ctx.cmd("net", &["share"]) {
        log.push(FallbackAttempt { source: "net share".into(), outcome: "read".into() });
        return inv_ok(out.lines().skip(4).take(30).collect::<Vec<_>>().join(" "), "net share".into(), "net share".into());
    }
    log.extend(one_fallback("net share", "unavailable"));
    err_outcome(log)
}

fn patch_currency(ctx: &mut ScanContext) -> CheckOutcome {
    let mut log = Vec::new();
    if linux_only(ctx) {
        if let Some(dpkg_log) = ctx.read("/var/log/dpkg.log") {
            log.push(FallbackAttempt { source: "/var/log/dpkg.log".into(), outcome: "read".into() });
            if let Some(first) = dpkg_log.lines().next() {
                let date = first.split_whitespace().next().unwrap_or("unknown");
                return inv_ok(format!("last package activity: {date}"), "/var/log/dpkg.log".into(), "head -1 /var/log/dpkg.log".into());
            }
        } else {
            log.push(FallbackAttempt { source: "/var/log/dpkg.log".into(), outcome: "missing".into() });
        }
        if let Some(out) = ctx.cmd("rpm", &["-qa", "--last"]) {
            log.push(FallbackAttempt { source: "rpm -qa --last".into(), outcome: "read".into() });
            let newest = out.lines().next().unwrap_or("");
            return inv_ok(format!("newest RPM: {newest}"), "rpm database".into(), "rpm -qa --last | head -1".into());
        }
        log.push(FallbackAttempt { source: "rpm -qa --last".into(), outcome: "unavailable".into() });
    } else if let Some(out) = ctx.cmd("powershell", &["-NoProfile", "-NonInteractive", "-Command", "(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn"]) {
        log.push(FallbackAttempt { source: "Get-HotFix".into(), outcome: "read".into() });
        return inv_ok(format!("newest hotfix installed: {}", out.trim()), "Get-HotFix".into(), "Get-HotFix | Sort InstalledOn -Desc | Select -First 1".into());
    } else {
        log.extend(one_fallback("Get-HotFix", "unavailable"));
    }
    err_outcome(log)
}

fn virt_platform(ctx: &mut ScanContext) -> CheckOutcome {
    if let Some(v) = &ctx.platform.virtualized {
        return inv_ok(format!("virtualization: {v}"), "systemd-detect-virt / dmi".into(), "systemd-detect-virt".into());
    }
    if linux_only(ctx) {
        if let Some(dmi) = ctx.read("/sys/class/dmi/id/product_name") {
            return inv_ok(format!("DMI product: {}", dmi.trim()), "/sys/class/dmi/id/product_name".into(), "cat /sys/class/dmi/id/product_name".into());
        }
    }
    degraded("virtualization could not be determined (bare metal or restricted DMI)")
}

fn time_sync(ctx: &mut ScanContext) -> CheckOutcome {
    let mut log = Vec::new();
    if let Some(out) = ctx.cmd("timedatectl", &["status"]) {
        log.push(FallbackAttempt { source: "timedatectl status".into(), outcome: "read".into() });
        return inv_ok(out.lines().take(6).collect::<Vec<_>>().join("; "), "timedatectl".into(), "timedatectl status".into());
    }
    log.push(FallbackAttempt { source: "timedatectl status".into(), outcome: "unavailable".into() });
    if let Some(chrony) = ctx.cmd("chronyc", &["tracking"]) {
        log.push(FallbackAttempt { source: "chronyc tracking".into(), outcome: "read".into() });
        return inv_ok(chrony.lines().take(4).collect::<Vec<_>>().join("; "), "chronyc".into(), "chronyc tracking".into());
    }
    log.push(FallbackAttempt { source: "chronyc tracking".into(), outcome: "unavailable".into() });
    if !linux_only(ctx) {
        if let Some(out) = ctx.cmd("w32tm", &["/query", "/status"]) {
            log.push(FallbackAttempt { source: "w32tm /query /status".into(), outcome: "read".into() });
            return inv_ok(out.lines().take(4).collect::<Vec<_>>().join("; "), "w32tm".into(), "w32tm /query /status".into());
        }
        log.push(FallbackAttempt { source: "w32tm".into(), outcome: "unavailable (service stopped?)".into() });
    }
    err_outcome(log)
}

fn dns_config(ctx: &mut ScanContext) -> CheckOutcome {
    if linux_only(ctx) {
        if let Some(resolv) = ctx.read("/etc/resolv.conf") {
            let servers: Vec<&str> = resolv.lines().filter_map(|l| l.strip_prefix("nameserver ")).map(str::trim).collect();
            return inv_ok(format!("resolvers: {}", servers.join(", ")), "/etc/resolv.conf".into(), "cat /etc/resolv.conf".into());
        }
        return err_outcome(one_fallback("/etc/resolv.conf", "missing"));
    }
    if let Some(out) = ctx.cmd("netsh", &["interface", "ip", "show", "dns"]) {
        return inv_ok(out.lines().take(12).collect::<Vec<_>>().join("; "), "netsh".into(), "netsh interface ip show dns".into());
    }
    err_outcome(one_fallback("netsh interface ip show dns", "unavailable"))
}

fn log_forwarding(ctx: &mut ScanContext) -> CheckOutcome {
    if linux_only(ctx) {
        if let Some(conf) = ctx.read("/etc/rsyslog.conf") {
            let forwards: Vec<&str> = conf.lines().filter(|l| l.contains("@@") || l.contains("@ ")).collect();
            let state = if forwards.is_empty() { "no remote forwarding configured" } else { "remote forwarding present" };
            return inv_ok(format!("rsyslog: {state}"), "/etc/rsyslog.conf".into(), "grep -E '@@|@ ' /etc/rsyslog.conf".into());
        }
        return degraded("rsyslog config not found; forwarding state unknown");
    }
    if let Some(_out) = ctx.cmd("reg", &["query", r"HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog"]) {
        return inv_ok("event log policy keys present".into(), "event forwarding policy".into(), "reg query".into());
    }
    degraded("Windows event forwarding policy not configured (or not readable)")
}

fn secure_boot(ctx: &mut ScanContext) -> CheckOutcome {
    let mut log = Vec::new();
    if let Some(out) = ctx.cmd("mokutil", &["--sb-state"]) {
        log.push(FallbackAttempt { source: "mokutil --sb-state".into(), outcome: "read".into() });
        return inv_ok(out, "mokutil".into(), "mokutil --sb-state".into());
    }
    log.push(FallbackAttempt { source: "mokutil".into(), outcome: "unavailable".into() });
    if let Some(efi) = ctx.read("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c") {
        let _ = efi;
        log.push(FallbackAttempt { source: "efivars SecureBoot".into(), outcome: "present (UEFI mode)".into() });
        return degraded("UEFI with SecureBoot variable present; exact state needs mokutil");
    }
    if !linux_only(ctx) {
        if let Some(out) = ctx.cmd("powershell", &["-NoProfile", "-NonInteractive", "-Command", "Confirm-SecureBootUEFI"]) {
            log.push(FallbackAttempt { source: "Confirm-SecureBootUEFI".into(), outcome: out.clone() });
            return inv_ok(format!("SecureBoot: {out}"), "Confirm-SecureBootUEFI".into(), "Confirm-SecureBootUEFI".into());
        }
        log.push(FallbackAttempt { source: "Confirm-SecureBootUEFI".into(), outcome: "unavailable (BIOS or non-admin)".into() });
    }
    err_outcome(log)
}

fn tpm_state(ctx: &mut ScanContext) -> CheckOutcome {
    if linux_only(ctx) {
        if ctx.exists("/sys/class/tpm/tpm0") {
            return inv_ok("TPM device present (/sys/class/tpm/tpm0)".into(), "/sys/class/tpm".into(), "ls /sys/class/tpm".into());
        }
        return inv_ok("no TPM device found".into(), "/sys/class/tpm".into(), "ls /sys/class/tpm".into());
    }
    if let Some(out) = ctx.cmd("powershell", &["-NoProfile", "-NonInteractive", "-Command", "Get-Tpm | Select-Object TpmReady,TpmPresent | ConvertTo-Json -Compress"]) {
        return inv_ok(format!("TPM: {out}"), "Get-Tpm".into(), "Get-Tpm".into());
    }
    degraded("TPM state needs admin PowerShell (Get-Tpm)")
}

fn fips_mode(ctx: &mut ScanContext) -> CheckOutcome {
    if linux_only(ctx) {
        if let Some(v) = ctx.read("/proc/sys/crypto/fips_enabled") {
            return inv_ok(format!("fips_enabled={}", v.trim()), "/proc/sys/crypto/fips_enabled".into(), "cat /proc/sys/crypto/fips_enabled".into());
        }
        return degraded("fips_enabled not present (kernel not FIPS-capable)");
    }
    if let Some(out) = ctx.cmd("reg", &["query", r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy", "/v", "Enabled"]) {
        return inv_ok(out.lines().last().unwrap_or("").trim().to_string(), "FipsAlgorithmPolicy".into(), "reg query".into());
    }
    degraded("FipsAlgorithmPolicy key not readable")
}

fn audit_coverage(ctx: &mut ScanContext) -> CheckOutcome {
    if linux_only(ctx) {
        if let Some(out) = ctx.cmd("auditctl", &["-l"]) {
            let count = out.lines().filter(|l| !l.trim().is_empty()).count();
            return inv_ok(format!("{count} audit rules loaded"), "auditctl -l".into(), "auditctl -l".into());
        }
        if let Some(rules) = ctx.read("/etc/audit/audit.rules") {
            let count = rules.lines().filter(|l| l.starts_with('-')).count();
            return inv_ok(format!("{count} rules configured on disk"), "/etc/audit/audit.rules".into(), "grep -c '^-' /etc/audit/audit.rules".into());
        }
        return degraded("audit rules not queryable (auditd absent or not root)");
    }
    if let Some(out) = ctx.cmd("auditpol", &["/get", "/category:*"]) {
        let enabled = out.lines().filter(|l| l.to_lowercase().contains("success") && !l.contains("No Auditing")).count();
        return inv_ok(format!("{enabled} auditing subcategories active"), "auditpol".into(), "auditpol /get /category:*".into());
    }
    degraded("auditpol needs admin rights")
}

fn priv_groups(ctx: &mut ScanContext) -> CheckOutcome {
    if linux_only(ctx) {
        if let Some(group) = ctx.read("/etc/group") {
            let admins: Vec<String> = group
                .lines()
                .filter(|l| l.starts_with("sudo:") || l.starts_with("wheel:") || l.starts_with("admin:"))
                .map(|l| l.split(':').nth(3).unwrap_or("").to_string())
                .filter(|m| !m.is_empty())
                .collect();
            return inv_ok(format!("privileged group members: {}", admins.join(", ")), "/etc/group".into(), "grep -E '^(sudo|wheel|admin):' /etc/group".into());
        }
        return err_outcome(one_fallback("/etc/group", "missing"));
    }
    if let Some(out) = ctx.cmd("powershell", &["-NoProfile", "-NonInteractive", "-Command", "Get-LocalGroupMember Administrators | Select-Object -ExpandProperty Name"]) {
        return inv_ok(format!("Administrators: {}", out.lines().collect::<Vec<_>>().join(", ")), "Get-LocalGroupMember".into(), "Get-LocalGroupMember Administrators".into());
    }
    degraded("local admin enumeration needs admin rights")
}

fn firewall_profile(ctx: &mut ScanContext) -> CheckOutcome {
    let mut log = Vec::new();
    if linux_only(ctx) {
        for svc in ["firewalld", "ufw", "nftables"] {
            if let Some(out) = ctx.cmd("systemctl", &["is-active", svc]) {
                log.push(FallbackAttempt { source: format!("systemctl is-active {svc}").into(), outcome: out.clone() });
                if out.contains("active") {
                    return inv_ok(format!("{svc} is active"), "systemctl".into(), format!("systemctl is-active {svc}"));
                }
            }
        }
        if let Some(out) = ctx.cmd("iptables", &["-L", "-n"]) {
            log.push(FallbackAttempt { source: "iptables -L -n".into(), outcome: "read".into() });
            return inv_ok(format!("iptables rules: {} lines", out.lines().count()), "iptables".into(), "iptables -L -n".into());
        }
        log.push(FallbackAttempt { source: "iptables -L -n".into(), outcome: "unavailable (needs root)".into() });
    } else if let Some(out) = ctx.cmd("netsh", &["advfirewall", "show", "allprofiles", "state"]) {
        log.push(FallbackAttempt { source: "netsh advfirewall".into(), outcome: "read".into() });
        return inv_ok(out.lines().filter(|l| l.contains("State")).collect::<Vec<_>>().join("; "), "netsh".into(), "netsh advfirewall show allprofiles state".into());
    } else {
        log.extend(one_fallback("netsh advfirewall", "unavailable"));
    }
    err_outcome(log)
}

fn cloud_agents(ctx: &mut ScanContext) -> CheckOutcome {
    let mut found = Vec::new();
    if ctx.exists("/etc/cloud") {
        found.push("cloud-init (/etc/cloud)");
    }
    if ctx.exists("C:/ProgramData/Amazon/EC2Launch") {
        found.push("EC2Launch");
    }
    if ctx.exists("C:/Windows/Panther") {
        found.push("Windows unattend area present");
    }
    if found.is_empty() {
        return inv_ok("no cloud bootstrap artifacts found (bare metal or stripped image)".into(), "filesystem".into(), "see evidence".into());
    }
    inv_ok(found.join("; "), "filesystem".into(), "see evidence".into())
}

fn edr_presence(ctx: &mut ScanContext) -> CheckOutcome {
    let mut log = Vec::new();
    if !linux_only(ctx) {
        if let Some(out) = ctx.cmd("powershell", &["-NoProfile", "-NonInteractive", "-Command", "(Get-MpComputerStatus).AMServiceEnabled"]) {
            log.push(FallbackAttempt { source: "Get-MpComputerStatus".into(), outcome: out.clone() });
            return inv_ok(format!("Defender AM service enabled: {}", out.trim()), "Get-MpComputerStatus".into(), "Get-MpComputerStatus".into());
        }
        log.push(FallbackAttempt { source: "Get-MpComputerStatus".into(), outcome: "unavailable".into() });
    } else {
        for svc in ["clamd", "crowdstrike-falcon-sensor", "cbagentd"] {
            if let Some(out) = ctx.cmd("systemctl", &["is-active", svc]) {
                if out.contains("active") {
                    log.push(FallbackAttempt { source: format!("systemctl {svc}").into(), outcome: "active".into() });
                    return inv_ok(format!("{svc} active"), "systemctl".into(), format!("systemctl is-active {svc}"));
                }
            }
        }
        log.push(FallbackAttempt { source: "known EDR services".into(), outcome: "none active".into() });
        return inv_ok("no known EDR/AV service detected".into(), "systemctl".into(), "systemctl is-active <edr>".into());
    }
    err_outcome(log)
}

fn backup_agent(ctx: &mut ScanContext) -> CheckOutcome {
    let mut candidates = Vec::new();
    if linux_only(ctx) {
        for svc in ["bacula-fd", "backuppc", "varagentd", "veeamflr"] {
            if let Some(out) = ctx.cmd("systemctl", &["is-active", svc]) {
                if out.contains("active") {
                    candidates.push(svc);
                }
            }
        }
    } else {
        for svc in ["VeeamEndpointBackupSvc", "BackupExecRPCService", "wbengine"] {
            if let Some(out) = ctx.cmd("sc", &["query", svc]) {
                if out.contains("RUNNING") {
                    candidates.push(svc);
                }
            }
        }
    }
    if candidates.is_empty() {
        return degraded("no known backup agent detected — verify backups exist for this host");
    }
    inv_ok(format!("backup-related services: {}", candidates.join(", ")), "service manager".into(), "see evidence".into())
}

fn kernel_modules(ctx: &mut ScanContext) -> CheckOutcome {
    if let Some(out) = ctx.cmd("lsmod", &[]) {
        let count = out.lines().count().saturating_sub(1);
        return inv_ok(format!("{count} modules loaded"), "lsmod".into(), "lsmod".into());
    }
    if let Some(out) = ctx.cmd("driverquery", &["/v"]) {
        return inv_ok(format!("driverquery: {} lines", out.lines().count()), "driverquery".into(), "driverquery /v".into());
    }
    err_outcome(one_fallback("lsmod / driverquery", "unavailable"))
}

fn mgmt_services(ctx: &mut ScanContext) -> CheckOutcome {
    let mut found = Vec::new();
    if linux_only(ctx) {
        if let Some(out) = ctx.cmd("systemctl", &["is-active", "sshd"]) {
            found.push(format!("sshd: {out}"));
        }
        found.push("winrm/rdp: n/a on linux".into());
    } else {
        for svc in ["WinRM", "TermService"] {
            if let Some(out) = ctx.cmd("sc", &["query", svc]) {
                let state = if out.contains("RUNNING") { "running" } else { "stopped" };
                found.push(format!("{svc}: {state}"));
            }
        }
    }
    if found.is_empty() {
        return degraded("management service states not queryable");
    }
    inv_ok(found.join("; "), "service manager".into(), "see evidence".into())
}

fn locale_tz(ctx: &mut ScanContext) -> CheckOutcome {
    let mut parts = Vec::new();
    if let Some(tz) = ctx.read("/etc/timezone") {
        parts.push(format!("tz={}", tz.trim()));
    }
    if let Some(l) = std::env::var("LANG").ok() {
        parts.push(format!("LANG={l}"));
    }
    if !linux_only(ctx) {
        if let Some(out) = ctx.cmd("tzutil", &["/g"]) {
            parts.push(format!("tz={}", out.trim()));
        }
    }
    if parts.is_empty() {
        return degraded("locale/timezone not determined");
    }
    inv_ok(parts.join("; "), "/etc/timezone, tzutil".into(), "cat /etc/timezone".into())
}

fn disks(ctx: &mut ScanContext) -> CheckOutcome {
    if linux_only(ctx) {
        if let Some(mounts) = ctx.read("/proc/mounts") {
            let real: Vec<String> = mounts
                .lines()
                .filter_map(|l| {
                    let f: Vec<&str> = l.split_whitespace().collect();
                    (f.len() >= 3 && !f[0].starts_with("tmpfs") && f[0] != "none" && f[2] != "swap").then(|| format!("{} ({})", f[1], f[2]))
                })
                .take(30)
                .collect();
            return inv_ok(real.join(", "), "/proc/mounts".into(), "cat /proc/mounts".into());
        }
        return err_outcome(one_fallback("/proc/mounts", "missing"));
    }
    if let Some(out) = ctx.cmd("powershell", &["-NoProfile", "-NonInteractive", "-Command", "Get-PSDrive -PSProvider FileSystem | Select-Object Name,Used,Free | ConvertTo-Json -Compress"]) {
        return inv_ok(out, "Get-PSDrive".into(), "Get-PSDrive".into());
    }
    err_outcome(one_fallback("Get-PSDrive", "unavailable"))
}

fn host_identity(ctx: &mut ScanContext) -> CheckOutcome {
    let mut parts = Vec::new();
    if linux_only(ctx) {
        if let Some(mid) = ctx.read("/etc/machine-id") {
            parts.push(format!("machine-id={}", mid.trim()));
        }
        if ctx.exists("/var/lib/sss/pubconf/krb5.include.d") || ctx.exists("/etc/sssd/sssd.conf") {
            parts.push("domain-joined (sssd present)".into());
        }
    } else if let Some(out) = ctx.cmd("dsregcmd", &["/status"]) {
        let joined = out.lines().find(|l| l.contains("AzureAdJoined") || l.contains("DomainJoined")).map(|l| l.trim().to_string());
        parts.push(joined.unwrap_or_else(|| "join state unknown".into()));
    }
    if parts.is_empty() {
        return degraded("identity sources not readable");
    }
    inv_ok(parts.join("; "), "identity files".into(), "see evidence".into())
}
