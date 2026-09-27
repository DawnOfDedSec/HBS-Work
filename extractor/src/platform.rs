//! Runtime platform/arch/distro detection and own-priority lowering.
//! One binary detects everything at runtime — there are no per-distro
//! builds (spec §3).

use crate::evidence;
use crate::model::SelfAudit;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Os {
    Linux,
    Windows,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DistroFamily {
    Rhel,
    Debian,
    Suse,
    Arch,
    Alpine,
    Unknown,
}

/// Where the extractor is actually running. Controls that can only exist
/// on real hardware (Secure Boot, TPM, bootloader, host firewall, kernel
/// modules) are `NotApplicable` — never `NonCompliant` and never
/// `Degraded` — inside a container, and virtual-firmware controls are
/// `NotApplicable` on a VM that exposes no such device.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Environment {
    BareMetal,
    VirtualMachine,
    Container,
    Wsl,
    Unknown,
}

/// Environment classification plus the independent signals that produced
/// it. Multiple signals are always collected so a single ambiguous probe
/// can never decide the result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentInfo {
    pub kind: Environment,
    /// Human-readable, redaction-safe descriptions of every marker found.
    pub signals: Vec<String>,
    /// Hypervisor/runtime name when known (e.g. `VMware`, `KVM`,
    /// `Microsoft Hyper-V`); `None` for bare metal, containers, or when
    /// undeterminable.
    pub hypervisor: Option<String>,
}

impl Default for EnvironmentInfo {
    fn default() -> Self {
        EnvironmentInfo {
            kind: Environment::Unknown,
            signals: Vec::new(),
            hypervisor: None,
        }
    }
}

impl EnvironmentInfo {
    /// A deterministic bare-metal classification (used by fixtures/tests
    /// that must not inherit the build host's environment).
    pub fn bare_metal() -> Self {
        EnvironmentInfo {
            kind: Environment::BareMetal,
            signals: vec!["bare metal (explicit)".into()],
            hypervisor: None,
        }
    }

    pub fn is_container(&self) -> bool {
        self.kind == Environment::Container
    }

    pub fn is_vm(&self) -> bool {
        self.kind == Environment::VirtualMachine
    }

    pub fn is_wsl(&self) -> bool {
        self.kind == Environment::Wsl
    }

    /// Hypervisor label or `fallback` when unknown.
    pub fn hypervisor_or(&self, fallback: &str) -> String {
        self.hypervisor
            .clone()
            .unwrap_or_else(|| fallback.to_string())
    }
}

/// Read-only probe surface used by [`detect_environment`]. Implemented by
/// [`crate::context::ScanContext`] (so fixture roots and command
/// injectors flow through) and by the real-host probe used from
/// [`detect`].
pub trait EnvProbe {
    /// Read an absolute host path read-only, capped.
    fn env_read(&mut self, abs_path: &str) -> Option<String>;
    /// Run one allowlisted query command.
    fn env_cmd(&mut self, program: &str, args: &[&str]) -> Option<String>;
    /// Process environment lookup (used only for container markers).
    fn env_var(&self, name: &str) -> Option<String> {
        let _ = name;
        None
    }
    /// Whether the probe targets Windows.
    fn is_windows(&self) -> bool;
    /// Target architecture (e.g. `x86_64`, `aarch64`).
    fn arch(&self) -> &str;
}

#[derive(Clone, Debug)]
pub struct PlatformInfo {
    pub os: Os,
    pub arch: String,
    pub kernel: String,
    pub distro: Option<String>,
    pub distro_version: Option<String>,
    pub family: DistroFamily,
    pub virtualized: Option<String>,
    /// Bare metal / VM / container / WSL classification with signals.
    pub environment: EnvironmentInfo,
}

/// Parse `/etc/os-release` content into (pretty distro name, family).
/// Family derives from ID first, then any ID_LIKE token.
pub fn parse_os_release(content: &str) -> (Option<String>, DistroFamily) {
    let mut id = None;
    let mut id_like: Vec<String> = Vec::new();
    let mut name = None;
    let mut version = None;
    for line in content.lines() {
        let (k, v) = match line.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim().trim_matches('"').trim_matches('\'')),
            None => continue,
        };
        match k {
            "ID" => id = Some(v.to_string()),
            "ID_LIKE" => id_like = v.split_whitespace().map(str::to_string).collect(),
            "NAME" => name = Some(v.to_string()),
            "VERSION_ID" => version = Some(v.to_string()),
            _ => {}
        }
    }
    let family = |tok: &str| match tok {
        "debian" | "ubuntu" | "mint" | "kali" => DistroFamily::Debian,
        "rhel" | "rocky" | "almalinux" | "centos" | "fedora" | "ol" | "amzn" => DistroFamily::Rhel,
        "sles" | "opensuse-leap" | "opensuse-tumbleweed" | "suse" => DistroFamily::Suse,
        "arch" | "artix" => DistroFamily::Arch,
        "alpine" => DistroFamily::Alpine,
        _ => DistroFamily::Unknown,
    };
    let f = id.as_deref().and_then(|i| {
        let f = family(i);
        (f != DistroFamily::Unknown).then_some(f)
    });
    let f = f.or_else(|| {
        id_like
            .iter()
            .map(|t| family(t))
            .find(|f| *f != DistroFamily::Unknown)
    });
    let _ = version; // version is parsed inline by detect_linux
    (name, f.unwrap_or(DistroFamily::Unknown))
}

fn detect_linux() -> PlatformInfo {
    let mut audit = SelfAudit::default();
    let (distro, version, family) =
        match evidence::read_file_capped(std::path::Path::new("/etc/os-release"), &mut audit) {
            Some(c) => {
                let (n, f) = parse_os_release(&c);
                let ver = c
                    .lines()
                    .find_map(|l| l.strip_prefix("VERSION_ID="))
                    .map(|v| v.trim().trim_matches('"').to_string());
                (n, ver, f)
            }
            None => (None, None, DistroFamily::Unknown),
        };
    let kernel =
        evidence::run_command("uname", &["-r"], 5000, &mut audit, &None).unwrap_or_default();
    let virt = evidence::run_command("systemd-detect-virt", &[], 5000, &mut audit, &None)
        .filter(|v| v != "none");
    let environment = host_environment();
    PlatformInfo {
        os: Os::Linux,
        arch: std::env::consts::ARCH.to_string(),
        kernel,
        distro,
        distro_version: version,
        family,
        virtualized: virt,
        environment,
    }
}

#[cfg(windows)]
fn detect_windows() -> PlatformInfo {
    // SAFETY: RtlGetVersion writes into a correctly-sized struct whose
    // dwOSVersionInfoSize we set; no pointers beyond the struct itself.
    unsafe {
        let mut info: windows_sys::Win32::System::SystemInformation::OSVERSIONINFOW =
            std::mem::zeroed();
        info.dwOSVersionInfoSize = std::mem::size_of_val(&info) as u32;
        let ok = windows_sys::Wdk::System::SystemServices::RtlGetVersion(&mut info);
        let kernel = if ok == 0 {
            format!(
                "{}.{}.{}",
                info.dwMajorVersion, info.dwMinorVersion, info.dwBuildNumber
            )
        } else {
            std::env::var("OS").unwrap_or_default()
        };
        let environment = host_environment();
        PlatformInfo {
            os: Os::Windows,
            arch: std::env::consts::ARCH.to_string(),
            kernel,
            distro: None,
            distro_version: None,
            family: DistroFamily::Unknown,
            virtualized: None,
            environment,
        }
    }
}

#[cfg(not(windows))]
fn detect_windows() -> PlatformInfo {
    // `detect` only calls this on Windows; keep the function total so no
    // platform combination can panic.
    detect_linux()
}

pub fn detect() -> PlatformInfo {
    if cfg!(windows) {
        detect_windows()
    } else {
        detect_linux()
    }
}

// ---------------------------------------------------------------------------
// Environment detection (bare metal / VM / container / WSL)
// ---------------------------------------------------------------------------

/// Real-host probe used by [`detect`]. Commands/reads are recorded in a
/// throwaway audit — the plugin scan re-detects through `ScanContext`.
struct HostProbe<'a> {
    audit: &'a mut SelfAudit,
}

impl EnvProbe for HostProbe<'_> {
    fn env_read(&mut self, abs_path: &str) -> Option<String> {
        evidence::read_file_capped(std::path::Path::new(abs_path), self.audit)
    }

    fn env_cmd(&mut self, program: &str, args: &[&str]) -> Option<String> {
        evidence::run_command(program, args, 5000, self.audit, &None)
    }

    fn env_var(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }

    fn is_windows(&self) -> bool {
        cfg!(windows)
    }

    fn arch(&self) -> &str {
        std::env::consts::ARCH
    }
}

/// Detect once per process for the real host; repeated probes are cached
/// (tests call `detect()` frequently and must not re-spawn tools).
fn host_environment() -> EnvironmentInfo {
    static HOST_ENV: std::sync::OnceLock<EnvironmentInfo> = std::sync::OnceLock::new();
    HOST_ENV
        .get_or_init(|| {
            let mut audit = SelfAudit::default();
            let mut probe = HostProbe { audit: &mut audit };
            detect_environment(&mut probe)
        })
        .clone()
}

/// Classify the runtime environment from multiple independent read-only
/// signals. Never a single probe: filesystem markers, cgroup markers,
/// mount tables, `systemd-detect-virt`, DMI (Linux) and
/// `Win32_ComputerSystem` (Windows) are all combined. Failure to observe
/// anything degrades to [`Environment::Unknown`], never a panic.
pub fn detect_environment(probe: &mut impl EnvProbe) -> EnvironmentInfo {
    if probe.is_windows() {
        detect_environment_windows(probe)
    } else {
        detect_environment_linux(probe)
    }
}

const CONTAINER_MARKERS: &[&str] = &[
    "docker",
    "kubepods",
    "containerd",
    "lxc",
    "podman",
    "libpod",
];

fn container_marker(text: &str) -> Option<&'static str> {
    let lower = text.to_ascii_lowercase();
    CONTAINER_MARKERS
        .iter()
        .copied()
        .find(|m| lower.contains(m))
}

fn is_container_virt(v: &str) -> bool {
    matches!(
        v,
        "docker"
            | "podman"
            | "lxc"
            | "lxc-libvirt"
            | "systemd-nspawn"
            | "containerd"
            | "rkt"
            | "openvz"
    )
}

fn is_vm_virt(v: &str) -> bool {
    matches!(
        v,
        "kvm"
            | "amazon"
            | "qemu"
            | "bochs"
            | "xen"
            | "uml"
            | "vmware"
            | "oracle"
            | "microsoft"
            | "zvm"
            | "parallels"
            | "bhyve"
            | "qnx"
            | "acrn"
            | "powervm"
            | "google"
    )
}

/// Friendly hypervisor label for a `systemd-detect-virt` token.
fn friendly_virt(v: &str) -> String {
    match v {
        "kvm" => "KVM",
        "qemu" => "QEMU",
        "vmware" => "VMware",
        "microsoft" => "Microsoft Hyper-V",
        "amazon" => "Amazon EC2",
        "google" => "Google Compute Engine",
        "xen" => "Xen",
        "oracle" => "Oracle VM",
        "parallels" => "Parallels",
        "bochs" => "Bochs",
        "bhyve" => "bhyve",
        "uml" => "User-Mode Linux",
        "acrn" => "ACRN",
        other => other,
    }
    .to_string()
}

/// Map a DMI / `Win32_ComputerSystem` vendor+model pair to a hypervisor
/// label. Only positive virtualization markers match; physical vendors
/// (Dell, HP, MSI, Supermicro, …) return `None`.
fn dmi_hypervisor(vendor: &str, product: &str) -> Option<String> {
    let hay = format!("{vendor} {product}").to_ascii_lowercase();
    const MARKERS: &[(&str, &str)] = &[
        ("vmware", "VMware"),
        ("virtualbox", "VirtualBox"),
        ("innotek", "VirtualBox"),
        ("kvm", "KVM"),
        ("qemu", "QEMU"),
        ("xen", "Xen"),
        ("amazon", "Amazon EC2"),
        ("google", "Google Compute Engine"),
        ("virtual machine", "Microsoft Hyper-V"),
        ("parallels", "Parallels"),
        ("bochs", "Bochs"),
        ("bhyve", "bhyve"),
        ("openstack", "OpenStack"),
        ("digitalocean", "DigitalOcean"),
        ("nutanix", "Nutanix AHV"),
    ];
    MARKERS
        .iter()
        .find(|(k, _)| hay.contains(k))
        .map(|(_, v)| (*v).to_string())
}

fn detect_environment_linux(probe: &mut impl EnvProbe) -> EnvironmentInfo {
    let mut signals: Vec<String> = Vec::new();
    let mut container: Option<String> = None;
    let mut wsl = false;
    let mut vm: Option<String> = None;
    let mut observed = false;

    // WSL: the kernel string is Microsoft-branded.
    if let Some(v) = probe.env_read("/proc/version") {
        observed = true;
        let lower = v.to_ascii_lowercase();
        if lower.contains("microsoft") || lower.contains("wsl") {
            wsl = true;
            signals.push("/proc/version: Microsoft/WSL".into());
        }
    }
    // Docker's flag file.
    if probe.env_read("/.dockerenv").is_some() {
        observed = true;
        container.get_or_insert_with(|| "docker".into());
        signals.push("/.dockerenv present".into());
    }
    // Podman's flag file.
    if probe.env_read("/run/.containerenv").is_some() {
        observed = true;
        container.get_or_insert_with(|| "containerenv".into());
        signals.push("/run/.containerenv present".into());
    }
    // cgroup v1 markers (v2 may be flat, so this is one signal among many).
    for path in ["/proc/1/cgroup", "/proc/self/cgroup"] {
        if let Some(cg) = probe.env_read(path) {
            observed = true;
            if let Some(m) = container_marker(&cg) {
                container.get_or_insert_with(|| m.to_string());
                signals.push(format!("{path}: {m}"));
            }
        }
    }
    // Overlay root filesystem (the usual container image layout).
    if let Some(mi) = probe.env_read("/proc/self/mountinfo") {
        observed = true;
        let overlay_root = mi.lines().any(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            f.len() >= 7 && f.get(4) == Some(&"/") && f.iter().any(|t| *t == "overlay")
        });
        if overlay_root {
            container.get_or_insert_with(|| "overlay-rootfs".into());
            signals.push("/proc/self/mountinfo: overlay root filesystem".into());
        }
    }
    // systemd's own detector.
    if let Some(v) = probe.env_cmd("systemd-detect-virt", &[]) {
        observed = true;
        let v = v.trim().to_ascii_lowercase();
        if !v.is_empty() {
            signals.push(format!("systemd-detect-virt: {v}"));
        }
        if is_container_virt(&v) {
            container.get_or_insert_with(|| v.clone());
        } else if v == "wsl" {
            wsl = true;
        } else if is_vm_virt(&v) {
            vm.get_or_insert_with(|| friendly_virt(&v));
        }
    }
    // DMI firmware strings (VM vendors and product names).
    if let Some(vendor) = probe.env_read("/sys/class/dmi/id/sys_vendor") {
        observed = true;
        let vendor = vendor.trim().to_string();
        signals.push(format!("dmi sys_vendor: {vendor}"));
        if let Some(h) = dmi_hypervisor(&vendor, "") {
            vm.get_or_insert(h);
        }
    }
    if let Some(product) = probe.env_read("/sys/class/dmi/id/product_name") {
        observed = true;
        let product = product.trim().to_string();
        signals.push(format!("dmi product_name: {product}"));
        if let Some(h) = dmi_hypervisor("", &product) {
            vm.get_or_insert(h);
        }
    }

    let kind = if container.is_some() {
        Environment::Container
    } else if wsl {
        Environment::Wsl
    } else if vm.is_some() {
        Environment::VirtualMachine
    } else if observed {
        Environment::BareMetal
    } else {
        signals.push("no environment signals observable".into());
        Environment::Unknown
    };
    let hypervisor = match kind {
        Environment::Container => None,
        Environment::Wsl => vm.or_else(|| Some("Microsoft WSL".into())),
        Environment::VirtualMachine => vm,
        _ => None,
    };
    EnvironmentInfo {
        kind,
        signals,
        hypervisor,
    }
}

fn json_field<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(|v| v.as_str())
}

fn detect_environment_windows(probe: &mut impl EnvProbe) -> EnvironmentInfo {
    let mut signals: Vec<String> = Vec::new();
    let mut container: Option<String> = None;
    let mut vm: Option<String> = None;
    let mut observed = false;

    // Container markers exposed through the process environment.
    for var in ["CONTAINER_TYPE", "CONTAINER", "DOCKER_CONTAINER", "DOCKER"] {
        if let Some(v) = probe.env_var(var) {
            let v = v.trim().to_string();
            if !v.is_empty() && !v.eq_ignore_ascii_case("false") && v != "0" {
                observed = true;
                signals.push(format!("env {var}={v}"));
                container.get_or_insert_with(|| format!("env:{var}"));
            }
        }
    }
    // Registry marker written by Windows container hosts.
    if let Some(out) = probe.env_cmd(
        "reg",
        &[
            "query",
            r"HKLM\SYSTEM\CurrentControlSet\Control\ContainerType",
        ],
    ) {
        observed = true;
        if out.to_ascii_lowercase().contains("containertype") {
            container.get_or_insert_with(|| "registry:ContainerType".into());
            signals.push("registry ContainerType present".into());
        }
    }
    // Win32_ComputerSystem is the authoritative hypervisor/vendor signal.
    if let Some(out) = probe.env_cmd(
        "powershell",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,HypervisorPresent | ConvertTo-Json -Compress",
        ],
    ) {
        observed = true;
        let parsed: Option<serde_json::Value> = serde_json::from_str(&out).ok();
        let obj = parsed.as_ref().and_then(|v| {
            v.as_array()
                .and_then(|a| a.first())
                .or(Some(v))
        });
        let manufacturer = obj.and_then(|o| json_field(o, "Manufacturer")).unwrap_or("");
        let model = obj.and_then(|o| json_field(o, "Model")).unwrap_or("");
        let hypervisor_present = obj
            .and_then(|o| o.get("HypervisorPresent"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !manufacturer.is_empty() {
            signals.push(format!("Win32_ComputerSystem Manufacturer: {manufacturer}"));
        }
        if !model.is_empty() {
            signals.push(format!("Win32_ComputerSystem Model: {model}"));
        }
        if hypervisor_present {
            signals.push("Win32_ComputerSystem HypervisorPresent: true".into());
        }
        // HypervisorPresent is true both for guests AND for bare metal
        // running Hyper-V/VBS, so only the vendor/model pair may classify
        // the host as a virtual machine.
        if let Some(h) = dmi_hypervisor(manufacturer, model) {
            vm = Some(h);
        }
    }

    // A Hyper-V-isolated container reports a "Virtual Machine" model but
    // is still a container; container detection wins.
    let kind = if container.is_some() {
        Environment::Container
    } else if vm.is_some() {
        Environment::VirtualMachine
    } else if observed {
        Environment::BareMetal
    } else {
        signals.push("no environment signals observable".into());
        Environment::Unknown
    };
    let hypervisor = if kind == Environment::VirtualMachine {
        vm
    } else {
        None
    };
    EnvironmentInfo {
        kind,
        signals,
        hypervisor,
    }
}

/// Lower our own process priority so the scan never disturbs a busy
/// server (spec §4.8). Best-effort: failures are ignored.
pub fn lower_own_priority() {
    #[cfg(unix)]
    unsafe {
        // SAFETY: libc::nice only touches the calling process's nice
        // value; return value (new nice or -1) is irrelevant here.
        let _ = libc::nice(10);
    }
    #[cfg(windows)]
    unsafe {
        // SAFETY: constants and a pseudo-handle; no user pointers.
        use windows_sys::Win32::System::Threading::{
            GetCurrentProcess, SetPriorityClass, BELOW_NORMAL_PRIORITY_CLASS,
        };
        SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS);
    }
}
