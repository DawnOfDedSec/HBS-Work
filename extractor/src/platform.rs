//! Runtime platform/arch/distro detection and own-priority lowering.
//! One binary detects everything at runtime — there are no per-distro
//! builds (spec §3).

use crate::evidence;
use crate::model::SelfAudit;

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

#[derive(Clone, Debug)]
pub struct PlatformInfo {
    pub os: Os,
    pub arch: String,
    pub kernel: String,
    pub distro: Option<String>,
    pub distro_version: Option<String>,
    pub family: DistroFamily,
    pub virtualized: Option<String>,
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
    let (distro, version, family) = match evidence::read_file_capped(std::path::Path::new("/etc/os-release"), &mut audit) {
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
    let kernel = evidence::run_command("uname", &["-r"], 5000, &mut audit, &None).unwrap_or_default();
    let virt = evidence::run_command("systemd-detect-virt", &[], 5000, &mut audit, &None)
        .filter(|v| v != "none");
    PlatformInfo {
        os: Os::Linux,
        arch: std::env::consts::ARCH.to_string(),
        kernel,
        distro,
        distro_version: version,
        family,
        virtualized: virt,
    }
}

#[cfg(windows)]
fn detect_windows() -> PlatformInfo {
    // SAFETY: RtlGetVersion writes into a correctly-sized struct whose
    // dwOSVersionInfoSize we set; no pointers beyond the struct itself.
    unsafe {
        let mut info: windows_sys::Win32::System::SystemInformation::OSVERSIONINFOW = std::mem::zeroed();
        info.dwOSVersionInfoSize = std::mem::size_of_val(&info) as u32;
        let ok = windows_sys::Wdk::System::SystemServices::RtlGetVersion(&mut info);
        let kernel = if ok == 0 {
            format!("{}.{}.{}", info.dwMajorVersion, info.dwMinorVersion, info.dwBuildNumber)
        } else {
            std::env::var("OS").unwrap_or_default()
        };
        PlatformInfo {
            os: Os::Windows,
            arch: std::env::consts::ARCH.to_string(),
            kernel,
            distro: None,
            distro_version: None,
            family: DistroFamily::Unknown,
            virtualized: None,
        }
    }
}

#[cfg(not(windows))]
fn detect_windows() -> PlatformInfo {
    unreachable!("detect_windows called on non-windows")
}

pub fn detect() -> PlatformInfo {
    if cfg!(windows) {
        detect_windows()
    } else {
        detect_linux()
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
