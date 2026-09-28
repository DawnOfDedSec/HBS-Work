//! HBS Console - Tauri 2 desktop shell (Windows, macOS, Linux).
//!
//! This is an optional *shell* around the same dashboard that the web install
//! gives you: it owns the lifecycle of the Bun dashboard server, adds a tray
//! icon, desktop shortcuts and launch-at-login, and opens the console either
//! embedded (native window) or in your browser. The dashboard itself is
//! untouched - every URL still works in a plain browser.
//!
//! Install root (mirrors scripts/install.sh + scripts/install.ps1):
//!   Windows: %LOCALAPPDATA%\HBS   (override: HBS_INSTALL_DIR / HBS_HOME)
//!   macOS:   ~/.hbs               (override: HBS_HOME)
//!   Linux:   ~/.hbs               (override: HBS_HOME)
//!
//! Layout: <root>\bin\hbs-server(.exe)  standalone dashboard binary (no Bun needed)
//!         <root>\app\dashboard\        source checkout (optional, dev installs)
//!         <root>\data\                 database, reports, hbs.env, server.log

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde_json::json;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, WebviewUrl, WebviewWindowBuilder};

const TRAY_ID: &str = "hbs-tray";
const MAIN_WINDOW: &str = "main";
const CONSOLE_WINDOW: &str = "console";

// Menu ids
const M_OPEN: &str = "open";
const M_BROWSER: &str = "browser";
const M_START: &str = "start";
const M_STOP: &str = "stop";
const M_RESTART: &str = "restart";
const M_LOGS: &str = "logs";
const M_DATA: &str = "data";
const M_UPDATE: &str = "update";
const M_AUTOSTART: &str = "autostart";
const M_QUIT: &str = "quit";
const M_QUIT_STOP: &str = "quit-stop";

// ---------------------------------------------------------------- paths/env

fn home_dir() -> PathBuf {
    let var = if cfg!(target_os = "windows") {
        "USERPROFILE"
    } else {
        "HOME"
    };
    std::env::var(var).map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("."))
}

/// Where the HBS install lives. Resolution order:
///   1. HBS_INSTALL_DIR / HBS_HOME (dev runs, installer-launched shortcuts)
///   2. the root hint the desktop-app installer persisted (Windows registry /
///      ~/.config/hbs/root elsewhere) - covers custom --dir installs
///   3. the platform default
fn install_root() -> PathBuf {
    for key in ["HBS_INSTALL_DIR", "HBS_HOME"] {
        if let Ok(v) = std::env::var(key) {
            if !v.trim().is_empty() {
                return PathBuf::from(v);
            }
        }
    }
    if let Some(root) = stored_root() {
        return root;
    }
    if cfg!(target_os = "windows") {
        std::env::var("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home_dir().join("AppData").join("Local"))
            .join("HBS")
    } else {
        home_dir().join(".hbs")
    }
}

#[cfg(target_os = "windows")]
fn stored_root() -> Option<PathBuf> {
    // HKCU\Software\PotenFYR\HBS-Console : InstallRoot (REG_SZ), written by
    // scripts/install-desktop.ps1 at install time.
    use std::os::windows::ffi::OsStringExt;
    let key = std::ffi::OsString::from_wide(&winreg_read(
        "Software\\PotenFYR\\HBS-Console",
        "InstallRoot",
    )?)
    .into_string()
    .ok()?;
    let trimmed = trim_quotes(&key);
    if trimmed.is_empty() {
        None
    } else {
        Some(PathBuf::from(trimmed))
    }
}

#[cfg(not(target_os = "windows"))]
fn stored_root() -> Option<PathBuf> {
    let path = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| home_dir().join(".config"))
        .join("hbs")
        .join("root");
    let text = std::fs::read_to_string(path).ok()?;
    let trimmed = trim_quotes(text.trim());
    if trimmed.is_empty() {
        None
    } else {
        Some(PathBuf::from(trimmed))
    }
}

fn trim_quotes(s: &str) -> String {
    s.trim().trim_matches('"').to_string()
}

/// Minimal RegGetValueW reader: avoids a whole registry crate for one value.
#[cfg(target_os = "windows")]
fn winreg_read(subkey: &str, value: &str) -> Option<Vec<u16>> {
    #[link(name = "advapi32")]
    extern "system" {
        fn RegGetValueW(
            hkey: usize,
            lpsubkey: *const u16,
            lpvalue: *const u16,
            dwflags: u32,
            pdwtype: *mut u32,
            pvdata: *mut u8,
            pcbdata: *mut u32,
        ) -> i32;
    }
    const HKEY_CURRENT_USER: usize = 0x8000_0001;
    const RRF_RT_REG_SZ: u32 = 0x0000_0002;
    const ERROR_SUCCESS: i32 = 0;

    let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
    let sub = wide(subkey);
    let val = wide(value);
    let mut kind: u32 = 0;
    let mut size: u32 = 0;
    let rc = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            sub.as_ptr(),
            val.as_ptr(),
            RRF_RT_REG_SZ,
            &mut kind,
            std::ptr::null_mut(),
            &mut size,
        )
    };
    if rc != ERROR_SUCCESS || size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let rc = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            sub.as_ptr(),
            val.as_ptr(),
            RRF_RT_REG_SZ,
            &mut kind,
            buf.as_mut_ptr(),
            &mut size,
        )
    };
    if rc != ERROR_SUCCESS {
        return None;
    }
    Some(
        buf.chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|c| *c != 0)
            .collect(),
    )
}

struct AppState {
    root: PathBuf,
    port: Mutex<u16>,
    /// The server process, when this shell started it.
    child: Mutex<Option<Child>>,
}

impl AppState {
    fn app_dir(&self) -> PathBuf {
        self.root.join("app")
    }
    fn bin_dir(&self) -> PathBuf {
        self.root.join("bin")
    }
    fn data_dir(&self) -> PathBuf {
        self.root.join("data")
    }
    fn log_file(&self) -> PathBuf {
        self.data_dir().join("server.log")
    }
    /// PID of the engine, written by this app and by the installers' CLIs, so
    /// any of them can stop or restart a server the others started.
    fn pid_file(&self) -> PathBuf {
        self.data_dir().join("server.pid")
    }
    fn entry(&self) -> PathBuf {
        self.app_dir().join("dashboard").join("server").join("index.ts")
    }
    fn port(&self) -> u16 {
        *self.port.lock().unwrap()
    }
    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port())
    }
    fn server_up(&self) -> bool {
        let addr = format!("127.0.0.1:{}", self.port());
        addr.parse()
            .ok()
            .and_then(|a| TcpStream::connect_timeout(&a, Duration::from_millis(400)).ok())
            .is_some()
    }

    fn log(&self, line: &str) {
        let _ = std::fs::create_dir_all(self.data_dir());
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.log_file())
        {
            let _ = writeln!(f, "[{}] [desktop] {}", now_stamp(), line);
        }
    }

    /// PORT + everything from data/hbs.env, injected into the server process.
    fn server_env(&self) -> Vec<(String, String)> {
        let mut envs: Vec<(String, String)> = Vec::new();
        if let Ok(text) = std::fs::read_to_string(self.data_dir().join("hbs.env")) {
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some((k, v)) = line.split_once('=') {
                    let k = k.trim();
                    if !k.is_empty() {
                        envs.push((k.to_string(), v.trim().to_string()));
                    }
                }
            }
        }
        let root = self.data_dir().to_string_lossy().into_owned();
        if !envs.iter().any(|(k, _)| k == "HBS_DATA_ROOT") {
            envs.push(("HBS_DATA_ROOT".into(), root));
        }
        envs.push(("PORT".into(), self.port().to_string()));
        envs
    }

    fn reload_port(&self) {
        let mut port = 3000u16;
        if let Ok(text) = std::fs::read_to_string(self.data_dir().join("hbs.env")) {
            for line in text.lines() {
                if let Some(v) = line.trim().strip_prefix("PORT=") {
                    if let Ok(n) = v.trim().parse::<u16>() {
                        port = n;
                    }
                }
            }
        }
        *self.port.lock().unwrap() = port;
    }

    /// Start the dashboard if nothing answers yet. Prefers a service-owned
    /// server (systemd/launchd) and falls back to spawning the standalone
    /// server binary ourselves (Bun runs it from source only as a fallback).
    fn ensure_started(&self) -> Result<(), String> {
        if self.server_up() {
            return Ok(());
        }
        if self.service_exists() {
            self.service_ctl("start")?;
            if self.wait_up(20) {
                return Ok(());
            }
        }
        let server = find_server(self).ok_or_else(|| {
            "the dashboard engine is missing - use Install engine to fetch it, or re-run the HBS installer".to_string()
        })?;
        let mut cmd = if server.ends_with("bun") || server.ends_with("bun.exe") {
            let mut c = Command::new(&server);
            c.arg("run")
                .arg("server/index.ts")
                .current_dir(self.app_dir().join("dashboard"));
            c
        } else {
            let mut c = Command::new(&server);
            c.current_dir(self.data_dir());
            c
        };
        for (k, v) in self.server_env() {
            cmd.env(k, v);
        }
        std::fs::create_dir_all(self.data_dir()).map_err(|e| e.to_string())?;
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.log_file())
            .map_err(|e| format!("cannot open {}: {e}", self.log_file().display()))?;
        let log2 = log.try_clone().map_err(|e| e.to_string())?;
        cmd.stdout(Stdio::from(log)).stderr(Stdio::from(log2));
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        let child = cmd
            .spawn()
            .map_err(|e| format!("could not start the dashboard ({}): {e}", server.display()))?;
        let pid = child.id();
        *self.child.lock().unwrap() = Some(child);
        // Publish the pid so the CLIs and the standalone tray can stop a
        // server this app started (and vice versa).
        let _ = std::fs::write(self.pid_file(), pid.to_string());
        self.log(&format!("started dashboard (pid {pid})"));
        if self.wait_up(30) {
            Ok(())
        } else {
            Err("dashboard did not answer within 30s - see View logs".into())
        }
    }

    fn wait_up(&self, secs: u64) -> bool {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < deadline {
            if self.server_up() {
                return true;
            }
            thread::sleep(Duration::from_millis(250));
        }
        self.server_up()
    }

    /// Stop the engine, whoever started it: our own child, a systemd/launchd
    /// unit, or a detached process the installer (or a previous shell) left
    /// behind and recorded in server.pid. Windows has no service manager, so
    /// adoption through the pid file is what makes tray Stop/Restart work.
    fn stop(&self) -> Result<(), String> {
        let owned = { self.child.lock().unwrap().take() };
        if let Some(mut child) = owned {
            let pid = child.id();
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_file(self.pid_file());
            self.log(&format!("stopped dashboard (pid {pid})"));
            return Ok(());
        }
        if self.service_exists() {
            return self.service_ctl("stop");
        }
        if let Some(pid) = self.read_pid() {
            if pid_alive(pid) {
                if terminate_pid(pid) {
                    let _ = std::fs::remove_file(self.pid_file());
                    self.log(&format!("stopped dashboard (pid {pid})"));
                    return Ok(());
                }
                return Err(format!("could not stop process {pid}"));
            }
            let _ = std::fs::remove_file(self.pid_file());
        }
        if self.server_up() {
            return Err(
                "a dashboard is answering but no pid file identifies it - stop it with `hbs stop`"
                    .into(),
            );
        }
        Err("no HBS server is running".into())
    }

    /// Read the engine pid recorded in the data directory.
    fn read_pid(&self) -> Option<u32> {
        std::fs::read_to_string(self.pid_file())
            .ok()
            .and_then(|text| text.trim().parse::<u32>().ok())
    }

    fn restart(&self) -> Result<(), String> {
        if self.child.lock().unwrap().is_some() {
            self.stop()?;
            thread::sleep(Duration::from_millis(400));
            return self.ensure_started();
        }
        if self.service_exists() {
            self.service_ctl("restart")?;
            if self.wait_up(25) {
                return Ok(());
            }
            return Err("service did not come back within 25s".into());
        }
        // Adopted or externally started: stop it, then bring it back under our
        // own control. Without this, Restart was a silent no-op on Windows.
        if self.server_up() || self.read_pid().map(pid_alive).unwrap_or(false) {
            self.stop()?;
            thread::sleep(Duration::from_millis(400));
        }
        self.ensure_started()
    }

    /// Hand the child to the OS and return - used by "Quit (keep server)".
    fn detach(&self) {
        if let Some(child) = self.child.lock().unwrap().take() {
            std::mem::forget(child);
        }
    }

    // --- service manager (systemd --user on Linux, launchd on macOS) --------

    #[cfg(target_os = "linux")]
    fn service_exists(&self) -> bool {
        Command::new("systemctl")
            .args(["--user", "cat", "hbs"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[cfg(target_os = "linux")]
    fn service_ctl(&self, action: &str) -> Result<(), String> {
        let st = Command::new("systemctl")
            .args(["--user", action, "hbs"])
            .status()
            .map_err(|e| format!("systemctl: {e}"))?;
        if st.success() {
            Ok(())
        } else {
            Err(format!("systemctl --user {action} hbs failed"))
        }
    }

    #[cfg(target_os = "macos")]
    fn service_exists(&self) -> bool {
        let uid = Command::new("id").arg("-u").output().ok().and_then(|o| {
            String::from_utf8(o.stdout).ok().map(|s| s.trim().to_string())
        });
        match uid {
            Some(uid) => Command::new("launchctl")
                .args(["print", &format!("gui/{uid}/net.hbs.dashboard")])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false),
            None => false,
        }
    }

    #[cfg(target_os = "macos")]
    fn service_ctl(&self, action: &str) -> Result<(), String> {
        let uid = Command::new("id")
            .arg("-u")
            .output()
            .map_err(|e| format!("id -u: {e}"))?;
        let uid = String::from_utf8_lossy(&uid.stdout).trim().to_string();
        let plist = home_dir()
            .join("Library")
            .join("LaunchAgents")
            .join("net.hbs.dashboard.plist");
        let label = format!("gui/{uid}/net.hbs.dashboard");
        let st = match action {
            "stop" => Command::new("launchctl").args(["bootout", &label]).status(),
            "start" => Command::new("launchctl")
                .args(["bootstrap", &format!("gui/{uid}"), &plist.to_string_lossy()])
                .status(),
            _ => Command::new("launchctl")
                .args(["kickstart", "-k", &label])
                .status(),
        }
        .map_err(|e| format!("launchctl: {e}"))?;
        if st.success() {
            Ok(())
        } else {
            Err(format!("launchctl {action} failed"))
        }
    }

    #[cfg(target_os = "windows")]
    fn service_exists(&self) -> bool {
        false
    }

    #[cfg(target_os = "windows")]
    fn service_ctl(&self, _action: &str) -> Result<(), String> {
        Err("no service manager on Windows; use Start/Stop in this menu".into())
    }
}

/// True while a process with this id exists.
fn pid_alive(pid: u32) -> bool {
    #[cfg(target_os = "windows")]
    {
        // tasklist rows are "image  pid  session  #  memory"; match the pid
        // column exactly rather than substring-searching the whole row.
        let needle = pid.to_string();
        Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/NH"])
            .output()
            .map(|out| {
                String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .any(|line| line.split_whitespace().nth(1) == Some(needle.as_str()))
            })
            .unwrap_or(false)
    }
    #[cfg(unix)]
    {
        Command::new("kill")
            .args(["-0", &pid.to_string()])
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }
}

/// Terminate a process we did not spawn. Returns true when the OS accepted it.
fn terminate_pid(pid: u32) -> bool {
    #[cfg(target_os = "windows")]
    {
        Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }
    #[cfg(unix)]
    {
        Command::new("kill")
            .arg(pid.to_string())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }
}

fn now_stamp() -> String {
    // UTC "YYYY-MM-DD hh:mm:ss" without pulling in a date crate.
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // civil-from-days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}:{s:02}")
}

fn find_bun() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("HBS_BUN") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }
    let exe = if cfg!(target_os = "windows") { "bun.exe" } else { "bun" };
    let candidates = [
        home_dir().join(".bun").join("bin").join(exe),
        install_root().join("bin").join(exe),
        PathBuf::from("/usr/local/bin").join(exe),
        PathBuf::from("/usr/bin").join(exe),
        PathBuf::from("/opt/homebrew/bin").join(exe),
    ];
    for c in candidates {
        if c.is_file() {
            return Some(c);
        }
    }
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let c = dir.join(exe);
            if c.is_file() {
                return Some(c);
            }
        }
    }
    None
}

/// The dashboard to run, best option first:
///   1. HBS_SERVER override
///   2. the standalone server binary the installer ships (<root>/bin)
///   3. Bun running the app from source (repo checkouts)
fn find_server(state: &AppState) -> Option<PathBuf> {
    if let Ok(p) = std::env::var("HBS_SERVER") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }
    let exe = if cfg!(target_os = "windows") {
        "hbs-server.exe"
    } else {
        "hbs-server"
    };
    let standalone = state.bin_dir().join(exe);
    if standalone.is_file() {
        return Some(standalone);
    }
    if state.entry().exists() {
        return find_bun();
    }
    None
}

/// The `hbs` control CLI, when installed - used by the Update action so the
/// desktop app and the CLI share one update path.
fn find_cli(state: &AppState) -> Option<PathBuf> {
    let exe = if cfg!(target_os = "windows") {
        "hbs.cmd"
    } else {
        "hbs"
    };
    let candidate = state.bin_dir().join(exe);
    if candidate.is_file() {
        return Some(candidate);
    }
    let user_local = home_dir().join(".local").join("bin").join(exe);
    if user_local.is_file() {
        return Some(user_local);
    }
    None
}

// ------------------------------------------------------ engine provisioning
// The desktop installers ship only the shell. The engine is one release asset
// per platform (install.ps1/install.sh use the same names), so when the shell
// starts without one it fetches the matching gzip, verifies the SHA-256 from
// manifest.json, and unpacks it into <root>/bin. This is why a standalone
// "HBS.Console_x64-setup.exe" install still ends up with a working dashboard.

const RELEASE_BASE_DEFAULT: &str = "https://github.com/PotenFYR-Studios/HBS-Tool/releases";

fn release_base() -> String {
    std::env::var("HBS_RELEASE_URL").unwrap_or_else(|_| RELEASE_BASE_DEFAULT.to_string())
}

fn http_client() -> Result<reqwest::blocking::Client, String> {
    // Redirects are followed: GitHub serves release assets through one, and
    // /latest is one too. resolve_tag() reads the final URL, so this needs no
    // API call and hits no rate limit.
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(300))
        .user_agent("hbs-console-desktop")
        .build()
        .map_err(|e| format!("http client: {e}"))
}

fn is_musl_host() -> bool {
    if std::path::Path::new("/etc/alpine-release").exists() {
        return true;
    }
    std::process::Command::new("ldd")
        .arg("--version")
        .output()
        .map(|out| {
            let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&out.stderr));
            text.contains("musl")
        })
        .unwrap_or(false)
}

/// Release asset target triple for this machine, matching the installers.
fn engine_target() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => Some("bun-windows-x64"),
        ("linux", "x86_64") => Some(if is_musl_host() { "bun-linux-x64-musl" } else { "bun-linux-x64" }),
        ("linux", "aarch64") => Some(if is_musl_host() { "bun-linux-arm64-musl" } else { "bun-linux-arm64" }),
        ("macos", "x86_64") => Some("bun-darwin-x64"),
        ("macos", "aarch64") => Some("bun-darwin-arm64"),
        _ => None,
    }
}

fn resolve_tag(client: &reqwest::blocking::Client, base: &str) -> Result<String, String> {
    if let Ok(tag) = std::env::var("HBS_RELEASE_TAG") {
        if !tag.trim().is_empty() {
            return Ok(tag.trim().to_string());
        }
    }
    let response = client
        .get(format!("{base}/latest"))
        .send()
        .and_then(|response| response.error_for_status())
        .map_err(|e| format!("could not reach {base}: {e}"))?;
    // After following redirects the URL is .../releases/tag/<tag>.
    response
        .url()
        .path()
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|tag| !tag.is_empty())
        .map(|tag| tag.to_string())
        .ok_or_else(|| "could not parse the release tag".to_string())
}

#[derive(serde::Deserialize)]
struct ManifestFile {
    name: String,
    sha256: String,
}

#[derive(serde::Deserialize)]
struct ReleaseManifest {
    version: String,
    files: Vec<ManifestFile>,
}

fn engine_asset<'a>(manifest: &'a ReleaseManifest, target: &str) -> Option<&'a ManifestFile> {
    let wanted = format!("hbs-server-{}-{}.gz", manifest.version, target);
    manifest.files.iter().find(|file| file.name == wanted)
}

fn provision_engine(state: &AppState) -> Result<PathBuf, String> {
    if let Some(existing) = find_server(state) {
        return Ok(existing);
    }
    let target = engine_target().ok_or_else(|| {
        format!(
            "no prebuilt engine for {}/{} - use the HBS installer",
            std::env::consts::OS,
            std::env::consts::ARCH
        )
    })?;
    let base = release_base();
    let client = http_client()?;
    let tag = resolve_tag(&client, &base)?;
    state.log(&format!("provisioning engine from release {tag} ({target})"));

    let manifest: ReleaseManifest = client
        .get(format!("{base}/download/{tag}/manifest.json"))
        .send()
        .and_then(|response| response.error_for_status())
        .map_err(|e| format!("could not read the release manifest: {e}"))?
        .json()
        .map_err(|e| format!("the release manifest is malformed: {e}"))?;

    let asset = engine_asset(&manifest, target)
        .ok_or_else(|| format!("release {tag} has no engine asset for {target}"))?;

    let bytes = client
        .get(format!("{base}/download/{tag}/{}", asset.name))
        .send()
        .and_then(|response| response.error_for_status())
        .map_err(|e| format!("could not download {}: {e}", asset.name))?
        .bytes()
        .map_err(|e| format!("could not read {}: {e}", asset.name))?;

    use sha2::{Digest, Sha256};
    let digest = hex::encode(Sha256::digest(&bytes));
    if digest != asset.sha256.to_lowercase() {
        return Err(format!("checksum mismatch for {} - download corrupted", asset.name));
    }

    let mut unpacked = Vec::with_capacity(bytes.len() * 3);
    flate2::read::GzDecoder::new(&bytes[..])
        .read_to_end(&mut unpacked)
        .map_err(|e| format!("could not unpack {}: {e}", asset.name))?;

    let exe = if cfg!(target_os = "windows") { "hbs-server.exe" } else { "hbs-server" };
    std::fs::create_dir_all(state.bin_dir()).map_err(|e| e.to_string())?;
    let dest = state.bin_dir().join(exe);
    let temp = state.bin_dir().join(format!("{exe}.{}.tmp", std::process::id()));
    std::fs::write(&temp, &unpacked).map_err(|e| format!("could not write {}: {e}", temp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o755));
    }
    std::fs::rename(&temp, &dest).map_err(|e| format!("could not install {}: {e}", dest.display()))?;
    state.log(&format!("engine installed: {}", dest.display()));
    Ok(dest)
}

#[tauri::command]
fn install_engine(state: tauri::State<AppState>) -> Result<serde_json::Value, String> {
    let path = provision_engine(&state)?;
    Ok(json!({ "ok": true, "server": path.to_string_lossy() }))
}

// ------------------------------------------------------------------ actions

fn open_system_browser(url: &str) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut c = Command::new("cmd");
        c.args(["/c", "start", "", url]);
        c
    };
    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut c = Command::new("open");
        c.arg(url);
        c
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut cmd = {
        let mut c = Command::new("xdg-open");
        c.arg(url);
        c
    };
    cmd.stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("could not open browser: {e}"))
}

fn open_system_path(path: &Path) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut c = Command::new("cmd");
        // explorer needs the path as-is; /select would need different args.
        c.args(["/c", "start", "", &path.to_string_lossy()]);
        c
    };
    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut c = Command::new("open");
        c.arg(path);
        c
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut cmd = {
        let mut c = Command::new("xdg-open");
        c.arg(path);
        c
    };
    cmd.stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("could not open {}: {e}", path.display()))
}

/// Show (or create) the embedded dashboard window, then hide the shell page.
fn open_console(app: &AppHandle) -> Result<(), String> {
    let state = app.state::<AppState>();
    state.ensure_started()?;
    let url = state.url();
    let parsed = url.parse().map_err(|e| format!("bad url {url}: {e}"))?;
    if let Some(win) = app.get_webview_window(CONSOLE_WINDOW) {
        let _ = win.show();
        let _ = win.unminimize();
        let _ = win.set_focus();
        let _ = win.eval(&format!("window.location.replace({url:?})"));
    } else {
        WebviewWindowBuilder::new(app, CONSOLE_WINDOW, WebviewUrl::External(parsed))
            .title("HBS Console")
            .inner_size(1280.0, 860.0)
            .min_inner_size(940.0, 620.0)
            .center()
            .build()
            .map_err(|e| format!("could not open console window: {e}"))?;
    }
    if let Some(main) = app.get_webview_window(MAIN_WINDOW) {
        let _ = main.hide();
    }
    Ok(())
}

fn show_shell(app: &AppHandle) {
    if let Some(w) = app.get_webview_window(MAIN_WINDOW) {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

fn run_update(state: &AppState) -> Result<(), String> {
    // Preferred path: the installed `hbs` control CLI downloads the latest
    // release assets (works for binary installs with no git checkout).
    if let Some(cli) = find_cli(state) {
        state.log("updating via the hbs CLI");
        let mut cmd = Command::new(&cli);
        cmd.arg("update");
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        }
        let out = cmd
            .output()
            .map_err(|e| format!("could not run {}: {e}", cli.display()))?;
        state.reload_port();
        if out.status.success() {
            return Ok(());
        }
        state.log(&format!(
            "hbs update failed ({}), falling back to git: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let app = state.app_dir();
    if !app.join(".git").exists() {
        return Err(
            "update failed - re-run the installer to update this install".into(),
        );
    }
    state.log("updating from git");
    for args in [vec!["fetch", "origin", "main"], vec!["reset", "--hard", "origin/main"]] {
        let out = Command::new("git")
            .current_dir(&app)
            .args(&args)
            .output()
            .map_err(|e| format!("git {args:?}: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
    }
    let bun = find_bun().ok_or("Bun runtime not found")?;
    let out = Command::new(bun)
        .current_dir(app.join("dashboard"))
        .args(["install", "--quiet"])
        .output()
        .map_err(|e| format!("bun install: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "bun install failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    state.reload_port();
    let _ = state.stop();
    thread::sleep(Duration::from_millis(400));
    state.ensure_started()
}

fn autostart_enabled(app: &AppHandle) -> bool {
    use tauri_plugin_autostart::ManagerExt;
    app.autolaunch().is_enabled().unwrap_or(false)
}

fn toggle_autostart(app: &AppHandle) {
    use tauri_plugin_autostart::ManagerExt;
    let al = app.autolaunch();
    if al.is_enabled().unwrap_or(false) {
        let _ = al.disable();
    } else {
        let _ = al.enable();
    }
    rebuild_tray(app);
}

// -------------------------------------------------------------------- tray

fn build_menu(app: &AppHandle) -> tauri::Result<Menu<tauri::Wry>> {
    let open = MenuItem::with_id(app, M_OPEN, "Open HBS Console", true, None::<&str>)?;
    let browser = MenuItem::with_id(app, M_BROWSER, "Open in browser", true, None::<&str>)?;
    let sep0 = PredefinedMenuItem::separator(app)?;
    let start = MenuItem::with_id(app, M_START, "Start server", true, None::<&str>)?;
    let stop = MenuItem::with_id(app, M_STOP, "Stop server", true, None::<&str>)?;
    let restart = MenuItem::with_id(app, M_RESTART, "Restart server", true, None::<&str>)?;
    let sep1 = PredefinedMenuItem::separator(app)?;
    let logs = MenuItem::with_id(app, M_LOGS, "View logs", true, None::<&str>)?;
    let data = MenuItem::with_id(app, M_DATA, "Open data folder", true, None::<&str>)?;
    let update = MenuItem::with_id(app, M_UPDATE, "Update HBS", true, None::<&str>)?;
    let sep2 = PredefinedMenuItem::separator(app)?;
    let autostart = CheckMenuItem::with_id(
        app,
        M_AUTOSTART,
        "Launch at login",
        true,
        autostart_enabled(app),
        None::<&str>,
    )?;
    let sep3 = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, M_QUIT, "Quit (keep server running)", true, None::<&str>)?;
    let quit_stop = MenuItem::with_id(app, M_QUIT_STOP, "Quit and stop server", true, None::<&str>)?;
    Menu::with_items(
        app,
        &[
            &open, &browser, &sep0, &start, &stop, &restart, &sep1, &logs, &data, &update, &sep2,
            &autostart, &sep3, &quit, &quit_stop,
        ],
    )
}

fn build_tray(app: &AppHandle) -> tauri::Result<()> {
    let menu = build_menu(app)?;
    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .menu(&menu)
        .show_menu_on_left_click(false)
        .tooltip("HBS Console")
        .on_menu_event(|app, event| handle_menu(app, event.id().as_ref()))
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                open_clicked(tray.app_handle());
            }
        });
    if let Ok(icon) = tauri::image::Image::from_bytes(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/icons/icon.png"
    ))) {
        builder = builder.icon(icon);
    }
    builder.build(app)?;
    Ok(())
}

fn rebuild_tray(app: &AppHandle) {
    let handle = app.clone();
    let _ = app.run_on_main_thread(move || {
        if let Some(tray) = handle.tray_by_id(TRAY_ID) {
            if let Ok(menu) = build_menu(&handle) {
                let _ = tray.set_menu(Some(menu));
            }
        }
    });
}

fn set_tooltip(app: &AppHandle, text: String) {
    let handle = app.clone();
    let _ = app.run_on_main_thread(move || {
        if let Some(tray) = handle.tray_by_id(TRAY_ID) {
            let _ = tray.set_tooltip(Some(text));
        }
    });
}

/// Surface a failure instead of only writing it to the log: show the fallback
/// window with the message, so a tray click never fails silently.
fn report(app: &AppHandle, context: &str, error: String) {
    let state = app.state::<AppState>();
    state.log(&format!("{context} failed: {error}"));
    show_shell(app);
    if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
        let _ = window.eval(&format!(
            "window.dispatchEvent(new CustomEvent('hbs-error', {{detail: {}}}))",
            json!(format!("{context}: {error}"))
        ));
    }
}

fn open_clicked(app: &AppHandle) {
    if let Err(e) = open_console(app) {
        report(app, "open", e);
    }
}

/// Run a lifecycle action off the UI thread. Starting or stopping can wait on
/// a port for up to 30s; doing that on the tray's main thread froze the menu,
/// which read as "the button does nothing".
fn run_lifecycle(app: &AppHandle, label: &'static str, action: fn(&AppState) -> Result<(), String>) {
    let handle = app.clone();
    std::thread::spawn(move || {
        let state = handle.state::<AppState>();
        match action(&state) {
            Ok(()) => {
                let text = if state.server_up() {
                    format!("HBS Console - running (port {})", state.port())
                } else {
                    "HBS Console - stopped".into()
                };
                set_tooltip(&handle, text);
                rebuild_tray(&handle);
                // Point an open console window at the (re)started engine so a
                // restart is visible instead of leaving a stale error page.
                if let Some(window) = handle.get_webview_window(CONSOLE_WINDOW) {
                    let _ = window.eval(&format!("window.location.replace({:?})", state.url()));
                }
                state.log(&format!("{label} complete"));
            }
            Err(e) => report(&handle, label, e),
        }
    });
}

fn handle_menu(app: &AppHandle, id: &str) {
    match id {
        M_OPEN => open_clicked(app),
        M_BROWSER => {
            let handle = app.clone();
            std::thread::spawn(move || {
                let state = handle.state::<AppState>();
                if let Err(e) = state
                    .ensure_started()
                    .and_then(|_| open_system_browser(&state.url()))
                {
                    report(&handle, "open in browser", e);
                }
            });
        }
        M_START => run_lifecycle(app, "start", AppState::ensure_started),
        M_STOP => run_lifecycle(app, "stop", AppState::stop),
        M_RESTART => run_lifecycle(app, "restart", AppState::restart),
        M_LOGS => {
            let state = app.state::<AppState>();
            let log = state.log_file();
            if !log.exists() {
                state.log("(log created)");
            }
            let _ = open_system_path(&log);
        }
        M_DATA => {
            let state = app.state::<AppState>();
            let dir = state.data_dir();
            let _ = std::fs::create_dir_all(&dir);
            let _ = open_system_path(&dir);
        }
        M_UPDATE => {
            // Downloads and reinstalls the engine; never on the UI thread.
            let handle = app.clone();
            std::thread::spawn(move || {
                let state = handle.state::<AppState>();
                match run_update(&state) {
                    Ok(()) => {
                        state.log("update complete");
                        set_tooltip(&handle, format!("HBS Console - running (port {})", state.port()));
                        rebuild_tray(&handle);
                    }
                    Err(e) => report(&handle, "update", e),
                }
            });
        }
        M_AUTOSTART => toggle_autostart(app),
        M_QUIT => {
            app.state::<AppState>().detach();
            app.exit(0);
        }
        M_QUIT_STOP => {
            let state = app.state::<AppState>();
            if let Err(e) = state.stop() {
                state.log(&format!("quit: {e}"));
            }
            app.exit(0);
        }
        _ => {}
    }
}

// ---------------------------------------------------------------- commands

/// Probes the local dashboard for its first-run setup state: `Some(true)` when
/// it answers and still has no administrator, `None` when it does not answer.
/// A substring test on the status JSON keeps this dependency-free.
fn setup_pending(port: u16) -> Option<bool> {
    let addr = format!("127.0.0.1:{port}");
    let mut stream = TcpStream::connect_timeout(&addr.parse().ok()?, Duration::from_millis(500)).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(800)));
    stream
        .write_all(b"GET /api/auth/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut raw = String::new();
    std::io::Read::read_to_string(&mut stream, &mut raw).ok()?;
    let compact: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    Some(compact.contains("\"initialized\":false"))
}

#[tauri::command]
fn status(state: tauri::State<AppState>) -> serde_json::Value {
    json!({
        "running": state.server_up(),
        "setupRequired": setup_pending(state.port()).unwrap_or(false),
        "port": state.port(),
        "url": state.url(),
        "root": state.root.to_string_lossy(),
        "server": find_server(&state).map(|p| p.to_string_lossy().into_owned()),
        "autostart": false,
    })
}

#[tauri::command]
fn start_server(state: tauri::State<AppState>) -> Result<serde_json::Value, String> {
    state.ensure_started()?;
    Ok(json!({ "running": true, "url": state.url() }))
}

#[tauri::command]
fn stop_server(state: tauri::State<AppState>) -> Result<(), String> {
    state.stop()
}

#[tauri::command]
fn restart_server(state: tauri::State<AppState>) -> Result<(), String> {
    state.restart()
}

#[tauri::command]
fn open_dashboard(app: AppHandle, state: tauri::State<AppState>) -> Result<(), String> {
    state.ensure_started()?;
    open_console(&app)
}

#[tauri::command]
fn open_in_browser(state: tauri::State<AppState>) -> Result<(), String> {
    state.ensure_started()?;
    open_system_browser(&state.url())
}

#[tauri::command]
fn open_path(state: tauri::State<AppState>, kind: String) -> Result<(), String> {
    let path = match kind.as_str() {
        "data" => state.data_dir(),
        "logs" => state.log_file(),
        other => return Err(format!("unknown path: {other}")),
    };
    open_system_path(&path)
}

#[tauri::command]
fn autostart_state(app: AppHandle) -> serde_json::Value {
    json!({ "enabled": autostart_enabled(&app) })
}

#[tauri::command]
fn set_autostart(app: AppHandle, enabled: bool) -> Result<bool, String> {
    use tauri_plugin_autostart::ManagerExt;
    let al = app.autolaunch();
    if enabled {
        al.enable().map_err(|e| e.to_string())?;
    } else {
        al.disable().map_err(|e| e.to_string())?;
    }
    Ok(al.is_enabled().unwrap_or(enabled))
}

#[tauri::command]
fn app_info(app: AppHandle) -> serde_json::Value {
    json!({
        "version": app.package_info().version.to_string(),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
    })
}

// -------------------------------------------------------------------- main

fn main() {
    let state = AppState {
        root: install_root(),
        port: Mutex::new(3000),
        child: Mutex::new(None),
    };
    state.reload_port();

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            // Second launch: focus whatever is already open.
            if app.get_webview_window(CONSOLE_WINDOW).is_some() {
                if let Some(w) = app.get_webview_window(CONSOLE_WINDOW) {
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            } else {
                show_shell(app);
            }
        }))
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .manage(state)
        .setup(|app| {
            let handle = app.handle().clone();
            build_tray(&handle)?;

            // Bring the dashboard up in the background, then surface it.
            let bg = handle.clone();
            thread::spawn(move || {
                let state = bg.state::<AppState>();
                let already = state.server_up();
                // A standalone app install (NSIS/MSI/dmg) has no engine yet.
                // Fetch it once, before the first start attempt.
                if !already && find_server(&state).is_none() {
                    if let Err(e) = provision_engine(&state) {
                        state.log(&format!("engine provisioning failed: {e}"));
                    }
                }
                match state.ensure_started() {
                    Ok(()) => {
                        set_tooltip(&bg, format!("HBS Console - running (port {})", state.port()));
                        if !already {
                            let _ = bg.run_on_main_thread(|| {});
                        }
                        // Auto-open the console window on launch.
                        let h = bg.clone();
                        let _ = bg.run_on_main_thread(move || {
                            if let Err(e) = open_console(&h) {
                                let state = h.state::<AppState>();
                                state.log(&format!("auto-open failed: {e}"));
                                show_shell(&h);
                            }
                        });
                    }
                    Err(e) => {
                        state.log(&format!("startup: {e}"));
                        set_tooltip(&bg, "HBS Console - stopped".into());
                        let h = bg.clone();
                        let _ = bg.run_on_main_thread(move || {
                            show_shell(&h);
                            if let Some(w) = h.get_webview_window(MAIN_WINDOW) {
                                let _ = w.eval(&format!(
                                    "window.dispatchEvent(new CustomEvent('hbs-error', {{detail: {}}}))",
                                    json!(e)
                                ));
                            }
                        });
                    }
                }
            });

            // Keep the tray tooltip honest.
            let tick = handle.clone();
            thread::spawn(move || loop {
                thread::sleep(Duration::from_secs(15));
                let state = tick.state::<AppState>();
                let text = if state.server_up() {
                    format!("HBS Console - running (port {})", state.port())
                } else {
                    "HBS Console - stopped".into()
                };
                set_tooltip(&tick, text);
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing any window keeps HBS in the tray; use Quit to exit.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            status,
            start_server,
            stop_server,
            restart_server,
            open_dashboard,
            open_in_browser,
            open_path,
            autostart_state,
            set_autostart,
            install_engine,
            app_info
        ])
        .run(tauri::generate_context!())
        .expect("error while running HBS Console");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_asset_uses_the_installer_asset_name() {
        let manifest = ReleaseManifest {
            version: "1.2.3".into(),
            files: vec![
                ManifestFile {
                    name: "hbs-server-1.2.3-bun-windows-x64.gz".into(),
                    sha256: "aa".into(),
                },
                ManifestFile {
                    name: "hbs-server-1.2.3-bun-linux-x64.gz".into(),
                    sha256: "bb".into(),
                },
            ],
        };
        assert_eq!(engine_asset(&manifest, "bun-windows-x64").unwrap().sha256, "aa");
        assert_eq!(engine_asset(&manifest, "bun-linux-x64").unwrap().sha256, "bb");
        assert!(engine_asset(&manifest, "bun-darwin-arm64").is_none());
    }

    #[test]
    fn pid_helpers_find_and_stop_a_process() {
        #[cfg(target_os = "windows")]
        let mut child = Command::new("cmd")
            .args(["/C", "ping -n 30 127.0.0.1 >NUL"])
            .spawn()
            .expect("spawn child");
        #[cfg(unix)]
        let mut child = Command::new("sleep").arg("30").spawn().expect("spawn child");

        let pid = child.id();
        assert!(pid_alive(pid), "a freshly spawned process must look alive");
        assert!(terminate_pid(pid), "terminate must be accepted by the OS");

        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && pid_alive(pid) {
            thread::sleep(Duration::from_millis(100));
        }
        assert!(!pid_alive(pid), "the process must be gone after terminate");
        let _ = child.wait();
    }

    /// Proves the whole download -> SHA-256 -> gunzip -> install path against
    /// the published release. Network-bound, so opt in with
    /// `cargo test -- --ignored` when a release has just been cut.
    #[test]
    #[ignore = "network: hits the published GitHub release"]
    fn provisions_the_published_engine() {
        let root = std::env::temp_dir().join(format!("hbs-provision-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let state = AppState {
            root: root.clone(),
            port: Mutex::new(3000),
            child: Mutex::new(None),
        };
        let path = provision_engine(&state).expect("provisioning failed");
        assert!(path.is_file(), "engine not written: {}", path.display());
        let bytes = std::fs::read(&path).unwrap();
        assert!(bytes.len() > 1_000_000, "engine suspiciously small: {}", bytes.len());
        let _ = std::fs::remove_dir_all(&root);
    }
}
