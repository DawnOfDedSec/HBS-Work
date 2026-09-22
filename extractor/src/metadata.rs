//! System fingerprint collection. Everything funnels through the
//! ScanContext (root prefix + injector) so both OS collectors are
//! unit-testable on any host. Missing values serialize as null —
//! degraded evidence, never an abort.

use crate::context::ScanContext;
use serde_json::{json, Map, Value};

pub fn collect(ctx: &mut ScanContext) -> Value {
    let mut m = Map::new();
    m.insert("elevated".into(), json!(ctx.elevated));
    if ctx.linux() {
        collect_linux(ctx, &mut m);
    } else {
        collect_windows(ctx, &mut m);
    }
    Value::Object(m)
}

fn set(m: &mut Map<String, Value>, k: &str, v: Value) {
    m.insert(k.to_string(), v);
}

fn trimmed(ctx: &mut ScanContext, path: &str) -> Option<String> {
    ctx.read(path).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn collect_linux(ctx: &mut ScanContext, m: &mut Map<String, Value>) {
    let hostname = trimmed(ctx, "/etc/hostname")
        .or_else(|| ctx.cmd("hostname", &[]));
    set(m, "hostname", json!(hostname));
    let fqdn = ctx.cmd("hostname", &["-f"]).or_else(|| hostname.clone());
    set(m, "fqdn", json!(fqdn));
    set(m, "machine_id", json!(trimmed(ctx, "/etc/machine-id")));
    set(
        m,
        "os_name",
        json!(ctx.platform.distro.clone().unwrap_or_else(|| "Linux".into())),
    );
    set(m, "os_version", json!(ctx.platform.distro_version.clone()));
    let kernel = ctx
        .cmd("uname", &["-r"])
        .filter(|k| !k.is_empty())
        .unwrap_or_else(|| ctx.platform.kernel.clone());
    set(m, "kernel", json!(kernel));
    set(m, "arch", json!(ctx.platform.arch));
    set(m, "distro_family", json!(format!("{:?}", ctx.platform.family)));
    set(m, "virtualization", json!(ctx.platform.virtualized.clone()));

    // uptime / boot
    let uptime = ctx.read("/proc/uptime").and_then(|s| {
        s.split_whitespace().next()
            .and_then(|v| v.parse::<f64>().ok())
            .map(|v| v as u64)
    });
    set(m, "uptime_seconds", json!(uptime));
    let boot = uptime.map(|u| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        now.saturating_sub(u)
    });
    set(m, "last_boot_unix", json!(boot));
    set(m, "install_date_unix", json!(null_first_boot(ctx)));

    // memory
    let meminfo = ctx.read("/proc/meminfo");
    let mem_field = |key: &str| -> Option<u64> {
        meminfo.as_ref().and_then(|s| {
            s.lines().find_map(|l| {
                let (k, rest) = l.split_once(':')?;
                (k == key)
                    .then(|| rest.trim().split_whitespace().next().and_then(|n| n.parse::<u64>().ok()).map(|kb| kb / 1024))
                    .flatten()
            })
        })
    };
    let mem = mem_field("MemTotal");
    set(m, "memory_mb", json!(mem));
    set(m, "memory", json!({
        "total_mb": mem_field("MemTotal"),
        "free_mb": mem_field("MemFree"),
        "available_mb": mem_field("MemAvailable"),
        "swap_total_mb": mem_field("SwapTotal"),
        "swap_free_mb": mem_field("SwapFree"),
    }));

    // cpu
    let cpuinfo = ctx.read("/proc/cpuinfo");
    let cpu_field = |key: &str| -> Option<String> {
        cpuinfo.as_ref().and_then(|s| {
            s.lines()
                .find(|l| l.starts_with(key))
                .and_then(|l| l.split(':').nth(1))
                .map(|v| v.trim().to_string())
        })
    };
    let cpu_model = cpu_field("model name");
    let cpu_cores = cpuinfo.as_ref().map(|s| {
        s.lines().filter(|l| l.starts_with("processor")).count() as u64
    });
    set(m, "cpu_model", json!(cpu_model.clone()));
    set(m, "cpu_cores", json!(cpu_cores));
    set(m, "cpu", json!({
        "model": cpu_model,
        "vendor": cpu_field("vendor_id"),
        "cores": cpu_cores,
        "microcode": cpu_field("microcode"),
        "cache": cpu_field("cache size"),
        "flags": cpu_field("flags").map(|f| f.split_whitespace().count()),
    }));

    // motherboard / BIOS / product (DMI)
    let mut dmi = |f: &str| trimmed(ctx, &format!("/sys/class/dmi/id/{f}"));
    set(m, "motherboard", json!({
        "vendor": dmi("board_vendor"),
        "name": dmi("board_name"),
        "version": dmi("board_version"),
    }));
    set(m, "bios", json!({
        "vendor": dmi("bios_vendor"),
        "version": dmi("bios_version"),
        "date": dmi("bios_date"),
    }));
    set(m, "product", json!({
        "name": dmi("product_name"),
        "vendor": dmi("sys_vendor"),
        "family": dmi("product_family"),
        "sku": dmi("product_sku"),
    }));

    // GPU (lspci when present; /sys/class/drm count as fallback)
    let mut gpus = Vec::new();
    if let Some(pci) = ctx.cmd("lspci", &["-mm"]) {
        for line in pci.lines() {
            let low = line.to_lowercase();
            if low.contains("vga") || low.contains("3d controller") || low.contains("display controller") {
                // plain lspci: "slot Class [code]: Vendor Device [ven:dev]"
                // -mm mode: quoted fields — handle both.
                let name = match line.split_once(": ") {
                    Some((_, rest)) => rest.to_string(),
                    None => line.split('"').nth(3).unwrap_or(line).to_string(),
                };
                gpus.push(json!({"name": name, "source": "lspci"}));
            }
        }
    }
    if gpus.is_empty() {
        let drm = list_dir(ctx, "/sys/class/drm");
        let cards = drm.iter().filter(|d| d.starts_with("card") && !d.contains('-')).count();
        if cards > 0 {
            gpus.push(json!({"name": format!("{cards} DRM card(s) (names need lspci)"), "source": "/sys/class/drm"}));
        }
    }
    set(m, "gpu", Value::Array(gpus));

    // storage block devices
    let mut storage = Vec::new();
    for dev in list_dir(ctx, "/sys/block") {
        let model = trimmed(ctx, &format!("/sys/block/{dev}/device/model"));
        let size_sectors = trimmed(ctx, &format!("/sys/block/{dev}/size"))
            .and_then(|s| s.parse::<u64>().ok());
        let ro = trimmed(ctx, &format!("/sys/block/{dev}/ro"));
        storage.push(json!({
            "device": dev,
            "model": model,
            "size_gb": size_sectors.map(|s| s * 512 / (1024 * 1024 * 1024)),
            "removable": ro.as_deref().map(|r| r == "1"),
        }));
    }
    set(m, "storage", Value::Array(storage));

    // network interfaces
    let mut interfaces = Vec::new();
    for n in list_dir(ctx, "/sys/class/net") {
        let mac = trimmed(ctx, &format!("/sys/class/net/{n}/address"));
        let state = trimmed(ctx, &format!("/sys/class/net/{n}/operstate"));
        interfaces.push(json!({"name": n, "mac": mac, "state": state}));
    }
    let dns_servers: Vec<String> = ctx
        .read("/etc/resolv.conf")
        .map(|s| {
            s.lines()
                .filter_map(|l| l.strip_prefix("nameserver ").map(str::trim).map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    set(m, "network", json!({
        "interfaces": interfaces,
        "dns": dns_servers,
        "hostname_fqdn": m.get("fqdn").cloned().unwrap_or(Value::Null),
    }));

    // kernel details
    let kernel_version = trimmed(ctx, "/proc/version");
    let modules_count = ctx.read("/proc/modules").map(|s| s.lines().filter(|l| !l.trim().is_empty()).count() as u64);
    let taint = trimmed(ctx, "/proc/sys/kernel/tainted");
    set(m, "kernel_info", json!({
        "release": m.get("kernel").cloned().unwrap_or(Value::Null),
        "version": kernel_version,
        "cmdline": ctx.read("/proc/cmdline").map(|s| s.trim().to_string()),
        "modules": modules_count,
        "tainted": taint,
    }));

    // system activity counts
    let processes = ctx.read("/proc/stat").and_then(|s| {
        s.lines()
            .find_map(|l| l.strip_prefix("processes ").and_then(|v| v.trim().parse::<u64>().ok()))
    });
    set(m, "processes", json!(processes));
    let services_count = ctx
        .cmd("systemctl", &["list-units", "--type=service", "--state=running"])
        .map(|o| o.lines().filter(|l| l.contains("running")).count() as u64);
    set(m, "services_count", json!(services_count));

    // disks: real filesystems from /proc/mounts, sizes via statvfs
    let mut disks = Vec::new();
    if let Some(mounts) = ctx.read("/proc/mounts") {
        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                continue;
            }
            let (dev, mount, fs) = (parts[0], parts[1], parts[2]);
            if !matches!(fs, "ext2" | "ext3" | "ext4" | "xfs" | "btrfs" | "zfs" | "f2fs" | "vfat") {
                continue;
            }
            if dev == "none" || dev.starts_with("tmpfs") {
                continue;
            }
            disks.push(json!({"mount": mount, "fs": fs, "total_mb": statvfs_mb(ctx, mount), "free_mb": null}));
        }
    }
    set(m, "disks", Value::Array(disks));

    // users
    let mut users = Vec::new();
    if let Some(passwd) = ctx.read("/etc/passwd") {
        for line in passwd.lines() {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() < 7 {
                continue;
            }
            let (name, uid, gid, shell) = (f[0], f[2], f[3], f[6]);
            let uid_n = uid.parse::<u32>().unwrap_or(u32::MAX);
            users.push(json!({
                "name": name,
                "uid": uid_n,
                "gid": gid.parse::<u32>().unwrap_or(u32::MAX),
                "groups": groups_of(ctx, gid),
                "shell_or_usertype": shell,
                "privileged": uid_n == 0,
                "last_logon": null,
            }));
        }
    }
    set(m, "users", Value::Array(users));

    // patch level: last package activity
    let last_update = ctx
        .read("/var/log/dpkg.log")
        .and_then(|s| s.lines().next().and_then(|l| l.split_whitespace().next().map(str::to_string)));
    set(m, "patch_level", json!({"last_update": last_update, "hotfix_count": null}));
    set(m, "registered_owner", Value::Null);

    // timezone / locale
    let tz = trimmed(ctx, "/etc/timezone").or_else(|| {
        ctx.cmd("timedatectl", &["show"]).and_then(|o| {
            o.lines()
                .find_map(|l| l.strip_prefix("Timezone=").map(|v| v.trim().to_string()))
        })
    });
    set(m, "timezone", json!(tz));
    set(
        m,
        "locale",
        json!(std::env::var("LANG").ok().or_else(|| std::env::var("LC_ALL").ok())),
    );
}

fn null_first_boot(_ctx: &mut ScanContext) -> Value {
    Value::Null
}

/// Directory entry names under a (prefixed) path, sorted.
fn list_dir(ctx: &ScanContext, abs_path: &str) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(ctx.path(abs_path))
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| e.file_type().map(|t| t.is_dir() || t.is_symlink()).unwrap_or(false))
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

fn groups_of(ctx: &mut ScanContext, gid: &str) -> Vec<String> {
    ctx.read("/etc/group")
        .map(|g| {
            g.lines()
                .filter_map(|l| {
                    let f: Vec<&str> = l.split(':').collect();
                    (f.len() >= 3 && f[2] == gid).then(|| f[0].to_string())
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(unix)]
fn statvfs_mb(_ctx: &ScanContext, mount: &str) -> Value {
    use std::ffi::CString;
    CString::new(mount)
        .ok()
        .and_then(|c| {
            let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
            // SAFETY: statvfs writes into a correctly-sized zeroed struct
            // from a valid NUL-terminated path; single-threaded call.
            (unsafe { libc::statvfs(c.as_ptr(), &mut st) } == 0).then_some(st)
        })
        .map(|st| json!((st.f_blocks as u64 * st.f_frsize as u64) / (1024 * 1024)))
        .unwrap_or(Value::Null)
}

#[cfg(not(unix))]
fn statvfs_mb(_ctx: &ScanContext, _mount: &str) -> Value {
    Value::Null
}

fn collect_windows(ctx: &mut ScanContext, m: &mut Map<String, Value>) {
    let hostname = ctx.cmd(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", "$env:COMPUTERNAME"],
    );
    set(m, "hostname", json!(hostname.clone()));
    set(m, "fqdn", json!(hostname));
    let machine_id = ctx
        .cmd(
            "powershell",
            &["-NoProfile", "-NonInteractive", "-Command",
              "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Cryptography').MachineGuid"],
        )
        .or_else(|| {
            ctx.cmd(
                "reg",
                &["query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"],
            )
            .and_then(|o| {
                o.lines()
                    .find(|l| l.contains("MachineGuid"))
                    .and_then(|l| l.split_whitespace().last().map(str::to_string))
            })
        });
    set(m, "machine_id", json!(machine_id));
    set(m, "os_name", json!("Windows"));
    set(m, "os_version", json!(ctx.platform.kernel.split('.').next_back().map(str::to_string)));
    set(m, "kernel", json!(ctx.platform.kernel));
    set(m, "arch", json!(ctx.platform.arch));
    set(m, "distro_family", json!(null_str()));
    set(m, "virtualization", json!(ctx.platform.virtualized.clone()));

    let sysinfo = ctx.cmd("systeminfo", &[]);
    let find_line = |needle: &str| -> Option<String> {
        sysinfo.as_ref().and_then(|s| {
            s.lines()
                .find(|l| l.to_lowercase().contains(needle))
                .and_then(|l| l.splitn(2, ':').nth(1))
                .map(|v| v.trim().to_string())
        })
    };
    set(m, "memory_mb", json!(find_line("total physical memory").and_then(|v| {
        let num: String = v.chars().filter(|c| c.is_ascii_digit()).collect();
        num.parse::<u64>().ok()
    })));
    let boot = find_line("system boot time");
    set(m, "last_boot", json!(boot));
    let install = find_line("original install date");
    set(m, "install_date", json!(install));
    set(m, "cpu_model", json!(find_line("processor(s)").map(|v| {
        v.split('[').nth(1).map(|x| x.trim_end_matches(']').to_string()).unwrap_or(v)
    })));
    set(m, "cpu_cores", json!(find_line("processor(s)").and_then(|v| {
        v.split_whitespace().next().and_then(|n| n.parse::<u64>().ok())
    })));

    // hotfix history
    let hotfixes = ctx.cmd(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command",
          "Get-HotFix | Select-Object HotFixID,InstalledOn | ConvertTo-Json -Compress"],
    );
    let parsed: Option<Vec<Value>> = hotfixes.as_ref().and_then(|s| serde_json::from_str(s).ok());
    let count = parsed.as_ref().map(|v| v.len() as u64);
    let newest = parsed.as_ref().and_then(|v| {
        v.iter()
            .filter_map(|h| h["InstalledOn"].as_str().map(str::to_string))
            .max()
    });
    set(m, "patch_level", json!({"hotfix_count": count, "newest_hotfix_date": newest}));

    // users via net users (parse the middle column block)
    let mut users = Vec::new();
    if let Some(out) = ctx.cmd("net", &["user"]) {
        let mut in_block = false;
        for line in out.lines().skip(4) {
            let l = line.trim();
            if l.starts_with("The command completed") {
                break;
            }
            if l.contains("-----") {
                if in_block {
                    break;
                }
                in_block = true;
                continue;
            }
            if in_block {
                for name in l.split_whitespace() {
                    users.push(json!({
                        "name": name,
                        "uid": null,
                        "gid": null,
                        "groups": null,
                        "shell_or_usertype": null,
                        "privileged": null,
                        "last_logon": null,
                    }));
                }
            }
        }
    }
    set(m, "users", Value::Array(users));

    let tz = ctx.cmd("tzutil", &["/g"]);
    set(m, "timezone", json!(tz));
    set(m, "locale", Value::Null);
    set(m, "disks", Value::Array(vec![]));
    set(m, "uptime_seconds", Value::Null);
    set(m, "registered_owner", Value::Null);
}

fn null_str() -> Value {
    Value::Null
}
