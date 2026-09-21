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
    let mem = ctx.read("/proc/meminfo").and_then(|s| {
        s.lines().find_map(|l| {
            let (k, rest) = l.split_once(':')?;
            (k == "MemTotal").then(|| {
                rest.trim()
                    .split_whitespace()
                    .next()
                    .and_then(|n| n.parse::<u64>().ok())
                    .map(|kb| kb / 1024)
            })?
        })
    });
    set(m, "memory_mb", json!(mem));

    // cpu
    let cpuinfo = ctx.read("/proc/cpuinfo");
    let cpu_model = cpuinfo.as_ref().and_then(|s| {
        s.lines()
            .find(|l| l.starts_with("model name"))
            .and_then(|l| l.split(':').nth(1))
            .map(|v| v.trim().to_string())
    });
    let cpu_cores = cpuinfo.as_ref().map(|s| {
        s.lines().filter(|l| l.starts_with("processor")).count() as u64
    });
    set(m, "cpu_model", json!(cpu_model));
    set(m, "cpu_cores", json!(cpu_cores));

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
