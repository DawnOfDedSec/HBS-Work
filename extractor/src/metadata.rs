//! System fingerprint collection.
//!
//! Every field is collected through an ordered list of read-only sources
//! ([`Source`]) so a single missing file, absent tool, or denied read can
//! never abort the scan or hide the other fields. Each source attempt is
//! recorded as a [`CollectionAttempt`] and surfaced under
//! `metadata._collection.attempts` for the report's diagnostics. A field
//! whose sources all fail becomes an explicit `null` with a recorded
//! reason — never an omitted key, never a panic.
//!
//! All collection funnels through the [`ScanContext`] (root prefix +
//! injector) so both OS collectors are unit-testable on any host. FQDN
//! resolution is **file-only** (`/etc/hostname` + the first
//! `search`/`domain` entry in `/etc/resolv.conf`, or the local computer
//! name on Windows): no DNS, no network, is ever contacted.

use crate::context::ScanContext;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

/// Upper bound on recorded attempts so `_collection` stays small.
const MAX_ATTEMPTS: usize = 400;

/// One candidate source for a metadata field.
enum Source<'a> {
    /// Absolute (root-prefixed) file read.
    File(&'a str),
    /// Allowlisted query command.
    Cmd(&'a str, &'a [&'a str]),
    /// In-process read-only reader (funles through `ScanContext`, e.g. a
    /// derived file parse). The label names the logical source.
    Native(&'a str, fn(&mut ScanContext) -> Option<String>),
}

/// One recorded attempt to resolve a field, surfaced under
/// `metadata._collection.attempts`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionAttempt {
    pub field: String,
    pub source: String,
    pub outcome: String,
}

/// Every key `collect` guarantees to emit, on every platform. Values may
/// be `null`; the key itself is never omitted.
pub const METADATA_KEYS: &[&str] = &[
    "elevated",
    "environment",
    "hypervisor",
    "environment_signals",
    "hostname",
    "fqdn",
    "machine_id",
    "os_name",
    "os_version",
    "kernel",
    "arch",
    "distro",
    "distro_family",
    "distro_version",
    "virtualization",
    "install_date",
    "install_date_unix",
    "last_boot",
    "last_boot_unix",
    "uptime",
    "uptime_seconds",
    "timezone",
    "locale",
    "cpu_model",
    "cpu_cores",
    "cpu",
    "memory",
    "memory_mb",
    "motherboard",
    "bios",
    "product",
    "gpu",
    "storage",
    "disks",
    "network",
    "kernel_info",
    "processes",
    "services_count",
    "users",
    "patch_level",
    "registered_owner",
];

/// Collect the full system fingerprint. Never panics; per-field failures
/// are isolated and recorded.
pub fn collect(ctx: &mut ScanContext) -> Value {
    let mut m = Map::new();
    let mut attempts: Vec<CollectionAttempt> = Vec::new();

    // Pre-seed every expected key as null so a failure in one field can
    // never remove a key or affect a sibling.
    for key in METADATA_KEYS {
        m.insert((*key).to_string(), Value::Null);
    }

    m.insert("elevated".into(), json!(ctx.elevated));
    // Environment classification travels with the system fingerprint so
    // the dashboard can distinguish host-only controls that were N/A.
    m.insert(
        "environment".into(),
        json!(format!("{:?}", ctx.platform.environment.kind)),
    );
    m.insert(
        "hypervisor".into(),
        json!(ctx.platform.environment.hypervisor.clone()),
    );
    m.insert(
        "environment_signals".into(),
        json!(ctx.platform.environment.signals.clone()),
    );

    if ctx.linux() {
        collect_linux(ctx, &mut m, &mut attempts);
    } else {
        collect_windows(ctx, &mut m, &mut attempts);
    }

    // Summarise every still-unresolved field so diagnostics can spot it
    // without walking the whole attempt list.
    for key in METADATA_KEYS {
        if m.get(*key).map(|v| v.is_null()).unwrap_or(true) {
            attempts.push(att(key, "all sources", "unresolved (null)"));
        }
    }

    if attempts.len() > MAX_ATTEMPTS {
        attempts.truncate(MAX_ATTEMPTS);
    }
    // Bounded and redacted: attempts carry only source labels/outcomes.
    for attempt in &mut attempts {
        attempt.source = crate::redact::redact(&attempt.source);
        attempt.outcome = crate::redact::redact(&attempt.outcome);
    }

    m.insert("_collection".into(), json!({ "attempts": attempts }));
    Value::Object(m)
}

fn set(m: &mut Map<String, Value>, k: &str, v: Value) {
    m.insert(k.to_string(), v);
}

fn att(field: &str, source: &str, outcome: impl Into<String>) -> CollectionAttempt {
    CollectionAttempt {
        field: field.to_string(),
        source: source.to_string(),
        outcome: outcome.into(),
    }
}

/// Try an ordered list of sources, recording `(field, source, outcome)`
/// for every attempt, and return the first `Some` value.
fn first_of(
    ctx: &mut ScanContext,
    attempts: &mut Vec<CollectionAttempt>,
    field: &str,
    sources: &[Source],
) -> Option<String> {
    for src in sources {
        let (source, value, outcome) = try_source(ctx, src);
        let found = value.is_some();
        attempts.push(att(field, &source, outcome));
        if found {
            return value;
        }
    }
    None
}

fn try_source(ctx: &mut ScanContext, src: &Source) -> (String, Option<String>, String) {
    match src {
        Source::File(path) => {
            let value = read_trimmed(ctx, path);
            let outcome = match &value {
                Some(_) => "read".to_string(),
                None => "missing or unreadable".to_string(),
            };
            ((*path).to_string(), value, outcome)
        }
        Source::Cmd(prog, args) => {
            let value = ctx
                .cmd(prog, args)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            let label = if args.is_empty() {
                (*prog).to_string()
            } else {
                format!("{prog} {}", args.join(" "))
            };
            let outcome = match &value {
                Some(_) => "read".to_string(),
                None if !crate::evidence::allowed(prog, args) => {
                    "refused by allowlist".to_string()
                }
                None => "unavailable".to_string(),
            };
            (label, value, outcome)
        }
        Source::Native(label, f) => {
            let value = f(ctx).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
            let outcome = match &value {
                Some(_) => "read".to_string(),
                None => "unavailable".to_string(),
            };
            ((*label).to_string(), value, outcome)
        }
    }
}

fn read_trimmed(ctx: &mut ScanContext, path: &str) -> Option<String> {
    ctx.read(path).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// Read a (possibly formatted) file and record the attempt. Used for
/// per-device / per-interface sub-fields whose paths are dynamic.
fn file_field(
    ctx: &mut ScanContext,
    attempts: &mut Vec<CollectionAttempt>,
    field: &str,
    path: &str,
) -> Option<String> {
    let value = read_trimmed(ctx, path);
    let outcome = match &value {
        Some(_) => "read".to_string(),
        None => "missing or unreadable".to_string(),
    };
    attempts.push(att(field, path, outcome));
    value
}

// ---------------------------------------------------------------------------
// Linux helpers
// ---------------------------------------------------------------------------

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn platform_distro(ctx: &mut ScanContext) -> Option<String> {
    ctx.platform.distro.clone()
}

fn platform_distro_version(ctx: &mut ScanContext) -> Option<String> {
    ctx.platform.distro_version.clone()
}

fn platform_kernel(ctx: &mut ScanContext) -> Option<String> {
    let k = ctx.platform.kernel.clone();
    (!k.is_empty()).then_some(k)
}

fn platform_arch(ctx: &mut ScanContext) -> Option<String> {
    let a = ctx.platform.arch.clone();
    (!a.is_empty()).then_some(a)
}

fn default_linux(_ctx: &mut ScanContext) -> Option<String> {
    Some("Linux".into())
}

fn default_windows(_ctx: &mut ScanContext) -> Option<String> {
    Some("Windows".into())
}

fn os_release_content(ctx: &mut ScanContext) -> Option<String> {
    ctx.read("/etc/os-release")
        .or_else(|| ctx.read("/usr/lib/os-release"))
}

fn parse_os_release_field(content: &str, key: &str) -> Option<String> {
    content.lines().find_map(|l| {
        let (k, v) = l.split_once('=')?;
        (k.trim() == key)
            .then(|| v.trim().trim_matches('"').trim_matches('\'').to_string())
            .filter(|s| !s.is_empty())
    })
}

fn os_release_name(ctx: &mut ScanContext) -> Option<String> {
    let content = os_release_content(ctx)?;
    parse_os_release_field(&content, "NAME").or_else(|| parse_os_release_field(&content, "ID"))
}

fn os_release_version(ctx: &mut ScanContext) -> Option<String> {
    let content = os_release_content(ctx)?;
    parse_os_release_field(&content, "VERSION_ID")
}

/// File-only FQDN: `/etc/hostname` (or the kernel hostname file) plus the
/// first `search`/`domain` entry from `/etc/resolv.conf`. Never DNS.
fn fqdn_from_files(ctx: &mut ScanContext) -> Option<String> {
    let host = read_trimmed(ctx, "/etc/hostname")
        .or_else(|| read_trimmed(ctx, "/proc/sys/kernel/hostname"))?;
    if host.contains('.') {
        return Some(host);
    }
    let domain = ctx.read("/etc/resolv.conf").and_then(|c| parse_search_domain(&c));
    Some(match domain {
        Some(d) => format!("{host}.{d}"),
        None => host,
    })
}

fn parse_search_domain(resolv: &str) -> Option<String> {
    for line in resolv.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') || line.is_empty() {
            continue;
        }
        let mut it = line.split_whitespace();
        match it.next() {
            Some("search") | Some("domain") => {
                if let Some(d) = it.next() {
                    return Some(d.to_string());
                }
            }
            _ => {}
        }
    }
    None
}

fn machine_id_dmi(ctx: &mut ScanContext) -> Option<String> {
    read_trimmed(ctx, "/sys/class/dmi/id/product_uuid").map(|u| format!("dmi-{u}"))
}

fn machine_id_hostname(ctx: &mut ScanContext) -> Option<String> {
    let host = read_trimmed(ctx, "/etc/hostname")
        .or_else(|| read_trimmed(ctx, "/proc/sys/kernel/hostname"))?;
    if ctx.platform.environment.is_container() {
        Some(format!("container-{host}"))
    } else {
        Some(format!("host-{host}"))
    }
}

fn parse_uptime_secs(raw: &str) -> Option<u64> {
    raw.split_whitespace()
        .next()
        .and_then(|v| v.parse::<f64>().ok())
        .map(|v| v as u64)
}

fn uptime_from_proc(ctx: &mut ScanContext) -> Option<String> {
    let raw = ctx.read("/proc/uptime")?;
    Some(parse_uptime_secs(&raw)?.to_string())
}

fn last_boot_from_proc(ctx: &mut ScanContext) -> Option<String> {
    let raw = ctx.read("/proc/uptime")?;
    let up = parse_uptime_secs(&raw)?;
    Some(unix_now().saturating_sub(up).to_string())
}

fn btime(ctx: &mut ScanContext) -> Option<u64> {
    let stat = ctx.read("/proc/stat")?;
    stat.lines().find_map(|l| {
        l.strip_prefix("btime ")
            .and_then(|v| v.trim().parse::<u64>().ok())
    })
}

fn last_boot_btime(ctx: &mut ScanContext) -> Option<String> {
    btime(ctx).map(|b| b.to_string())
}

fn uptime_from_btime(ctx: &mut ScanContext) -> Option<String> {
    btime(ctx).map(|b| unix_now().saturating_sub(b).to_string())
}

#[derive(Default)]
struct MemInfo {
    total: Option<u64>,
    free: Option<u64>,
    available: Option<u64>,
    swap_total: Option<u64>,
    swap_free: Option<u64>,
}

fn parse_memory(raw: &str) -> MemInfo {
    let mut m = MemInfo::default();
    if raw.contains("MemTotal:") {
        let parse_kb = |key: &str| -> Option<u64> {
            raw.lines().find_map(|l| {
                let (k, rest) = l.split_once(':')?;
                if k.trim() != key {
                    return None;
                }
                rest.trim()
                    .split_whitespace()
                    .next()
                    .and_then(|n| n.parse::<u64>().ok())
                    .map(|kb| kb / 1024)
            })
        };
        m.total = parse_kb("MemTotal");
        m.free = parse_kb("MemFree");
        m.available = parse_kb("MemAvailable");
        m.swap_total = parse_kb("SwapTotal");
        m.swap_free = parse_kb("SwapFree");
        return m;
    }
    // `free -m`
    for line in raw.lines() {
        let mut it = line.split_whitespace();
        match it.next() {
            Some("Mem:") => {
                let cols: Vec<u64> = it.filter_map(|v| v.parse::<u64>().ok()).collect();
                m.total = cols.first().copied();
                m.free = cols.get(2).copied();
                m.available = cols.last().copied();
            }
            Some("Swap:") => {
                let cols: Vec<u64> = it.filter_map(|v| v.parse::<u64>().ok()).collect();
                m.swap_total = cols.first().copied();
                m.swap_free = cols.get(2).copied();
            }
            _ => {}
        }
    }
    m
}

#[derive(Default)]
struct CpuInfo {
    model: Option<String>,
    vendor: Option<String>,
    cores: Option<u64>,
    microcode: Option<String>,
    cache: Option<String>,
    flags: Option<u64>,
}

fn parse_cpu(raw: &str) -> CpuInfo {
    let field = |key: &str| -> Option<String> {
        raw.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            (k.trim() == key)
                .then(|| v.trim().to_string())
                .filter(|s| !s.is_empty())
        })
    };
    let mut c = CpuInfo::default();
    if raw.lines().any(|l| l.trim_start().starts_with("processor")) {
        c.model = field("model name").or_else(|| field("Processor"));
        c.vendor = field("vendor_id");
        c.microcode = field("microcode");
        c.cache = field("cache size");
        c.cores = Some(raw.lines().filter(|l| l.trim_start().starts_with("processor")).count() as u64)
            .filter(|n| *n > 0);
        c.flags = field("flags").map(|f| f.split_whitespace().count() as u64);
        return c;
    }
    // `lscpu`
    c.model = field("Model name");
    c.vendor = field("Vendor ID");
    c.microcode = field("Microcode");
    c.cache = field("L3 cache");
    c.cores = field("CPU(s)").and_then(|v| v.parse::<u64>().ok());
    c
}

fn dmi_field(
    ctx: &mut ScanContext,
    attempts: &mut Vec<CollectionAttempt>,
    name: &str,
) -> Option<String> {
    file_field(
        ctx,
        attempts,
        &format!("dmi.{name}"),
        &format!("/sys/class/dmi/id/{name}"),
    )
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
                    (f.len() >= 3 && f.get(2) == Some(&gid))
                        .then(|| f.first().copied().unwrap_or_default().to_string())
                        .filter(|s| !s.is_empty())
                })
                .collect()
        })
        .unwrap_or_default()
}

fn user_row_linux(ctx: &mut ScanContext, line: &str) -> Option<Value> {
    let f: Vec<&str> = line.split(':').collect();
    if f.len() < 7 {
        return None;
    }
    let name = f.first()?.to_string();
    let uid = f.get(2).and_then(|s| s.parse::<u32>().ok());
    let gid = f.get(3).and_then(|s| s.parse::<u32>().ok());
    let shell = f.get(6).map(|s| s.to_string());
    let groups = f.get(3).map(|g| groups_of(ctx, g)).unwrap_or_default();
    Some(json!({
        "name": name,
        "uid": uid.unwrap_or(u32::MAX),
        "gid": gid.unwrap_or(u32::MAX),
        "groups": groups,
        "shell_or_usertype": shell,
        "privileged": uid == Some(0),
        "last_logon": null,
    }))
}

/// Trimmed non-empty lines, sorted (used for simple list outputs).
fn non_empty_lines(raw: &str) -> Vec<String> {
    let mut names: Vec<String> = raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    names.sort();
    names
}

fn collect_linux(ctx: &mut ScanContext, m: &mut Map<String, Value>, a: &mut Vec<CollectionAttempt>) {
    // hostname ------------------------------------------------------------
    let hostname = first_of(
        ctx,
        a,
        "hostname",
        &[
            Source::File("/etc/hostname"),
            Source::File("/proc/sys/kernel/hostname"),
            Source::Cmd("hostname", &[]),
        ],
    );
    set(m, "hostname", json!(hostname));

    // fqdn (file-only, never DNS) ----------------------------------------
    let fqdn = first_of(
        ctx,
        a,
        "fqdn",
        &[
            Source::Native(
                "/etc/hostname + /etc/resolv.conf (search|domain)",
                fqdn_from_files,
            ),
            Source::Cmd("hostname", &[]),
        ],
    );
    set(m, "fqdn", json!(fqdn));

    // machine identity ----------------------------------------------------
    let machine_id = first_of(
        ctx,
        a,
        "machine_id",
        &[
            Source::File("/etc/machine-id"),
            Source::File("/var/lib/dbus/machine-id"),
            Source::Native("dmi product_uuid", machine_id_dmi),
            Source::Native("hostname-derived", machine_id_hostname),
        ],
    );
    set(m, "machine_id", json!(machine_id));

    // OS / kernel / arch --------------------------------------------------
    set(
        m,
        "os_name",
        json!(first_of(
            ctx,
            a,
            "os_name",
            &[
                Source::Native("/etc/os-release NAME", os_release_name),
                Source::Native("platform distro", platform_distro),
                Source::Native("default", default_linux),
            ],
        )),
    );
    set(
        m,
        "os_version",
        json!(first_of(
            ctx,
            a,
            "os_version",
            &[
                Source::Native("/etc/os-release VERSION_ID", os_release_version),
                Source::Native("platform distro_version", platform_distro_version),
            ],
        )),
    );
    set(
        m,
        "kernel",
        json!(first_of(
            ctx,
            a,
            "kernel",
            &[
                Source::Cmd("uname", &["-r"]),
                Source::File("/proc/sys/kernel/osrelease"),
                Source::Native("platform kernel", platform_kernel),
            ],
        )),
    );
    set(
        m,
        "arch",
        json!(first_of(
            ctx,
            a,
            "arch",
            &[
                Source::Cmd("uname", &["-m"]),
                Source::Native("platform arch", platform_arch),
            ],
        )),
    );
    set(m, "distro", json!(platform_distro(ctx)));
    set(m, "distro_family", json!(format!("{:?}", ctx.platform.family)));
    set(m, "distro_version", json!(platform_distro_version(ctx)));
    set(m, "virtualization", json!(ctx.platform.virtualized.clone()));

    // install date: no reliable local source on Linux ---------------------
    a.push(att(
        "install_date",
        "platform",
        "no local install-date source on Linux",
    ));

    // last boot / uptime --------------------------------------------------
    let last_boot = first_of(
        ctx,
        a,
        "last_boot_unix",
        &[
            Source::Native("now - /proc/uptime", last_boot_from_proc),
            Source::Native("/proc/stat btime", last_boot_btime),
        ],
    )
    .and_then(|s| s.parse::<u64>().ok());
    set(m, "last_boot_unix", json!(last_boot));
    set(m, "last_boot", json!(last_boot));
    let uptime = first_of(
        ctx,
        a,
        "uptime_seconds",
        &[
            Source::Native("/proc/uptime", uptime_from_proc),
            Source::Native("now - /proc/stat btime", uptime_from_btime),
        ],
    )
    .and_then(|s| s.parse::<u64>().ok());
    set(m, "uptime_seconds", json!(uptime));
    set(m, "uptime", json!(uptime));

    // memory --------------------------------------------------------------
    let mem_raw = first_of(
        ctx,
        a,
        "memory",
        &[Source::File("/proc/meminfo"), Source::Cmd("free", &["-m"])],
    );
    let mem = mem_raw.as_deref().map(parse_memory).unwrap_or_default();
    set(m, "memory_mb", json!(mem.total));
    set(
        m,
        "memory",
        json!({
            "total_mb": mem.total,
            "free_mb": mem.free,
            "available_mb": mem.available,
            "swap_total_mb": mem.swap_total,
            "swap_free_mb": mem.swap_free,
        }),
    );

    // cpu -----------------------------------------------------------------
    let cpu_raw = first_of(
        ctx,
        a,
        "cpu",
        &[Source::File("/proc/cpuinfo"), Source::Cmd("lscpu", &[])],
    );
    let cpu = cpu_raw.as_deref().map(parse_cpu).unwrap_or_default();
    set(m, "cpu_model", json!(cpu.model));
    set(m, "cpu_cores", json!(cpu.cores));
    set(
        m,
        "cpu",
        json!({
            "model": cpu.model,
            "vendor": cpu.vendor,
            "cores": cpu.cores,
            "microcode": cpu.microcode,
            "cache": cpu.cache,
            "flags": cpu.flags,
        }),
    );

    // motherboard / BIOS / product (DMI) ----------------------------------
    set(
        m,
        "motherboard",
        json!({
            "vendor": dmi_field(ctx, a, "board_vendor"),
            "name": dmi_field(ctx, a, "board_name"),
            "version": dmi_field(ctx, a, "board_version"),
        }),
    );
    set(
        m,
        "bios",
        json!({
            "vendor": dmi_field(ctx, a, "bios_vendor"),
            "version": dmi_field(ctx, a, "bios_version"),
            "date": dmi_field(ctx, a, "bios_date"),
        }),
    );
    set(
        m,
        "product",
        json!({
            "name": dmi_field(ctx, a, "product_name"),
            "vendor": dmi_field(ctx, a, "sys_vendor"),
            "family": dmi_field(ctx, a, "product_family"),
            "sku": dmi_field(ctx, a, "product_sku"),
        }),
    );

    // GPU -----------------------------------------------------------------
    let mut gpus = Vec::new();
    let lspci = ctx.cmd("lspci", &["-mm"]);
    a.push(att(
        "gpu",
        "lspci -mm",
        if lspci.is_some() { "read" } else { "unavailable" },
    ));
    if let Some(pci) = &lspci {
        for line in pci.lines() {
            let low = line.to_lowercase();
            if low.contains("vga") || low.contains("3d controller") || low.contains("display controller")
            {
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
        a.push(att("gpu", "/sys/class/drm", format!("{cards} DRM card(s)")));
        if cards > 0 {
            gpus.push(json!({"name": format!("{cards} DRM card(s) (names need lspci)"), "source": "/sys/class/drm"}));
        }
    }
    set(m, "gpu", Value::Array(gpus));

    // storage -------------------------------------------------------------
    let mut storage = Vec::new();
    for dev in list_dir(ctx, "/sys/block") {
        let model = file_field(ctx, a, "storage.model", &format!("/sys/block/{dev}/device/model"));
        let size_sectors = file_field(ctx, a, "storage.size", &format!("/sys/block/{dev}/size"))
            .and_then(|s| s.parse::<u64>().ok());
        let ro = file_field(ctx, a, "storage.ro", &format!("/sys/block/{dev}/ro"));
        storage.push(json!({
            "device": dev,
            "model": model,
            "size_gb": size_sectors.map(|s| s * 512 / (1024 * 1024 * 1024)),
            "removable": ro.as_deref().map(|r| r == "1"),
        }));
    }
    set(m, "storage", Value::Array(storage));

    // network -------------------------------------------------------------
    let mut interfaces = Vec::new();
    for n in list_dir(ctx, "/sys/class/net") {
        let mac = file_field(ctx, a, "network.mac", &format!("/sys/class/net/{n}/address"));
        let state = file_field(ctx, a, "network.state", &format!("/sys/class/net/{n}/operstate"));
        interfaces.push(json!({"name": n, "mac": mac, "state": state}));
    }
    let dns_servers: Vec<String> = first_of(
        ctx,
        a,
        "network.dns",
        &[Source::File("/etc/resolv.conf")],
    )
    .map(|s| {
        s.lines()
            .filter_map(|l| l.strip_prefix("nameserver ").map(str::trim).map(str::to_string))
            .collect()
    })
    .unwrap_or_default();
    set(
        m,
        "network",
        json!({
            "interfaces": interfaces,
            "dns": dns_servers,
            "hostname_fqdn": m.get("fqdn").cloned().unwrap_or(Value::Null),
        }),
    );

    // kernel details ------------------------------------------------------
    let kernel_version = file_field(ctx, a, "kernel_info.version", "/proc/version");
    let modules_count = ctx
        .read("/proc/modules")
        .map(|s| s.lines().filter(|l| !l.trim().is_empty()).count() as u64);
    a.push(att(
        "kernel_info.modules",
        "/proc/modules",
        if modules_count.is_some() { "read" } else { "missing or unreadable" },
    ));
    let taint = file_field(ctx, a, "kernel_info.tainted", "/proc/sys/kernel/tainted");
    let cmdline = file_field(ctx, a, "kernel_info.cmdline", "/proc/cmdline");
    set(
        m,
        "kernel_info",
        json!({
            "release": m.get("kernel").cloned().unwrap_or(Value::Null),
            "version": kernel_version,
            "cmdline": cmdline,
            "modules": modules_count,
            "tainted": taint,
        }),
    );

    // system activity -----------------------------------------------------
    let processes = ctx.read("/proc/stat").and_then(|s| {
        s.lines()
            .find_map(|l| l.strip_prefix("processes ").and_then(|v| v.trim().parse::<u64>().ok()))
    });
    a.push(att(
        "processes",
        "/proc/stat processes",
        if processes.is_some() { "read" } else { "missing or unreadable" },
    ));
    set(m, "processes", json!(processes));

    let services_count = ctx
        .cmd("systemctl", &["list-units", "--type=service", "--state=running"])
        .map(|o| o.lines().filter(|l| l.contains("running")).count() as u64);
    a.push(att(
        "services_count",
        "systemctl list-units --type=service --state=running",
        if services_count.is_some() { "read" } else { "unavailable" },
    ));
    set(m, "services_count", json!(services_count));

    // disks ---------------------------------------------------------------
    let mounts = first_of(
        ctx,
        a,
        "disks",
        &[Source::File("/proc/mounts"), Source::Cmd("findmnt", &["-rn"])],
    );
    let mut disks = Vec::new();
    if let Some(mounts) = &mounts {
        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                continue;
            }
            let (dev, mount, fs) = (parts[0], parts[1], parts[2]);
            if !matches!(fs, "ext2" | "ext3" | "ext4" | "xfs" | "btrfs" | "zfs" | "f2fs" | "vfat") {
                continue;
            }
            if dev == "none" || dev.starts_with("tmpfs") || dev == "overlay" {
                continue;
            }
            disks.push(json!({"mount": mount, "fs": fs, "total_mb": statvfs_mb(ctx, mount), "free_mb": null}));
        }
    }
    set(m, "disks", Value::Array(disks));

    // users ---------------------------------------------------------------
    let passwd = first_of(
        ctx,
        a,
        "users",
        &[Source::File("/etc/passwd"), Source::Cmd("getent", &["passwd"])],
    );
    let users: Vec<Value> = passwd
        .as_deref()
        .map(|raw| raw.lines().filter_map(|l| user_row_linux(ctx, l)).collect())
        .unwrap_or_default();
    set(m, "users", Value::Array(users));

    // patch level ---------------------------------------------------------
    let patch_raw = first_of(
        ctx,
        a,
        "patch_level",
        &[
            Source::File("/var/log/dpkg.log"),
            Source::Cmd("rpm", &["-qa", "--last"]),
        ],
    );
    let last_update = patch_raw
        .as_deref()
        .and_then(|s| s.lines().next())
        .and_then(|l| l.split_whitespace().next().map(str::to_string));
    set(m, "patch_level", json!({"last_update": last_update, "hotfix_count": null}));
    a.push(att(
        "registered_owner",
        "platform",
        "not applicable on Linux",
    ));

    // timezone / locale ---------------------------------------------------
    let tz = first_of(
        ctx,
        a,
        "timezone",
        &[
            Source::File("/etc/timezone"),
            Source::Cmd("timedatectl", &["show"]),
        ],
    )
    .and_then(|raw| {
        raw.lines()
            .find_map(|l| l.strip_prefix("Timezone=").map(|v| v.trim().to_string()))
            .or_else(|| {
                let t = raw.trim().to_string();
                (!t.is_empty()).then_some(t)
            })
    });
    set(m, "timezone", json!(tz));
    let locale = first_of(
        ctx,
        a,
        "locale",
        &[
            Source::Native("$LANG/$LC_ALL", env_locale),
            Source::File("/etc/default/locale"),
            Source::File("/etc/locale.conf"),
        ],
    );
    set(m, "locale", json!(locale));
}

fn env_locale(ctx: &mut ScanContext) -> Option<String> {
    host_env(ctx, "LANG")
        .or_else(|| host_env(ctx, "LC_ALL"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
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

// ---------------------------------------------------------------------------
// Windows helpers
// ---------------------------------------------------------------------------

const WIN_CURRENT_VERSION: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
const WIN_CRYPTO: &str = r"HKLM\SOFTWARE\Microsoft\Cryptography";
const WIN_BIOS: &str = r"HKLM\HARDWARE\DESCRIPTION\System\BIOS";
const WIN_CPU0: &str = r"HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0";
const WIN_TZ: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation";

const PS_COMPUTERNAME: &[&str] = &[
    "-NoProfile",
    "-NonInteractive",
    "-Command",
    "$env:COMPUTERNAME",
];
const PS_OS_MEM: &[&str] = &[
    "-NoProfile",
    "-NonInteractive",
    "-Command",
    "Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize,FreePhysicalMemory,TotalVirtualMemorySize,FreeVirtualMemory | ConvertTo-Json -Compress",
];
const PS_CPU: &[&str] = &[
    "-NoProfile",
    "-NonInteractive",
    "-Command",
    "Get-CimInstance Win32_Processor | Select-Object Name,NumberOfLogicalProcessors | ConvertTo-Json -Compress",
];
const PS_VIDEO: &[&str] = &[
    "-NoProfile",
    "-NonInteractive",
    "-Command",
    "Get-CimInstance Win32_VideoController | Select-Object Name | ConvertTo-Json -Compress",
];
const PS_LOGICALDISK: &[&str] = &[
    "-NoProfile",
    "-NonInteractive",
    "-Command",
    "Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID,Size,FreeSpace | ConvertTo-Json -Compress",
];
const PS_DISKDRIVE: &[&str] = &[
    "-NoProfile",
    "-NonInteractive",
    "-Command",
    "Get-CimInstance Win32_DiskDrive | Select-Object Model,Size | ConvertTo-Json -Compress",
];
const PS_HOTFIX: &[&str] = &[
    "-NoProfile",
    "-NonInteractive",
    "-Command",
    "Get-HotFix | Select-Object HotFixID,InstalledOn | ConvertTo-Json -Compress",
];
const PS_LOCALUSER: &[&str] = &[
    "-NoProfile",
    "-NonInteractive",
    "-Command",
    "Get-LocalUser | Select-Object -ExpandProperty Name",
];
const PS_PROCESS_COUNT: &[&str] = &[
    "-NoProfile",
    "-NonInteractive",
    "-Command",
    "(Get-Process | Measure-Object).Count",
];
const PS_SERVICE_COUNT: &[&str] = &[
    "-NoProfile",
    "-NonInteractive",
    "-Command",
    "(Get-Service | Measure-Object).Count",
];

/// Registry string read through the shared `reg query` -> PowerShell ->
/// native chain, recording every attempt against `field`.
fn reg_sz_field(
    ctx: &mut ScanContext,
    a: &mut Vec<CollectionAttempt>,
    field: &str,
    path: &str,
    name: &str,
) -> Option<String> {
    let q = crate::checks::windows::reg_query_sz_with_log(ctx, path, name);
    for at in q.attempts {
        a.push(att(field, &at.source, at.outcome));
    }
    q.value
}

fn ps_cim_json(
    ctx: &mut ScanContext,
    a: &mut Vec<CollectionAttempt>,
    field: &str,
    script: &[&str],
) -> Option<Value> {
    let raw = first_of(ctx, a, field, &[Source::Cmd("powershell", script)])?;
    serde_json::from_str(&raw).ok()
}

/// Read a process environment variable, but never from the build/test
/// host when a command injector is installed (deterministic runs must
/// not observe host state).
fn host_env(ctx: &ScanContext, name: &str) -> Option<String> {
    if ctx.has_injector() {
        return None;
    }
    std::env::var(name).ok()
}

fn env_computername(ctx: &mut ScanContext) -> Option<String> {
    host_env(ctx, "COMPUTERNAME")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn fqdn_windows_env(ctx: &mut ScanContext) -> Option<String> {
    let host = host_env(ctx, "COMPUTERNAME").filter(|s| !s.trim().is_empty());
    let domain = host_env(ctx, "USERDNSDOMAIN")
        .filter(|s| !s.trim().is_empty());
    match (host, domain) {
        (Some(h), Some(d)) => Some(format!("{}.{}", h.trim(), d.trim())),
        (Some(h), None) => Some(h.trim().to_string()),
        _ => None,
    }
}

fn win_build(ctx: &mut ScanContext) -> Option<String> {
    ctx.platform
        .kernel
        .rsplit('.')
        .next()
        .map(str::to_string)
        .filter(|s| !s.is_empty())
}

fn parse_windows_memory(sysinfo: Option<&str>, cim: Option<&Value>) -> MemInfo {
    let mut m = MemInfo::default();
    if let Some(s) = sysinfo {
        let find = |needle: &str| -> Option<String> {
            s.lines()
                .find(|l| l.to_lowercase().contains(needle))
                .and_then(|l| l.splitn(2, ':').nth(1))
                .map(|v| v.trim().to_string())
        };
        m.total = find("total physical memory").and_then(|v| leading_u64(&v));
        m.available = find("available physical memory").and_then(|v| leading_u64(&v));
        let virt = find("virtual memory: max size").and_then(|v| leading_u64(&v));
        let virt_avail = find("virtual memory: available").and_then(|v| leading_u64(&v));
        m.swap_total = virt;
        m.swap_free = virt_avail;
    }
    if let Some(v) = cim {
        let kb = |key: &str| -> Option<u64> {
            v.get(key)
                .and_then(|x| x.as_u64().or_else(|| x.as_str().and_then(|s| s.parse::<u64>().ok())))
                .map(|kb| kb / 1024)
        };
        m.total = m.total.or_else(|| kb("TotalVisibleMemorySize"));
        m.free = m.free.or_else(|| kb("FreePhysicalMemory"));
        m.available = m.available.or_else(|| kb("FreePhysicalMemory"));
        m.swap_total = m.swap_total.or_else(|| kb("TotalVirtualMemorySize"));
        m.swap_free = m.swap_free.or_else(|| kb("FreeVirtualMemory"));
    }
    m
}

/// Parse the leading run of decimal digits out of a human string like
/// `"16,253 MB"` or `"16253720"`.
fn leading_u64(s: &str) -> Option<u64> {
    let digits: String = s
        .trim()
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse::<u64>().ok()
}

fn user_row_windows(name: String) -> Value {
    json!({
        "name": name,
        "uid": null,
        "gid": null,
        "groups": null,
        "shell_or_usertype": null,
        "privileged": null,
        "last_logon": null,
    })
}

fn parse_net_users(raw: Option<&str>) -> Vec<Value> {
    let Some(out) = raw else {
        return Vec::new();
    };
    let mut users = Vec::new();
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
                users.push(user_row_windows(name.to_string()));
            }
        }
    }
    users
}

fn parse_hotfix_json(raw: &str) -> Option<Vec<Value>> {
    serde_json::from_str::<Vec<Value>>(raw).ok()
}

fn collect_windows(ctx: &mut ScanContext, m: &mut Map<String, Value>, a: &mut Vec<CollectionAttempt>) {
    // hostname / fqdn -----------------------------------------------------
    let hostname = first_of(
        ctx,
        a,
        "hostname",
        &[
            Source::Native("COMPUTERNAME env", env_computername),
            Source::Cmd("powershell", PS_COMPUTERNAME),
            Source::Cmd("hostname", &[]),
        ],
    );
    set(m, "hostname", json!(hostname));
    let fqdn = first_of(
        ctx,
        a,
        "fqdn",
        &[
            Source::Native("COMPUTERNAME + USERDNSDOMAIN env", fqdn_windows_env),
            Source::Cmd("powershell", PS_COMPUTERNAME),
            Source::Cmd("hostname", &[]),
        ],
    );
    set(m, "fqdn", json!(fqdn));

    // machine identity ----------------------------------------------------
    let machine_id = reg_sz_field(ctx, a, "machine_id", WIN_CRYPTO, "MachineGuid");
    set(m, "machine_id", json!(machine_id));

    // OS / kernel / arch --------------------------------------------------
    let os_name = reg_sz_field(ctx, a, "os_name", WIN_CURRENT_VERSION, "ProductName")
        .or_else(|| first_of(ctx, a, "os_name", &[Source::Native("default", default_windows)]));
    set(m, "os_name", json!(os_name));
    let os_version = reg_sz_field(ctx, a, "os_version", WIN_CURRENT_VERSION, "DisplayVersion")
        .or_else(|| reg_sz_field(ctx, a, "os_version", WIN_CURRENT_VERSION, "ReleaseId"))
        .or_else(|| reg_sz_field(ctx, a, "os_version", WIN_CURRENT_VERSION, "CurrentBuildNumber"))
        .or_else(|| {
            first_of(
                ctx,
                a,
                "os_version",
                &[Source::Native("platform kernel build", win_build)],
            )
        });
    set(m, "os_version", json!(os_version));
    set(
        m,
        "kernel",
        json!(first_of(
            ctx,
            a,
            "kernel",
            &[Source::Native("platform kernel", platform_kernel)],
        )),
    );
    set(
        m,
        "arch",
        json!(first_of(
            ctx,
            a,
            "arch",
            &[Source::Native("platform arch", platform_arch)],
        )),
    );
    set(m, "distro", Value::Null);
    set(m, "distro_family", json!("Unknown"));
    set(m, "distro_version", Value::Null);
    set(m, "virtualization", json!(ctx.platform.virtualized.clone()));

    // systeminfo drives several fields; collect it once -------------------
    let sysinfo = first_of(ctx, a, "systeminfo", &[Source::Cmd("systeminfo", &[])]);
    let info = |needle: &str| -> Option<String> {
        sysinfo.as_ref().and_then(|s| {
            s.lines()
                .find(|l| l.to_lowercase().contains(needle))
                .and_then(|l| l.splitn(2, ':').nth(1))
                .map(|v| v.trim().to_string())
        })
    };

    // install date / last boot -------------------------------------------
    let install_date = info("original install date");
    set(m, "install_date", json!(install_date));
    set(m, "install_date_unix", Value::Null);
    let last_boot = info("system boot time");
    set(m, "last_boot", json!(last_boot));
    set(m, "last_boot_unix", Value::Null);
    // Uptime cannot be derived from `systeminfo` reliably (localized boot
    // date); record the reason rather than invent a value.
    a.push(att(
        "uptime_seconds",
        "platform",
        "no reliable local uptime source on Windows",
    ));
    set(m, "uptime_seconds", Value::Null);
    set(m, "uptime", Value::Null);

    // memory --------------------------------------------------------------
    let mem_cim = ps_cim_json(ctx, a, "memory.cim", PS_OS_MEM);
    let mem = parse_windows_memory(sysinfo.as_deref(), mem_cim.as_ref());
    set(m, "memory_mb", json!(mem.total));
    set(
        m,
        "memory",
        json!({
            "total_mb": mem.total,
            "free_mb": mem.free,
            "available_mb": mem.available,
            "swap_total_mb": mem.swap_total,
            "swap_free_mb": mem.swap_free,
        }),
    );

    // cpu -----------------------------------------------------------------
    let cpu_model_sysinfo = info("processor(s)").map(|v| {
        v.split('[')
            .nth(1)
            .map(|x| x.trim_end_matches(']').to_string())
            .unwrap_or(v)
    });
    let cpu_model = cpu_model_sysinfo
        .or_else(|| reg_sz_field(ctx, a, "cpu_model", WIN_CPU0, "ProcessorNameString"));
    set(m, "cpu_model", json!(cpu_model));
    let cpu_cores = first_of(ctx, a, "cpu_cores", &[Source::Cmd("powershell", PS_CPU)])
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .and_then(|v| {
            let obj = v.as_array().and_then(|x| x.first()).cloned().unwrap_or(v);
            obj.get("NumberOfLogicalProcessors")
                .and_then(|n| n.as_u64().or_else(|| n.as_str().and_then(|s| s.parse().ok())))
        })
        .or_else(|| {
            info("processor(s)").and_then(|v| v.split_whitespace().next().and_then(|n| n.parse::<u64>().ok()))
        });
    set(m, "cpu_cores", json!(cpu_cores));
    set(
        m,
        "cpu",
        json!({
            "model": cpu_model,
            "vendor": reg_sz_field(ctx, a, "cpu.vendor", WIN_CPU0, "VendorIdentifier"),
            "cores": cpu_cores,
            "microcode": null,
            "cache": null,
            "flags": null,
        }),
    );

    // motherboard / BIOS / product ----------------------------------------
    set(
        m,
        "motherboard",
        json!({
            "vendor": reg_sz_field(ctx, a, "motherboard.vendor", WIN_BIOS, "BaseBoardManufacturer"),
            "name": reg_sz_field(ctx, a, "motherboard.name", WIN_BIOS, "BaseBoardProduct"),
            "version": null,
        }),
    );
    set(
        m,
        "bios",
        json!({
            "vendor": reg_sz_field(ctx, a, "bios.vendor", WIN_BIOS, "BIOSVendor"),
            "version": reg_sz_field(ctx, a, "bios.version", WIN_BIOS, "BIOSVersion"),
            "date": reg_sz_field(ctx, a, "bios.date", WIN_BIOS, "BIOSReleaseDate"),
        }),
    );
    set(
        m,
        "product",
        json!({
            "name": reg_sz_field(ctx, a, "product.name", WIN_BIOS, "SystemProductName"),
            "vendor": reg_sz_field(ctx, a, "product.vendor", WIN_BIOS, "SystemManufacturer"),
            "family": reg_sz_field(ctx, a, "product.family", WIN_BIOS, "SystemFamily"),
            "sku": reg_sz_field(ctx, a, "product.sku", WIN_BIOS, "SystemSKU"),
        }),
    );

    // GPU -----------------------------------------------------------------
    let mut gpus = Vec::new();
    if let Some(v) = ps_cim_json(ctx, a, "gpu", PS_VIDEO) {
        for item in value_array(&v) {
            if let Some(name) = item.get("Name").and_then(|x| x.as_str()) {
                gpus.push(json!({"name": name, "source": "CIM Win32_VideoController"}));
            }
        }
    }
    set(m, "gpu", Value::Array(gpus));

    // storage -------------------------------------------------------------
    let mut storage = Vec::new();
    if let Some(v) = ps_cim_json(ctx, a, "storage", PS_DISKDRIVE) {
        for item in value_array(&v) {
            let size_gb = item
                .get("Size")
                .and_then(|x| x.as_u64().or_else(|| x.as_str().and_then(|s| s.parse().ok())))
                .map(|b| b / (1024 * 1024 * 1024));
            storage.push(json!({
                "device": null,
                "model": item.get("Model").and_then(|x| x.as_str()),
                "size_gb": size_gb,
                "removable": null,
            }));
        }
    }
    set(m, "storage", Value::Array(storage));

    // network -------------------------------------------------------------
    let dns_servers: Vec<String> = first_of(
        ctx,
        a,
        "network.dns",
        &[Source::Cmd("netsh", &["interface", "ip", "show", "dns"])],
    )
    .map(|s| {
        s.lines()
            .map(str::trim)
            .filter(|l| l.starts_with("DNS Servers") || l.chars().all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.'))
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect()
    })
    .unwrap_or_default();
    set(
        m,
        "network",
        json!({
            "interfaces": [],
            "dns": dns_servers,
            "hostname_fqdn": m.get("fqdn").cloned().unwrap_or(Value::Null),
        }),
    );

    // kernel details ------------------------------------------------------
    set(
        m,
        "kernel_info",
        json!({
            "release": m.get("kernel").cloned().unwrap_or(Value::Null),
            "build": win_build(ctx),
            "version": info("os version"),
        }),
    );

    // system activity -----------------------------------------------------
    let processes = first_of(ctx, a, "processes", &[Source::Cmd("powershell", PS_PROCESS_COUNT)])
        .and_then(|s| s.trim().parse::<u64>().ok());
    set(m, "processes", json!(processes));
    let services_count = first_of(ctx, a, "services_count", &[Source::Cmd("powershell", PS_SERVICE_COUNT)])
        .and_then(|s| s.trim().parse::<u64>().ok());
    set(m, "services_count", json!(services_count));

    // disks ---------------------------------------------------------------
    let mut disks = Vec::new();
    if let Some(v) = ps_cim_json(ctx, a, "disks", PS_LOGICALDISK) {
        for item in value_array(&v) {
            let total = item
                .get("Size")
                .and_then(|x| x.as_u64().or_else(|| x.as_str().and_then(|s| s.parse().ok())))
                .map(|b| b / (1024 * 1024 * 1024));
            let free = item
                .get("FreeSpace")
                .and_then(|x| x.as_u64().or_else(|| x.as_str().and_then(|s| s.parse().ok())))
                .map(|b| b / (1024 * 1024 * 1024));
            disks.push(json!({
                "mount": item.get("DeviceID").and_then(|x| x.as_str()),
                "fs": null,
                "total_mb": total,
                "free_mb": free,
            }));
        }
    }
    set(m, "disks", Value::Array(disks));

    // users ---------------------------------------------------------------
    let net_users = first_of(ctx, a, "users", &[Source::Cmd("net", &["user"])]);
    let mut users = parse_net_users(net_users.as_deref());
    if users.is_empty() {
        if ctx.native_fallbacks_enabled() {
            match crate::checks::windows::native_accounts::native_enum_local_users() {
                Some(names) => {
                    a.push(att("users", "native NetUserEnum", format!("{} users", names.len())));
                    users = names.into_iter().map(user_row_windows).collect();
                }
                None => a.push(att("users", "native NetUserEnum", "unavailable or empty")),
            }
        } else {
            a.push(att("users", "native NetUserEnum", "skipped (injected context)"));
        }
    }
    if users.is_empty() {
        if let Some(raw) = first_of(ctx, a, "users", &[Source::Cmd("powershell", PS_LOCALUSER)]) {
            users = non_empty_lines(&raw).into_iter().map(user_row_windows).collect();
        }
    }
    set(m, "users", Value::Array(users));

    // patch level ---------------------------------------------------------
    let hotfix_raw = first_of(ctx, a, "patch_level", &[Source::Cmd("powershell", PS_HOTFIX)]);
    let (count, newest) = match hotfix_raw.as_deref().and_then(parse_hotfix_json) {
        Some(list) => {
            let newest = list
                .iter()
                .filter_map(|h| h.get("InstalledOn").and_then(|x| x.as_str()).map(str::to_string))
                .max();
            (Some(list.len() as u64), newest)
        }
        None => {
            let count = first_of(ctx, a, "patch_level", &[Source::Cmd("wmic", &["qfe"])])
                .map(|out| {
                    out.lines()
                        .filter(|l| !l.trim().is_empty() && !l.to_lowercase().starts_with("description"))
                        .count() as u64
                });
            (count, None)
        }
    };
    set(m, "patch_level", json!({"hotfix_count": count, "newest_hotfix_date": newest}));

    // owner / timezone / locale -------------------------------------------
    let owner = reg_sz_field(ctx, a, "registered_owner", WIN_CURRENT_VERSION, "RegisteredOwner");
    set(m, "registered_owner", json!(owner));
    let tz = first_of(ctx, a, "timezone", &[Source::Cmd("tzutil", &["/g"])])
        .or_else(|| reg_sz_field(ctx, a, "timezone", WIN_TZ, "TimeZoneKeyName"));
    set(m, "timezone", json!(tz));
    let locale = first_of(
        ctx,
        a,
        "locale",
        &[
            Source::Native("$LANG/$LC_ALL", env_locale),
            Source::Cmd("powershell", PS_COMPUTERNAME),
        ],
    );
    set(m, "locale", json!(locale));
}

/// Normalise a JSON CIM payload (single object or array) into a slice.
fn value_array(v: &Value) -> Vec<&Value> {
    match v {
        Value::Array(a) => a.iter().collect(),
        Value::Null => Vec::new(),
        other => vec![other],
    }
}
