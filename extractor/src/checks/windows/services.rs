//! WIN-SVC: Windows service hardening checks.
//!
//! Evidence from query-only `sc qc <name>`. Absent legacy services count
//! as compliant: the safest service is the one that does not exist.
//! Registry fallback via `reg query ...\Services\<name>\Start` when `sc`
//! is unavailable. Missing evidence degrades, never errors. Print Spooler
//! lives here and nowhere else (PrintNightmare rationale).

use crate::checks::windows::reg_query_dword_with_log;
use crate::checks::{degraded, nok, ok};
use crate::context::ScanContext;
use crate::model::{CheckOutcome, FallbackAttempt, RegisteredCheck};
use crate::platform::Os;

const START_BOOT: u32 = 0;
const START_SYSTEM: u32 = 1;
const START_AUTO: u32 = 2;
const START_DEMAND: u32 = 3;
const START_DISABLED: u32 = 4;

/// Services that exist on every Windows build; querying one successfully
/// proves `sc` itself works, so a later `None` means "service absent"
/// rather than "tool blocked".
const SC_PROBES: &[&str] = &["RpcSs", "Schedule", "winmgmt"];

#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct ServiceConfig {
    pub start_type: Option<u32>,
    pub binary_path: Option<String>,
}

/// Parse `sc qc <name>` text output.
pub fn parse_sc_qc(raw: &str) -> Option<ServiceConfig> {
    let mut cfg = ServiceConfig::default();
    let mut found = false;
    for line in raw.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("START_TYPE") {
            // "START_TYPE         : 4   DISABLED"
            let rest = rest.trim().strip_prefix(':').map(str::trim).unwrap_or("");
            let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(v) = num.parse::<u32>() {
                cfg.start_type = Some(v);
                found = true;
            }
        } else if let Some(rest) = trimmed.strip_prefix("BINARY_PATH_NAME") {
            let rest = rest.trim().strip_prefix(':').map(str::trim).unwrap_or("");
            if !rest.is_empty() {
                cfg.binary_path = Some(rest.to_string());
                found = true;
            }
        }
    }
    found.then_some(cfg)
}

struct ServiceCheckDef {
    services: &'static [&'static str],
}

/// What evidence gathering produced for a service group.
enum Fetch {
    Found(String, ServiceConfig, Vec<FallbackAttempt>),
    /// Every service in the group is confirmed not installed.
    Absent(Vec<FallbackAttempt>),
    /// Could not distinguish absent from blocked.
    Unreadable(Vec<FallbackAttempt>),
}

fn start_name(start: u32) -> &'static str {
    match start {
        START_BOOT => "BOOT_START",
        START_SYSTEM => "SYSTEM_START",
        START_AUTO => "AUTO_START",
        START_DEMAND => "DEMAND_START",
        START_DISABLED => "DISABLED",
        _ => "UNKNOWN",
    }
}

fn registry_start(
    ctx: &mut ScanContext,
    service: &str,
    attempts: &mut Vec<FallbackAttempt>,
) -> Option<ServiceConfig> {
    let path = format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{service}");
    let query = reg_query_dword_with_log(ctx, &path, "Start");
    let readable = query.value.is_some();
    attempts.push(FallbackAttempt {
        source: format!("reg query {path}\\Start"),
        outcome: if readable {
            format!("read Start = {}", query.value.unwrap())
        } else {
            "unavailable or service absent".into()
        },
    });
    query.value.map(|start| ServiceConfig {
        start_type: Some(start),
        binary_path: None,
    })
}

fn fetch_service_group(ctx: &mut ScanContext, services: &[&str]) -> Fetch {
    let mut attempts = Vec::new();
    let sc_alive = SC_PROBES.iter().any(|probe| {
        let parsed = ctx
            .cmd("sc", &["qc", probe])
            .and_then(|raw| parse_sc_qc(&raw))
            .is_some();
        if parsed {
            attempts.push(FallbackAttempt {
                source: format!("sc qc {probe}"),
                outcome: "sc tool alive (probe)".into(),
            });
        }
        parsed
    });
    if !sc_alive {
        attempts.push(FallbackAttempt {
            source: "sc qc (probe)".into(),
            outcome: "sc unavailable or output blocked".into(),
        });
        for service in services {
            if let Some(cfg) = registry_start(ctx, service, &mut attempts) {
                return Fetch::Found((*service).to_string(), cfg, attempts);
            }
        }
        return Fetch::Unreadable(attempts);
    }
    for service in services {
        match ctx.cmd("sc", &["qc", service]) {
            Some(raw) => match parse_sc_qc(&raw) {
                Some(cfg) => {
                    attempts.push(FallbackAttempt {
                        source: format!("sc qc {service}"),
                        outcome: "read service configuration".into(),
                    });
                    return Fetch::Found((*service).to_string(), cfg, attempts);
                }
                None => attempts.push(FallbackAttempt {
                    source: format!("sc qc {service}"),
                    outcome: "service not installed (sc error output)".into(),
                }),
            },
            None => attempts.push(FallbackAttempt {
                source: format!("sc qc {service}"),
                outcome: "service not installed".into(),
            }),
        }
    }
    Fetch::Absent(attempts)
}

fn with_log(mut outcome: CheckOutcome, attempts: Vec<FallbackAttempt>) -> CheckOutcome {
    outcome.fallback_log = attempts;
    outcome
}

fn absent_ok(def: &ServiceCheckDef) -> CheckOutcome {
    ok(
        format!(
            "service(s) {} not installed (compliant by absence)",
            def.services.join("/")
        ),
        format!("services:{}", def.services.join("/")),
        format!("sc qc {}", def.services[0]),
    )
}

/// Policy: service must be disabled or not installed.
fn disabled_check(ctx: &mut ScanContext, def: &ServiceCheckDef) -> CheckOutcome {
    match fetch_service_group(ctx, def.services) {
        Fetch::Found(name, cfg, attempts) => {
            let Some(start) = cfg.start_type else {
                return with_log(
                    degraded(&format!("{name} start type unreadable through read-only sources")),
                    attempts,
                );
            };
            with_log(
                if start == START_DISABLED {
                    ok(
                        format!("{name} start type = DISABLED"),
                        format!("services:{name}"),
                        format!("sc qc {name}"),
                    )
                } else {
                    nok(
                        format!(
                            "{name} start type = {} (expected DISABLED)",
                            start_name(start)
                        ),
                        format!("services:{name}"),
                        format!("sc qc {name}"),
                    )
                },
                attempts,
            )
        }
        Fetch::Absent(attempts) => with_log(absent_ok(def), attempts),
        Fetch::Unreadable(attempts) => with_log(
            degraded(&format!(
                "cannot read {} state through any read-only source",
                def.services.join("/")
            )),
            attempts,
        ),
    }
}

/// Policy: disable where unused (Spooler) — enabled is NonCompliant with
/// role-aware wording.
fn disable_if_unused(ctx: &mut ScanContext, def: &ServiceCheckDef) -> CheckOutcome {
    match fetch_service_group(ctx, def.services) {
        Fetch::Found(name, cfg, attempts) => {
            let Some(start) = cfg.start_type else {
                return with_log(
                    degraded(&format!("{name} start type unreadable through read-only sources")),
                    attempts,
                );
            };
            with_log(
                if start == START_DISABLED {
                    ok(
                        format!("{name} start type = DISABLED"),
                        format!("services:{name}"),
                        format!("sc qc {name}"),
                    )
                } else {
                    nok(
                        format!(
                            "{name} start type = {} (disable when printing is unused)",
                            start_name(start)
                        ),
                        format!("services:{name}"),
                        format!("sc qc {name}"),
                    )
                },
                attempts,
            )
        }
        Fetch::Absent(attempts) => with_log(absent_ok(def), attempts),
        Fetch::Unreadable(attempts) => with_log(
            degraded(&format!(
                "cannot read {} state through any read-only source",
                def.services.join("/")
            )),
            attempts,
        ),
    }
}

/// Policy: record state, never fail (Informational evaluation checks).
fn evaluate_service(ctx: &mut ScanContext, def: &ServiceCheckDef) -> CheckOutcome {
    match fetch_service_group(ctx, def.services) {
        Fetch::Found(name, cfg, attempts) => {
            let detail = match cfg.start_type {
                Some(start) => format!("{name} start type = {}", start_name(start)),
                None => format!("{name} configuration unreadable"),
            };
            with_log(
                ok(detail, format!("services:{name}"), format!("sc qc {name}")),
                attempts,
            )
        }
        Fetch::Absent(attempts) => with_log(
            ok(
                format!("service(s) {} not installed", def.services.join("/")),
                format!("services:{}", def.services.join("/")),
                format!("sc qc {}", def.services[0]),
            ),
            attempts,
        ),
        Fetch::Unreadable(attempts) => with_log(
            degraded(&format!(
                "cannot read {} state through any read-only source",
                def.services.join("/")
            )),
            attempts,
        ),
    }
}

/// WIN-SVC-020: inventory of catalog services not disabled. Read-only
/// sweep over the checks' own service names via `sc qc`; Informational,
/// never fails.
fn auto_start_inventory(ctx: &mut ScanContext) -> CheckOutcome {
    const CATALOG: &[ServiceCheckDef] = &[
        ServiceCheckDef { services: &["TlntSvr"] },
        ServiceCheckDef { services: &["RemoteRegistry"] },
        ServiceCheckDef { services: &["Spooler"] },
        ServiceCheckDef { services: &["SNMP"] },
        ServiceCheckDef { services: &["RemoteAccess"] },
        ServiceCheckDef { services: &["SSDPSRV"] },
        ServiceCheckDef { services: &["upnphost"] },
        ServiceCheckDef { services: &["Wecsvc"] },
        ServiceCheckDef { services: &["W3SVC"] },
        ServiceCheckDef { services: &["SysMain"] },
    ];
    let mut attempts = Vec::new();
    let mut enabled: Vec<String> = Vec::new();
    for def in CATALOG {
        for service in def.services {
            if let Some(cfg) = ctx
                .cmd("sc", &["qc", service])
                .and_then(|raw| parse_sc_qc(&raw))
            {
                if cfg.start_type.map_or(false, |s| s != START_DISABLED) {
                    enabled.push((*service).to_string());
                }
                attempts.push(FallbackAttempt {
                    source: format!("sc qc {service}"),
                    outcome: "inventoried".into(),
                });
            }
        }
    }
    if attempts.is_empty() {
        attempts.push(FallbackAttempt {
            source: "sc qc (catalog sweep)".into(),
            outcome: "no catalog service readable".into(),
        });
    }
    let listing = if enabled.is_empty() {
        "none enabled".to_string()
    } else {
        enabled.join(", ")
    };
    with_log(
        ok(
            format!("catalog services not disabled: {listing}"),
            "services:inventory".into(),
            "sc qc <catalog services>".into(),
        ),
        attempts,
    )
}

fn win(p: &crate::platform::PlatformInfo) -> bool {
    p.os == Os::Windows
}

pub fn register(reg: &mut Vec<RegisteredCheck>) {
    use crate::check;
    check!(
        reg, "WIN-SVC-001",
        "Telnet service disabled or absent",
        "The legacy Telnet server (TlntSvr) is disabled or not installed.",
        "Telnet sends credentials in cleartext and predates every modern control.",
        "Disable TlntSvr or remove the Telnet Server feature.",
        High, "Services", &["CIS 2.2.19"],
        win,
        |ctx| disabled_check(ctx, &ServiceCheckDef { services: &["TlntSvr", "telnet"] })
    );
    check!(
        reg, "WIN-SVC-002",
        "TFTP service disabled or absent",
        "Trivial FTP daemon is disabled or not installed.",
        "TFTP has no authentication and is a malware drop/transfer channel.",
        "Disable or remove any TFTP service.",
        Medium, "Services", &[],
        win,
        |ctx| disabled_check(ctx, &ServiceCheckDef { services: &["tftpd", "TFTP", "SimpleTFTP"] })
    );
    check!(
        reg, "WIN-SVC-003",
        "RemoteRegistry service disabled",
        "Remote access to the registry is disabled.",
        "Remote registry reads leak policy, software and credential material.",
        "Set the RemoteRegistry service start type to Disabled.",
        High, "Services", &["CIS 2.2.14"],
        win,
        |ctx| disabled_check(ctx, &ServiceCheckDef { services: &["RemoteRegistry"] })
    );
    check!(
        reg, "WIN-SVC-004",
        "Print Spooler disabled where printing is unused",
        "Spooler is disabled on hosts that do not print (print servers excepted).",
        "Spooler is the PrintNightmare RCE surface; disabling it kills that class.",
        "Disable Spooler on non-print servers; restrict otherwise.",
        High, "Services", &["CIS 2.2.9"],
        win,
        |ctx| disable_if_unused(ctx, &ServiceCheckDef { services: &["Spooler"] })
    );
    check!(
        reg, "WIN-SVC-005",
        "Fax service disabled or absent",
        "The Fax service is disabled or not installed.",
        "Fax is rarely used and exposes an unwatched processing surface.",
        "Disable the Fax service.",
        Low, "Services", &["CIS 2.2.6"],
        win,
        |ctx| disabled_check(ctx, &ServiceCheckDef { services: &["Fax"] })
    );
    check!(
        reg, "WIN-SVC-006",
        "SMBv1 driver disabled",
        "The MRxSmb10 SMBv1 mini-redirector is disabled.",
        "With the driver off, SMBv1 cannot be negotiated even if other toggles regress.",
        "Set MRxSmb10 start type to 4 (Disabled) and remove SMB1Optional features.",
        Critical, "Services", &["CIS 18.3.2"],
        win,
        |ctx| disabled_check(ctx, &ServiceCheckDef { services: &["MRxSmb10"] })
    );
    check!(
        reg, "WIN-SVC-007",
        "WinHTTP Web Proxy Auto-Discovery disabled",
        "WPAD service (WinHttpAutoProxySvc) is disabled.",
        "WPAD lets any network peer become your proxy: traffic interception made easy.",
        "Disable WinHttpAutoProxySvc.",
        Medium, "Services", &[],
        win,
        |ctx| disabled_check(ctx, &ServiceCheckDef { services: &["WinHttpAutoProxySvc"] })
    );
    check!(
        reg, "WIN-SVC-008",
        "SNMP service disabled or absent",
        "The SNMP service is disabled or not installed.",
        "SNMPv1/v2c communities are cleartext; the service leaks host inventory.",
        "Disable SNMP or require SNMPv3 with authentication.",
        Medium, "Services", &["CIS 2.2.18"],
        win,
        |ctx| disabled_check(ctx, &ServiceCheckDef { services: &["SNMP", "SNMPService"] })
    );
    check!(
        reg, "WIN-SVC-009",
        "Routing and Remote Access disabled",
        "RemoteAccess (RRAS) service is disabled.",
        "RRAS turns the host into a router/VPN endpoint: a high-value takeover target.",
        "Disable RemoteAccess unless the host is a dedicated VPN server.",
        Medium, "Services", &[],
        win,
        |ctx| disabled_check(ctx, &ServiceCheckDef { services: &["RemoteAccess"] })
    );
    check!(
        reg, "WIN-SVC-010",
        "SSDP Discovery disabled",
        "SSDPSRV discovery service is disabled.",
        "SSDP broadcasts host presence and enables UPnP negotiation.",
        "Disable SSDPSRV.",
        Low, "Services", &["CIS 2.2.16"],
        win,
        |ctx| disabled_check(ctx, &ServiceCheckDef { services: &["SSDPSRV"] })
    );
    check!(
        reg, "WIN-SVC-011",
        "UPnP Device Host disabled",
        "upnphost service is disabled.",
        "UPnP opens NAT-traversal paths without user intent.",
        "Disable upnphost (and its SSDPSRV dependency).",
        Low, "Services", &["CIS 2.2.22"],
        win,
        |ctx| disabled_check(ctx, &ServiceCheckDef { services: &["upnphost"] })
    );
    check!(
        reg, "WIN-SVC-012",
        "Windows Event Collector evaluated",
        "Wecsvc subscription service state is recorded.",
        "Event collection state determines whether centralized log review exists.",
        "Enable Wecsvc when forwarding to a collector; document otherwise.",
        Informational, "Services", &["CIS 8.1"],
        win,
        |ctx| evaluate_service(ctx, &ServiceCheckDef { services: &["Wecsvc"] })
    );
    check!(
        reg, "WIN-SVC-013",
        "IIS web server services evaluated",
        "Web server service state is recorded.",
        "A web role on a non-web server is unmanaged attack surface.",
        "Stop W3SVC unless this host is an approved web server.",
        Informational, "Services", &[],
        win,
        |ctx| evaluate_service(ctx, &ServiceCheckDef { services: &["W3SVC", "IISADMIN"] })
    );
    check!(
        reg, "WIN-SVC-014",
        "Microsoft FTP service disabled or absent",
        "msftpsvc FTP service is disabled or not installed.",
        "FTP sends credentials and data in cleartext; SFTP/HTTPS cover modern needs.",
        "Disable msftpsvc; use SFTP or HTTPS transfers.",
        Medium, "Services", &[],
        win,
        |ctx| disabled_check(ctx, &ServiceCheckDef { services: &["msftpsvc", "FTPSVC"] })
    );
    check!(
        reg, "WIN-SVC-015",
        "Xbox Live services disabled",
        "XblAuthManager and related Xbox services are disabled.",
        "Game services on servers are pure surface with zero operational value.",
        "Disable XblAuthManager, XblGameSave, XboxNetApiSvc, XboxGipSvc.",
        Low, "Services", &[],
        win,
        |ctx| disabled_check(ctx, &ServiceCheckDef {
            services: &["XblAuthManager", "XblGameSave", "XboxNetApiSvc", "XboxGipSvc"],
        })
    );
    check!(
        reg, "WIN-SVC-016",
        "SysMain (Superfetch) evaluated",
        "SysMain prefetch service state is recorded.",
        "SysMain is a known memory-abuse vector on RAM-constrained servers.",
        "Consider disabling SysMain on dedicated servers.",
        Informational, "Services", &[],
        win,
        |ctx| evaluate_service(ctx, &ServiceCheckDef { services: &["SysMain"] })
    );
    check!(
        reg, "WIN-SVC-017",
        "Bluetooth support evaluated",
        "Bluetooth service state is recorded.",
        "Bluetooth stacks expose pairing and audio surfaces on servers.",
        "Disable BTAGService/bthserv where no Bluetooth hardware is needed.",
        Informational, "Services", &[],
        win,
        |ctx| evaluate_service(ctx, &ServiceCheckDef {
            services: &["BTAGService", "bthserv", "BluetoothUserService"],
        })
    );
    check!(
        reg, "WIN-SVC-018",
        "Peer Name Resolution Protocol disabled",
        "PNRPsvc (and p2p host) services are disabled.",
        "Peer-to-peer name resolution creates undocumented host-to-host channels.",
        "Disable PNRPsvc, p2psvc, p2pimsvc.",
        Low, "Services", &[],
        win,
        |ctx| disabled_check(ctx, &ServiceCheckDef {
            services: &["PNRPsvc", "p2psvc", "p2pimsvc"],
        })
    );
    check!(
        reg, "WIN-SVC-019",
        "Link-Layer Topology Discovery disabled",
        "lltdsvc discovery mapper is disabled.",
        "LLTD maps the network neighborhood; servers do not need to advertise.",
        "Disable lltdsvc.",
        Low, "Services", &[],
        win,
        |ctx| disabled_check(ctx, &ServiceCheckDef { services: &["lltdsvc"] })
    );
    check!(
        reg, "WIN-SVC-020",
        "Unnecessary auto-start services inventory",
        "Catalog services not configured as disabled are listed.",
        "Auto-start sprawl widens the service attack surface over time.",
        "Review non-disabled catalog services against the approved baseline.",
        Informational, "Services", &[],
        win,
        auto_start_inventory
    );
}
