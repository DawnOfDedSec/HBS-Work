//! Security regression tests for the zero-network-egress guarantee: the
//! command allowlist validator must refuse every DNS/remote form *before*
//! a process is spawned, and the allowlist must contain no
//! name-resolution/network programs. Network egress is owned solely by
//! the explicit `--push` path in `push.rs`, never by evidence collection.

use hbs_extractor::evidence::{
    allowed, validate_powershell_script, COMMAND_ALLOWLIST, FORBIDDEN_NETWORK_PROGRAMS,
};

#[test]
fn hostname_forms_are_file_only() {
    assert!(allowed("hostname", &[]));
    assert!(allowed("hostname", &["-s"]));
    // `-f`/`-A`/`-I` resolve names or interfaces.
    assert!(!allowed("hostname", &["-f"]));
    assert!(!allowed("hostname", &["-A"]));
    assert!(!allowed("hostname", &["-I"]));
}

#[test]
fn getent_hosts_lookup_is_refused() {
    assert!(allowed("getent", &["passwd"]));
    assert!(allowed("getent", &["group"]));
    assert!(allowed("getent", &["shadow"]));
    assert!(allowed("getent", &["initgroups"]));
    assert!(!allowed("getent", &["hosts"]));
    assert!(!allowed("getent", &["hosts", "example.com"]));
}

#[test]
fn showmount_is_removed_entirely() {
    assert!(!COMMAND_ALLOWLIST.contains(&"showmount"));
    assert!(!allowed("showmount", &["-e"]));
    assert!(!allowed("showmount", &[]));
}

#[test]
fn arp_requires_numeric_output() {
    assert!(allowed("arp", &["-an"]));
    assert!(!allowed("arp", &["-a"]));
}

#[test]
fn iptables_requires_numeric_listing() {
    assert!(allowed("iptables", &["-L", "-n"]));
    assert!(allowed("iptables", &["-S", "-n"]));
    assert!(!allowed("iptables", &["-L"]));
    assert!(!allowed("iptables", &["-S"]));
    // State-changing invocations are refused even with -n present.
    assert!(!allowed("iptables", &["-F", "-n"]));
    assert!(!allowed("iptables", &["-A", "INPUT", "-j", "ACCEPT", "-n"]));
}

#[test]
fn remote_targets_are_refused_before_spawn() {
    // The exact cases from the hardening spec.
    assert!(!allowed("wmic", &["qfe", "/node:x"]));
    assert!(!allowed("reg", &["query", r"\\host\HKLM\x"]));
    assert!(!allowed("netsh", &["interface", "portproxy", "show"]));

    // Every remote-target form, centrally enforced.
    assert!(!allowed("wmic", &["qfe", "/server:host"]));
    assert!(!allowed("arp", &["-an", "@host"]));
    assert!(!allowed("arp", &["-an", "//host/share"]));
    assert!(!allowed("arp", &["-an", "-ComputerName", "host"]));
    assert!(!allowed("arp", &["-an", "-Session", "1"]));
    assert!(!allowed("arp", &["-an", "-Credential", "x"]));
    assert!(!allowed(
        "powershell",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-CimInstance -CimSession x -ClassName Win32_BIOS",
        ]
    ));
}

#[test]
fn net_verbs_are_local_only() {
    assert!(allowed("net", &["user"]));
    assert!(allowed("net", &["localgroup"]));
    assert!(allowed("net", &["accounts"]));
    assert!(allowed("net", &["share"]));
    for verb in ["view", "use", "time", "send", "start", "stop", "group"] {
        assert!(!allowed("net", &[verb]), "net {verb} must be refused");
    }
}

#[test]
fn netsh_verbs_are_local_query_contexts() {
    assert!(allowed("netsh", &["advfirewall", "show", "allprofiles"]));
    assert!(allowed("netsh", &["interface", "ip", "show", "dns"]));
    assert!(allowed("netsh", &["interface", "ipv4", "show", "route"]));
    assert!(allowed("netsh", &["http", "show", "urlacl"]));
    assert!(allowed("netsh", &["wlan", "show", "profiles"]));
    assert!(!allowed("netsh", &["interface", "portproxy", "show"]));
    assert!(!allowed(
        "netsh",
        &["advfirewall", "set", "allprofiles", "state", "off"]
    ));
    assert!(!allowed(
        "netsh",
        &["interface", "ip", "set", "dns", "name=Ethernet"]
    ));
}

#[test]
fn powershell_rejects_remote_capable_scripts() {
    assert!(!validate_powershell_script(
        "Get-WmiObject -ComputerName x -Class Win32_BIOS"
    ));
    for token in [
        "-ComputerName x",
        "-Session 1",
        "-Credential $c",
        "-AsJob",
        "-ThrottleLimit 10",
        "-CimSession x",
        "-cimsession x",
    ] {
        let script = format!("Get-WmiObject {token} -Class Win32_BIOS");
        assert!(
            !validate_powershell_script(&script),
            "remote-capable script accepted: {script}"
        );
    }
    // Local queries are still fine.
    assert!(validate_powershell_script(
        "Get-WmiObject -Class Win32_BIOS"
    ));
    assert!(validate_powershell_script(
        "Get-CimInstance Win32_OperatingSystem"
    ));
}

#[test]
fn local_only_programs_are_verb_locked() {
    // `realm discover` and `systeminfo /s` reach other hosts.
    assert!(allowed("realm", &["list"]));
    assert!(!allowed("realm", &["discover", "example.com"]));
    assert!(allowed("systeminfo", &[]));
    assert!(!allowed("systeminfo", &["/s", "host"]));
    // `wevtutil qe ... /r:host` reads a remote event log.
    assert!(!allowed("wevtutil", &["qe", "Security", "/r:host"]));
    // The unused, network-capable `gpg` is not allowlisted at all.
    assert!(!COMMAND_ALLOWLIST.contains(&"gpg"));
}

#[test]
fn allowlist_contains_no_dns_or_network_programs() {
    for prog in FORBIDDEN_NETWORK_PROGRAMS {
        assert!(
            !COMMAND_ALLOWLIST.contains(prog),
            "network program `{prog}` must never be allowlisted"
        );
    }
}
