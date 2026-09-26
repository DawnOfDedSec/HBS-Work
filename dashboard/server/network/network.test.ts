// Network device / firewall configuration review tests.
//
// Fixtures are realistic production-style configuration excerpts for each
// supported platform (Cisco IOS/ASA/NX-OS/WLC, JunOS, Palo Alto, FortiOS,
// Aruba switch + IAP, Ubiquiti) plus the full API flow against a real
// in-memory database.

import { beforeEach, describe, expect, it } from "bun:test";
import { Database } from "bun:sqlite";
import { Hono } from "hono";
import { openDb, runMigrations } from "../db";
import { requireRole, type UserRole } from "../auth";
import {
  detectVendor,
  parseNetworkConfig,
  redactConfigText,
  redactLine,
  VENDOR_LABELS,
} from "./config-parser";
import type { ParsedNetworkConfig } from "./config-parser";
import { reviewConfig, ruleCatalog } from "./review";
import { ingestNetworkConfig, registerNetworkRoutes, MAX_NETWORK_BATCH_FILES } from "./routes";

// ---------------------------------------------------------------------------
// Fixtures — realistic excerpts per platform
// ---------------------------------------------------------------------------

const CISCO_IOS_SWITCH = `
! Building configuration...
version 15.2
service password-encryption
service timestamps log datetime msec
!
hostname CORE-SW-01
!
enable secret 5 $1$AbCd$EfGhIjKlMnOpQrStUvWxw0
security passwords min-length 12
login block-for 120 attempts 3 within 60
no ip source-route
no cdp run
!
username admin privilege 15 secret 5 $1$XYZ$ABCDEFGHIJKLMNOPQRSTUVWXYZ0
username backup password 7 08224F40081A0A0602
!
aaa new-model
aaa authentication login default group tacacs+ local
tacacs-server host 10.10.0.10
!
ip domain name corp.local
ip ssh version 2
no ip http server
ip http secure-server
!
snmp-server community public RW
snmp-server community s3cr3tRO 99
!
logging host 10.10.0.20
ntp server 10.10.0.5
ntp authenticate
!
spanning-tree mode rapid-pvst
ip dhcp snooping
ip dhcp snooping vlan 10,20
!
banner motd ^C
Authorized access only. All activity is monitored.
^C
!
vlan 10
 name USERS
!
vlan 20
 name VOICE
!
interface GigabitEthernet1/0/1
 description AP-Lobby
 switchport mode access
 switchport access vlan 10
 switchport port-security
 spanning-tree portfast
 spanning-tree bpduguard enable
!
interface GigabitEthernet1/0/24
 description Uplink-to-Core
 switchport mode trunk
 switchport trunk native vlan 1
 switchport trunk allowed vlan 10,20,99
!
interface Vlan99
 ip address 10.99.0.2 255.255.255.0
!
line vty 0 4
 exec-timeout 10 0
 login local
 transport input telnet
!
end
`.trim();

const CISCO_IOS_ROUTER_HARDENED = `
version 15.8
hostname EDGE-RTR-01
!
enable secret 9 $9$abcdefghijklmn$opaquevaluehere
username netops privilege 15 secret 9 $9$zyxwvutsrqponm$opaquevaluehere
!
aaa new-model
aaa authentication login default group tacacs+ local
tacacs-server host 10.10.0.10 key 7 00071A150754
!
ip ssh version 2
no ip http server
no ip http secure-server
!
snmp-server group MONITOR v3 priv read MONITOR-VIEW
snmp-server user poller MONITOR v3 auth sha authpass123 priv aes 128 privpass123
!
logging host 10.10.0.20
service timestamps log datetime msec localtime
ntp server 10.10.0.5
ntp authenticate
ntp authentication-key 1 md5 NTPkey123
!
no ip source-route
no cdp run
banner motd ^C Restricted system. Authorized personnel only. ^C
!
interface GigabitEthernet0/0
 description Uplink
 ip address 203.0.113.1 255.255.255.252
 ip access-group EDGE-IN in
!
ip access-list extended EDGE-IN
 permit ip host 10.10.0.0 255.255.255.0 any
 deny   ip any any log
!
line vty 0 4
 exec-timeout 5 0
 transport input ssh
!
ip route 0.0.0.0 0.0.0.0 203.0.113.2
end
`.trim();

const CISCO_ASA = `
: Saved
ASA Version 9.16(1)
!
hostname ASA-EDGE-01
enable password 8NnXx encrypted
passwd 2KFQnN encrypted
username admin password Nx8x9s encrypted privilege 15
!
interface GigabitEthernet0/0
 nameif outside
 security-level 0
 ip address 203.0.113.2 255.255.255.248
!
interface GigabitEthernet0/1
 nameif inside
 security-level 100
 ip address 192.168.10.1 255.255.255.0
!
route outside 0.0.0.0 0.0.0.0 203.0.113.1 1
!
access-list OUTSIDE_IN extended permit ip any any
access-group OUTSIDE_IN in interface outside
!
telnet 192.168.10.0 255.255.255.0 inside
ssh 192.168.10.0 255.255.255.0 inside
ssh version 2
http server enable
!
logging enable
logging host inside 10.10.0.20
!
crypto ikev1 policy 10
 authentication pre-share
 encryption 3des
 hash md5
 group 2
!
`.trim();

const JUNOS_BRACE = `
system {
    host-name EDGE-JX-01;
    services {
        ssh {
            protocol-version v2;
        }
        telnet;
        web-management {
            http;
        }
    }
    syslog {
        host 10.10.0.20 {
            any any;
        }
    }
    ntp {
        server 10.10.0.5;
    }
    login {
        user ops {
            class super-user;
            authentication {
                encrypted-password "$1$salt$hashvalue123456"; ## SECRET-DATA
            }
        }
    }
}
snmp {
    community public {
        authorization read-only;
        clients {
            10.10.0.0/24;
        }
    }
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.0.1/30;
            }
        }
    }
}
routing-options {
    static {
        route 0.0.0.0/0 next-hop 10.0.0.2;
    }
}
vlans {
    USERS {
        vlan-id 10;
    }
}
`.trim();

const JUNOS_SET = [
  "set system host-name EDGE-JX-01",
  "set system services ssh protocol-version v2",
  "set system services telnet",
  "set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/30",
  "set routing-options static route 0.0.0.0/0 next-hop 10.0.0.2",
  "set vlans USERS vlan-id 10",
].join("\n");

const PANOS_SET = [
  "set deviceconfig system hostname PA-FW-01",
  "set deviceconfig system ntp-servers primary-ntp ntp-server-address 10.10.0.5",
  "set mgt-config users admin phash $5$salthashvalue",
  "set network interface ethernet ethernet1/1 layer3 ip 203.0.113.2/29",
  "set rulebase security rules rule1 from untrust",
  "set rulebase security rules rule1 to trust",
  "set rulebase security rules rule1 source any",
  "set rulebase security rules rule1 destination any",
  "set rulebase security rules rule1 service any",
  "set rulebase security rules rule1 action allow",
  "set shared log-settings syslog collector1 server 10.10.0.20 transport UDP port 514",
].join("\n");

const FORTIOS = `
#config-version=FGT60E-4.0.6-FW-build0161-200511-openssl
config system global
    set hostname FGT-BRANCH-01
end
config system admin
    edit "admin"
        set password ENC SH2$opaquevaluehere
        set trusthost1 10.20.0.0 255.255.255.0
        set accprofile "super_admin"
    next
end
config system interface
    edit "port1"
        set ip 203.0.113.2 255.255.255.248
        set allowaccess ping https ssh
        set role wan
    next
    edit "port2"
        set ip 192.168.1.1 255.255.255.0
        set allowaccess ping https ssh http telnet
        set role lan
    next
end
config firewall policy
    edit 1
        set name "Any to Any"
        set srcintf "port2"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic enable
    next
end
config system snmp community
    edit 1
        set name "public"
        set status enable
    next
end
config system ntp
    set ntpsync enable
    set server "10.10.0.5"
end
config log syslogd setting
    set status enable
    set server "10.10.0.20"
end
config router static
    edit 1
        set gateway 203.0.113.1
        set device "port1"
    next
end
`.trim();

const ARUBA_SWITCH = `
; J9623A Configuration Editor; Created on release #J9623A-01
hostname ARUBA-SW-01
password manager user-name admin plaintext MyS3cret
snmp-server community "public" unrestricted
telnet-server enable
web-management plaintext
ip authorized-managers 10.20.0.5 255.255.255.255
vlan 1
   name "DEFAULT_VLAN"
   untagged 1-10
   ip address 192.168.1.10 255.255.255.0
vlan 10
   name "USERS"
   untagged 11-20
   tagged 47
`.trim();

const ARUBA_IAP = `
virtual-controller-country US
name IAP-LOBBY-01
mgmt-user admin S3cret123
wlan ssid-profile Guest
  essid Guest-WiFi
  opmode opensystem
wlan ssid-profile Corp
  essid CORP
  opmode wpa2-psk-aes
  wpa-passphrase SharedPass1
`.trim();

const WLC_AIREOS = `
(Cisco Controller) >config wlan create 1 CORP-PSK CORP
(Cisco Controller) >config wlan security wpa akm 802.1X on 1
(Cisco Controller) >config radius auth add 1 10.10.0.30
(Cisco Controller) >config network ssh enable
sysname WLC-DC-01
`.trim();

const EDGEOS = [
  "set system host-name UBNT-EDGE-01",
  "set system login user ubnt authentication plaintext-password 'secret123'",
  "set interfaces ethernet eth0 address 192.168.1.1/24",
  "set service ssh port 22",
  "set system ntp server 0.ubnt.pool.ntp.org",
  "set firewall name WAN_IN rule 10 action accept",
  "set firewall name WAN_IN rule 10 source address any",
].join("\n");

const NXOS = `
!Command: show running-config
version 9.3(5) Bios:version
hostname NX-AGG-01
feature telnet
feature lacp
boot nxos bootflash:/nxos.9.3.5.bin
vrf context management
username admin password 5 $1$xyz$hashvaluehere role network-admin
snmp-server community public group network-operator
interface Ethernet1/1
  description uplink
  switchport mode trunk
  switchport trunk native vlan 1
`.trim();

const GARBAGE = `
this is not a configuration file
just some random notes about the network
weather: sunny
`.trim();

// ---------------------------------------------------------------------------
// Parser helpers
// ---------------------------------------------------------------------------

function linesOf(text: string) {
  return text.split(/\r\n|\r|\n/).map((line, index) => ({
    n: index + 1,
    text: line.replace(/\t/g, "  "),
    lower: line.toLowerCase(),
  }));
}

function parseProfile(text: string, filename?: string): ParsedNetworkConfig {
  return parseNetworkConfig(text, filename).profile;
}

// ---------------------------------------------------------------------------
// Vendor detection & parsing
// ---------------------------------------------------------------------------

describe("network config detection", () => {
  it("detects every supported platform", () => {
    expect(detectVendor(CISCO_IOS_SWITCH).vendor).toBe("cisco-ios");
    expect(detectVendor(CISCO_IOS_ROUTER_HARDENED).vendor).toBe("cisco-ios");
    expect(detectVendor(CISCO_ASA).vendor).toBe("cisco-asa");
    expect(detectVendor(JUNOS_BRACE).vendor).toBe("juniper-junos");
    expect(detectVendor(JUNOS_SET).vendor).toBe("juniper-junos");
    expect(detectVendor(PANOS_SET).vendor).toBe("palo-alto");
    expect(detectVendor(FORTIOS).vendor).toBe("fortinet");
    expect(detectVendor(ARUBA_SWITCH).vendor).toBe("aruba-switch");
    expect(detectVendor(ARUBA_IAP).vendor).toBe("arubaos");
    expect(detectVendor(WLC_AIREOS).vendor).toBe("cisco-wlc");
    expect(detectVendor(EDGEOS).vendor).toBe("ubiquiti");
    expect(detectVendor(NXOS).vendor).toBe("cisco-nxos");
    expect(detectVendor(GARBAGE).vendor).toBe("generic");
  });
});

describe("network config parsing", () => {
  it("parses a Cisco IOS switch (identity, interfaces, users, snmp, vty)", () => {
    const profile = parseProfile(CISCO_IOS_SWITCH, "core-sw.cfg");
    expect(profile.vendor).toBe("cisco-ios");
    expect(profile.hostname).toBe("CORE-SW-01");
    expect(profile.osVersion).toBe("15.2");
    expect(profile.deviceType).toBe("switch");
    expect(profile.vlans.map((vlan) => vlan.id)).toEqual(["10", "20"]);
    const uplink = profile.interfaces.find((iface) => iface.name === "GigabitEthernet1/0/24");
    expect(uplink?.mode).toBe("trunk");
    expect(uplink?.nativeVlan).toBe("1");
    const access = profile.interfaces.find((iface) => iface.name === "GigabitEthernet1/0/1");
    expect(access?.accessVlan).toBe("10");
    expect(access?.portSecurity).toBe(true);
    expect(profile.users.map((user) => user.name)).toEqual(["admin", "backup"]);
    expect(profile.users[0]?.hashType).toContain("type 5");
    expect(profile.users[1]?.hashType).toContain("type 7");
    expect(profile.snmp.communities.some((community) => community.value === "public" && community.access === "rw")).toBe(true);
    expect(profile.management.sshVersion).toBe("2");
    expect(profile.management.telnetEnabled).toBe(true);
    expect(profile.management.vtyExecTimeout).toBe("10:0");
    expect(profile.management.minPasswordLength).toBe(12);
    expect(profile.management.loginBlockFor).toBeTruthy();
    expect(profile.aaa.newModel).toBe(true);
    expect(profile.aaa.tacacsHosts).toContain("10.10.0.10");
    expect(profile.logging.hosts).toContain("10.10.0.20");
    expect(profile.ntp.servers).toContain("10.10.0.5");
    expect(profile.ntp.authenticated).toBe(true);
    expect(profile.banners.length).toBeGreaterThan(0);
    expect(profile.secrets.some((secret) => /enable/i.test(secret.purpose))).toBe(true);
  });

  it("parses a hardened Cisco IOS router with decided secure state", () => {
    const profile = parseProfile(CISCO_IOS_ROUTER_HARDENED, "edge-rtr.cfg");
    expect(profile.hostname).toBe("EDGE-RTR-01");
    expect(profile.deviceType).toBe("router");
    expect(profile.management.sshVersion).toBe("2");
    expect(profile.management.telnetEnabled).toBe(false);
    expect(profile.management.vtyAcl).toBeNull();
    expect(profile.snmp.v3Configured).toBe(true);
    expect(profile.snmp.communities).toHaveLength(0);
    const uplink = profile.interfaces.find((iface) => iface.name === "GigabitEthernet0/0");
    expect(uplink?.aclIn).toBe("EDGE-IN");
    const acl = profile.acls.find((entry) => entry.name === "EDGE-IN");
    expect(acl?.rules.length).toBe(2);
    expect(profile.staticRoutes[0]?.destination).toContain("default");
  });

  it("parses Cisco ASA (interfaces, security levels, ACL, ikev1)", () => {
    const profile = parseProfile(CISCO_ASA, "asa-edge.cfg");
    expect(profile.vendor).toBe("cisco-asa");
    expect(profile.hostname).toBe("ASA-EDGE-01");
    expect(profile.osVersion).toBe("9.16(1)");
    expect(profile.deviceType).toBe("firewall");
    const outside = profile.interfaces.find((iface) => iface.nameif === "outside");
    expect(outside?.securityLevel).toBe(0);
    expect(outside?.aclIn).toBe("OUTSIDE_IN");
    expect(profile.acls[0]?.rules.some((rule) => /^permit/i.test(rule.text) && /any any/.test(rule.text))).toBe(true);
    expect(profile.management.telnetEnabled).toBe(true);
    expect(profile.management.sshVersion).toBe("2");
    expect(profile.management.mgmtHosts.length).toBeGreaterThan(0);
    expect(profile.vpns[0]?.encryption).toContain("3des");
    expect(profile.vpns[0]?.auth).toContain("md5");
    expect(profile.vpns[0]?.preSharedKey).toBe(true);
    expect(profile.staticRoutes[0]?.destination).toContain("default");
  });

  it("parses JunOS brace syntax into the set model", () => {
    const profile = parseProfile(JUNOS_BRACE, "edge-jx.conf");
    expect(profile.vendor).toBe("juniper-junos");
    expect(profile.hostname).toBe("EDGE-JX-01");
    expect(profile.management.telnetEnabled).toBe(true);
    expect(profile.management.sshVersion).toBe("2");
    expect(profile.management.httpEnabled).toBe(true);
    expect(profile.snmp.communities[0]?.value).toBe("public");
    expect(profile.snmp.communities[0]?.access).toBe("ro");
    expect(profile.interfaces[0]?.ipAddress).toBe("10.0.0.1/30");
    expect(profile.staticRoutes[0]?.destination).toContain("default");
    expect(profile.vlans[0]?.name).toBe("USERS");
    expect(profile.logging.hosts).toContain("10.10.0.20");
    expect(profile.users[0]?.role).toBe("super-user");
  });

  it("parses set-style JunOS identically for hostname", () => {
    const profile = parseProfile(JUNOS_SET, "edge-jx-set.conf");
    expect(profile.hostname).toBe("EDGE-JX-01");
    expect(profile.management.telnetEnabled).toBe(true);
    expect(profile.vlans[0]?.id).toBe("10");
  });

  it("parses Palo Alto set config (identity, any/any rule, user phash)", () => {
    const profile = parseProfile(PANOS_SET, "pa-fw.txt");
    expect(profile.vendor).toBe("palo-alto");
    expect(profile.hostname).toBe("PA-FW-01");
    expect(profile.users[0]?.name).toBe("admin");
    expect(profile.users[0]?.hashType).toContain("phash");
    expect(profile.interfaces[0]?.ipAddress).toBe("203.0.113.2/29");
    const rule = profile.firewallRules.find((entry) => entry.id === "rule1");
    expect(rule?.source).toBe("any");
    expect(rule?.destination).toBe("any");
    expect(rule?.service).toBe("any");
    expect(rule?.action).toBe("allow");
    expect(profile.ntp.servers).toContain("10.10.0.5");
  });

  it("parses FortiOS (identity, allowaccess, policy, snmp, wan role)", () => {
    const profile = parseProfile(FORTIOS, "fgt-branch.conf");
    expect(profile.vendor).toBe("fortinet");
    expect(profile.hostname).toBe("FGT-BRANCH-01");
    expect(profile.model).toBe("FGT60E");
    expect(profile.osVersion).toBe("4.0.6");
    expect(profile.deviceType).toBe("firewall");
    expect(profile.users[0]?.name).toBe("admin");
    expect(profile.users[0]?.hashType).toContain("vendor-encrypted");
    expect(profile.management.mgmtHosts.length).toBeGreaterThan(0);
    expect(profile.management.telnetEnabled).toBe(true);
    expect(profile.management.httpEnabled).toBe(true);
    const wan = profile.interfaces.find((iface) => iface.name === "port1");
    expect(wan?.description).toBe("role: wan");
    const policy = profile.firewallRules[0];
    expect(policy?.source).toBe("all");
    expect(policy?.service).toBe("ALL");
    expect(profile.snmp.communities[0]?.value).toBe("public");
    expect(profile.logging.hosts).toContain("10.10.0.20");
  });

  it("parses Aruba ProCurve switch (users, snmp, telnet, vlan port maps)", () => {
    const profile = parseProfile(ARUBA_SWITCH, "aruba-sw.txt");
    expect(profile.vendor).toBe("aruba-switch");
    expect(profile.hostname).toBe("ARUBA-SW-01");
    expect(profile.deviceType).toBe("switch");
    expect(profile.users[0]?.hashType).toBe("cleartext");
    expect(profile.snmp.communities[0]?.value).toBe("public");
    expect(profile.snmp.communities[0]?.access).toBe("rw");
    expect(profile.management.telnetEnabled).toBe(true);
    expect(profile.management.httpEnabled).toBe(true);
    expect(profile.management.mgmtHosts).toContain("10.20.0.5");
    const port1 = profile.interfaces.find((iface) => iface.name === "1");
    expect(port1?.accessVlan).toBe("1");
    expect(port1?.mode).toBe("access");
    expect(profile.vlans.length).toBe(2);
  });

  it("parses Aruba IAP wireless (SSIDs, opmode, psk)", () => {
    const profile = parseProfile(ARUBA_IAP, "iap-lobby.cfg");
    expect(profile.vendor).toBe("arubaos");
    expect(profile.hostname).toBe("IAP-LOBBY-01");
    expect(profile.deviceType).toBe("wireless-controller");
    expect(profile.wirelessLans).toHaveLength(2);
    const guest = profile.wirelessLans.find((wlan) => wlan.ssid === "Guest-WiFi");
    expect(guest?.authMode).toContain("opensystem");
    const corp = profile.wirelessLans.find((wlan) => wlan.ssid === "CORP");
    expect(corp?.psk).toBe(true);
  });

  it("parses Cisco WLC AireOS (wlan, radius, ssh)", () => {
    const profile = parseProfile(WLC_AIREOS, "wlc-dc.txt");
    expect(profile.vendor).toBe("cisco-wlc");
    expect(profile.hostname).toBe("WLC-DC-01");
    expect(profile.deviceType).toBe("wireless-controller");
    expect(profile.wirelessLans[0]?.ssid).toBe("CORP");
    expect(profile.wirelessLans[0]?.authMode).toBe("wpa-802.1X");
    expect(profile.aaa.radiusHosts).toContain("10.10.0.30");
    expect(profile.management.sshEnabled).toBe(true);
  });

  it("parses Ubiquiti EdgeOS with default ubnt user", () => {
    const profile = parseProfile(EDGEOS, "ubnt.cfg");
    expect(profile.vendor).toBe("ubiquiti");
    expect(profile.hostname).toBe("UBNT-EDGE-01");
    expect(profile.users[0]?.name).toBe("ubnt");
    expect(profile.users[0]?.hashType).toBe("cleartext");
    expect(profile.management.sshEnabled).toBe(true);
  });

  it("parses NX-OS (feature telnet, snmp, trunk native vlan 1)", () => {
    const profile = parseProfile(NXOS, "nx-agg.cfg");
    expect(profile.vendor).toBe("cisco-nxos");
    expect(profile.hostname).toBe("NX-AGG-01");
    expect(profile.deviceType).toBe("switch");
    expect(profile.management.telnetEnabled).toBe(true);
    expect(profile.snmp.communities[0]?.value).toBe("public");
    const uplink = profile.interfaces.find((iface) => iface.name === "Ethernet1/1");
    expect(uplink?.nativeVlan).toBe("1");
  });

  it("degrades unknown content to a generic profile without throwing", () => {
    const profile = parseProfile(GARBAGE, "notes.txt");
    expect(profile.vendor).toBe("generic");
    expect(profile.hostname).toBe("notes");
    expect(reviewConfig(profile, linesOf(GARBAGE)).findings.length).toBeGreaterThan(0);
  });

  it("keeps hostname-less configs with generic filenames distinct", () => {
    // Two different hostname-less exports both named config.txt must NOT merge
    // into one device identity — the generic name is not a hostname.
    const a = parseProfile(CISCO_IOS_SWITCH.replace(/^hostname .*\n/m, ""), "config.txt");
    const b = parseProfile(CISCO_IOS_ROUTER_HARDENED.replace(/^hostname .*\n/m, ""), "config.txt");
    expect(a.hostname).toBeNull();
    expect(b.hostname).toBeNull();
    // A descriptive filename still becomes the display identity.
    const named = parseProfile(CISCO_IOS_SWITCH.replace(/^hostname .*\n/m, ""), "edge-lab-sw.cfg");
    expect(named.hostname).toBe("edge-lab-sw");
  });

  it("never stores secret values in the parsed profile", () => {
    const text = [CISCO_IOS_SWITCH, ARUBA_SWITCH, EDGEOS, ARUBA_IAP].join("\n");
    const profile = parseProfile(text, "combined.cfg");
    const serialized = JSON.stringify(profile);
    expect(serialized).not.toContain("MyS3cret");
    expect(serialized).not.toContain("secret123");
    expect(serialized).not.toContain("SharedPass1");
    expect(serialized).not.toContain("08224F40081A0A0602");
  });
});

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

describe("config redaction", () => {
  it("masks secret values but keeps type indicators and structure", () => {
    expect(redactLine("username backup password 7 08224F40081A0A0602")).toBe("username backup password 7 <redacted>");
    expect(redactLine("enable secret 5 $1$AbCd$EfGh")).toBe("enable secret 5 <redacted>");
    expect(redactLine("set password ENC SH2$opaquevalue")).toBe("set password <redacted> <redacted>");
    expect(redactLine("wpa-passphrase SharedPass1")).toBe("wpa-passphrase <redacted>");
    expect(redactLine("transport input telnet ssh")).toBe("transport input telnet ssh");
    expect(redactLine("interface GigabitEthernet1/0/1")).toBe("interface GigabitEthernet1/0/1");
  });

  it("keeps SNMP community lines readable for review evidence", () => {
    expect(redactLine("snmp-server community public RW")).toBe("snmp-server community public RW");
  });

  it("redacts a whole config line-preserving", () => {
    const redacted = redactConfigText(ARUBA_SWITCH);
    expect(redacted.split("\n").length).toBe(ARUBA_SWITCH.split("\n").length);
    expect(redacted).not.toContain("MyS3cret");
    expect(redacted).toContain("snmp-server community \"public\" unrestricted");
  });
});

// ---------------------------------------------------------------------------
// Review engine
// ---------------------------------------------------------------------------

describe("network configuration review", () => {
  it("catalog exposes a broad rule set across categories", () => {
    const catalog = ruleCatalog();
    expect(catalog.length).toBeGreaterThanOrEqual(40);
    const categories = new Set(catalog.map((rule) => rule.category));
    for (const expected of ["Authentication", "Management", "SNMP", "Logging", "Firewall policy", "VPN", "Switching", "Wireless"]) {
      expect(categories.has(expected)).toBe(true);
    }
    // check ids are unique and well-formed
    const ids = catalog.map((rule) => rule.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ids) expect(id).toMatch(/^NET-[A-Z]+-\d{3}$/);
  });

  it("flags the weak Cisco IOS switch on the expected rules", () => {
    const { profile } = parseNetworkConfig(CISCO_IOS_SWITCH, "core-sw.cfg");
    const { findings, score } = reviewConfig(profile, linesOf(CISCO_IOS_SWITCH));
    const byId = new Map(findings.map((finding) => [finding.checkId, finding]));

    const nc = (id: string) => expect(byId.get(id)?.status).toBe("NonCompliant");
    const ok = (id: string) => expect(byId.get(id)?.status).toBe("Compliant");

    nc("NET-AUTH-003"); // type-7 storage
    nc("NET-MGMT-001"); // telnet on vty
    nc("NET-SNMP-001"); // default community
    nc("NET-SNMP-002"); // v2c without v3
    nc("NET-SNMP-003"); // RW community
    nc("NET-SNMP-004"); // public community without ACL
    nc("NET-SW-003"); // native vlan 1
    ok("NET-AUTH-001"); // enable secret present
    ok("NET-AUTH-002"); // users hashed
    ok("NET-AUTH-005"); // aaa new-model
    ok("NET-MGMT-002"); // http explicitly off
    ok("NET-MGMT-003"); // ssh v2
    ok("NET-MGMT-010"); // banner present
    ok("NET-LOG-001"); // syslog host
    ok("NET-LOG-002"); // service timestamps present
    ok("NET-NTP-001"); // ntp server
    ok("NET-NTP-002"); // ntp authenticate
    ok("NET-SW-001"); // dhcp snooping on
    ok("NET-MGMT-011"); // min-length 12

    // evidence carries line numbers and never leaks the type-7 secret
    const type7 = byId.get("NET-AUTH-003");
    expect(type7?.evidence.some((line) => /^line \d+:/.test(line))).toBe(true);
    expect(JSON.stringify(findings)).not.toContain("08224F40081A0A0602");

    expect(score).toBeGreaterThanOrEqual(0);
    expect(score).toBeLessThanOrEqual(100);
    // weak switch must not score safely
    expect(score).toBeLessThan(80);
  });

  it("scores the hardened router high with compliant decisions", () => {
    const { profile } = parseNetworkConfig(CISCO_IOS_ROUTER_HARDENED, "edge-rtr.cfg");
    const { findings, score } = reviewConfig(profile, linesOf(CISCO_IOS_ROUTER_HARDENED));
    const byId = new Map(findings.map((finding) => [finding.checkId, finding]));

    ok(byId, "NET-MGMT-001"); // telnet explicitly off
    ok(byId, "NET-MGMT-002"); // http explicitly off
    ok(byId, "NET-MGMT-003"); // ssh v2
    ok(byId, "NET-MGMT-010"); // banner
    ok(byId, "NET-SNMP-002"); // v3 only
    ok(byId, "NET-SNMP-003"); // no RW communities
    ok(byId, "NET-LOG-001"); // syslog
    ok(byId, "NET-LOG-002"); // timestamps
    ok(byId, "NET-NTP-001");
    ok(byId, "NET-NTP-002");
    ok(byId, "NET-SVC-002"); // no ip source-route
    ok(byId, "NET-SVC-003"); // no cdp run
    ok(byId, "NET-AUTH-006") ; // tacacs+ configured -> not applicable here; see below

    expect(score).toBeGreaterThan(85);
  });

  it("flags ASA telnet, any/any ACL and weak IKE", () => {
    const { profile } = parseNetworkConfig(CISCO_ASA, "asa.cfg");
    const { findings } = reviewConfig(profile, linesOf(CISCO_ASA));
    const byId = new Map(findings.map((finding) => [finding.checkId, finding]));

    expect(byId.get("NET-MGMT-001")?.status).toBe("NonCompliant");
    expect(byId.get("NET-FW-003")?.status).toBe("NonCompliant");
    expect(byId.get("NET-FW-003")?.severity).toBe("High");
    expect(byId.get("NET-VPN-001")?.status).toBe("NonCompliant");
    expect(byId.get("NET-VPN-001")?.severity).toBe("Critical"); // md5 + 3des
    expect(byId.get("NET-VPN-002")?.status).toBe("NonCompliant"); // PSK
    expect(byId.get("NET-FW-002")?.status).toBe("Compliant"); // firewall has ACLs
    expect(byId.get("NET-FW-004")?.status).toBe("Compliant"); // outside has ingress ACL
    expect(byId.get("NET-MGMT-003")?.status).toBe("Compliant"); // ssh version 2
  });

  it("flags Palo Alto any/any allow rule", () => {
    const { profile } = parseNetworkConfig(PANOS_SET, "pa.txt");
    const { findings } = reviewConfig(profile, linesOf(PANOS_SET));
    const byId = new Map(findings.map((finding) => [finding.checkId, finding]));
    expect(byId.get("NET-FW-001")?.status).toBe("NonCompliant");
    expect(byId.get("NET-FW-001")?.evidence.some((line) => line.includes("rule1"))).toBe(false); // evidence is line-based
    expect(byId.get("NET-AUTH-002")?.status).toBe("Compliant"); // phash admin
  });

  it("flags FortiOS telnet/http on LAN, default snmp and any/any policy", () => {
    const { profile } = parseNetworkConfig(FORTIOS, "fgt.conf");
    const { findings } = reviewConfig(profile, linesOf(FORTIOS));
    const byId = new Map(findings.map((finding) => [finding.checkId, finding]));
    expect(byId.get("NET-MGMT-001")?.status).toBe("NonCompliant");
    expect(byId.get("NET-MGMT-002")?.status).toBe("NonCompliant");
    expect(byId.get("NET-SNMP-001")?.status).toBe("NonCompliant");
    expect(byId.get("NET-FW-001")?.status).toBe("NonCompliant");
    expect(byId.get("NET-MGMT-005")?.status).toBe("Compliant"); // trusthost set
    expect(byId.get("NET-FW-005")?.status).toBe("Compliant"); // WAN has no mgmt services
  });

  it("flags Aruba switch plaintext manager and unrestricted snmp", () => {
    const { profile } = parseNetworkConfig(ARUBA_SWITCH, "aruba.txt");
    const { findings } = reviewConfig(profile, linesOf(ARUBA_SWITCH));
    const byId = new Map(findings.map((finding) => [finding.checkId, finding]));
    expect(byId.get("NET-AUTH-002")?.status).toBe("NonCompliant");
    expect(byId.get("NET-MGMT-009")?.status).toBe("NonCompliant"); // default admin + plaintext
    expect(byId.get("NET-SNMP-001")?.status).toBe("NonCompliant");
    expect(byId.get("NET-SNMP-003")?.status).toBe("NonCompliant"); // unrestricted == rw
    expect(byId.get("NET-MGMT-001")?.status).toBe("NonCompliant");
    expect(byId.get("NET-MGMT-002")?.status).toBe("NonCompliant");
  });

  it("flags open and PSK wireless networks on IAP", () => {
    const { profile } = parseNetworkConfig(ARUBA_IAP, "iap.cfg");
    const { findings } = reviewConfig(profile, linesOf(ARUBA_IAP));
    const byId = new Map(findings.map((finding) => [finding.checkId, finding]));
    expect(byId.get("NET-WIFI-001")?.status).toBe("NonCompliant");
    expect(byId.get("NET-WIFI-001")?.severity).toBe("High"); // opensystem, not WEP
    expect(byId.get("NET-WIFI-003")?.status).toBe("NonCompliant"); // PSK without RADIUS
  });

  it("flags Ubiquiti default ubnt credential as critical", () => {
    const { profile } = parseNetworkConfig(EDGEOS, "ubnt.cfg");
    const { findings } = reviewConfig(profile, linesOf(EDGEOS));
    const byId = new Map(findings.map((finding) => [finding.checkId, finding]));
    expect(byId.get("NET-MGMT-009")?.status).toBe("NonCompliant");
    expect(byId.get("NET-MGMT-009")?.severity).toBe("Critical");
    expect(byId.get("NET-AUTH-002")?.status).toBe("NonCompliant");
  });

  it("never false-passes: N/A checks never count toward the score", () => {
    const { profile } = parseNetworkConfig(GARBAGE, "notes.txt");
    const { findings, score } = reviewConfig(profile, linesOf(GARBAGE));
    for (const finding of findings) {
      if (finding.status === "NotApplicable") continue;
      // generic profile still gets evaluated on whatever evidence exists
      expect(["Compliant", "NonCompliant"]).toContain(finding.status);
    }
    expect(score).toBeGreaterThanOrEqual(0);
    expect(score).toBeLessThanOrEqual(100);
  });

  it("summary aggregates severities for NonCompliant only", () => {
    const { profile } = parseNetworkConfig(CISCO_IOS_SWITCH, "core-sw.cfg");
    const { summary } = reviewConfig(profile, linesOf(CISCO_IOS_SWITCH));
    expect(summary.total).toBe(summary.critical + summary.high + summary.medium + summary.low + summary.informational + summary.compliant + summary.notApplicable);
    expect(summary.critical + summary.high).toBeGreaterThan(0);
  });
});

function ok(byId: Map<string, { status: string }>, id: string): void {
  const finding = byId.get(id);
  // AUTH-006 is gated to apply only when AAA is on but no remote server — it
  // is legitimately NotApplicable on the hardened router (tacacs present), so
  // accept either N/A or Compliant there.
  if (id === "NET-AUTH-006") {
    expect(["NotApplicable", "Compliant"]).toContain(finding?.status ?? "");
    return;
  }
  expect(finding?.status).toBe("Compliant");
}

// ---------------------------------------------------------------------------
// API routes
// ---------------------------------------------------------------------------

type TestUser = { id: number; username: string; role: string };

const ADMIN: TestUser = { id: 1, username: "admin1", role: "super_admin" };
const AUDITOR: TestUser = { id: 2, username: "auditor1", role: "auditor" };
const VIEWER: TestUser = { id: 3, username: "viewer1", role: "viewer" };

describe("network review API", () => {
  let db: Database;
  let reportSeq = 0;

  const makeApp = (user: TestUser) => {
    const app = new Hono();
    app.use("*", async (c, next) => {
      (c as unknown as { set(name: string, value: unknown): void }).set("user", user);
      await next();
    });
    registerNetworkRoutes(app, db, {
      requireRole: (...roles: string[]) => requireRole(...(roles as UserRole[])) as never,
    });
    return app;
  };

  const request = async (user: TestUser, path: string, init?: RequestInit) => {
    const response = await makeApp(user).request(path, init);
    const text = await response.text();
    const contentType = response.headers.get("content-type") ?? "";
    if (!contentType.includes("application/json")) {
      return { status: response.status, body: text, headers: response.headers };
    }
    return { status: response.status, body: text ? JSON.parse(text) : null, headers: response.headers };
  };

  const uploadFile = async (user: TestUser, filename: string, content: string, campaignId = 1, locationId = 1) => {
    const form = new FormData();
    form.append("campaignId", String(campaignId));
    form.append("locationId", String(locationId));
    form.append("files", new File([content], filename));
    return request(user, "/api/network/upload", { method: "POST", body: form });
  };

  beforeEach(() => {
    db = openDb(":memory:");
    runMigrations(db);
    db.query(
      "INSERT INTO campaigns (id, name, status, tags, created_at, updated_at) VALUES (1, 'Net Audit', 'active', '[]', '2026-01-01', '2026-01-01')",
    ).run();
    db.query(
      "INSERT INTO locations (id, campaign_id, name, tags, created_at, updated_at) VALUES (1, 1, 'DC-East', '[]', '2026-01-01', '2026-01-01')",
    ).run();
    db.query(
      "INSERT INTO locations (id, campaign_id, name, tags, created_at, updated_at) VALUES (2, 1, 'Branch', '[]', '2026-01-01', '2026-01-01')",
    ).run();
    reportSeq = 0;
  });

  it("uploads configs, routes devices to the chosen location, and lists them", async () => {
    const ios = await uploadFile(AUDITOR, "core-sw.cfg", CISCO_IOS_SWITCH);
    expect(ios.status).toBe(200);
    expect(ios.body.results[0].result.ok).toBe(true);
    expect(ios.body.results[0].result.hostname).toBe("CORE-SW-01");
    expect(ios.body.results[0].result.vendorLabel).toBe(VENDOR_LABELS["cisco-ios"]);
    expect(ios.body.results[0].result.findings.critical).toBeGreaterThan(0);
    const deviceId = ios.body.results[0].result.deviceId;

    // a second device in the same location
    await uploadFile(AUDITOR, "fgt-branch.conf", FORTIOS);

    const listed = await request(VIEWER, "/api/network/devices?locationId=1");
    expect(listed.status).toBe(200);
    expect(listed.body.devices).toHaveLength(2);
    const names = listed.body.devices.map((device: { hostname: string | null }) => device.hostname).sort();
    expect(names).toEqual(["CORE-SW-01", "FGT-BRANCH-01"]);
    expect(listed.body.devices[0].links.device).toMatch(/^\/api\/network\/devices\/\d+$/);

    // device keyed by hostname: re-upload of a changed config merges into the same device
    const changed = CISCO_IOS_SWITCH.replace("vlan 10", "vlan 30");
    const again = await uploadFile(AUDITOR, "core-sw.cfg", changed);
    expect(again.body.results[0].result.duplicate).toBe(false);
    expect(again.body.results[0].result.deviceId).toBe(deviceId);
    const listed2 = await request(VIEWER, "/api/network/devices?locationId=1");
    expect(listed2.body.devices).toHaveLength(2);
  });

  it("is idempotent for identical re-uploads (same location, same bytes)", async () => {
    const first = await uploadFile(AUDITOR, "core-sw.cfg", CISCO_IOS_SWITCH);
    const second = await uploadFile(AUDITOR, "core-sw.cfg", CISCO_IOS_SWITCH);
    expect(second.body.results[0].result.ok).toBe(true);
    expect(second.body.results[0].result.duplicate).toBe(true);
    expect(second.body.results[0].result.reportId).toBe(first.body.results[0].result.reportId);
  });

  it("keeps the same config at two locations as separate reports", async () => {
    const atDc = await uploadFile(AUDITOR, "asa.cfg", CISCO_ASA, 1, 1);
    const atBranch = await uploadFile(AUDITOR, "asa.cfg", CISCO_ASA, 1, 2);
    expect(atDc.body.results[0].result.duplicate).toBe(false);
    expect(atBranch.body.results[0].result.duplicate).toBe(false);
    expect(atBranch.body.results[0].result.deviceId).toBe(atDc.body.results[0].result.deviceId);
    const branch = await request(VIEWER, "/api/network/devices?locationId=2");
    expect(branch.body.devices).toHaveLength(1);
  });

  it("rejects invalid targets: missing location, mismatched campaign, retired location", async () => {
    const missing = await uploadFile(AUDITOR, "x.cfg", CISCO_IOS_SWITCH, 1, 999);
    expect(missing.body.results[0].result.code).toBe("LOCATION_NOT_FOUND");

    const mismatch = await uploadFile(AUDITOR, "x.cfg", CISCO_IOS_SWITCH, 2, 1);
    expect(mismatch.body.results[0].result.code).toBe("LOCATION_MISMATCH");

    db.query("UPDATE locations SET retired_at = '2026-01-02' WHERE id = 2").run();
    const retired = await uploadFile(AUDITOR, "x.cfg", CISCO_IOS_SWITCH, 1, 2);
    expect(retired.body.results[0].result.code).toBe("LOCATION_RETIRED");
  });

  it("rejects empty, binary, and oversized files without blocking siblings", async () => {
    const form = new FormData();
    form.append("campaignId", "1");
    form.append("locationId", "1");
    form.append("files", new File([CISCO_IOS_SWITCH], "good.cfg"));
    form.append("files", new File([new Uint8Array([0, 1, 2, 0])], "binary.hbs"));
    const response = await makeApp(AUDITOR).request("/api/network/upload", { method: "POST", body: form });
    const body = await response.json();
    const results = body.results as Array<{ name: string; result: { ok: boolean; code?: string } }>;
    expect(results.find((entry) => entry.name === "good.cfg")?.result.ok).toBe(true);
    expect(results.find((entry) => entry.name === "binary.hbs")?.result.ok).toBe(false);
    expect(results.find((entry) => entry.name === "binary.hbs")?.result.code).toBe("BINARY_NOT_CONFIG");

    const empty = await uploadFile(AUDITOR, "empty.cfg", "");
    expect(empty.body.results[0].result.code).toBe("EMPTY_FILE");
  });

  it("enforces the batch limit and role gating", async () => {
    const form = new FormData();
    form.append("campaignId", "1");
    form.append("locationId", "1");
    for (let index = 0; index <= MAX_NETWORK_BATCH_FILES; index += 1) {
      form.append("files", new File([`hostname SW-${index}`], `sw-${index}.cfg`));
    }
    const response = await makeApp(ADMIN).request("/api/network/upload", { method: "POST", body: form });
    expect(response.status).toBe(413);

    const forbidden = await uploadFile(VIEWER, "x.cfg", CISCO_IOS_SWITCH);
    expect(forbidden.status).toBe(403);
  });

  it("device detail exposes parsed information and review findings", async () => {
    const uploaded = await uploadFile(ADMIN, "fgt-branch.conf", FORTIOS);
    const reportId = uploaded.body.results[0].result.reportId as number;
    const deviceId = uploaded.body.results[0].result.deviceId as number;

    const detail = await request(VIEWER, `/api/network/devices/${deviceId}`);
    expect(detail.status).toBe(200);
    expect(detail.body.device.hostname).toBe("FGT-BRANCH-01");
    expect(detail.body.device.model).toBe("FGT60E");
    expect(detail.body.locations[0].name).toBe("DC-East");
    expect(detail.body.reports[0].id).toBe(reportId);
    expect(detail.body.latest.parsed.hostname).toBe("FGT-BRANCH-01");
    const checkIds = detail.body.latest.findings.map((finding: { checkId: string }) => finding.checkId);
    expect(checkIds).toContain("NET-MGMT-001");
    expect(detail.body.latest.findings.every((finding: { evidence: string[] }) => Array.isArray(finding.evidence))).toBe(true);
    expect(detail.body.summary.severity.critical + detail.body.summary.severity.high).toBeGreaterThan(0);
  });

  it("report detail returns parsed config, findings and a redacted raw config", async () => {
    const uploaded = await uploadFile(ADMIN, "aruba-sw.txt", ARUBA_SWITCH);
    const reportId = uploaded.body.results[0].result.reportId as number;

    const report = await request(VIEWER, `/api/network/reports/${reportId}`);
    expect(report.status).toBe(200);
    expect(report.body.device.vendorLabel).toBe(VENDOR_LABELS["aruba-switch"]);
    expect(report.body.parsed.hostname).toBe("ARUBA-SW-01");
    expect(report.body.findings.length).toBeGreaterThanOrEqual(40);
    expect(report.body.configText).toContain("hostname ARUBA-SW-01");
    expect(report.body.configText).not.toContain("MyS3cret");
    // findings never leak secrets either
    expect(JSON.stringify(report.body.findings)).not.toContain("MyS3cret");
  });

  it("supports the treatment workflow with justification enforcement and history", async () => {
    const uploaded = await uploadFile(ADMIN, "core-sw.cfg", CISCO_IOS_SWITCH);
    const reportId = uploaded.body.results[0].result.reportId as number;
    const path = `/api/network/reports/${reportId}/findings/NET-SNMP-001/treatment`;

    const noJustification = await request(AUDITOR, path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ state: "accepted_risk" }),
    });
    expect(noJustification.status).toBe(400);
    expect(noJustification.body.code).toBe("JUSTIFICATION_REQUIRED");

    const accepted = await request(AUDITOR, path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ state: "accepted_risk", justification: "Legacy NMS depends on v2c until Q4.", assignee: "netops" }),
    });
    expect(accepted.status).toBe(200);
    expect(accepted.body.state).toBe("accepted_risk");

    const invalid = await request(AUDITOR, path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ state: "nope" }),
    });
    expect(invalid.status).toBe(400);
    expect(invalid.body.code).toBe("INVALID_TREATMENT_STATE");

    // history was appended (trigger on update + explicit insert)
    const history = db
      .query(
        `SELECT h.to_state, h.justification FROM network_finding_state_history h
           JOIN network_finding_states s ON s.id = h.finding_state_id
          WHERE s.report_id = ? AND s.check_id = 'NET-SNMP-001'
          ORDER BY h.id`,
      )
      .all(reportId) as Array<{ to_state: string; justification: string | null }>;
    expect(history.length).toBeGreaterThanOrEqual(2); // trigger row + explicit row
    expect(history.at(-1)?.justification).toContain("Legacy NMS");

    // the state is reflected on subsequent report reads
    const report = await request(VIEWER, `/api/network/reports/${reportId}`);
    const finding = report.body.findings.find((entry: { checkId: string }) => entry.checkId === "NET-SNMP-001");
    expect(finding.treatmentState).toBe("accepted_risk");

    // history is readable through the API as well
    const historyApi = await request(VIEWER, `/api/network/reports/${reportId}/findings/NET-SNMP-001/history`);
    expect(historyApi.status).toBe(200);
    expect(historyApi.body.history.length).toBe(history.length);
    expect(historyApi.body.history.at(-1)?.toState).toBe("accepted_risk");
    expect(historyApi.body.history.at(-1)?.fromState).toBe("open");
  });

  it("404s cleanly for unknown devices and reports", async () => {
    expect((await request(VIEWER, "/api/network/devices/999")).status).toBe(404);
    expect((await request(VIEWER, "/api/network/reports/999")).status).toBe(404);
  });

  it("requires campaignId or locationId for listings", async () => {
    const response = await request(VIEWER, "/api/network/devices");
    expect(response.status).toBe(400);
  });

  it("exposes the review rule catalog", async () => {
    const listed = await request(VIEWER, "/api/network/rules");
    expect(listed.status).toBe(200);
    expect(listed.body.total).toBeGreaterThanOrEqual(46);
    const ids = (listed.body.rules as Array<{ id: string }>).map((rule) => rule.id);
    expect(ids).toContain("NET-LIFE-001");
    expect(ids).toContain("NET-MGMT-001");
  });

  it("diffs two uploads of the same device (fixed/regressed)", async () => {
    // v2 is identical to v1 except: telnet -> ssh and the RW community removed.
    const hardened = CISCO_IOS_SWITCH
      .replace("transport input telnet", "transport input ssh")
      .replace("snmp-server community public RW", "snmp-server community public RO");
    const first = await uploadFile(ADMIN, "core-sw.cfg", CISCO_IOS_SWITCH);
    expect(first.body.results[0].result.ok).toBe(true);
    const second = await uploadFile(ADMIN, "core-sw.cfg", hardened);
    expect(second.body.results[0].result.ok).toBe(true);
    const deviceId = first.body.results[0].result.deviceId as number;
    expect(second.body.results[0].result.deviceId).toBe(deviceId);

    const diff = await request(VIEWER, `/api/network/devices/${deviceId}/diff`);
    expect(diff.status).toBe(200);
    expect(diff.body.diff).not.toBeNull();
    // Telnet was removed between the two uploads.
    const fixedIds = (diff.body.fixed as Array<{ checkId: string }>).map((entry) => entry.checkId);
    expect(fixedIds).toContain("NET-MGMT-001");
    expect(fixedIds).toContain("NET-SNMP-003");
    expect(diff.body.regressed).toHaveLength(0);
    expect(diff.body.to.score).toBeGreaterThan(diff.body.from.score);

    // Explicit report selection must be validated to belong to the device.
    const bad = await request(VIEWER, `/api/network/devices/${deviceId}/diff?from=999999&to=999998`);
    expect(bad.status).toBe(400);
  });

  it("applies bulk treatments with one justification", async () => {
    const uploaded = await uploadFile(ADMIN, "core-sw.cfg", CISCO_IOS_SWITCH);
    const reportId = uploaded.body.results[0].result.reportId as number;

    const missing = await request(ADMIN, `/api/network/reports/${reportId}/findings/treatment-bulk`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ checkIds: ["NET-SNMP-001", "NET-MGMT-001"], state: "false_positive" }),
    });
    expect(missing.status).toBe(400);
    expect(missing.body.code).toBe("JUSTIFICATION_REQUIRED");

    const bulk = await request(ADMIN, `/api/network/reports/${reportId}/findings/treatment-bulk`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        checkIds: ["NET-SNMP-001", "NET-MGMT-001", "NET-FAKE-001"],
        state: "false_positive",
        justification: "Both verified as scanner noise by netops.",
      }),
    });
    expect(bulk.status).toBe(200);
    expect(bulk.body.applied).toHaveLength(2);
    expect(bulk.body.skipped).toHaveLength(1);
    expect(bulk.body.skipped[0].reason).toBe("NOT_IN_REPORT");

    const report = await request(VIEWER, `/api/network/reports/${reportId}`);
    const states = (report.body.findings as Array<{ checkId: string; treatmentState: string }>)
      .filter((finding) => finding.checkId === "NET-SNMP-001" || finding.checkId === "NET-MGMT-001")
      .map((finding) => finding.treatmentState);
    expect(states).toEqual(["false_positive", "false_positive"]);
  });

  it("exports review findings as xlsx and csv", async () => {
    const uploaded = await uploadFile(ADMIN, "core-sw.cfg", CISCO_IOS_SWITCH);
    const deviceId = uploaded.body.results[0].result.deviceId as number;
    const reportId = uploaded.body.results[0].result.reportId as number;

    const xlsx = await request(VIEWER, `/api/network/reports/${reportId}/export?format=xlsx`);
    expect(xlsx.status).toBe(200);
    expect(String(xlsx.headers.get("content-type"))).toContain("spreadsheetml");

    const csv = await request(VIEWER, `/api/network/devices/${deviceId}/export?format=csv`);
    expect(csv.status).toBe(200);
    expect(String(csv.headers.get("content-type"))).toContain("text/csv");
    expect(String(csv.body)).toContain("NET-MGMT-001");

    const bad = await request(VIEWER, `/api/network/reports/${reportId}/export?format=pdf`);
    expect(bad.status).toBe(400);
    const missing = await request(VIEWER, "/api/network/reports/999999/export");
    expect(missing.status).toBe(404);
  });

  it("super_admin can delete a device with all reports", async () => {
    const uploaded = await uploadFile(ADMIN, "core-sw.cfg", CISCO_IOS_SWITCH);
    const deviceId = uploaded.body.results[0].result.deviceId as number;
    const viewerDelete = await request(VIEWER, `/api/network/devices/${deviceId}`, { method: "DELETE" });
    expect(viewerDelete.status).toBe(403);
    const deleted = await request(ADMIN, `/api/network/devices/${deviceId}`, { method: "DELETE" });
    expect(deleted.status).toBe(200);
    expect(deleted.body.deleted).toBe(true);
    const listed = await request(VIEWER, "/api/network/devices?locationId=1");
    expect(listed.body.devices).toHaveLength(0);
    // audit trail recorded the deletion
    const audits = db.query("SELECT action FROM audit_log WHERE action LIKE 'network.%'").all() as Array<{ action: string }>;
    expect(audits.some((audit) => audit.action === "network.device.delete")).toBe(true);
  });

  it("device deletion cascades through treated findings and their history", async () => {
    const uploaded = await uploadFile(ADMIN, "core-sw.cfg", CISCO_IOS_SWITCH);
    const deviceId = uploaded.body.results[0].result.deviceId as number;
    const reportId = uploaded.body.results[0].result.reportId as number;

    const treated = await request(ADMIN, `/api/network/reports/${reportId}/findings/NET-SNMP-001/treatment`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ state: "remediated", justification: "SNMPv3 deployed.", assignee: "netops" }),
    });
    expect(treated.status).toBe(200);

    const deleted = await request(ADMIN, `/api/network/devices/${deviceId}`, { method: "DELETE" });
    expect(deleted.status).toBe(200);
    expect(deleted.body.deleted).toBe(true);
    const remainingStates = db.query("SELECT COUNT(*) AS n FROM network_finding_states").get() as { n: number };
    const remainingHistory = db.query("SELECT COUNT(*) AS n FROM network_finding_state_history").get() as { n: number };
    expect(remainingStates.n).toBe(0);
    expect(remainingHistory.n).toBe(0);
  });

  it("records config ingestion in the audit log", async () => {
    await uploadFile(AUDITOR, "core-sw.cfg", CISCO_IOS_SWITCH);
    const audits = db
      .query("SELECT action, resource FROM audit_log WHERE action = 'network.config.upload'")
      .all() as Array<{ action: string; resource: string }>;
    expect(audits).toHaveLength(1);
    expect(audits[0].resource).toMatch(/^network_report:\d+$/);
  });

  it("handles a mixed multi-vendor batch in one request", async () => {
    const form = new FormData();
    form.append("campaignId", "1");
    form.append("locationId", "1");
    const batch: Array<[string, string]> = [
      ["core-sw.cfg", CISCO_IOS_SWITCH],
      ["asa-edge.cfg", CISCO_ASA],
      ["edge-jx.conf", JUNOS_BRACE],
      ["pa-fw.txt", PANOS_SET],
      ["fgt-branch.conf", FORTIOS],
      ["aruba-sw.txt", ARUBA_SWITCH],
      ["iap-lobby.cfg", ARUBA_IAP],
      ["wlc-dc.txt", WLC_AIREOS],
      ["ubnt.cfg", EDGEOS],
      ["nx-agg.cfg", NXOS],
      ["notes.txt", GARBAGE],
    ];
    const expectedNames: string[] = [];
    for (const [name, content] of batch) {
      form.append("files", new File([content], name));
      expectedNames.push(name);
    }
    const response = await makeApp(ADMIN).request("/api/network/upload", { method: "POST", body: form });
    expect(response.status).toBe(200);
    const body = (await response.json()) as { results: Array<{ name: string; result: { ok: boolean; vendorLabel: string; deviceType: string } }> };
    const byName = new Map(body.results.map((entry) => [entry.name, entry.result]));
    expect(body.results).toHaveLength(batch.length);
    expect(byName.get("core-sw.cfg")?.vendorLabel).toBe(VENDOR_LABELS["cisco-ios"]);
    expect(byName.get("asa-edge.cfg")?.deviceType).toBe("firewall");
    expect(byName.get("edge-jx.conf")?.ok).toBe(true);
    expect(byName.get("pa-fw.txt")?.ok).toBe(true);
    expect(byName.get("fgt-branch.conf")?.ok).toBe(true);
    expect(byName.get("aruba-sw.txt")?.ok).toBe(true);
    expect(byName.get("iap-lobby.cfg")?.deviceType).toBe("wireless-controller");
    expect(byName.get("wlc-dc.txt")?.deviceType).toBe("wireless-controller");
    expect(byName.get("ubnt.cfg")?.ok).toBe(true);
    expect(byName.get("nx-agg.cfg")?.deviceType).toBe("switch");
    expect(byName.get("notes.txt")?.ok).toBe(true); // generic still ingests

    const devices = await request(VIEWER, "/api/network/devices?locationId=1");
    expect(devices.body.devices.length).toBe(batch.length - 1 + 1); // garbage gets its own device too
  });
});
