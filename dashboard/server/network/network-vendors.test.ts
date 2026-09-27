// Compatibility suite: full, realistic running-config exports for every
// supported platform. Each fixture is a faithful reconstruction of the
// vendor's documented export syntax (CLI running-config, set-mode export,
// .rsc export, clish `show configuration`, or XML backup) and asserts the
// parsed identity, inventory, and hardening-relevant fields, then runs the
// review engine over it. Real production configs must parse like these.
//
// Discovered-vendor notes:
//   * Sophos SFOS has no plaintext full-config export (backups are encrypted;
//     the import/export path produces Entities.xml). We parse Entities.xml.
//   * WatchGuard Fireware XML backups are schema-proprietary; detection is
//     best-effort and the profile may stay sparse.

import { describe, expect, it } from "bun:test";
import { detectVendor, parseNetworkConfig, redactConfigText } from "./config-parser";
import { reviewConfig } from "./review";

function parse(text: string, filename = ""): ReturnType<typeof parseNetworkConfig>["profile"] {
  return parseNetworkConfig(text, filename).profile;
}

function linesOf(text: string): Array<{ n: number; text: string; lower: string }> {
  return text.split(/\r?\n/).map((line, index) => ({ n: index + 1, text: line.trim(), lower: line.toLowerCase() }));
}

// ---------------------------------------------------------------------------
// Cisco IOS (full branch switch)
// ---------------------------------------------------------------------------

const IOS_FULL = `
!RAM Device configuration for core-sw-01
!
version 15.2(4)E7
service timestamps debug datetime msec localtime show-timezone
service timestamps log datetime msec localtime show-timezone
no service password-encryption
service password-recovery
!
hostname core-sw-01
!
enable secret 9 $9$OpaqueSalt$OpaqueValueHash
!
username netops secret 9 $9$OpaqueSalt2$OpaqueValueHash2
username backup privilege 1 password 7 08224F40081A0A0602
!
aaa new-model
aaa authentication login default group tacacs+ local
aaa authorization commands 15 default group tacacs+ local
!
ip domain-name hq.example.net
ip name-server 10.10.0.53 10.10.0.54
!
login block-for 120 attempts 3 within 60
!
crypto key generate rsa modulus 4096
ip ssh version 2
ip ssh dh min size 4096
ip ssh server algorithm encryption aes256-gcm aes128-gcm
!
no ip http server
no ip http secure-server
!
snmp-server group MONITOR v3 priv
snmp-server user netops MONITOR v3 auth sha priv aes 128
snmp-server contact network@example.net
!
logging buffered 64000 informational
logging host 10.10.0.20
service timestamps log datetime msec localtime show-timezone
!
archive
 log config
  logging enable
!
control-plane
 service-policy input COPP-POLICY
!
ntp server 10.10.0.30 prefer
ntp authenticate
ntp authentication-key 1 md5 08224F4008 7
!
ip dhcp snooping
ip dhcp snooping vlan 10,20,99
no ip dhcp snooping information option
!
spanning-tree mode rapid-pvst
spanning-tree portfast default
spanning-tree bpduguard default
!
vlan 10
 name USERS
vlan 20
 name PRINTERS
vlan 99
 name MGMT
!
interface GigabitEthernet1/0/1
 description AP-Lobby
 switchport mode trunk
 switchport trunk native vlan 99
 switchport trunk allowed vlan 10,20,99
!
interface GigabitEthernet1/0/2
 description USER-PORT
 switchport mode access
 switchport access vlan 10
 storm-control broadcast level 5.00
!
interface Vlan99
 description MGMT
 ip address 10.99.0.2 255.255.255.0
 no ip route-cache
!
interface GigabitEthernet1/1/1
 description UPLINK-CORE
 switchport mode trunk
!
line con 0
 exec-timeout 10 0
line vty 0 4
 access-class MGMT-HOSTS in
 exec-timeout 10 0
 transport input ssh
!
banner motd ^C Authorized access only. All activity is monitored. ^C
!
end`.trim();

describe("Cisco IOS full config", () => {
  it("parses identity, inventory, and hardening features", () => {
    const profile = parse(IOS_FULL, "core-sw-01.cfg");
    expect(profile.vendor).toBe("cisco-ios");
    expect(profile.hostname).toBe("core-sw-01");
    expect(profile.osVersion).toBe("15.2(4)E7");
    expect(profile.deviceType).toBe("switch");
    expect(profile.vlans.map((vlan) => vlan.id)).toEqual(["10", "20", "99"]);
    expect(profile.users).toHaveLength(2);
    expect(profile.aaa.newModel).toBe(true);
    expect(profile.aaa.tacacsHosts.length).toBe(0); // method list references, not servers
    expect(profile.management.sshVersion).toBe("2");
    expect(profile.management.sshDhMinSize).toBe(4096);
    expect(profile.management.sshCiphers).toContain("aes256-gcm");
    expect(profile.management.telnetEnabled).toBe(false);
    expect(profile.management.httpEnabled).toBe(false);
    expect(profile.management.vtyAcl).toBe("MGMT-HOSTS");
    expect(profile.management.loginBlockFor).toBeTruthy();
    expect(profile.snmp.v3Configured).toBe(true);
    expect(profile.snmp.communities).toHaveLength(0);
    expect(profile.logging.hosts).toContain("10.10.0.20");
    expect(profile.ntp.servers).toContain("10.10.0.30");
    // services captured from the full config
    const service = (name: string) => profile.services.find((entry) => entry.name === name);
    expect(service("config archive")?.enabled).toBe(true);
    expect(service("control plane protection (CoPP)")?.enabled).toBe(true);
    expect(service("dhcp snooping")?.enabled).toBe(true);
    expect(service("global bpduguard")?.enabled).toBe(true);
    expect(service("global portfast")?.enabled).toBe(true);
  });

  it("reviews a hardened full config with compliant key decisions", () => {
    const profile = parse(IOS_FULL, "core-sw-01.cfg");
    const { findings, score } = reviewConfig(profile, linesOf(IOS_FULL));
    const byId = new Map(findings.map((finding) => [finding.checkId, finding]));
    expect(byId.get("NET-MGMT-001")?.status).toBe("Compliant");
    expect(byId.get("NET-MGMT-002")?.status).toBe("Compliant");
    expect(byId.get("NET-MGMT-003")?.status).toBe("Compliant");
    expect(byId.get("NET-MGMT-005")?.status).toBe("Compliant");
    expect(byId.get("NET-SNMP-002")?.status).toBe("Compliant");
    expect(byId.get("NET-SNMP-003")?.status).toBe("Compliant");
    expect(byId.get("NET-LOG-001")?.status).toBe("Compliant");
    expect(byId.get("NET-SVC-004")?.status).toBe("Compliant");
    expect(byId.get("NET-MGMT-013")?.status).toBe("Compliant");
    expect(byId.get("NET-LOG-003")?.status).toBe("Compliant");
    expect(byId.get("NET-SW-001")?.status).toBe("Compliant");
    expect(byId.get("NET-SW-007")?.status).toBe("Compliant");
    // AUTH-004 flags the surviving type-5-less MD5 key / AUTH-003 the type-7 backup user
    expect(byId.get("NET-AUTH-003")?.status).toBe("NonCompliant");
    expect(score).toBeGreaterThan(70);
  });
});

// ---------------------------------------------------------------------------
// Cisco NX-OS
// ---------------------------------------------------------------------------

const NXOS_FULL = `
!Command: show running-config
!Time: Tue Sep 22 10:11:12 2026
version 9.3(10) Bios:version(05.42)
hostname agg-nx-01
feature telnet
feature ospf
feature bgp
username admin password 5 $5$opaque$hash  role network-admin
username svc-backup password 5 $5$opaque2$hash2 role network-operator
ip domain-name dc.example.net
ssh key rsa 4096
ssh login-attempts 3
ip access-list MGMT-ACL
  10 permit ip 10.20.0.0/24 any
  20 deny ip any any
line vty
  exec-timeout 15
  access-class MGMT-ACL in
feature telnet
no feature telnet
snmp-server community public group network-operator
snmp-server user netops MONITOR v3 auth sha priv aes-128
logging server 10.20.0.20 6 use-vrf management
ntp server 10.20.0.30 use-vrf management
vlan 1,10,20
interface Ethernet1/1
  description UPLINK
  no switchport
  ip address 10.0.12.2/30
  ip router ospf 1 area 0.0.0.0
interface mgmt0
  ip address 10.20.0.11/24
router ospf 1
  router-id 10.0.12.2
  authentication message-digest
end`.trim();

describe("Cisco NX-OS full config", () => {
  it("parses identity, features, and vty hardening", () => {
    const profile = parse(NXOS_FULL, "agg-nx-01.cfg");
    expect(profile.vendor).toBe("cisco-nxos");
    expect(profile.hostname).toBe("agg-nx-01");
    expect(profile.osVersion).toBe("9.3(10)");
    expect(profile.deviceType).toBe("switch");
    expect(profile.management.telnetEnabled).toBe(false);
    expect(profile.management.sshEnabled).toBe(true);
    expect(profile.management.vtyAcl).toBe("MGMT-ACL");
    expect(profile.snmp.communities[0]?.value).toBe("public");
    expect(profile.snmp.v3Configured).toBe(true);
    expect(profile.users.length).toBeGreaterThanOrEqual(2);
    expect(profile.routingProtocols[0]?.protocol).toBe("ospf");
    expect(profile.logging.hosts).toContain("10.20.0.20");
  });

  it("flags the public community and the plaintext-service exposure", () => {
    const profile = parse(NXOS_FULL, "agg-nx-01.cfg");
    const { findings } = reviewConfig(profile, linesOf(NXOS_FULL));
    const byId = new Map(findings.map((finding) => [finding.checkId, finding]));
    expect(byId.get("NET-SNMP-004")?.status).toBe("NonCompliant");
    expect(byId.get("NET-SNMP-003")?.status).toBe("Compliant");
    expect(byId.get("NET-ROUT-001")?.status).toBe("Compliant");
  });
});

// ---------------------------------------------------------------------------
// Cisco ASA
// ---------------------------------------------------------------------------

const ASA_FULL = `
: Saved
: Hardware: ASAv, 2048 MB RAM, CPU Xeon E5 series 2 GHz
ASA Version 9.16(3)55
!
hostname edge-asav
domain-name example.net
enable password $sha512$5000$Opaque$Value pbkdf2
passwd 2KFQnbNIdI.2KYOU encrypted
names
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
boot system disk0:/asa916-55-smp-k8.SPA
aaa-server TACACS protocol tacacs+
aaa authentication ssh console TACACS LOCAL
aaa authentication enable console TACACS LOCAL
snmp-server host inside 192.168.10.20 community ***** version 2c
snmp-server enable traps syslog
logging enable
logging host inside 192.168.10.20
logging timestamp
!
crypto ikev1 policy 10
 authentication pre-share
 encryption 3des
 hash md5
 group 2
!
crypto ikev1 enable outside
!
telnet 192.168.10.0 255.255.255.0 inside
ssh 192.168.10.0 255.255.255.0 inside
ssh version 2
http server enable
http 192.168.10.0 255.255.255.0 inside
!
class-map inspection_default
 match default-inspection-traffic
!
policy-map global_policy
 class inspection_default
  inspect dns preset_dns_map
!
service-policy global_policy global
!
banner motd Authorized access only
: end`.trim();

describe("Cisco ASA full config", () => {
  it("parses interfaces, AAA, VPN proposals, and management exposure", () => {
    const profile = parse(ASA_FULL, "edge-asav.cfg");
    expect(profile.vendor).toBe("cisco-asa");
    expect(profile.hostname).toBe("edge-asav");
    expect(profile.osVersion).toBe("9.16(3)55");
    expect(profile.deviceType).toBe("firewall");
    expect(profile.interfaces.map((iface) => iface.nameif)).toEqual(["outside", "inside"]);
    expect(profile.interfaces[0]?.securityLevel).toBe(0);
    expect(profile.management.telnetEnabled).toBe(true);
    expect(profile.management.sshVersion).toBe("2");
    expect(profile.management.mgmtHosts.some((entry) => entry.startsWith("192.168.10.0"))).toBe(true);
    expect(profile.snmp.enabled).toBe(true);
    expect(profile.logging.hosts).toContain("192.168.10.20");
    expect(profile.vpns[0]?.encryption).toContain("3des");
    expect(profile.vpns[0]?.auth).toContain("md5");
    expect(profile.vpns[0]?.preSharedKey).toBe(true);
  });

  it("flags weak VPN crypto; telnet is inside-only", () => {
    const profile = parse(ASA_FULL, "edge-asav.cfg");
    const { findings } = reviewConfig(profile, linesOf(ASA_FULL));
    const byId = new Map(findings.map((finding) => [finding.checkId, finding]));
    expect(byId.get("NET-VPN-001")?.status).toBe("NonCompliant");
    expect(byId.get("NET-MGMT-001")?.status).toBe("NonCompliant");
    // telnet is allowed from the inside interface only - no WAN exposure
    expect(byId.get("NET-FW-005")?.status).toBe("Compliant");
  });
});

// ---------------------------------------------------------------------------
// Juniper Junos (set-mode, the standard export format)
// ---------------------------------------------------------------------------

const JUNOS_SET_FULL = `
## Last commit: 2026-09-20 08:00:00 UTC by netops
version 22.4R3-S4.9;
system {
    host-name edge-srx;
    time-zone UTC;
    root-authentication {
        encrypted-password "$6$OpaqueRound$OpaqueHashValueHere"; ## SECRET-DATA
    }
    login {
        user netops {
            uid 2001;
            class super-user;
            authentication {
                encrypted-password "$6$Opaque2$AnotherHashValue"; ## SECRET-DATA
            }
        }
    }
    services {
        ssh {
            protocol-version v2;
            root-login deny;
            connection-limit-limit 10;
        }
        telnet;
        web-management {
            https {
                system-generated-certificate;
            }
        }
    }
    syslog {
        host 10.30.0.20 {
            any any;
        }
    }
    ntp {
        server 10.30.0.30;
    }
}
interfaces {
    ge-0/0/0 {
        description UPLINK-ISP;
        unit 0 {
            family inet {
                address 198.51.100.2/30;
            }
        }
    }
    ge-0/0/1 {
        description INSIDE;
        unit 0 {
            family inet {
                address 192.168.20.1/24;
            }
        }
    }
}
routing-options {
    static {
        route 0.0.0.0/0 next-hop 198.51.100.1;
    }
}
security {
    policies {
        from-zone trust to-zone untrust {
            policy permit-outbound {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    permit;
                }
            }
        }
    }
    zones {
        security-zone trust {
            interfaces {
                ge-0/0/1.0;
            }
        }
    }
}
snmp {
    community public {
        authorization read-only;
    }
}
`.trim();

describe("Juniper Junos set/hierarchical export", () => {
  it("parses identity, users, services, and policies", () => {
    const profile = parse(JUNOS_SET_FULL, "edge-srx.conf");
    expect(profile.vendor).toBe("juniper-junos");
    expect(profile.hostname).toBe("edge-srx");
    expect(profile.osVersion).toBe("22.4R3-S4.9");
    expect(profile.interfaces.length).toBeGreaterThanOrEqual(2);
    expect(profile.management.telnetEnabled).toBe(true);
    expect(profile.management.sshEnabled).toBe(true);
    expect(profile.snmp.communities.some((community) => community.value === "public")).toBe(true);
    expect(profile.staticRoutes.length).toBeGreaterThanOrEqual(1);
    expect(profile.logging.hosts).toContain("10.30.0.20");
    expect(profile.ntp.servers).toContain("10.30.0.30");
  });

  it("flags telnet, default community, and root-auth state", () => {
    const profile = parse(JUNOS_SET_FULL, "edge-srx.conf");
    const { findings } = reviewConfig(profile, linesOf(JUNOS_SET_FULL));
    const byId = new Map(findings.map((finding) => [finding.checkId, finding]));
    expect(byId.get("NET-MGMT-001")?.status).toBe("NonCompliant");
    expect(byId.get("NET-SNMP-004")?.status).toBe("NonCompliant");
    expect(byId.get("NET-SNMP-002")?.status).toBe("NonCompliant");
  });
});

// ---------------------------------------------------------------------------
// Palo Alto PAN-OS (set-mode)
// ---------------------------------------------------------------------------

const PANOS_SET_FULL = `
set deviceconfig system hostname pa-edge
set deviceconfig system ip-address 192.168.30.10 netmask 255.255.255.0
set deviceconfig system ntp-servers primary-ntp-server ntp-server-address 10.40.0.30
set deviceconfig system syslog server1 server 10.40.0.20
set deviceconfig system service disable-telnet yes
set deviceconfig system service disable-http yes
set deviceconfig setting management admin-lockout failed-attempts 5 lockout-time 30
set mgt-config users admin phash $1$Opaque$HashValue
set mgt-config users netops phash $1$Opaque2$HashValue2
set network interface ethernet ethernet1/1 layer3 ip 203.0.113.1/29
set network interface ethernet ethernet1/2 layer3 ip 192.168.40.1/24
set rulebase security rules rule-outbound from untrust to any source any destination any service any action deny
set rulebase security rules rule-web from untrust to dmz source any destination web-srv service https action allow
set rulebase security rules rule1 from any to any source any destination any service any action allow
set shared service-group svc-web members https
`.trim();

describe("Palo Alto PAN-OS set export", () => {
  it("parses identity, hardening flags, and firewall rules", () => {
    const profile = parse(PANOS_SET_FULL, "pa-edge.cfg");
    expect(profile.vendor).toBe("palo-alto");
    expect(profile.hostname).toBe("pa-edge");
    expect(profile.deviceType).toBe("firewall");
    expect(profile.management.telnetEnabled).toBe(false);
    expect(profile.management.httpEnabled).toBe(false);
    expect(profile.management.loginBlockFor).toBeTruthy();
    expect(profile.firewallRules.length).toBe(3);
  });

  it("flags the any/any allow rule with masked evidence", () => {
    const profile = parse(PANOS_SET_FULL, "pa-edge.cfg");
    const { findings } = reviewConfig(profile, linesOf(PANOS_SET_FULL));
    const byId = new Map(findings.map((finding) => [finding.checkId, finding]));
    const fw1 = byId.get("NET-FW-001");
    expect(fw1?.status).toBe("NonCompliant");
    expect(fw1?.evidence.some((entry) => entry.includes("rule1"))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Fortinet FortiOS (nested blocks)
// ---------------------------------------------------------------------------

const FORTIOS_FULL = `
#config-version=FGT80F-7.4.4-FW-build2697-240215-openssl-3.0
config system global
    set hostname fgt-branch
    set admin-sport 8443
    set admintimeout 10
end
config system admin
    edit "netops"
        set accprofile "super_admin"
        set password ENC SH2$OpaqueCipherTextHere
    next
    edit "auditor"
        set accprofile "read-only"
        set password ENC SH2$OpaqueCipherText2
    next
end
config system interface
    edit "port1"
        set vdom "root"
        set mode static
        set ip 203.0.113.1 255.255.255.248
        set allowaccess ping
        set role wan
    next
    edit "port2"
        set vdom "root"
        set mode static
        set ip 192.168.50.1 255.255.255.0
        set allowaccess ping https ssh
        set role lan
    next
end
config system ntp
    set ntpsync enable
    set server "10.50.0.30"
end
config log syslogd setting
    set status enable
    set server "10.50.0.20"
end
config firewall policy
    edit 1
        set name "LAN-to-WAN"
        set srcintf "port2"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set logtraffic all
    next
    edit 2
        set name "WAN-to-LAN-HTTPS"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "web-srv"
        set action accept
        set schedule "always"
        set service "HTTPS"
        set logtraffic utm
    next
end
config vpn ipsec phase1-interface
    edit "VPN-HUB"
        set interface "port1"
        set proposal aes256-sha256
        set type static
        set remote-gw 198.51.100.9
        set psksecret ENC SH2$OpaquePsk
    next
end
`.trim();

describe("Fortinet FortiOS nested export", () => {
  it("parses identity, admins, policies, and VPN", () => {
    const profile = parse(FORTIOS_FULL, "fgt-branch.conf");
    expect(profile.vendor).toBe("fortinet");
    expect(profile.hostname).toBe("fgt-branch");
    expect(profile.osVersion).toBe("7.4.4");
    expect(profile.model).toBe("FGT80F");
    expect(profile.deviceType).toBe("firewall");
    expect(profile.users).toHaveLength(2);
    expect(profile.firewallRules.length).toBe(2);
    expect(profile.vpns[0]?.encryption).toContain("aes256-sha256");
    expect(profile.logging.hosts).toContain("10.50.0.20");
    expect(profile.ntp.servers).toContain("10.50.0.30");
    expect(profile.management.allowAccess.some((entry) => entry.startsWith("port1:"))).toBe(true);
  });

  it("evaluates WAN exposure and LAN-to-WAN policy", () => {
    const profile = parse(FORTIOS_FULL, "fgt-branch.conf");
    const { findings } = reviewConfig(profile, linesOf(FORTIOS_FULL));
    const byId = new Map(findings.map((finding) => [finding.checkId, finding]));
    expect(byId.get("NET-FW-005")?.status).toBe("Compliant");
    // no telnet anywhere in the allowaccess lists
    expect(byId.get("NET-MGMT-001")?.status).toBe("NotApplicable");
  });
});

// ---------------------------------------------------------------------------
// Arista EOS
// ---------------------------------------------------------------------------

const ARISTA_EOS_FULL = `
! device: leaf-sw-01 (DCS-7050SX3-48YC8, EOS-4.29.4M)
!
hostname leaf-sw-01
!
snmp-server view systemiso iso iso
snmp-server group MONITOR v3 priv read systemiso
!
aaa authentication login default group tacacs+ local
aaa authorization exec default group tacacs+ local
!
username netops secret sha512 $6$OpaqueSalt$OpaqueHashValue
username backup secret 5 $1$Salt$HashValue
!
management api http-commands
   no shutdown
!
interface Management1
   ip address 10.60.0.11/24
!
interface Ethernet1
   description UPLINK-SPINE
   no switchport
   ip address 10.0.61.1/31
!
interface Ethernet5
   description HOST-PORT
   switchport mode access
   switchport access vlan 10
   spanning-tree portfast
   spanning-tree bpduguard enable
!
ip routing
!
ip route 0.0.0.0/0 10.0.61.0
!
ntp server 10.60.0.30 iburst
logging host 10.60.0.20
!
line vty
   exec-timeout 10 0
   access-class MGMT in
   transport input ssh
end`.trim();

describe("Arista EOS running-config", () => {
  it("detects and parses the EOS grammar", () => {
    const profile = parse(ARISTA_EOS_FULL, "leaf-sw-01.cfg");
    expect(profile.vendor).toBe("arista-eos");
    expect(profile.hostname).toBe("leaf-sw-01");
    expect(profile.deviceType).toBe("switch");
    expect(profile.management.telnetEnabled).toBe(false);
    expect(profile.management.httpsEnabled).toBe(true);
    expect(profile.snmp.v3Configured).toBe(true);
    expect(profile.logging.hosts).toContain("10.60.0.20");
    expect(profile.management.sshDhMinSize).toBeNull();
  });

  it("evaluates CDP and edge-port protection on EOS", () => {
    const profile = parse(ARISTA_EOS_FULL, "leaf-sw-01.cfg");
    const { findings } = reviewConfig(profile, linesOf(ARISTA_EOS_FULL));
    const byId = new Map(findings.map((finding) => [finding.checkId, finding]));
    expect(byId.get("NET-SVC-003")?.status).toBe("NonCompliant");
    expect(byId.get("NET-SW-007")?.status).toBe("Compliant");
    // Arista `secret 5` is legacy MD5 - must be migrated
    expect(byId.get("NET-AUTH-004")?.status).toBe("NonCompliant");
  });
});

// ---------------------------------------------------------------------------
// Huawei VRP
// ---------------------------------------------------------------------------

const HUAWEI_VRP_FULL = `
#
!Software Version V200R021C00SPC100
#
sysname hu-agg-sw
#
vlan batch 10 20 99
#
telnet server disable
#
stelnet server enable
#
http server disable
#
http secure-server enable
#
snmp-agent
snmp-agent community read cipher %^%#OpaqueSnmpCipher#%^%
snmp-agent group v3 netmonv3
snmp-agent usm-user v3 netops netmonv3
#
aaa
 authentication-scheme default
 local-user netops password irreversible-cipher $1d$Opaq$ueHash
 local-user netops privilege level 15
 local-user netops service-type ssh
#
info-center loghost 10.70.0.20
#
ntp-service unicast-server 10.70.0.30
ntp-service authentication enable
#
interface GigabitEthernet0/0/1
 description UPLINK
 port link-type trunk
 port trunk allow-pass vlan 10 20 99
#
interface GigabitEthernet0/0/2
 description HOST-PORT
 port link-type access
 port default vlan 10
#
interface Vlanif99
 ip address 10.99.99.2 255.255.255.0
#
ospf 1
 area 0.0.0.0
  authentication-mode md5 1 cipher %^%#OpaqueOspf#%^%
#
user-interface vty 0 4
 authentication-mode aaa
 protocol inbound ssh
#
return`.trim();

describe("Huawei VRP display current-configuration", () => {
  it("detects and parses the VRP grammar", () => {
    const profile = parse(HUAWEI_VRP_FULL, "hu-agg-sw.cfg");
    expect(profile.vendor).toBe("huawei-vrp");
    expect(profile.hostname).toBe("hu-agg-sw");
    expect(profile.osVersion).toBe("V200R021C00SPC100");
    expect(profile.deviceType).toBe("switch");
    expect(profile.vlans.map((vlan) => vlan.id)).toEqual(["10", "20", "99"]);
    expect(profile.management.telnetEnabled).toBe(false);
    expect(profile.management.sshEnabled).toBe(true);
    expect(profile.management.httpEnabled).toBe(false);
    expect(profile.snmp.v3Configured).toBe(true);
    expect(profile.logging.hosts).toContain("10.70.0.20");
    expect(profile.ntp.servers).toContain("10.70.0.30");
    expect(profile.ntp.authenticated).toBe(true);
    expect(profile.users[0]?.hashType).toContain("irreversible");
    expect(profile.routingProtocols[0]?.authConfigured).toBe(true);
  });

  it("reviews hardening across shared checks", () => {
    const profile = parse(HUAWEI_VRP_FULL, "hu-agg-sw.cfg");
    const { findings } = reviewConfig(profile, linesOf(HUAWEI_VRP_FULL));
    const byId = new Map(findings.map((finding) => [finding.checkId, finding]));
    expect(byId.get("NET-MGMT-001")?.status).toBe("Compliant");
    expect(byId.get("NET-MGMT-002")?.status).toBe("Compliant");
    expect(byId.get("NET-NTP-001")?.status).toBe("Compliant");
    expect(byId.get("NET-ROUT-001")?.status).toBe("Compliant");
  });
});

// ---------------------------------------------------------------------------
// Check Point GAiA (clish show configuration)
// ---------------------------------------------------------------------------

const GAIA_FULL = `
#
# Configuration of cp-gw
# Language version: 10.0v1
#
# Exported by admin on Mon Mar 19 15:06:22 2026
#
set hostname cp-gw
set timezone Etc/UTC
set password-controls min-password-length 12
set password-controls complexity 2
set password-controls history-checking true
set ntp active on
add ntp server address 10.80.0.30 type primary
set ntp authentication on
set snmp agent on
set snmp agent-version V3
set telnet-state off
set ssh server password-based-authentication on
set ssh server permit-root-login off
set web daemon-enable on
add syslog log-server splunk address 10.80.0.20
add rba user netops roles adminRole
set user netops password-hash $1$Round$SaltedHashValue
add interface eth0 ipv4-address 203.0.113.10 mask-length 29
set interface eth0 state on
add interface eth1 ipv4-address 172.16.10.1 mask-length 24
set interface eth1 state on
set static-route default nexthop gateway ip 203.0.113.9 on
set tacacs-server address 10.80.0.40 key-hashed $1d$Opaque
`.trim();

describe("Check Point GAiA clish export", () => {
  it("detects and parses clish set-commands", () => {
    const profile = parse(GAIA_FULL, "cp-gw.txt");
    expect(profile.vendor).toBe("checkpoint-gaia");
    expect(profile.hostname).toBe("cp-gw");
    expect(profile.deviceType).toBe("firewall");
    expect(profile.management.telnetEnabled).toBe(false);
    expect(profile.management.sshEnabled).toBe(true);
    expect(profile.management.httpsEnabled).toBe(true);
    expect(profile.management.minPasswordLength).toBe(12);
    expect(profile.snmp.enabled).toBe(true);
    expect(profile.snmp.v3Configured).toBe(true);
    expect(profile.ntp.servers).toContain("10.80.0.30");
    expect(profile.ntp.authenticated).toBe(true);
    expect(profile.logging.hosts).toContain("10.80.0.20");
    expect(profile.aaa.tacacsHosts).toContain("10.80.0.40");
    expect(profile.interfaces).toHaveLength(2);
    expect(profile.staticRoutes[0]?.destination).toContain("default");
    expect(profile.users.some((user) => user.name === "netops" && user.role === "admin")).toBe(true);
  });

  it("reviews GAiA hardening", () => {
    const profile = parse(GAIA_FULL, "cp-gw.txt");
    const { findings } = reviewConfig(profile, linesOf(GAIA_FULL));
    const byId = new Map(findings.map((finding) => [finding.checkId, finding]));
    expect(byId.get("NET-MGMT-001")?.status).toBe("Compliant");
    expect(byId.get("NET-MGMT-011")?.status).toBe("Compliant");
    expect(byId.get("NET-SNMP-002")?.status).toBe("Compliant");
    expect(byId.get("NET-NTP-001")?.status).toBe("Compliant");
  });
});

// ---------------------------------------------------------------------------
// MikroTik RouterOS (.rsc export)
// ---------------------------------------------------------------------------

const MIKROTIK_FULL = `
# 2026-09-21 12:00:00 by RouterOS 7.14.3
# software id = ABCD-1234
#
/system identity
set name=mt-core
/system note
set show-at-login=yes note="Authorized access only"
/system clock
set time-zone-name=UTC
/user
add name=netops password= group=full comment="ops admin"
add name=audit password= group=read
/user settings
set minimum-password-length=12
/ip service
set telnet disabled=yes
set ftp disabled=yes
set www disabled=yes
set ssh strong-crypto=yes
set www-ssl disabled=no
/snmp
set enabled=yes contact=noc@example.net
/snmp community
add name=netmon-ro read-access=yes
/system ntp client
set enabled=yes
/system ntp client servers
add address=10.90.0.30
/system logging action
add name=remote1 target=remote remote=10.90.0.20
/interface
set [ find default-name=ether1 ] name=ether-wan comment="ISP uplink"
/interface wireless security-profiles
add name=corp-wpa2 authentication-types=wpa2-eap
add name=guest-psk authentication-types=wpa2-psk wpa2-pre-shared-key=guestpass
/ip address
add address=203.0.113.6/29 interface=ether-wan
add address=192.168.60.1/24 interface=ether-lan
/ip ipsec proposal
add name=legacy-3des enc-algorithms=3des auth-algorithms=md5
/ip firewall filter
add chain=input action=accept protocol=tcp dst-port=22 comment="ssh in"
add chain=input action=accept
/ip route
add dst-address=0.0.0.0/0 gateway=203.0.113.1
/radius
add address=10.90.0.40 service=login
`.trim();

describe("MikroTik RouterOS .rsc export", () => {
  it("detects and parses the export grammar", () => {
    const profile = parse(MIKROTIK_FULL, "mt-core.rsc");
    expect(profile.vendor).toBe("mikrotik-routeros");
    expect(profile.hostname).toBe("mt-core");
    expect(profile.osVersion).toBe("7.14.3");
    expect(profile.deviceType).toBe("router");
    expect(profile.management.telnetEnabled).toBe(false);
    expect(profile.management.sshEnabled).toBe(true);
    expect(profile.management.httpEnabled).toBe(false);
    expect(profile.management.minPasswordLength).toBe(12);
    expect(profile.snmp.enabled).toBe(true);
    expect(profile.snmp.communities[0]?.value).toBe("netmon-ro");
    expect(profile.ntp.servers).toContain("10.90.0.30");
    expect(profile.logging.hosts).toContain("10.90.0.20");
    expect(profile.users).toHaveLength(2);
    expect(profile.wirelessLans.map((wlan) => wlan.authMode)).toContain("wpa2-eap");
    expect(profile.wirelessLans.some((wlan) => wlan.psk)).toBe(true);
    expect(profile.vpns[0]?.encryption).toContain("3des");
    expect(profile.firewallRules.length).toBe(2);
    expect(profile.aaa.radiusHosts).toContain("10.90.0.40");
    expect(profile.banners[0]?.text).toContain("Authorized access only");
  });

  it("flags the legacy 3des proposal and the open input rule", () => {
    const profile = parse(MIKROTIK_FULL, "mt-core.rsc");
    const { findings } = reviewConfig(profile, linesOf(MIKROTIK_FULL));
    const byId = new Map(findings.map((finding) => [finding.checkId, finding]));
    expect(byId.get("NET-VPN-001")?.status).toBe("NonCompliant");
    expect(byId.get("NET-FW-001")?.status).toBe("NonCompliant");
    expect(byId.get("NET-WIFI-003")?.status).toBe("NonCompliant");
  });
});

// ---------------------------------------------------------------------------
// pfSense / OPNsense (config.xml)
// ---------------------------------------------------------------------------

const PFSENSE_XML = `<?xml version="1.0"?>
<pfsense>
	<version>23.09.1</version>
	<lastchange>2026-09-01</lastchange>
	<system>
		<hostname>pfsense-edge</hostname>
		<domain>lab.example.net</domain>
		<timezone>Etc/UTC</timezone>
		<timeservers>10.95.0.30</timeservers>
		<webgui>
			<protocol>https</protocol>
		</webgui>
		<ssh>
			<enable/>
		</ssh>
		<user>
			<name>admin</name>
			<scope>system</scope>
			<bcrypt-hash>$2b$10$OpaqueBcryptHashValue</bcrypt-hash>
		</user>
		<user>
			<name>netops</name>
			<scope>user</scope>
			<bcrypt-hash>$2b$10$OpaqueBcryptHashValue2</bcrypt-hash>
		</user>
	</system>
	<interfaces>
		<wan>
			<descr>wan</descr>
			<if>igb0</if>
			<ipaddr>203.0.113.10/29</ipaddr>
		</wan>
		<lan>
			<descr>lan</descr>
			<if>igb1</if>
			<ipaddr>192.168.70.1/24</ipaddr>
		</lan>
		<opt1>
			<descr>DMZ</descr>
			<if>igb2</if>
			<ipaddr>192.168.80.1/24</ipaddr>
		</opt1>
	</interfaces>
	<snmpd>
		<enable/>
		<rocommunity>pfmon</rocommunity>
	</snmpd>
	<filter>
		<rule>
			<type>pass</type>
			<interface>wan</interface>
			<descr>Allow HTTPS to web</descr>
			<source><any/></source>
			<destination><address>192.168.80.10</address><port>443</port></destination>
			<log/>
			<tracker>0100000101</tracker>
		</rule>
		<rule>
			<type>pass</type>
			<interface>wan</interface>
			<source><any/></source>
			<destination><any/></destination>
			<tracker>0100000102</tracker>
		</rule>
	</filter>
</pfsense>`.trim();

describe("pfSense config.xml", () => {
  it("parses identity, users, interfaces, and filter rules", () => {
    const profile = parse(PFSENSE_XML, "config-pfsense.xml");
    expect(profile.vendor).toBe("pfsense");
    expect(profile.hostname).toBe("pfsense-edge");
    expect(profile.osVersion).toBe("23.09.1");
    expect(profile.deviceType).toBe("firewall");
    expect(profile.management.sshEnabled).toBe(true);
    expect(profile.management.httpsEnabled).toBe(true);
    expect(profile.snmp.enabled).toBe(true);
    expect(profile.snmp.communities[0]?.value).toBe("pfmon");
    expect(profile.ntp.servers).toContain("10.95.0.30");
    expect(profile.users).toHaveLength(2);
    expect(profile.users[0]?.hashType).toContain("BCRYPT");
    expect(profile.interfaces.length).toBeGreaterThanOrEqual(2);
    expect(profile.firewallRules.length).toBe(2);
  });

  it("flags the any/any WAN pass rule", () => {
    const profile = parse(PFSENSE_XML, "config-pfsense.xml");
    const { findings } = reviewConfig(profile, linesOf(PFSENSE_XML));
    const byId = new Map(findings.map((finding) => [finding.checkId, finding]));
    expect(byId.get("NET-FW-001")?.status).toBe("NonCompliant");
  });
});

const OPNSENSE_XML = `<?xml version="1.0"?>
<opnsense>
	<version>24.7</version>
	<system>
		<hostname>opn-edge</hostname>
		<domain>lab.example.net</domain>
		<timezone>Etc/UTC</timezone>
		<user>
			<name>root</name>
			<password-hash>$2y$10$OpaqueBcrypt</password-hash>
		</user>
	</system>
	<interfaces>
		<wan><descr>wan</descr><if>vtnet0</if><ipaddr>198.51.100.10/30</ipaddr></wan>
		<lan><descr>lan</descr><if>vtnet1</if><ipaddr>10.100.0.1/24</ipaddr></lan>
	</interfaces>
	<syslog>
		<remote>10.100.0.20</remote>
	</syslog>
	<filter>
		<rule>
			<action>pass</action>
			<interface>lan</interface>
			<description>LAN out</description>
			<source><any/></source>
			<destination><any/></destination>
		</rule>
	</filter>
</opnsense>`.trim();

describe("OPNsense config.xml", () => {
  it("parses identity and rules", () => {
    const profile = parse(OPNSENSE_XML, "config-opnsense.xml");
    expect(profile.vendor).toBe("opnsense");
    expect(profile.hostname).toBe("opn-edge");
    expect(profile.deviceType).toBe("firewall");
    expect(profile.logging.hosts).toContain("10.100.0.20");
    expect(profile.firewallRules.length).toBe(1);
    expect(profile.users[0]?.hashType).toContain("BCRYPT");
  });
});

// ---------------------------------------------------------------------------
// Sophos SFOS (Entities.xml from selective export)
// ---------------------------------------------------------------------------

const SOPHOS_XML = `<?xml version="1.0" encoding="UTF-8"?>
<Entities>
	<FirewallRule transactionid="100">
		<Name>WAN to Web</Name>
		<Description>Published web server</Description>
		<IPFamily>IPv4</IPFamily>
		<PolicyType>Network</PolicyType>
		<Status>Enable</Status>
		<SourceZones><Zone>WAN</Zone></SourceZones>
		<DestinationZones><Zone>DMZ</Zone></DestinationZones>
		<SourceNetworks><Network>Any</Network></SourceNetworks>
		<DestinationNetworks><Network>web-srv</Network></DestinationNetworks>
		<Services><Service>HTTPS</Service></Services>
		<Action>Accept</Action>
		<EnableLogging>Enabled</EnableLogging>
	</FirewallRule>
	<FirewallRule transactionid="101">
		<Name>ANY-ANY</Name>
		<Description>Temporary wide open</Description>
		<IPFamily>IPv4</IPFamily>
		<PolicyType>Network</PolicyType>
		<Status>Enable</Status>
		<SourceZones><Zone>Any</Zone></SourceZones>
		<DestinationZones><Zone>Any</Zone></DestinationZones>
		<SourceNetworks><Network>Any</Network></SourceNetworks>
		<DestinationNetworks><Network>Any</Network></DestinationNetworks>
		<Services><Service>Any</Service></Services>
		<Action>Accept</Action>
		<EnableLogging>Disabled</EnableLogging>
	</FirewallRule>
	<IPHost transactionid="102">
		<Name>web-srv</Name>
		<IPFamily>IPv4</IPFamily>
		<HostType>IP</HostType>
		<IPAddress>10.10.20.10</IPAddress>
	</IPHost>
</Entities>`.trim();

describe("Sophos SFOS Entities.xml", () => {
  it("parses firewall rules from the selective export", () => {
    const profile = parse(SOPHOS_XML, "Entities.xml");
    expect(profile.vendor).toBe("sophos-sfos");
    expect(profile.deviceType).toBe("firewall");
    expect(profile.firewallRules).toHaveLength(2);
    const anyAny = profile.firewallRules.find((rule) => rule.name === "ANY-ANY");
    expect(anyAny?.source).toBe("Any");
    expect(anyAny?.action).toBe("accept");
  });

  it("flags the wide-open rule via NET-FW-001", () => {
    const profile = parse(SOPHOS_XML, "Entities.xml");
    const { findings } = reviewConfig(profile, linesOf(SOPHOS_XML));
    const byId = new Map(findings.map((finding) => [finding.checkId, finding]));
    expect(byId.get("NET-FW-001")?.status).toBe("NonCompliant");
  });
});

// ---------------------------------------------------------------------------
// Detection robustness
// ---------------------------------------------------------------------------

describe("vendor detection on full configs", () => {
  const fixtures: Array<[string, string]> = [
    ["cisco-ios", IOS_FULL],
    ["cisco-nxos", NXOS_FULL],
    ["cisco-asa", ASA_FULL],
    ["juniper-junos", JUNOS_SET_FULL],
    ["palo-alto", PANOS_SET_FULL],
    ["fortinet", FORTIOS_FULL],
    ["arista-eos", ARISTA_EOS_FULL],
    ["huawei-vrp", HUAWEI_VRP_FULL],
    ["checkpoint-gaia", GAIA_FULL],
    ["mikrotik-routeros", MIKROTIK_FULL],
    ["pfsense", PFSENSE_XML],
    ["opnsense", OPNSENSE_XML],
    ["sophos-sfos", SOPHOS_XML],
  ];

  it.each(fixtures)("detects %s", (expected, text) => {
    expect(detectVendor(text).vendor).toBe(expected as never);
  });

  it("never throws and always yields a review on every fixture", () => {
    for (const [, text] of fixtures) {
      const profile = parse(text, "device.cfg");
      const { findings } = reviewConfig(profile, linesOf(text));
      expect(findings.length).toBeGreaterThan(0);
      expect(findings.every((finding) => typeof finding.severity === "string")).toBe(true);
      // redaction never leaks FortiOS/MikroTik secrets
      const redacted = redactConfigText(text);
      expect(redacted).not.toMatch(/SH2\$/);
      expect(redacted).not.toContain("guestpass");
    }
  });
});
