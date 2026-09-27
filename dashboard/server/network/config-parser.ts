// Network device / firewall configuration parser.
//
// Accepts raw configuration text (running-config, startup-config, set-style
// exports, XML exports) from the major network platforms and normalizes it
// into a single `ParsedNetworkConfig` profile that the review engine and the
// dashboard UI consume.
//
// Design rules (mirroring the sealed-report pipeline):
//   * never throws â€” a malformed/unrecognized config degrades to `generic`;
//   * every array is bounded; every string is sanitized and size-bounded;
//   * secret values (passwords, PSKs, enable secrets, community strings used
//     as credentials) are NEVER stored in clear form. Only the hash/storage
//     type is kept, and evidence helpers mask offending values per line.

export type VendorId =
  | "cisco-ios"
  | "cisco-nxos"
  | "cisco-asa"
  | "cisco-wlc"
  | "cisco-wlc-iosxe"
  | "juniper-junos"
  | "palo-alto"
  | "fortinet"
  | "aruba-switch"
  | "arubaos"
  | "ubiquiti"
  | "f5"
  | "sonicwall"
  | "arista-eos"
  | "huawei-vrp"
  | "checkpoint-gaia"
  | "mikrotik-routeros"
  | "pfsense"
  | "opnsense"
  | "sophos-sfos"
  | "watchguard"
  | "generic";

export type DeviceType =
  | "firewall"
  | "router"
  | "switch"
  | "wireless-controller"
  | "load-balancer"
  | "unknown";

export type Severity = "Critical" | "High" | "Medium" | "Low" | "Informational";

// ---- bounds -----------------------------------------------------------------

export const MAX_CONFIG_BYTES = 4 * 1024 * 1024;
const MAX_LINES = 200_000;
const MAX_INTERFACES = 2_048;
const MAX_VLANS = 4_096;
const MAX_ROUTES = 2_048;
const MAX_ROUTING_PROTOCOLS = 64;
const MAX_USERS = 512;
const MAX_SECRETS = 256;
const MAX_ACLS = 512;
const MAX_ACL_RULES = 1_024;
const MAX_FW_RULES = 4_096;
const MAX_NAT_RULES = 4_096;
const MAX_VPNS = 512;
const MAX_WLANS = 256;
const MAX_BANNERS = 16;
const MAX_SERVICES = 256;
const MAX_STRING = 512;
const MAX_BANNER_TEXT = 2_048;

// ---- normalized profile ------------------------------------------------------

export type ParsedInterface = {
  name: string;
  line: number;
  description: string | null;
  ipAddress: string | null;
  adminEnabled: boolean | null;
  mode: "access" | "trunk" | "routed" | "l2" | "unknown";
  accessVlan: string | null;
  nativeVlan: string | null;
  allowedVlans: string | null;
  aclIn: string | null;
  aclOut: string | null;
  portSecurity: boolean | null;
  bpduGuard: boolean | null;
  portfast: boolean | null;
  stormControl: boolean | null;
  speedDuplex: string | null;
  nameif: string | null; // ASA
  securityLevel: number | null; // ASA
};

export type ParsedVlan = { id: string; name: string | null; line: number };
export type ParsedRoute = { destination: string; nextHop: string; line: number };
export type ParsedRoutingProtocol = { protocol: string; processId: string | null; networks: string[]; authConfigured: boolean | null; line: number };

export type ParsedUser = {
  name: string;
  role: string | null;
  hashType: string;
  line: number;
};

export type ParsedSecret = { purpose: string; hashType: string; line: number };

export type ParsedSnmpCommunity = {
  value: string;
  access: "ro" | "rw" | "unknown";
  acl: string | null;
  line: number;
};

export type ParsedSnmp = {
  enabled: boolean;
  communities: ParsedSnmpCommunity[];
  v3Configured: boolean;
  v3Users: string[];
  line: number | null;
};

export type ParsedNtp = { servers: string[]; authenticated: boolean | null; line: number | null };

export type ParsedLogging = {
  enabled: boolean | null;
  hosts: string[];
  buffered: boolean | null;
  timestamps: boolean | null;
  line: number | null;
};

export type ParsedAaa = {
  newModel: boolean | null;
  authenticationMethods: string[];
  tacacsHosts: string[];
  radiusHosts: string[];
  line: number | null;
};

export type ParsedManagement = {
  sshEnabled: boolean | null;
  sshVersion: string | null;
  telnetEnabled: boolean | null;
  httpEnabled: boolean | null;
  httpsEnabled: boolean | null;
  vtyAcl: string | null;
  vtyExecTimeout: string | null;
  consoleExecTimeout: string | null;
  loginBlockFor: string | null;
  minPasswordLength: number | null;
  mgmtHosts: string[];
  allowAccess: string[];
  /** `ip ssh dh min size` value (Cisco); below 2048 is weak. */
  sshDhMinSize: number | null;
  /** SSH cipher/MAC algorithm names when the config pins them. */
  sshCiphers: string[];
};

export type ParsedAclRule = { n: number; text: string; action: "permit" | "deny" | "other" };
export type ParsedAcl = {
  name: string;
  type: "standard" | "extended" | "unknown";
  appliedTo: string[];
  rules: ParsedAclRule[];
  line: number;
};

export type ParsedFirewallRule = {
  id: string;
  name: string | null;
  srcIntf: string | null;
  dstIntf: string | null;
  source: string | null;
  destination: string | null;
  service: string | null;
  action: string | null;
  log: boolean | null;
  line: number;
};

export type ParsedNatRule = { id: string | null; description: string; line: number };

export type ParsedVpn = {
  kind: "ipsec" | "ssl" | "unknown";
  name: string | null;
  encryption: string[];
  auth: string[];
  dhGroup: string | null;
  preSharedKey: boolean;
  aggressiveMode: boolean;
  line: number;
};

export type ParsedWlan = {
  ssid: string;
  profile: string | null;
  authMode: string;
  psk: boolean;
  line: number;
};

export type ParsedBanner = { kind: string; text: string; line: number };
export type ParsedService = { name: string; enabled: boolean; line: number };

export type ParsedNetworkConfig = {
  vendor: VendorId;
  vendorLabel: string;
  deviceType: DeviceType;
  hostname: string | null;
  model: string | null;
  osVersion: string | null;
  serial: string | null;
  uptime: string | null;
  configLines: number;
  interfaces: ParsedInterface[];
  vlans: ParsedVlan[];
  staticRoutes: ParsedRoute[];
  routingProtocols: ParsedRoutingProtocol[];
  users: ParsedUser[];
  secrets: ParsedSecret[];
  snmp: ParsedSnmp;
  ntp: ParsedNtp;
  logging: ParsedLogging;
  aaa: ParsedAaa;
  management: ParsedManagement;
  acls: ParsedAcl[];
  firewallRules: ParsedFirewallRule[];
  natRules: ParsedNatRule[];
  vpns: ParsedVpn[];
  wirelessLans: ParsedWlan[];
  banners: ParsedBanner[];
  services: ParsedService[];
};

// ---- small helpers ------------------------------------------------------------

function clean(value: string | null | undefined, max = MAX_STRING): string | null {
  if (typeof value !== "string") return null;
  // strip control characters, collapse whitespace
  const cleaned = value.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "").trim();
  if (!cleaned) return null;
  return cleaned.length > max ? cleaned.slice(0, max) : cleaned;
}

export type RawLine = { n: number; text: string; lower: string };

function toLines(text: string): RawLine[] {
  const raw = text.split(/\r\n|\r|\n/).slice(0, MAX_LINES);
  return raw.map((line, index) => {
    // Indented CLI sub-commands must match the anchored grammar, so every
    // line is normalized to a trimmed form (no parser relies on indentation).
    const trimmed = line.replace(/\t/g, "  ").trim();
    return { n: index + 1, text: trimmed, lower: trimmed.toLowerCase() };
  });
}

function pushBounded<T>(array: T[], item: T, max: number): void {
  if (array.length < max) array.push(item);
}

/** Secret hash/storage classification from a config token. */
export function classifyHash(token: string | null | undefined): string {
  const value = (token ?? "").trim();
  if (!value) return "unknown";
  if (/^\$1\$/.test(value)) return "MD5 crypt ($1$)";
  if (/^\$2[aby]\$/.test(value)) return "BCRYPT ($2)";
  if (/^\$5\$/.test(value)) return "SHA-256 crypt ($5$)";
  if (/^\$6\$/.test(value)) return "SHA-512 crypt ($6$)";
  if (/^\$8\$/.test(value)) return "PBKDF2 (type 8)";
  if (/^\$9\$/.test(value)) return "SCRYPT (type 9)";
  if (/^\$sha512\$/.test(value)) return "SHA-512 (hashed)";
  if (/^AES_256_GCM:/i.test(value)) return "AES-256-GCM encrypted";
  if (/^ENC\b/i.test(value)) return "vendor-encrypted";
  if (/^phash:/i.test(value)) return "PBKDF2 phash";
  if (/^[A-Za-z0-9+/]{4,}$/.test(value) && /^[0-9]{2}[A-F0-9]{4,}/i.test(value)) return "reversible (type 7)";
  return "cleartext or unknown";
}

const SECRET_KEYWORD_RE =
  /\b(?:password|passwd|secret|psk|psksecret|passphrase|encrypted-password|pre-shared-key|wpa-passphrase|plain-text-password|plaintext-password)\b/i;

const SKIP_TOKENS = new Set([
  "0", "1", "2", "5", "6", "7", "8", "9", // hash-type indicators
  "plaintext", "cleartext", "encrypted", "hashed", "ciphertext", "prompt", "digest",
]);

/** Mask the value after a secret keyword in a config line, for evidence display. */
export function redactLine(text: string): string {
  // keep SNMP community lines readable â€” weak community names are the finding
  if (/\bsnmp-server community\b|\bsnmp community\b|\bservice snmp\b/i.test(text)) return text;
  let out = text;
  const keyword = SECRET_KEYWORD_RE.exec(out);
  if (keyword) {
    const head = out.slice(0, keyword.index + keyword[0].length);
    const rest = out.slice(keyword.index + keyword[0].length);
    const tokens = rest.split(/(\s+)/);
    for (let i = 0; i < tokens.length; i += 1) {
      const token = tokens[i];
      if (!token || /^\s+$/.test(token)) continue;
      if (SKIP_TOKENS.has(token.toLowerCase())) continue;
      if (/^(?:phash|md5|sha\d*|salt|otp)$/i.test(token)) continue;
      // FortiOS `ENC <opaque>` storage form: the bare marker carries no
      // information, so both the indicator and the value are masked.
      tokens[i] = "<redacted>";
    }
    out = head + tokens.join("");
  }
  // standalone hash-looking values (vendor hash formats without a keyword)
  out = out.replace(/(?<![\w./-])\$(?:1|5|8|9)\$[\w+/.$-]{4,}/g, "<redacted-hash>");
  out = out.replace(/(?<![\w./-])(?:AES_256_GCM|AES_128_GCM):[\w+/=-]{4,}/gi, "<redacted-hash>");
  return out;
}

/**
 * Line-preserving redaction of a whole configuration for display: masks
 * password-like values while keeping line numbers and structure intact.
 */
export function redactConfigText(text: string): string {
  return text
    .split(/\r\n|\r|\n/)
    .map((line) => redactLine(line))
    .join("\n")
    .slice(0, MAX_CONFIG_BYTES);
}

const DEFAULT_WEAK_COMMUNITIES = new Set(["public", "private", "cisco", "cisco123", "monitor", "manager", "ilmi"]);

export function isDefaultCommunity(value: string): boolean {
  return DEFAULT_WEAK_COMMUNITIES.has(value.toLowerCase());
}

// ---- vendor detection ----------------------------------------------------------

type Signature = { vendor: VendorId; weight: number; patterns: RegExp[] };

const SIGNATURES: Signature[] = [
  {
    vendor: "cisco-asa",
    weight: 6,
    patterns: [/^asa version\s+\d/i, /^: saved$/im, /^pix version\s+\d/i, /^passwd\s+\S+\s+encrypted/m, /^boot system disk0:/im],
  },
  {
    vendor: "cisco-nxos",
    weight: 5,
    patterns: [/^boot nxos\s/im, /^feature nv overlay$/im, /^vrf context\s+\S+/im, /^install feature-set/im, /^!command: show running-config/mi, /^feature vpc$/im],
  },
  {
    vendor: "cisco-wlc-iosxe",
    weight: 5,
    patterns: [/^wlan\s+\S+\s+\d+\s+\S+/im, /^ap\s+\S+$/im, /^wireless management trustquery/mi, /^ap profile\s+\S+/im, /^ap country \S+/im],
  },
  {
    vendor: "cisco-wlc",
    weight: 5,
    patterns: [/^\(cisco controller\)/im, /^config wlan create\s/im, /^config wlan security/im, /^sysname\s+\S+/im, /^config interface address/im],
  },
  {
    vendor: "juniper-junos",
    weight: 5,
    patterns: [/^set system host-name\s/im, /^system\s*\{/im, /^## last (changed|commit)/im, /^set interfaces\s+\S+\s+unit\s/im, /^routing-options\s*\{/im, /^security\s*\{\s*$/im],
  },
  {
    vendor: "palo-alto",
    weight: 6,
    patterns: [/^set deviceconfig /im, /^<config version=/im, /^set mgt-config users /im, /^set rulebase security rules /im, /^<panconfig>/im, /^set shared config /im],
  },
  {
    vendor: "fortinet",
    weight: 6,
    patterns: [/^#config-version=/im, /^config system global$/im, /^config firewall policy$/im, /^set hostname\s/im, /^FortiGate-/im, /^config system admin$/im],
  },
  {
    vendor: "arubaos",
    weight: 5,
    patterns: [/^wlan ssid-profile\s/im, /^virtual-controller-country\s/im, /^mgmt-user\s/im, /^wlan virtual-ap\s/im, /^amp-server\s/im],
  },
  {
    vendor: "aruba-switch",
    weight: 5,
    patterns: [/^;.*configuration editor/im, /^password manager/im, /^snmp-server community\s+"[^"]*"\s+unrestricted/im, /^ip authorized-managers/im, /^vsf member\s/im, /^console local-interface/im],
  },
  {
    vendor: "ubiquiti",
    weight: 5,
    patterns: [/^set interfaces ethernet eth\d/im, /^set system host-name\s/im, /^set service dhcp-server/im, /^set firewall name\s/im, /^vyatta/i],
  },
  {
    vendor: "f5",
    weight: 5,
    patterns: [/^ltm virtual\s/im, /^ltm pool\s/im, /^cm device\s+\S+\s*\{/im, /^net vlan\s/im, /^create ltm /im],
  },
  {
    vendor: "sonicwall",
    weight: 6,
    patterns: [/<config version=/im, /<sonicwall>/im, /<system[^>]*>\s*<product/i, /<admin[^>]*>/im],
  },
  {
    vendor: "checkpoint-gaia",
    weight: 6,
    patterns: [/^set password-controls /im, /^set snmp (agent|community) /im, /^# Exported by /im, /^set interface \S+ ipv4-address /im, /^add ntp server /im, /^set clienv /im, /^add rba user /im],
  },
  {
    vendor: "mikrotik-routeros",
    weight: 5,
    patterns: [/^# by RouterOS /im, /^\/ip service$/im, /^\/user add /im, /^\/interface ethernet/im, /^\/system identity$/im, /^\/ip address$/im],
  },
  {
    vendor: "huawei-vrp",
    weight: 5,
    patterns: [/^sysname\s+\S+/im, /^undo /im, /^local-user\s+\S+\s+password/im, /^snmp-agent/im, /^telnet server enable/im, /^info-center loghost/im, /^ntp-service unicast-server/im, /^~$/im],
  },
  {
    vendor: "arista-eos",
    weight: 5,
    patterns: [/^management api http-commands$/im, /^daemon TerminAttr/im, /^interface Management\d/im, /^! device: /im, /^sflow run$/im, /^spanning-tree mode (mstp|rstp)$/im],
  },
  {
    vendor: "pfsense",
    weight: 6,
    patterns: [/^<pfsense>/im, /<lastchange>/im, /<dnsserver>/im, /<syslog>/im, /<ssh>[\s\S]{0,200}<enable\/>/im],
  },
  {
    vendor: "opnsense",
    weight: 6,
    patterns: [/^<opnsense>/im, /<lastchange>/im, /<OPNsense>/im, /<syslog>[\s\S]{0,200}<remote>/im, /<system>\s*<hostname>/im],
  },
  {
    vendor: "sophos-sfos",
    weight: 6,
    patterns: [/<Entities[\s>]/i, /<FirewallRule[\s>]/i, /<IPHost[\s>]/i, /<IPService[\s>]/i, /<TransactionID>/im],
  },
  {
    vendor: "watchguard",
    weight: 5,
    patterns: [/<Firebox[\s>]/i, /<WatchGuard/i, /<Fireware[\s>]/i, /<Device-Configuration/i],
  },
  {
    vendor: "cisco-ios",
    weight: 4,
    patterns: [/^building configuration/i, /^version\s+1[25]\.\d/im, /^service password-encryption/im, /^interface (gigabitethernet|fastethernet|tenGigabitEthernet|vlan|serial|tunnel)/im, /^enable secret/im, /^spanning-tree mode/im, /^boot-start-marker/im, /^config-register\s+0x/i],
  },
];

const VENDOR_LABELS: Record<VendorId, string> = {
  "cisco-ios": "Cisco IOS/IOS-XE",
  "cisco-nxos": "Cisco NX-OS",
  "cisco-asa": "Cisco ASA/PIX",
  "cisco-wlc": "Cisco WLC (AireOS)",
  "cisco-wlc-iosxe": "Cisco Catalyst 9800 (IOS-XE WLC)",
  "juniper-junos": "Juniper JunOS",
  "palo-alto": "Palo Alto PAN-OS",
  fortinet: "Fortinet FortiGate",
  "aruba-switch": "HPE Aruba Switch (AOS/ProCurve)",
  arubaos: "Aruba (AOS/IAP Wireless)",
  ubiquiti: "Ubiquiti EdgeOS/UniFi",
  f5: "F5 BIG-IP",
  sonicwall: "SonicWall",
  "arista-eos": "Arista EOS",
  "huawei-vrp": "Huawei VRP",
  "checkpoint-gaia": "Check Point GAiA",
  "mikrotik-routeros": "MikroTik RouterOS",
  pfsense: "pfSense CE",
  opnsense: "OPNsense",
  "sophos-sfos": "Sophos Firewall (SFOS)",
  watchguard: "WatchGuard Fireware",
  generic: "Generic / unrecognized",
};

const DEFAULT_DEVICE_TYPE: Record<VendorId, DeviceType> = {
  "cisco-ios": "unknown",
  "cisco-nxos": "switch",
  "cisco-asa": "firewall",
  "cisco-wlc": "wireless-controller",
  "cisco-wlc-iosxe": "wireless-controller",
  "juniper-junos": "unknown",
  "palo-alto": "firewall",
  fortinet: "firewall",
  "aruba-switch": "switch",
  arubaos: "wireless-controller",
  ubiquiti: "unknown",
  f5: "load-balancer",
  sonicwall: "firewall",
  "arista-eos": "switch",
  "huawei-vrp": "unknown",
  "checkpoint-gaia": "firewall",
  "mikrotik-routeros": "router",
  pfsense: "firewall",
  opnsense: "firewall",
  "sophos-sfos": "firewall",
  watchguard: "firewall",
  generic: "unknown",
};

export function detectVendor(text: string): { vendor: VendorId; score: number } {
  const sample = text.slice(0, 256 * 1024);
  let best: { vendor: VendorId; score: number } = { vendor: "generic", score: 0 };
  for (const signature of SIGNATURES) {
    let hits = 0;
    for (const pattern of signature.patterns) {
      if (pattern.test(sample)) hits += 1;
    }
    const score = hits >= 2 ? signature.weight + hits : hits;
    if (score > 0 && score > best.score) best = { vendor: signature.vendor, score };
  }
  return best;
}

// ---- shared empty profile -------------------------------------------------------

function emptyProfile(vendor: VendorId): ParsedNetworkConfig {
  return {
    vendor,
    vendorLabel: VENDOR_LABELS[vendor],
    deviceType: DEFAULT_DEVICE_TYPE[vendor],
    hostname: null,
    model: null,
    osVersion: null,
    serial: null,
    uptime: null,
    configLines: 0,
    interfaces: [],
    vlans: [],
    staticRoutes: [],
    routingProtocols: [],
    users: [],
    secrets: [],
    snmp: { enabled: false, communities: [], v3Configured: false, v3Users: [], line: null },
    ntp: { servers: [], authenticated: null, line: null },
    logging: { enabled: null, hosts: [], buffered: null, timestamps: null, line: null },
    aaa: { newModel: null, authenticationMethods: [], tacacsHosts: [], radiusHosts: [], line: null },
    management: {
      sshEnabled: null,
      sshVersion: null,
      telnetEnabled: null,
      httpEnabled: null,
      httpsEnabled: null,
      vtyAcl: null,
      vtyExecTimeout: null,
      consoleExecTimeout: null,
      loginBlockFor: null,
      minPasswordLength: null,
      mgmtHosts: [],
      allowAccess: [],
      sshDhMinSize: null,
      sshCiphers: [],
    },
    acls: [],
    firewallRules: [],
    natRules: [],
    vpns: [],
    wirelessLans: [],
    banners: [],
    services: [],
  };
}

// ---- Cisco IOS / IOS-XE / NX-OS / Catalyst-9800 family ---------------------------

// A new top-level section begins with any of these keywords.
const IOS_SECTION_START =
  /^(interface|router|line|vlan \d|ip access-list|ip prefix-list|access-list|banner|crypto|policy-map|class-map|route-map|control-plane|vlan |vrf |snmp-server|logging|ntp|aaa|username|enable|ip route|ip dhcp|spanning-tree|wlan |ap |parameter-map|redundancy|fabric|feature|boot |hostname|no |ip domain|service |ip http|ssh |lldp|cdp|errdisable|mac address-table|crypto key|track |event |fallback|alias|voice |sccp|dial-peer|controller|card|license|udld|key chain|monitor |probe |server |tls |websecure|ip ssh)/;

function parseCiscoIosLike(text: string, vendor: VendorId): ParsedNetworkConfig {
  const lines = toLines(text);
  const profile = emptyProfile(vendor);
  profile.configLines = lines.length;

  let currentInterface: ParsedInterface | null = null;
  let currentAcl: ParsedAcl | null = null;
  let currentRouting: ParsedRoutingProtocol | null = null;
  let currentLineType: "vty" | "console" | null = null;
  let inIsakmpPolicy = false;
  let bannerCapture: { kind: string; delimiter: string; buffer: string[] } | null = null;
  let pendingVlan: { id: string; name: string | null; line: number } | null = null;
  let inControlPlane = false;
  let inArchive = false;

  const findInterface = (name: string, line: number): ParsedInterface => {
    if (currentInterface && currentInterface.name === name) return currentInterface;
    const existing = profile.interfaces.find((entry) => entry.name === name);
    if (existing) return existing;
    const created: ParsedInterface = {
      name,
      line,
      description: null,
      ipAddress: null,
      adminEnabled: null,
      mode: "unknown",
      accessVlan: null,
      nativeVlan: null,
      allowedVlans: null,
      aclIn: null,
      aclOut: null,
      portSecurity: null,
      bpduGuard: null,
      portfast: null,
      stormControl: null,
      speedDuplex: null,
      nameif: null,
      securityLevel: null,
    };
    pushBounded(profile.interfaces, created, MAX_INTERFACES);
    return created;
  };

  const findAcl = (name: string, type: ParsedAcl["type"], line: number): ParsedAcl => {
    if (currentAcl && currentAcl.name === name) return currentAcl;
    const existing = profile.acls.find((entry) => entry.name === name);
    if (existing) return existing;
    const created: ParsedAcl = { name, type, appliedTo: [], rules: [], line };
    pushBounded(profile.acls, created, MAX_ACLS);
    return created;
  };

  const addService = (name: string, enabled: boolean, line: number): void => {
    const existing = profile.services.find((entry) => entry.name === name);
    if (existing) {
      existing.enabled = enabled;
      existing.line = line;
      return;
    }
    pushBounded(profile.services, { name, enabled, line }, MAX_SERVICES);
  };

  for (const { n, text: line, lower } of lines) {
    // multi-line banner capture (IOS: banner <kind> <delim> ... same delim ends)
    if (bannerCapture) {
      if (line.includes(bannerCapture.delimiter)) {
        const textBefore = line.slice(0, line.indexOf(bannerCapture.delimiter));
        if (textBefore.trim()) bannerCapture.buffer.push(textBefore);
        pushBounded(
          profile.banners,
          { kind: bannerCapture.kind, text: clean(bannerCapture.buffer.join(" ").trim(), MAX_BANNER_TEXT) ?? "", line: n },
          MAX_BANNERS,
        );
        bannerCapture = null;
      } else if (bannerCapture.buffer.length < 32) {
        bannerCapture.buffer.push(line.trim());
      }
      continue;
    }

    if (!line.trim() || lower === "!" || lower === "end" || lower.startsWith("building configuration")) {
      currentInterface = null;
      currentAcl = null;
      currentRouting = null;
      currentLineType = null;
      inIsakmpPolicy = false;
      inControlPlane = false;
      inArchive = false;
      continue;
    }

    // ---- identity ----
    let match = /^hostname\s+(\S+)/i.exec(line);
    if (match) {
      profile.hostname = clean(match[1]);
      continue;
    }
    match = /^version\s+(\S+)/i.exec(line);
    if (match && !profile.osVersion) {
      profile.osVersion = clean(match[1]);
      continue;
    }
    match = /processor board (?:id|ID)\s+(\S+)/.exec(line);
    if (match && !profile.serial) {
      profile.serial = clean(match[1]);
      continue;
    }
    match = /^!\s*Model number:\s*(\S+)/i.exec(line);
    if (match && !profile.model) {
      profile.model = clean(match[1]);
      continue;
    }
    match = /^chassis_id\s*:\s*(\S+)/i.exec(line);
    if (match && !profile.model) {
      profile.model = clean(match[1]);
      continue;
    }
    match = /^uptime is\s+(.+)$/i.exec(line);
    if (match) {
      profile.uptime = clean(match[1]);
      continue;
    }
    match = /^!Name:\s*(.+)$/i.exec(line);
    if (match && !profile.model) {
      profile.model = clean(match[1]);
      continue;
    }

    // ---- banners ----
    match = /^banner\s+(motd|login|exec|incoming|slip-ppp)\s+(.+)$/i.exec(line);
    if (match) {
      const rest = match[2].trim();
      const delimiter = rest.slice(0, 1);
      const after = rest.slice(1);
      const endIdx = after.indexOf(delimiter);
      if (endIdx >= 0) {
        pushBounded(
          profile.banners,
          { kind: match[1].toLowerCase(), text: clean(after.slice(0, endIdx), MAX_BANNER_TEXT) ?? "", line: n },
          MAX_BANNERS,
        );
      } else {
        bannerCapture = { kind: match[1].toLowerCase(), delimiter, buffer: after.trim() ? [after.trim()] : [] };
      }
      continue;
    }

    // ---- interfaces ----
    match = /^interface\s+(\S+)/i.exec(line);
    if (match) {
      currentInterface = findInterface(match[1], n);
      currentAcl = null;
      currentRouting = null;
      currentLineType = null;
      inIsakmpPolicy = false;
      continue;
    }

    // ---- vty / console ----
    match = /^line\s+(con(?:sole)?\s*\d|vty(?:\s+[\d\s]+)?)/i.exec(line);
    if (match) {
      currentInterface = null;
      currentAcl = null;
      currentRouting = null;
      inIsakmpPolicy = false;
      currentLineType = /con/i.test(match[1]) ? "console" : "vty";
      continue;
    }

    if (currentLineType === "vty") {
      match = /^transport input\s+(.+)$/i.exec(line);
      if (match) {
        const inputs = match[1].toLowerCase();
        // `transport input` is an explicit allowlist: telnet is enabled only
        // when named (or via all/none-less lists), otherwise it is disabled.
        const allowsTelnet = /\btelnet\b|\ball\b/.test(inputs);
        profile.management.telnetEnabled = allowsTelnet;
        if (/ssh/.test(inputs)) profile.management.sshEnabled = true;
        if (allowsTelnet) {
          addService("telnet (vty transport input all/telnet)", true, n);
        }
        if (inputs === "none") {
          profile.management.sshEnabled = profile.management.sshEnabled ?? false;
        }
        continue;
      }
      match = /^access-class\s+(\S+)\s+in/i.exec(line);
      if (match) {
        profile.management.vtyAcl = clean(match[1]);
        continue;
      }
      match = /^exec-timeout\s+(\d+)\s*(\d+)?/i.exec(line);
      if (match) {
        const minutes = Number(match[1]);
        profile.management.vtyExecTimeout = `${minutes}:${match[2] ?? "0"}`;
        continue;
      }
    }
    if (currentLineType === "console") {
      match = /^exec-timeout\s+(\d+)\s*(\d+)?/i.exec(line);
      if (match) {
        profile.management.consoleExecTimeout = `${match[1]}:${match[2] ?? "0"}`;
        continue;
      }
    }

    // ---- ACLs (named) ----
    match = /^ip access-list\s+(standard|extended)\s+(\S+)/i.exec(line);
    if (match) {
      currentInterface = null;
      currentRouting = null;
      currentLineType = null;
      inIsakmpPolicy = false;
      currentAcl = findAcl(match[2], match[1] as ParsedAcl["type"], n);
      continue;
    }
    // ---- ACLs (numbered) ----
    match = /^access-list\s+(\d+)\s+(permit|deny)\s+(.+)$/i.exec(line);
    if (match) {
      const acl = findAcl(match[1], Number(match[1]) < 100 ? "standard" : "extended", n);
      pushBounded(acl.rules, { n, text: `${match[2]} ${match[3]}`.trim(), action: match[2].toLowerCase() as "permit" | "deny" }, MAX_ACL_RULES);
      continue;
    }
    if (currentAcl) {
      match = /^\s*(permit|deny)\s+(.+)$/i.exec(line);
      if (match) {
        pushBounded(currentAcl.rules, { n, text: `${match[1]} ${match[2]}`.trim(), action: match[1].toLowerCase() as "permit" | "deny" }, MAX_ACL_RULES);
        continue;
      }
      match = /^\s*remark\s+(.+)$/i.exec(line);
      if (match) {
        pushBounded(currentAcl.rules, { n, text: `remark ${match[1]}`.trim(), action: "other" }, MAX_ACL_RULES);
        continue;
      }
    }

    // ---- access-group applications ----
    match = /^ip access-group\s+(\S+)\s+(in|out)/i.exec(line);
    if (match && currentInterface) {
      if (match[2].toLowerCase() === "in") currentInterface.aclIn = clean(match[1]);
      else currentInterface.aclOut = clean(match[1]);
      continue;
    }
    match = /^access-group\s+(\S+)\s+(in|out)\s+interface\s+(\S+)/i.exec(line);
    if (match) {
      const m = match;
      const applied = `${m[3]} ${m[2]}`;
      const acl = profile.acls.find((entry) => entry.name === m[1]);
      if (acl && !acl.appliedTo.includes(applied) && acl.appliedTo.length < 32) acl.appliedTo.push(applied);
      continue;
    }

    // ---- users / secrets ----
    match = /^username\s+(\S+)(.*)$/i.exec(line);
    if (match && !/password\s+\d+\s+\S+\s+autocommand/i.test(line)) {
      const rest = match[2] ?? "";
      const privilege = /privilege\s+(\d+)/i.exec(rest);
      let hashType = "unknown";
      if (/nopassword/i.test(rest)) hashType = "none (no password)";
      else if (/secret\s+(\d)/i.test(rest)) hashType = `Cisco type ${/secret\s+(\d)/i.exec(rest)?.[1]}`;
      else if (/secret/i.test(rest)) hashType = "Cisco type 5 (MD5)";
      else if (/password\s+(\d)\s/i.test(rest)) hashType = `Cisco type ${/password\s+(\d)\s/i.exec(rest)?.[1]}`;
      else if (/password/i.test(rest)) hashType = "cleartext or unknown";
      else hashType = "no password (command-based user)";
      pushBounded(
        profile.users,
        { name: clean(match[1]) ?? "unknown", role: privilege ? `privilege ${privilege[1]}` : null, hashType, line: n },
        MAX_USERS,
      );
      continue;
    }
    match = /^enable\s+(secret|password)\s*(\d)?\s*(\S+)?/i.exec(line);
    if (match) {
      const isSecret = /secret/i.test(match[1]);
      const hashType = isSecret
        ? match[2]
          ? `Cisco type ${match[2]}`
          : "Cisco type 5 (MD5, implicit)"
        : classifyHash(match[3] ?? "");
      pushBounded(profile.secrets, { purpose: "privileged (enable) mode", hashType, line: n }, MAX_SECRETS);
      addService("enable password (non-hashed)", !isSecret, n);
      continue;
    }
    match = /^service\s+password-encryption/i.exec(line);
    if (match) {
      addService("password-encryption", true, n);
      continue;
    }
    match = /^security passwords min-length\s+(\d+)/i.exec(line);
    if (match) {
      profile.management.minPasswordLength = Number(match[1]);
      continue;
    }
    match = /^login block-for\s+(\d+)\s+attempts\s+(\d+)\s+within\s+(\d+)/i.exec(line);
    if (match) {
      profile.management.loginBlockFor = `${match[2]} attempts / ${match[3]}s -> ${match[1]}s block`;
      continue;
    }

    // ---- AAA ----
    match = /^aaa\s+new-model/i.exec(line);
    if (match) {
      profile.aaa.newModel = true;
      profile.aaa.line = n;
      continue;
    }
    match = /^aaa authentication login\s+(\S+)\s+(.+)$/i.exec(line);
    if (match) {
      pushBounded(profile.aaa.authenticationMethods, `${match[1]}: ${match[2].trim()}`.slice(0, MAX_STRING), 64);
      continue;
    }
    match = /^(?:tacacs-server host|\btacacs server\b|tacacs-server)\s*(\S+)?/i.exec(line);
    if (match && /tacacs/i.test(line)) {
      const host = clean(match[1]);
      if (host) pushBounded(profile.aaa.tacacsHosts, host, 32);
      continue;
    }
    match = /^(?:radius-server host|radius server)\s*(\S+)?/i.exec(line);
    if (match) {
      const host = clean(match[1]);
      if (host) pushBounded(profile.aaa.radiusHosts, host, 32);
      continue;
    }

    // ---- SNMP ----
    match = /^snmp-server community\s+(\S+)\s+(RO|RW|group)\b(?:\s+(\S+))?/i.exec(line);
    if (match) {
      profile.snmp.enabled = true;
      if (profile.snmp.line === null) profile.snmp.line = n;
      // NX-OS group syntax: `snmp-server community <name> group <group-name>`;
      // admin/write groups confer read-write, operator groups are read-only.
      const access =
        match[2].toUpperCase() === "RO"
          ? "ro"
          : match[2].toUpperCase() === "RW"
            ? "rw"
            : /admin|write|rw/i.test(match[3] ?? "")
              ? "rw"
              : "ro";
      // `group <name>` is an NX-OS role group, not an ACL.
      const acl = match[2].toUpperCase() === "GROUP" ? null : clean(match[3]);
      pushBounded(
        profile.snmp.communities,
        {
          value: clean(match[1]) ?? "unknown",
          access,
          acl,
          line: n,
        },
        64,
      );
      continue;
    }
    if (/^snmp-server group\s+\S+\s+v3/i.test(line)) {
      profile.snmp.enabled = true;
      profile.snmp.v3Configured = true;
      if (profile.snmp.line === null) profile.snmp.line = n;
      continue;
    }
    match = /^snmp-server user\s+(\S+)\s+\S+\s+v3/i.exec(line);
    if (match) {
      profile.snmp.v3Configured = true;
      pushBounded(profile.snmp.v3Users, clean(match[1]) ?? "unknown", 64);
      continue;
    }

    // ---- NTP ----
    match = /^ntp server\s+(\S+)/i.exec(line);
    if (match) {
      const server = clean(match[1]);
      if (server) pushBounded(profile.ntp.servers, server, 16);
      if (profile.ntp.line === null) profile.ntp.line = n;
      continue;
    }
    if (/^ntp authenticate/i.test(line)) {
      profile.ntp.authenticated = true;
      continue;
    }

    // ---- logging ----
    match = /^(?:logging host|logging)\s+(\d+\.\d+\.\d+\.\d+)/i.exec(line);
    if (match) {
      profile.logging.enabled = true;
      const host = clean(match[1]);
      if (host) pushBounded(profile.logging.hosts, host, 16);
      if (profile.logging.line === null) profile.logging.line = n;
      continue;
    }
    match = /^logging server\s+(\d+\.\d+\.\d+\.\d+)/i.exec(line); // NX-OS
    if (match) {
      profile.logging.enabled = true;
      const host = clean(match[1]);
      if (host) pushBounded(profile.logging.hosts, host, 16);
      if (profile.logging.line === null) profile.logging.line = n;
      continue;
    }
    match = /^logging buffered\s+(\d+|\w+)/i.exec(line);
    if (match) {
      profile.logging.buffered = !/^(0|none)$/i.test(match[1]);
      continue;
    }
    if (/^service timestamps log datetime/i.test(line)) {
      profile.logging.timestamps = true;
      continue;
    }
    if (/^no logging (console|monitor|buffered)/i.test(line) && profile.logging.enabled !== true) {
      profile.logging.enabled = false;
      continue;
    }

    // ---- management services ----
    if (/^ip http server/i.test(line)) {
      profile.management.httpEnabled = true;
      addService("ip http server", true, n);
      continue;
    }
    if (/^ip http secure-server/i.test(line)) {
      profile.management.httpsEnabled = true;
      continue;
    }
    if (/^no ip http server/i.test(line)) {
      profile.management.httpEnabled = false;
      addService("ip http server", false, n);
      continue;
    }
    match = /^ip ssh version\s+(\d)/i.exec(line);
    if (match) {
      profile.management.sshEnabled = true;
      profile.management.sshVersion = match[1];
      continue;
    }
    // SSH crypto hardening (CIS: DH >= 2048, no CBC/3DES/Arcfour).
    match = /^ip ssh dh min size\s+(\d+)/i.exec(line);
    if (match) {
      profile.management.sshDhMinSize = Number(match[1]);
      continue;
    }
    match = /^ip ssh server algorithm (?:encryption|mac)\s+(.+)$/i.exec(line);
    if (match) {
      for (const algo of match[1].split(/\s+/)) {
        const name = clean(algo);
        if (name && profile.management.sshCiphers.length < 32) profile.management.sshCiphers.push(name);
      }
      continue;
    }
    if (/^crypto key generate rsa/i.test(line) || /show.*crypto key mypubkey/.test(lower)) {
      profile.management.sshEnabled = profile.management.sshEnabled ?? true;
      continue;
    }
    if (/^ssh key (?:rsa|dsa)/i.test(line)) {
      profile.management.sshEnabled = true;
      continue;
    }
    if (/^management api http-commands$/i.test(line)) {
      // EOS management API serves HTTPS; presence in the config means enabled
      profile.management.httpsEnabled = true;
      continue;
    }
    if (vendor === "cisco-nxos" && /^feature telnet/i.test(line)) {
      profile.management.telnetEnabled = true;
      addService("telnet (nxos feature)", true, n);
      continue;
    }
    if (vendor === "cisco-nxos" && /^no feature telnet|^feature telnet\b.*\bremove/i.test(line)) {
      profile.management.telnetEnabled = false;
      addService("telnet (nxos feature)", false, n);
      continue;
    }

    // ---- routing ----
    match = /^ip route (?:vrf\s+\S+\s+)?(\S+)\s+(\S+)\s+(\S+)/i.exec(line);
    if (match && !/^ip route\s+0\.0\.0\.0/i.test(line)) {
      pushBounded(
        profile.staticRoutes,
        { destination: `${match[1]}/${match[2]}`, nextHop: match[3], line: n },
        MAX_ROUTES,
      );
      continue;
    }
    if (/^ip route\s+0\.0\.0\.0/i.test(line)) {
      const parts = line.trim().split(/\s+/);
      pushBounded(profile.staticRoutes, { destination: "0.0.0.0/0 (default)", nextHop: parts[parts.length - 1] ?? "?", line: n }, MAX_ROUTES);
      continue;
    }
    match = /^ip routing/i.exec(line);
    if (match) addService("ip routing", true, n);
    match = /^router\s+(ospf|eigrp|bgp|rip|isis)\s*(\S+)?/i.exec(line);
    if (match) {
      currentInterface = null;
      currentAcl = null;
      currentLineType = null;
      currentRouting = { protocol: match[1].toLowerCase(), processId: match[2] ?? null, networks: [], authConfigured: false, line: n };
      pushBounded(profile.routingProtocols, currentRouting, MAX_ROUTING_PROTOCOLS);
      continue;
    }
    if (currentRouting) {
      match = /^network\s+(\S+)/i.exec(line);
      if (match && currentRouting.networks.length < 64) {
        currentRouting.networks.push(clean(match[1]) ?? "");
        continue;
      }
      // Routing protocol authentication: OSPF area auth, EIGRP MD5/SHA, BGP
      // neighbor passwords. Rogue-router/route-injection defenses.
      if (/authentication (?:mode\s+)?(?:md5|message-digest|sha| hmac-sha)/i.test(line) || /^area\s+\S+\s+authentication\b/i.test(line)) {
        currentRouting.authConfigured = true;
        continue;
      }
      match = /^neighbor\s+\S+\s+password\s+\S+/i.exec(line);
      if (match) {
        currentRouting.authConfigured = true;
        continue;
      }
    }

    // ---- control-plane protection (CoPP) and config archive ----
    if (/^control-plane$/i.test(line)) {
      inControlPlane = true;
      inArchive = false;
      currentInterface = null;
      currentLineType = null;
      continue;
    }
    if (inControlPlane) {
      match = /^service-policy (?:input|output)\s+\S+/i.exec(line);
      if (match) addService("control plane protection (CoPP)", true, n);
      continue;
    }
    if (/^archive$/i.test(line)) {
      inArchive = true;
      continue;
    }
    if (inArchive) {
      if (/^log config$/i.test(line)) continue;
      if (/^logging enable$/i.test(line)) addService("config archive", true, n);
      continue;
    }
    // Legacy config autoload from the network (supply-chain exposure).
    if (/^service config$/i.test(line)) {
      addService("service config (network autoload)", true, n);
      continue;
    }
    if (/^no service config$/i.test(line)) {
      addService("service config (network autoload)", false, n);
      continue;
    }
    if (/^ip bootp server$/i.test(line)) {
      addService("bootp", true, n);
      continue;
    }
    if (/^no ip bootp server$/i.test(line)) {
      addService("bootp", false, n);
      continue;
    }
    if (/^no service finger$/i.test(line)) {
      addService("finger", false, n);
      continue;
    }

    // ---- VLANs ----
    match = /^vlan\s+(\d+)$/i.exec(line);
    if (match) {
      pendingVlan = { id: match[1], name: null, line: n };
      pushBounded(profile.vlans, pendingVlan, MAX_VLANS);
      currentInterface = null;
      continue;
    }
    match = /^vlan\s+(\d+)\s*;\s*(.*)$/i.exec(line); // NX-OS one-liner style
    if (match) {
      pushBounded(profile.vlans, { id: match[1], name: clean(match[2]), line: n }, MAX_VLANS);
      continue;
    }
    if (pendingVlan) {
      match = /^\s*name\s+(.+)$/i.exec(line);
      if (match) {
        pendingVlan.name = clean(match[1]);
        pendingVlan = null;
        continue;
      }
    }

    // ---- switchport (inside interface blocks) ----
    if (currentInterface) {
      const iface = currentInterface;
      match = /^\s*description\s+(.+)$/i.exec(line);
      if (match) {
        iface.description = clean(match[1]);
        continue;
      }
      match = /^\s*ip address\s+(\S+)\s+(\S+)/i.exec(line);
      if (match) {
        iface.ipAddress = `${match[1]} ${match[2]}`;
        iface.mode = "routed";
        continue;
      }
      match = /^\s*ip address dhcp/i.exec(line);
      if (match) {
        iface.ipAddress = "dhcp";
        iface.mode = "routed";
        continue;
      }
      match = /^\s*switchport mode\s+(\S+)/i.exec(line);
      if (match) {
        const mode = match[1].toLowerCase();
        iface.mode = mode === "access" ? "access" : mode === "trunk" ? "trunk" : "l2";
        continue;
      }
      match = /^\s*switchport access vlan\s+(\d+)/i.exec(line);
      if (match) {
        iface.accessVlan = match[1];
        if (iface.mode === "unknown") iface.mode = "access";
        continue;
      }
      match = /^\s*switchport trunk native vlan\s+(\d+)/i.exec(line);
      if (match) {
        iface.nativeVlan = match[1];
        iface.mode = "trunk";
        continue;
      }
      match = /^\s*switchport trunk allowed vlan\s+(?:add\s+)?(.+)$/i.exec(line);
      if (match) {
        iface.allowedVlans = clean(match[1]);
        iface.mode = "trunk";
        continue;
      }
      match = /^\s*switchport port-security/i.exec(line);
      if (match) {
        iface.portSecurity = !/no\s+switchport port-security/i.test(line);
        continue;
      }
      if (/^\s*spanning-tree bpduguard enable/i.test(line)) iface.bpduGuard = true;
      if (/^\s*spanning-tree portfast/i.test(line)) iface.portfast = true;
      if (/^\s*storm-control/i.test(line)) iface.stormControl = true;
      match = /^\s*shutdown$/i.exec(line);
      if (match) {
        iface.adminEnabled = false;
        continue;
      }
      if (/^\s*no shutdown/i.test(line)) {
        iface.adminEnabled = true;
        continue;
      }
      match = /^\s*(speed|duplex)\s+(\S+)/i.exec(line);
      if (match) {
        iface.speedDuplex = clean(`${match[1]} ${match[2]}`);
        continue;
      }
      if (/^no switchport$/i.test(line.trim())) {
        iface.mode = "routed";
        continue;
      }
      continue;
    }

    // ---- global switching security ----
    if (/^ip dhcp snooping$/i.test(line)) addService("dhcp snooping", true, n);
    if (/^ip arp inspection vlan/i.test(line)) addService("dynamic arp inspection", true, n);
    if (/^spanning-tree portfast (default|edge)/i.test(line)) addService("global portfast", true, n);
    if (/^spanning-tree bpduguard default/i.test(line)) addService("global bpduguard", true, n);
    if (/^no cdp run/i.test(line)) addService("cdp", false, n);
    if (/^cdp run/i.test(line)) addService("cdp", true, n);
    if (/^no ip source-route/i.test(line)) addService("ip source-route", false, n);
    if (/^ip source-route/i.test(line)) addService("ip source-route", true, n);
    if (/^service finger/i.test(line)) addService("finger", true, n);
    if (/^ip http timeout-policy idle/i.test(line)) addService("http idle policy", true, n);

    // ---- ISAKMP / VPN ----
    match = /^crypto isakmp policy\s+(\d+)/i.exec(line);
    if (match) {
      inIsakmpPolicy = true;
      currentInterface = null;
      const vpn: ParsedVpn = {
        kind: "ipsec",
        name: `isakmp policy ${match[1]}`,
        encryption: [],
        auth: [],
        dhGroup: null,
        preSharedKey: false,
        aggressiveMode: false,
        line: n,
      };
      pushBounded(profile.vpns, vpn, MAX_VPNS);
      continue;
    }
    if (inIsakmpPolicy) {
      const active = profile.vpns[profile.vpns.length - 1];
      match = /^\s*encryption\s+(\S+)/i.exec(line);
      if (match && active) {
        active.encryption.push(match[1].toLowerCase());
        continue;
      }
      match = /^\s*hash\s+(\S+)/i.exec(line);
      if (match && active) {
        active.auth.push(match[1].toLowerCase());
        continue;
      }
      match = /^\s*authentication\s+pre-share/i.exec(line);
      if (match && active) {
        active.preSharedKey = true;
        continue;
      }
      match = /^\s*group\s+(\d+)/i.exec(line);
      if (match && active) {
        active.dhGroup = match[1];
        continue;
      }
    }
    match = /^crypto isakmp key\s+(\S+)/i.exec(line);
    if (match) {
      pushBounded(
        profile.secrets,
        { purpose: "IKE preshared key", hashType: "cleartext PSK", line: n },
        MAX_SECRETS,
      );
      const active = profile.vpns[profile.vpns.length - 1];
      if (active) active.preSharedKey = true;
      continue;
    }
    match = /^crypto isakmp peer\s+.*aggressive/i.exec(line);
    if (match) {
      const active = profile.vpns[profile.vpns.length - 1];
      if (active) active.aggressiveMode = true;
      continue;
    }

    // ---- Catalyst 9800 wireless ----
    match = /^wlan\s+(\S+)\s+(\d+)\s+(\S+)/i.exec(line);
    if (match) {
      const wlan: ParsedWlan = {
        profile: match[1],
        ssid: match[3],
        authMode: "unknown",
        psk: false,
        line: n,
      };
      pushBounded(profile.wirelessLans, wlan, MAX_WLANS);
      continue;
    }
    if (profile.wirelessLans.length > 0) {
      const wlan = profile.wirelessLans[profile.wirelessLans.length - 1];
      if (/^\s*no security wpa\b/i.test(line)) wlan.authMode = "open";
      else if (/^\s*security wpa psk/i.test(line)) {
        wlan.psk = true;
        wlan.authMode = "wpa-psk";
      } else if (/^\s*security wpa akm 802.1x/i.test(line) || /dot1x/.test(lower)) wlan.authMode = "wpa-802.1X";
      else if (/^\s*security wpa wpa2?\b/i.test(line)) wlan.authMode = wlan.authMode === "unknown" ? "wpa2" : wlan.authMode;
      if (/wep/i.test(lower) && /^\s*security/i.test(line)) wlan.authMode = "wep";
      if (/tkip/i.test(lower)) wlan.authMode = `${wlan.authMode}+tkip`;
    }

    // ---- ASA-flavoured access-group inside IOS parse is handled above ----
    void IOS_SECTION_START; // (kept for documentation; section detection is implicit)
  }

  inferDeviceTypeIos(profile);
  return profile;
}

function inferDeviceTypeIos(profile: ParsedNetworkConfig): void {
  if (profile.deviceType !== "unknown") return;
  const hasSwitchports = profile.interfaces.some(
    (iface) => iface.mode === "access" || iface.mode === "trunk" || iface.accessVlan !== null,
  );
  const hasWlans = profile.wirelessLans.length > 0;
  if (hasWlans) profile.deviceType = "wireless-controller";
  else if (hasSwitchports || profile.vlans.length > 0) profile.deviceType = "switch";
  else if (profile.routingProtocols.length > 0 || profile.staticRoutes.length > 0 || profile.interfaces.some((iface) => iface.mode === "routed")) {
    profile.deviceType = "router";
  }
}

// ---- Cisco ASA -----------------------------------------------------------------

function parseAsa(text: string): ParsedNetworkConfig {
  const lines = toLines(text);
  const profile = emptyProfile("cisco-asa");
  profile.configLines = lines.length;

  let currentInterface: ParsedInterface | null = null;
  let inObjectNetwork = false;
  let pendingAclName: string | null = null;

  const findInterface = (name: string, line: number): ParsedInterface => ({
    name,
    line,
    description: null,
    ipAddress: null,
    adminEnabled: null,
    mode: "routed",
    accessVlan: null,
    nativeVlan: null,
    allowedVlans: null,
    aclIn: null,
    aclOut: null,
    portSecurity: null,
    bpduGuard: null,
    portfast: null,
    stormControl: null,
    speedDuplex: null,
    nameif: null,
    securityLevel: null,
  });

  for (const { n, text: line, lower } of lines) {
    if (!line.trim() || lower.startsWith(": ")) {
      if (currentInterface) currentInterface = null;
      continue;
    }

    let match = /^:Saved$/i.exec(line);
    if (match) continue;
    match = /^ASA Version\s+(\S+)/i.exec(line);
    if (match) {
      profile.osVersion = clean(match[1]);
      continue;
    }
    match = /^hostname\s+(\S+)/i.exec(line);
    if (match) {
      profile.hostname = clean(match[1]);
      continue;
    }
    match = /^domain-name\s+(\S+)/i.exec(line);
    if (match) {
      profile.model = profile.model; // domain kept out of model; no-op for clarity
      continue;
    }
    match = /^enable password\s+(\S+)(.*)$/i.exec(line);
    if (match) {
      pushBounded(profile.secrets, { purpose: "enable mode", hashType: classifyHash(match[1]), line: n }, MAX_SECRETS);
      continue;
    }
    match = /^passwd\s+(\S+)/i.exec(line);
    if (match) {
      pushBounded(profile.secrets, { purpose: "telnet/mgmt password", hashType: classifyHash(match[1]), line: n }, MAX_SECRETS);
      continue;
    }
    match = /^username\s+(\S+)\s+password\s+(\S+)\s+(encrypted\s+)?privilege\s+(\d+)/i.exec(line);
    if (match) {
      pushBounded(
        profile.users,
        {
          name: clean(match[1]) ?? "unknown",
          role: `privilege ${match[4]}`,
          hashType: match[3] ? "vendor-encrypted" : "cleartext",
          line: n,
        },
        MAX_USERS,
      );
      continue;
    }

    // interfaces
    match = /^interface\s+(\S+)$/i.exec(line);
    if (match) {
      currentInterface = findInterface(match[1], n);
      pushBounded(profile.interfaces, currentInterface, MAX_INTERFACES);
      continue;
    }
    match = /^interface\s+(\S+)\s*\.?(\d*)/i.exec(line);
    if (match && !currentInterface) {
      currentInterface = findInterface(match[0].replace(/^interface\s+/i, "").trim(), n);
      pushBounded(profile.interfaces, currentInterface, MAX_INTERFACES);
      continue;
    }
    if (currentInterface) {
      match = /^\s*nameif\s+(\S+)/i.exec(line);
      if (match) {
        currentInterface.nameif = clean(match[1]);
        continue;
      }
      match = /^\s*security-level\s+(\d+)/i.exec(line);
      if (match) {
        currentInterface.securityLevel = Number(match[1]);
        continue;
      }
      match = /^\s*ip address\s+(\S+)\s+(\S+)/i.exec(line);
      if (match) {
        currentInterface.ipAddress = `${match[1]} ${match[2]}`;
        continue;
      }
      if (/^\s*shutdown/i.test(line)) {
        currentInterface.adminEnabled = false;
        continue;
      }
      if (/^\s*no shut/i.test(line)) {
        currentInterface.adminEnabled = true;
        continue;
      }
      match = /^\s*description\s+(.+)$/i.exec(line);
      if (match) {
        currentInterface.description = clean(match[1]);
        continue;
      }
    }

    // routes
    match = /^route\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\S+))?/i.exec(line);
    if (match) {
      pushBounded(
        profile.staticRoutes,
        {
          destination: match[2] === "0.0.0.0" && match[3] === "0.0.0.0" ? "0.0.0.0/0 (default)" : `${match[2]} ${match[3]}`,
          nextHop: `${match[4] ?? "gateway"} via ${match[1]}`,
          line: n,
        },
        MAX_ROUTES,
      );
      continue;
    }

    // ACLs
    match = /^access-list\s+(\S+)\s+(standard|extended)?\s*(permit|deny)\s+(.*)$/i.exec(line);
    if (match && !/^\s*!/.test(line)) {
      let acl = profile.acls.find((entry) => entry.name === match![1]);
      if (!acl) {
        acl = { name: match[1], type: (match[2] as ParsedAcl["type"]) ?? "extended", appliedTo: [], rules: [], line: n };
        pushBounded(profile.acls, acl, MAX_ACLS);
      }
      pushBounded(acl.rules, { n, text: `${match[3]} ${match[4]}`.trim(), action: match[3].toLowerCase() as "permit" | "deny" }, MAX_ACL_RULES);
      pendingAclName = acl.name;
      continue;
    }
    match = /^access-group\s+(\S+)\s+(in|out)\s+interface\s+(\S+)/i.exec(line);
    if (match) {
      const acl = profile.acls.find((entry) => entry.name === match![1]);
      const applied = `${match[3]} ${match[2]}`;
      if (acl && !acl.appliedTo.includes(applied) && acl.appliedTo.length < 32) acl.appliedTo.push(applied);
      const iface = profile.interfaces.find((entry) => entry.nameif === match![3] || entry.name === match![3]);
      if (iface) {
        if (match[2].toLowerCase() === "in") iface.aclIn = clean(match[1]);
        else iface.aclOut = clean(match[1]);
      }
      continue;
    }

    // NAT (8.2 classic + 8.3 twic-nat object)
    if (/^nat\s*\(/i.test(line)) {
      pushBounded(profile.natRules, { id: null, description: line.trim().slice(0, MAX_STRING), line: n }, MAX_NAT_RULES);
      continue;
    }
    match = /^object network\s+(\S+)/i.exec(line);
    if (match) {
      inObjectNetwork = true;
      pushBounded(profile.natRules, { id: match[1], description: "network object", line: n }, MAX_NAT_RULES);
      continue;
    }
    if (inObjectNetwork && /^\s*nat\s*\(/i.test(line)) {
      const last = profile.natRules[profile.natRules.length - 1];
      if (last) last.description = `object NAT: ${line.trim().slice(0, 200)}`;
      continue;
    }
    if (inObjectNetwork && /^object /i.test(line)) inObjectNetwork = false;

    // management
    match = /^telnet\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(\S+)/i.exec(line);
    if (match) {
      profile.management.telnetEnabled = true;
      const src = clean(`${match[1]} ${match[2]}`);
      const iface = clean(match[3]);
      if (src) profile.management.mgmtHosts.push(src);
      if (src && iface) pushBounded(profile.management.allowAccess, `${iface}:${match[1]}`, 32);
      continue;
    }
    if (/^telnet timeout/i.test(line)) continue;
    match = /^ssh\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(\S+)/i.exec(line);
    if (match) {
      profile.management.sshEnabled = profile.management.sshEnabled ?? true;
      const src = clean(`${match[1]} ${match[2]}`);
      if (src) profile.management.mgmtHosts.push(src);
      continue;
    }
    match = /^ssh version\s+(\d)/i.exec(line);
    if (match) {
      profile.management.sshVersion = match[1];
      continue;
    }
    if (/^http server enable/i.test(line)) profile.management.httpEnabled = true;
    if (/^no http server enable/i.test(line)) profile.management.httpEnabled = false;
    match = /^http\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(\S+)/i.exec(line);
    if (match) {
      const src = clean(`${match[1]} ${match[2]}`);
      if (src) profile.management.mgmtHosts.push(src);
      continue;
    }
    if (/^aaa authentication ssh console/i.test(line) || /^aaa authentication telnet console/i.test(line)) {
      profile.aaa.newModel = true;
      pushBounded(profile.aaa.authenticationMethods, line.trim().slice(0, MAX_STRING), 64);
      continue;
    }

    // snmp
    match = /^snmp-server (?:host|community)\s+(\S+)\s*(.*)$/i.exec(line);
    if (match) {
      profile.snmp.enabled = true;
      if (profile.snmp.line === null) profile.snmp.line = n;
      if (/^snmp-server community/i.test(line)) {
        pushBounded(
          profile.snmp.communities,
          { value: clean(match[1]) ?? "unknown", access: "ro", acl: null, line: n },
          64,
        );
      }
      continue;
    }

    // logging â€” `logging host <interface> <ip>` (ASA) or `logging host <ip>`
    if (/^logging enable/i.test(line)) profile.logging.enabled = true;
    match = /^logging host\s+(?:\S+\s+)?(\d+\.\d+\.\d+\.\d+)/i.exec(line);
    if (match) {
      profile.logging.enabled = true;
      const host = clean(match[1]);
      if (host) pushBounded(profile.logging.hosts, host, 16);
      if (profile.logging.line === null) profile.logging.line = n;
      continue;
    }
    if (/^logging timestamp\s+ntp/i.test(line) || /^clock timezone/i.test(line)) profile.logging.timestamps = profile.logging.timestamps ?? false;

    // NTP
    match = /^ntp server\s+(\S+)/i.exec(line);
    if (match) {
      const server = clean(match[1]);
      if (server) pushBounded(profile.ntp.servers, server, 16);
      if (profile.ntp.line === null) profile.ntp.line = n;
      continue;
    }
    if (/^ntp authenticate/i.test(line)) profile.ntp.authenticated = true;

    // ---- VPN ----
    match = /^(?:crypto\s+)?(?:isakmp|ikev1|ikev2)\s+policy\s+(\d+)/i.exec(line);
    if (match) {
      pendingAclName = null;
      const vpn: ParsedVpn = {
        kind: "ipsec",
        name: `ike policy ${match[1]}`,
        encryption: [],
        auth: [],
        dhGroup: null,
        preSharedKey: false,
        aggressiveMode: false,
        line: n,
      };
      pushBounded(profile.vpns, vpn, MAX_VPNS);
      continue;
    }
    if (profile.vpns.length > 0) {
      const vpn = profile.vpns[profile.vpns.length - 1];
      match = /^\s*encryption\s+(\S+)/i.exec(line);
      if (match) {
        vpn.encryption.push(match[1].toLowerCase());
        continue;
      }
      match = /^\s*(?:hash|integrity)\s+(\S+)/i.exec(line);
      if (match) {
        vpn.auth.push(match[1].toLowerCase());
        continue;
      }
      match = /^\s*group\s+(\d+)/i.exec(line);
      if (match) {
        vpn.dhGroup = match[1];
        continue;
      }
      if (/^\s*authentication pre-share/i.test(line)) {
        vpn.preSharedKey = true;
        continue;
      }
    }
    match = /^(?:crypto isakmp key|tunnel-group\s+\S+\s+ipsec-attributes.*$)/i.exec(line);
    if (match && /^crypto isakmp key/i.test(line)) {
      pushBounded(profile.secrets, { purpose: "IKE preshared key", hashType: "cleartext PSK", line: n }, MAX_SECRETS);
      continue;
    }
    if (/isakmp peer .*aggressive|aggressive-mode/i.test(lower)) {
      const vpn = profile.vpns[profile.vpns.length - 1];
      if (vpn) vpn.aggressiveMode = true;
      continue;
    }
    if (/^crypto ipsec (?:ikev1 )?transform-set/i.test(line)) {
      const tokens = line.trim().split(/\s+/).slice(3);
      const active = profile.vpns[profile.vpns.length - 1];
      if (active) {
        for (const token of tokens) {
          const value = token.toLowerCase();
          if (/^(aes|3des|des|aes-gcm|aes-192|aes-256)/.test(value)) active.encryption.push(value);
          else if (/^(sha|md5|sha256|sha384|sha512)/.test(value)) active.auth.push(value);
        }
      }
      continue;
    }
  }

  return profile;
}

// ---- JunOS (set style + brace style) ----------------------------------------------

/** Converts hierarchical JunOS brace syntax to `set ...` lines. */
function junosBracesToSets(lines: RawLine[]): RawLine[] {
  const out: RawLine[] = [];
  const stack: string[] = [];
  for (const { n, text } of lines) {
    const line = text.trim();
    if (!line) continue;
    if (line.endsWith("{")) {
      const path = line.slice(0, -1).trim();
      if (path) stack.push(path.replace(/;$/, ""));
      continue;
    }
    if (line === "}" || line === "};") {
      stack.pop();
      continue;
    }
    const statement = line.replace(/;$/, "").trim();
    if (!statement || statement.startsWith("#") || statement.startsWith("/*")) continue;
    const path = stack.length > 0 ? `${stack.join(" ")} ${statement}` : statement;
    out.push({ n, text: `set ${path}`, lower: `set ${path.toLowerCase()}` });
  }
  return out;
}

function parseJunos(text: string): ParsedNetworkConfig {
  const raw = toLines(text);
  const lines = raw.some((entry) => /^set\s/i.test(entry.text) || /^\S[^{}]*\{/.test(entry.text))
    ? raw.some((entry) => /[{]/.test(entry.text) && !/^set/i.test(entry.text))
      ? junosBracesToSets(raw)
      : raw
    : raw;
  const profile = emptyProfile("juniper-junos");
  profile.configLines = raw.length;

  const services: string[] = [];
  const addService = (name: string, enabled: boolean, line: number): void => {
    const existing = profile.services.find((entry) => entry.name === name);
    if (existing) {
      existing.enabled = enabled;
      existing.line = line;
      return;
    }
    pushBounded(profile.services, { name, enabled, line }, MAX_SERVICES);
  };

  let currentAcl: ParsedAcl | null = null;

  for (const { n, text: line, lower } of lines) {
    let match = /^set\s+system\s+host-name\s+(\S+)/i.exec(line);
    if (match) {
      profile.hostname = clean(match[1]);
      continue;
    }
    match = /^set\s+version\s+(\S+)/i.exec(line) ?? /^version\s+(\S+?);?\s*$/i.exec(line);
    if (match) {
      profile.osVersion = clean(match[1]);
      continue;
    }
    if (/^set\s+system\s+root-authentication/i.test(line)) {
      const hashType = /encrypted-password/.test(lower) ? "MD5 crypt (encrypted-password)" : "cleartext or unknown";
      pushBounded(profile.secrets, { purpose: "root authentication", hashType, line: n }, MAX_SECRETS);
      continue;
    }
    match = /^set\s+system\s+login\s+user\s+(\S+)(.*)$/i.exec(line);
    if (match) {
      const rest = match[2] ?? "";
      let user = profile.users.find((entry) => entry.name === match![1]);
      if (!user) {
        user = { name: match[1], role: /class\s+(\S+)/i.exec(rest)?.[1] ?? null, hashType: "unknown", line: n };
        pushBounded(profile.users, user, MAX_USERS);
      }
      if (/class\s+(\S+)/i.test(rest)) user.role = /class\s+(\S+)/i.exec(rest)?.[1] ?? user.role;
      if (/plain-text-password/.test(lower)) user.hashType = "cleartext prompt";
      else if (/encrypted-password/.test(lower)) user.hashType = "MD5 crypt (encrypted-password)";
      else if (/ssh-rsa|ssh-ed25519/.test(lower)) user.hashType = "ssh public key";
      continue;
    }
    match = /^set\s+system\s+services\s+(\S+)(.*)$/i.exec(line);
    if (match) {
      services.push(`${match[1]}${match[2] ?? ""}`.trim());
      if (/^ssh/.test(match[1])) {
        profile.management.sshEnabled = true;
        const version = /protocol-version\s+(v?\d)/i.exec(line)?.[1];
        if (version) profile.management.sshVersion = version.replace(/^v/, "");
      }
      if (/^telnet/.test(match[1])) {
        profile.management.telnetEnabled = true;
        addService("telnet (system services)", true, n);
      }
      if (/^web-management\s+http\b(?!s)/.test(`${match[1]}${match[2] ?? ""}`.trim())) {
        profile.management.httpEnabled = true;
        addService("web-management http", true, n);
      }
      if (/^web-management\s+https/.test(`${match[1]}${match[2] ?? ""}`.trim())) profile.management.httpsEnabled = true;
      continue;
    }
    match = /^set\s+system\s+services\s+ssh\s+root-login\s+allow/i.exec(line);
    if (match) {
      addService("ssh root login allow", true, n);
      continue;
    }
    if (/^set\s+system\s+login\s+retry-options/i.test(line)) addService("login retry options", true, n);

    // interfaces
    match = /^set\s+interfaces\s+(\S+)\s+description\s+(.+)$/i.exec(line);
    if (match) {
      let iface = profile.interfaces.find((entry) => entry.name === match![1]);
      if (!iface) {
        iface = {
          name: match[1],
          line: n,
          description: null,
          ipAddress: null,
          adminEnabled: null,
          mode: "unknown",
          accessVlan: null,
          nativeVlan: null,
          allowedVlans: null,
          aclIn: null,
          aclOut: null,
          portSecurity: null,
          bpduGuard: null,
          portfast: null,
          stormControl: null,
          speedDuplex: null,
          nameif: null,
          securityLevel: null,
        };
        pushBounded(profile.interfaces, iface, MAX_INTERFACES);
      }
      iface.description = clean(match[2]);
      continue;
    }
    match = /^set\s+interfaces\s+(\S+)\s+unit\s+(\d+)\s+family\s+inet\s+address\s+(\S+)/i.exec(line);
    if (match) {
      const name = `${match[1]}.${match[2]}`;
      let iface = profile.interfaces.find((entry) => entry.name === name);
      if (!iface) {
        iface = {
          name,
          line: n,
          description: null,
          ipAddress: null,
          adminEnabled: null,
          mode: "routed",
          accessVlan: null,
          nativeVlan: null,
          allowedVlans: null,
          aclIn: null,
          aclOut: null,
          portSecurity: null,
          bpduGuard: null,
          portfast: null,
          stormControl: null,
          speedDuplex: null,
          nameif: null,
          securityLevel: null,
        };
        pushBounded(profile.interfaces, iface, MAX_INTERFACES);
      }
      iface.ipAddress = clean(match[3]);
      iface.mode = "routed";
      continue;
    }
    match = /^set\s+interfaces\s+(\S+)\s+disable/i.exec(line);
    if (match) {
      const iface = profile.interfaces.find((entry) => entry.name === match![1]);
      if (iface) iface.adminEnabled = false;
      continue;
    }
    match = /^set\s+interfaces\s+(\S+)\s+(?:flexible-ethernet-tools|member-link|native-vlan-id)\s*(\S+)?/i.exec(line);
    if (match && /native-vlan-id/.test(line)) {
      const iface = profile.interfaces.find((entry) => entry.name === match![1]);
      if (iface) {
        iface.nativeVlan = match[2] ?? null;
        iface.mode = "trunk";
      }
      continue;
    }
    match = /^set\s+interfaces\s+(\S+)\s+unit\s+\d+\s+family\s+ethernet-switching\s+port-mode\s+(\S+)/i.exec(line);
    if (match) {
      let iface = profile.interfaces.find((entry) => entry.name === match![1]);
      if (!iface) {
        iface = {
          name: match[1],
          line: n,
          description: null,
          ipAddress: null,
          adminEnabled: null,
          mode: "unknown",
          accessVlan: null,
          nativeVlan: null,
          allowedVlans: null,
          aclIn: null,
          aclOut: null,
          portSecurity: null,
          bpduGuard: null,
          portfast: null,
          stormControl: null,
          speedDuplex: null,
          nameif: null,
          securityLevel: null,
        };
        pushBounded(profile.interfaces, iface, MAX_INTERFACES);
      }
      iface.mode = /trunk/i.test(match[2]) ? "trunk" : "access";
      continue;
    }
    match = /^set\s+interfaces\s+(\S+)\s+unit\s+\d+\s+family\s+ethernet-switching\s+vlan\s+members\s+(\S+)/i.exec(line);
    if (match) {
      const iface = profile.interfaces.find((entry) => entry.name === match![1]);
      if (iface) {
        if (iface.mode === "unknown") iface.mode = "access";
        if (iface.accessVlan === null) iface.accessVlan = match[2];
        else if (iface.mode === "trunk") iface.allowedVlans = clean(`${iface.allowedVlans ?? ""},${match[2]}`.replace(/^,/, ""));
      }
      continue;
    }

    // vlans
    match = /^set\s+vlans\s+(\S+)\s+vlan-id\s+(\d+)/i.exec(line);
    if (match) {
      pushBounded(profile.vlans, { id: match[2], name: clean(match[1]), line: n }, MAX_VLANS);
      continue;
    }

    // routes / protocols
    match = /^set\s+routing-options\s+static\s+route\s+(\S+)\s+next-hop\s+(\S+)/i.exec(line);
    if (match) {
      pushBounded(
        profile.staticRoutes,
        { destination: match[1] === "0.0.0.0/0" ? "0.0.0.0/0 (default)" : match[1], nextHop: match[2], line: n },
        MAX_ROUTES,
      );
      continue;
    }
    match = /^set\s+protocols\s+(ospf|bgp|rip|isis|ospf3)(.*)$/i.exec(line);
    if (match) {
      let proto = profile.routingProtocols.find((entry) => entry.protocol === match![1]);
      if (!proto) {
        proto = { protocol: match[1], processId: null, networks: [], authConfigured: null, line: n };
        pushBounded(profile.routingProtocols, proto, MAX_ROUTING_PROTOCOLS);
      }
      const area = /area\s+(\S+)/i.exec(match[2] ?? "")?.[1];
      const iface = /interface\s+(\S+)/i.exec(match[2] ?? "")?.[1];
      const neighbor = /neighbor\s+(\S+)/i.exec(match[2] ?? "")?.[1];
      const detail = area ?? iface ?? neighbor;
      if (detail && proto.networks.length < 64 && !proto.networks.includes(detail)) proto.networks.push(detail);
      continue;
    }

    // snmp
    match = /^set\s+snmp\s+community\s+(\S+)\s+authorization\s+(\S+)/i.exec(line);
    if (match) {
      profile.snmp.enabled = true;
      if (profile.snmp.line === null) profile.snmp.line = n;
      pushBounded(
        profile.snmp.communities,
        {
          value: clean(match[1]) ?? "unknown",
          access: /read-only/i.test(match[2]) ? "ro" : /read-write/i.test(match[2]) ? "rw" : "unknown",
          acl: /clients\s+\[?\s*([^\]]+)/i.exec(line)?.[1]?.trim() ?? null,
          line: n,
        },
        64,
      );
      continue;
    }
    if (/^set\s+snmp\s+v3/i.test(line)) {
      profile.snmp.enabled = true;
      profile.snmp.v3Configured = true;
      if (profile.snmp.line === null) profile.snmp.line = n;
      continue;
    }

    // ntp
    match = /^set\s+system\s+ntp\s+server\s+(\S+)/i.exec(line);
    if (match) {
      const server = clean(match[1]);
      if (server) pushBounded(profile.ntp.servers, server, 16);
      if (profile.ntp.line === null) profile.ntp.line = n;
      continue;
    }
    if (/^set\s+system\s+ntp\s+authentication-key/i.test(line)) profile.ntp.authenticated = true;

    // logging
    match = /^set\s+system\s+syslog\s+host\s+(\S+)/i.exec(line);
    if (match) {
      profile.logging.enabled = true;
      const host = clean(match[1]);
      if (host) pushBounded(profile.logging.hosts, host, 16);
      if (profile.logging.line === null) profile.logging.line = n;
      continue;
    }
    if (/^set\s+system\s+syslog/i.test(line) && profile.logging.line === null) profile.logging.line = n;

    // aaa
    if (/^set\s+access\s+profile/i.test(line) || /tacacs-server|^set\s+system\s+tacplus-server/i.test(line)) {
      match = /tacplus-server\s+(\S+)|tacacs-server\s+(\S+)/i.exec(line);
      const host = match?.[1] ?? match?.[2] ?? null;
      if (host) pushBounded(profile.aaa.tacacsHosts, clean(host) ?? host, 32);
      continue;
    }
    if (/^set\s+system\s+radius-server\s+(\S+)/i.test(line)) {
      pushBounded(profile.aaa.radiusHosts, clean(/^set\s+system\s+radius-server\s+(\S+)/i.exec(line)?.[1] ?? "") ?? "radius", 32);
      continue;
    }

    // firewall filters
    match = /^set\s+firewall\s+family\s+inet\s+filter\s+(\S+)\s+term\s+(\S+)\s+from\s+address\s+(\S+)/i.exec(line);
    if (match) {
      let acl = profile.acls.find((entry) => entry.name === match![1]);
      if (!acl) {
        acl = { name: match[1], type: "extended", appliedTo: [], rules: [], line: n };
        pushBounded(profile.acls, acl, MAX_ACLS);
      }
      pushBounded(acl.rules, { n, text: `from address ${match[3]}`, action: "other" }, MAX_ACL_RULES);
      currentAcl = acl;
      continue;
    }
    match = /^set\s+firewall\s+family\s+inet\s+filter\s+(\S+)\s+term\s+(\S+)\s+then\s+(\S+)/i.exec(line);
    if (match) {
      let acl = profile.acls.find((entry) => entry.name === match![1]);
      if (!acl) {
        acl = { name: match[1], type: "extended", appliedTo: [], rules: [], line: n };
        pushBounded(profile.acls, acl, MAX_ACLS);
      }
      const action = match[3].toLowerCase();
      pushBounded(
        acl.rules,
        { n, text: `term ${match[2]} then ${match[3]}`, action: action === "accept" ? "permit" : action === "discard" || action === "reject" ? "deny" : "other" },
        MAX_ACL_RULES,
      );
      currentAcl = acl;
      continue;
    }
    match = /^set\s+interfaces\s+(\S+)\s+unit\s+\d+\s+family\s+inet\s+filter\s+input\s+(\S+)/i.exec(line);
    if (match) {
      const acl = profile.acls.find((entry) => entry.name === match![2]);
      const applied = `${match[1]} in`;
      if (acl && !acl.appliedTo.includes(applied) && acl.appliedTo.length < 32) acl.appliedTo.push(applied);
      const iface = profile.interfaces.find((entry) => entry.name === match![1] || entry.name.startsWith(`${match![1]}.`));
      if (iface) iface.aclIn = clean(match[2]);
      continue;
    }

    // security zones / host-inbound (SRX)
    if (/^set\s+security\s+zones\s+security-zone/i.test(line)) {
      if (/host-inbound-traffics?\s+system-services\s+/i.test(line)) {
        const servicesList = /system-services\s+(.+)$/i.exec(line)?.[1] ?? "";
        if (/telnet/i.test(servicesList)) {
          profile.management.telnetEnabled = true;
          addService("telnet (srx host-inbound)", true, n);
        }
        if (/ssh/i.test(servicesList)) profile.management.sshEnabled = true;
      }
      continue;
    }

    // vpn
    if (/^set\s+security\s+ike\s+proposal/i.test(line)) {
      let vpn = profile.vpns.find((entry) => entry.kind === "ipsec" && entry.name === "ike proposals");
      if (!vpn) {
        vpn = { kind: "ipsec", name: "ike proposals", encryption: [], auth: [], dhGroup: null, preSharedKey: false, aggressiveMode: false, line: n };
        pushBounded(profile.vpns, vpn, MAX_VPNS);
      }
      match = /encryption-algorithm\s+(\S+)/i.exec(line);
      if (match) vpn.encryption.push(match[1].toLowerCase());
      match = /authentication-algorithm\s+(\S+)/i.exec(line);
      if (match) vpn.auth.push(match[1].toLowerCase());
      match = /dh-group\s+(\S+)/i.exec(line);
      if (match) vpn.dhGroup = match[1];
      continue;
    }
    if (/^set\s+security\s+ike\s+policy\s+\S+\s+pre-shared-key\s/i.test(line)) {
      const vpn = profile.vpns.find((entry) => entry.kind === "ipsec");
      if (vpn) vpn.preSharedKey = true;
      pushBounded(profile.secrets, { purpose: "IKE preshared key", hashType: "cleartext PSK", line: n }, MAX_SECRETS);
      continue;
    }
  }

  if (services.length > 0) {
    // keep a bounded sample of raw system services for display
    for (const [index, svc] of services.slice(0, 64).entries()) {
      addService(`junos: ${svc.slice(0, 120)}`, true, profile.services[index]?.line ?? 1);
    }
  }
  void currentAcl;

  if (profile.vlans.length > 0 || profile.interfaces.some((iface) => iface.mode === "access" || iface.mode === "trunk")) {
    profile.deviceType = "switch";
  } else if (profile.routingProtocols.length > 0 || profile.staticRoutes.length > 0) {
    profile.deviceType = profile.vpns.length > 0 ? "firewall" : "router";
  }
  if (/^set\s+security\s+zones/i.test(text) || /srx/i.test(text.slice(0, 4096).toLowerCase())) {
    profile.deviceType = "firewall";
  }
  return profile;
}

// ---- Palo Alto PAN-OS (set style + light XML) -------------------------------------

function parsePanos(text: string): ParsedNetworkConfig {
  const lines = toLines(text);
  const profile = emptyProfile("palo-alto");
  profile.configLines = lines.length;
  const isXml = /<config[^>]*version=/i.test(text.slice(0, 8192));

  if (isXml) {
    // Light XML extraction: hostname, version, security rules, interface entries.
    profile.hostname = clean(/<hostname>([^<]+)<\/hostname>/i.exec(text)?.[1]);
    profile.osVersion = clean(/<config[^>]*version="([^"]+)"/i.exec(text)?.[1]);
    const ruleBlocks = text.match(/<entry name="([^"]+)">(?:(?!<\/entry>)[\s\S]){0,4000}?<\/entry>/g) ?? [];
    for (const block of ruleBlocks.slice(0, MAX_FW_RULES)) {
      const name = /<entry name="([^"]+)">/.exec(block)?.[1] ?? "rule";
      if (!/<action>/.test(block)) continue; // heuristics: security rules carry <action>
      const action = /<action>(?:<member>)?([^<]+)/i.exec(block)?.[1] ?? null;
      const from = /<from>(?:<member>)?([^<]+)/i.exec(block)?.[1] ?? null;
      const to = /<to>(?:<member>)?([^<]+)/i.exec(block)?.[1] ?? null;
      const source = /<source>(?:<member>)?([^<]+)/i.exec(block)?.[1] ?? null;
      const destination = /<destination>(?:<member>)?([^<]+)/i.exec(block)?.[1] ?? null;
      const service = /<service>(?:<member>)?([^<]+)/i.exec(block)?.[1] ?? null;
      pushBounded(
        profile.firewallRules,
        {
          id: name,
          name: clean(name),
          srcIntf: clean(from),
          dstIntf: clean(to),
          source: clean(source),
          destination: clean(destination),
          service: clean(service),
          action: clean(action),
          log: null,
          line: 0,
        },
        MAX_FW_RULES,
      );
    }
    if (/<mgt-config>/i.test(text)) {
      const admin = /<users>\s*<entry name="([^"]+)"/i.exec(text)?.[1];
      if (admin) {
        pushBounded(profile.users, { name: admin, role: "superuser?", hashType: "phash (PBKDF2)", line: 0 }, MAX_USERS);
      }
    }
    profile.hostname = profile.hostname ?? "panos-xml";
    return profile;
  }

  for (const { n, text: line } of lines) {
    let match = /^set\s+(?:deviceconfig\s+)?system\s+hostname\s+(\S+)/i.exec(line);
    if (match) {
      profile.hostname = clean(match[1]);
      continue;
    }
    match = /^set\s+deviceconfig\s+system\s+ip-address\s+(\S+)/i.exec(line);
    if (match) {
      profile.model = profile.model;
      continue;
    }
    match = /^set\s+mgt-config\s+users\s+(\S+)\s+(password|phash)/i.exec(line);
    if (match) {
      pushBounded(
        profile.users,
        {
          name: clean(match[1]) ?? "admin",
          role: "admin",
          hashType: /phash/i.test(match[2]) ? "PBKDF2 phash" : "cleartext",
          line: n,
        },
        MAX_USERS,
      );
      continue;
    }
    match = /^set\s+deviceconfig\s+system\s+ntp-servers\s+(?:primary-ntp|secondary-ntp)\s+ntp-server-address\s+(\S+)/i.exec(line);
    if (match) {
      const server = clean(match[1]);
      if (server) pushBounded(profile.ntp.servers, server, 16);
      if (profile.ntp.line === null) profile.ntp.line = n;
      continue;
    }
    match = /^set\s+deviceconfig\s+system\s+snmp-setting\s+access\s+version\s+v3/i.exec(line);
    if (match) {
      profile.snmp.enabled = true;
      profile.snmp.v3Configured = true;
      if (profile.snmp.line === null) profile.snmp.line = n;
      continue;
    }
    if (/^set\s+deviceconfig\s+system\s+service\s+/i.test(line)) {
      // `set deviceconfig system service disable-telnet yes` / `disable-http yes`
      const lower = line.toLowerCase();
      if (/disable-telnet/.test(lower)) profile.management.telnetEnabled = !/\byes\b/.test(lower);
      if (/disable-http/.test(lower)) profile.management.httpEnabled = !/\byes\b/.test(lower);
      continue;
    }
    match = /^set\s+deviceconfig\s+setting\s+management\s+admin-lockout\s+failed-attempts\s+(\d+)\s+lockout-time\s+(\d+)/i.exec(line);
    if (match) {
      profile.management.loginBlockFor = `${match[1]} attempts / ${match[2]} min`;
      continue;
    }
    // interfaces
    match = /^set\s+network\s+interface\s+ethernet\s+(\S+)\s+layer3\s+ip\s+(\S+)/i.exec(line);
    if (match) {
      let iface = profile.interfaces.find((entry) => entry.name === match![1]);
      if (!iface) {
        iface = {
          name: match[1],
          line: n,
          description: null,
          ipAddress: null,
          adminEnabled: null,
          mode: "routed",
          accessVlan: null,
          nativeVlan: null,
          allowedVlans: null,
          aclIn: null,
          aclOut: null,
          portSecurity: null,
          bpduGuard: null,
          portfast: null,
          stormControl: null,
          speedDuplex: null,
          nameif: null,
          securityLevel: null,
        };
        pushBounded(profile.interfaces, iface, MAX_INTERFACES);
      }
      iface.ipAddress = clean(match[2]);
      continue;
    }
    match = /^set\s+network\s+interface\s+ethernet\s+(\S+)\s+comment\s+(.+)$/i.exec(line);
    if (match) {
      const iface = profile.interfaces.find((entry) => entry.name === match![1]);
      if (iface) iface.description = clean(match[2]);
      continue;
    }
    match = /^set\s+zone\s+(?:network\s+)?zone\s+(\S+)\s+network\s+layer3\s*(.*)$/i.exec(line);
    if (match) {
      const zone = match[1];
      const members = (match[2] ?? "").split(/[\s[\]]+/).filter(Boolean);
      for (const member of members.slice(0, 64)) {
        const iface = profile.interfaces.find((entry) => entry.name === member);
        if (iface) iface.nameif = clean(zone);
      }
      continue;
    }
    // security rules â€” PAN-OS exports one segment per line, but interactive
    // `set` lines can pack several segments; split on the segment keywords.
    const packedRule = /^set\s+rulebase\s+security\s+rules\s+\S+/i.test(line)
      ? line.split(/\s+(?=from\s|to\s|source\s|destination\s|service\s|action\s|log-setting\s)/i)
      : null;
    if (packedRule && packedRule.length > 1) {
      const idMatch = /^set\s+rulebase\s+security\s+rules\s+(\S+)/i.exec(packedRule[0]);
      const ruleId = idMatch?.[1] ?? `pan-${n}`;
      let rule = profile.firewallRules.find((entry) => entry.id === ruleId);
      if (!rule) {
        rule = { id: ruleId, name: clean(ruleId), srcIntf: null, dstIntf: null, source: null, destination: null, service: null, action: null, log: null, line: n };
        pushBounded(profile.firewallRules, rule, MAX_FW_RULES);
      }
      for (const segment of packedRule.slice(1)) {
        let segmentMatch = /^from\s+(.+)$/i.exec(segment);
        if (segmentMatch) {
          rule.srcIntf = clean(segmentMatch[1].replace(/[\[\]]/g, ""));
          continue;
        }
        segmentMatch = /^to\s+(.+)$/i.exec(segment);
        if (segmentMatch) {
          rule.dstIntf = clean(segmentMatch[1].replace(/[\[\]]/g, ""));
          continue;
        }
        segmentMatch = /^source\s+(.+)$/i.exec(segment);
        if (segmentMatch) {
          rule.source = clean(segmentMatch[1].replace(/[\[\]]/g, ""));
          continue;
        }
        segmentMatch = /^destination\s+(.+)$/i.exec(segment);
        if (segmentMatch) {
          rule.destination = clean(segmentMatch[1].replace(/[\[\]]/g, ""));
          continue;
        }
        segmentMatch = /^service\s+(.+)$/i.exec(segment);
        if (segmentMatch) {
          rule.service = clean(segmentMatch[1].replace(/[\[\]]/g, ""));
          continue;
        }
        segmentMatch = /^action\s+(\S+)/i.exec(segment);
        if (segmentMatch) {
          rule.action = clean(segmentMatch[1]);
          continue;
        }
        segmentMatch = /^log-setting\s+(\S+)/i.exec(segment);
        if (segmentMatch) rule.log = true;
      }
      continue;
    }
    // NAT rules
    if (/^set\s+rulebase\s+nat\s+rules\s/i.test(line)) {
      const name = /^set\s+rulebase\s+nat\s+rules\s+(\S+)/i.exec(line)?.[1] ?? null;
      const existing = profile.natRules.find((entry) => entry.id === name);
      if (!existing) {
        pushBounded(profile.natRules, { id: name, description: line.trim().slice(0, 200), line: n }, MAX_NAT_RULES);
      }
      continue;
    }
    // logging / syslog
    if (/^set\s+shared\s+log-settings\s+syslog/i.test(line) || /^set\s+system\s+log-settings/i.test(line)) {
      profile.logging.enabled = true;
      if (profile.logging.line === null) profile.logging.line = n;
      continue;
    }
    // ike
    match = /^set\s+network\s+ike\s+crypto-profiles\s+ike-crypto-profiles\s+(\S+)\s+(encryption|hash|dh-group)\s+(\S+)/i.exec(line);
    if (match) {
      let vpn = profile.vpns.find((entry) => entry.name === match![1]);
      if (!vpn) {
        vpn = { kind: "ipsec", name: match[1], encryption: [], auth: [], dhGroup: null, preSharedKey: false, aggressiveMode: false, line: n };
        pushBounded(profile.vpns, vpn, MAX_VPNS);
      }
      if (match[2] === "encryption") vpn.encryption.push(match[3].toLowerCase());
      else if (match[2] === "hash") vpn.auth.push(match[3].toLowerCase());
      else vpn.dhGroup = match[3];
      continue;
    }
    match = /^set\s+network\s+ike\s+gateway\s+\S+\s+authentication\s+pre-shared-key\s+key\s+\S+/i.exec(line);
    if (match) {
      const vpn = profile.vpns[profile.vpns.length - 1];
      if (vpn) vpn.preSharedKey = true;
      pushBounded(profile.secrets, { purpose: "IKE preshared key", hashType: "cleartext PSK", line: n }, MAX_SECRETS);
      continue;
    }
  }

  if (profile.firewallRules.length > 0) {
    // default-route style: ensure at least identity presence
    profile.hostname = profile.hostname ?? "panos";
  }
  return profile;
}

// ---- Fortinet FortiGate ---------------------------------------------------------

function parseFortios(text: string): ParsedNetworkConfig {
  const lines = toLines(text);
  const profile = emptyProfile("fortinet");
  profile.configLines = lines.length;

  let path: string[] = [];
  let currentUser: ParsedUser | null = null;
  let currentRule: ParsedFirewallRule | null = null;
  let currentIface: ParsedInterface | null = null;
  let currentCommunity: ParsedSnmpCommunity | null = null;
  let currentVpn: ParsedVpn | null = null;

  for (const { n, text: line, lower } of lines) {
    const trimmed = line.trim();

    // comments carry model/version info: "#config-version=FGT60E-4.0.6-FW-build0161..."
    // (older builds use a "v" prefix: "#config-version=FGT-KVM-v7.0.3-FW-...")
    const configVersion = /^#config-version=([\w-]+?)-v?(\d[\d.]*)-/i.exec(trimmed) ?? /^#\s*(FortiGate-\S+)/i.exec(trimmed);
    if (configVersion) {
      profile.model = profile.model ?? clean(configVersion[1]);
      profile.osVersion = profile.osVersion ?? clean(configVersion[2] ?? null);
      continue;
    }
    if (trimmed.startsWith("#")) {
      const model = /device:\s*(\S+)/i.exec(trimmed) ?? /(FortiGate[\w-]*)/i.exec(trimmed);
      if (model && !profile.model) profile.model = clean(model[1]);
      continue;
    }

    if (/^config\s+/i.test(trimmed)) {
      path = trimmed.replace(/^config\s+/i, "").split(/\s+/);
      currentUser = null;
      currentRule = null;
      currentIface = null;
      currentCommunity = null;
      currentVpn = null;
      continue;
    }
    if (/^end$/i.test(trimmed)) {
      path = [];
      currentUser = null;
      currentRule = null;
      currentIface = null;
      currentCommunity = null;
      currentVpn = null;
      continue;
    }
    const editMatch = /^edit\s+"?([^"\s]+)"?$/i.exec(trimmed);
    if (editMatch) {
      const section = path.join(" ");
      if (/^system global$/i.test(section)) continue;
      if (/^system admin$/i.test(section)) {
        currentUser = { name: editMatch[1], role: null, hashType: "unknown", line: n };
        pushBounded(profile.users, currentUser, MAX_USERS);
      } else if (/^system interface$/i.test(section)) {
        currentIface = {
          name: editMatch[1],
          line: n,
          description: null,
          ipAddress: null,
          adminEnabled: null,
          mode: "unknown",
          accessVlan: null,
          nativeVlan: null,
          allowedVlans: null,
          aclIn: null,
          aclOut: null,
          portSecurity: null,
          bpduGuard: null,
          portfast: null,
          stormControl: null,
          speedDuplex: null,
          nameif: null,
          securityLevel: null,
        };
        pushBounded(profile.interfaces, currentIface, MAX_INTERFACES);
      } else if (/^firewall policy(6)?$/i.test(section)) {
        currentRule = { id: editMatch[1], name: null, srcIntf: null, dstIntf: null, source: null, destination: null, service: null, action: null, log: null, line: n };
        pushBounded(profile.firewallRules, currentRule, MAX_FW_RULES);
      } else if (/^system snmp community$/i.test(section)) {
        currentCommunity = { value: "", access: "ro", acl: null, line: n };
        pushBounded(profile.snmp.communities, currentCommunity, 64);
        profile.snmp.enabled = true;
        if (profile.snmp.line === null) profile.snmp.line = n;
      } else if (/^vpn ipsec phase1(-interface)?$/i.test(section)) {
        currentVpn = { kind: "ipsec", name: editMatch[1], encryption: [], auth: [], dhGroup: null, preSharedKey: false, aggressiveMode: false, line: n };
        pushBounded(profile.vpns, currentVpn, MAX_VPNS);
      } else if (/^router static$/i.test(section)) {
        // handled via `set dst`/`set gateway` below
      }
      continue;
    }
    if (/^next$/i.test(trimmed) || /^unset\s+/i.test(trimmed)) {
      continue;
    }

    const setMatch = /^set\s+(\S+)\s*(.*)$/i.exec(trimmed);
    if (!setMatch) continue;
    const key = setMatch[1].toLowerCase();
    const value = (setMatch[2] ?? "").replace(/^"|"$/g, "").trim();
    const section = path.join(" ");

    if (/^system global$/i.test(section)) {
      if (key === "hostname") profile.hostname = clean(value);
      if (key === "alias") profile.hostname = profile.hostname ?? clean(value);
      continue;
    }
    if (/^system admin$/i.test(section) && currentUser) {
      if (key === "password") currentUser.hashType = /^ENC\b/i.test(value) ? "vendor-encrypted (ENC)" : "cleartext";
      if (key === "accprofile") currentUser.role = clean(value);
      if (key.startsWith("trusthost")) {
        if (value && profile.management.mgmtHosts.length < 32) profile.management.mgmtHosts.push(value);
      }
      continue;
    }
    if (/^system interface$/i.test(section) && currentIface) {
      if (key === "ip") currentIface.ipAddress = clean(value);
      if (key === "mode") {
        /* static/dhcp */
      }
      if (key === "allowaccess") {
        const access = value.toLowerCase().split(/\s+/).filter(Boolean);
        currentIface.mode = "unknown";
        profile.management.allowAccess.push(...access.slice(0, 16).map((token) => `${currentIface?.name}:${token}`));
        if (access.includes("telnet")) profile.management.telnetEnabled = true;
        if (access.includes("ssh")) profile.management.sshEnabled = true;
        if (access.includes("http")) profile.management.httpEnabled = true;
        if (access.includes("https")) profile.management.httpsEnabled = true;
        if (access.includes("snmp")) profile.snmp.enabled = true;
        if (access.includes("ping")) currentIface.mode = "unknown";
      }
      if (key === "role") currentIface.description = `role: ${value}`;
      if (key === "status" && value.toLowerCase() === "down") currentIface.adminEnabled = false;
      continue;
    }
    if (/^firewall policy/i.test(section) && currentRule) {
      if (key === "name") currentRule.name = clean(value);
      if (key === "srcintf") currentRule.srcIntf = clean(value.replace(/^"|"$/g, ""));
      if (key === "dstintf") currentRule.dstIntf = clean(value.replace(/^"|"$/g, ""));
      if (key === "srcaddr") currentRule.source = clean(value.replace(/^"|"$/g, ""));
      if (key === "dstaddr") currentRule.destination = clean(value.replace(/^"|"$/g, ""));
      if (key === "service") currentRule.service = clean(value.replace(/^"|"$/g, ""));
      if (key === "action") currentRule.action = clean(value);
      if (key === "logtraffic") currentRule.log = !/disable/i.test(value);
      if (key === "nat") {
        /* nat enable/disable */
      }
      continue;
    }
    if (/^system snmp community$/i.test(section) && currentCommunity) {
      if (key === "name") currentCommunity.value = value;
      if (key === "status" && value.toLowerCase() === "disable") currentCommunity.access = "unknown";
      if (key.startsWith("host")) currentCommunity.acl = clean(value);
      continue;
    }
    if (/^vpn ipsec phase1/i.test(section) && currentVpn) {
      if (key === "proposal") currentVpn.encryption.push(...value.toLowerCase().split(/\s+/).slice(0, 16));
      if (key === "psktype" || key === "authmethod") {
        if (/psk/i.test(value)) currentVpn.preSharedKey = true;
      }
      if (key === "peer" || key === "peertype") {
        /* certificate auth when peertype=one + peer cert */
      }
      if (key === "dhgrp") currentVpn.dhGroup = clean(value);
      if (key === "passive-mode") {
        /* ignore */
      }
      continue;
    }
    if (/^router static$/i.test(section)) {
      if (key === "dst") {
        const gw = "";
        pushBounded(profile.staticRoutes, { destination: value || "default", nextHop: gw || "(set gateway follows)", line: n }, MAX_ROUTES);
      }
      if (key === "gateway" || key === "device") {
        const last = profile.staticRoutes[profile.staticRoutes.length - 1];
        if (last && (last.nextHop === "(set gateway follows)" || key === "gateway")) {
          last.nextHop = [value, last.nextHop === "(set gateway follows)" ? null : last.nextHop].filter(Boolean).join(" via ") || value;
        }
      }
      continue;
    }
    if (/^system ntp$/i.test(section)) {
      if (key === "ntpsync" && value.toLowerCase() === "enable") {
        if (profile.ntp.line === null) profile.ntp.line = n;
      }
      if (key.startsWith("server")) {
        const server = clean(value);
        if (server) pushBounded(profile.ntp.servers, server, 16);
        if (profile.ntp.line === null) profile.ntp.line = n;
      }
      continue;
    }
    if (/^log syslogd setting$/i.test(section)) {
      if (key === "status" && value.toLowerCase() === "enable") {
        profile.logging.enabled = true;
        if (profile.logging.line === null) profile.logging.line = n;
      }
      if (key === "server") {
        const host = clean(value);
        if (host) pushBounded(profile.logging.hosts, host, 16);
      }
      continue;
    }
    if (/^system dns$/i.test(section)) {
      /* dns servers */
      continue;
    }
    if (/^system settings$/i.test(section) || /^system global$/i.test(section)) {
      if (key === "admin-sport" || key === "admin-sport https") {
        /* mgmt port */
      }
      continue;
    }
    if (/^vpn ssl settings$/i.test(section)) {
      const vpn: ParsedVpn = {
        kind: "ssl",
        name: "ssl-vpn",
        encryption: [],
        auth: [],
        dhGroup: null,
        preSharedKey: false,
        aggressiveMode: false,
        line: n,
      };
      if (key === "status" && value.toLowerCase() === "enable") {
        if (!profile.vpns.some((entry) => entry.kind === "ssl")) pushBounded(profile.vpns, vpn, MAX_VPNS);
      }
      continue;
    }
    if (/^system ha$/i.test(section) || /^system virtual-wan-link$/i.test(section)) {
      void key;
      continue;
    }
    void lower;
  }

  // a default route often appears as `set dst ""` meaning 0.0.0.0/0
  if (profile.staticRoutes.length === 0 && /set gateway\s/i.test(text)) {
    pushBounded(profile.staticRoutes, { destination: "default", nextHop: "see config", line: 0 }, MAX_ROUTES);
  }
  return profile;
}

// ---- Aruba switch (AOS-CX / ProCurve) --------------------------------------------

function parseArubaSwitch(text: string): ParsedNetworkConfig {
  const lines = toLines(text);
  const profile = emptyProfile("aruba-switch");
  profile.configLines = lines.length;

  let currentIface: ParsedInterface | null = null;
  let currentVlan: ParsedVlan | null = null;

  const newIface = (name: string, line: number): ParsedInterface => ({
    name,
    line,
    description: null,
    ipAddress: null,
    adminEnabled: null,
    mode: "unknown",
    accessVlan: null,
    nativeVlan: null,
    allowedVlans: null,
    aclIn: null,
    aclOut: null,
    portSecurity: null,
    bpduGuard: null,
    portfast: null,
    stormControl: null,
    speedDuplex: null,
    nameif: null,
    securityLevel: null,
  });

  for (const { n, text: line, lower } of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith(";")) {
      const header = /^;\s*(\S+ \S* Configuration Editor.*?|\S+.*?Software version\s+\S+)/i.exec(trimmed);
      if (header && !profile.model) {
        profile.model = clean(trimmed.replace(/^;\s*/, "").slice(0, 120));
      }
      const version = /;\s*\S+\s+Software version\s+(\S+)/i.exec(trimmed);
      if (version && !profile.osVersion) profile.osVersion = clean(version[1]);
      continue;
    }

    let match = /^hostname\s+"?([^"\s]+)"?/i.exec(trimmed);
    if (match) {
      profile.hostname = clean(match[1]);
      continue;
    }

    // users
    match = /^(?:password\s+(?:manager|operator)\s+user-name\s+(\S+))\s+(.*)$/i.exec(trimmed);
    if (match) {
      const rest = match[2] ?? "";
      const hashType = /plaintext/i.test(rest) ? "cleartext" : /hashed|sha-?\d*/i.test(rest) ? "hashed" : classifyHash(rest.split(/\s+/)[0]);
      pushBounded(profile.users, { name: clean(match[1]) ?? "manager", role: match[0].includes("manager") ? "manager" : "operator", hashType, line: n }, MAX_USERS);
      continue;
    }
    match = /^user\s+(\S+)\s+group\s+(\S+)\s+password\s+(ciphertext|plaintext|hashed)\s+(\S+)/i.exec(trimmed);
    if (match) {
      pushBounded(
        profile.users,
        {
          name: clean(match[1]) ?? "unknown",
          role: match[2],
          hashType: match[3].toLowerCase() === "ciphertext" ? "vendor-encrypted" : match[3].toLowerCase() === "plaintext" ? "cleartext" : "hashed",
          line: n,
        },
        MAX_USERS,
      );
      continue;
    }
    match = /^(?:password\s+(?:manager|operator))\s+(?:plaintext|sha-?\d*|hashed)\s+(\S+)/i.exec(trimmed);
    if (match) {
      pushBounded(profile.secrets, { purpose: "switch manager/operator password", hashType: /plaintext/i.test(line) ? "cleartext" : "hashed", line: n }, MAX_SECRETS);
      continue;
    }

    // snmp
    match = /^snmp-server community\s+"([^"]*)"\s+(\S+)(.*)$/i.exec(trimmed);
    if (match) {
      profile.snmp.enabled = true;
      if (profile.snmp.line === null) profile.snmp.line = n;
      const access = /unrestricted|manager/i.test(match[2]) ? "rw" : /operator/i.test(match[2]) ? "ro" : "unknown";
      pushBounded(profile.snmp.communities, { value: match[1], access, acl: match[3]?.trim() || null, line: n }, 64);
      continue;
    }
    if (/^snmpv3 (?:enable|user|only)/i.test(trimmed)) {
      profile.snmp.v3Configured = true;
      profile.snmp.enabled = true;
      continue;
    }

    // mgmt services
    if (/^telnet-server enable/i.test(trimmed)) {
      profile.management.telnetEnabled = true;
      continue;
    }
    if (/^no telnet-server/i.test(trimmed)) {
      profile.management.telnetEnabled = false;
      continue;
    }
    if (/^web-management (plaintext|enable)$/i.test(trimmed)) {
      profile.management.httpEnabled = true;
      continue;
    }
    if (/^no web-management/i.test(trimmed)) {
      profile.management.httpEnabled = false;
      continue;
    }
    if (/^web-management ssl/i.test(trimmed)) profile.management.httpsEnabled = true;
    if (/^ip authorized-managers?/i.test(trimmed)) {
      const host = /^ip authorized-managers?\s+([0-9.]+)/i.exec(trimmed)?.[1];
      if (host && profile.management.mgmtHosts.length < 32) profile.management.mgmtHosts.push(host);
      continue;
    }
    if (/^ip (?:default-gateway|route)\s+(\S+)\s+(\S+)/i.test(trimmed)) {
      pushBounded(profile.staticRoutes, { destination: /^ip route/.test(trimmed) ? match![1] : "0.0.0.0/0 (default)", nextHop: match![2], line: n }, MAX_ROUTES);
      continue;
    }
    if (/^ip dns/i.test(trimmed)) continue;
    match = /^(?:time|sntp|ntp)\s+(?:server|ntp)\s+(\S+)/i.exec(trimmed) ?? /^sntp server\s+(\S+)/i.exec(trimmed);
    if (match) {
      const server = clean(match[1]);
      if (server) pushBounded(profile.ntp.servers, server, 16);
      if (profile.ntp.line === null) profile.ntp.line = n;
      continue;
    }
    if (/^timesync sntp|^sntp unicast/i.test(trimmed)) {
      if (profile.ntp.line === null) profile.ntp.line = n;
      continue;
    }
    match = /^logging\s+(\d+\.\d+\.\d+\.\d+)/i.exec(trimmed);
    if (match) {
      profile.logging.enabled = true;
      const host = clean(match[1]);
      if (host) pushBounded(profile.logging.hosts, host, 16);
      if (profile.logging.line === null) profile.logging.line = n;
      continue;
    }
    if (/^aaa port-access|dot1x/i.test(trimmed)) profile.services.push({ name: `802.1X: ${trimmed.slice(0, 80)}`, enabled: true, line: n });

    // vlan blocks
    match = /^vlan\s+(\d+)\s*$/i.exec(trimmed);
    if (match) {
      currentVlan = { id: match[1], name: null, line: n };
      pushBounded(profile.vlans, currentVlan, MAX_VLANS);
      currentIface = null;
      continue;
    }
    match = /^vlan\s+(\d+)\s+name\s+"?([^"\s].*?)"?\s*$/i.exec(trimmed);
    if (match) {
      currentVlan = { id: match[1], name: clean(match[2]), line: n };
      pushBounded(profile.vlans, currentVlan, MAX_VLANS);
      currentIface = null;
      continue;
    }
    if (currentVlan) {
      match = /^\s*name\s+"?([^"\n]+?)"?\s*$/i.exec(line);
      if (match) {
        currentVlan.name = clean(match[1]);
        continue;
      }
      // ProCurve port membership: `untagged 1-4` / `tagged 10`
      match = /^\s*(untagged|tagged)\s+([\d,\-\/]+)\s*$/i.exec(line);
      if (match) {
        const mode = match[1].toLowerCase() === "untagged" ? "access" : "trunk";
        for (const port of expandPortList(match[2]).slice(0, 64)) {
          let iface = profile.interfaces.find((entry) => entry.name === port);
          if (!iface) {
            iface = newIface(port, n);
            pushBounded(profile.interfaces, iface, MAX_INTERFACES);
          }
          if (mode === "access") {
            iface.accessVlan = iface.accessVlan ?? currentVlan.id;
            iface.mode = "access";
          } else if (iface.mode !== "access") {
            iface.mode = "trunk";
          }
        }
        continue;
      }
      if (/^\s*ip address\s+(\S+)\s+(\S+)/i.test(trimmed)) {
        // vlan L3 address â€” track on vlan pseudo-interface
        const ipMatch = /^\s*ip address\s+(\S+)\s+(\S+)/i.exec(line);
        const name = `vlan${currentVlan.id}`;
        let iface = profile.interfaces.find((entry) => entry.name === name);
        if (!iface) {
          iface = newIface(name, n);
          pushBounded(profile.interfaces, iface, MAX_INTERFACES);
        }
        iface.ipAddress = ipMatch ? `${ipMatch[1]} ${ipMatch[2]}` : null;
        iface.mode = "routed";
        continue;
      }
    }

    // interface blocks (AOS-CX style)
    match = /^interface\s+([\w\/\.\-]+)\s*$/i.exec(trimmed);
    if (match) {
      currentIface = profile.interfaces.find((entry) => entry.name === match![1]) ?? newIface(match[1], n);
      if (!profile.interfaces.includes(currentIface)) pushBounded(profile.interfaces, currentIface, MAX_INTERFACES);
      currentVlan = null;
      continue;
    }
    if (currentIface) {
      match = /^\s*(?:no\s+)?shutdown\s*$/i.exec(trimmed);
      if (match) {
        currentIface.adminEnabled = !/^\s*no\s+shutdown/i.test(line) && !/^no shutdown/i.test(trimmed) ? false : true;
        if (/^no shutdown/i.test(trimmed)) currentIface.adminEnabled = true;
        else if (/^shutdown/i.test(trimmed)) currentIface.adminEnabled = false;
        continue;
      }
      match = /^\s*description\s+"?([^"\n]+?)"?\s*$/i.exec(trimmed);
      if (match) {
        currentIface.description = clean(match[1]);
        continue;
      }
      match = /^\s*vlan access\s+(\d+)/i.exec(trimmed);
      if (match) {
        currentIface.accessVlan = match[1];
        currentIface.mode = "access";
        continue;
      }
      match = /^\s*vlan trunk (?:native-?vlan|native)\s+(\d+)/i.exec(trimmed);
      if (match) {
        currentIface.nativeVlan = match[1];
        currentIface.mode = "trunk";
        continue;
      }
      match = /^\s*vlan trunk allowed\s+(.*)$/i.exec(trimmed);
      if (match) {
        currentIface.allowedVlans = clean(match[1]);
        currentIface.mode = "trunk";
        continue;
      }
      if (/^\s*port-security/i.test(trimmed)) currentIface.portSecurity = !/^no\s/i.test(trimmed);
      if (/^\s*dhcpv4-snooping|^\s*arp-protection/i.test(trimmed)) currentIface.stormControl = currentIface.stormControl ?? null;
      match = /^\s*(?:speed|speed-duplex)\s+(\S+)/i.exec(trimmed);
      if (match) currentIface.speedDuplex = clean(match[1]);
      continue;
    }

    // global switching
    if (/^dhcpv4-snooping$/i.test(trimmed)) profile.services.push({ name: "dhcp snooping", enabled: true, line: n });
    if (/^dhcpv4-snooping vlan/i.test(trimmed)) profile.services.push({ name: "dhcp snooping vlan", enabled: true, line: n });
    if (/^qos|storm-control/i.test(trimmed) && /^storm-control/i.test(trimmed)) {
      profile.services.push({ name: "storm-control", enabled: true, line: n });
    }
    void lower;
  }

  if (profile.osVersion === null && /version\s+(\S+)/i.test(text.slice(0, 4096))) {
    profile.osVersion = clean(/;\s*\S+\s+Software version\s+(\S+)/i.exec(text)?.[1] ?? null);
  }
  return profile;
}

/** Expands `1-4,7,10-12` style port lists. */
function expandPortList(value: string): string[] {
  const out: string[] = [];
  for (const part of value.split(",")) {
    const range = /^(\d+)-(\d+)$/.exec(part.trim());
    if (range) {
      const start = Number(range[1]);
      const end = Math.min(Number(range[2]), start + 255);
      for (let port = start; port <= end; port += 1) out.push(String(port));
    } else if (/^[\d\/\.]+$/.test(part.trim())) {
      out.push(part.trim());
    }
  }
  return out;
}

// ---- ArubaOS wireless (IAP / controller) ------------------------------------------

function parseArubaOs(text: string): ParsedNetworkConfig {
  const lines = toLines(text);
  const profile = emptyProfile("arubaos");
  profile.configLines = lines.length;

  let currentSsid: ParsedWlan | null = null;

  for (const { n, text: line, lower } of lines) {
    const trimmed = line.trim();
    let match = /^virtual-controller-country\s+(\S+)/i.exec(trimmed);
    if (match) {
      profile.model = profile.model ?? "Instant AP";
      continue;
    }
    match = /^(?:name|hostname)\s+(\S+)/i.exec(trimmed);
    if (match && !profile.hostname && !/^name\s+server/i.test(trimmed)) {
      profile.hostname = clean(match[1]);
      continue;
    }
    match = /^mgmt-user\s+(\S+)\s+(\S+)/i.exec(trimmed);
    if (match) {
      pushBounded(
        profile.users,
        { name: clean(match[1]) ?? "admin", role: "mgmt", hashType: /^<|\s+cleartext/i.test(line) || !/^\w{8,}$/.test(match[2]) ? "cleartext or pbkdf2" : "hashed", line: n },
        MAX_USERS,
      );
      continue;
    }
    match = /^wlan ssid-profile\s+(\S+)/i.exec(trimmed);
    if (match) {
      currentSsid = { ssid: match[1], profile: match[1], authMode: "unknown", psk: false, line: n };
      pushBounded(profile.wirelessLans, currentSsid, MAX_WLANS);
      continue;
    }
    if (currentSsid) {
      match = /^\s*essid\s+(\S+)/i.exec(trimmed);
      if (match) {
        currentSsid.ssid = match[1].replace(/^"|"$/g, "");
        continue;
      }
      match = /^\s*opmode\s+(.+)$/i.exec(trimmed);
      if (match) {
        const opmode = match[1].toLowerCase();
        currentSsid.authMode = opmode;
        currentSsid.psk = /psk/.test(opmode);
        continue;
      }
      match = /^\s*wpa-passphrase\s+(\S+)/i.exec(trimmed);
      if (match) {
        currentSsid.psk = true;
        pushBounded(profile.secrets, { purpose: `wpa passphrase (${currentSsid.ssid})`, hashType: "cleartext PSK", line: n }, MAX_SECRETS);
        continue;
      }
      if (/^\s*wep-key/i.test(trimmed)) {
        currentSsid.authMode = "wep";
        pushBounded(profile.secrets, { purpose: `wep key (${currentSsid.ssid})`, hashType: "cleartext WEP", line: n }, MAX_SECRETS);
        continue;
      }
    }
    if (/^wlan virtual-ap/i.test(trimmed)) {
      currentSsid = null;
      continue;
    }
    match = /^openai-??/i.exec(trimmed);
    if (match) continue;
    // radius / auth servers
    match = /^auth-server\s+(\S+)/i.exec(trimmed) ?? /^radius-server\s+host\s+(\S+)/i.exec(trimmed);
    if (match) {
      const host = clean(match[1]);
      if (host) pushBounded(profile.aaa.radiusHosts, host, 32);
      continue;
    }
    if (/^wlan auth-server/i.test(trimmed)) {
      const host = /^wlan auth-server\s+(\S+)/i.exec(trimmed)?.[1];
      if (host) pushBounded(profile.aaa.radiusHosts, host, 32);
      continue;
    }
    match = /^ntp server\s+(\S+)/i.exec(trimmed);
    if (match) {
      const server = clean(match[1]);
      if (server) pushBounded(profile.ntp.servers, server, 16);
      if (profile.ntp.line === null) profile.ntp.line = n;
      continue;
    }
    match = /^syslog-server\s+(\S+)/i.exec(trimmed);
    if (match) {
      profile.logging.enabled = true;
      const host = clean(match[1]);
      if (host) pushBounded(profile.logging.hosts, host, 16);
      if (profile.logging.line === null) profile.logging.line = n;
      continue;
    }
    // arm/acl minimal
    if (/^wlan access-rule/i.test(trimmed)) {
      profile.acls.push({
        name: /^wlan access-rule\s+(\S+)/i.exec(trimmed)?.[1] ?? "access-rule",
        type: "extended",
        appliedTo: ["wlan"],
        rules: [],
        line: n,
      });
      continue;
    }
    void lower;
  }

  if (profile.wirelessLans.length > 0) profile.deviceType = "wireless-controller";
  return profile;
}

// ---- Cisco WLC AireOS -------------------------------------------------------------

function parseWlcAireos(text: string): ParsedNetworkConfig {
  const lines = toLines(text);
  const profile = emptyProfile("cisco-wlc");
  profile.configLines = lines.length;

  for (const { n, text: line, lower } of lines) {
    const trimmed = line.replace(/^\(Cisco Controller\)\s*>?/i, "").trim();
    let match = /^sysname\s+(\S+)/i.exec(trimmed);
    if (match) {
      profile.hostname = clean(match[1]);
      continue;
    }
    // `config wlan create <id> <name> <ssid>`
    match = /^config\s+wlan\s+create\s+(\d+)\s+"?([^"\s]+)"?\s+"?([^"\s]+)"?/i.exec(trimmed);
    if (match) {
      pushBounded(profile.wirelessLans, { ssid: match[3], profile: match[2], authMode: "unknown", psk: false, line: n }, MAX_WLANS);
      continue;
    }
    // `config wlan security wpa akm 802.1X on <id>`
    if (/^config\s+wlan\s+security/i.test(trimmed) && profile.wirelessLans.length > 0) {
      const wlan = profile.wirelessLans[profile.wirelessLans.length - 1];
      if (/psk/i.test(trimmed)) {
        wlan.psk = true;
        wlan.authMode = "wpa-psk";
      } else if (/802\.1x/i.test(trimmed)) wlan.authMode = "wpa-802.1X";
      if (/wep/i.test(trimmed)) wlan.authMode = "wep";
      if (/tkip/i.test(trimmed)) wlan.authMode = `${wlan.authMode}+tkip`;
      continue;
    }
    match = /^config\s+wlan\s+disable\s+(\d+)/i.exec(trimmed);
    if (match) {
      /* disabled wlan */
      continue;
    }
    // AireOS: `config radius auth add <index> <server>` (index is positional)
    match =
      /^config\s+radius\s+(?:auth|acct)\s+add\s+\d+\s+(\S+)/i.exec(trimmed) ??
      /^config\s+radius\s+(?:auth|acct)\s+add\s+(\S+)/i.exec(trimmed);
    if (match) {
      const host = clean(match[1]);
      if (host) pushBounded(profile.aaa.radiusHosts, host, 32);
      continue;
    }
    match = /^config\s+time\s+ntp\s+server\s+(\S+)\s+(\S+)/i.exec(trimmed) ?? /^config\s+time\s+manual\s+(\S+)/i.exec(trimmed);
    if (match) {
      const server = clean(match[2] ?? match[1]);
      if (server && /\d/.test(server)) pushBounded(profile.ntp.servers, server, 16);
      if (profile.ntp.line === null) profile.ntp.line = n;
      continue;
    }
    match = /^config\s+logging\s+syslog\s+host\s+(\S+)/i.exec(trimmed);
    if (match) {
      profile.logging.enabled = true;
      const host = clean(match[1]);
      if (host) pushBounded(profile.logging.hosts, host, 16);
      if (profile.logging.line === null) profile.logging.line = n;
      continue;
    }
    if (/^config\s+network\s+telnet\s+enable/i.test(trimmed) || /^config\s+network\s+ssh\s+telnet/i.test(trimmed)) {
      profile.management.telnetEnabled = true;
      continue;
    }
    if (/^config\s+network\s+ssh\s+enable/i.test(trimmed)) profile.management.sshEnabled = true;
    if (/^config\s+snmp\s+(?:community\s+create|server\s+enable)/i.test(trimmed)) {
      profile.snmp.enabled = true;
      if (profile.snmp.line === null) profile.snmp.line = n;
      continue;
    }
    match = /^config\s+snmp\s+community\s+create\s+(ro|rw)\s+(\S+)\s+(\S+)/i.exec(trimmed);
    if (match) {
      pushBounded(
        profile.snmp.communities,
        { value: match[3], access: match[1].toLowerCase() === "ro" ? "ro" : "rw", acl: null, line: n },
        64,
      );
      continue;
    }
    match = /^config\s+interface\s+address\s+(\S+)\s+(\S+)\s+(\S+)/i.exec(trimmed);
    if (match) {
      let iface = profile.interfaces.find((entry) => entry.name === match![1]);
      if (!iface) {
        iface = {
          name: match[1],
          line: n,
          description: null,
          ipAddress: null,
          adminEnabled: null,
          mode: "unknown",
          accessVlan: null,
          nativeVlan: null,
          allowedVlans: null,
          aclIn: null,
          aclOut: null,
          portSecurity: null,
          bpduGuard: null,
          portfast: null,
          stormControl: null,
          speedDuplex: null,
          nameif: null,
          securityLevel: null,
        };
        pushBounded(profile.interfaces, iface, MAX_INTERFACES);
      }
      iface.ipAddress = `${match[2]} ${match[3]}`;
      continue;
    }
    match = /^config\s+user\s+add\s+(\S+)\s+(\S+)/i.exec(trimmed);
    if (match) {
      pushBounded(profile.users, { name: match[1], role: null, hashType: "cleartext or unknown", line: n }, MAX_USERS);
      continue;
    }
    void lower;
  }

  if (profile.wirelessLans.length > 0) profile.deviceType = "wireless-controller";
  return profile;
}

// ---- Ubiquiti EdgeOS / UniFi -------------------------------------------------------

function parseUbiquiti(text: string): ParsedNetworkConfig {
  const lines = toLines(text);
  const profile = emptyProfile("ubiquiti");
  profile.configLines = lines.length;

  for (const { n, text: line } of lines) {
    const trimmed = line.trim();
    let match = /^set\s+system\s+host-name\s+(\S+)/i.exec(trimmed);
    if (match) {
      profile.hostname = clean(match[1]);
      continue;
    }
    match = /^set\s+system\s+login\s+user\s+(\S+)\s+authentication\s+plaintext-password\s+\S+/i.exec(trimmed);
    if (match) {
      pushBounded(profile.users, { name: match[1], role: null, hashType: "cleartext", line: n }, MAX_USERS);
      continue;
    }
    match = /^set\s+system\s+login\s+user\s+(\S+)(.*)$/i.exec(trimmed);
    if (match) {
      const rest = match[2] ?? "";
      let user = profile.users.find((entry) => entry.name === match![1]);
      if (!user) {
        user = {
          name: match[1],
          role: /level\s+(\S+)/i.exec(rest)?.[1] ?? null,
          hashType: /encrypted-password/.test(rest) ? "SHA crypt" : "unknown",
          line: n,
        };
        pushBounded(profile.users, user, MAX_USERS);
      }
      if (/level\s+(\S+)/i.test(rest)) user.role = /level\s+(\S+)/i.exec(rest)?.[1] ?? user.role;
      continue;
    }
    match = /^set\s+interfaces\s+ethernet\s+(\S+)\s+address\s+(\S+)/i.exec(trimmed);
    if (match) {
      let iface = profile.interfaces.find((entry) => entry.name === match![1]);
      if (!iface) {
        iface = {
          name: match[1],
          line: n,
          description: null,
          ipAddress: null,
          adminEnabled: null,
          mode: "routed",
          accessVlan: null,
          nativeVlan: null,
          allowedVlans: null,
          aclIn: null,
          aclOut: null,
          portSecurity: null,
          bpduGuard: null,
          portfast: null,
          stormControl: null,
          speedDuplex: null,
          nameif: null,
          securityLevel: null,
        };
        pushBounded(profile.interfaces, iface, MAX_INTERFACES);
      }
      iface.ipAddress = clean(match[2]);
      continue;
    }
    match = /^set\s+interfaces\s+ethernet\s+(\S+)\s+description\s+(.+)$/i.exec(trimmed);
    if (match) {
      const iface = profile.interfaces.find((entry) => entry.name === match![1]);
      if (iface) iface.description = clean(match[2]);
      continue;
    }
    match = /^set\s+system\s+name-server\s+(\S+)/i.exec(trimmed);
    if (match) {
      /* dns */
      continue;
    }
    match = /^set\s+system\s+ntp\s+server\s+(\S+)/i.exec(trimmed);
    if (match) {
      const server = clean(match[1]);
      if (server) pushBounded(profile.ntp.servers, server, 16);
      if (profile.ntp.line === null) profile.ntp.line = n;
      continue;
    }
    match = /^set\s+system\s+syslog\s+host\s+(\S+)/i.exec(trimmed);
    if (match) {
      profile.logging.enabled = true;
      const host = clean(match[1]);
      if (host) pushBounded(profile.logging.hosts, host, 16);
      if (profile.logging.line === null) profile.logging.line = n;
      continue;
    }
    if (/^set\s+service\s+ssh(?!-)/i.test(trimmed)) profile.management.sshEnabled = true;
    if (/^set\s+service\s+telnet/i.test(trimmed)) {
      profile.management.telnetEnabled = true;
      profile.services.push({ name: "telnet (service)", enabled: true, line: n });
    }
    if (/^set\s+service\s+snmp\s+community\s+(\S+)/i.test(trimmed)) {
      profile.snmp.enabled = true;
      if (profile.snmp.line === null) profile.snmp.line = n;
      const community = /^set\s+service\s+snmp\s+community\s+(\S+)/i.exec(trimmed)?.[1] ?? "unknown";
      const existing = profile.snmp.communities.find((entry) => entry.value === community);
      if (!existing) {
        pushBounded(profile.snmp.communities, { value: community.replace(/"/g, ""), access: "ro", acl: null, line: n }, 64);
      }
      continue;
    }
    // firewall rules
    match = /^set\s+firewall\s+name\s+(\S+)\s+rule\s+(\d+)\s+action\s+(\S+)/i.exec(trimmed);
    if (match) {
      let acl = profile.acls.find((entry) => entry.name === match![1]);
      if (!acl) {
        acl = { name: match[1], type: "extended", appliedTo: [], rules: [], line: n };
        pushBounded(profile.acls, acl, MAX_ACLS);
      }
      const action = match[3].toLowerCase();
      pushBounded(acl.rules, { n, text: `rule ${match[2]} ${action}`, action: action === "accept" ? "permit" : "deny" }, MAX_ACL_RULES);
      continue;
    }
    match = /^set\s+firewall\s+name\s+(\S+)\s+rule\s+(\d+)\s+source\s+address\s+(\S+)/i.exec(trimmed);
    if (match) {
      const acl = profile.acls.find((entry) => entry.name === match![1]);
      const rule = acl?.rules[acl.rules.length - 1];
      if (rule) rule.text = `${rule.text} src ${match[3]}`;
      continue;
    }
    match = /^set\s+protocols\s+static\s+route\s+(\S+)\s+next-hop\s+(\S+)/i.exec(trimmed);
    if (match) {
      pushBounded(profile.staticRoutes, { destination: match[1], nextHop: match[2], line: n }, MAX_ROUTES);
      continue;
    }
    if (/^set\s+vpn\s+ipsec\s+ike-group\s/i.test(trimmed)) {
      let vpn = profile.vpns.find((entry) => entry.kind === "ipsec" && entry.name === "ike groups");
      if (!vpn) {
        vpn = { kind: "ipsec", name: "ike groups", encryption: [], auth: [], dhGroup: null, preSharedKey: false, aggressiveMode: false, line: n };
        pushBounded(profile.vpns, vpn, MAX_VPNS);
      }
      match = /encryption\s+(\S+)/i.exec(trimmed);
      if (match) vpn.encryption.push(match[1].toLowerCase());
      match = /hash\s+(\S+)/i.exec(trimmed);
      if (match) vpn.auth.push(match[1].toLowerCase());
      match = /dh-group\s+(\S+)/i.exec(trimmed);
      if (match) vpn.dhGroup = match[1];
      continue;
    }
    if (/^set\s+vpn\s+(?:ipsec\s+site-to-site|l2tp).*pre-shared-key/i.test(trimmed)) {
      const vpn = profile.vpns.find((entry) => entry.kind === "ipsec");
      if (vpn) vpn.preSharedKey = true;
      pushBounded(profile.secrets, { purpose: "VPN preshared key", hashType: "cleartext PSK", line: n }, MAX_SECRETS);
      continue;
    }
  }
  return profile;
}

// ---- F5 BIG-IP (tmsh, light) --------------------------------------------------------

function parseF5(text: string): ParsedNetworkConfig {
  const lines = toLines(text);
  const profile = emptyProfile("f5");
  profile.configLines = lines.length;

  for (const { n, text: line } of lines) {
    const trimmed = line.trim();
    let match = /^(?:cm device|tmsh)\s+(?:.*\s)?hostname\s+(\S+)/i.exec(trimmed) ?? /^hostname\s+(\S+)/i.exec(trimmed);
    if (match && !profile.hostname) {
      profile.hostname = clean(match[1]);
      continue;
    }
    match = /^(ltm|net)\s+virtual\s+(\S+)/i.exec(trimmed);
    if (match) {
      pushBounded(
        profile.firewallRules,
        { id: match[2], name: clean(match[2]), srcIntf: null, dstIntf: null, source: null, destination: null, service: null, action: "virtual-server", log: null, line: n },
        MAX_FW_RULES,
      );
      continue;
    }
    match = /^net\s+self\s+(\S+)\s+address\s+(\S+)/i.exec(trimmed);
    if (match) {
      pushBounded(
        profile.interfaces,
        {
          name: match[1],
          line: n,
          description: null,
          ipAddress: clean(match[2]),
          adminEnabled: null,
          mode: "routed",
          accessVlan: null,
          nativeVlan: null,
          allowedVlans: null,
          aclIn: null,
          aclOut: null,
          portSecurity: null,
          bpduGuard: null,
          portfast: null,
          stormControl: null,
          speedDuplex: null,
          nameif: null,
          securityLevel: null,
        },
        MAX_INTERFACES,
      );
      continue;
    }
    if (/^sys\s+ntp\s+servers?\s+/i.test(trimmed)) {
      const servers = trimmed.split(/\s+/).slice(3).filter(Boolean).slice(0, 16);
      for (const server of servers) pushBounded(profile.ntp.servers, clean(server) ?? server, 16);
      if (profile.ntp.line === null) profile.ntp.line = n;
      continue;
    }
    if (/^sys\s+syslog\s+.*remote\s+server/i.test(trimmed) || /remote server.*host/i.test(trimmed)) {
      profile.logging.enabled = true;
      if (profile.logging.line === null) profile.logging.line = n;
      continue;
    }
  }
  if (profile.hostname === null && /bigip/i.test(text.slice(0, 8192).toLowerCase())) profile.hostname = "bigip";
  return profile;
}

// ---- SonicWall (light XML) -----------------------------------------------------------

function parseSonicwall(text: string): ParsedNetworkConfig {
  const profile = emptyProfile("sonicwall");
  profile.configLines = toLines(text).length;
  profile.hostname = clean(/<hostname>([^<]+)<\/hostname>/i.exec(text)?.[1]) ?? "sonicwall";
  const model = /<product[^>]*>\s*([^<\s]+)/i.exec(text)?.[1] ?? /sonicwall\s*(\S+)/i.exec(text)?.[1];
  if (model) profile.model = clean(model);
  const version = /<version[^>]*>\s*([^<]+)/i.exec(text)?.[1];
  if (version) profile.osVersion = clean(version);
  const admin = /<admin[^>]*>\s*<name>([^<]+)<\/name>/i.exec(text)?.[1];
  if (admin) pushBounded(profile.users, { name: admin, role: "admin", hashType: "vendor-encrypted", line: 0 }, MAX_USERS);
  // HTTP/HTTPS mgmt flags
  if (/<http>\s*<enabled>\s*true/i.test(text)) profile.management.httpEnabled = true;
  if (/<https>\s*<enabled>\s*true/i.test(text)) profile.management.httpsEnabled = true;
  return profile;
}

// ---- Generic fallback -------------------------------------------------------------------

function parseGeneric(text: string): ParsedNetworkConfig {
  const lines = toLines(text);
  const profile = emptyProfile("generic");
  profile.configLines = lines.length;
  for (const { n, text: line } of lines) {
    const match = /^hostname\s+(\S+)/i.exec(line.trim()) ?? /^set\s+system\s+host-name\s+(\S+)/i.exec(line.trim());
    if (match) {
      profile.hostname = clean(match[1]);
      break;
    }
    void n;
  }
  if (profile.hostname === null) {
    // use a stable synthetic identity so the device can still be tracked
    profile.hostname = null;
  }
  return profile;
}

// ---- public entry points -------------------------------------------------------------------

export type ParseResult = {
  profile: ParsedNetworkConfig;
  vendor: VendorId;
  detectionScore: number;
};

// ---- Huawei VRP -----------------------------------------------------------------
// `display current-configuration` output: `#` section separators, `sysname`,
// `interface X` blocks with indented commands, `undo` negation, `local-user`
// under `aaa`, `snmp-agent`, `info-center loghost`, `ntp-service`.

function parseHuaweiVrp(text: string): ParsedNetworkConfig {
  const lines = toLines(text);
  const profile = emptyProfile("huawei-vrp");
  profile.configLines = lines.length;

  let currentInterface: ParsedInterface | null = null;
  let inAaa = false;
  let inPasswordPolicy = false;
  let currentRouting: ParsedRoutingProtocol | null = null;

  const blankInterface = (name: string, line: number): ParsedInterface => ({
    name,
    line,
    description: null,
    ipAddress: null,
    adminEnabled: null,
    mode: "unknown",
    accessVlan: null,
    nativeVlan: null,
    allowedVlans: null,
    aclIn: null,
    aclOut: null,
    portSecurity: null,
    bpduGuard: null,
    portfast: null,
    stormControl: null,
    speedDuplex: null,
    nameif: null,
    securityLevel: null,
  });

  for (const { n, text: line } of lines) {
    if (!line || line === "#" || line === "return") {
      currentInterface = null;
      inPasswordPolicy = false;
      if (/^#\s*$/.test(line)) inAaa = false;
      continue;
    }
    if (/^!Software Version\s+(\S+)/i.test(line)) {
      profile.osVersion = clean(/^!Software Version\s+(\S+)/i.exec(line)?.[1]);
      continue;
    }
    if (/^display current-configuration/i.test(line) || /^<\S+>$/.test(line)) continue;

    let match = /^sysname\s+(.+)$/i.exec(line);
    if (match) {
      profile.hostname = clean(match[1]);
      continue;
    }
    match = /^vlan batch\s+(.+)$/i.exec(line);
    if (match) {
      for (const id of match[1].split(/\s+/).slice(0, 32)) {
        pushBounded(profile.vlans, { id, name: null, line: n }, MAX_VLANS);
      }
      continue;
    }
    match = /^interface\s+(\S+)\s*$/i.exec(line);
    if (match) {
      currentInterface = blankInterface(match[1], n);
      pushBounded(profile.interfaces, currentInterface, MAX_INTERFACES);
      continue;
    }
    if (currentInterface) {
      if (/^undo shutdown$/i.test(line)) {
        currentInterface.adminEnabled = true;
        continue;
      }
      if (/^shutdown$/i.test(line)) {
        currentInterface.adminEnabled = false;
        continue;
      }
      match = /^description\s+(.+)$/i.exec(line);
      if (match) {
        currentInterface.description = clean(match[1]);
        continue;
      }
      match = /^ip address\s+(\S+)\s+(\S+)$/i.exec(line);
      if (match) {
        currentInterface.ipAddress = `${match[1]} ${match[2]}`;
        currentInterface.mode = "routed";
        continue;
      }
      match = /^port link-type\s+(\S+)$/i.exec(line);
      if (match) {
        currentInterface.mode = match[1].toLowerCase() === "trunk" ? "trunk" : match[1].toLowerCase() === "access" ? "access" : "l2";
        continue;
      }
      match = /^port default vlan\s+(\d+)$/i.exec(line);
      if (match) {
        currentInterface.accessVlan = match[1];
        if (currentInterface.mode === "unknown") currentInterface.mode = "access";
        continue;
      }
      match = /^port trunk allow-pass vlan\s+(.+)$/i.exec(line);
      if (match) {
        currentInterface.allowedVlans = clean(match[1]);
        currentInterface.mode = "trunk";
        continue;
      }
      if (/^port trunk pvid vlan\s+/i.test(line)) {
        currentInterface.nativeVlan = clean(/^port trunk pvid vlan\s+(\d+)/i.exec(line)?.[1]);
        continue;
      }
      continue;
    }

    // management services
    if (/^telnet server enable$/i.test(line)) {
      profile.management.telnetEnabled = true;
      continue;
    }
    if (/^telnet server enable$/i.test(line)) {
      profile.management.telnetEnabled = true;
      continue;
    }
    if (/^telnet server disable$/i.test(line)) {
      profile.management.telnetEnabled = false;
      continue;
    }
    if (/^undo telnet server/i.test(line)) {
      profile.management.telnetEnabled = false;
      continue;
    }
    if (/^stelnet server enable$/i.test(line) || /^ssh server enable$/i.test(line) || /^snetconf server enable$/i.test(line)) {
      profile.management.sshEnabled = true;
      profile.management.sshVersion = "2"; // VRP stelnet is SSHv2-only
      continue;
    }
    if (/^undo stelnet server|undo ssh server enable/i.test(line)) {
      profile.management.sshEnabled = false;
      continue;
    }
    if (/^http server enable$/i.test(line)) {
      profile.management.httpEnabled = true;
      continue;
    }
    if (/^http server disable$/i.test(line)) {
      profile.management.httpEnabled = false;
      continue;
    }
    if (/^undo http server/i.test(line)) {
      profile.management.httpEnabled = false;
      continue;
    }
    if (/^http secure-server enable$/i.test(line)) {
      profile.management.httpsEnabled = true;
      continue;
    }
    match = /^ssh server cipher\s+(.+)$/i.exec(line);
    if (match) {
      for (const algo of match[1].split(":")) {
        const name = clean(algo);
        if (name && profile.management.sshCiphers.length < 32) profile.management.sshCiphers.push(name);
      }
      continue;
    }
    match = /^ntp-service unicast-server\s+(\S+)/i.exec(line);
    if (match) {
      const host = clean(match[1]);
      if (host) pushBounded(profile.ntp.servers, host, 16);
      if (profile.ntp.line === null) profile.ntp.line = n;
      continue;
    }
    if (/^ntp-service authentication enable$/i.test(line)) {
      profile.ntp.authenticated = true;
      continue;
    }
    match = /^info-center loghost\s+(\S+)/i.exec(line);
    if (match) {
      const host = clean(match[1]);
      if (host && !/^console$/i.test(host)) pushBounded(profile.logging.hosts, host, 16);
      profile.logging.enabled = true;
      continue;
    }
    match = /^snmp-agent community\s+(read|write)\s+(?:cipher\s+)?(\S+)/i.exec(line);
    if (match) {
      profile.snmp.enabled = true;
      if (profile.snmp.line === null) profile.snmp.line = n;
      pushBounded(
        profile.snmp.communities,
        { value: clean(match[2]) ?? "unknown", access: match[1].toLowerCase() === "write" ? "rw" : "ro", acl: null, line: n },
        64,
      );
      continue;
    }
    if (/^snmp-agent group v3/i.test(line) || /^snmp-agent usm-user v3/i.test(line)) {
      profile.snmp.enabled = true;
      profile.snmp.v3Configured = true;
      continue;
    }
    if (/^snmp-agent$/i.test(line)) {
      profile.snmp.enabled = true;
      if (profile.snmp.line === null) profile.snmp.line = n;
      continue;
    }

    // aaa / users
    if (/^aaa$/i.test(line)) {
      inAaa = true;
      profile.aaa.newModel = true;
      profile.aaa.line = n;
      continue;
    }
    if (inAaa && /^password-policy$/i.test(line)) {
      inPasswordPolicy = true;
      continue;
    }
    if (inPasswordPolicy) {
      match = /^password min-length\s+(\d+)/i.exec(line);
      if (match) {
        profile.management.minPasswordLength = Number(match[1]);
        inPasswordPolicy = false;
        continue;
      }
      if (/^#/.test(line)) inPasswordPolicy = false;
    }
    match = /^local-user\s+(\S+)\s+password\s+(irreversible-cipher|cipher)\s+\S+/i.exec(line);
    if (match) {
      profile.users.push({
        name: clean(match[1]) ?? "unknown",
        role: null,
        hashType: match[2].toLowerCase() === "cipher" ? "Huawei reversible cipher" : "Huawei irreversible cipher (hashed)",
        line: n,
      });
      continue;
    }
    match = /^local-user\s+(\S+)\s+privilege level\s+(\d+)/i.exec(line);
    if (match) {
      const user = profile.users.find((entry) => entry.name === match![1]);
      if (user) user.role = match[2] === "15" || match[2] === "3" ? "admin-level" : `level ${match[2]}`;
      continue;
    }
    match = /^hwtacacs-server template\s+\S+/i.exec(line) ?? /^radius-server template\s+\S+/i.exec(line);
    if (match) {
      profile.aaa.newModel = true;
      continue;
    }
    match = /^hwtacacs-server authentication\s+(\S+)/i.exec(line);
    if (match) {
      const host = clean(match[1]);
      if (host) pushBounded(profile.aaa.tacacsHosts, host, 32);
      continue;
    }
    match = /^radius-server authentication\s+(\S+)/i.exec(line);
    if (match) {
      const host = clean(match[1]);
      if (host) pushBounded(profile.aaa.radiusHosts, host, 32);
      continue;
    }

    // routing
    match = /^ospf\s+(\S+)?/i.exec(line);
    if (match) {
      currentRouting = { protocol: "ospf", processId: match[1] ?? null, networks: [], authConfigured: false, line: n };
      pushBounded(profile.routingProtocols, currentRouting, MAX_ROUTING_PROTOCOLS);
      continue;
    }
    match = /^bgp\s+(\S+)?/i.exec(line);
    if (match) {
      currentRouting = { protocol: "bgp", processId: match[1] ?? null, networks: [], authConfigured: false, line: n };
      pushBounded(profile.routingProtocols, currentRouting, MAX_ROUTING_PROTOCOLS);
      continue;
    }
    if (currentRouting && /authentication-mode\s+(hmac-md5|hmac-sha|md5)/i.test(line)) {
      currentRouting.authConfigured = true;
      continue;
    }
    if (currentRouting && /^peer\s+\S+\s+password\s/i.test(line)) {
      currentRouting.authConfigured = true;
      continue;
    }
    match = /^ip route-static\s+(\S+)\s+(\S+)\s+(\S+)/i.exec(line);
    if (match) {
      pushBounded(profile.staticRoutes, { destination: match[1], nextHop: match[3], line: n }, MAX_ROUTES);
      continue;
    }
  }

  // device type heuristic: switching signals beat routing signals
  if (profile.vlans.length > 0 || profile.interfaces.some((iface) => /Vlanif/i.test(iface.name))) {
    profile.deviceType = "switch";
  } else if (profile.routingProtocols.length > 0) {
    profile.deviceType = "router";
  }
  return profile;
}

// ---- Check Point GAiA (clish) ----------------------------------------------------
// `show configuration` / `save configuration` output: `set ...` / `add ...`
// lines with `#` comments. The security policy lives on SmartConsole, so the
// GAiA layer is about the OS hardening (users, services, interfaces, NTP).

function parseCheckpointGaia(text: string): ParsedNetworkConfig {
  const lines = toLines(text);
  const profile = emptyProfile("checkpoint-gaia");
  profile.configLines = lines.length;

  const ifaceByName = (name: string, line: number): ParsedInterface => {
    const existing = profile.interfaces.find((entry) => entry.name === name);
    if (existing) return existing;
    const created: ParsedInterface = {
      name,
      line,
      description: null,
      ipAddress: null,
      adminEnabled: null,
      mode: "routed",
      accessVlan: null,
      nativeVlan: null,
      allowedVlans: null,
      aclIn: null,
      aclOut: null,
      portSecurity: null,
      bpduGuard: null,
      portfast: null,
      stormControl: null,
      speedDuplex: null,
      nameif: null,
      securityLevel: null,
    };
    pushBounded(profile.interfaces, created, MAX_INTERFACES);
    return created;
  };

  for (const { n, text: line } of lines) {
    if (!line || line.startsWith("#")) continue;
    let match = /^set hostname\s+(.+)$/i.exec(line);
    if (match) {
      profile.hostname = clean(match[1]);
      continue;
    }
    match = /^set password-controls min-password-length\s+(\d+)/i.exec(line);
    if (match) {
      profile.management.minPasswordLength = Number(match[1]);
      continue;
    }
    if (/^set password-controls complexity (?:1|2)$/i.test(line)) {
      // complexity enabled â€” informational only
      continue;
    }
    // users
    match = /^set user\s+(\S+)\s+password-hash\s+(\S+)/i.exec(line);
    if (match) {
      profile.users.push({
        name: clean(match[1]) ?? "unknown",
        role: null,
        hashType: classifyHash(match[2]),
        line: n,
      });
      continue;
    }
    match = /^set user\s+(\S+)\s+(?:real-name|primary-group)\s+(.+)$/i.exec(line);
    if (match) {
      const user = profile.users.find((entry) => entry.name === match![1]);
      if (user && /admin/i.test(match[2])) user.role = "admin";
      continue;
    }
    match = /^add rba user\s+(\S+)\s+roles\s+(\S+)/i.exec(line);
    if (match) {
      let user = profile.users.find((entry) => entry.name === match![1]);
      if (!user) {
        user = { name: clean(match[1]) ?? "unknown", role: null, hashType: "unknown", line: n };
        profile.users.push(user);
      }
      user.role = match[2].toLowerCase() === "adminrole" ? "admin" : clean(match[2]);
      continue;
    }
    // services
    if (/^set telnet-state on/i.test(line)) {
      profile.management.telnetEnabled = true;
      continue;
    }
    if (/^set telnet-state off/i.test(line)) {
      profile.management.telnetEnabled = false;
      continue;
    }
    if (/^set ssh server\b/i.test(line) || /^add ssh server\b/i.test(line)) {
      profile.management.sshEnabled = true;
      profile.management.sshVersion = "2"; // GAiA sshd is SSHv2-only
      if (/permit-root-login (?:on|yes)/i.test(line)) {
        // root SSH is tracked as a user-shaped finding via MGMT-004 semantics
      }
      continue;
    }
    match = /^set web (?:daemon-enable|ssl-port)\b/i.exec(line);
    if (match) {
      profile.management.httpsEnabled = /daemon-enable on/i.test(line) ? true : profile.management.httpsEnabled ?? true;
      continue;
    }
    // snmp
    if (/^set snmp agent on/i.test(line)) {
      profile.snmp.enabled = true;
      if (profile.snmp.line === null) profile.snmp.line = n;
      continue;
    }
    if (/^set snmp agent off/i.test(line)) {
      profile.snmp.enabled = false;
      continue;
    }
    if (/^set snmp agent-version\s+V3/i.test(line)) {
      profile.snmp.v3Configured = true;
      continue;
    }
    match = /^set snmp community\s+(\S+)\s+(read-only|read-write)/i.exec(line);
    if (match) {
      profile.snmp.enabled = true;
      if (profile.snmp.line === null) profile.snmp.line = n;
      pushBounded(
        profile.snmp.communities,
        { value: clean(match[1]) ?? "unknown", access: match[2] === "read-write" ? "rw" : "ro", acl: null, line: n },
        64,
      );
      continue;
    }
    // ntp
    match = /^add ntp server address\s+(\S+)/i.exec(line);
    if (match) {
      const host = clean(match[1]);
      if (host) pushBounded(profile.ntp.servers, host, 16);
      continue;
    }
    if (/^set ntp active on/i.test(line)) continue;
    if (/^set ntp authentication\b/i.test(line)) {
      profile.ntp.authenticated = /on|true/i.test(line) ? true : false;
      continue;
    }
    // syslog
    match = /^add syslog log-server\s+\S+\s+address\s+(\S+)/i.exec(line);
    if (match) {
      const host = clean(match[1]);
      if (host) pushBounded(profile.logging.hosts, host, 16);
      profile.logging.enabled = true;
      continue;
    }
    // aaa
    match = /^(?:add|set) (?:tacacs|radius)-server.*address\s+(\S+)/i.exec(line);
    if (match) {
      const host = clean(match[1]);
      if (host) {
        pushBounded(/tacacs/i.test(line) ? profile.aaa.tacacsHosts : profile.aaa.radiusHosts, host, 32);
        profile.aaa.newModel = true;
      }
      continue;
    }
    // interfaces
    match = /^set interface\s+(\S+)\s+ipv4-address\s+(\S+)\s+mask-length\s+(\d+)/i.exec(line);
    if (match) {
      const iface = ifaceByName(match[1], n);
      iface.ipAddress = `${match[2]}/${match[3]}`;
      iface.mode = "routed";
      continue;
    }
    match = /^set interface\s+(\S+)\s+(?:comments|description)\s+(.+)$/i.exec(line);
    if (match) {
      ifaceByName(match[1], n).description = clean(match[2]);
      continue;
    }
    match = /^set interface\s+(\S+)\s+state\s+(on|off)/i.exec(line);
    if (match) {
      ifaceByName(match[1], n).adminEnabled = match[2] === "on";
      continue;
    }
    // routes
    match = /^set static-route\s+(\S+)\s+nexthop gateway ip\s+(\S+)/i.exec(line);
    if (match) {
      pushBounded(
        profile.staticRoutes,
        { destination: match[1] === "default" ? "0.0.0.0/0 (default)" : match[1], nextHop: clean(match[2]) ?? "?", line: n },
        MAX_ROUTES,
      );
      continue;
    }
    // management hosts (allowed GUI clients)
    match = /^add gui-client\s+(\S+)/i.exec(line) ?? /^set gui-client\s+\S+\s+ip-address\s+(\S+)/i.exec(line);
    if (match) {
      const host = clean(match[1]);
      if (host) pushBounded(profile.management.mgmtHosts, host, 32);
      continue;
    }
  }
  return profile;
}

// ---- MikroTik RouterOS (.rsc export) ----------------------------------------------
// Export grammar: `/path` menu declarations followed by `add key=value â€¦` /
// `set [index|find] key=value â€¦` lines; `# by RouterOS x.y` header comments.

function parseMikrotikQuoted(text: string): string {
  const match = /^"(.*)"$/.exec(text.trim());
  return (match ? match[1] : text.trim()).slice(0, MAX_STRING);
}

function parseMikrotik(text: string): ParsedNetworkConfig {
  const lines = toLines(text);
  const profile = emptyProfile("mikrotik-routeros");
  profile.configLines = lines.length;
  let path = "";

  const addService = (name: string, enabled: boolean, line: number): void => {
    const existing = profile.services.find((entry) => entry.name === name);
    if (existing) {
      existing.enabled = enabled;
      existing.line = line;
      return;
    }
    pushBounded(profile.services, { name, enabled, line }, MAX_SERVICES);
  };

  for (const { n, text: line } of lines) {
    if (!line) continue;
    if (line.startsWith("#")) {
      const version = /^#\s*(?:apr|may|jun|jul|aug|sep|oct|nov|dec|jan|feb|mar)\/\d{2}\/\d{4}.*by RouterOS\s+(\S+)/i.exec(line) ?? /^#.*by RouterOS\s+(\S+)/i.exec(line);
      if (version) profile.osVersion = clean(version[1]);
      continue;
    }
    if (line.startsWith("/")) {
      path = line.toLowerCase();
      continue;
    }
    const tokens = line.match(/(?:[^\s"]+"[^"]*")|(?:[^\s"]+)/g) ?? [];
    const action = tokens[0]?.toLowerCase();
    const kv = new Map<string, string>();
    const positionals: string[] = [];
    for (let index = 1; index < tokens.length; index += 1) {
      const token = tokens[index];
      const separator = token.indexOf("=");
      if (separator > 0) kv.set(token.slice(0, separator), parseMikrotikQuoted(token.slice(separator + 1)));
      else positionals.push(token);
    }

    if (action === "set" || action === "add") {
      // identity
      if (path === "/system identity" && kv.has("name")) {
        profile.hostname = clean(kv.get("name")) ?? profile.hostname;
        continue;
      }
      if (path === "/system note" && kv.has("note")) {
        if (kv.get("show-at-login") === "yes" || kv.has("note")) {
          pushBounded(profile.banners, { kind: "login note", text: clean(kv.get("note")) ?? "", line: n }, MAX_BANNERS);
        }
        continue;
      }
      if (path === "/system clock" && kv.has("time-zone-name")) continue;
      // users
      if (path === "/user" && kv.has("name")) {
        profile.users.push({
          name: kv.get("name") ?? "unknown",
          role: kv.get("group") ?? null,
          hashType: kv.has("password") ? classifyHash(kv.get("password")) : "not exported (sensitive hidden)",
          line: n,
        });
        continue;
      }
      if (path === "/user settings" && kv.has("minimum-password-length")) {
        profile.management.minPasswordLength = Number(kv.get("minimum-password-length")) || null;
        continue;
      }
      // services: `set telnet disabled=yes` (v6 positional, v7 numbers=)
      if (path === "/ip service" && action === "set") {
        const service = (positionals[0] ?? kv.get("numbers") ?? "").toLowerCase();
        const disabled = kv.get("disabled") === "yes";
        if (service) {
          if (service === "telnet") profile.management.telnetEnabled = !disabled;
          if (service === "ssh") {
            profile.management.sshEnabled = !disabled;
            profile.management.sshVersion = "2"; // RouterOS ssh is v2-only
          }
          if (service === "www") profile.management.httpEnabled = !disabled;
          if (service === "www-ssl") profile.management.httpsEnabled = !disabled;
          if (service === "api" || service === "api-ssl") continue;
          addService(`${service} service`, !disabled, n);
        }
        continue;
      }
      if (path === "/ip service" && action === "add") continue;
      // snmp
      if (path === "/snmp" && action === "set") {
        if (kv.get("enabled") === "yes") {
          profile.snmp.enabled = true;
          if (profile.snmp.line === null) profile.snmp.line = n;
        }
        continue;
      }
      if (path === "/snmp community" && action === "add" && kv.has("name")) {
        profile.snmp.enabled = true;
        if (profile.snmp.line === null) profile.snmp.line = n;
        pushBounded(
          profile.snmp.communities,
          { value: kv.get("name") ?? "unknown", access: /write/i.test(kv.get("write-access") ?? "") ? "rw" : "ro", acl: null, line: n },
          64,
        );
        continue;
      }
      // ntp
      if (path === "/system ntp client" && kv.has("servers")) {
        for (const server of (kv.get("servers") ?? "").split(",").slice(0, 16)) {
          const host = clean(server);
          if (host) pushBounded(profile.ntp.servers, host, 16);
        }
        continue;
      }
      if (path === "/system ntp client servers" && action === "add" && kv.has("address")) {
        const host = clean(kv.get("address"));
        if (host) pushBounded(profile.ntp.servers, host, 16);
        continue;
      }
      // syslog
      if (path === "/system logging action" && kv.has("remote")) {
        const host = clean(kv.get("remote"));
        if (host) pushBounded(profile.logging.hosts, host, 16);
        profile.logging.enabled = true;
        continue;
      }
      // radius
      if (path === "/radius" && action === "add" && kv.has("address")) {
        const host = clean(kv.get("address"));
        if (host) pushBounded(profile.aaa.radiusHosts, host, 32);
        profile.aaa.newModel = true;
        continue;
      }
      // wireless security profiles
      if (path.includes("security-profiles") && action === "add" && kv.has("name")) {
        const authTypes = kv.get("authentication-types") ?? "";
        pushBounded(
          profile.wirelessLans,
          {
            ssid: kv.get("name") ?? "unknown",
            profile: kv.get("name") ?? null,
            authMode: authTypes || "unknown",
            psk: kv.has("wpa2-pre-shared-key") || kv.has("wpa-pre-shared-key") || /psk/i.test(authTypes),
            line: n,
          },
          MAX_WLANS,
        );
        continue;
      }
      // ipsec proposals
      if (path === "/ip ipsec proposal" && action === "add" && kv.has("name")) {
        pushBounded(
          profile.vpns,
          {
            kind: "ipsec",
            name: kv.get("name") ?? null,
            encryption: (kv.get("enc-algorithms") ?? kv.get("encryption-algorithms") ?? "").split(",").map((entry) => entry.trim()).filter(Boolean),
            auth: (kv.get("auth-algorithms") ?? "").split(",").map((entry) => entry.trim()).filter(Boolean),
            dhGroup: kv.get("dh-group") ?? null,
            preSharedKey: true,
            aggressiveMode: false,
            line: n,
          },
          MAX_VPNS,
        );
        continue;
      }
      // interfaces
      if (path.startsWith("/interface") && kv.has("name")) {
        const existing = profile.interfaces.find((entry) => entry.name === kv.get("name"));
        if (!existing) {
          pushBounded(
            profile.interfaces,
            {
              name: kv.get("name") ?? "unknown",
              line: n,
              description: kv.get("comment") ?? null,
              ipAddress: null,
              adminEnabled: kv.get("disabled") === "yes" ? false : null,
              mode: "unknown",
              accessVlan: null,
              nativeVlan: null,
              allowedVlans: null,
              aclIn: null,
              aclOut: null,
              portSecurity: null,
              bpduGuard: null,
              portfast: null,
              stormControl: null,
              speedDuplex: null,
              nameif: null,
              securityLevel: null,
            },
            MAX_INTERFACES,
          );
        }
        continue;
      }
      // addresses
      if (path === "/ip address" && action === "add" && kv.has("address")) {
        const target = kv.get("interface") ?? "";
        const iface = profile.interfaces.find((entry) => entry.name === target);
        if (iface) {
          iface.ipAddress = kv.get("address") ?? null;
          iface.mode = "routed";
        } else {
          pushBounded(
            profile.interfaces,
            {
              name: target || `addr${profile.interfaces.length + 1}`,
              line: n,
              description: null,
              ipAddress: kv.get("address") ?? null,
              adminEnabled: null,
              mode: "routed",
              accessVlan: null,
              nativeVlan: null,
              allowedVlans: null,
              aclIn: null,
              aclOut: null,
              portSecurity: null,
              bpduGuard: null,
              portfast: null,
              stormControl: null,
              speedDuplex: null,
              nameif: null,
              securityLevel: null,
            },
            MAX_INTERFACES,
          );
        }
        continue;
      }
      // firewall filter
      if (path === "/ip firewall filter" && action === "add") {
        const chain = kv.get("chain") ?? "unknown";
        const actionValue = kv.get("action") ?? "unknown";
        pushBounded(
          profile.firewallRules,
          {
            id: `ros-${profile.firewallRules.length + 1}`,
            name: kv.get("comment") ?? null,
            srcIntf: kv.get("in-interface") ?? null,
            dstIntf: kv.get("out-interface") ?? null,
            source: kv.get("src-address") ?? "any",
            destination: kv.get("dst-address") ?? "any",
            service: kv.get("protocol")
              ? [kv.get("protocol"), kv.get("dst-port")].filter(Boolean).join("/")
              : kv.get("dst-port") ?? "any",
            action: actionValue,
            log: kv.get("log") === "yes",
            line: n,
          },
          MAX_FW_RULES,
        );
        continue;
      }
      // static routes
      if (path === "/ip route" && action === "add" && kv.has("dst-address")) {
        pushBounded(
          profile.staticRoutes,
          { destination: kv.get("dst-address") ?? "?", nextHop: kv.get("gateway") ?? "?", line: n },
          MAX_ROUTES,
        );
        continue;
      }
    }
  }
  return profile;
}

// ---- XML-based firewalls (pfSense / OPNsense / Sophos SFOS / WatchGuard) ----------
// Extracted with bounded tag regexes â€” no full DOM, tolerant to attribute and
// whitespace differences. pfSense/OPNsense `config.xml` is a stable documented
// format; Sophos `Entities.xml` (from the selective backup tar) is parsed
// best-effort for rules and admin settings.

function xmlSlice(doc: string, tag: string, max = 200): string[] {
  const out: string[] = [];
  const re = new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)</${tag}>`, "gi");
  let match: RegExpExecArray | null;
  while ((match = re.exec(doc)) !== null && out.length < max) out.push(match[1]);
  return out;
}

function xmlText(block: string, tag: string): string | null {
  const match = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`, "i").exec(block) ?? new RegExp(`<${tag}[^>]*/>`, "i").exec(block);
  if (!match) return null;
  const value = match[1] ?? "";
  return clean(value.replace(/<[^>]+>/g, "").trim());
}

function xmlHasEmptyTag(block: string, tag: string): boolean {
  return new RegExp(`<${tag}\\s*/>`, "i").test(block);
}

function parseXmlFirewall(text: string, vendor: "pfsense" | "opnsense" | "sophos-sfos" | "watchguard"): ParsedNetworkConfig {
  const doc = text.replace(/<!--[\s\S]*?-->/g, "");
  const profile = emptyProfile(vendor);
  profile.configLines = doc.split(/\r\n|\r|\n/).length;

  if (vendor === "sophos-sfos") {
    // Entities.xml: firewall rules with child elements.
    for (const block of xmlSlice(doc, "FirewallRule", 512)) {
      const networks = (tag: string): string | null => {
        const group = new RegExp(`<${tag}>[\\s\\S]*?</${tag}>`, "i").exec(block);
        if (!group) return null;
        const items = xmlSlice(group[0], "Network").length > 0 ? xmlSlice(group[0], "Network") : xmlSlice(group[0], "Service");
        return items.length > 0 ? items.map((entry) => clean(entry) ?? "unknown").join(",") : null;
      };
      pushBounded(
        profile.firewallRules,
        {
          id: xmlText(block, "FirewallRule") ?? xmlText(block, "Name") ?? `sfos-${profile.firewallRules.length + 1}`,
          name: xmlText(block, "Name"),
          srcIntf: xmlText(block, "SourceZones"),
          dstIntf: xmlText(block, "DestinationZones"),
          source: networks("SourceNetworks") ?? "any",
          destination: networks("DestinationNetworks") ?? "any",
          service: networks("Services") ?? "any",
          action: (xmlText(block, "Action") ?? "unknown").toLowerCase(),
          log: /true/i.test(xmlText(block, "EnableLogging") ?? ""),
          line: profile.firewallRules.length + 1,
        },
        MAX_FW_RULES,
      );
    }
    // administrative settings, when present in the export
    const minLen = xmlText(doc, "PasswordComplexity");
    if (minLen && /^\d+$/.test(minLen)) profile.management.minPasswordLength = Number(minLen);
    return profile;
  }

  // pfSense / OPNsense config.xml share the same core layout.
  const hostname = xmlText(doc, "hostname");
  profile.hostname = hostname;
  profile.osVersion = xmlText(doc, "version");
  const domain = xmlText(doc, "domain");
  if (hostname && domain) profile.uptime = null;

  // system settings
  const systemBlock = new RegExp(`<system>([\\s\\S]*?)</system>`, "i").exec(doc)?.[1] ?? doc;
  if (xmlHasEmptyTag(systemBlock, "enable") && /<ssh>/i.test(systemBlock)) profile.management.sshEnabled = true;
  if (/<webgui>[\s\S]*?<protocol>https<\/protocol>/i.test(doc)) profile.management.httpsEnabled = true;
  if (/<webgui>[\s\S]*?<protocol>http<\/protocol>/i.test(doc)) profile.management.httpEnabled = true;
  const rocommunity = xmlText(systemBlock, "rocommunity") ?? xmlText(doc, "rocommunity");
  if (rocommunity || xmlHasEmptyTag(systemBlock, "snmpdenable") || /<snmpd>[\s\S]*?<enable\/>/.test(doc)) {
    profile.snmp.enabled = true;
    if (profile.snmp.line === null) profile.snmp.line = 1;
    if (rocommunity) {
      pushBounded(profile.snmp.communities, { value: rocommunity, access: "ro", acl: null, line: 1 }, 64);
    }
  }
  const timeservers = xmlText(systemBlock, "timeservers");
  if (timeservers) {
    for (const server of timeservers.split(/\s+/).slice(0, 16)) {
      const host = clean(server);
      if (host) pushBounded(profile.ntp.servers, host, 16);
    }
  }
  const remote = xmlText(doc, "remoteserver") ?? xmlText(doc, "nvsremote") ?? xmlText(doc, "remote");
  if (remote) {
    const host = clean(remote.split(":")[0]);
    if (host) pushBounded(profile.logging.hosts, host, 16);
    profile.logging.enabled = true;
  }
  for (const userBlock of xmlSlice(systemBlock, "user", 512)) {
    const name = xmlText(userBlock, "name");
    if (!name) continue;
    const password = xmlText(userBlock, "password") ?? xmlText(userBlock, "bcrypt-hash") ?? xmlText(userBlock, "password-hash");
    profile.users.push({
      name,
      role: xmlText(userBlock, "scope") ?? (xmlHasEmptyTag(userBlock, "priv") ? "user" : null),
      hashType: password ? classifyHash(password) : "no password stored",
      line: profile.users.length + 1,
    });
  }

  // interfaces
  const interfacesBlock = new RegExp(`<interfaces>([\\s\\S]*?)</interfaces>`, "i").exec(doc)?.[1] ?? "";
  for (const [index, block] of xmlSlice(interfacesBlock, "wan", 16).concat(xmlSlice(interfacesBlock, "lan", 16)).entries()) {
    const name = index === 0 ? "wan" : "lan";
    pushBounded(
      profile.interfaces,
      {
        name,
        line: index + 1,
        description: xmlText(block, "descr"),
        ipAddress: xmlText(block, "ipaddr") ?? (xmlHasEmptyTag(block, "dhcp") ? "dhcp" : null),
        adminEnabled: null,
        mode: "routed",
        accessVlan: null,
        nativeVlan: null,
        allowedVlans: null,
        aclIn: null,
        aclOut: null,
        portSecurity: null,
        bpduGuard: null,
        portfast: null,
        stormControl: null,
        speedDuplex: null,
        nameif: null,
        securityLevel: null,
      },
      MAX_INTERFACES,
    );
  }
  for (const [index, block] of xmlSlice(interfacesBlock, "opt", 64).entries()) {
    pushBounded(
      profile.interfaces,
      {
        name: xmlText(block, "descr") ?? `opt${index + 1}`,
        line: 100 + index,
        description: xmlText(block, "descr"),
        ipAddress: xmlText(block, "ipaddr"),
        adminEnabled: null,
        mode: "routed",
        accessVlan: null,
        nativeVlan: null,
        allowedVlans: null,
        aclIn: null,
        aclOut: null,
        portSecurity: null,
        bpduGuard: null,
        portfast: null,
        stormControl: null,
        speedDuplex: null,
        nameif: null,
        securityLevel: null,
      },
      MAX_INTERFACES,
    );
  }

  // firewall rules
  const filterBlock = new RegExp(`<filter>([\\s\\S]*?)</filter>`, "i").exec(doc)?.[1] ?? "";
  for (const block of xmlSlice(filterBlock, "rule", 1024)) {
    const type = (xmlText(block, "type") ?? "unknown").toLowerCase();
    const sourceAny = /<source>[\s\S]*?<any\s*\/>[\s\S]*?<\/source>/i.test(block) || xmlHasEmptyTag(block, "source");
    const destinationAny = /<destination>[\s\S]*?<any\s*\/>[\s\S]*?<\/destination>/i.test(block) || xmlHasEmptyTag(block, "destination");
    pushBounded(
      profile.firewallRules,
      {
        id: xmlText(block, "tracker") ?? `pf-${profile.firewallRules.length + 1}`,
        name: xmlText(block, "descr"),
        srcIntf: xmlText(block, "interface"),
        dstIntf: null,
        source: sourceAny ? "any" : xmlText(block, "source") ?? "any",
        destination: destinationAny ? "any" : xmlText(block, "destination") ?? "any",
        service: xmlText(block, "destination") ? xmlText(block, "port") ?? "any" : "any",
        action: type,
        log: xmlHasEmptyTag(block, "log"),
        line: profile.firewallRules.length + 1,
      },
      MAX_FW_RULES,
    );
  }
  return profile;
}

/**
 * Parse any network/firewall configuration text into the normalized profile.
 * Never throws: unrecognized content yields a `generic` profile.
 */
export function parseNetworkConfig(text: string, filename?: string): ParseResult {
  const bounded = text.length > MAX_CONFIG_BYTES ? text.slice(0, MAX_CONFIG_BYTES) : text;
  const detection = detectVendor(bounded);
  let profile: ParsedNetworkConfig;
  try {
    switch (detection.vendor) {
      case "cisco-ios":
      case "cisco-nxos":
      case "cisco-wlc-iosxe":
        profile = parseCiscoIosLike(bounded, detection.vendor);
        break;
      case "cisco-asa":
        profile = parseAsa(bounded);
        break;
      case "cisco-wlc":
        profile = parseWlcAireos(bounded);
        break;
      case "juniper-junos":
        profile = parseJunos(bounded);
        break;
      case "palo-alto":
        profile = parsePanos(bounded);
        break;
      case "fortinet":
        profile = parseFortios(bounded);
        break;
      case "aruba-switch":
        profile = parseArubaSwitch(bounded);
        break;
      case "arubaos":
        profile = parseArubaOs(bounded);
        break;
      case "ubiquiti":
        profile = parseUbiquiti(bounded);
        break;
      case "f5":
        profile = parseF5(bounded);
        break;
      case "sonicwall":
        profile = parseSonicwall(bounded);
        break;
      case "arista-eos":
        profile = parseCiscoIosLike(bounded, "arista-eos");
        break;
      case "huawei-vrp":
        profile = parseHuaweiVrp(bounded);
        break;
      case "checkpoint-gaia":
        profile = parseCheckpointGaia(bounded);
        break;
      case "mikrotik-routeros":
        profile = parseMikrotik(bounded);
        break;
      case "pfsense":
      case "opnsense":
      case "sophos-sfos":
      case "watchguard":
        profile = parseXmlFirewall(bounded, detection.vendor);
        break;
      default:
        profile = parseGeneric(bounded);
    }
  } catch {
    profile = parseGeneric(bounded);
    profile.vendor = "generic";
    profile.vendorLabel = VENDOR_LABELS.generic;
  }
  if (!profile.hostname && filename) {
    // Fall back to the file name (without extension) as display identity â€” but
    // never from generic export names, which would collapse unrelated
    // hostname-less devices into one identity downstream.
    const base = filename.replace(/\.(cfg|conf|config|txt|dump|log)$/i, "").slice(0, 64);
    if (!GENERIC_CONFIG_NAMES.test(base)) {
      profile.hostname = clean(base);
    }
  }
  return { profile, vendor: profile.vendor, detectionScore: detection.score };
}

/** Names that carry no device identity (exports/redirects from tooling). */
const GENERIC_CONFIG_NAMES = /^(?:config|configuration|conft?|running|running-config|startup|startup-config|running_config|nvram|system|export|backup|dump|output|terminal|cisco|device|switch|router|firewall)$/i;

export { VENDOR_LABELS };
