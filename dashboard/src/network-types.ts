// Types for the network device / firewall configuration review feature.
// Mirrors the server contracts in dashboard/server/network/.

export type NetworkVendor =
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

export type NetworkDeviceType =
  | "firewall"
  | "router"
  | "switch"
  | "wireless-controller"
  | "load-balancer"
  | "unknown";

export type NetworkSeverity = "Critical" | "High" | "Medium" | "Low" | "Informational";

export type NetworkReviewStatus = "Compliant" | "NonCompliant" | "NotApplicable";

export type NetworkParsedInterface = {
  name: string;
  line: number;
  description: string | null;
  ipAddress: string | null;
  adminEnabled: boolean | null;
  mode: string;
  accessVlan: string | null;
  nativeVlan: string | null;
  allowedVlans: string | null;
  aclIn: string | null;
  aclOut: string | null;
  portSecurity: boolean | null;
  nameif?: string | null;
  securityLevel?: number | null;
};

export type NetworkParsedUser = {
  name: string;
  role: string | null;
  hashType: string;
  line: number;
};

export type NetworkParsedSecret = {
  purpose: string;
  hashType: string;
  line: number;
};

export type NetworkParsedSnmpCommunity = {
  value: string;
  access: string;
  acl: string | null;
  line: number;
};

export type NetworkParsedFirewallRule = {
  id: string | null;
  name?: string | null;
  source: string | null;
  destination: string | null;
  service: string | null;
  action: string | null;
  line: number;
};

export type NetworkParsedWlan = {
  ssid: string | null;
  authMode: string | null;
  psk: boolean;
  line: number;
};

/** Subset of the parsed profile the UI renders. The server persists the full document. */
export type NetworkParsedConfig = {
  vendor: NetworkVendor;
  vendorLabel?: string;
  deviceType: NetworkDeviceType;
  hostname: string | null;
  model: string | null;
  osVersion: string | null;
  serial: string | null;
  uptime: string | null;
  configLines: number;
  interfaces: NetworkParsedInterface[];
  users: NetworkParsedUser[];
  secrets: NetworkParsedSecret[];
  snmp: {
    enabled: boolean | null;
    v3Configured: boolean | null;
    communities: NetworkParsedSnmpCommunity[];
  };
  ntp: { servers: string[]; authenticated: boolean | null };
  logging: { enabled: boolean | null; hosts: string[]; timestamps: boolean | null };
  aaa: { newModel: boolean | null; tacacsHosts: string[]; radiusHosts: string[] };
  management: {
    sshEnabled: boolean | null;
    sshVersion: string | null;
    telnetEnabled: boolean | null;
    httpEnabled: boolean | null;
    httpsEnabled: boolean | null;
    vtyAcl: string | null;
    mgmtHosts: string[];
  };
  firewallRules: NetworkParsedFirewallRule[];
  vpns: Array<{ kind: string; name: string; encryption: string[]; auth: string[]; preSharedKey: boolean }>;
  wirelessLans: NetworkParsedWlan[];
};

export type NetworkFinding = {
  checkId: string;
  title: string;
  severity: NetworkSeverity;
  category: string;
  status: NetworkReviewStatus;
  description: string;
  evidence: string[];
  recommendation: string;
  references: string[];
  /** Added by the API from the treatment projection. */
  treatmentState?: "open" | "accepted_risk" | "false_positive" | "remediated";
};

export type NetworkDeviceSummary = {
  id: number;
  hostname: string | null;
  vendor: NetworkVendor;
  vendorLabel: string;
  deviceType: NetworkDeviceType;
  model: string | null;
  osVersion: string | null;
  serial: string | null;
  firstSeenAt: string;
  lastSeenAt: string;
  reportCount: number;
  latestReportId: number | null;
  latestReceivedAt: string | null;
  score: number | null;
  severity: { critical: number; high: number; medium: number; low: number; informational: number };
  locationCount: number;
  links: { device: string };
};

export type NetworkDeviceDetail = {
  device: {
    id: number;
    deviceKey: string;
    hostname: string | null;
    vendor: NetworkVendor;
    vendorLabel: string;
    deviceType: NetworkDeviceType;
    model: string | null;
    osVersion: string | null;
    serial: string | null;
    firstSeenAt: string;
    lastSeenAt: string;
  };
  locations: Array<{ id: number; name: string; campaignId: number; firstSeenAt: string; lastSeenAt: string }>;
  reports: Array<{
    id: number;
    campaignId: number;
    locationId: number;
    configName: string;
    configSize: number;
    configSha256: string;
    score: number | null;
    receivedAt: string;
    uploadedBy: string | null;
  }>;
  latest: {
    reportId: number;
    receivedAt: string;
    score: number | null;
    parsed: NetworkParsedConfig | null;
    findings: NetworkFinding[];
    severity: { critical: number; high: number; medium: number; low: number; informational: number };
  } | null;
  summary: {
    severity: { critical: number; high: number; medium: number; low: number; informational: number };
    reportCount: number;
  };
};

export type NetworkReportDetail = {
  report: {
    id: number;
    deviceId: number;
    campaignId: number;
    locationId: number;
    configName: string;
    configSha256: string;
    configSize: number;
    receivedAt: string;
    uploadedBy: string | null;
    score: number | null;
  };
  device: {
    id: number;
    hostname: string | null;
    vendor: NetworkVendor;
    vendorLabel: string;
    deviceType: NetworkDeviceType;
    model: string | null;
    osVersion: string | null;
    serial: string | null;
  };
  parsed: NetworkParsedConfig | null;
  findings: NetworkFinding[];
  configText: string;
};

export type NetworkUploadResult =
  | {
      ok: true;
      duplicate: boolean;
      deviceId: number;
      reportId: number;
      campaignId: number;
      locationId: number;
      vendor: NetworkVendor;
      vendorLabel: string;
      deviceType: NetworkDeviceType;
      hostname: string | null;
      score: number;
      findings: { critical: number; high: number; medium: number; low: number; informational: number; compliant: number; notApplicable: number };
    }
  | { ok: false; code: string; error: string };

export type NetworkTreatmentHistoryEntry = {
  id: number;
  actor: string | null;
  changedAt: string;
  fromState: string | null;
  toState: string;
  justification: string | null;
  assignee: string | null;
  dueDate: string | null;
};

export type NetworkDiffEntry = {
  checkId: string;
  title: string;
  severity: string;
  from: string;
  to: string;
};

export type NetworkDiffResponse = {
  device: { id: number; hostname: string | null };
  from: { reportId: number; receivedAt: string; score: number | null };
  to: { reportId: number; receivedAt: string; score: number | null };
  fixed: NetworkDiffEntry[];
  regressed: NetworkDiffEntry[];
  changed: NetworkDiffEntry[];
  unchangedCount: number;
  links: Record<string, string>;
} | null;
