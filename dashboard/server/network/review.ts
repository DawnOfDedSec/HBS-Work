// Network configuration security review engine.
//
// Consumes a normalized `ParsedNetworkConfig` (see ./config-parser) and runs
// a catalog of vendor-aware hardening checks against it. Every check always
// resolves to exactly one authoritative status — Compliant, NonCompliant, or
// NotApplicable — mirroring the extractor's "never false-pass, never error"
// contract: when the platform does not expose a feature the check becomes
// NotApplicable rather than passing.
//
// Scoring reuses the dashboard's server-authoritative metric formulas
// (risk = 100 * (1 - Σ w·failed / Σ w·applicable), weights C=10/H=6/M=3/L=1).

import {
  isDefaultCommunity,
  redactLine,
  type ParsedNetworkConfig,
  type RawLine,
  type Severity,
  type VendorId,
} from "./config-parser";

export type ReviewStatus = "Compliant" | "NonCompliant" | "NotApplicable";

export type NetworkFinding = {
  checkId: string;
  title: string;
  severity: Severity;
  category: string;
  status: ReviewStatus;
  description: string;
  evidence: string[];
  recommendation: string;
  references: string[];
};

type Evidence = { status: ReviewStatus; evidence: string[]; severity?: Severity };

type RuleContext = { profile: ParsedNetworkConfig; lines: RawLine[] };

type Rule = {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  description: string;
  recommendation: string;
  references: string[];
  applies: (ctx: RuleContext) => boolean;
  evaluate: (ctx: RuleContext) => Evidence;
};

const CIS_BENCH = "CIS Benchmarks (Network Devices)";
const CIS_BENCH_FW = "CIS Benchmarks (Firewalls)";
const NIST_AC = "NIST SP 800-53 AC-4/AC-17";
const NIST_AU = "NIST SP 800-53 AU-2/AU-9";
const NIST_IA = "NIST SP 800-53 IA-2/IA-5";
const PCI_DSS = "PCI-DSS v4.0 (2.2.6/4.2.1)";
const CIS_V8 = "CIS Controls v8 (4.4/12.2)";

/**
 * Curated, conservative end-of-support markers per vendor. These are widely
 * published lifecycle milestones — always verify against the vendor's EOL
 * portal before acting. Matched on the leading version segments only.
 */
const EOS_MARKERS: Array<{ vendor: VendorId | "any"; match: RegExp; product: string; note: string }> = [
  { vendor: "cisco-ios", match: /^(?:12\.\d|15\.[01])\b/, product: "Cisco IOS", note: "12.x and 15.0/15.1 trains are past end of support" },
  { vendor: "cisco-asa", match: /^(?:8\.\d|9\.[0-4])\b/, product: "Cisco ASA", note: "8.x and 9.0–9.4 releases are past end of support" },
  { vendor: "fortinet", match: /^[1-5]\./, product: "FortiOS", note: "5.x and earlier branches are past end of support" },
  { vendor: "palo-alto", match: /^[1-8]\./, product: "PAN-OS", note: "8.1 and earlier releases are past end of support" },
  { vendor: "juniper-junos", match: /^(?:[1-9]\.|1[0-4]\.)/, product: "Junos OS", note: "releases before 15.1 are past end of support" },
  { vendor: "cisco-wlc", match: /^[1-7]\./, product: "Cisco WLC AireOS", note: "8.0 and earlier releases are past end of support" },
];

const CISCO_IOS_FAMILY: VendorId[] = ["cisco-ios", "cisco-nxos", "cisco-wlc-iosxe"];

function lineAt(ctx: RuleContext, n: number | null | undefined): string | null {
  if (typeof n !== "number" || n < 1 || n > ctx.lines.length) return null;
  return `line ${n}: ${redactLine(ctx.lines[n - 1].text.trim())}`;
}

/**
 * Line-based evidence that masks the policy rule identifier (PAN-OS
 * `set rulebase security rules <id> …`). Rule names are frequently
 * operationally sensitive ("bypass-audit") and add nothing to the finding.
 */
function policyLineAt(ctx: RuleContext, n: number | null | undefined): string | null {
  return lineAt(ctx, n)?.replace(/(\brules\s+)\S+/, "$1<id>") ?? null;
}

function ev(ctx: RuleContext, ns: Array<number | null | undefined>): string[] {
  return ns
    .map((n) => lineAt(ctx, n))
    .filter((entry): entry is string => entry !== null)
    .slice(0, 8);
}

const isCiscoIosFamily = (vendor: VendorId): boolean => CISCO_IOS_FAMILY.includes(vendor);

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

const RULES: Rule[] = [
  // ---- Authentication & secrets ----
  {
    id: "NET-AUTH-001",
    title: "Privileged (enable) mode secret is missing or plaintext",
    severity: "High",
    category: "Authentication",
    description:
      "Privileged mode must be protected by a hashed secret. A missing secret, or use of the reversible `enable password` form, lets anyone who reaches the device console or vty obtain full administrative control.",
    recommendation:
      "Configure `enable secret` with a strong password (Cisco type 8/9, minimum type 5). Remove any `enable password` line. Restrict and monitor management access in parallel.",
    references: [CIS_BENCH, NIST_IA],
    applies: (ctx) =>
      isCiscoIosFamily(ctx.profile.vendor) || ctx.profile.vendor === "cisco-asa" || ctx.profile.vendor === "aruba-switch",
    evaluate: (ctx) => {
      const { profile } = ctx;
      const secrets = profile.secrets.filter((secret) => /enable/i.test(secret.purpose) || /privileged/i.test(secret.purpose));
      if (secrets.length === 0) {
        const remoteAuth =
          (profile.aaa.newModel === true && profile.aaa.tacacsHosts.length + profile.aaa.radiusHosts.length > 0) ||
          profile.management.mgmtHosts.length > 0 && profile.aaa.newModel === true;
        if (remoteAuth) {
          return {
            status: "NotApplicable",
            evidence: ev(ctx, []),
          };
        }
        return {
          status: "NonCompliant",
          evidence: ev(ctx, [profile.secrets[0]?.line]),
        };
      }
      const plaintext = secrets.filter((secret) => /cleartext|reversible/i.test(secret.hashType));
      if (plaintext.length > 0) {
        return { status: "NonCompliant", evidence: ev(ctx, plaintext.map((secret) => secret.line)) };
      }
      const legacy = secrets.filter((secret) => /type 5/i.test(secret.hashType));
      if (legacy.length === secrets.length) {
        // type 5 is the CIS minimum but PBKDF2/scrypt is preferred
        return { status: "Compliant", evidence: ev(ctx, secrets.map((secret) => secret.line)) };
      }
      return { status: "Compliant", evidence: ev(ctx, secrets.map((secret) => secret.line)) };
    },
  },
  {
    id: "NET-AUTH-002",
    title: "Local user credentials stored without a password hash",
    severity: "Critical",
    category: "Authentication",
    description:
      "One or more local users are configured with a plaintext password, a `nopassword` form, or no credential at all. Anyone who can read the configuration (backups, TFTP, show run) obtains working credentials.",
    recommendation:
      "Every local user must use a strong one-way hash (Cisco `secret 9`/`secret 8`, JunOS `encrypted-password`, FortiOS `ENC` or PBKDF2). Remove plaintext `password` forms and users without credentials.",
    references: [CIS_BENCH, NIST_IA],
    applies: (ctx) => ctx.profile.users.length > 0,
    evaluate: (ctx) => {
      const bad = ctx.profile.users.filter(
        (user) => /cleartext/i.test(user.hashType) || /none/i.test(user.hashType) || /no password/i.test(user.hashType),
      );
      if (bad.length > 0) {
        return { status: "NonCompliant", evidence: ev(ctx, bad.map((user) => user.line)) };
      }
      return { status: "Compliant", evidence: ev(ctx, ctx.profile.users.slice(0, 4).map((user) => user.line)) };
    },
  },
  {
    id: "NET-AUTH-003",
    title: "Reversible type-7 password storage in use",
    severity: "High",
    category: "Authentication",
    description:
      "Cisco type-7 passwords are obfuscated, not hashed — they can be reversed in seconds with publicly available tools. `service password-encryption` produces type 7 and must not be relied on.",
    recommendation:
      "Re-enter all passwords/secrets using `secret 9` (SCRYPT) or `secret 8` (PBKDF2). Treat any existing type-7 value as compromised and rotate it.",
    references: [CIS_BENCH, NIST_IA],
    applies: (ctx) => isCiscoIosFamily(ctx.profile.vendor) || ctx.profile.vendor === "cisco-wlc",
    evaluate: (ctx) => {
      const type7Users = ctx.profile.users.filter((user) => /type 7/i.test(user.hashType));
      const type7Secrets = ctx.profile.secrets.filter((secret) => /reversible/i.test(secret.hashType));
      const offenders = [...type7Users, ...type7Secrets];
      if (offenders.length > 0) {
        return { status: "NonCompliant", evidence: ev(ctx, offenders.map((entry) => entry.line)) };
      }
      if (ctx.profile.users.length + ctx.profile.secrets.length === 0) {
        return { status: "NotApplicable", evidence: [] };
      }
      return { status: "Compliant", evidence: [] };
    },
  },
  {
    id: "NET-AUTH-004",
    title: "Legacy MD5 (type 5) hashing should be migrated",
    severity: "Low",
    category: "Authentication",
    description:
      "MD5-based password hashing (Cisco type 5, JunOS encrypted-password) is deprecated; GPU cracking makes weak choices recoverable. Modern platforms support PBKDF2 (type 8) and SCRYPT (type 9).",
    recommendation:
      "Migrate credentials to type 8/9 hashing where the platform supports it, and enforce a strong minimum length in the meantime.",
    references: [CIS_BENCH, NIST_IA],
    applies: (ctx) => ctx.profile.users.length > 0 || ctx.profile.secrets.length > 0,
    evaluate: (ctx) => {
      const legacy = [
        ...ctx.profile.users.filter((user) => /type 5|md5/i.test(user.hashType)),
        ...ctx.profile.secrets.filter((secret) => /type 5|md5/i.test(secret.hashType)),
      ];
      if (legacy.length > 0) {
        return { status: "NonCompliant", evidence: ev(ctx, legacy.map((entry) => entry.line)) };
      }
      return { status: "Compliant", evidence: [] };
    },
  },
  {
    id: "NET-AUTH-005",
    title: "No authentication, authorization, and accounting (AAA)",
    severity: "Medium",
    category: "Authentication",
    description:
      "The device does not use centralized AAA. Per-device local accounts do not scale, cannot be disabled centrally, and leave no accountability trail.",
    recommendation:
      "Enable AAA (`aaa new-model`) and authenticate administrative sessions against TACACS+/RADIUS with a hardened local fallback account.",
    references: [CIS_BENCH, NIST_IA],
    applies: (ctx) =>
      isCiscoIosFamily(ctx.profile.vendor) || ctx.profile.vendor === "cisco-asa" || ctx.profile.vendor === "juniper-junos",
    evaluate: (ctx) => {
      const { profile } = ctx;
      const remote = profile.aaa.tacacsHosts.length + profile.aaa.radiusHosts.length > 0;
      if (profile.aaa.newModel === true || remote) {
        return { status: "Compliant", evidence: ev(ctx, [profile.aaa.line]) };
      }
      return { status: "NonCompliant", evidence: ev(ctx, [profile.aaa.line]) };
    },
  },
  {
    id: "NET-AUTH-006",
    title: "Administrative authentication is not centralized (no TACACS+/RADIUS)",
    severity: "Low",
    category: "Authentication",
    description:
      "No remote authentication server is configured. Centralized authentication enforces MFA/AD policy, per-admin roles, and immediate revocation.",
    recommendation:
      "Point the device at at least two TACACS+/RADIUS servers and keep a single locked-down local emergency account.",
    references: [CIS_BENCH, NIST_IA],
    applies: (ctx) =>
      (ctx.profile.aaa.newModel === true || ctx.profile.vendor === "juniper-junos" || ctx.profile.vendor === "arubaos") &&
      ctx.profile.aaa.tacacsHosts.length + ctx.profile.aaa.radiusHosts.length === 0,
    evaluate: (ctx) => ({ status: "NonCompliant", evidence: ev(ctx, [ctx.profile.aaa.line]) }),
  },

  // ---- Management access ----
  {
    id: "NET-MGMT-001",
    title: "Telnet management service enabled",
    severity: "Critical",
    category: "Management",
    description:
      "Telnet transmits everything — including credentials — in cleartext. An attacker positioned on the path captures administrative passwords trivially.",
    recommendation:
      "Disable Telnet (`no feature telnet`, `transport input ssh`, remove `telnet-server enable`, drop telnet from FortiOS allowaccess) and use SSHv2 exclusively.",
    references: [CIS_BENCH, NIST_AC, PCI_DSS, CIS_V8],
    applies: (ctx) => ctx.profile.management.telnetEnabled !== null || isCiscoIosFamily(ctx.profile.vendor),
    evaluate: (ctx) => {
      const { profile } = ctx;
      if (profile.management.telnetEnabled === true) {
        const telnetServices = profile.services.filter((service) => /telnet/i.test(service.name));
        return {
          status: "NonCompliant",
          evidence: ev(ctx, [...telnetServices.map((service) => service.line)]),
        };
      }
      if (profile.management.telnetEnabled === false) return { status: "Compliant", evidence: [] };
      // Cisco defaults: telnet is reachable unless transport input restricts it
      if (isCiscoIosFamily(profile.vendor)) {
        return { status: "NonCompliant", evidence: [] };
      }
      return { status: "NotApplicable", evidence: [] };
    },
  },
  {
    id: "NET-MGMT-002",
    title: "Cleartext HTTP management service enabled",
    severity: "High",
    category: "Management",
    description:
      "The web management interface is served over plain HTTP. Credentials, session cookies, and the full device configuration cross the network unencrypted.",
    recommendation:
      "Disable the HTTP listener (`no ip http server`, `no web-management plaintext`, FortiOS remove `http` from allowaccess) and require HTTPS with a trusted certificate.",
    references: [CIS_BENCH, NIST_AC, PCI_DSS],
    applies: (ctx) => ctx.profile.management.httpEnabled !== null,
    evaluate: (ctx) => {
      const { profile } = ctx;
      if (profile.management.httpEnabled === true) {
        const services = profile.services.filter((service) => /http/i.test(service.name) && !/secure/i.test(service.name));
        return { status: "NonCompliant", evidence: ev(ctx, services.map((service) => service.line)) };
      }
      if (profile.management.httpEnabled === false) return { status: "Compliant", evidence: [] };
      return { status: "NotApplicable", evidence: [] };
    },
  },
  {
    id: "NET-MGMT-003",
    title: "SSHv1 allowed or SSH hardening state unknown",
    severity: "High",
    category: "Management",
    description:
      "SSH version 1 has well-known integrity and interception flaws and is prohibited by every major benchmark. Where the device supports SSH, the configured version must be pinned to 2.",
    recommendation:
      "Set `ip ssh version 2` (Cisco), `set system services ssh protocol-version v2` (JunOS), or the platform equivalent; disable v1 fallback.",
    references: [CIS_BENCH, NIST_AC],
    applies: (ctx) =>
      profileHasManagement(ctx.profile) &&
      (isCiscoIosFamily(ctx.profile.vendor) || ctx.profile.vendor === "juniper-junos" || ctx.profile.vendor === "cisco-asa" || ctx.profile.vendor === "cisco-wlc"),
    evaluate: (ctx) => {
      const { profile } = ctx;
      if (profile.management.sshVersion === "1") {
        return { status: "NonCompliant", evidence: ev(ctx, []) };
      }
      if (profile.management.sshVersion === "2" || profile.management.sshVersion === "v2") {
        return { status: "Compliant", evidence: [] };
      }
      if (profile.management.sshEnabled === true) {
        return { status: "NonCompliant", evidence: [] };
      }
      return { status: "NotApplicable", evidence: [] };
    },
  },
  {
    id: "NET-MGMT-004",
    title: "Direct root SSH login permitted",
    severity: "Medium",
    category: "Management",
    description:
      "Direct root/administrator login over SSH bypasses per-admin accountability and shared-credential rotation. Benchmarks require it to be disabled.",
    recommendation:
      "Disable direct root SSH (`set system services ssh root-login deny-password`) and require named accounts elevated by AAA.",
    references: [CIS_BENCH, NIST_IA],
    applies: (ctx) => ctx.profile.services.some((service) => /root login/i.test(service.name)),
    evaluate: (ctx) => {
      const offenders = ctx.profile.services.filter((service) => /root login/i.test(service.name) && service.enabled);
      if (offenders.length > 0) {
        return { status: "NonCompliant", evidence: ev(ctx, offenders.map((service) => service.line)) };
      }
      return { status: "Compliant", evidence: [] };
    },
  },
  {
    id: "NET-MGMT-005",
    title: "Management plane not restricted by ACL or trusted hosts",
    severity: "High",
    category: "Management",
    description:
      "Administrative access (SSH/Telnet/HTTP) is reachable from any source. Management planes must only be reachable from designated jump hosts/administration networks.",
    recommendation:
      "Apply `access-class` to vty lines (Cisco), `allowed-ip`/`trustedhost` entries (FortiOS/ProCurve), or firewall-zone restrictions so only admin subnets reach the device.",
    references: [CIS_BENCH, NIST_AC, CIS_V8],
    applies: (ctx) =>
      profileHasManagement(ctx.profile) &&
      (isCiscoIosFamily(ctx.profile.vendor) ||
        ctx.profile.vendor === "cisco-asa" ||
        ctx.profile.vendor === "fortinet" ||
        ctx.profile.vendor === "aruba-switch"),
    evaluate: (ctx) => {
      const { profile } = ctx;
      if (profile.management.vtyAcl !== null || profile.management.mgmtHosts.length > 0) {
        return {
          status: "Compliant",
          evidence: ev(ctx, []),
        };
      }
      return { status: "NonCompliant", evidence: [] };
    },
  },
  {
    id: "NET-MGMT-006",
    title: "Idle session timeout not enforced on vty lines",
    severity: "Medium",
    category: "Management",
    description:
      "Without `exec-timeout`, abandoned privileged sessions stay open indefinitely — a workstation left unattended becomes an open management console.",
    recommendation: "Set vty and console `exec-timeout 10 0` (10 minutes) or shorter.",
    references: [CIS_BENCH],
    applies: (ctx) => isCiscoIosFamily(ctx.profile.vendor) || ctx.profile.vendor === "cisco-asa",
    evaluate: (ctx) => {
      const timeout = ctx.profile.management.vtyExecTimeout;
      if (timeout === null) return { status: "NonCompliant", evidence: [] };
      const minutes = Number(timeout.split(":")[0]);
      if (Number.isFinite(minutes) && minutes > 0 && minutes <= 10) {
        return { status: "Compliant", evidence: [] };
      }
      return { status: "NonCompliant", evidence: [] };
    },
  },
  {
    id: "NET-MGMT-007",
    title: "Console idle timeout not enforced",
    severity: "Low",
    category: "Management",
    description: "An unattended console port with no timeout keeps a privileged session open indefinitely.",
    recommendation: "Set console `exec-timeout 10 0` and enable `logging synchronous`.",
    references: [CIS_BENCH],
    applies: (ctx) => isCiscoIosFamily(ctx.profile.vendor),
    evaluate: (ctx) => {
      const timeout = ctx.profile.management.consoleExecTimeout;
      if (timeout === null) return { status: "NonCompliant", evidence: [] };
      const minutes = Number(timeout.split(":")[0]);
      if (Number.isFinite(minutes) && minutes > 0 && minutes <= 10) return { status: "Compliant", evidence: [] };
      return { status: "NonCompliant", evidence: [] };
    },
  },
  {
    id: "NET-MGMT-008",
    title: "No brute-force lockout for management logins",
    severity: "Low",
    category: "Management",
    description:
      "The device accepts unlimited authentication attempts. Rate-limiting/lockout slows credential guessing and generates evidence of the attempt.",
    recommendation:
      "Configure `login block-for <sec> attempts <n> within <sec>` (Cisco) or `set system login retry-options` (JunOS), and log failures.",
    references: [CIS_BENCH, NIST_AC],
    applies: (ctx) => isCiscoIosFamily(ctx.profile.vendor) || ctx.profile.vendor === "juniper-junos",
    evaluate: (ctx) => {
      const enabled = ctx.profile.services.some((service) => /retry options/i.test(service.name)) || ctx.profile.management.loginBlockFor !== null;
      if (enabled) return { status: "Compliant", evidence: [] };
      return { status: "NonCompliant", evidence: [] };
    },
  },
  {
    id: "NET-MGMT-009",
    title: "Default or embedded vendor credentials in use",
    severity: "Critical",
    category: "Authentication",
    description:
      "A well-known default account (admin/cisco/ubnt/…) is present with plaintext or missing credentials. Default credential lists are the first thing an attacker tries.",
    recommendation:
      "Rename or disable default accounts, set unique strong credentials, and record the change in the credential vault.",
    references: [CIS_BENCH, "CISA Known Exploited Vulnerabilities — default credentials guidance"],
    applies: (ctx) => ctx.profile.users.length > 0,
    evaluate: (ctx) => {
      const defaults = new Set(["admin", "cisco", "ubnt", "root", "manager", "operator"]);
      const offenders = ctx.profile.users.filter(
        (user) => defaults.has(user.name.toLowerCase()) && /cleartext|none|no password/i.test(user.hashType),
      );
      if (offenders.length > 0) {
        return { status: "NonCompliant", evidence: ev(ctx, offenders.map((user) => user.line)) };
      }
      return { status: "Compliant", evidence: [] };
    },
  },
  {
    id: "NET-MGMT-010",
    title: "Legal warning banner not configured",
    severity: "Low",
    category: "Management",
    description:
      "A login banner establishing ownership, authorized use, and monitoring notice supports prosecution and deters casual access. Its absence is a governance gap.",
    recommendation: "Configure `banner motd` (Cisco), `login message`/`set system login announcement` (JunOS), or the platform equivalent.",
    references: [CIS_BENCH],
    applies: (ctx) =>
      isCiscoIosFamily(ctx.profile.vendor) || ctx.profile.vendor === "juniper-junos" || ctx.profile.vendor === "cisco-asa" || ctx.profile.vendor === "fortinet",
    evaluate: (ctx) => {
      if (ctx.profile.banners.length > 0) {
        return { status: "Compliant", evidence: ev(ctx, ctx.profile.banners.map((banner) => banner.line)) };
      }
      return { status: "NonCompliant", evidence: [] };
    },
  },
  {
    id: "NET-MGMT-011",
    title: "Minimum password length policy not set",
    severity: "Low",
    category: "Authentication",
    description: "Without a minimum length policy, short passwords satisfy the device defaults and fall to brute force.",
    recommendation: "Set `security passwords min-length 15` (Cisco) or the platform equivalent, and rotate regularly.",
    references: [CIS_BENCH, NIST_IA],
    applies: (ctx) => isCiscoIosFamily(ctx.profile.vendor),
    evaluate: (ctx) => {
      const min = ctx.profile.management.minPasswordLength;
      if (min === null) return { status: "NonCompliant", evidence: [] };
      if (min >= 8) return { status: "Compliant", evidence: [] };
      return { status: "NonCompliant", evidence: [] };
    },
  },

  // ---- SNMP ----
  {
    id: "NET-SNMP-001",
    title: "Default SNMP community strings in use",
    severity: "Critical",
    category: "SNMP",
    description:
      "The well-known `public`/`private` community strings (or vendor defaults) are active. They are attempted first by any scanning tool and expose full device state — or write access.",
    recommendation:
      "Delete default communities, create unique randomized strings (or better, move to SNMPv3 with authPriv), and restrict with ACLs.",
    references: [CIS_BENCH, NIST_IA],
    applies: (ctx) => ctx.profile.snmp.communities.length > 0,
    evaluate: (ctx) => {
      const defaults = ctx.profile.snmp.communities.filter((community) => isDefaultCommunity(community.value));
      if (defaults.length > 0) {
        return { status: "NonCompliant", evidence: ev(ctx, defaults.map((community) => community.line)) };
      }
      return { status: "Compliant", evidence: ev(ctx, ctx.profile.snmp.communities.slice(0, 3).map((community) => community.line)) };
    },
  },
  {
    id: "NET-SNMP-002",
    title: "SNMPv1/v2c in use without SNMPv3",
    severity: "High",
    category: "SNMP",
    description:
      "SNMPv1/v2c authenticate with plaintext community strings and send responses unencrypted, allowing both credential sniffing and traffic replay. SNMPv3 with authPriv fixes both.",
    recommendation:
      "Create SNMPv3 users/groups with authentication and privacy (`snmp-server group … v3 priv`, JunOS `snmp v3`), then remove v1/v2c communities.",
    references: [CIS_BENCH, NIST_AC],
    applies: (ctx) => ctx.profile.snmp.enabled,
    evaluate: (ctx) => {
      const { profile } = ctx;
      if (profile.snmp.v3Configured && profile.snmp.communities.length === 0) {
        return { status: "Compliant", evidence: ev(ctx, [profile.snmp.line]) };
      }
      if (profile.snmp.communities.length > 0) {
        return { status: "NonCompliant", evidence: ev(ctx, [profile.snmp.line, ...profile.snmp.communities.map((community) => community.line)]) };
      }
      if (profile.snmp.v3Configured) return { status: "Compliant", evidence: ev(ctx, [profile.snmp.line]) };
      return { status: "NonCompliant", evidence: ev(ctx, [profile.snmp.line]) };
    },
  },
  {
    id: "NET-SNMP-003",
    title: "Read-write (RW) SNMP community configured",
    severity: "Critical",
    category: "SNMP",
    description:
      "A read-write community grants full configuration changes over SNMP — equivalent to handing out a privileged CLI account, often with no per-user accountability.",
    recommendation: "Remove RW communities; if write access is unavoidable, use SNMPv3 views scoped to specific OIDs with authPriv.",
    references: [CIS_BENCH, PCI_DSS],
    applies: (ctx) => ctx.profile.snmp.communities.length > 0 || ctx.profile.snmp.v3Configured === true,
    evaluate: (ctx) => {
      const rw = ctx.profile.snmp.communities.filter((community) => community.access === "rw");
      if (rw.length > 0) {
        return { status: "NonCompliant", evidence: ev(ctx, rw.map((community) => community.line)) };
      }
      // SNMPv3-only deployments (no communities at all) are compliant here.
      return { status: "Compliant", evidence: ev(ctx, ctx.profile.snmp.communities.slice(0, 2).map((community) => community.line)) };
    },
  },
  {
    id: "NET-SNMP-004",
    title: "SNMP not restricted by ACL / client list",
    severity: "Medium",
    category: "SNMP",
    description: "SNMP answers queries from any source address. Pollers should be pinned to management hosts by ACL or client list.",
    recommendation: "Attach an ACL to every community (`snmp-server community X RO 10`) or an SNMP client list (JunOS/Aruba).",
    references: [CIS_BENCH],
    applies: (ctx) => ctx.profile.snmp.communities.length > 0,
    evaluate: (ctx) => {
      const unrestricted = ctx.profile.snmp.communities.filter((community) => community.acl === null || community.acl === "");
      if (unrestricted.length > 0) {
        return { status: "NonCompliant", evidence: ev(ctx, unrestricted.map((community) => community.line)) };
      }
      return { status: "Compliant", evidence: [] };
    },
  },

  // ---- Logging & time ----
  {
    id: "NET-LOG-001",
    title: "No remote syslog destination configured",
    severity: "Medium",
    category: "Logging",
    description:
      "Event history lives only on the device and is lost on reboot, log rotation, or tampering. Centralized logging is required for incident response and retention policy.",
    recommendation:
      "Send logs to at least one central collector (`logging host`, `set system syslog host`, FortiOS `log syslogd setting`) and protect the collector.",
    references: [CIS_BENCH, NIST_AU],
    applies: (ctx) =>
      ctx.profile.logging.enabled !== null || isCiscoIosFamily(ctx.profile.vendor) || ctx.profile.vendor === "fortinet" || ctx.profile.vendor === "juniper-junos",
    evaluate: (ctx) => {
      const { profile } = ctx;
      if (profile.logging.hosts.length > 0) {
        return { status: "Compliant", evidence: ev(ctx, [profile.logging.line]) };
      }
      return { status: "NonCompliant", evidence: ev(ctx, [profile.logging.line]) };
    },
  },
  {
    id: "NET-LOG-002",
    title: "Log timestamps not synchronized (no service timestamps / NTP-backed clock)",
    severity: "Low",
    category: "Logging",
    description:
      "Without datetime timestamps the forensic value of logs collapses: events cannot be correlated across devices or with other evidence.",
    recommendation: "Enable `service timestamps log datetime msec` and set the clock from authenticated NTP.",
    references: [CIS_BENCH, NIST_AU],
    applies: (ctx) => isCiscoIosFamily(ctx.profile.vendor),
    evaluate: (ctx) => {
      if (ctx.profile.logging.timestamps === true) return { status: "Compliant", evidence: [] };
      return { status: "NonCompliant", evidence: [] };
    },
  },
  {
    id: "NET-NTP-001",
    title: "No NTP time source configured",
    severity: "Medium",
    category: "Time synchronization",
    description:
      "Without NTP the device clock drifts, certificates and logs become untrustworthy, and event correlation across the estate is impossible.",
    recommendation: "Configure at least two internal NTP servers (or trusted public pool) on every infrastructure device.",
    references: [CIS_BENCH, NIST_AU],
    applies: (ctx) =>
      ctx.profile.ntp.line !== null || isCiscoIosFamily(ctx.profile.vendor) || ctx.profile.vendor === "fortinet" || ctx.profile.vendor === "juniper-junos" || ctx.profile.vendor === "palo-alto",
    evaluate: (ctx) => {
      if (ctx.profile.ntp.servers.length > 0) {
        return { status: "Compliant", evidence: ev(ctx, [ctx.profile.ntp.line]) };
      }
      return { status: "NonCompliant", evidence: ev(ctx, [ctx.profile.ntp.line]) };
    },
  },
  {
    id: "NET-NTP-002",
    title: "NTP authentication not enabled",
    severity: "Low",
    category: "Time synchronization",
    description:
      "Unauthenticated NTP lets an attacker spoof time responses — invalidating logs and potentially breaking certificate validation or Kerberos-style authentication downstream.",
    recommendation: "Enable NTP authentication with a keyed MD5/SHA key against the internal NTP servers.",
    references: [CIS_BENCH],
    applies: (ctx) => ctx.profile.ntp.servers.length > 0 && ctx.profile.ntp.authenticated !== null,
    evaluate: (ctx) => {
      if (ctx.profile.ntp.authenticated === true) return { status: "Compliant", evidence: ev(ctx, [ctx.profile.ntp.line]) };
      return { status: "NonCompliant", evidence: ev(ctx, [ctx.profile.ntp.line]) };
    },
  },

  // ---- Firewall policy ----
  {
    id: "NET-FW-001",
    title: "Permissive firewall rule (any/any allow)",
    severity: "High",
    category: "Firewall policy",
    description:
      "A rule permitting all sources to all destinations on all services defeats the purpose of the firewall. Rules must be scoped to required source/destination/service tuples.",
    recommendation:
      "Replace any/any rules with explicit app/service rules, place stricter rules above broader ones, and enable logging on deny where useful.",
    references: [CIS_BENCH_FW, NIST_AC],
    applies: (ctx) => ctx.profile.firewallRules.length > 0,
    evaluate: (ctx) => {
      const permissive = ctx.profile.firewallRules.filter(
        (rule) =>
          /accept|allow|permit/i.test(rule.action ?? "") &&
          /any|all/i.test(rule.source ?? "") &&
          /any|all/i.test(rule.destination ?? "") &&
          /any|all/i.test(rule.service ?? ""),
      );
      if (permissive.length > 0) {
        return { status: "NonCompliant", evidence: permissive.map((rule) => policyLineAt(ctx, rule.line)).filter((entry): entry is string => entry !== null).slice(0, 8) };
      }
      return { status: "Compliant", evidence: ev(ctx, ctx.profile.firewallRules.slice(0, 2).map((rule) => rule.line)) };
    },
  },
  {
    id: "NET-FW-002",
    title: "Firewall device has no access policy rules",
    severity: "High",
    category: "Firewall policy",
    description:
      "No firewall policy (security rules / access-lists / policy entries) was found in the configuration. Either the export is incomplete or the device forwards without an enforced policy.",
    recommendation:
      "Re-export the full running configuration and verify an explicit deny-by-default policy exists between security zones.",
    references: [CIS_BENCH_FW, NIST_AC],
    applies: (ctx) => ctx.profile.deviceType === "firewall",
    evaluate: (ctx) => {
      if (ctx.profile.firewallRules.length > 0 || ctx.profile.acls.length > 0) {
        return { status: "Compliant", evidence: [] };
      }
      return { status: "NonCompliant", evidence: [] };
    },
  },
  {
    id: "NET-FW-003",
    title: "ACL contains permit ip any any",
    severity: "High",
    category: "Firewall policy",
    description:
      "An ACL with a leading `permit … any any` entry neutralizes every rule below it. Traffic that should be filtered passes freely.",
    recommendation: "Review ACL entry order, scope each permit to required flows, and end extended ACLs with an explicit `deny ip any any log`.",
    references: [CIS_BENCH, NIST_AC],
    applies: (ctx) => ctx.profile.acls.length > 0,
    evaluate: (ctx) => {
      const offenders: Array<{ name: string; n: number }> = [];
      for (const acl of ctx.profile.acls) {
        for (const rule of acl.rules) {
          if (rule.action === "permit" && /(^|\s)any\s+any(\s|$)/i.test(rule.text)) {
            offenders.push({ name: acl.name, n: rule.n });
            break;
          }
        }
      }
      if (offenders.length > 0) {
        return { status: "NonCompliant", evidence: ev(ctx, offenders.map((entry) => entry.n)) };
      }
      return { status: "Compliant", evidence: [] };
    },
  },
  {
    id: "NET-FW-004",
    title: "Untrusted interface without ingress filtering",
    severity: "Medium",
    category: "Firewall policy",
    description:
      "An outside/untrust interface (ASA security-level 0 or WAN role) has no inbound access-group/policy attached, so only interface defaults protect it.",
    recommendation: "Bind an explicit inbound ACL/policy to untrusted interfaces and log denied attempts.",
    references: [CIS_BENCH_FW],
    applies: (ctx) =>
      ctx.profile.vendor === "cisco-asa" ||
      (ctx.profile.vendor === "fortinet" && ctx.profile.interfaces.some((iface) => /wan|untrust/i.test(`${iface.name} ${iface.description ?? ""}`))),
    evaluate: (ctx) => {
      const untrusted = ctx.profile.interfaces.filter((iface) => iface.securityLevel === 0 || /wan|untrust/i.test(`${iface.name} ${iface.description ?? ""}`));
      const unprotected = untrusted.filter((iface) => iface.aclIn === null && iface.aclOut === null);
      if (untrusted.length === 0) return { status: "NotApplicable", evidence: [] };
      if (unprotected.length > 0) {
        return { status: "NonCompliant", evidence: ev(ctx, unprotected.map((iface) => iface.line)) };
      }
      return { status: "Compliant", evidence: [] };
    },
  },
  {
    id: "NET-FW-005",
    title: "Cleartext management services exposed on WAN-facing interface",
    severity: "High",
    category: "Management",
    description:
      "The WAN/untrust interface allows cleartext management protocols (telnet/http/snmp) from any source. These transmit credentials and configuration in the clear and are continuously probed on internet-facing addresses.",
    recommendation:
      "Remove cleartext management services from WAN interfaces (FortiOS `allowaccess`), bind mgmt to an inside interface, or restrict to VPN/admin subnets. Prefer HTTPS/SSH with restricted source IPs.",
    references: [CIS_BENCH_FW, NIST_AC],
    applies: (ctx) => ctx.profile.management.allowAccess.length > 0,
    evaluate: (ctx) => {
      const wan = ctx.profile.interfaces.filter((iface) => /wan|untrust|internet/i.test(`${iface.name} ${iface.description ?? ""}`));
      const exposed = ctx.profile.management.allowAccess.filter((entry) => {
        const name = entry.split(":")[0];
        const service = entry.split(":")[1] ?? "";
        const isWan = wan.some((iface) => iface.name === name);
        // ping/https/ssh are accepted hardening trade-offs; only cleartext
        // protocols make the interface NonCompliant.
        return isWan && /telnet|http(?!s)|snmp/i.test(service);
      });
      if (exposed.length > 0) {
        return { status: "NonCompliant", evidence: ev(ctx, wan.map((iface) => iface.line)) };
      }
      return { status: "Compliant", evidence: [] };
    },
  },

  // ---- VPN ----
  {
    id: "NET-VPN-001",
    title: "Weak IKE/IPsec proposal (DES/3DES/MD5/SHA1 or low DH group)",
    severity: "Critical",
    category: "VPN",
    description:
      "The IKE/IPsec proposals include broken or deprecated algorithms (DES, 3DES, MD5, SHA-1) or Diffie-Hellman groups below 14. These are within reach of state adversaries and are flagged by PCI-DSS.",
    recommendation:
      "Use AES-GCM-256 with SHA-384/SHA-256 and DH group 19/20 (or 14+ minimum). Remove weak proposals from the policy so they cannot be negotiated down to.",
    references: [CIS_BENCH_FW, "NIST SP 800-77", PCI_DSS],
    applies: (ctx) => ctx.profile.vpns.length > 0,
    evaluate: (ctx) => {
      const critical: number[] = [];
      const high: number[] = [];
      for (const vpn of ctx.profile.vpns) {
        for (const cipher of vpn.encryption) {
          if (/\bdes\b(?!3)/i.test(cipher) || /\bnull\b/i.test(cipher)) critical.push(vpn.line);
          else if (/3des|sha1(?!60)/i.test(cipher)) high.push(vpn.line);
        }
        for (const hash of vpn.auth) {
          if (/\bmd5\b/i.test(hash)) critical.push(vpn.line);
          else if (/\bsha1(?!60)\b/i.test(hash)) high.push(vpn.line);
        }
        const group = Number(vpn.dhGroup);
        if (Number.isFinite(group) && group > 0 && group < 14) high.push(vpn.line);
      }
      if (critical.length > 0) return { status: "NonCompliant", evidence: ev(ctx, critical) };
      if (high.length > 0) return { status: "NonCompliant", evidence: ev(ctx, high) };
      return { status: "Compliant", evidence: ev(ctx, ctx.profile.vpns.slice(0, 2).map((vpn) => vpn.line)) };
    },
  },
  {
    id: "NET-VPN-002",
    title: "Site-to-site VPN relies on pre-shared keys",
    severity: "Medium",
    category: "VPN",
    description:
      "Pre-shared keys appear in cleartext in exports and backups, are shared symmetric secrets, and rarely rotate. Certificate-based IKE removes all three problems.",
    recommendation: "Migrate IKE peers to RSA/ECC certificates; when PSKs are unavoidable, make them long/high-entropy and store them in a vault.",
    references: [CIS_BENCH_FW, "NIST SP 800-77"],
    applies: (ctx) => ctx.profile.vpns.length > 0,
    evaluate: (ctx) => {
      const psk = ctx.profile.vpns.filter((vpn) => vpn.preSharedKey);
      if (psk.length > 0) {
        return { status: "NonCompliant", evidence: ev(ctx, psk.map((vpn) => vpn.line)) };
      }
      return { status: "Compliant", evidence: [] };
    },
  },
  {
    id: "NET-VPN-003",
    title: "IKE aggressive mode enabled (PSK exposure)",
    severity: "High",
    category: "VPN",
    description:
      "Aggressive mode exchanges identities and hashes before encryption, allowing offline dictionary attacks against the pre-shared key from a single captured handshake.",
    recommendation: "Use IKEv2 (or main mode with certificates). Disable aggressive-mode peer policies.",
    references: [CIS_BENCH_FW, "NIST SP 800-77"],
    applies: (ctx) => ctx.profile.vpns.length > 0,
    evaluate: (ctx) => {
      const aggressive = ctx.profile.vpns.filter((vpn) => vpn.aggressiveMode);
      if (aggressive.length > 0) {
        return { status: "NonCompliant", evidence: ev(ctx, aggressive.map((vpn) => vpn.line)) };
      }
      return { status: "Compliant", evidence: [] };
    },
  },

  // ---- Switching ----
  {
    id: "NET-SW-001",
    title: "DHCP snooping not enabled",
    severity: "Medium",
    category: "Switching",
    description:
      "Without DHCP snooping, a rogue DHCP server on user ports can hand out a malicious default gateway/DNS — enabling man-in-the-middle of the whole segment.",
    recommendation: "Enable `ip dhcp snooping` and `ip dhcp snooping vlan <user-vlans>`, and mark only uplinks as trusted.",
    references: [CIS_BENCH],
    applies: (ctx) => (ctx.profile.deviceType === "switch" && isCiscoIosFamily(ctx.profile.vendor)) || ctx.profile.vendor === "aruba-switch",
    evaluate: (ctx) => {
      const enabled = ctx.profile.services.some((service) => /dhcp snooping/i.test(service.name) && service.enabled);
      if (enabled) return { status: "Compliant", evidence: ev(ctx, ctx.profile.services.filter((service) => /dhcp snooping/i.test(service.name)).map((service) => service.line)) };
      return { status: "NonCompliant", evidence: [] };
    },
  },
  {
    id: "NET-SW-002",
    title: "Dynamic ARP Inspection not enabled",
    severity: "Medium",
    category: "Switching",
    description:
      "Without DAI, any host can send gratuitous ARP replies and spoof the gateway MAC — the classic MITM on flat networks. DAI builds on DHCP snooping bindings.",
    recommendation: "Enable `ip arp inspection vlan <user-vlans>` with trusted uplinks and a binding database.",
    references: [CIS_BENCH],
    applies: (ctx) => ctx.profile.deviceType === "switch" && isCiscoIosFamily(ctx.profile.vendor),
    evaluate: (ctx) => {
      const enabled = ctx.profile.services.some((service) => /arp inspection/i.test(service.name) && service.enabled);
      if (enabled) return { status: "Compliant", evidence: ev(ctx, ctx.profile.services.filter((service) => /arp inspection/i.test(service.name)).map((service) => service.line)) };
      return { status: "NonCompliant", evidence: [] };
    },
  },
  {
    id: "NET-SW-003",
    title: "VLAN 1 used as native VLAN on trunks",
    severity: "Medium",
    category: "Switching",
    description:
      "The default native VLAN carries untagged frames and is a well-known VLAN-hopping vector. Benchmarks require moving the native VLAN to an unused ID and pruning it from trunks.",
    recommendation: "Set `switchport trunk native vlan <unused-id>` on every trunk and remove VLAN 1 with `switchport trunk allowed vlan remove 1`.",
    references: [CIS_BENCH],
    applies: (ctx) => ctx.profile.interfaces.some((iface) => iface.mode === "trunk"),
    evaluate: (ctx) => {
      const trunks = ctx.profile.interfaces.filter((iface) => iface.mode === "trunk");
      const vlan1Native = trunks.filter((iface) => iface.nativeVlan === "1");
      const untaggedNative = trunks.filter((iface) => iface.nativeVlan === null);
      if (vlan1Native.length > 0) {
        return { status: "NonCompliant", evidence: ev(ctx, vlan1Native.map((iface) => iface.line)) };
      }
      if (untaggedNative.length === trunks.length && isCiscoIosFamily(ctx.profile.vendor)) {
        return { status: "NonCompliant", evidence: ev(ctx, trunks.slice(0, 4).map((iface) => iface.line)) };
      }
      return { status: "Compliant", evidence: ev(ctx, trunks.slice(0, 3).map((iface) => iface.line)) };
    },
  },
  {
    id: "NET-SW-004",
    title: "Trunks carry VLAN 1 (no pruning)",
    severity: "Low",
    category: "Switching",
    description: "Trunks that allow VLAN 1 expose the management/default VLAN across the switching fabric and widen hopping blast radius.",
    recommendation: "Add `switchport trunk allowed vlan <required>` (explicit list) or `switchport trunk allowed vlan except 1`.",
    references: [CIS_BENCH],
    applies: (ctx) => ctx.profile.interfaces.some((iface) => iface.mode === "trunk" && iface.allowedVlans !== null),
    evaluate: (ctx) => {
      const offenders = ctx.profile.interfaces.filter(
        (iface) => iface.mode === "trunk" && iface.allowedVlans !== null && /(^|[,\s])1([,\s]|$)/.test(iface.allowedVlans ?? ""),
      );
      const allVlans = ctx.profile.interfaces.filter((iface) => /all/i.test(iface.allowedVlans ?? ""));
      if (offenders.length + allVlans.length > 0) {
        return { status: "NonCompliant", evidence: ev(ctx, [...offenders, ...allVlans].map((iface) => iface.line)) };
      }
      return { status: "Compliant", evidence: [] };
    },
  },
  {
    id: "NET-SW-005",
    title: "Unused switch ports not administratively disabled",
    severity: "Medium",
    category: "Switching",
    description:
      "Open wall ports are free network access for visitors and attackers. Ports with no configuration and no shutdown remain live by default on Cisco/Aruba switches.",
    recommendation: "Shut down all unused access ports (`shutdown`) — or place them in a quarantine VLAN with no uplink.",
    references: [CIS_BENCH],
    applies: (ctx) =>
      (ctx.profile.deviceType === "switch" || ctx.profile.interfaces.some((iface) => iface.mode === "access")) &&
      (isCiscoIosFamily(ctx.profile.vendor) || ctx.profile.vendor === "aruba-switch") &&
      ctx.profile.interfaces.length >= 8,
    evaluate: (ctx) => {
      const physical = ctx.profile.interfaces.filter((iface) => /^(Gi|Te|Fa|Eth|1\/|2\/|3\/|\d)/i.test(iface.name) && !/vlan/i.test(iface.name));
      const unused = physical.filter((iface) => iface.adminEnabled === null && iface.mode === "unknown" && iface.accessVlan === null && iface.description === null);
      if (physical.length === 0) return { status: "NotApplicable", evidence: [] };
      if (unused.length > 0) {
        return {
          status: "NonCompliant",
          evidence: [`${unused.length} of ${physical.length} ports appear unused and are not shut down (e.g. ${unused.slice(0, 3).map((iface) => iface.name).join(", ")})`],
        };
      }
      return { status: "Compliant", evidence: [] };
    },
  },
  {
    id: "NET-SW-006",
    title: "Port security not enabled on access ports",
    severity: "Low",
    category: "Switching",
    description: "Access ports accept unlimited MAC addresses, enabling MAC flooding against the CAM table and unauthorized multi-device hubs.",
    recommendation: "Enable `switchport port-security maximum 1` with violation shutdown (or 802.1X where deployed).",
    references: [CIS_BENCH],
    applies: (ctx) =>
      ctx.profile.interfaces.some((iface) => iface.mode === "access") && (isCiscoIosFamily(ctx.profile.vendor) || ctx.profile.vendor === "aruba-switch"),
    evaluate: (ctx) => {
      const access = ctx.profile.interfaces.filter((iface) => iface.mode === "access");
      const unprotected = access.filter((iface) => iface.portSecurity !== true);
      if (access.length === 0) return { status: "NotApplicable", evidence: [] };
      if (unprotected.length === access.length) {
        return { status: "NonCompliant", evidence: ev(ctx, access.slice(0, 3).map((iface) => iface.line)) };
      }
      if (unprotected.length > 0) {
        return { status: "NonCompliant", evidence: ev(ctx, unprotected.slice(0, 3).map((iface) => iface.line)) };
      }
      return { status: "Compliant", evidence: [] };
    },
  },

  // ---- Wireless ----
  {
    id: "NET-WIFI-001",
    title: "WEP-secured or open SSID broadcast",
    severity: "Critical",
    category: "Wireless",
    description:
      "WEP is broken (cracked in minutes) and open networks provide no confidentiality or integrity. Both invite passive capture and hostile clients onto the attached network.",
    recommendation: "Close open/WEP SSIDs or isolate them in a guest VLAN with no access to internal resources; use WPA2/WPA3-Enterprise where possible.",
    references: [CIS_BENCH, "NIST SP 800-153"],
    applies: (ctx) => ctx.profile.wirelessLans.length > 0,
    evaluate: (ctx) => {
      const wep = ctx.profile.wirelessLans.filter((wlan) => /wep/i.test(wlan.authMode));
      if (wep.length > 0) return { status: "NonCompliant", severity: "Critical", evidence: ev(ctx, wep.map((wlan) => wlan.line)) };
      const open = ctx.profile.wirelessLans.filter((wlan) => /open|opensystem|none/i.test(wlan.authMode));
      if (open.length > 0) return { status: "NonCompliant", severity: "High", evidence: ev(ctx, open.map((wlan) => wlan.line)) };
      return { status: "Compliant", evidence: ev(ctx, ctx.profile.wirelessLans.slice(0, 3).map((wlan) => wlan.line)) };
    },
  },
  {
    id: "NET-WIFI-002",
    title: "TKIP or WPA-only encryption on SSID",
    severity: "Medium",
    category: "Wireless",
    description:
      "TKIP and WPA(prepended) are deprecated — TKIP is broken (Michael/temporal key attacks) and is prohibited by 802.11-2012 and Wi-Fi Alliance certification.",
    recommendation: "Require WPA2-AES/CCMP at minimum (prefer WPA3-SAE/Enterprise). Remove TKIP pairings from SSID security configuration.",
    references: [CIS_BENCH, "NIST SP 800-153"],
    applies: (ctx) => ctx.profile.wirelessLans.length > 0,
    evaluate: (ctx) => {
      const offenders = ctx.profile.wirelessLans.filter((wlan) => /tkip/i.test(wlan.authMode) || /(^|[^2])wpa(?!2|3|-802)/i.test(wlan.authMode));
      if (offenders.length > 0) return { status: "NonCompliant", evidence: ev(ctx, offenders.map((wlan) => wlan.line)) };
      return { status: "Compliant", evidence: [] };
    },
  },
  {
    id: "NET-WIFI-003",
    title: "Pre-shared key SSIDs without 802.1X (enterprise networks)",
    severity: "Low",
    category: "Wireless",
    description:
      "Shared PSKs cannot attribute traffic to users, survive staff departure, and leak with every device that holds them. 802.1X issues per-user credentials.",
    recommendation: "Move corporate SSIDs to WPA2/WPA3-Enterprise (RADIUS). Keep PSK only on segregated guest networks with periodic rotation.",
    references: [CIS_BENCH, NIST_IA],
    applies: (ctx) => ctx.profile.wirelessLans.some((wlan) => wlan.psk) && ctx.profile.aaa.radiusHosts.length === 0,
    evaluate: (ctx) => {
      const psk = ctx.profile.wirelessLans.filter((wlan) => wlan.psk);
      return { status: "NonCompliant", evidence: ev(ctx, psk.map((wlan) => wlan.line)) };
    },
  },

  // ---- Legacy services / L3 hardening ----
  {
    id: "NET-SVC-001",
    title: "Legacy or unnecessary services enabled",
    severity: "Medium",
    category: "Services",
    description:
      "Finger, small-services, config server, and similar legacy listeners expand the attack surface with decades-old protocol implementations.",
    recommendation: "Disable them explicitly (`no service finger`, `no ip bootp server`, `no service pad`, …) and verify with a port scan.",
    references: [CIS_BENCH],
    applies: (ctx) => isCiscoIosFamily(ctx.profile.vendor) || ctx.profile.vendor === "ubiquiti",
    evaluate: (ctx) => {
      const legacy = ctx.profile.services.filter(
        (service) => service.enabled && /finger|bootp|pad|small-servers|config server|telnet/i.test(service.name),
      );
      if (legacy.length > 0) return { status: "NonCompliant", evidence: ev(ctx, legacy.map((service) => service.line)) };
      return { status: "Compliant", evidence: [] };
    },
  },
  {
    id: "NET-SVC-002",
    title: "IP source routing not disabled",
    severity: "Medium",
    category: "Routing",
    description:
      "Source-routed packets let the sender choose the path — a route-spoofing/trust-bypass technique. Benchmarks require `no ip source-route` on every L3 device.",
    recommendation: "Apply `no ip source-route` globally (Cisco). Verify with an ACL test that source-routed packets are dropped.",
    references: [CIS_BENCH],
    applies: (ctx) => isCiscoIosFamily(ctx.profile.vendor),
    evaluate: (ctx) => {
      const enabled = ctx.profile.services.find((service) => service.name === "ip source-route");
      if (enabled) {
        return enabled.enabled
          ? { status: "NonCompliant", evidence: ev(ctx, [enabled.line]) }
          : { status: "Compliant", evidence: ev(ctx, [enabled.line]) };
      }
      return { status: "NonCompliant", evidence: [] };
    },
  },
  {
    id: "NET-SVC-003",
    title: "CDP enabled globally on edge devices",
    severity: "Low",
    category: "Services",
    description:
      "Cisco Discovery Protocol advertises platform, software version, and VLAN topology to anyone on the segment — free reconnaissance on user-facing or DMZ ports.",
    recommendation: "Disable CDP globally (`no cdp run`) and enable per-interface only on trusted infrastructure links if required.",
    references: [CIS_BENCH],
    applies: (ctx) => isCiscoIosFamily(ctx.profile.vendor),
    evaluate: (ctx) => {
      const cdp = ctx.profile.services.find((service) => service.name === "cdp");
      if (cdp) {
        return cdp.enabled
          ? { status: "NonCompliant", evidence: ev(ctx, [cdp.line]) }
          : { status: "Compliant", evidence: ev(ctx, [cdp.line]) };
      }
      return { status: "NonCompliant", evidence: [] };
    },
  },
  {
    id: "NET-LIFE-001",
    title: "Operating system release past end of support",
    severity: "Medium",
    category: "Lifecycle",
    description:
      "The device runs an OS release the vendor no longer supports: no security patches for newly published CVEs, and working exploits for known flaws are public. Internet-trusting infrastructure on end-of-support software is a standing exposure.",
    recommendation:
      "Upgrade to a supported release train (verify timing against the vendor's end-of-life portal). Interim: restrict management exposure, remove internet reachability, and monitor vendor advisories for the frozen release.",
    references: [PCI_DSS, CIS_V8],
    applies: (ctx) =>
      ctx.profile.osVersion !== null &&
      EOS_MARKERS.some((marker) => (marker.vendor === "any" || marker.vendor === ctx.profile.vendor) && marker.match.test(ctx.profile.osVersion ?? "")),
    evaluate: (ctx) => {
      const version = ctx.profile.osVersion ?? "";
      const marker = EOS_MARKERS.find((entry) => (entry.vendor === "any" || entry.vendor === ctx.profile.vendor) && entry.match.test(version));
      if (!marker) return { status: "Compliant", evidence: [] };
      return { status: "NonCompliant", evidence: [`${marker.product} ${version}: ${marker.note}.`] };
    },
  },
];

function profileHasManagement(profile: ParsedNetworkConfig): boolean {
  return (
    profile.management.sshEnabled === true ||
    profile.management.telnetEnabled === true ||
    profile.management.httpEnabled === true ||
    profile.management.sshVersion !== null ||
    profile.interfaces.some((iface) => iface.aclIn !== null)
  );
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

export type ReviewResult = {
  findings: NetworkFinding[];
  score: number;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    informational: number;
    compliant: number;
    notApplicable: number;
    total: number;
  };
};

/** Runs the whole rule catalog against one parsed configuration. */
export function reviewConfig(profile: ParsedNetworkConfig, lines: RawLine[]): ReviewResult {
  const ctx: RuleContext = { profile, lines };
  const findings: NetworkFinding[] = [];
  for (const rule of RULES) {
    let evidence: Evidence;
    try {
      const applicable = rule.applies(ctx);
      if (!applicable) {
        findings.push(toFinding(rule, "NotApplicable", []));
        continue;
      }
      evidence = rule.evaluate(ctx);
      findings.push(toFinding(rule, evidence.status, evidence.evidence, evidence.severity));
    } catch {
      // A rule must never break the review — degrade to NotApplicable.
      findings.push(toFinding(rule, "NotApplicable", []));
    }
  }

  const summary: ReviewResult["summary"] = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
    compliant: 0,
    notApplicable: 0,
    total: findings.length,
  };
  let failedWeight = 0;
  let applicableWeight = 0;
  const weights: Record<Severity, number> = { Critical: 10, High: 6, Medium: 3, Low: 1, Informational: 0 };
  for (const finding of findings) {
    if (finding.status === "NotApplicable") {
      summary.notApplicable += 1;
      continue;
    }
    if (finding.status === "Compliant") {
      summary.compliant += 1;
    } else {
      const key = finding.severity.toLowerCase() as "critical" | "high" | "medium" | "low" | "informational";
      summary[key] += 1;
    }
    const weight = weights[finding.severity];
    if (weight <= 0) continue;
    applicableWeight += weight;
    if (finding.status === "NonCompliant") failedWeight += weight;
  }
  const score = applicableWeight <= 0 ? 100 : 100 * (1 - failedWeight / applicableWeight);
  return { findings, score: Math.round(score * 100) / 100, summary };
}

function toFinding(rule: Rule, status: ReviewStatus, evidence: string[], severity?: Severity): NetworkFinding {
  return {
    checkId: rule.id,
    title: rule.title,
    severity: severity ?? rule.severity,
    category: rule.category,
    status,
    description: rule.description,
    evidence: evidence.slice(0, 8),
    recommendation: rule.recommendation,
    references: rule.references,
  };
}

/** Rule catalog introspection (used by tests and the UI legend). */
export function ruleCatalog(): Array<Pick<Rule, "id" | "title" | "severity" | "category">> {
  return RULES.map(({ id, title, severity, category }) => ({ id, title, severity, category }));
}
