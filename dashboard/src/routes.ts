import type { LucideIcon } from "lucide-react";
import {
  Activity,
  BookOpen,
  FolderKanban,
  Hammer,
  LayoutDashboard,
  ListChecks,
  Presentation,
  Server,
  Settings,
  Wrench,
} from "lucide-react";
import type { AuthUser } from "./types";

export type RouteKey =
  | "overview"
  | "campaigns"
  | "locations"
  | "findings"
  | "remediation"
  | "treatment"
  | "telemetry"
  | "standards"
  | "executive"
  | "admin";

/** Sidebar groupings for the console shell. */
export type NavGroupKey = "operate" | "analyze" | "govern";

export type NavItem = {
  key: RouteKey;
  label: string;
  icon: LucideIcon;
  group: NavGroupKey;
  /** One-line description surfaced in the command palette and tooltips. */
  description: string;
  /** Extra search terms for the command palette. */
  keywords?: string[];
  roles?: Array<AuthUser["role"]>;
};

export const NAV_GROUP_LABEL: Record<NavGroupKey, string> = {
  operate: "Operate",
  analyze: "Analyze",
  govern: "Govern",
};

export const NAV_GROUP_ORDER: NavGroupKey[] = ["operate", "analyze", "govern"];

export const NAV_ITEMS: NavItem[] = [
  {
    key: "overview",
    label: "Overview",
    icon: LayoutDashboard,
    group: "operate",
    description: "Risk posture, coverage, and freshness",
    keywords: ["dashboard", "home", "risk", "posture"],
  },
  {
    key: "campaigns",
    label: "Campaigns",
    icon: FolderKanban,
    group: "operate",
    description: "Scans, targets, and issued extractors",
    keywords: ["scan", "engagement", "client", "extractor"],
  },
  {
    key: "locations",
    label: "Locations & Hosts",
    icon: Server,
    group: "operate",
    description: "Sites, hosts, and their reports",
    keywords: ["host", "site", "machine", "reports"],
  },
  {
    key: "findings",
    label: "Findings",
    icon: ListChecks,
    group: "operate",
    description: "Search, filter, and triage checks",
    keywords: ["checks", "results", "explorer", "search", "vulnerabilities"],
  },
  {
    key: "treatment",
    label: "Treatment",
    icon: Wrench,
    group: "operate",
    description: "Own, accept, or remediate findings",
    keywords: ["remediation", "accepted risk", "false positive", "assignee"],
  },
  {
    key: "remediation",
    label: "Remediation",
    icon: Hammer,
    group: "operate",
    description: "Grouped fixes, owners, and copy-ready commands",
    keywords: ["fix", "remediation", "commands", "repro", "sysadmin", "runbook"],
  },
  {
    key: "telemetry",
    label: "Telemetry",
    icon: Activity,
    group: "analyze",
    description: "Freshness, ingest health, and runtime",
    keywords: ["freshness", "ingest", "runtime", "health"],
  },
  {
    key: "standards",
    label: "Standards",
    icon: BookOpen,
    group: "analyze",
    description: "CIS, NIST 800-53, ISO 27001, PCI-DSS coverage",
    keywords: ["cis", "nist", "iso", "pci", "compliance", "references"],
  },
  {
    key: "executive",
    label: "Executive Summary",
    icon: Presentation,
    group: "govern",
    description: "Board-ready posture one-pager with presentation and print modes",
    keywords: ["board", "management", "executive", "summary", "presentation", "print", "pdf", "report"],
  },
  {
    key: "admin",
    label: "Admin",
    icon: Settings,
    group: "govern",
    description: "Users, keys, audit, and retention",
    keywords: ["users", "keys", "audit", "retention", "backup"],
    roles: ["super_admin"],
  },
];

export type NavGroup = { key: NavGroupKey; label: string; items: NavItem[] };

export function visibleNav(role: AuthUser["role"]): NavItem[] {
  return NAV_ITEMS.filter((item) => !item.roles || item.roles.includes(role));
}

/** Role-filtered items grouped into the sidebar's Operate/Analyze/Govern sections. */
export function groupedNav(role: AuthUser["role"]): NavGroup[] {
  const items = visibleNav(role);
  return NAV_GROUP_ORDER.map((key) => ({
    key,
    label: NAV_GROUP_LABEL[key],
    items: items.filter((item) => item.group === key),
  })).filter((group) => group.items.length > 0);
}

export function navItem(key: RouteKey): NavItem | undefined {
  return NAV_ITEMS.find((item) => item.key === key);
}

export function routeLabel(key: RouteKey): string {
  return navItem(key)?.label ?? key;
}
