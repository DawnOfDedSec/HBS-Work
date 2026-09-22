import type { LucideIcon } from "lucide-react";
import {
  Activity,
  BookOpen,
  FolderKanban,
  LayoutDashboard,
  ListChecks,
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
  | "treatment"
  | "telemetry"
  | "standards"
  | "admin";

export type NavItem = {
  key: RouteKey;
  label: string;
  icon: LucideIcon;
  roles?: AuthUser["role"][];
};

export const NAV_ITEMS: NavItem[] = [
  { key: "overview", label: "Overview", icon: LayoutDashboard },
  { key: "campaigns", label: "Campaigns", icon: FolderKanban },
  { key: "locations", label: "Locations & Hosts", icon: Server },
  { key: "findings", label: "Findings", icon: ListChecks },
  { key: "treatment", label: "Treatment", icon: Wrench },
  { key: "telemetry", label: "Telemetry", icon: Activity },
  { key: "standards", label: "Standards", icon: BookOpen },
  { key: "admin", label: "Admin", icon: Settings, roles: ["super_admin"] },
];

export function visibleNav(role: AuthUser["role"]): NavItem[] {
  return NAV_ITEMS.filter((item) => !item.roles || item.roles.includes(role));
}
