import { useState } from "react";
import {
  DatabaseBackup,
  KeyRound,
  ScrollText,
  Settings,
  ShieldAlert,
  Trash2,
  UsersRound,
  type LucideIcon,
} from "lucide-react";
import { EmptyState, SectionHeader, TabPanel, Tabs, type TabItem } from "../components/ui";
import type { AuthUser } from "../types";
import { Audit } from "./admin/Audit";
import { Backup } from "./admin/Backup";
import { Keys } from "./admin/Keys";
import { Retention } from "./admin/Retention";
import { Users } from "./admin/Users";

type Tab = "users" | "keys" | "retention" | "audit" | "backup";

const TAB_META: Array<{ value: Tab; label: string; icon: LucideIcon }> = [
  { value: "users", label: "Users", icon: UsersRound },
  { value: "keys", label: "Keys", icon: KeyRound },
  { value: "retention", label: "Retention", icon: Trash2 },
  { value: "audit", label: "Audit", icon: ScrollText },
  { value: "backup", label: "Backup", icon: DatabaseBackup },
];

/** Admin workspace hub. Server also enforces super_admin; this is defense in depth. */
export function AdminHub({ role }: { role: AuthUser["role"] }) {
  const [tab, setTab] = useState<Tab>("users");

  if (role !== "super_admin") {
    return (
      <section className="mx-auto flex max-w-7xl flex-col gap-5">
        <SectionHeader
          eyebrow="Govern"
          title="Admin"
          description="Users, issuance keys, retention, audit, and backup."
          icon={Settings}
        />
        <EmptyState
          icon={ShieldAlert}
          title="Administrator access required"
          detail="Your role cannot manage users, keys, or retention."
        />
      </section>
    );
  }

  const items: TabItem[] = TAB_META.map((meta) => ({
    value: meta.value,
    label: meta.label,
    icon: meta.icon,
  }));

  return (
    <section aria-label="Administration" className="mx-auto flex max-w-7xl flex-col gap-5">
      <SectionHeader
        eyebrow="Govern"
        title="Admin"
        description="Console administration: identity, issuance keys, retention, the append-only audit trail, and encrypted backup."
        icon={Settings}
      />

      <Tabs items={items} value={tab} onChange={(value) => setTab(value as Tab)} label="Admin views" idBase="admin-tabs" />

      <TabPanel id="users" active={tab === "users"} idBase="admin-tabs">
        <Users role={role} />
      </TabPanel>
      <TabPanel id="keys" active={tab === "keys"} idBase="admin-tabs">
        <Keys role={role} />
      </TabPanel>
      <TabPanel id="retention" active={tab === "retention"} idBase="admin-tabs">
        <Retention role={role} />
      </TabPanel>
      <TabPanel id="audit" active={tab === "audit"} idBase="admin-tabs">
        <Audit role={role} />
      </TabPanel>
      <TabPanel id="backup" active={tab === "backup"} idBase="admin-tabs">
        <Backup role={role} />
      </TabPanel>
    </section>
  );
}
