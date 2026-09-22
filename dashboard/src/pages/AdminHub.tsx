import { useState } from "react";
import { EmptyState } from "../components/EmptyState";
import type { AuthUser } from "../types";
import { Audit } from "./admin/Audit";
import { Backup } from "./admin/Backup";
import { Keys } from "./admin/Keys";
import { Retention } from "./admin/Retention";
import { Users } from "./admin/Users";

const TABS = ["Users", "Keys", "Retention", "Audit", "Backup"] as const;
type Tab = (typeof TABS)[number];

/** Admin workspace hub. Server also enforces super_admin; this is defense in depth. */
export function AdminHub({ role }: { role: AuthUser["role"] }) {
  const [tab, setTab] = useState<Tab>("Users");
  if (role !== "super_admin") {
    return <EmptyState title="Administrator access required" detail="Your role cannot manage users, keys, or retention." />;
  }
  return (
    <section aria-label="Administration" className="space-y-4">
      <div role="tablist" aria-label="Admin views" className="flex flex-wrap gap-1 border-b border-slate-800">
        {TABS.map((item) => (
          <button
            key={item}
            role="tab"
            type="button"
            aria-selected={tab === item}
            onClick={() => setTab(item)}
            className={`px-3 py-2 text-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 ${
              tab === item ? "border-b-2 border-sky-400 text-sky-200" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            {item}
          </button>
        ))}
      </div>
      <div role="tabpanel" aria-label={tab}>
        {tab === "Users" ? <Users role={role} /> : null}
        {tab === "Keys" ? <Keys role={role} /> : null}
        {tab === "Retention" ? <Retention role={role} /> : null}
        {tab === "Audit" ? <Audit role={role} /> : null}
        {tab === "Backup" ? <Backup role={role} /> : null}
      </div>
    </section>
  );
}
