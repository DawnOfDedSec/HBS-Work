import { useState } from "react";
import { ScopeSelector } from "../components/ScopeSelector";
import { EmptyState } from "../components/EmptyState";
import { CampaignSummary } from "./CampaignSummary";
import { Findings } from "./Findings";
import { Locations } from "./Locations";
import { Telemetry } from "./Telemetry";
import { Treatment } from "./Treatment";

const TABS = ["Summary", "Findings", "Reports", "Locations & Hosts", "Treatment", "Standards", "Telemetry"] as const;
type Tab = (typeof TABS)[number];

type Props = {
  campaignId: number;
  onBack: () => void;
  onOpenHost: (hostId: number) => void;
  onOpenDownloads: (locationId: number) => void;
  onDrilldown: (query: string) => void;
};

/** Campaign workspace shell. Tabs map to the findings/locations/telemetry workspaces. */
export function CampaignDetail({ campaignId, onBack, onOpenHost, onOpenDownloads, onDrilldown }: Props) {
  const [tab, setTab] = useState<Tab>("Summary");

  return (
    <section aria-label={`Campaign ${campaignId}`} className="space-y-4">
      <div className="flex items-center gap-3">
        <button type="button" onClick={onBack} className="rounded border border-slate-700 px-2 py-1 text-sm">
          ← Campaigns
        </button>
        <h2 className="text-lg font-semibold">Campaign #{campaignId}</h2>
      </div>

      <ScopeSelector />

      <div role="tablist" aria-label="Campaign views" className="flex flex-wrap gap-1 border-b border-slate-800">
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
        {tab === "Summary" ? <CampaignSummary campaignId={campaignId} onDrilldown={onDrilldown} /> : null}
        {tab === "Findings" ? <Findings /> : null}
        {tab === "Locations & Hosts" ? (
          <Locations campaignId={campaignId} onOpenHost={onOpenHost} onOpenDownloads={onOpenDownloads} />
        ) : null}
        {tab === "Treatment" ? <Treatment /> : null}
        {tab === "Telemetry" ? <Telemetry /> : null}
        {tab === "Reports" || tab === "Standards" ? (
          <EmptyState title={`${tab} view`} detail="Choose a report scope above to populate this view." />
        ) : null}
      </div>
    </section>
  );
}
