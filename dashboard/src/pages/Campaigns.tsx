import { useEffect, useState } from "react";
import { api, ApiError } from "../api";
import { CreateCampaignModal } from "../components/CreateCampaignModal";
import { EmptyState } from "../components/EmptyState";
import type { Campaign } from "../types";

type Props = { onOpen: (campaignId: number) => void };

export function Campaigns({ onOpen }: Props) {
  const [campaigns, setCampaigns] = useState<Campaign[] | null>(null);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    api
      .listCampaigns()
      .then((rows) => alive && setCampaigns(rows))
      .catch((err) => alive && setError(err instanceof ApiError ? err.message : "failed to load campaigns"));
    return () => {
      alive = false;
    };
  }, []);

  return (
    <section aria-label="Campaigns" className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Campaigns</h2>
        <button
          type="button"
          onClick={() => setCreating(true)}
          className="rounded bg-sky-600 px-3 py-1.5 text-sm font-medium focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
        >
          New campaign
        </button>
      </div>

      {error ? <EmptyState title="Could not load campaigns" detail={error} /> : null}
      {campaigns === null && !error ? <p role="status">Loading campaigns…</p> : null}
      {campaigns && campaigns.length === 0 ? (
        <EmptyState title="No campaigns yet" detail="Create a campaign to issue extractors and receive reports." />
      ) : null}

      <ul className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {(campaigns ?? []).map((campaign) => (
          <li key={campaign.id}>
            <button
              type="button"
              onClick={() => onOpen(campaign.id)}
              className="w-full rounded-lg border border-slate-800 bg-slate-900/60 p-4 text-left hover:bg-slate-800/70 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
            >
              <div className="font-medium">{campaign.name}</div>
              <div className="mt-1 text-xs text-slate-400">
                {campaign.client ?? "—"} · {campaign.status}
              </div>
            </button>
          </li>
        ))}
      </ul>

      <CreateCampaignModal
        open={creating}
        onClose={() => setCreating(false)}
        onCreated={(campaign) => setCampaigns((current) => [...(current ?? []), campaign])}
      />    </section>
  );
}
