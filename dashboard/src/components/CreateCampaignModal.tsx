import { useEffect, useRef, useState } from "react";
import { api, ApiError } from "../api";
import type { Campaign } from "../types";

type Props = {
  open: boolean;
  onClose: () => void;
  onCreated: (campaign: Campaign) => void;
};

/** Accessible campaign creation dialog (with an atomic first location). */
export function CreateCampaignModal({ open, onClose, onCreated }: Props) {
  const [name, setName] = useState("");
  const [client, setClient] = useState("");
  const [scope, setScope] = useState("");
  const [firstLocation, setFirstLocation] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const nameRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (open) nameRef.current?.focus();
  }, [open]);

  if (!open) return null;

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const result = await api.createCampaign({
        name,
        client: client || undefined,
        scope: scope || undefined,
        location: firstLocation ? { name: firstLocation } : undefined,
      });
      onCreated(result);
      onClose();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "could not create campaign");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div role="dialog" aria-modal="true" aria-labelledby="create-campaign-title" className="w-full max-w-md rounded-lg border border-slate-700 bg-slate-950 p-5">
        <h2 id="create-campaign-title" className="text-lg font-semibold">New campaign</h2>
        <form onSubmit={submit} className="mt-4 space-y-3">
          <label className="block text-sm">
            Name
            <input ref={nameRef} value={name} onChange={(e) => setName(e.target.value)} required className="mt-1 w-full rounded border border-slate-700 bg-slate-900 px-2 py-1" />
          </label>
          <label className="block text-sm">
            Client
            <input value={client} onChange={(e) => setClient(e.target.value)} className="mt-1 w-full rounded border border-slate-700 bg-slate-900 px-2 py-1" />
          </label>
          <label className="block text-sm">
            Scope
            <input value={scope} onChange={(e) => setScope(e.target.value)} className="mt-1 w-full rounded border border-slate-700 bg-slate-900 px-2 py-1" />
          </label>
          <label className="block text-sm">
            First location
            <input value={firstLocation} onChange={(e) => setFirstLocation(e.target.value)} className="mt-1 w-full rounded border border-slate-700 bg-slate-900 px-2 py-1" />
          </label>
          {error ? <p role="alert" className="text-sm text-red-400">{error}</p> : null}
          <div className="flex justify-end gap-2 pt-2">
            <button type="button" onClick={onClose} className="rounded border border-slate-700 px-3 py-1.5 text-sm">Cancel</button>
            <button type="submit" disabled={busy} className="rounded bg-sky-600 px-3 py-1.5 text-sm font-medium disabled:opacity-50">
              {busy ? "Creating…" : "Create"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
