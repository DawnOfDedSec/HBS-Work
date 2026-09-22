import { useEffect, useState } from "react";
import { api, ApiError } from "../api";
import { Button, Input, Modal, useToast } from "./ui";
import type { Campaign } from "../types";

type Props = {
  open: boolean;
  onClose: () => void;
  onCreated: (campaign: Campaign) => void;
};

function parseTags(value: string): string[] {
  return [
    ...new Set(
      value
        .split(",")
        .map((tag) => tag.trim())
        .filter((tag) => tag.length > 0),
    ),
  ];
}

/** Accessible campaign creation dialog (with an atomic first location). */
export function CreateCampaignModal({ open, onClose, onCreated }: Props) {
  const [name, setName] = useState("");
  const [client, setClient] = useState("");
  const [scope, setScope] = useState("");
  const [tags, setTags] = useState("");
  const [firstLocation, setFirstLocation] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const toast = useToast();

  useEffect(() => {
    if (!open) return;
    setName("");
    setClient("");
    setScope("");
    setTags("");
    setFirstLocation("");
    setError(null);
  }, [open]);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const result = await api.createCampaign({
        name,
        client: client || undefined,
        scope: scope || undefined,
        tags: parseTags(tags),
        location: firstLocation ? { name: firstLocation } : undefined,
      });
      onCreated(result);
      toast.success("Campaign created", { description: `${result.name} · campaign #${result.id}` });
      onClose();
    } catch (err) {
      const message = err instanceof ApiError ? err.message : "could not create campaign";
      setError(message);
      toast.error("Could not create campaign", { description: message });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="New campaign"
      description="A campaign groups locations, hosts, and every report received for an engagement."
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" loading={busy} form="create-campaign-form" type="submit">
            Create
          </Button>
        </>
      }
    >
      <form id="create-campaign-form" onSubmit={submit} className="flex flex-col gap-3">
        <Input
          label="Name"
          value={name}
          onChange={(event) => setName(event.target.value)}
          required
          autoFocus
          placeholder="Acme Q3 hardening"
        />
        <div className="grid gap-3 sm:grid-cols-2">
          <Input label="Client" value={client} onChange={(event) => setClient(event.target.value)} placeholder="Acme Corp" />
          <Input label="Scope" value={scope} onChange={(event) => setScope(event.target.value)} placeholder="Internal network" />
        </div>
        <Input
          label="Tags (comma separated)"
          value={tags}
          onChange={(event) => setTags(event.target.value)}
          placeholder="prod, pci, eu"
        />
        <Input
          label="First location"
          value={firstLocation}
          onChange={(event) => setFirstLocation(event.target.value)}
          hint="Optional. You can add more locations after creation."
          placeholder="Datacenter A"
        />
        {error ? (
          <p role="alert" className="rounded-control border border-critical/40 bg-critical-soft/60 p-2 text-xs text-critical">
            {error}
          </p>
        ) : null}
      </form>
    </Modal>
  );
}
