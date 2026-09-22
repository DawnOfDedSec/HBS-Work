import { useCallback, useEffect, useRef, useState } from "react";
import { Bookmark, ChevronDown, Trash2 } from "lucide-react";
import { api, ApiError } from "../api";
import { Button, Input, Select, useToast } from "./ui";
import { cn, focusRing } from "./ui/cn";
import type { AuthUser } from "../types";

export type SavedView = {
  id: number;
  ownerId: number;
  campaignId: number | null;
  name: string;
  scope: string;
  query: string;
  visibility: "personal" | "team";
  createdAt: string;
  updatedAt: string;
  canEdit: boolean;
  canDelete: boolean;
};

export type SavedViewsMenuProps = {
  /** The canonical (serialized) query for the current filters. */
  currentQuery: string;
  role?: AuthUser["role"];
  /** Apply a saved view's canonical query to the current page. */
  onApply: (query: string) => void;
};

type ViewsResponse = { views: SavedView[] };

function errorMessage(error: unknown): string {
  return error instanceof ApiError ? error.message : "Request failed. Please retry.";
}

/**
 * Saved-views quick switcher. Lists the personal/team views from
 * `GET /api/saved-views`, applies one with `onApply`, and (for auditors) saves
 * the current filter set with `POST /api/saved-views`.
 */
export function SavedViewsMenu({ currentQuery, role, onApply }: SavedViewsMenuProps) {
  const toast = useToast();
  const [open, setOpen] = useState(false);
  const [views, setViews] = useState<SavedView[]>([]);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [name, setName] = useState("");
  const [visibility, setVisibility] = useState<"personal" | "team">("personal");
  const [error, setError] = useState<string | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const canWrite = role === "super_admin" || role === "auditor";

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    api
      .raw<ViewsResponse>("GET", "/api/saved-views")
      .then((response) => setViews(Array.isArray(response.views) ? response.views : []))
      .catch((err) => setError(errorMessage(err)))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (open) load();
  }, [open, load]);

  useEffect(() => {
    if (!open) return;
    function onPointerDown(event: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) setOpen(false);
    }
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", onPointerDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onPointerDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  function save() {
    const trimmed = name.trim();
    if (!trimmed) {
      setError("Give the view a name.");
      return;
    }
    setSaving(true);
    setError(null);
    api
      .raw<{ view: SavedView }>("POST", "/api/saved-views", {
        name: trimmed,
        query: currentQuery,
        visibility,
      })
      .then(() => {
        toast.success("View saved", { description: trimmed });
        setName("");
        load();
      })
      .catch((err) => {
        const message = errorMessage(err);
        setError(message);
        toast.error("Could not save view", { description: message });
      })
      .finally(() => setSaving(false));
  }

  function remove(view: SavedView) {
    api
      .raw<void>("DELETE", `/api/saved-views/${view.id}`)
      .then(() => {
        setViews((current) => current.filter((entry) => entry.id !== view.id));
        toast.success("View deleted", { description: view.name });
      })
      .catch((err) => toast.error("Could not delete view", { description: errorMessage(err) }));
  }

  return (
    <div className="relative" ref={containerRef}>
      <Button
        size="sm"
        variant="secondary"
        icon={Bookmark}
        iconRight={ChevronDown}
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((value) => !value)}
      >
        Saved views
      </Button>

      {open ? (
        <div
          role="menu"
          aria-label="Saved views"
          className="absolute right-0 top-10 z-50 w-72 overflow-hidden rounded-panel border border-hairline bg-surface-overlay p-2 shadow-overlay animate-scale-in"
        >
          {loading ? (
            <p className="px-2 py-4 text-center text-xs text-ink-muted">Loading views…</p>
          ) : views.length === 0 ? (
            <p className="px-2 py-4 text-center text-xs text-ink-muted">
              No saved views yet{canWrite ? ". Save the current filters below." : "."}
            </p>
          ) : (
            <ul className="hbs-scroll max-h-56 overflow-y-auto">
              {views.map((view) => (
                <li key={view.id} className="flex items-center gap-1">
                  <button
                    type="button"
                    role="menuitem"
                    onClick={() => {
                      onApply(view.query);
                      setOpen(false);
                    }}
                    className={cn(
                      "min-w-0 flex-1 rounded-control px-2 py-2 text-left text-sm text-ink hover:bg-surface-raised",
                      focusRing,
                    )}
                  >
                    <span className="block truncate font-medium">{view.name}</span>
                    <span className="block truncate text-2xs text-ink-subtle">
                      {view.visibility} · {view.query || "no filters"}
                    </span>
                  </button>
                  {view.canDelete ? (
                    <button
                      type="button"
                      aria-label={`Delete view ${view.name}`}
                      onClick={() => remove(view)}
                      className={cn("rounded p-1.5 text-ink-subtle hover:bg-surface-raised hover:text-critical", focusRing)}
                    >
                      <Trash2 size={13} aria-hidden />
                    </button>
                  ) : null}
                </li>
              ))}
            </ul>
          )}

          {canWrite ? (
            <div className="mt-2 border-t border-hairline-soft pt-2">
              <div className="flex items-center gap-1.5">
                <Input
                  size="sm"
                  aria-label="Saved view name"
                  placeholder="Save current filters…"
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter") {
                      event.preventDefault();
                      save();
                    }
                  }}
                  containerClassName="flex-1"
                />
                <Button size="sm" variant="primary" loading={saving} onClick={save}>
                  Save
                </Button>
              </div>
              <Select
                size="sm"
                className="mt-1.5"
                aria-label="Saved view visibility"
                value={visibility}
                onChange={(value) => setVisibility(value === "team" ? "team" : "personal")}
                options={[
                  { value: "personal", label: "Personal" },
                  { value: "team", label: "Team" },
                ]}
              />
            </div>
          ) : null}

          {error ? <p className="mt-1.5 px-2 text-2xs text-critical">{error}</p> : null}
        </div>
      ) : null}
    </div>
  );
}
