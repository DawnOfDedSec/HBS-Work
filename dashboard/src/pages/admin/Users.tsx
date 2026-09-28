import { useCallback, useEffect, useState, type ReactNode } from "react";
import { AlertTriangle, ShieldCheck, UserPlus, UsersRound } from "lucide-react";
import { api, ApiError } from "../../api";
import {
  Badge,
  Button,
  Card,
  CardHeader,
  EmptyState,
  Input,
  Modal,
  SectionHeader,
  Select,
  Skeleton,
  Table,
  type TableColumn,
  useToast,
} from "../../components/ui";
import { sanitizeText } from "../../components/EvidenceDrawer";
import type { AuthUser } from "../../types";

export type AdminRole = AuthUser["role"];

export type RoleState = { role: AdminRole | null; loading: boolean; error: string | null };

const ROLES: AdminRole[] = ["super_admin", "auditor", "viewer"];

const ROLE_LABEL: Record<AdminRole, string> = {
  super_admin: "Super admin",
  auditor: "Auditor",
  viewer: "Viewer",
};

/**
 * Resolve the signed-in user's role. Pages may pass the role straight from the
 * app shell; when it is absent the page asks `GET /api/auth/status` itself so
 * the view still role-gates when mounted standalone.
 */
export function useAdminRole(provided?: AdminRole | null): RoleState {
  const [role, setRole] = useState<AdminRole | null>(provided ?? null);
  const [loading, setLoading] = useState(provided == null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (provided != null) {
      setRole(provided);
      setLoading(false);
      return;
    }
    let alive = true;
    setLoading(true);
    api
      .authStatus()
      .then((status) => {
        if (alive) setRole(status.user?.role ?? null);
      })
      .catch(() => {
        if (alive) setError("Could not confirm your role.");
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [provided]);

  return { role, loading, error };
}

/** UI-side role gate; the server enforces the same rule. */
export function AdminGate({
  role,
  loading,
  error,
  allow,
  children,
}: {
  role: AdminRole | null;
  loading: boolean;
  error: string | null;
  allow: AdminRole[];
  children: ReactNode;
}) {
  if (loading) {
    return (
      <Card>
        <Skeleton width="40%" />
        <Skeleton className="mt-3" width="80%" />
      </Card>
    );
  }
  if (error) return <EmptyState icon={AlertTriangle} title="Permission check failed" detail={error} />;
  if (!role || !allow.includes(role)) {
    return (
      <EmptyState
        icon={ShieldCheck}
        title="Not authorized"
        detail="This area is restricted to administrators. Ask a super admin for access."
      />
    );
  }
  return <>{children}</>;
}

type AdminUser = {
  id: number;
  username: string;
  role: AdminRole;
  active: number | boolean;
  allowedCampaigns?: number[] | null;
  created_at: string;
  updated_at: string;
};

function isActive(user: AdminUser): boolean {
  return Boolean(user.active);
}

function errorMessage(error: unknown): string {
  return error instanceof ApiError ? error.message : "Request failed. Please retry.";
}

export function Users({ role: providedRole }: { role?: AdminRole | null } = {}) {
  const { role, loading: roleLoading, error: roleError } = useAdminRole(providedRole);
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<number | null>(null);
  const [creating, setCreating] = useState(false);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [newRole, setNewRole] = useState<AdminRole>("viewer");
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [accessUser, setAccessUser] = useState<AdminUser | null>(null);
  const [accessSelection, setAccessSelection] = useState<number[]>([]);
  const [campaigns, setCampaigns] = useState<Array<{ id: number; name: string }>>([]);
  const toast = useToast();

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await api.raw<{ users: AdminUser[] }>("GET", "/api/users");
      setUsers(Array.isArray(response.users) ? response.users : []);
    } catch (err) {
      const message = errorMessage(err);
      setError(message);
      toast.error("Could not load users", { description: message });
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    if (role === "super_admin") void refresh();
  }, [role, refresh]);

  const activeSuperAdmins = users.filter((user) => user.role === "super_admin" && isActive(user)).length;

  async function mutate(id: number, body: Record<string, unknown>) {
    setBusy(id);
    setError(null);
    try {
      await api.raw("PATCH", `/api/users/${id}`, body);
      toast.success("User updated");
      await refresh();
    } catch (err) {
      const message = errorMessage(err);
      setError(message);
      toast.error("Could not update user", { description: message });
    } finally {
      setBusy(null);
    }
  }

  async function deactivate(id: number) {
    setBusy(id);
    setError(null);
    try {
      await api.raw("DELETE", `/api/users/${id}`);
      toast.success("User deactivated");
      await refresh();
    } catch (err) {
      const message = errorMessage(err);
      setError(message);
      toast.error("Could not deactivate user", { description: message });
    } finally {
      setBusy(null);
    }
  }

  async function create(event: React.FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setFormError(null);
    try {
      await api.raw("POST", "/api/users", { username, password, role: newRole });
      toast.success("User created", { description: username });
      setCreating(false);
      setUsername("");
      setPassword("");
      setNewRole("viewer");
      await refresh();
    } catch (err) {
      setFormError(errorMessage(err));
    } finally {
      setSubmitting(false);
    }
  }

  async function openAccess(user: AdminUser) {
    setAccessUser(user);
    setAccessSelection(user.allowedCampaigns ?? []);
    try {
      const rows = await api.raw<Array<{ id: number; name: string }>>("GET", "/api/campaigns");
      setCampaigns(Array.isArray(rows) ? rows.map((row) => ({ id: row.id, name: row.name })) : []);
    } catch {
      setCampaigns([]);
    }
  }

  async function saveAccess() {
    if (!accessUser) return;
    setBusy(accessUser.id);
    try {
      await api.raw("PATCH", `/api/users/${accessUser.id}`, {
        allowedCampaigns: accessSelection.length > 0 ? accessSelection : null,
      });
      toast.success(
        accessSelection.length > 0 ? "Campaign access updated" : "Campaign restriction removed",
        { description: sanitizeText(accessUser.username) },
      );
      setAccessUser(null);
      await refresh();
    } catch (err) {
      toast.error("Could not update campaign access", { description: errorMessage(err) });
    } finally {
      setBusy(null);
    }
  }

  const columns: Array<TableColumn<AdminUser>> = [
    {
      key: "username",
      header: "Username",
      render: (user) => <span className="font-medium text-ink">{sanitizeText(user.username)}</span>,
    },
    {
      key: "role",
      header: "Role",
      render: (user) => {
        const lastSuperAdmin = user.role === "super_admin" && isActive(user) && activeSuperAdmins <= 1;
        return (
          <Select
            aria-label={`Role for ${user.username}`}
            value={user.role}
            disabled={busy === user.id || lastSuperAdmin}
            onChange={(value) => void mutate(user.id, { role: value })}
            options={ROLES.map((option) => ({ value: option, label: ROLE_LABEL[option] }))}
            size="sm"
            className="w-40"
          />
        );
      },
    },
    {
      key: "active",
      header: "Status",
      render: (user) =>
        isActive(user) ? <Badge tone="compliant">Active</Badge> : <Badge tone="na">Deactivated</Badge>,
    },
    {
      key: "campaignAccess",
      header: "Campaign access",
      render: (user) =>
        isActive(user) ? (
          <Button size="sm" variant="ghost" disabled={busy === user.id} onClick={() => void openAccess(user)}>
            {user.allowedCampaigns && user.allowedCampaigns.length > 0
              ? `${user.allowedCampaigns.length} campaign${user.allowedCampaigns.length === 1 ? "" : "s"}`
              : "All campaigns"}
          </Button>
        ) : (
          <span className="text-2xs text-ink-subtle">-</span>
        ),
    },
    {
      key: "created_at",
      header: "Created",
      sortable: true,
      render: (user) => <span className="text-xs text-ink-muted">{sanitizeText(user.created_at)}</span>,
    },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      align: "right",
      render: (user) => {
        const lastSuperAdmin = user.role === "super_admin" && isActive(user) && activeSuperAdmins <= 1;
        return isActive(user) ? (
          <Button
            size="sm"
            variant="secondary"
            disabled={busy === user.id || lastSuperAdmin}
            title={lastSuperAdmin ? "Cannot deactivate the last active super admin" : undefined}
            onClick={() => void deactivate(user.id)}
          >
            Deactivate
          </Button>
        ) : (
          <Button size="sm" variant="secondary" disabled={busy === user.id} onClick={() => void mutate(user.id, { active: true })}>
            Reactivate
          </Button>
        );
      },
    },
  ];

  return (
    <AdminGate role={role} loading={roleLoading} error={roleError} allow={["super_admin"]}>
      <section aria-label="User administration" className="flex flex-col gap-5">
        <SectionHeader
          eyebrow="Govern"
          title="Users"
          description="Console identities and roles. The last active super admin can never be deactivated."
          icon={UsersRound}
          actions={
            <Button variant="primary" icon={UserPlus} onClick={() => setCreating(true)}>
              Create user
            </Button>
          }
        />

        {error ? (
          <div
            role="alert"
            className="flex items-start gap-2 rounded-control border border-critical/40 bg-critical-soft/60 p-3 text-sm text-critical"
          >
            <AlertTriangle size={16} aria-hidden className="mt-0.5 shrink-0" />
            <span>{error}</span>
          </div>
        ) : null}

        <Card flush className="overflow-hidden">
          <div className="p-4">
            <CardHeader
              icon={UsersRound}
              title="Console users"
              description="Change a role inline or deactivate an account."
              actions={<Badge tone="accent">{users.length} users</Badge>}
            />
          </div>
          {loading && users.length === 0 ? (
            <div className="flex flex-col gap-2 p-4">
              {Array.from({ length: 4 }).map((_, index) => (
                <Skeleton key={index} height={30} />
              ))}
            </div>
          ) : users.length === 0 ? (
            <div className="p-4">
              <EmptyState title="No users yet" detail="Create the first console user." />
            </div>
          ) : (
            <Table label="Console users" columns={columns} rows={users} rowKey={(user) => String(user.id)} stickyHeader />
          )}
        </Card>

        <Modal
          open={creating}
          onClose={() => setCreating(false)}
          title="Create user"
          description="New accounts start with the selected role and a salted Argon2id hash. Passwords follow the same policy as the setup wizard."
          footer={
            <>
              <Button variant="secondary" onClick={() => setCreating(false)}>
                Cancel
              </Button>
              <Button variant="primary" loading={submitting} form="create-user-form" type="submit">
                Create user
              </Button>
            </>
          }
        >
          <form id="create-user-form" onSubmit={create} className="flex flex-col gap-3">
            <Input label="Username" value={username} onChange={(event) => setUsername(event.target.value)} required autoFocus />
            <Input
              label="Password"
              type="password"
              autoComplete="new-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              hint="At least 12 characters, or a longer passphrase."
              required
            />
            <Select
              label="Role"
              value={newRole}
              onChange={(value) => setNewRole(value as AdminRole)}
              options={ROLES.map((option) => ({ value: option, label: ROLE_LABEL[option] }))}
            />
            {formError ? (
              <p role="alert" className="rounded-control border border-critical/40 bg-critical-soft/60 p-2 text-xs text-critical">
                {formError}
              </p>
            ) : null}
          </form>
        </Modal>

      {accessUser ? (
        <Modal
          open
          onClose={() => setAccessUser(null)}
          size="lg"
          title={`Campaign access · ${sanitizeText(accessUser.username)}`}
          description="Restrict this account to specific campaigns. No selection means unrestricted access."
          footer={
            <>
              <Button variant="ghost" onClick={() => setAccessUser(null)}>
                Cancel
              </Button>
              <Button
                variant="primary"
                loading={busy === accessUser.id}
                onClick={() => void saveAccess()}
              >
                Save access
              </Button>
            </>
          }
        >
          <div className="flex flex-col gap-2">
            {campaigns.length === 0 ? (
              <p className="text-sm text-ink-subtle">No campaigns exist yet.</p>
            ) : (
              campaigns.map((campaign) => (
                <label key={campaign.id} className="flex items-center gap-2 rounded-control px-1 py-1 text-sm text-ink">
                  <input
                    type="checkbox"
                    className="h-3.5 w-3.5"
                    checked={accessSelection.includes(campaign.id)}
                    onChange={(event) =>
                      setAccessSelection((current) =>
                        event.target.checked
                          ? [...current, campaign.id].sort((a, b) => a - b)
                          : current.filter((id) => id !== campaign.id),
                      )
                    }
                  />
                  <span className="truncate">
                    {sanitizeText(campaign.name)} <span className="text-2xs text-ink-subtle">#{campaign.id}</span>
                  </span>
                </label>
              ))
            )}
          </div>
        </Modal>
      ) : null}
      </section>
    </AdminGate>
  );
}
