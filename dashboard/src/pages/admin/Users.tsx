import { useEffect, useState, type ReactNode } from "react";
import { api, ApiError } from "../../api";
import { EmptyState } from "../../components/EmptyState";
import { sanitizeText } from "../../components/EvidenceDrawer";
import type { AuthUser } from "../../types";

export type AdminRole = AuthUser["role"];

export type RoleState = { role: AdminRole | null; loading: boolean; error: string | null };

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
  if (loading) return <p role="status">Checking permissions…</p>;
  if (error) return <EmptyState title="Permission check failed" detail={error} />;
  if (!role || !allow.includes(role)) {
    return (
      <EmptyState
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
  created_at: string;
  updated_at: string;
};

const ROLES: AdminRole[] = ["super_admin", "auditor", "viewer"];

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
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState<number | null>(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [newRole, setNewRole] = useState<AdminRole>("viewer");

  async function refresh() {
    setLoading(true);
    setError(null);
    try {
      const response = await api.raw<{ users: AdminUser[] }>("GET", "/api/users");
      setUsers(Array.isArray(response.users) ? response.users : []);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (role === "super_admin") void refresh();
  }, [role]);

  const activeSuperAdmins = users.filter((user) => user.role === "super_admin" && isActive(user)).length;

  async function mutate(id: number, body: Record<string, unknown>) {
    setBusy(id);
    setError(null);
    try {
      await api.raw("PATCH", `/api/users/${id}`, body);
      setNotice("User updated.");
      await refresh();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(null);
    }
  }

  async function deactivate(id: number) {
    setBusy(id);
    setError(null);
    try {
      await api.raw("DELETE", `/api/users/${id}`);
      setNotice("User deactivated.");
      await refresh();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(null);
    }
  }

  async function create(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    try {
      await api.raw("POST", "/api/users", { username, password, role: newRole });
      setUsername("");
      setPassword("");
      setNewRole("viewer");
      setNotice("User created.");
      await refresh();
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  return (
    <AdminGate role={role} loading={roleLoading} error={roleError} allow={["super_admin"]}>
      <section aria-label="User administration" className="space-y-5">
        <h2 className="text-lg font-semibold">Users</h2>

        {error ? (
          <p role="alert" className="rounded border border-red-500/50 bg-red-500/10 p-3 text-sm text-red-200">
            {error}
          </p>
        ) : null}
        {notice ? (
          <p role="status" className="rounded border border-sky-500/40 bg-sky-500/10 p-3 text-sm text-sky-100">
            {notice}
          </p>
        ) : null}

        <form onSubmit={create} className="flex flex-wrap items-end gap-3 rounded-lg border border-slate-800 p-3">
          <label className="flex flex-col text-xs text-slate-400">
            Username
            <input
              required
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              className="mt-1 rounded border border-slate-700 bg-slate-900 px-2 py-1 text-sm"
            />
          </label>
          <label className="flex flex-col text-xs text-slate-400">
            Password
            <input
              required
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              className="mt-1 rounded border border-slate-700 bg-slate-900 px-2 py-1 text-sm"
            />
          </label>
          <label className="flex flex-col text-xs text-slate-400">
            Role
            <select
              value={newRole}
              onChange={(event) => setNewRole(event.target.value as AdminRole)}
              className="mt-1 rounded border border-slate-700 bg-slate-900 px-2 py-1 text-sm"
            >
              {ROLES.map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          </label>
          <button
            type="submit"
            className="rounded bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-500 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-300"
          >
            Create user
          </button>
        </form>

        {loading && users.length === 0 ? (
          <p role="status">Loading users…</p>
        ) : users.length === 0 ? (
          <EmptyState title="No users yet" />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-sm">
              <caption className="sr-only">Console users</caption>
              <thead>
                <tr className="text-left text-slate-400">
                  <th scope="col" className="border-b border-slate-800 py-2 pr-3">Username</th>
                  <th scope="col" className="border-b border-slate-800 py-2 pr-3">Role</th>
                  <th scope="col" className="border-b border-slate-800 py-2 pr-3">Status</th>
                  <th scope="col" className="border-b border-slate-800 py-2 pr-3">Created</th>
                  <th scope="col" className="border-b border-slate-800 py-2">Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((user) => {
                  const lastSuperAdmin = user.role === "super_admin" && isActive(user) && activeSuperAdmins <= 1;
                  return (
                    <tr key={user.id} className="align-top">
                      <td className="border-b border-slate-900 py-2 pr-3">{sanitizeText(user.username)}</td>
                      <td className="border-b border-slate-900 py-2 pr-3">
                        <label className="sr-only" htmlFor={`role-${user.id}`}>
                          Role for {user.username}
                        </label>
                        <select
                          id={`role-${user.id}`}
                          value={user.role}
                          disabled={busy === user.id || lastSuperAdmin}
                          onChange={(event) => void mutate(user.id, { role: event.target.value })}
                          className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-xs disabled:opacity-50"
                        >
                          {ROLES.map((option) => (
                            <option key={option} value={option}>
                              {option}
                            </option>
                          ))}
                        </select>
                      </td>
                      <td className="border-b border-slate-900 py-2 pr-3">
                        {isActive(user) ? "active" : "deactivated"}
                      </td>
                      <td className="border-b border-slate-900 py-2 pr-3">{sanitizeText(user.created_at)}</td>
                      <td className="border-b border-slate-900 py-2">
                        {isActive(user) ? (
                          <button
                            type="button"
                            disabled={busy === user.id || lastSuperAdmin}
                            onClick={() => void deactivate(user.id)}
                            title={lastSuperAdmin ? "Cannot deactivate the last active super admin" : undefined}
                            className="rounded border border-slate-700 px-2 py-0.5 text-xs hover:bg-slate-800 disabled:opacity-40 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
                          >
                            Deactivate
                          </button>
                        ) : (
                          <button
                            type="button"
                            disabled={busy === user.id}
                            onClick={() => void mutate(user.id, { active: true })}
                            className="rounded border border-slate-700 px-2 py-0.5 text-xs hover:bg-slate-800 disabled:opacity-40 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400"
                          >
                            Reactivate
                          </button>
                        )}
                        {lastSuperAdmin ? (
                          <span className="ml-2 text-xs text-amber-300">last super admin</span>
                        ) : null}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </AdminGate>
  );
}
