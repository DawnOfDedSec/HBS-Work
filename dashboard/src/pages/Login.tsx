import { useState, type FormEvent } from "react";
import { Eye, EyeOff, KeyRound, Lock, ShieldCheck, User } from "lucide-react";
import { api, ApiError } from "../api";
import { Button, Input, Kbd } from "../components/ui";
import { useToast } from "../components/Toaster";
import type { AuthUser } from "../types";

type Props = { onAuthed: (user: AuthUser) => void };

type FieldErrors = { username?: string; password?: string };

const FEATURES: Array<{ icon: typeof ShieldCheck; title: string; detail: string }> = [
  {
    icon: ShieldCheck,
    title: "368 hardening testcases",
    detail: "Read-only scans on Linux and Windows; the target writes exactly one sealed report.",
  },
  {
    icon: KeyRound,
    title: "One key per issuance",
    detail: "Reports are sealed to an X25519 key only this dashboard can open.",
  },
  {
    icon: Lock,
    title: "Argon2id, peppered",
    detail: "Hashes use 64 MiB and a secret kept outside the database.",
  },
];

/** Sign-in screen with inline validation and explicit error states. */
export function Login({ onAuthed }: Props) {
  const toast = useToast();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [errors, setErrors] = useState<FieldErrors>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function validate(): FieldErrors {
    const next: FieldErrors = {};
    if (!username.trim()) next.username = "Enter your username.";
    if (!password) next.password = "Enter your password.";
    return next;
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    const found = validate();
    setErrors(found);
    if (Object.keys(found).length > 0) return;

    setBusy(true);
    setFormError(null);
    try {
      const { user } = await api.login(username.trim(), password);
      toast.success(`Signed in as ${user.username}`, { description: "Welcome back to the console." });
      onAuthed(user);
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : "Sign-in failed. Try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="hbs-grid flex min-h-screen items-center justify-center bg-canvas p-4">
      <div className="grid w-full max-w-4xl overflow-hidden rounded-panel border border-hairline bg-surface shadow-overlay lg:grid-cols-[1.05fr_1fr]">
        <aside className="hidden flex-col justify-between gap-10 border-r border-hairline bg-canvas-elevated p-8 lg:flex">
          <div>
            <div className="flex items-center gap-2.5">
              <span className="flex h-9 w-9 items-center justify-center rounded-control bg-accent-soft text-accent">
                <ShieldCheck size={20} aria-hidden />
              </span>
              <span className="text-sm font-semibold tracking-tight">HBS Console</span>
            </div>
            <h1 className="mt-8 text-2xl font-semibold leading-tight tracking-tight">
              Host baseline security,
              <br />
              measured and governed.
            </h1>
            <p className="mt-3 max-w-sm text-sm text-ink-muted">
              Sign in to review campaign posture, triage findings, and evidence compliance against your standards.
            </p>
          </div>
          <ul className="space-y-4">
            {FEATURES.map((feature) => {
              const Icon = feature.icon;
              return (
                <li key={feature.title} className="flex items-start gap-3">
                  <span className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-control bg-surface text-accent">
                    <Icon size={16} aria-hidden />
                  </span>
                  <span>
                    <span className="block text-sm font-medium text-ink">{feature.title}</span>
                    <span className="block text-xs text-ink-muted">{feature.detail}</span>
                  </span>
                </li>
              );
            })}
          </ul>
        </aside>

        <main className="p-6 sm:p-8">
          <div className="mb-6 flex items-center gap-2.5 lg:hidden">
            <span className="flex h-8 w-8 items-center justify-center rounded-control bg-accent-soft text-accent">
              <ShieldCheck size={18} aria-hidden />
            </span>
            <span className="text-sm font-semibold tracking-tight">HBS Console</span>
          </div>
          <h2 className="text-lg font-semibold tracking-tight">Sign in</h2>
          <p className="mt-1 text-sm text-ink-muted">Use your console credentials.</p>

          <form onSubmit={submit} aria-label="Sign in" className="mt-6 flex flex-col gap-4" noValidate>
            {formError ? (
              <p
                role="alert"
                className="rounded-control border border-critical/40 bg-critical-soft px-3 py-2 text-xs text-critical"
              >
                {formError}
              </p>
            ) : null}

            <Input
              label="Username"
              autoComplete="username"
              autoFocus
              icon={User}
              value={username}
              onChange={(event) => {
                setUsername(event.target.value);
                if (errors.username) setErrors((current) => ({ ...current, username: undefined }));
              }}
              onBlur={() => setErrors((current) => ({ ...current, username: username.trim() ? undefined : "Enter your username." }))}
              error={errors.username}
              size="lg"
              required
            />

            <Input
              label="Password"
              type={showPassword ? "text" : "password"}
              autoComplete="current-password"
              icon={Lock}
              value={password}
              onChange={(event) => {
                setPassword(event.target.value);
                if (errors.password) setErrors((current) => ({ ...current, password: undefined }));
              }}
              onBlur={() => setErrors((current) => ({ ...current, password: password ? undefined : "Enter your password." }))}
              error={errors.password}
              size="lg"
              required
              trailing={
                <Button
                  variant="ghost"
                  size="icon"
                  aria-label={showPassword ? "Hide password" : "Show password"}
                  onClick={() => setShowPassword((value) => !value)}
                >
                  {showPassword ? <EyeOff size={16} aria-hidden /> : <Eye size={16} aria-hidden />}
                </Button>
              }
            />

            <Button type="submit" variant="primary" size="lg" block loading={busy}>
              {busy ? "Signing inâ€¦" : "Sign in"}
            </Button>
          </form>

          <p className="mt-6 flex items-center gap-2 text-2xs text-ink-subtle">
            Press <Kbd>âŒ˜</Kbd> <Kbd>K</Kbd> inside the console to jump anywhere.
          </p>
        </main>
      </div>
    </div>
  );
}
