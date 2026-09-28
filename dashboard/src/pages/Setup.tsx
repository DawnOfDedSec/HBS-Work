import { useState, type FormEvent } from "react";
import {
  ArrowLeft,
  ArrowRight,
  Check,
  CheckCircle2,
  Eye,
  EyeOff,
  Lock,
  PartyPopper,
  ShieldCheck,
  User,
} from "lucide-react";
import { api, ApiError } from "../api";
import { Button, Input, ProgressBar, type ProgressTone } from "../components/ui";
import { cn } from "../components/ui/cn";
import { useToast } from "../components/Toaster";
import type { AuthUser } from "../types";

type Props = { onAuthed: (user: AuthUser) => void };

type Step = 0 | 1 | 2;

const STEPS: Array<{ id: Step; label: string }> = [
  { id: 0, label: "Welcome" },
  { id: 1, label: "Administrator" },
  { id: 2, label: "Finish" },
];

const MIN_PASSWORD = 12;

function passwordStrength(password: string): { score: number; label: string; tone: ProgressTone } {
  if (!password) return { score: 0, label: "No password yet", tone: "critical" };
  let score = 0;
  if (password.length >= MIN_PASSWORD) score += 1;
  if (password.length >= 12) score += 1;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score += 1;
  if (/\d/.test(password)) score += 1;
  if (/[^A-Za-z0-9]/.test(password)) score += 1;
  const clamped = Math.min(4, score);
  const label = ["Very weak", "Weak", "Fair", "Good", "Strong"][clamped];
  const tone: ProgressTone = clamped <= 1 ? "critical" : clamped === 2 ? "degraded" : "compliant";
  return { score: clamped, label, tone };
}

/**
 * First-run wizard: welcome â†’ administrator account (with a password-strength
 * meter) â†’ done. Creates the initial super admin via `api.setup`.
 */
export function Setup({ onAuthed }: Props) {
  const toast = useToast();
  const [step, setStep] = useState<Step>(0);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [errors, setErrors] = useState<{ username?: string; password?: string; confirm?: string }>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<AuthUser | null>(null);

  const strength = passwordStrength(password);

  function validate(): typeof errors {
    const next: typeof errors = {};
    if (username.trim().length < 3) next.username = "Use at least 3 characters.";
    if (password.length < MIN_PASSWORD) next.password = `Use at least ${MIN_PASSWORD} characters.`;
    if (password !== confirm) next.confirm = "Passwords do not match.";
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
      const { user } = await api.setup(username.trim(), password);
      setCreated(user);
      setStep(2);
      toast.success("Administrator created", { description: `${user.username} can now manage the console.` });
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : "Setup failed. Try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="hbs-grid flex min-h-screen items-center justify-center bg-canvas p-4">
      <div className="w-full max-w-xl rounded-panel border border-hairline bg-surface p-6 shadow-overlay sm:p-8">
        <div className="flex items-center gap-2.5">
          <span className="flex h-9 w-9 items-center justify-center rounded-control bg-accent-soft text-accent">
            <ShieldCheck size={20} aria-hidden />
          </span>
          <div>
            <p className="text-2xs font-semibold uppercase tracking-wide text-ink-subtle">HBS Console</p>
            <p className="text-sm font-semibold tracking-tight">First-run setup</p>
          </div>
        </div>

        <ol className="mt-6 flex items-center gap-2" aria-label="Setup progress">
          {STEPS.map((item, index) => {
            const state = step === item.id ? "current" : step > item.id ? "done" : "upcoming";
            return (
              <li key={item.id} className="flex flex-1 items-center gap-2">
                <span
                  className={cn(
                    "flex h-6 w-6 shrink-0 items-center justify-center rounded-full border text-2xs font-semibold",
                    state === "done" && "border-compliant/50 bg-compliant-soft text-compliant",
                    state === "current" && "border-accent/50 bg-accent-soft text-accent",
                    state === "upcoming" && "border-hairline bg-surface-raised text-ink-subtle",
                  )}
                >
                  {state === "done" ? <Check size={12} aria-hidden /> : index + 1}
                </span>
                <span
                  className={cn(
                    "hidden text-xs sm:inline",
                    state === "upcoming" ? "text-ink-subtle" : "text-ink",
                  )}
                >
                  {item.label}
                </span>
                {index < STEPS.length - 1 ? <span className="h-px flex-1 bg-hairline" aria-hidden /> : null}
              </li>
            );
          })}
        </ol>

        {step === 0 ? (
          <section className="mt-7" aria-labelledby="setup-welcome">
            <h1 id="setup-welcome" className="text-xl font-semibold tracking-tight">
              Welcome to the security console
            </h1>
            <p className="mt-2 text-sm text-ink-muted">
              This looks like a fresh deployment. In a moment we&apos;ll create the first administrator account.
              That account manages users, issuance keys, and retention policy.
            </p>
            <ul className="mt-5 space-y-2 text-sm text-ink-muted">
              {[
                "Create the initial super administrator",
                "Issue signed extractors to your hosts",
                "Review posture, findings, and standards coverage",
              ].map((line) => (
                <li key={line} className="flex items-center gap-2">
                  <CheckCircle2 size={15} className="text-compliant" aria-hidden />
                  {line}
                </li>
              ))}
            </ul>
            <div className="mt-7 flex justify-end">
              <Button variant="primary" iconRight={ArrowRight} onClick={() => setStep(1)}>
                Get started
              </Button>
            </div>
          </section>
        ) : null}

        {step === 1 ? (
          <section className="mt-7" aria-labelledby="setup-admin">
            <h1 id="setup-admin" className="text-xl font-semibold tracking-tight">
              Create the administrator
            </h1>
            <p className="mt-2 text-sm text-ink-muted">
              Choose credentials for the first account. Store them in your password manager.
            </p>

            <form onSubmit={submit} aria-label="Initial setup" className="mt-5 flex flex-col gap-4" noValidate>
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
                icon={User}
                autoComplete="username"
                autoFocus
                value={username}
                onChange={(event) => {
                  setUsername(event.target.value);
                  if (errors.username) setErrors((current) => ({ ...current, username: undefined }));
                }}
                error={errors.username}
                hint="At least 3 characters."
                required
              />

              <div>
                <Input
                  label="Password"
                  type={showPassword ? "text" : "password"}
                  icon={Lock}
                  autoComplete="new-password"
                  value={password}
                  onChange={(event) => {
                    setPassword(event.target.value);
                    if (errors.password) setErrors((current) => ({ ...current, password: undefined }));
                  }}
                  error={errors.password}
                  hint={`At least ${MIN_PASSWORD} characters; a 16+ character passphrase is even stronger.`}
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
                <div className="mt-2">
                  <ProgressBar
                    value={strength.score}
                    max={4}
                    tone={strength.tone}
                    label="Password strength"
                    showValue={false}
                  />
                  <p className="mt-1 text-2xs text-ink-subtle">
                    Strength: <span className="text-ink">{strength.label}</span>. Mix upper/lower case, numbers, and symbols.
                  </p>
                </div>
              </div>

              <Input
                label="Confirm password"
                type={showPassword ? "text" : "password"}
                icon={Lock}
                autoComplete="new-password"
                value={confirm}
                onChange={(event) => {
                  setConfirm(event.target.value);
                  if (errors.confirm) setErrors((current) => ({ ...current, confirm: undefined }));
                }}
                error={errors.confirm}
                required
              />

              <div className="mt-1 flex justify-between">
                <Button variant="ghost" icon={ArrowLeft} onClick={() => setStep(0)} disabled={busy}>
                  Back
                </Button>
                <Button type="submit" variant="primary" loading={busy}>
                  {busy ? "Creatingâ€¦" : "Create administrator"}
                </Button>
              </div>
            </form>
          </section>
        ) : null}

        {step === 2 && created ? (
          <section className="mt-7 text-center" aria-labelledby="setup-done">
            <span className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-compliant-soft text-compliant">
              <PartyPopper size={22} aria-hidden />
            </span>
            <h1 id="setup-done" className="mt-4 text-xl font-semibold tracking-tight">
              You&apos;re all set
            </h1>
            <p className="mt-2 text-sm text-ink-muted">
              The administrator <span className="font-medium text-ink">{created.username}</span> is ready. Sign in to
              start your first campaign.
            </p>
            <div className="mx-auto mt-5 max-w-xs rounded-control border border-hairline bg-surface-raised p-3 text-left text-xs">
              <p className="flex items-center justify-between">
                <span className="text-ink-subtle">Username</span>
                <span className="font-medium text-ink">{created.username}</span>
              </p>
              <p className="mt-1.5 flex items-center justify-between">
                <span className="text-ink-subtle">Role</span>
                <span className="font-medium text-ink">Super admin</span>
              </p>
            </div>
            <div className="mt-6 flex justify-center">
              <Button variant="primary" iconRight={ArrowRight} onClick={() => onAuthed(created)}>
                Enter the console
              </Button>
            </div>
          </section>
        ) : null}
      </div>
    </div>
  );
}
