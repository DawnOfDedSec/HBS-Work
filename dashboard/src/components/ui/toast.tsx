import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { createPortal } from "react-dom";
import { CheckCircle2, Info, X, AlertTriangle, type LucideIcon } from "lucide-react";
import { cn, focusRing } from "./cn";

export type ToastTone = "success" | "error" | "info";

export type ToastAction = { label: string; onClick: () => void };

export type ToastOptions = {
  title: string;
  description?: string;
  tone?: ToastTone;
  /** Milliseconds before auto-dismiss; `0` keeps it until dismissed. */
  duration?: number;
  action?: ToastAction;
};

export type ToastRecord = ToastOptions & { id: string };

/** Imperative API returned by `useToast()`. */
export type ToastApi = {
  push: (options: ToastOptions) => string;
  success: (title: string, options?: Omit<ToastOptions, "title" | "tone">) => string;
  error: (title: string, options?: Omit<ToastOptions, "title" | "tone">) => string;
  info: (title: string, options?: Omit<ToastOptions, "title" | "tone">) => string;
  dismiss: (id: string) => void;
};

const ToastContext = createContext<ToastApi | null>(null);

let toastCounter = 0;

const TONE_META: Record<ToastTone, { icon: LucideIcon; className: string; accentClass: string }> = {
  success: { icon: CheckCircle2, className: "text-compliant", accentClass: "bg-compliant" },
  error: { icon: AlertTriangle, className: "text-critical", accentClass: "bg-critical" },
  info: { icon: Info, className: "text-accent", accentClass: "bg-accent" },
};

const MAX_TOASTS = 6;
const DEFAULT_DURATION = 5000;

function ToastItem({ toast, onDismiss }: { toast: ToastRecord; onDismiss: (id: string) => void }) {
  const [paused, setPaused] = useState(false);
  const tone = toast.tone ?? "info";
  const meta = TONE_META[tone];
  const Icon = meta.icon;

  useEffect(() => {
    const duration = toast.duration ?? DEFAULT_DURATION;
    if (paused || duration <= 0) return;
    const timer = window.setTimeout(() => onDismiss(toast.id), duration);
    return () => window.clearTimeout(timer);
  }, [paused, toast.id, toast.duration, onDismiss]);

  return (
    <div
      role={tone === "error" ? "alert" : "status"}
      onMouseEnter={() => setPaused(true)}
      onMouseLeave={() => setPaused(false)}
      onFocus={() => setPaused(true)}
      onBlur={() => setPaused(false)}
      className="pointer-events-auto relative overflow-hidden rounded-panel border border-hairline bg-surface-overlay p-3 pl-4 shadow-overlay animate-toast-in"
    >
      <span className={cn("absolute inset-y-0 left-0 w-1", meta.accentClass)} aria-hidden />
      <div className="flex items-start gap-3">
        <Icon size={18} className={cn("mt-0.5 shrink-0", meta.className)} aria-hidden />
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium text-ink">{toast.title}</p>
          {toast.description ? <p className="mt-0.5 text-xs text-ink-muted">{toast.description}</p> : null}
          {toast.action ? (
            <button
              type="button"
              onClick={() => {
                toast.action?.onClick();
                onDismiss(toast.id);
              }}
              className={cn("mt-2 rounded text-xs font-medium text-accent hover:underline", focusRing)}
            >
              {toast.action.label}
            </button>
          ) : null}
        </div>
        <button
          type="button"
          onClick={() => onDismiss(toast.id)}
          aria-label="Dismiss notification"
          className={cn("-mr-1 -mt-1 rounded p-1 text-ink-subtle hover:bg-surface-raised hover:text-ink", focusRing)}
        >
          <X size={14} aria-hidden />
        </button>
      </div>
    </div>
  );
}

/**
 * Global toast provider. Wrap the application once, then call
 * `useToast().success(...)` / `.error(...)` / `.info(...)` from anywhere.
 */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastRecord[]>([]);

  const dismiss = useCallback((id: string) => {
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);

  const push = useCallback((options: ToastOptions) => {
    toastCounter += 1;
    const id = `toast-${Date.now()}-${toastCounter}`;
    const record: ToastRecord = { tone: "info", ...options, id };
    setToasts((current) => [...current, record].slice(-MAX_TOASTS));
    return id;
  }, []);

  const value = useMemo<ToastApi>(
    () => ({
      push,
      dismiss,
      success: (title, options) => push({ ...options, title, tone: "success" }),
      error: (title, options) => push({ ...options, title, tone: "error" }),
      info: (title, options) => push({ ...options, title, tone: "info" }),
    }),
    [push, dismiss],
  );

  const viewport =
    typeof document === "undefined"
      ? null
      : createPortal(
          <div
            aria-live="polite"
            aria-atomic="false"
            className="pointer-events-none fixed bottom-4 right-4 z-[100] flex w-[min(24rem,calc(100vw-2rem))] flex-col gap-2"
          >
            {toasts.map((toast) => (
              <ToastItem key={toast.id} toast={toast} onDismiss={dismiss} />
            ))}
          </div>,
          document.body,
        );

  return (
    <ToastContext.Provider value={value}>
      {children}
      {viewport}
    </ToastContext.Provider>
  );
}

/** Access the toast API. Throws if used outside a `ToastProvider`. */
export function useToast(): ToastApi {
  const context = useContext(ToastContext);
  if (!context) throw new Error("useToast must be used within a ToastProvider");
  return context;
}
