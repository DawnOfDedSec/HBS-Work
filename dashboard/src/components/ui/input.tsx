import { forwardRef, useId, type InputHTMLAttributes, type ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import { cn, focusRing } from "./cn";

export type InputProps = Omit<InputHTMLAttributes<HTMLInputElement>, "size"> & {
  label?: string;
  hint?: string;
  error?: string;
  /** Leading icon rendered inside the field. */
  icon?: LucideIcon;
  /** Trailing control rendered inside the field (e.g. a password toggle). */
  trailing?: ReactNode;
  size?: "sm" | "md" | "lg";
  invalid?: boolean;
  containerClassName?: string;
};

const SIZE_CLASS: Record<"sm" | "md" | "lg", string> = {
  sm: "h-8 text-xs",
  md: "h-9 text-sm",
  lg: "h-11 text-sm",
};

/**
 * Text input with label, hint/error messaging, optional leading icon and
 * trailing control. Error state is conveyed with `aria-invalid` plus text.
 */
export const Input = forwardRef<HTMLInputElement, InputProps>(function Input(
  {
    label,
    hint,
    error,
    icon: Icon,
    trailing,
    size = "md",
    invalid = false,
    containerClassName,
    className,
    id,
    "aria-describedby": ariaDescribedBy,
    ...rest
  },
  ref,
) {
  const generatedId = useId();
  const inputId = id ?? generatedId;
  const messageId = error ? `${inputId}-error` : hint ? `${inputId}-hint` : undefined;
  const describedBy = [ariaDescribedBy, messageId].filter(Boolean).join(" ") || undefined;
  const isInvalid = invalid || Boolean(error);

  return (
    <div className={cn("flex flex-col gap-1", containerClassName)}>
      {label ? (
        <label htmlFor={inputId} className="text-2xs font-medium text-ink-muted">
          {label}
        </label>
      ) : null}
      <div className="relative">
        {Icon ? (
          <Icon
            size={15}
            aria-hidden
            className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-ink-subtle"
          />
        ) : null}
        <input
          ref={ref}
          id={inputId}
          aria-invalid={isInvalid || undefined}
          aria-describedby={describedBy}
          className={cn(
            "w-full rounded-control border bg-surface-raised text-ink transition-colors placeholder:text-ink-subtle",
            SIZE_CLASS[size],
            Icon ? "pl-9" : "pl-3",
            trailing ? "pr-10" : "pr-3",
            isInvalid ? "border-critical/60" : "border-control-edge hover:border-control-edge-strong",
            focusRing,
            className,
          )}
          {...rest}
        />
        {trailing ? <div className="absolute right-1.5 top-1/2 -translate-y-1/2">{trailing}</div> : null}
      </div>
      {error ? (
        <p id={`${inputId}-error`} className="text-2xs text-critical" role="alert">
          {error}
        </p>
      ) : hint ? (
        <p id={`${inputId}-hint`} className="text-2xs text-ink-subtle">
          {hint}
        </p>
      ) : null}
    </div>
  );
});
