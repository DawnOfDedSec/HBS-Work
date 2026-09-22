import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from "react";
import { Loader2, type LucideIcon } from "lucide-react";
import { cn, focusRing } from "./cn";

export type ButtonVariant = "primary" | "secondary" | "ghost" | "danger" | "subtle";
export type ButtonSize = "sm" | "md" | "lg" | "icon";

export type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: ButtonVariant;
  size?: ButtonSize;
  /** Leading icon component. */
  icon?: LucideIcon;
  /** Trailing icon component. */
  iconRight?: LucideIcon;
  /** Show a busy spinner and disable interaction. */
  loading?: boolean;
  /** Convenience for full-width buttons in forms. */
  block?: boolean;
};

const VARIANT_CLASS: Record<ButtonVariant, string> = {
  primary:
    "bg-accent text-accent-contrast border border-transparent shadow-panel hover:bg-accent-strong active:translate-y-px",
  secondary:
    "bg-surface-raised text-ink border border-hairline hover:border-hairline-strong hover:bg-surface-overlay",
  ghost: "bg-transparent text-ink-muted border border-transparent hover:bg-surface-raised hover:text-ink",
  danger:
    "bg-critical-strong text-white border border-transparent shadow-panel hover:brightness-110 active:translate-y-px",
  subtle: "bg-accent-soft text-accent border border-transparent hover:brightness-110",
};

const SIZE_CLASS: Record<ButtonSize, string> = {
  sm: "h-8 px-3 text-xs gap-1.5 rounded-md",
  md: "h-9 px-3.5 text-sm gap-2 rounded-control",
  lg: "h-11 px-5 text-sm gap-2 rounded-control",
  icon: "h-9 w-9 p-0 justify-center rounded-control",
};

/**
 * The single button primitive. Every variant and size is expressed with
 * semantic tokens, and disabled/busy states remain keyboard discoverable.
 */
export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  {
    variant = "secondary",
    size = "md",
    icon: Icon,
    iconRight: IconRight,
    loading = false,
    block = false,
    className,
    children,
    disabled,
    type = "button",
    ...rest
  },
  ref,
) {
  const isDisabled = disabled || loading;
  return (
    <button
      ref={ref}
      type={type}
      disabled={isDisabled}
      aria-busy={loading || undefined}
      className={cn(
        "inline-flex select-none items-center font-medium transition-colors",
        focusRing,
        VARIANT_CLASS[variant],
        SIZE_CLASS[size],
        block && "w-full justify-center",
        isDisabled && "cursor-not-allowed opacity-55 hover:brightness-100",
        className,
      )}
      {...rest}
    >
      {loading ? (
        <Loader2 size={size === "lg" ? 18 : 16} className="animate-spin" aria-hidden />
      ) : Icon ? (
        <Icon size={size === "lg" ? 18 : 16} aria-hidden />
      ) : null}
      {children !== undefined && children !== null ? <span>{children}</span> : null}
      {IconRight && !loading ? <IconRight size={size === "lg" ? 18 : 16} aria-hidden /> : null}
    </button>
  );
});

export type IconButtonProps = Omit<ButtonProps, "size" | "icon"> & {
  icon: LucideIcon;
  /** Accessible name — required because the button has no visible text. */
  label: string;
  size?: "sm" | "md" | "lg";
};

const ICON_SIZE: Record<"sm" | "md" | "lg", string> = {
  sm: "h-7 w-7 rounded-md",
  md: "h-9 w-9 rounded-control",
  lg: "h-10 w-10 rounded-control",
};

/** A square, label-only button for toolbars and row actions. */
export const IconButton = forwardRef<HTMLButtonElement, IconButtonProps>(function IconButton(
  { icon: Icon, label, variant = "ghost", size = "md", className, ...rest },
  ref,
) {
  return (
    <Button
      ref={ref}
      variant={variant}
      size="icon"
      aria-label={label}
      title={label}
      className={cn(ICON_SIZE[size], className)}
      {...rest}
    >
      <Icon size={size === "lg" ? 18 : 16} aria-hidden />
    </Button>
  );
});

export type ButtonGroupProps = { children: ReactNode; className?: string };

/** Segmented group that visually fuses adjacent buttons. */
export function ButtonGroup({ children, className }: ButtonGroupProps) {
  return (
    <div
      role="group"
      className={cn(
        "inline-flex items-center gap-0.5 rounded-control border border-hairline bg-surface-raised p-0.5",
        className,
      )}
    >
      {children}
    </div>
  );
}
