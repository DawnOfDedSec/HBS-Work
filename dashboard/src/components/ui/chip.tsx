import type { ReactNode } from "react";
import { X, type LucideIcon } from "lucide-react";
import { cn, focusRing } from "./cn";

export type ChipProps = {
  label: ReactNode;
  /** Optional value shown after the label (e.g. `Critical`). */
  value?: ReactNode;
  icon?: LucideIcon;
  /** Renders a remove affordance for active filters. */
  onRemove?: () => void;
  /** Makes the whole chip a toggle/action control. */
  onClick?: () => void;
  active?: boolean;
  className?: string;
};

/**
 * A compact filter chip. Removable chips expose a dedicated remove button with
 * an explicit accessible name so it is operable by touch and keyboard.
 */
export function Chip({ label, value, icon: Icon, onRemove, onClick, active = false, className }: ChipProps) {
  const inner = (
    <>
      {Icon ? <Icon size={12} aria-hidden /> : null}
      <span className="font-medium">{label}</span>
      {value !== undefined && value !== null ? <span className="text-ink-muted">{value}</span> : null}
    </>
  );

  const shell = cn(
    "inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-2xs",
    active
      ? "border-accent/40 bg-accent-soft text-accent"
      : "border-hairline bg-surface-raised text-ink",
    className,
  );

  if (onRemove) {
    return (
      <span className={shell}>
        {onClick ? (
          <button type="button" onClick={onClick} className={cn("inline-flex items-center gap-1.5", focusRing)}>
            {inner}
          </button>
        ) : (
          inner
        )}
        <button
          type="button"
          onClick={onRemove}
          aria-label={`Remove ${typeof label === "string" ? label : "filter"} filter`}
          className={cn("-mr-1 rounded-full p-0.5 text-ink-subtle hover:bg-surface-overlay hover:text-ink", focusRing)}
        >
          <X size={11} aria-hidden />
        </button>
      </span>
    );
  }

  if (onClick) {
    return (
      <button type="button" onClick={onClick} aria-pressed={active} className={cn(shell, focusRing)}>
        {inner}
      </button>
    );
  }

  return <span className={shell}>{inner}</span>;
}
