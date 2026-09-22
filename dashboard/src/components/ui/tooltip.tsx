import { cloneElement, useId, useState, type ReactElement, type ReactNode } from "react";
import { cn } from "./cn";

type TooltipTriggerProps = { "aria-describedby"?: string };

export type TooltipProps = {
  content: ReactNode;
  /** A single interactive child; it receives `aria-describedby` while open. */
  children: ReactElement<TooltipTriggerProps>;
  side?: "top" | "bottom";
  className?: string;
};

/**
 * A hover/focus tooltip. Focus events bubble, so keyboard users get the same
 * disclosure as pointer users; Escape dismisses it.
 */
export function Tooltip({ content, children, side = "top", className }: TooltipProps) {
  const [open, setOpen] = useState(false);
  const id = useId();
  const trigger = cloneElement(children, {
    "aria-describedby": open ? id : children.props["aria-describedby"],
  });

  return (
    <span
      className="relative inline-flex"
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
      onKeyDown={(event) => {
        if (event.key === "Escape") setOpen(false);
      }}
    >
      {trigger}
      {open ? (
        <span
          role="tooltip"
          id={id}
          className={cn(
            "pointer-events-none absolute left-1/2 z-50 w-max max-w-64 -translate-x-1/2 rounded-control border border-hairline bg-surface-overlay px-2 py-1 text-2xs text-ink shadow-raised animate-fade-in",
            side === "top" ? "bottom-full mb-1.5" : "top-full mt-1.5",
            className,
          )}
        >
          {content}
        </span>
      ) : null}
    </span>
  );
}
