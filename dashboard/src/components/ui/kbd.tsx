import type { ReactNode } from "react";
import { cn } from "./cn";

export type KbdProps = { children: ReactNode; className?: string };

/** A keyboard-key token, e.g. ⌘K hints in the palette and toolbar. */
export function Kbd({ children, className }: KbdProps) {
  return (
    <kbd
      className={cn(
        "inline-flex h-5 min-w-5 items-center justify-center rounded border border-hairline bg-surface-raised px-1.5 font-mono text-2xs text-ink-subtle",
        className,
      )}
    >
      {children}
    </kbd>
  );
}
