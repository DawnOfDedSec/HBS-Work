import type { ReactNode } from "react";
import { cn } from "./cn";

export type ToolbarProps = {
  children: ReactNode;
  /** Accessible name for the toolbar region. */
  label?: string;
  className?: string;
};

/** A horizontal strip that groups filter/search/action controls. */
export function Toolbar({ children, label, className }: ToolbarProps) {
  return (
    <div
      role="toolbar"
      aria-label={label}
      className={cn(
        "flex flex-wrap items-center gap-2 rounded-control border border-hairline bg-surface px-3 py-2",
        className,
      )}
    >
      {children}
    </div>
  );
}

export function ToolbarGroup({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn("flex flex-wrap items-center gap-2", className)}>{children}</div>;
}

export function ToolbarSpacer() {
  return <div className="flex-1" aria-hidden />;
}

export function ToolbarDivider() {
  return <span className="h-5 w-px bg-hairline" aria-hidden />;
}
