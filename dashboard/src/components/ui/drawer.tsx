import { useEffect, useId, useRef, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { X } from "lucide-react";
import { cn } from "./cn";
import { IconButton } from "./button";
import { useFocusTrap } from "./use-focus-trap";

export type DrawerSize = "sm" | "md" | "lg";

export type DrawerProps = {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  description?: ReactNode;
  children?: ReactNode;
  footer?: ReactNode;
  size?: DrawerSize;
  className?: string;
};

const SIZE_CLASS: Record<DrawerSize, string> = {
  sm: "w-80",
  md: "w-[26rem]",
  lg: "w-[34rem]",
};

/**
 * A right-side panel with a focus trap and Escape-to-close. Useful for
 * evidence, filters, and detail inspectors that should not lose page context.
 */
export function Drawer({ open, onClose, title, description, children, footer, size = "md", className }: DrawerProps) {
  const panelRef = useRef<HTMLDivElement>(null);
  const titleId = useId();
  useFocusTrap(open, panelRef, onClose);

  useEffect(() => {
    if (!open) return;
    const previous = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = previous;
    };
  }, [open]);

  if (!open || typeof document === "undefined") return null;

  return createPortal(
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-canvas/75 backdrop-blur-sm animate-fade-in" onClick={onClose} aria-hidden />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        className={cn(
          "relative z-10 flex h-full max-w-full flex-col border-l border-hairline bg-surface shadow-overlay animate-slide-in-right",
          SIZE_CLASS[size],
          className,
        )}
      >
        <div className="flex items-start justify-between gap-4 border-b border-hairline-soft p-4">
          <div className="min-w-0">
            <h2 id={titleId} className="text-base font-semibold text-ink">
              {title}
            </h2>
            {description ? <p className="mt-1 text-xs text-ink-muted">{description}</p> : null}
          </div>
          <IconButton icon={X} label="Close panel" onClick={onClose} />
        </div>
        <div className="hbs-scroll min-h-0 flex-1 overflow-y-auto p-4">{children}</div>
        {footer ? (
          <div className="flex items-center justify-end gap-2 border-t border-hairline-soft p-4">{footer}</div>
        ) : null}
      </div>
    </div>,
    document.body,
  );
}
