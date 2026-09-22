import { useEffect, useId, useRef, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { X } from "lucide-react";
import { cn } from "./cn";
import { IconButton } from "./button";
import { useFocusTrap } from "./use-focus-trap";

export type ModalSize = "sm" | "md" | "lg" | "xl";

export type ModalProps = {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  description?: ReactNode;
  children?: ReactNode;
  /** Rendered in a right-aligned footer row. */
  footer?: ReactNode;
  size?: ModalSize;
  /** Close when the backdrop is clicked (default true). */
  closeOnOverlay?: boolean;
  className?: string;
};

const SIZE_CLASS: Record<ModalSize, string> = {
  sm: "max-w-sm",
  md: "max-w-lg",
  lg: "max-w-2xl",
  xl: "max-w-4xl",
};

/**
 * A centered dialog with a focus trap, Escape-to-close, backdrop dismissal and
 * body scroll lock. Focus is restored to the invoking control on close.
 */
export function Modal({
  open,
  onClose,
  title,
  description,
  children,
  footer,
  size = "md",
  closeOnOverlay = true,
  className,
}: ModalProps) {
  const panelRef = useRef<HTMLDivElement>(null);
  const titleId = useId();
  const descriptionId = useId();
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
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-canvas/75 p-4 backdrop-blur-sm animate-fade-in sm:items-center"
      onMouseDown={(event) => {
        if (closeOnOverlay && event.target === event.currentTarget) onClose();
      }}
    >
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={description ? descriptionId : undefined}
        tabIndex={-1}
        className={cn("hbs-panel my-auto w-full p-0 shadow-overlay animate-scale-in", SIZE_CLASS[size], className)}
      >
        <div className="flex items-start justify-between gap-4 border-b border-hairline-soft p-4">
          <div className="min-w-0">
            <h2 id={titleId} className="text-base font-semibold text-ink">
              {title}
            </h2>
            {description ? (
              <p id={descriptionId} className="mt-1 text-xs text-ink-muted">
                {description}
              </p>
            ) : null}
          </div>
          <IconButton icon={X} label="Close dialog" onClick={onClose} />
        </div>
        {children ? <div className="hbs-scroll max-h-[70vh] overflow-y-auto p-4">{children}</div> : null}
        {footer ? (
          <div className="flex items-center justify-end gap-2 border-t border-hairline-soft p-4">{footer}</div>
        ) : null}
      </div>
    </div>,
    document.body,
  );
}
