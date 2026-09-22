import type { HTMLAttributes, ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import { cn } from "./cn";

export type CardProps = HTMLAttributes<HTMLDivElement> & {
  /** Visually recessed surface (used for nested/inset content). */
  inset?: boolean;
  /** Remove interior padding when the card hosts a flush table. */
  flush?: boolean;
};

/** A raised content surface built on the hairline + elevation tokens. */
export function Card({ inset = false, flush = false, className, children, ...rest }: CardProps) {
  return (
    <div
      className={cn(
        inset ? "hbs-inset" : "hbs-panel",
        !flush && "p-4",
        className,
      )}
      {...rest}
    >
      {children}
    </div>
  );
}

export type CardHeaderProps = {
  title: ReactNode;
  description?: ReactNode;
  icon?: LucideIcon;
  /** Right-aligned actions (buttons, filters, toggles). */
  actions?: ReactNode;
  className?: string;
  id?: string;
};

export function CardHeader({ title, description, icon: Icon, actions, className, id }: CardHeaderProps) {
  return (
    <div className={cn("flex flex-wrap items-start justify-between gap-3", className)}>
      <div className="flex min-w-0 items-start gap-2.5">
        {Icon ? (
          <span className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-control bg-surface-raised text-ink-muted">
            <Icon size={15} aria-hidden />
          </span>
        ) : null}
        <div className="min-w-0">
          <h3 id={id} className="text-sm font-semibold text-ink">
            {title}
          </h3>
          {description ? <p className="mt-0.5 text-xs text-ink-muted">{description}</p> : null}
        </div>
      </div>
      {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export type CardBodyProps = HTMLAttributes<HTMLDivElement> & { padded?: boolean };

export function CardBody({ padded = true, className, children, ...rest }: CardBodyProps) {
  return (
    <div className={cn(padded ? "pt-3" : "pt-0", className)} {...rest}>
      {children}
    </div>
  );
}

export function CardFooter({ className, children, ...rest }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn("mt-4 flex items-center justify-between gap-3 border-t border-hairline-soft pt-3", className)}
      {...rest}
    >
      {children}
    </div>
  );
}
