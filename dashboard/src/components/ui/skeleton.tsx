import { cn } from "./cn";

export type SkeletonProps = {
  variant?: "text" | "rect" | "circle";
  width?: string | number;
  height?: string | number;
  className?: string;
};

/** A shimmering placeholder used while data loads. */
export function Skeleton({ variant = "text", width, height, className }: SkeletonProps) {
  return (
    <span
      aria-hidden
      className={cn(
        "block animate-shimmer rounded bg-surface-raised",
        variant === "text" && "h-3 rounded-full",
        variant === "circle" && "rounded-full",
        className,
      )}
      style={{
        width: width ?? undefined,
        height: height ?? undefined,
      }}
    />
  );
}

export type SkeletonTextProps = { lines?: number; className?: string };

/** A stack of text-line placeholders with a shorter final line. */
export function SkeletonText({ lines = 3, className }: SkeletonTextProps) {
  return (
    <div className={cn("space-y-2", className)} role="status" aria-label="Loading">
      {Array.from({ length: lines }).map((_, index) => (
        <Skeleton key={index} width={index === lines - 1 ? "60%" : "100%"} />
      ))}
    </div>
  );
}
