/** Join conditional class names. Small, dependency-free, and typed. */
export type ClassValue = string | number | false | null | undefined;

export function cn(...values: ClassValue[]): string {
  return values.filter((value): value is string | number => Boolean(value)).join(" ");
}

/**
 * The standard keyboard focus treatment. Applied to every interactive
 * primitive so focus is always visible and consistent.
 */
export const focusRing =
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus focus-visible:ring-offset-2 focus-visible:ring-offset-canvas";
