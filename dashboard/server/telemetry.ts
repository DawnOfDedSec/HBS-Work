// Small pure statistics helpers shared by telemetry and diagnostics (Task 49).

/**
 * Nearest-rank percentile over an ascending-sorted numeric array.
 * Returns null for an empty input. `p` is a percentage in [0, 100].
 */
export function percentile(sorted: readonly number[], p: number): number | null {
  const n = sorted.length;
  if (n === 0) return null;
  const rank = Math.ceil((Math.min(Math.max(p, 0), 100) / 100) * n);
  const index = Math.min(Math.max(rank - 1, 0), n - 1);
  return Math.round(sorted[index] * 1000) / 1000;
}
