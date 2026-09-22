import { Stat, type StatTone } from "./ui";

export type KpiTileTone = "default" | "critical" | "high" | "ok";

export type KpiTileProps = {
  label: string;
  value: string | number;
  hint?: string;
  tone?: KpiTileTone;
  onClick?: () => void;
};

const TONE: Record<KpiTileTone, StatTone> = {
  default: "default",
  critical: "critical",
  high: "high",
  ok: "ok",
};

/**
 * Backwards-compatible KPI tile. Delegates to the `Stat` primitive so legacy
 * pages keep their import path and props while the console styling stays
 * centralised in the UI kit.
 */
export function KpiTile({ label, value, hint, tone = "default", onClick }: KpiTileProps) {
  return <Stat label={label} value={value} hint={hint} tone={TONE[tone]} onClick={onClick} />;
}
