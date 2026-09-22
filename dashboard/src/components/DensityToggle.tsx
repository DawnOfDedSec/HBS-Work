import { AlignJustify, Rows3 } from "lucide-react";
import { Button, ButtonGroup } from "./ui";
import type { Density } from "../useDensity";

export type DensityToggleProps = {
  density: Density;
  onChange: (density: Density) => void;
  /** Accessible name for the segmented group. */
  label?: string;
  className?: string;
};

/** Compact/comfortable row density, persisted by `useDensity`. */
export function DensityToggle({ density, onChange, label = "Table density", className }: DensityToggleProps) {
  return (
    <ButtonGroup className={className}>
      <span className="sr-only">{label}</span>
      <Button
        size="sm"
        variant={density === "comfortable" ? "subtle" : "ghost"}
        icon={Rows3}
        aria-pressed={density === "comfortable"}
        onClick={() => onChange("comfortable")}
      >
        Comfortable
      </Button>
      <Button
        size="sm"
        variant={density === "compact" ? "subtle" : "ghost"}
        icon={AlignJustify}
        aria-pressed={density === "compact"}
        onClick={() => onChange("compact")}
      >
        Compact
      </Button>
    </ButtonGroup>
  );
}
