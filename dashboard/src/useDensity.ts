// Persisted table density (comfortable | compact) for dense data tables.

import { useCallback, useEffect, useState } from "react";

export type Density = "comfortable" | "compact";

const STORAGE_KEY = "hbs-table-density";

function readInitialDensity(): Density {
  if (typeof window === "undefined") return "comfortable";
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (stored === "compact" || stored === "comfortable") return stored;
  } catch {
    // storage may be unavailable (private mode); fall through to the default
  }
  return "comfortable";
}

export type DensityController = {
  density: Density;
  /** True when the compact row style is active (maps to `Table dense`). */
  dense: boolean;
  setDensity: (density: Density) => void;
  toggle: () => void;
};

/** Comfortable/compact density persisted across reloads. */
export function useDensity(): DensityController {
  const [density, setDensity] = useState<Density>(readInitialDensity);

  useEffect(() => {
    try {
      window.localStorage.setItem(STORAGE_KEY, density);
    } catch {
      // storage may be unavailable; the session value still applies
    }
  }, [density]);

  const toggle = useCallback(() => {
    setDensity((current) => (current === "compact" ? "comfortable" : "compact"));
  }, []);

  return { density, dense: density === "compact", setDensity, toggle };
}
