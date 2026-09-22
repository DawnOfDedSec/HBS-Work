import { useCallback, useLayoutEffect, useState } from "react";

export type Theme = "dark" | "light";

const STORAGE_KEY = "hbs-theme";

function readInitialTheme(): Theme {
  if (typeof window === "undefined") return "dark";
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (stored === "dark" || stored === "light") return stored;
  } catch {
    // storage may be unavailable (private mode); fall through to the default
  }
  return "dark";
}

/**
 * Dark-first light/dark theme persisted across reloads. The attribute is set
 * in a layout effect so the correct tokens apply before the browser paints.
 */
export function useTheme() {
  const [theme, setTheme] = useState<Theme>(readInitialTheme);

  useLayoutEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      window.localStorage.setItem(STORAGE_KEY, theme);
    } catch {
      // storage may be unavailable; the theme still applies for this session
    }
  }, [theme]);

  const toggle = useCallback(() => setTheme((current) => (current === "dark" ? "light" : "dark")), []);

  return { theme, setTheme, toggle };
}
