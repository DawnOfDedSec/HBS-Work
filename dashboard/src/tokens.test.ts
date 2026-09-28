import { describe, expect, it } from "bun:test";
import { existsSync, readdirSync, readFileSync } from "node:fs";

/**
 * Guards the contrast contract documented at the top of index.css.
 *
 * Every assertion here maps to a real WCAG failure that was measured in the
 * shipped tokens, not to a style preference: the 11px label style is the most
 * used text in the console, and several controls are identified only by their
 * border. Surfaces are not interchangeable either, so each token is checked
 * against every surface it can be painted on, at its worst case.
 *
 * If one of these fails, fix the token - do not relax the threshold.
 */

const css = readFileSync(`${import.meta.dir}/index.css`, "utf8");

/** Pull `--color-*: #rrggbb` declarations out of the block starting at `selector`. */
function colorTokens(selector: string): Record<string, string> {
  const start = css.indexOf(selector);
  if (start < 0) throw new Error(`index.css is missing the ${selector} block`);
  const open = css.indexOf("{", start);
  const close = css.indexOf("}", open);
  const tokens: Record<string, string> = {};
  for (const [, name, hex] of css.slice(open, close).matchAll(/--color-([a-z0-9-]+):\s*(#[0-9a-fA-F]{6})/g)) {
    tokens[name] = hex;
  }
  return tokens;
}

const darkBase = colorTokens("@theme {");
const lightOnly = colorTokens('[data-theme="light"] {');

type Theme = Record<string, string>;

const THEMES: ReadonlyArray<[string, Theme]> = [
  ["dark", darkBase],
  ["light", { ...darkBase, ...lightOnly }],
];

/** Relative luminance of a #rrggbb colour. */
function luminance(hex: string): number {
  const value = Number.parseInt(hex.slice(1), 16);
  const channel = (raw: number): number => {
    const c = raw / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  };
  return (
    0.2126 * channel((value >> 16) & 255) +
    0.7152 * channel((value >> 8) & 255) +
    0.0722 * channel(value & 255)
  );
}

/** WCAG contrast ratio between two #rrggbb colours. */
function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

/** Every surface a token can be painted on, including the raised/overlay cases. */
const SURFACES = [
  "canvas",
  "canvas-elevated",
  "surface",
  "surface-raised",
  "surface-overlay",
  "surface-sunken",
] as const;

/** Foregrounds used as text on panels, tables, KPI tiles and chips. */
const TEXT_TOKENS = ["ink", "ink-muted", "ink-subtle"] as const;

const TONES = [
  "accent",
  "critical",
  "high",
  "medium",
  "low",
  "info",
  "compliant",
  "noncompliant",
  "degraded",
  "na",
  "error",
  "treatment-open",
  "treatment-accepted",
  "treatment-false-positive",
  "treatment-remediated",
  "evidence-primary",
  "evidence-fallback",
  "evidence-degraded",
] as const;

/** Label token -> the fill it is painted on. */
const CONTRAST_PAIRS: ReadonlyArray<readonly [string, string]> = [
  ["accent-contrast", "accent"],
  ["critical-contrast", "critical-strong"],
];

const AA_TEXT = 4.5;
const AA_NON_TEXT = 3;

function colour(theme: Theme, name: string): string {
  const hex = theme[name];
  if (!hex) throw new Error(`token --color-${name} is not declared`);
  return hex;
}

/** Collect `${what} = ratio` strings for every pair below the threshold. */
function below(theme: Theme, pairs: ReadonlyArray<readonly [string, string]>, min: number): string[] {
  return pairs
    .map(([fg, bg]) => [fg, bg, contrast(colour(theme, fg), colour(theme, bg))] as const)
    .filter(([, , value]) => value < min)
    .map(([fg, bg, value]) => `${fg} on ${bg} = ${value.toFixed(2)}:1 (needs ${min}:1)`);
}

describe("token contract", () => {
  it("declares the same colour tokens in both themes", () => {
    // A token missing from the light block silently keeps its dark value, which
    // is how a light theme ends up with unreadable text.
    expect(Object.keys(lightOnly).sort()).toEqual(Object.keys(darkBase).sort());
  });

  for (const [name, theme] of THEMES) {
    describe(`${name} theme`, () => {
      it("keeps body, muted and subtle text at AA on every surface", () => {
        const pairs = TEXT_TOKENS.flatMap((fg) =>
          SURFACES.map((bg) => [fg, bg] as const),
        );
        expect(below(theme, pairs, AA_TEXT)).toEqual([]);
      });

      it("keeps every tone readable as text on every surface", () => {
        const pairs = TONES.flatMap((fg) => SURFACES.map((bg) => [fg, bg] as const));
        expect(below(theme, pairs, AA_TEXT)).toEqual([]);
      });

      it("keeps every tone readable on its own soft tint", () => {
        const pairs = TONES.filter((tone) => theme[`${tone}-soft`]).map(
          (tone) => [tone, `${tone}-soft`] as const,
        );
        expect(below(theme, pairs, AA_TEXT)).toEqual([]);
      });

      it("keeps label colours readable on their own solid fill", () => {
        expect(below(theme, CONTRAST_PAIRS, AA_TEXT)).toEqual([]);
      });

      it("keeps control boundaries at 3:1 against every surface they border", () => {
        const pairs = SURFACES.map((bg) => ["control-edge", bg] as const);
        expect(below(theme, pairs, AA_NON_TEXT)).toEqual([]);
      });

      it("keeps the hover boundary stronger than the resting one", () => {
        expect(contrast(colour(theme, "control-edge-strong"), colour(theme, "control-edge")))
          .toBeGreaterThan(1.15);
      });

      it("keeps the focus ring at 3:1 against the surfaces it outlines", () => {
        const pairs = (["surface", "surface-raised", "canvas"] as const).map(
          (bg) => ["focus", bg] as const,
        );
        expect(below(theme, pairs, AA_NON_TEXT)).toEqual([]);
      });

      it("preserves the ink hierarchy: ink > ink-muted > ink-subtle", () => {
        const surface = colour(theme, "surface");
        const ink = contrast(colour(theme, "ink"), surface);
        const muted = contrast(colour(theme, "ink-muted"), surface);
        const subtle = contrast(colour(theme, "ink-subtle"), surface);
        expect(ink).toBeGreaterThan(muted);
        expect(muted).toBeGreaterThan(subtle);
      });
    });
  }
});

describe("token discipline", () => {
  it("uses no raw Tailwind palette colour in components", () => {
    // The palette ignores [data-theme], so these render wrong in at least one
    // theme. Every colour must come from a --color-* token.
    const palette =
      /\b(?:bg|text|border|ring|from|via|to|fill|stroke|divide|outline|decoration|caret|shadow)-(?:white|black|(?:slate|gray|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose)(?:-\d{2,3})?)\b/;
    const offenders: string[] = [];
    for (const file of readdirSync(import.meta.dir, { recursive: true })) {
      const path = `${import.meta.dir}/${file}`;
      if (!String(file).endsWith(".tsx")) continue;
      readFileSync(path, "utf8")
        .split("\n")
        .forEach((line, index) => {
          const match = line.match(palette);
          if (match) offenders.push(`${file}:${index + 1}: ${match[0]}`);
        });
    }
    expect(offenders).toEqual([]);
  });
});

describe("typography", () => {
  const html = readFileSync(`${import.meta.dir}/../index.html`, "utf8");

  it("declares a @font-face for every family the tokens name", () => {
    // The tokens said Inter and JetBrains Mono for the console's whole life
    // while neither was ever shipped, so it rendered in the OS default face.
    // Declaring a face is meaningless without the file behind it.
    expect(css).toMatch(/--font-sans:\s*"Inter"/);
    expect(css).toMatch(/--font-mono:\s*"JetBrains Mono"/);
    expect(css).toContain('font-family: "Inter"');
    expect(css).toContain('font-family: "JetBrains Mono"');
  });

  it("ships every font file the stylesheet references", () => {
    const referenced = [...css.matchAll(/url\("\/(fonts\/[^"]+\.woff2)"\)/g)].map((m) => m[1]);
    expect(referenced.length).toBeGreaterThanOrEqual(2);
    for (const relative of referenced) {
      expect(existsSync(`${import.meta.dir}/../public/${relative}`)).toBe(true);
    }
  });

  it("declares each face as variable with a swap fallback", () => {
    const faces = [...css.matchAll(/@font-face\s*\{([^}]*)\}/g)].map((m) => m[1]);
    expect(faces.length).toBeGreaterThanOrEqual(2);
    for (const face of faces) {
      // A range means one file serves every weight; a single weight would
      // silently synthesise bold, which looks wrong at 11px.
      expect(face).toContain("font-weight: 400 700");
      expect(face).toContain("font-display: swap");
    }
  });

  it("preloads each font in index.html", () => {
    for (const file of ["inter-latin-var.woff2", "jbmono-latin-var.woff2"]) {
      expect(html).toContain(`<link rel="preload" href="/fonts/${file}"`);
    }
  });

  it("keeps the theme storage key in sync between index.html and useTheme.ts", () => {
    // index.html reads the key before paint to avoid a dark flash for
    // light-theme users. If the two ever drift, the flash silently returns.
    const source = readFileSync(`${import.meta.dir}/useTheme.ts`, "utf8");
    const key = /STORAGE_KEY = "([^"]+)"/.exec(source)?.[1];
    expect(key).toBeTruthy();
    expect(html).toContain(`localStorage.getItem("${key}")`);
  });
});
