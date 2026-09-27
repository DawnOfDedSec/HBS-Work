/**
 * Design guard for the docs site.
 *
 * Every assertion here is a defect that was actually measured in the shipped
 * theme, not a style preference:
 *   - `faint` was 3.36-3.97:1 on every surface;
 *   - the focus ring composited to 1.19:1, i.e. invisible;
 *   - the primary CTA put white text on the vivid brand gradient, 2.80:1 at the
 *     orange end;
 *   - no font was loaded at all, so `JetBrains Mono` and `Fira Code` silently
 *     fell back to whatever the OS had.
 * If one of these fails, fix the token or the stylesheet. Do not relax the
 * threshold, and do not delete an assertion to make the build pass.
 *
 * Run standalone with `bun run check`, or as part of `bun run build`.
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import tailwind from '../tailwind.config.js';

const root = join(import.meta.dir, '..');
const colors = tailwind.theme.extend.colors as Record<string, string | Record<string, string>>;
const css = readFileSync(join(root, 'src/index.css'), 'utf8');
const html = readFileSync(join(root, 'index.html'), 'utf8');

const AA_TEXT = 4.5;
const AA_NON_TEXT = 3;

/** flatten the nested accent/cta groups to `accent-2` style keys */
function flatten(value: Record<string, string | Record<string, string>>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, entry] of Object.entries(value)) {
    if (typeof entry === 'string') out[key] = entry;
    else for (const [sub, hex] of Object.entries(entry)) out[sub === 'DEFAULT' ? key : `${key}-${sub}`] = hex;
  }
  return out;
}

const palette = flatten(colors);
const hex = (name: string): string => {
  const value = palette[name];
  if (!value) throw new Error(`token "${name}" is not defined in tailwind.config.js`);
  return value;
};

function luminance(value: string): number {
  const n = Number.parseInt(value.slice(1), 16);
  const channel = (raw: number) => {
    const c = raw / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel((n >> 16) & 255) + 0.7152 * channel((n >> 8) & 255) + 0.0722 * channel(n & 255);
}

function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

const failures: string[] = [];
const check = (label: string, ok: boolean, detail = '') => {
  if (!ok) failures.push(`${label}${detail ? ` - ${detail}` : ''}`);
};

// ---------------------------------------------------------------- contrast
const SURFACES = ['surface', 'bg2', 'panel', 'elevated'];
const TEXT_TOKENS = ['ink', 'ink2', 'muted', 'faint', 'link', 'linkh'];

for (const fg of TEXT_TOKENS) {
  for (const bg of SURFACES) {
    const ratio = contrast(hex(fg), hex(bg));
    check(`${fg} on ${bg}`, ratio >= AA_TEXT, `${ratio.toFixed(2)}:1, needs ${AA_TEXT}:1`);
  }
}

for (const bg of SURFACES) {
  const ratio = contrast(hex('edge'), hex(bg));
  check(`edge on ${bg}`, ratio >= AA_NON_TEXT, `${ratio.toFixed(2)}:1, needs ${AA_NON_TEXT}:1 (1.4.11)`);
}

// white on every CTA gradient stop - the button's whole surface is text background
for (const stop of ['cta', 'cta-2', 'cta-3']) {
  const ratio = contrast('#ffffff', hex(stop));
  check(`white on ${stop}`, ratio >= AA_TEXT, `${ratio.toFixed(2)}:1, needs ${AA_TEXT}:1`);
}

// status tones used as text in allow/refuse lists and the licence table
for (const tone of ['ok', 'warn', 'deny']) {
  for (const bg of ['surface', 'panel']) {
    const ratio = contrast(hex(tone), hex(bg));
    check(`${tone} on ${bg}`, ratio >= AA_TEXT, `${ratio.toFixed(2)}:1, needs ${AA_TEXT}:1`);
  }
}

// the focus indicator lives in index.css, not in Tailwind
const focusMatch = /--focus:\s*(#[0-9a-fA-F]{6})/.exec(css);
check('index.css declares --focus', Boolean(focusMatch));
if (focusMatch) {
  for (const bg of SURFACES) {
    const ratio = contrast(focusMatch[1], hex(bg));
    check(`focus ring on ${bg}`, ratio >= AA_NON_TEXT, `${ratio.toFixed(2)}:1, needs ${AA_NON_TEXT}:1`);
  }
}

// the gradient in .btn-primary must be built from the cta-* variables, so the
// stops cannot drift away from the values asserted above
check(
  '.btn-primary uses the cta-* variables',
  /\.btn-primary\s*\{[^}]*linear-gradient\([^)]*var\(--cta-1\)/.test(css),
);
for (const v of ['--cta-1', '--cta-2', '--cta-3']) {
  const declared = new RegExp(`\\${v}:\\s*(#[0-9a-fA-F]{6})`).exec(css);
  check(`${v} is declared in :root`, Boolean(declared));
  if (declared) {
    const key = { '--cta-1': 'cta', '--cta-2': 'cta-2', '--cta-3': 'cta-3' }[v]!;
    check(`${v} matches the ${key} token`, declared[1].toLowerCase() === hex(key).toLowerCase(), `${declared[1]} vs ${hex(key)}`);
  }
}

// ------------------------------------------------------------------- fonts
for (const [family, file] of [
  ['IBM Plex Sans', 'plex-sans-latin-var.woff2'],
  ['JetBrains Mono', 'jbmono-latin-var.woff2'],
]) {
  check(`@font-face declares ${family}`, css.includes(`font-family: '${family}'`));
  check(`${file} is vendored`, existsSync(join(root, 'public/fonts', file)));
  check(`index.html preloads ${file}`, html.includes(file));
  check(`@font-face ${family} sets a variable weight range`, /@font-face\s*\{[^}]*font-weight:\s*400 700/.test(css));
}

// ---------------------------------------------------------------- discipline
/**
 * Raw Tailwind palette colours ignore these tokens entirely (`bg-emerald-400`
 * does not respond to a token change), so they are banned in components - the
 * same rule the dashboard's token test enforces.
 */
const PALETTE =
  /\b(?:bg|text|border|ring|from|via|to|fill|stroke|divide|outline|decoration|caret|shadow)-(?:white|black|(?:slate|gray|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose)(?:-\d{2,3})?)\b/;
const DEAD_CLASSES = ['grad-text', 'glass-card', 'hbs-scroll', 'animate-shimmer'];

for (const file of readdirSync(join(root, 'src'), { recursive: true })) {
  if (!String(file).endsWith('.tsx')) continue;
  const body = readFileSync(join(root, 'src', String(file)), 'utf8');
  body.split('\n').forEach((line, i) => {
    const hit = line.match(PALETTE);
    if (hit) failures.push(`raw palette class ${hit[0]} in src/${file}:${i + 1}`);
    for (const dead of DEAD_CLASSES) {
      if (line.includes(dead)) failures.push(`removed class "${dead}" still referenced in src/${file}:${i + 1}`);
    }
  });
}

// ------------------------------------------------------------------- report
if (failures.length > 0) {
  console.error(`\n[check-design] ${failures.length} problem(s):\n`);
  for (const f of failures) console.error(`  - ${f}`);
  console.error('');
  process.exit(1);
}
console.log('[check-design] token, contrast, font and class contracts hold');
