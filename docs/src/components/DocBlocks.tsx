import type { DocBlock } from '../docs/content';
import Code from './Code';
import Note from './ui/Note';

/**
 * Stable anchor for a heading. The section content is authored with numeric
 * prefixes ("1. Install and open the dashboard"); the anchor drops them so the
 * URL reads /docs/getting-started#install-and-open-the-dashboard.
 */
export function slugifyHeading(text: string): string {
  return text
    .toLowerCase()
    .replace(/^\s*\d+[.)]\s*/, '')
    .replace(/[^a-z0-9\s-]/g, '')
    .trim()
    .replace(/\s+/g, '-');
}

export interface Heading {
  /** index into the section's block array, so the renderer and the TOC agree */
  index: number;
  id: string;
  text: string;
}

/**
 * Headings and their anchors, computed once per section and shared by the
 * "On this page" list and the rendered headings - two independent slug
 * calculations is how a TOC ends up linking nowhere.
 */
export function collectHeadings(blocks: readonly DocBlock[]): Heading[] {
  const seen = new Map<string, number>();
  const headings: Heading[] = [];
  blocks.forEach((block, index) => {
    if (block.type !== 'h2') return;
    const base = slugifyHeading(block.content) || `section-${index + 1}`;
    const count = seen.get(base) ?? 0;
    seen.set(base, count + 1);
    headings.push({ index, id: count === 0 ? base : `${base}-${count + 1}`, text: block.content });
  });
  return headings;
}

/** Rough reading time, computed from the section's own words. */
export function readingMinutes(blocks: readonly DocBlock[]): number {
  let words = 0;
  const count = (value: string) => value.trim().split(/\s+/).filter(Boolean).length;
  for (const block of blocks) {
    if (block.type === 'text' || block.type === 'h2' || block.type === 'note') words += count(block.content);
    else if (block.type === 'list') words += block.items.reduce((n, i) => n + count(i), 0);
    else if (block.type === 'table')
      words += block.rows.reduce((n, row) => n + row.reduce((m, cell) => m + count(cell), 0), 0);
  }
  return Math.max(1, Math.round(words / 200));
}

export function Block({ block, id }: { block: DocBlock; id?: string }) {
  switch (block.type) {
    case 'text':
      return <p className="leading-[1.75] text-ink2">{block.content}</p>;
    case 'h2':
      return (
        <h2 id={id} className="scroll-mt-24 pt-5 text-[1.15rem] font-bold">
          {block.content}
        </h2>
      );
    case 'code':
      return <Code content={block.content} lang={block.lang} title={block.title} />;
    case 'table': {
      const headers = block.headers as readonly string[];
      return (
        <div className="overflow-x-auto">
          <table className="spec-table">
            <thead>
              <tr>
                {headers.map((h) => (
                  <th key={h} scope="col">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {block.rows.map((row, i) => (
                <tr key={i}>
                  {row.map((cell, j) => (
                    <td key={j} className={j === 0 ? 'font-mono text-[0.8rem]' : undefined}>
                      {j === 0 ? <code className="inline">{cell}</code> : cell}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
    }
    case 'list':
      return (
        <ul className="space-y-1.5 pl-5 text-ink2">
          {block.items.map((item, i) => (
            <li key={i} className="list-disc">
              {item}
            </li>
          ))}
        </ul>
      );
    case 'note':
      return <Note tone={block.tone}>{block.content}</Note>;
  }
}
