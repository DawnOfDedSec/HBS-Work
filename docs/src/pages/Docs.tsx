import { useEffect, useMemo } from 'react';
import { Link, NavLink, useParams } from 'react-router-dom';
import { ArrowLeft, ArrowRight, Clock } from 'lucide-react';
import { DOC_SECTIONS } from '../docs/content';
import { Block, collectHeadings, readingMinutes } from '../components/DocBlocks';

export default function Docs() {
  const { section } = useParams();
  const active = DOC_SECTIONS.find((s) => s.slug === section) ?? DOC_SECTIONS[0];
  const index = DOC_SECTIONS.findIndex((s) => s.slug === active.slug);

  const headings = useMemo(() => collectHeadings(active.content), [active]);
  const minutes = useMemo(() => readingMinutes(active.content), [active]);
  const headingIdByIndex = useMemo(
    () => new Map(headings.map((h) => [h.index, h.id])),
    [headings],
  );

  useEffect(() => {
    window.scrollTo(0, 0);
  }, [active.slug]);

  const prev = index > 0 ? DOC_SECTIONS[index - 1] : null;
  const next = index < DOC_SECTIONS.length - 1 ? DOC_SECTIONS[index + 1] : null;
  const href = (slug: string) => (slug === DOC_SECTIONS[0].slug ? '/docs' : `/docs/${slug}`);

  return (
    <div className="mx-auto max-w-[1280px] px-6 py-10">
      <header className="border-b border-hairline pb-6">
        <div className="flex items-center gap-3 font-mono text-[0.7rem] uppercase tracking-[0.16em] text-faint">
          <span>Documentation</span>
          <span aria-hidden="true">/</span>
          <span className="text-link">
            {String(index + 1).padStart(2, '0')} of {String(DOC_SECTIONS.length).padStart(2, '0')}
          </span>
        </div>
        <h1 className="mt-3 text-[clamp(1.7rem,3.4vw,2.4rem)] font-bold">{active.title}</h1>
        <p className="mt-3 max-w-[720px] leading-relaxed text-muted">{active.blurb}</p>
        <p className="mt-4 inline-flex items-center gap-1.5 font-mono text-[0.72rem] text-faint">
          <Clock size={12} aria-hidden="true" />≈ {minutes} min read
        </p>
      </header>

      <div className="mt-8 flex flex-col gap-8 lg:flex-row">
        {/* sidebar: section list, then the in-page contents on desktop */}
        <aside className="lg:w-60 lg:shrink-0">
          <nav
            aria-label="Documentation sections"
            className="-mx-1 flex gap-1.5 overflow-x-auto pb-1 lg:mx-0 lg:flex-col lg:overflow-visible lg:pb-0"
          >
            {DOC_SECTIONS.map((s, i) => (
              <NavLink
                key={s.slug}
                to={href(s.slug)}
                end
                className={({ isActive }) =>
                  'flex shrink-0 items-center gap-2.5 rounded-lg px-3 py-2 text-[0.84rem] transition lg:shrink ' +
                  (isActive || s.slug === active.slug
                    ? 'bg-wash-strong font-semibold text-ink'
                    : 'text-muted hover:bg-wash hover:text-ink')
                }
                style={s.slug === active.slug ? { boxShadow: 'inset 2px 0 0 #8b5cf6' } : undefined}
              >
                <span className="section-num">{String(i + 1).padStart(2, '0')}</span>
                <span className="whitespace-nowrap lg:whitespace-normal">{s.title}</span>
              </NavLink>
            ))}
          </nav>

          {headings.length > 0 ? (
            <nav aria-label="On this page" className="panel mt-6 hidden p-4 lg:block">
              <p className="mono-label">On this page</p>
              <ul className="mt-3 space-y-1.5 border-l border-hairline">
                {headings.map((h) => (
                  <li key={h.id}>
                    <a
                      href={`#${h.id}`}
                      className="-ml-px block border-l border-transparent pl-3 text-[0.8rem] leading-snug text-muted transition hover:border-accent hover:text-ink"
                    >
                      {h.text}
                    </a>
                  </li>
                ))}
              </ul>
            </nav>
          ) : null}

          <div className="panel mt-6 hidden p-4 lg:block">
            <p className="mono-label">Resources</p>
            <ul className="mt-3 space-y-2 text-[0.82rem]">
              <li>
                <a
                  className="text-link hover:text-linkh"
                  href="https://github.com/PotenFYR-Studios/HBS-Tool/releases"
                >
                  Releases and installers
                </a>
              </li>
              <li>
                <Link className="text-link hover:text-linkh" to="/examples">
                  Example workflows
                </Link>
              </li>
              <li>
                <Link className="text-link hover:text-linkh" to="/license">
                  License
                </Link>
              </li>
            </ul>
          </div>
        </aside>

        <article className="min-w-0 flex-1 space-y-5 pb-16">
          {active.content.map((block, i) => (
            <Block key={i} block={block} id={headingIdByIndex.get(i)} />
          ))}

          {/* pager */}
          <nav className="grid gap-3 border-t border-hairline pt-8 sm:grid-cols-2" aria-label="Section navigation">
            {prev ? (
              <Link to={href(prev.slug)} className="panel group p-4 transition hover:border-accent/40">
                <span className="inline-flex items-center gap-1.5 font-mono text-[0.68rem] uppercase tracking-[0.14em] text-faint">
                  <ArrowLeft size={12} aria-hidden="true" />
                  Previous
                </span>
                <span className="mt-1.5 block font-semibold text-ink">{prev.title}</span>
              </Link>
            ) : (
              <span aria-hidden="true" />
            )}
            {next ? (
              <Link
                to={href(next.slug)}
                className="panel group p-4 text-right transition hover:border-accent/40 sm:col-start-2"
              >
                <span className="inline-flex items-center gap-1.5 font-mono text-[0.68rem] uppercase tracking-[0.14em] text-faint">
                  Next
                  <ArrowRight size={12} aria-hidden="true" />
                </span>
                <span className="mt-1.5 block font-semibold text-ink">{next.title}</span>
              </Link>
            ) : null}
          </nav>
        </article>
      </div>
    </div>
  );
}
