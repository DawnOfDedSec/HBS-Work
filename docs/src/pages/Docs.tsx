import { useEffect } from 'react';
import { Link, NavLink, useParams } from 'react-router-dom';
import { DOC_SECTIONS } from '../docs/content';
import { Block } from '../components/DocBlocks';

export default function Docs() {
  const { section } = useParams();
  const active = DOC_SECTIONS.find((s) => s.slug === section) ?? DOC_SECTIONS[0];

  useEffect(() => {
    window.scrollTo(0, 0);
  }, [active.slug]);

  return (
    <div className="mx-auto max-w-[1280px] px-6 py-10">
      <p className="mono-label">Documentation</p>
      <h1 className="mt-2 text-3xl font-extrabold text-white">
        {active.title}
      </h1>
      <p className="mt-2 max-w-[720px] text-muted">{active.blurb}</p>

      <div className="mt-8 flex flex-col gap-8 md:flex-row">
        {/* sidebar (SPEC 5.9) */}
        <aside className="md:w-56 md:shrink-0">
          <nav className="flex flex-row flex-wrap gap-1 md:flex-col" aria-label="Docs sections">
            {DOC_SECTIONS.map((s) => (
              <NavLink
                key={s.slug}
                to={s.slug === DOC_SECTIONS[0].slug ? '/docs' : `/docs/${s.slug}`}
                end
                className={({ isActive }) =>
                  'rounded-lg px-3 py-2 text-[0.86em] transition ' +
                  (isActive || s.slug === active.slug
                    ? 'bg-white/[0.06] font-semibold text-white'
                    : 'text-muted hover:bg-white/5 hover:text-white')
                }
                style={
                  s.slug === active.slug
                    ? { boxShadow: 'inset 2px 0 0 #8b5cf6' }
                    : undefined
                }
              >
                {s.title}
              </NavLink>
            ))}
          </nav>
          <div className="mt-6 hidden rounded-xl border border-white/[0.08] bg-white/[0.02] p-4 md:block">
            <p className="mono-label">Resources</p>
            <ul className="mt-2 space-y-1.5 text-[0.82em]">
              <li>
                <a className="text-link hover:text-linkh" href="https://github.com/PotenFYR-Studios/HBS-Tool/releases">
                  Releases &amp; installers
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

        {/* content (SPEC 5.10) */}
        <article className="min-w-0 flex-1 space-y-5 pb-16">
          {active.content.map((block, i) => (
            <Block key={i} block={block} />
          ))}

          {/* prev/next pager */}
          <div className="flex justify-between gap-4 pt-8">
            {(() => {
              const idx = DOC_SECTIONS.findIndex((s) => s.slug === active.slug);
              const prev = idx > 0 ? DOC_SECTIONS[idx - 1] : null;
              const next = idx < DOC_SECTIONS.length - 1 ? DOC_SECTIONS[idx + 1] : null;
              return (
                <>
                  {prev ? (
                    <Link
                      to={prev.slug === DOC_SECTIONS[0].slug ? '/docs' : `/docs/${prev.slug}`}
                      className="glass-card flex-1 !gap-0.5"
                    >
                      <span className="text-[0.72em] text-faint">← Previous</span>
                      <span className="text-[0.9em] font-semibold text-white">{prev.title}</span>
                    </Link>
                  ) : (
                    <span className="flex-1" />
                  )}
                  {next ? (
                    <Link to={`/docs/${next.slug}`} className="glass-card flex-1 items-end !gap-0.5 text-right">
                      <span className="text-[0.72em] text-faint">Next →</span>
                      <span className="text-[0.9em] font-semibold text-white">{next.title}</span>
                    </Link>
                  ) : (
                    <span className="flex-1" />
                  )}
                </>
              );
            })()}
          </div>
        </article>
      </div>
    </div>
  );
}
