import { Link } from 'react-router-dom';
import { Boxes, FileLock2, Handshake } from 'lucide-react';

const HALVES = [
  {
    icon: FileLock2,
    title: 'The extractor',
    body: 'A single static Rust binary that evaluates 368 hardening testcases on Linux and Windows, starts unprivileged, never touches the network by default, and writes exactly one file: a sealed .hbs report the issuing dashboard decrypts.',
  },
  {
    icon: Boxes,
    title: 'The dashboard',
    body: 'Bun + Hono + React. It issues one patched extractor per campaign and location, ingests sealed reports, routes hosts by machine-id, and serves consoles from executive one-pagers down to raw evidence pivots.',
  },
];

export default function About() {
  return (
    <div className="mx-auto max-w-[900px] px-6 py-10">
      <header className="border-b border-hairline pb-6">
        <p className="mono-label">About</p>
        <h1 className="mt-3 text-[clamp(1.7rem,3.4vw,2.4rem)] font-bold">HBS Tool</h1>
        <p className="mt-4 text-[1.02rem] leading-[1.8] text-ink2">
          <strong className="font-semibold text-ink">HBS</strong> (Host Baseline Security) is an
          offline-first, strictly read-only configuration-security review platform for enterprise
          servers, built by{' '}
          <a
            className="text-link hover:text-linkh"
            href="https://github.com/PotenFYR-Studios"
            target="_blank"
            rel="noopener noreferrer"
          >
            PotenFYR Studios
          </a>
          . It is built for four audiences: security leadership, system administrators, cyber
          analysts and upper management.
        </p>
      </header>

      <section className="mt-8">
        <p className="section-num">01</p>
        <h2 className="mt-2 text-[1.2rem] font-bold">Two halves, deliberately separate</h2>
        <div className="mt-5 grid gap-4 sm:grid-cols-2">
          {HALVES.map((h) => {
            const Icon = h.icon;
            return (
              <article key={h.title} className="panel p-5">
                <span className="icon-tile">
                  <Icon size={18} aria-hidden="true" />
                </span>
                <h3 className="mt-4 font-bold">{h.title}</h3>
                <p className="mt-2 text-[0.9rem] leading-[1.75] text-ink2">{h.body}</p>
              </article>
            );
          })}
        </div>
      </section>

      <section className="mt-10">
        <p className="section-num">02</p>
        <h2 className="mt-2 text-[1.2rem] font-bold">Open source, in an ecosystem</h2>
        <article className="panel mt-5 p-5">
          <span className="icon-tile">
            <Handshake size={18} aria-hidden="true" />
          </span>
          <p className="mt-4 text-[0.9rem] leading-[1.8] text-ink2">
            HBS is part of the PotenFYR Studios open-source ecosystem, alongside{' '}
            <a
              className="text-link hover:text-linkh"
              href="https://botlists.docs.potenfyr.in"
              target="_blank"
              rel="noopener noreferrer"
            >
              discord-botlists
            </a>
            ,{' '}
            <a
              className="text-link hover:text-linkh"
              href="https://statfyr.docs.potenfyr.in"
              target="_blank"
              rel="noopener noreferrer"
            >
              statfyr
            </a>{' '}
            and more at{' '}
            <a
              className="text-link hover:text-linkh"
              href="https://potenfyr.in"
              target="_blank"
              rel="noopener noreferrer"
            >
              potenfyr.in
            </a>
            . This documentation site is built from the repository's{' '}
            <code className="inline">docs/</code> directory and deployed to GitHub Pages; the
            README mirrors the same content.
          </p>
        </article>
      </section>

      <div className="mt-10 flex flex-wrap gap-3">
        <Link to="/docs" className="btn-primary">
          Read the docs
        </Link>
        <a
          href="https://github.com/PotenFYR-Studios/HBS-Tool"
          target="_blank"
          rel="noopener noreferrer"
          className="btn-ghost"
        >
          GitHub repository
        </a>
      </div>
    </div>
  );
}
