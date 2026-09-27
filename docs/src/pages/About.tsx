import { Link } from 'react-router-dom';

export default function About() {
  return (
    <div className="mx-auto max-w-[900px] px-6 py-10">
      <p className="mono-label">About</p>
      <h1 className="mt-2 text-3xl font-extrabold text-white">HBS Tool</h1>
      <div className="mt-6 space-y-4 leading-[1.8] text-ink2">
        <p>
          <strong className="text-white">HBS</strong> (Host Baseline Security) is an offline-first,
          strictly read-only configuration-security review platform for enterprise servers, built by{' '}
          <a
            className="text-link hover:text-linkh"
            href="https://github.com/PotenFYR-Studios"
            target="_blank"
            rel="noopener noreferrer"
          >
            PotenFYR Studios
          </a>
          . It is built for four audiences: security leadership, system administrators, cyber
          analysts, and upper management.
        </p>
        <p>
          The two halves are deliberately separate. The <strong className="text-white">extractor</strong>{' '}
          is a single static Rust binary that evaluates 368 hardening testcases on Linux and Windows,
          starts unprivileged, never touches the network by default, and writes exactly one file: a
          sealed <code className="inline">.hbs</code> report the issuing dashboard decrypts. The{' '}
          <strong className="text-white">dashboard</strong> (Bun + Hono + React) issues one patched
          extractor per campaign/location, ingests sealed reports, routes hosts by machine-id, and
          serves consoles from executive one-pagers down to raw evidence pivots.
        </p>
        <p>
          HBS is part of the PotenFYR Studios open-source ecosystem, alongside{' '}
          <a className="text-link hover:text-linkh" href="https://botlists.docs.potenfyr.in" target="_blank" rel="noopener noreferrer">
            discord-botlists
          </a>
          ,{' '}
          <a className="text-link hover:text-linkh" href="https://statfyr.docs.potenfyr.in" target="_blank" rel="noopener noreferrer">
            statfyr
          </a>{' '}
          and more at{' '}
          <a className="text-link hover:text-linkh" href="https://potenfyr.in" target="_blank" rel="noopener noreferrer">
            potenfyr.in
          </a>
          .
        </p>
        <p>
          This documentation site is built from the repository's{' '}
          <code className="inline">docs/</code> directory and deployed to GitHub Pages. The README in
          the repository mirrors the same content.
        </p>
      </div>
      <div className="mt-8 flex flex-wrap gap-3">
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
