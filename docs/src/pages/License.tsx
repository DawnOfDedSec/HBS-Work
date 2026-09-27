export default function License() {
  return (
    <div className="mx-auto max-w-[900px] px-6 py-10">
      <p className="mono-label">License</p>
      <h1 className="mt-2 text-3xl font-extrabold text-white">Apache-2.0 with the Commons Clause</h1>
      <div className="mt-6 space-y-4 leading-[1.8] text-ink2">
        <p>
          HBS Tool is licensed under the <strong className="text-white">Apache License 2.0 with the
          Commons Clause</strong>, held by{' '}
          <a
            className="text-link hover:text-linkh"
            href="https://github.com/PotenFYR-Studios"
            target="_blank"
            rel="noopener noreferrer"
          >
            PotenFYR Studios
          </a>
          . The repository's{' '}
          <a
            className="text-link hover:text-linkh"
            href="https://github.com/PotenFYR-Studios/HBS-Tool/blob/main/LICENSE"
            target="_blank"
            rel="noopener noreferrer"
          >
            LICENSE
          </a>{' '}
          file is authoritative - this page is a plain-language summary, not legal advice.
        </p>
        <div
          className="rounded-xl px-5 py-4 text-sm text-ink2"
          style={{ borderLeft: '3px solid rgba(139, 92, 246, 0.45)', background: 'rgba(139, 92, 246, 0.08)' }}
        >
          <span className="mono-label mr-2" style={{ color: '#d8ccfe' }}>
            In short
          </span>
          You are free to fork, modify, and use HBS Tool for free, for any purpose - including
          commercial use, and building products or services around it. You may NOT sell the software
          itself (or a product or service whose value derives entirely or substantially from its
          functionality) as a paid product.
        </div>
        <p>
          Commons Clause is a narrow condition on top of Apache-2.0, not a switch to a non-free
          license: every Apache-2.0 grant (use, modification, distribution, patent grant,
          contributions) applies exactly as written. Only reselling the software itself is off
          limits. Internal use at your company, client engagements where HBS is a tool rather than
          the product being sold, and commercial derivatives that add their own value all remain
          fully permitted.
        </p>
        <p>
          See{' '}
          <a
            className="text-link hover:text-linkh"
            href="https://github.com/PotenFYR-Studios/HBS-Tool/blob/main/NOTICE.md"
            target="_blank"
            rel="noopener noreferrer"
          >
            NOTICE.md
          </a>{' '}
          for attribution details: referenced standards (CIS Benchmarks, NIST SP 800-53, ISO/IEC
          27001, PCI-DSS) are the property of their publishers and are referenced for traceability,
          never redistributed. All product names, logos, brands and trademarks belong to their
          respective owners.
        </p>
      </div>
      <p className="mt-8 text-[0.85em] text-faint">
        Questions about licensing? Reach the maintainers via{' '}
        <a
          className="text-link hover:text-linkh"
          href="https://github.com/PotenFYR-Studios/HBS-Tool/issues"
          target="_blank"
          rel="noopener noreferrer"
        >
          GitHub issues
        </a>{' '}
        or{' '}
        <a className="text-link hover:text-linkh" href="https://potenfyr.in" target="_blank" rel="noopener noreferrer">
          potenfyr.in
        </a>
        .
      </p>
    </div>
  );
}
