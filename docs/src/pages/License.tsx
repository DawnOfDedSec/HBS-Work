import Note from '../components/ui/Note';

const TERMS: Array<[string, string, string]> = [
  ['Fork, modify, self-host', 'Allowed', 'Apache-2.0 grants apply exactly as written.'],
  ['Commercial use inside your company', 'Allowed', 'Internal use is not resale.'],
  ['Client engagements using HBS as a tool', 'Allowed', 'HBS is not the product being sold.'],
  ['Derivatives that add their own value', 'Allowed', 'Additive products are fine.'],
  ['Selling the software itself', 'Not allowed', 'The Commons Clause restricts resale of the software.'],
];

export default function License() {
  return (
    <div className="mx-auto max-w-[900px] px-6 py-10">
      <header className="border-b border-hairline pb-6">
        <p className="mono-label">License</p>
        <h1 className="mt-3 text-[clamp(1.7rem,3.4vw,2.4rem)] font-bold">
          Apache-2.0 with the Commons Clause
        </h1>
        <p className="mt-4 leading-[1.8] text-ink2">
          HBS Tool is licensed under the{' '}
          <strong className="font-semibold text-ink">
            Apache License 2.0 with the Commons Clause
          </strong>
          , held by{' '}
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
      </header>

      <div className="mt-8">
        <Note tone="info" label="In short">
          You are free to fork, modify and use HBS Tool for free, for any purpose - including
          commercial use, and building products or services around it. You may NOT sell the software
          itself (or a product or service whose value derives entirely or substantially from its
          functionality) as a paid product.
        </Note>
      </div>

      <section className="mt-8">
        <p className="section-num">01</p>
        <h2 className="mt-2 text-[1.2rem] font-bold">What that means in practice</h2>
        <div className="mt-5 overflow-x-auto">
          <table className="spec-table">
            <caption className="sr-only">Permitted and restricted uses under Apache-2.0 with the Commons Clause</caption>
            <thead>
              <tr>
                <th scope="col">Use</th>
                <th scope="col">Status</th>
                <th scope="col">Why</th>
              </tr>
            </thead>
            <tbody>
              {TERMS.map(([use, status, why]) => (
                <tr key={use}>
                  <td className="text-ink">{use}</td>
                  <td className={status === 'Allowed' ? 'font-mono text-[0.8rem] text-ok' : 'font-mono text-[0.8rem] text-deny'}>
                    {status}
                  </td>
                  <td className="text-faint">{why}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="mt-10 space-y-4 leading-[1.8] text-ink2">
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
      </section>

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
        <a
          className="text-link hover:text-linkh"
          href="https://potenfyr.in"
          target="_blank"
          rel="noopener noreferrer"
        >
          potenfyr.in
        </a>
        .
      </p>
    </div>
  );
}
