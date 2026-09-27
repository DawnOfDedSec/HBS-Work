import { Link } from 'react-router-dom';
import Code from '../components/Code';

const STATS = [
  { value: '368', label: 'hardening testcases' },
  { value: '2', label: 'platforms: Linux + Windows' },
  { value: '0', label: 'bytes written except the report' },
  { value: 'HBS2', label: 'sealed report envelope' },
];

const FEATURES = [
  {
    icon: '🔒',
    title: 'Sealed reports',
    text: 'Every scan produces a single .hbs file — an AEAD envelope (X25519 + ChaCha20-Poly1305/AES-256-GCM) that only the issuing dashboard can decrypt. The entire header is authenticated as AAD.',
  },
  {
    icon: '📖',
    title: 'Strictly read-only',
    text: 'Only allowlisted query commands run; state-changing or network-capable probes are rejected before spawn. DNS/remote forms are refused. The one write on the target is the sealed report.',
  },
  {
    icon: '🔌',
    title: 'Air-gapped by default',
    text: 'The extractor touches no network unless you explicitly pass --push. Reports travel by USB drop or dashboard upload — the dashboard derives campaign and location from the issuance alone.',
  },
  {
    icon: '🧭',
    title: 'Every audience served',
    text: 'Executive one-pager for leadership, copyable remediation for sysadmins, pivots + evidence diffing for analysts, board-ready printable exports for management.',
  },
  {
    icon: '📏',
    title: 'Bounded and honest',
    text: 'Peak RSS < 200 MB, < 10 MB binary, exactly one disk write. Checks degrade to DegradedPartial with missingData — never false-pass, never silent Error.',
  },
  {
    icon: '🧪',
    title: 'Validated for real',
    text: '13-distro Linux sweep with --network none, Windows Server Core LTSC 2019/2022/2025 containers, native Windows matrices, cross-language crypto vectors.',
  },
];

export default function Home() {
  return (
    <div className="mx-auto max-w-[1280px] px-6">
      {/* hero (SPEC 5.4) */}
      <section className="relative flex flex-col items-center py-20 text-center">
        <p className="mono-label">PotenFYR Studios · configuration security</p>
        <h1 className="mt-4 max-w-[900px] text-4xl font-extrabold leading-[1.15] text-white md:text-6xl">
          Offline-first host baseline <span className="grad-text-vivid">security reviews</span>
        </h1>
        <p className="mt-6 max-w-[760px] text-[1.05em] leading-relaxed text-muted">
          HBS pairs a strictly read-only Rust extractor with a sealed-report dashboard: 368 hardening
          testcases across Linux and Windows, sealed .hbs reports only the issuing dashboard can
          decrypt, and executive-to-evidence consoles.
        </p>
        <div className="mt-9 flex flex-wrap items-center justify-center gap-4">
          <Link to="/docs" className="btn-primary">
            Read the docs
          </Link>
          <a
            href="https://github.com/PotenFYR-Studios/HBS-Tool"
            target="_blank"
            rel="noopener noreferrer"
            className="btn-ghost"
          >
            Star on GitHub ⭑
          </a>
        </div>
        <div className="mt-12 grid w-full max-w-[900px] grid-cols-2 gap-3 md:grid-cols-4">
          {STATS.map((s) => (
            <div key={s.label} className="stat-tile">
              <p className="grad-text font-mono text-3xl font-extrabold">{s.value}</p>
              <p className="mt-1 text-[0.75em] text-muted">{s.label}</p>
            </div>
          ))}
        </div>
      </section>

      {/* quick taste */}
      <section className="grid items-start gap-6 py-10 md:grid-cols-2">
        <div>
          <p className="mono-label">Two commands, whole fleet</p>
          <h2 className="mt-3 text-2xl font-bold text-white">Issue. Scan. Seal. Review.</h2>
          <p className="mt-3 leading-relaxed text-muted">
            The dashboard patches a per-issuance X25519 public key into the extractor keyslot. On the
            target, the extractor scans unprivileged and writes one sealed report beside itself. Upload
            it — or let --push deliver it. Everything else is automatic.
          </p>
          <div className="mt-5 flex flex-wrap gap-3">
            <Link to="/docs/getting-started" className="btn-ghost">
              Getting started
            </Link>
            <Link to="/docs/security-model" className="btn-ghost">
              Security model
            </Link>
          </div>
        </div>
        <Code
          lang="bash"
          title="target host (offline, unprivileged)"
          content={`# run the issued extractor on the target — no network
./hbs-extractor --no-elevate --quiet

# hbs-report-*.hbs appears beside the binary: the only
# file the tool ever writes. Deliver it by USB drop,
# dashboard upload, or optional --push.`}
        />
      </section>

      {/* feature cards (SPEC 5.5) */}
      <section className="py-10">
        <p className="mono-label">Why HBS</p>
        <h2 className="mt-3 text-2xl font-bold text-white md:text-3xl">
          Built like evidence, not like a scanner
        </h2>
        <div className="mt-8 grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {FEATURES.map((f) => (
            <div key={f.title} className="glass-card">
              <div className="icon-tile">{f.icon}</div>
              <h3 className="text-[1.02em] font-bold text-white">{f.title}</h3>
              <p className="text-[0.85em] leading-relaxed text-muted">{f.text}</p>
            </div>
          ))}
        </div>
      </section>

      {/* audiences */}
      <section className="py-10">
        <p className="mono-label">Four audiences, one console</p>
        <div className="mt-6 grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {[
            ['Security leadership', 'Executive one-pager, risk gauge, plain-language narrative, presentation mode.'],
            ['System administrators', 'Actionable remediation grouped into action items with copyable fix commands.'],
            ['Cyber analysts', 'Pivots, evidence blocks, host/report diffing, telemetry percentiles.'],
            ['Upper management', 'Board-ready reporting and printable deliverables (PDF, Excel, Word).'],
          ].map(([t, d]) => (
            <div key={t} className="glass-card">
              <h3 className="text-[0.95em] font-bold text-white">{t}</h3>
              <p className="text-[0.84em] leading-relaxed text-muted">{d}</p>
            </div>
          ))}
        </div>
      </section>

      {/* bottom CTA */}
      <section className="py-14 text-center">
        <h2 className="text-2xl font-bold text-white md:text-3xl">
          Ready to run your first <span className="grad-text">sealed scan</span>?
        </h2>
        <p className="mx-auto mt-3 max-w-[560px] text-muted">
          The dashboard runs on your machine; the extractor runs on theirs — and never phones home.
        </p>
        <div className="mt-7 flex justify-center">
          <Link to="/docs/getting-started" className="btn-primary">
            Get started in minutes
          </Link>
        </div>
      </section>
    </div>
  );
}
