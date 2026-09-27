import { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  ArrowRight,
  BadgeCheck,
  BookOpen,
  Boxes,
  FileLock2,
  Gauge,
  GitFork,
  KeyRound,
  Layers,
  Network,
  Regex,
  ScrollText,
  ShieldCheck,
  ShieldOff,
  Users,
  WifiOff,
} from 'lucide-react';
import Marquee from '../components/ui/Marquee';
import NumberTicker from '../components/ui/NumberTicker';
import Pipeline from '../components/ui/Pipeline';
import Reveal from '../components/ui/Reveal';
import Tabs from '../components/ui/Tabs';
import Terminal from '../components/ui/Terminal';

const READOUT = [
  { value: 368, label: 'hardening testcases' },
  { value: 2, label: 'platform families' },
  { value: 1, label: 'disk write, total' },
  { value: 13, label: 'distro versions tested' },
];

const ENVELOPE: Array<[string, string]> = [
  ['format', 'HBS2'],
  ['key agreement', 'X25519'],
  ['AEAD', 'ChaCha20-Poly1305 / AES-256-GCM'],
  ['header', 'authenticated as AAD'],
  ['scan mode', 'read-only · unprivileged'],
  ['network', 'none'],
];

const STANDARDS = [
  'CIS Benchmarks',
  'NIST SP 800-53',
  'ISO/IEC 27001',
  'PCI-DSS',
  'kernel ≥ 3.10',
  'bare metal',
  'VM',
  'container',
  'WSL',
];

const PLATFORMS = [
  'Debian 12',
  'Ubuntu 24.04',
  'Rocky 9',
  'AlmaLinux',
  'CentOS',
  'SUSE',
  'Arch',
  'Alpine 3.20',
  'Amazon Linux',
  'Windows 10/11',
  'Server 2016–2025',
  'Server Core LTSC 2019/2022/2025',
  'x86_64 · aarch64 · armv7',
];

const ALLOWED = [
  'Allowlisted read-only query commands',
  'Unprivileged execution, no elevation required',
];

const REFUSED = [
  'State-changing commands, rejected before spawn',
  'Network-capable probes and DNS/remote forms, refused',
  'Temp exports, package installs, service restarts',
];

const ROLES = [
  {
    value: 'leadership',
    label: 'Leadership',
    icon: <Gauge size={15} aria-hidden="true" />,
    title: 'A one-pager you can hand over the same day',
    body: 'An executive summary with a risk gauge, a plain-language narrative of what changed, and a presentation mode that strips the console chrome for a projector or a screen share.',
    facts: ['Executive one-pager', 'Risk gauge and narrative', 'Presentation mode'],
  },
  {
    value: 'sysadmin',
    label: 'Sysadmins',
    icon: <ShieldCheck size={15} aria-hidden="true" />,
    title: 'Fixes you can copy, not a PDF to interpret',
    body: 'Findings group into remediation action items. Each carries the evidence block it came from and the exact command or configuration change that closes it.',
    facts: ['Action items with fixes', 'Copyable commands', 'Grouped by host and check'],
  },
  {
    value: 'analyst',
    label: 'Analysts',
    icon: <Regex size={15} aria-hidden="true" />,
    title: 'Pivots, evidence, and diffs between two scans',
    body: 'Drill from a fleet score to one check on one host, open the raw evidence a result came from, and diff two reports of the same machine to see exactly what moved.',
    facts: ['Pivots to raw evidence', 'Host and report diffing', 'Telemetry percentiles'],
  },
  {
    value: 'management',
    label: 'Management',
    icon: <ScrollText size={15} aria-hidden="true" />,
    title: 'Board-ready deliverables, printable',
    body: 'Exports arrive as PDF, Excel and Word with branding, timestamps and provenance intact, so a review drops into a governance pack without being retyped.',
    facts: ['PDF · Excel · Word', 'Print-styled layouts', 'Provenance preserved'],
  },
] as const;

type RoleValue = (typeof ROLES)[number]['value'];

const CAPABILITIES = [
  {
    icon: FileLock2,
    title: 'Sealed reports',
    body: 'A scan produces one .hbs file: an AEAD envelope whose header is authenticated as additional data, so campaign, location and issuance cannot be edited without breaking it.',
    points: ['Per-issuance X25519 key', 'AEAD, authenticated header', 'Only the issuing dashboard decrypts'],
  },
  {
    icon: ShieldOff,
    title: 'Strictly read-only',
    body: 'Only allowlisted query commands are ever spawned. Anything that could change state or reach the network is rejected before it runs.',
    points: [],
  },
  {
    icon: WifiOff,
    title: 'Air-gapped by default',
    body: 'The extractor touches no network unless you explicitly pass --push. A report travels by USB drop or a dashboard upload.',
    points: [],
  },
  {
    icon: Gauge,
    title: 'Bounded, and honest about it',
    body: 'Peak RSS under 200 MB, a binary under 10 MB, exactly one write to the target disk. A control that cannot exist in the environment reports NotApplicable with a reason instead of failing.',
    points: [],
  },
  {
    icon: Boxes,
    title: 'Validated, not just built',
    body: 'A 13-distro Linux sweep with --network none, Windows Server Core LTSC containers, native Windows matrices, and cross-language crypto vectors shared by the Rust and TypeScript sides.',
    points: [],
  },
];

const BUDGETS: Array<[string, string, string]> = [
  ['Peak RSS', '< 200 MB (typically 20–40 MB)', 'bounded 1 MiB reads, streaming JSON'],
  ['Binary size', '< 10 MB (expected 5–8 MB)', 'static musl, opt-level=z, LTO, strip, CI gate'],
  ['CPU', '< 0.5 core sustained', 'sequential checks, ≤ 2 workers, 2–5 s timeouts, lowered priority'],
  ['Target disk writes', 'exactly 1', 'sealed report only; no temp exports'],
  ['Target network', 'none by default', 'no egress unless --push is passed explicitly'],
];

const ONWARD = [
  {
    to: '/docs',
    icon: BookOpen,
    title: 'Documentation',
    body: 'Install, issue, scan, review: everything from zero to a reviewed report.',
  },
  {
    to: '/docs/security-model',
    icon: ShieldCheck,
    title: 'Security model',
    body: 'The sealed envelope, the read-only guarantee, and what HBS deliberately does not claim.',
  },
  {
    to: '/examples',
    icon: Network,
    title: 'Example workflows',
    body: 'Offline scans, air-gapped push, filtered re-scans, Windows CI runs and batch uploads.',
  },
];

export default function Home() {
  const [role, setRole] = useState<RoleValue>('leadership');
  const active = ROLES.find((r) => r.value === role) ?? ROLES[0];

  return (
    <div className="mx-auto max-w-[1280px] px-6">
      {/* ----------------------------------------------------------------
          Hero. The sealed report is the hero object; the headline is plain
          text, because a gradient-filled headline is the house style of every
          generated landing page and this product's argument is a file format.
      ----------------------------------------------------------------- */}
      <section className="grid items-center gap-12 py-14 lg:grid-cols-[1.02fr_0.98fr] lg:py-20">
        <Reveal>
          <p className="mono-label">PotenFYR Studios · configuration security</p>
          <h1 className="mt-4 text-[clamp(2.1rem,4.6vw,3.5rem)] font-bold leading-[1.08]">
            Offline-first host baseline security reviews
          </h1>
          <p className="mt-5 max-w-[560px] text-[1.02rem] leading-relaxed text-muted">
            HBS pairs a strictly read-only Rust extractor with a sealed-report dashboard. 368
            hardening testcases run against Linux and Windows servers, and the only thing that
            leaves the machine is one encrypted report that only the issuing dashboard can open.
          </p>

          <div className="mt-8 flex flex-wrap items-center gap-3">
            <Link to="/docs/getting-started" className="btn-primary">
              Read the getting-started guide
              <ArrowRight size={16} aria-hidden="true" />
            </Link>
            <a
              href="https://github.com/PotenFYR-Studios/HBS-Tool"
              target="_blank"
              rel="noopener noreferrer"
              className="btn-ghost"
            >
              <GitFork size={16} aria-hidden="true" />
              View the repository
            </a>
          </div>

          {/* a readout strip, not four identical stat tiles */}
          <dl className="mt-10 grid max-w-[620px] grid-cols-2 gap-y-6 border-t border-hairline pt-6 sm:grid-cols-4">
            {READOUT.map((r, i) => (
              <div key={r.label} className={i > 0 ? 'sm:border-l sm:border-hairline sm:pl-4' : ''}>
                <dt className="mono-label">{r.label}</dt>
                <dd className="stat-num mt-1.5">
                  <NumberTicker value={r.value} />
                </dd>
              </div>
            ))}
          </dl>
        </Reveal>

        <Reveal delay={120}>
          <figure className="artifact">
            <figcaption className="flex items-center gap-2.5 border-b border-hairline px-4 py-3">
              <FileLock2 size={15} className="shrink-0 text-link" aria-hidden="true" />
              <span className="min-w-0 flex-1 truncate text-[0.78rem] text-ink2">
                hbs-report-ubuntu-24.04.hbs
              </span>
              <span className="inline-flex items-center gap-1 rounded-full border border-link/40 bg-accent/10 px-2 py-0.5 text-[0.6rem] uppercase tracking-[0.12em] text-link">
                <BadgeCheck size={11} aria-hidden="true" />
                sealed
              </span>
            </figcaption>

            <dl className="divide-y divide-hairline px-4">
              {ENVELOPE.map(([k, v]) => (
                <div key={k} className="flex items-baseline justify-between gap-4 py-2.5">
                  <dt className="text-[0.72rem] uppercase tracking-[0.1em] text-faint">{k}</dt>
                  <dd className="text-right text-[0.78rem] text-ink2">{v}</dd>
                </div>
              ))}
            </dl>

            <p className="flex items-start gap-2 border-t border-hairline px-4 py-3 text-[0.72rem] leading-relaxed text-muted">
              <KeyRound size={13} className="mt-0.5 shrink-0 text-link" aria-hidden="true" />
              Decryptable by the issuing dashboard alone. Lose the key and the report is gone.
            </p>
          </figure>
        </Reveal>
      </section>

      {/* 01 · the pipeline */}
      <section className="border-t border-hairline py-14">
        <Reveal>
          <div className="flex flex-wrap items-end justify-between gap-4">
            <div className="max-w-[620px]">
              <p className="section-num">01</p>
              <h2 className="mt-2 text-[clamp(1.4rem,2.4vw,1.9rem)] font-bold">
                How a scan becomes evidence
              </h2>
              <p className="mt-3 leading-relaxed text-muted">
                Nothing about the review lives on the target host except the report itself. The
                dashboard derives campaign and location from the issuance, so a host that moves
                between sites still routes to the right place.
              </p>
            </div>
            <Link to="/docs/security-model" className="btn-quiet">
              Security model
              <ArrowRight size={14} aria-hidden="true" />
            </Link>
          </div>
          <div className="mt-8">
            <Pipeline />
          </div>
        </Reveal>
      </section>

      {/* 02 · coverage */}
      <section className="border-t border-hairline py-14">
        <div>
          <p className="section-num">02</p>
          <h2 className="mt-2 text-[clamp(1.4rem,2.4vw,1.9rem)] font-bold">What it runs against</h2>
          <p className="mt-3 max-w-[680px] leading-relaxed text-muted">
            Testcases map to baselines auditors already ask for, and the sweep covers the
            distributions and Windows builds an enterprise fleet actually contains.
          </p>
        </div>
        <div className="mt-7 space-y-3">
          <Marquee label="Baselines and environments covered" speed={34}>
            {STANDARDS.map((s) => (
              <span key={s} className="chip">
                <span className="chip-mark" aria-hidden="true">
                  ▪
                </span>
                {s}
              </span>
            ))}
          </Marquee>
          <Marquee label="Platforms tested" speed={42} reverse>
            {PLATFORMS.map((p) => (
              <span key={p} className="chip">
                {p}
              </span>
            ))}
          </Marquee>
        </div>
      </section>

      {/* 03 · capabilities, deliberately unequal in weight */}
      <section className="border-t border-hairline py-14">
        <div>
          <p className="section-num">03</p>
          <h2 className="mt-2 text-[clamp(1.4rem,2.4vw,1.9rem)] font-bold">
            What makes the output auditable
          </h2>
        </div>

        <div className="mt-8 grid gap-4 lg:grid-cols-3">
          <div className="lg:col-span-2">
            <article className="beam-card h-full p-6">
              <span className="icon-tile">
                <FileLock2 size={18} aria-hidden="true" />
              </span>
              <h3 className="mt-4 text-lg font-bold">{CAPABILITIES[0].title}</h3>
              <p className="mt-2 max-w-[620px] leading-relaxed text-muted">{CAPABILITIES[0].body}</p>
              <ul className="mt-5 grid gap-2 sm:grid-cols-3">
                {CAPABILITIES[0].points.map((p) => (
                  <li
                    key={p}
                    className="panel-inset flex items-start gap-2 px-3 py-2.5 text-[0.78rem] text-ink2"
                  >
                    <KeyRound size={13} className="mt-0.5 shrink-0 text-link" aria-hidden="true" />
                    {p}
                  </li>
                ))}
              </ul>
            </article>
          </div>

          <div>
            <article className="panel h-full p-6">
              <span className="icon-tile">
                <ShieldOff size={18} aria-hidden="true" />
              </span>
              <h3 className="mt-4 text-lg font-bold">{CAPABILITIES[1].title}</h3>
              <p className="mt-2 leading-relaxed text-muted">{CAPABILITIES[1].body}</p>
              <ul className="mt-5 space-y-2">
                {ALLOWED.map((a) => (
                  <li key={a} className="flex items-start gap-2 text-[0.8rem] text-ink2">
                    <BadgeCheck size={14} className="mt-0.5 shrink-0 text-ok" aria-hidden="true" />
                    {a}
                  </li>
                ))}
                {REFUSED.map((r) => (
                  <li key={r} className="flex items-start gap-2 text-[0.8rem] text-muted">
                    <ShieldOff size={14} className="mt-0.5 shrink-0 text-deny" aria-hidden="true" />
                    {r}
                  </li>
                ))}
              </ul>
            </article>
          </div>

          {CAPABILITIES.slice(2).map((c, i) => {
            const Icon = c.icon;
            return (
              <div key={c.title}>
                <article className="panel h-full p-6">
                  <span className="icon-tile">
                    <Icon size={18} aria-hidden="true" />
                  </span>
                  <h3 className="mt-4 text-lg font-bold">{c.title}</h3>
                  <p className="mt-2 leading-relaxed text-muted">{c.body}</p>
                </article>
              </div>
            );
          })}
        </div>
      </section>

      {/* 04 · audiences as a switcher rather than four identical cards */}
      <section className="border-t border-hairline py-14">
        <div>
          <p className="section-num">04</p>
          <h2 className="mt-2 text-[clamp(1.4rem,2.4vw,1.9rem)] font-bold">
            One console, four audiences
          </h2>
        </div>
        <div>
          <div className="mt-7">
            <Tabs
              items={ROLES.map((r) => ({ value: r.value, label: r.label, icon: r.icon }))}
              value={role}
              onChange={setRole}
              label="Choose your role"
              idBase="role"
            >
              <div className="panel grid gap-6 p-6 md:grid-cols-[1.2fr_0.8fr] md:p-7">
                <div>
                  <h3 className="text-lg font-bold">{active.title}</h3>
                  <p className="mt-2.5 leading-relaxed text-muted">{active.body}</p>
                </div>
                <ul className="space-y-2">
                  {active.facts.map((f) => (
                    <li
                      key={f}
                      className="panel-inset flex items-center gap-2.5 px-3.5 py-2.5 text-[0.82rem] text-ink2"
                    >
                      <Users size={14} className="shrink-0 text-link" aria-hidden="true" />
                      {f}
                    </li>
                  ))}
                </ul>
              </div>
            </Tabs>
          </div>
        </div>
      </section>

      {/* 05 · budgets as the site's own spec table */}
      <section className="border-t border-hairline py-14">
        <div>
          <p className="section-num">05</p>
          <h2 className="mt-2 text-[clamp(1.4rem,2.4vw,1.9rem)] font-bold">Bounded by design</h2>
          <p className="mt-3 max-w-[680px] leading-relaxed text-muted">
            Resource limits are part of the contract rather than aspirations: each row is enforced
            in code and gated in CI.
          </p>
        </div>
        <div>
          <div className="mt-7 overflow-x-auto">
            <table className="spec-table">
              <caption className="sr-only">HBS resource budgets and how each is enforced</caption>
              <thead>
                <tr>
                  <th scope="col">Metric</th>
                  <th scope="col">Budget</th>
                  <th scope="col">Enforced by</th>
                </tr>
              </thead>
              <tbody>
                {BUDGETS.map(([metric, budget, how]) => (
                  <tr key={metric}>
                    <td className="font-mono text-[0.8rem] text-ink">{metric}</td>
                    <td>{budget}</td>
                    <td className="text-faint">{how}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* 06 · start, then the three ways onward */}
      <section className="border-t border-hairline py-14">
        <div className="grid items-start gap-8 lg:grid-cols-[0.95fr_1.05fr]">
          <div>
            <p className="section-num">06</p>
            <h2 className="mt-2 text-[clamp(1.4rem,2.4vw,1.9rem)] font-bold">
              Two commands, whole fleet
            </h2>
            <p className="mt-3 leading-relaxed text-muted">
              Install the dashboard where you manage scans from. It keeps everything local and
              serves on <code className="inline">http://127.0.0.1:3000</code>. Extractor binaries
              are issued per campaign and location, so nothing is shared between engagements.
            </p>
            <div className="mt-6 flex flex-wrap gap-3">
              <Link to="/docs/getting-started" className="btn-primary">
                Start the walkthrough
                <ArrowRight size={16} aria-hidden="true" />
              </Link>
              <Link to="/examples" className="btn-ghost">
                <Layers size={16} aria-hidden="true" />
                Example workflows
              </Link>
            </div>
          </div>
          <div>
            <Terminal
              title="dashboard host"
              lines={[
                '# Linux / macOS',
                'curl -fsSL https://raw.githubusercontent.com/PotenFYR-Studios/HBS-Tool/main/scripts/install.sh | bash',
                '',
                '# Windows (PowerShell)',
                'irm https://raw.githubusercontent.com/PotenFYR-Studios/HBS-Tool/main/scripts/install.ps1 | iex',
              ]}
            />
          </div>
        </div>

        <div className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {ONWARD.map((c) => {
            const Icon = c.icon;
            return (
              <Link
                key={c.title}
                to={c.to}
                className="panel group p-5 transition hover:border-accent/40"
              >
                <div className="flex items-center gap-2.5">
                  <Icon size={16} className="text-link" aria-hidden="true" />
                  <h3 className="text-[0.95rem] font-bold">{c.title}</h3>
                </div>
                <p className="mt-2 text-[0.84rem] leading-relaxed text-muted">{c.body}</p>
                <span className="mt-3 inline-flex items-center gap-1 font-mono text-[0.7rem] text-faint">
                  open
                  <ArrowRight
                    size={12}
                    className="transition group-hover:translate-x-0.5"
                    aria-hidden="true"
                  />
                </span>
              </Link>
            );
          })}
        </div>
      </section>
    </div>
  );
}
