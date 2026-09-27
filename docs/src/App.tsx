import { useEffect, useState } from 'react';
import { Link, NavLink, Outlet, useLocation } from 'react-router-dom';
import { GitFork, MessageCircle, Globe, Menu, X } from 'lucide-react';

const NAV = [
  { to: '/', label: 'Home' },
  { to: '/docs', label: 'Docs' },
  { to: '/examples', label: 'Examples' },
  { to: '/about', label: 'About' },
];

const RIGHT_LINKS = [
  { href: 'https://potenfyr.in', label: 'Website', icon: Globe },
  { href: 'https://discord.com/invite/zUaN2FPBec', label: 'Discord', icon: MessageCircle },
  { href: 'https://github.com/PotenFYR-Studios/HBS-Tool', label: 'GitHub', icon: GitFork },
];

export default function App() {
  const [open, setOpen] = useState(false);
  const location = useLocation();

  // close the mobile drawer on navigation
  useEffect(() => {
    setOpen(false);
  }, [location.pathname]);

  return (
    <div className="relative min-h-screen">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-[60] focus:rounded-lg focus:bg-panel focus:px-4 focus:py-2 focus:text-ink"
      >
        Skip to content
      </a>

      {/* 56px sticky navbar (SPEC 5.1). The 2px rule on top is the brand mark:
          the vivid violet-pink-orange trio lives here and on the dot field,
          never behind text (it fails AA as a text background). */}
      <header
        className="sticky top-0 z-50 flex h-14 items-center gap-3.5 border-b border-hairline px-5"
        style={{ background: 'rgba(11, 13, 20, 0.72)', backdropFilter: 'blur(14px) saturate(1.4)' }}
      >
        <span
          aria-hidden="true"
          className="pointer-events-none absolute inset-x-0 top-0 h-[2px]"
          style={{ background: 'linear-gradient(90deg, #8b5cf6, #ec4899 55%, #f97316)' }}
        />

        <Link
          to="/"
          className="flex shrink-0 items-center gap-2.5 font-semibold text-ink"
          style={{ fontSize: '0.95em' }}
        >
          <img
            src="/favicon.png"
            alt=""
            className="h-6 w-6"
            style={{ filter: 'drop-shadow(0 0 8px rgba(139, 92, 246, 0.5))' }}
          />
          <span>
            hbs-tool<span className="brand-dot">.</span>
          </span>
        </Link>

        <nav className="hidden items-center gap-1 md:flex" aria-label="Primary">
          {NAV.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              end={n.to === '/'}
              className={({ isActive }) =>
                'rounded-[7px] px-2.5 py-[5px] text-[0.84em] font-medium transition ' +
                (isActive ? 'text-ink' : 'text-muted hover:bg-wash hover:text-ink')
              }
              style={({ isActive }) =>
                isActive
                  ? {
                      background: 'rgba(139, 92, 246, 0.18)',
                      boxShadow: 'inset 0 0 0 1px rgba(139, 92, 246, 0.45)',
                    }
                  : undefined
              }
            >
              {n.label}
            </NavLink>
          ))}
        </nav>

        <div className="ml-auto hidden items-center gap-4 md:flex">
          {RIGHT_LINKS.map((l) => {
            const Icon = l.icon;
            return (
              <a
                key={l.label}
                href={l.href}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 text-xs text-muted transition hover:text-link"
                aria-label={`${l.label} (opens in a new tab)`}
              >
                <Icon size={13} aria-hidden="true" />
                {l.label}
              </a>
            );
          })}
        </div>

        <button
          className="ml-auto inline-flex h-9 w-9 items-center justify-center rounded-lg border border-edge text-muted transition hover:text-ink md:hidden"
          onClick={() => setOpen(!open)}
          aria-label="Toggle navigation menu"
          aria-expanded={open}
          aria-controls="mobile-nav"
        >
          {open ? <X size={16} aria-hidden="true" /> : <Menu size={16} aria-hidden="true" />}
        </button>
      </header>

      {open ? (
        <div
          id="mobile-nav"
          className="fixed inset-x-0 top-14 z-40 border-b border-hairline px-4 pb-5 pt-3 md:hidden"
          style={{ background: 'rgba(11, 13, 20, 0.98)', backdropFilter: 'blur(14px)' }}
        >
          {NAV.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              end={n.to === '/'}
              className={({ isActive }) =>
                'block rounded-lg px-3 py-2.5 transition ' +
                (isActive ? 'bg-wash-strong font-semibold text-ink' : 'text-ink2 hover:bg-wash')
              }
            >
              {n.label}
            </NavLink>
          ))}
          <div className="mt-3 flex flex-wrap gap-x-4 gap-y-2 border-t border-hairline pt-3">
            {RIGHT_LINKS.map((l) => (
              <a
                key={l.label}
                href={l.href}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-muted hover:text-link"
              >
                {l.label}
              </a>
            ))}
          </div>
        </div>
      ) : null}

      <main id="main" className="relative z-[1]">
        <Outlet />
      </main>

      {/* full-bleed 3-zone footer (SPEC 5.2) */}
      <footer className="relative z-[1] border-t border-hairline" style={{ background: 'rgba(14, 17, 29, 0.6)' }}>
        <div className="mx-auto max-w-[1280px] px-6 py-10">
          <div className="flex flex-col justify-between gap-8 md:flex-row md:items-start">
            <div>
              <p className="font-mono text-sm font-bold text-ink">
                hbs-tool<span className="brand-dot">.</span>
              </p>
              <p className="mt-2 max-w-[420px] text-[0.8em] leading-relaxed text-muted">
                Offline-first, strictly read-only host baseline security reviews: 368 hardening
                testcases, sealed .hbs reports, executive-to-evidence dashboards.
              </p>
            </div>
            <nav className="flex flex-wrap gap-x-5 gap-y-2 font-mono text-[0.78em]" aria-label="Footer">
              <a
                href="https://github.com/PotenFYR-Studios"
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted transition hover:text-ink"
              >
                GitHub Org
              </a>
              <a
                href="https://potenfyr.in"
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted transition hover:text-ink"
              >
                potenfyr.in
              </a>
              <a
                href="https://discord.com/invite/zUaN2FPBec"
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted transition hover:text-ink"
              >
                Support Discord
              </a>
              <a
                href="https://github.com/PotenFYR-Studios/HBS-Tool/releases"
                target="_blank"
                rel="noopener noreferrer"
                className="text-muted transition hover:text-ink"
              >
                Releases
              </a>
              <Link to="/docs" className="text-link transition hover:text-linkh">
                Docs
              </Link>
              <Link to="/license" className="text-link transition hover:text-linkh">
                License
              </Link>
            </nav>
          </div>
          <div className="mt-6 flex flex-col justify-between gap-2 border-t border-hairline pt-4 text-[0.75em] text-faint sm:flex-row">
            <p>© 2026 PotenFYR Studios. Released under Apache-2.0 with the Commons Clause.</p>
            <p>
              Crafted with <span className="sr-only">love</span>
              <span aria-hidden="true">♥</span> for defenders.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
