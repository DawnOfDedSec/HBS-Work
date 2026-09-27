import {
  Crosshair,
  FileLock2,
  KeyRound,
  LayoutDashboard,
  MonitorCheck,
  ShieldOff,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

type Stage = {
  n: string;
  label: string;
  detail: string;
  icon: LucideIcon;
  /** the file produced on the target host, rendered as a monospace fact */
  fact?: string;
};

const STAGES: Stage[] = [
  {
    n: '01',
    label: 'Campaign',
    detail: 'Scope, location and cadence. One extractor per issuance, never a shared key.',
    icon: Crosshair,
  },
  {
    n: '02',
    label: 'Issuance',
    detail: 'A per-issuance X25519 public key is patched into the extractor keyslot.',
    icon: KeyRound,
  },
  {
    n: '03',
    label: 'Target host',
    detail: 'Strictly read-only scan against 368 testcases. No network, unprivileged.',
    icon: MonitorCheck,
  },
  {
    n: '04',
    label: 'Sealed report',
    detail: 'One file appears beside the binary. It is the only write the tool ever makes.',
    icon: FileLock2,
    fact: 'hbs-report-*.hbs',
  },
  {
    n: '05',
    label: 'Dashboard',
    detail: 'Decrypt, verify, route by machine-id, then remediate and export.',
    icon: LayoutDashboard,
  },
];

/**
 * The pipeline diagram: the product's central claim, drawn as the thing itself
 * rather than asserted in a paragraph. Mobile stacks it into a vertical
 * timeline with static connectors; from md up the connectors animate a packet
 * of light travelling the route.
 */
export default function Pipeline() {
  return (
    <div role="group" aria-label="Sealed report pipeline, from issuance to reviewed report">
      {/* mobile: vertical timeline */}
      <div className="flex flex-col md:hidden">
        {STAGES.map((s, i) => (
          <div key={s.n}>
            <StageNode stage={s} />
            {i < STAGES.length - 2 ? (
              <div
                aria-hidden="true"
                className="ml-[19px] h-7 w-[2px] bg-gradient-to-b from-accent/40 to-accent-2/40"
              />
            ) : i === STAGES.length - 2 ? (
              <AirGap vertical />
            ) : null}
          </div>
        ))}
      </div>

      {/* md and up: horizontal rail */}
      <div className="hidden items-stretch gap-3 md:flex">
        {STAGES.map((s, i) => (
          <div key={s.n} className="flex min-w-0 flex-1 items-center gap-3">
            <StageNode stage={s} />
            {i < STAGES.length - 2 ? (
              <span aria-hidden="true" className="rail w-8 shrink-0 lg:w-12" />
            ) : i === STAGES.length - 2 ? (
              <AirGap />
            ) : null}
          </div>
        ))}
      </div>
    </div>
  );
}

function StageNode({ stage }: { stage: Stage }) {
  const Icon = stage.icon;
  return (
    <div className="panel min-w-0 flex-1 p-4">
      <div className="flex items-center gap-2.5">
        <span className="icon-tile !h-8 !w-8 shrink-0">
          <Icon size={16} aria-hidden="true" />
        </span>
        <span className="section-num">{stage.n}</span>
      </div>
      <p className="mt-3 font-semibold text-ink">{stage.label}</p>
      <p className="mt-1 text-[0.82rem] leading-relaxed text-muted">{stage.detail}</p>
      {stage.fact ? (
        <p className="mt-2 font-mono text-[0.72rem] text-link">{stage.fact}</p>
      ) : null}
    </div>
  );
}

/**
 * The air gap is the point of the product, so it is drawn as a boundary the
 * rail cannot cross rather than a connector between two boxes.
 */
function AirGap({ vertical = false }: { vertical?: boolean }) {
  return (
    <div
      className={
        vertical
          ? 'relative ml-[19px] flex h-16 w-[2px] flex-col items-start justify-center border-x border-dashed border-link/50'
          : 'relative flex h-full w-10 shrink-0 flex-col items-center justify-center border-x border-dashed border-link/50 lg:w-14'
      }
    >
      <span className="absolute left-1/2 top-1/2 flex -translate-x-1/2 -translate-y-1/2 items-center gap-1.5 whitespace-nowrap rounded-full border border-link/40 bg-surface px-2 py-1 font-mono text-[0.6rem] uppercase tracking-[0.14em] text-link">
        <ShieldOff size={11} aria-hidden="true" />
        air gap
      </span>
    </div>
  );
}
