import type { ReactNode } from 'react';
import { Info, Lightbulb, TriangleAlert, type LucideIcon } from 'lucide-react';

export type NoteTone = 'info' | 'warn' | 'tip';

/**
 * One callout for the whole site. Previously the docs renderer and the license
 * page each carried their own inline border-left + rgba() colours, which is how
 * two copies of the same component drift apart.
 */
const TONES: Record<NoteTone, { icon: LucideIcon; label: string; className: string }> = {
  info: { icon: Info, label: 'Info', className: 'note-info' },
  warn: { icon: TriangleAlert, label: 'Note', className: 'note-warn' },
  tip: { icon: Lightbulb, label: 'Tip', className: 'note-tip' },
};

export default function Note({
  tone = 'info',
  children,
  label,
}: {
  tone?: NoteTone;
  children: ReactNode;
  label?: string;
}) {
  const { icon: Icon, label: defaultLabel, className } = TONES[tone];
  return (
    <div className={`note ${className}`}>
      <p className="mono-label note-label">
        <Icon size={13} aria-hidden="true" />
        {label ?? defaultLabel}
      </p>
      <div className="note-body">{children}</div>
    </div>
  );
}
