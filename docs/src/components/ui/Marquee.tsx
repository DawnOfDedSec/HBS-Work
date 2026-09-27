import { type ReactNode } from 'react';

interface MarqueeProps {
  children: ReactNode;
  /** seconds for one full loop */
  speed?: number;
  reverse?: boolean;
  className?: string;
  /** What the strip is scrolling, for screen readers. The duplicate track is aria-hidden. */
  label?: string;
}

/**
 * Magic UI's Marquee, ported to plain CSS so the docs bundle stays
 * dependency-light. Two details make it work: the track is duplicated and
 * translated -50% (a seamless loop needs identical halves), and the second
 * copy is aria-hidden so assistive tech reads the list once.
 */
export default function Marquee({
  children,
  speed = 38,
  reverse = false,
  className = '',
  label,
}: MarqueeProps) {
  return (
    <div
      className={`marquee ${className}`}
      role={label ? 'group' : undefined}
      aria-label={label}
    >
      <div
        className={`marquee-track ${reverse ? 'marquee-reverse' : ''}`}
        style={{ animationDuration: `${speed}s` }}
      >
        {children}
        <span aria-hidden="true" className="marquee-copy">
          {children}
        </span>
      </div>
    </div>
  );
}
