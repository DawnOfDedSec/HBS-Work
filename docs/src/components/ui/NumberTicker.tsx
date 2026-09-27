import { useEffect, useRef, useState } from 'react';

interface NumberTickerProps {
  value: number;
  /** characters rendered before/after the number */
  prefix?: string;
  suffix?: string;
  durationMs?: number;
  className?: string;
}

const reducedMotion = (): boolean =>
  typeof window !== 'undefined' &&
  typeof window.matchMedia === 'function' &&
  window.matchMedia('(prefers-reduced-motion: reduce)').matches;

/**
 * Magic UI's Number Ticker, ported without a motion dependency.
 *
 * The first render is the FINAL value on purpose: this site is prerendered, so
 * the static HTML and the no-JS case must already show the real number. The
 * count-up only starts once the element scrolls into view, on the client, and
 * only when reduced motion is not requested.
 */
export default function NumberTicker({
  value,
  prefix = '',
  suffix = '',
  durationMs = 1100,
  className = '',
}: NumberTickerProps) {
  const ref = useRef<HTMLSpanElement>(null);
  const [display, setDisplay] = useState(value);
  const [animate, setAnimate] = useState(false);

  useEffect(() => {
    if (reducedMotion()) return;
    const node = ref.current;
    if (!node || typeof IntersectionObserver === 'undefined') return;

    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          setAnimate(true);
          observer.disconnect();
        }
      },
      { threshold: 0.4 },
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    if (!animate) return;
    let frame = 0;
    const start = performance.now();
    const tick = (now: number) => {
      const progress = Math.min((now - start) / durationMs, 1);
      // ease-out cubic: fast arrival, soft landing
      const eased = 1 - (1 - progress) ** 3;
      setDisplay(Math.round(eased * value));
      if (progress < 1) frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [animate, value, durationMs]);

  return (
    <span ref={ref} className={`tabular-nums ${className}`}>
      {prefix}
      {display}
      {suffix}
    </span>
  );
}
