import { useEffect, useRef, useState } from 'react';

interface TerminalProps {
  lines: string[];
  /** window title, rendered in the chrome bar */
  title: string;
  /** shown when nothing has been run - these are illustrative commands */
  lang?: string;
}

/**
 * Terminal window (Magic UI's Terminal pattern, CSS only).
 *
 * The lines are all present in the first render - the prerendered HTML, the
 * crawler and the no-JS visitor see the complete command. The staggered reveal
 * is added on the client only, once, and skipped entirely when the visitor
 * asks for reduced motion.
 */
export default function Terminal({ lines, title }: TerminalProps) {
  const ref = useRef<HTMLDivElement>(null);
  const [armed, setArmed] = useState(false);

  useEffect(() => {
    if (
      typeof window === 'undefined' ||
      typeof IntersectionObserver === 'undefined' ||
      (typeof window.matchMedia === 'function' &&
        window.matchMedia('(prefers-reduced-motion: reduce)').matches)
    ) {
      return;
    }
    const node = ref.current;
    /* Already on screen at mount: arm immediately, otherwise the finished
       lines paint first and then visibly restart from the animation's frame 0. */
    if (node) {
      const rect = node.getBoundingClientRect();
      if (rect.top < window.innerHeight && rect.bottom > 0) {
        setArmed(true);
        return;
      }
    }
    if (!node) return;
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          setArmed(true);
          observer.disconnect();
        }
      },
      { threshold: 0.3 },
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, []);

  return (
    <div className="term" ref={ref}>
      <div className="term-bar">
        <span className="term-dot" aria-hidden="true" />
        <span className="term-dot" aria-hidden="true" />
        <span className="term-dot" aria-hidden="true" />
        <p className="ml-1.5 font-mono text-[0.7rem] text-faint">{title}</p>
      </div>
      <pre className="overflow-x-auto px-4 py-3">
        <code className="font-mono text-[0.8rem] leading-relaxed text-ink2">
          {lines.map((line, i) => (
            <span
              key={i}
              className={`block ${armed ? 'term-line' : ''}`}
              style={armed ? { animationDelay: `${i * 120}ms` } : undefined}
            >
              {line}
              {i === lines.length - 1 ? <span className="term-caret ml-0.5" aria-hidden="true" /> : null}
            </span>
          ))}
        </code>
      </pre>
    </div>
  );
}
