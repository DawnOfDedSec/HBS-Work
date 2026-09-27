import {
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type ReactNode,
} from 'react';

/**
 * `useLayoutEffect` warns when it runs during server rendering, and this site
 * is prerendered - so it is `useEffect` on the server and `useLayoutEffect` in
 * the browser, where running before paint is exactly what we need.
 */
const useIsomorphicLayoutEffect = typeof window === 'undefined' ? useEffect : useLayoutEffect;

interface RevealProps {
  children: ReactNode;
  /** stagger offset in ms */
  delay?: number;
  className?: string;
}

const prefersReducedMotion = (): boolean =>
  typeof window !== 'undefined' &&
  typeof window.matchMedia === 'function' &&
  window.matchMedia('(prefers-reduced-motion: reduce)').matches;

/**
 * Reserved for the two moments worth animating on the home page - the hero and
 * the pipeline. It was briefly on every section, which is the "same fade-up on
 * everything" tell: once motion is everywhere it stops signalling anything.
 *
 * Order matters and is the whole point of this component:
 *   1. the prerendered HTML has no `.reveal` class, so crawlers, no-JS
 *      visitors and the first paint all show the content;
 *   2. a layout effect (before paint) arms `.reveal`, hiding it instantly;
 *   3. the next frame enables the transition (`.reveal-ready`);
 *   4. intersecting adds `.is-in` and the section fades up.
 * Do not collapse steps 2 and 3 into one class: arming *after* paint animates
 * content downwards, which reads as a flash of disappearing text.
 */
export default function Reveal({ children, delay = 0, className = '' }: RevealProps) {
  const ref = useRef<HTMLDivElement>(null);
  const [armed, setArmed] = useState(false);
  const [ready, setReady] = useState(false);
  const [shown, setShown] = useState(false);

  useIsomorphicLayoutEffect(() => {
    if (
      typeof window === 'undefined' ||
      typeof IntersectionObserver === 'undefined' ||
      prefersReducedMotion()
    ) {
      setShown(true);
      return;
    }
    setArmed(true);
    const raf = requestAnimationFrame(() => setReady(true));
    return () => cancelAnimationFrame(raf);
  }, []);

  useEffect(() => {
    const node = ref.current;
    if (!node || !armed || shown || typeof IntersectionObserver === 'undefined') return;

    /**
     * Anything that has scrolled off the top counts as seen.
     *
     * An IntersectionObserver only fires when a threshold is crossed, and a
     * jump - an anchor link, End, a restored scroll position, a fast fling -
     * moves past a section without it ever intersecting. The observer stays
     * silent, `.is-in` is never added, and the section sits at opacity 0 for
     * good: invisible content, not just a missed animation.
     */
    const rescue = () => {
      if (node.getBoundingClientRect().bottom < 0) setShown(true);
    };

    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          setShown(true);
          observer.disconnect();
        }
      },
      { rootMargin: '-40px 0px -60px 0px' },
    );
    observer.observe(node);
    rescue();
    window.addEventListener('scroll', rescue, { passive: true });
    return () => {
      observer.disconnect();
      window.removeEventListener('scroll', rescue);
    };
  }, [armed, shown]);

  const classes = [
    armed ? 'reveal' : '',
    ready ? 'reveal-ready' : '',
    shown ? 'is-in' : '',
    className,
  ]
    .filter(Boolean)
    .join(' ');

  return (
    <div
      ref={ref}
      className={classes}
      style={delay && armed ? { transitionDelay: `${delay}ms` } : undefined}
    >
      {children}
    </div>
  );
}
