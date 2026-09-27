/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      /**
       * Self-hosted in docs/public/fonts (see the @font-face block in
       * src/index.css). One variable file per family, latin subset, 75 KB
       * total, and no third-party request: a security vendor's docs should
       * not leak visitor IPs to a font CDN.
       */
      fontFamily: {
        sans: ['"IBM Plex Sans"', 'ui-sans-serif', 'system-ui', '-apple-system', 'Segoe UI', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Consolas', 'monospace'],
      },
      colors: {
        // canonical PotenFYR docs tokens (SPEC v1, section 2.1)
        surface: '#0b0d14',
        bg2: '#101320',
        panel: '#151828',
        elevated: '#1a1e32',
        ink: '#e8eaf2',
        ink2: '#b9bfd4',
        muted: '#9aa0b4',
        // was #6a7089: that failed AA on every surface (3.36-3.97:1). This
        // value clears 4.5:1 on `elevated`, the lightest surface in use.
        faint: '#7e85a2',
        link: '#c4b5fd',
        linkh: '#f9a8d4',
        // Interactive boundary token (WCAG 1.4.11). The old
        // rgba(255,255,255,0.08) border composited to 1.20:1 on the canvas.
        edge: '#6f7488',
        'edge-strong': '#a3a8bd',
        // Hairlines and washes were written as `border-white/[0.08]` in
        // 22 places, which is unrethemable: the utility is baked to white
        // and ignores any token change. Named so a light theme is possible
        // without a find-and-replace sweep.
        hairline: 'rgba(255, 255, 255, 0.09)',
        wash: 'rgba(255, 255, 255, 0.035)',
        'wash-strong': 'rgba(255, 255, 255, 0.07)',
        // status tones shared by callouts, allow/refuse lists and badges.
        // Defined here so no component reaches for a raw Tailwind palette
        // class (bg-emerald-400 and friends ignore these tokens entirely).
        ok: '#34d399',
        warn: '#fbbf24',
        deny: '#fb7185',
        accent: {
          DEFAULT: '#8b5cf6',
          2: '#ec4899',
          3: '#f97316',
        },
        /**
         * Deepened gradient stops used ONLY as a background for white text.
         * The vivid accent trio fails there (white on #f97316 is 2.80:1);
         * these clear AA on every stop. Keep the vivid trio for non-text
         * brand marks: the banner rule, the brand dot, the dot field.
         */
        cta: {
          DEFAULT: '#7c3aed',
          2: '#db2777',
          3: '#c2410c',
        },
      },
      animation: {
        marquee: 'marquee 38s linear infinite',
        'marquee-reverse': 'marquee-reverse 38s linear infinite',
        // a packet of light travelling a connector rail in the pipeline
        'flow-sweep': 'flow-sweep 3.2s linear infinite',
        'scan-pulse': 'scan-pulse 2.4s ease-in-out infinite',
        'caret-blink': 'caret-blink 1.05s steps(1) infinite',
      },
      keyframes: {
        marquee: {
          from: { transform: 'translateX(0)' },
          to: { transform: 'translateX(-50%)' },
        },
        'marquee-reverse': {
          from: { transform: 'translateX(-50%)' },
          to: { transform: 'translateX(0)' },
        },
        'flow-sweep': {
          from: { backgroundPosition: '-140% 0' },
          to: { backgroundPosition: '240% 0' },
        },
        'scan-pulse': {
          '0%, 100%': { opacity: '0.35' },
          '50%': { opacity: '1' },
        },
        'caret-blink': {
          '0%, 49%': { opacity: '1' },
          '50%, 100%': { opacity: '0' },
        },
      },
    },
  },
  plugins: [],
};
