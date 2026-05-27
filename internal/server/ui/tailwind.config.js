/** @type {import('tailwindcss').Config} */
// v1.4 Phase 0 Tailwind config. v1.18 phase 0 (ADR-017) relocated the
// canonical token vocabulary to internal/server/ui/design/tokens.css.
// This file maps Tailwind color/shadow/font/duration/easing keys onto
// those CSS variables so utilities like `bg-primary`,
// `text-severity-critical`, `shadow-soft`, `font-mono`, `duration-150`,
// `ease-spring` resolve to the design-system contract. Adding a new
// utility key here without a matching token in tokens.css is the v1.18
// anti-pattern: every utility resolves to a token.
module.exports = {
  darkMode: ['class'],
  content: [
    'internal/server/ui/templates/**/*.html',
    'internal/server/ui/src/**/*.{html,js}',
    // v1.18 phase 0 — component partials + the /design route templates
    // landing at phase 3 + phase 7. Tailwind scans these for class
    // usage so utilities used only inside the design system land in the
    // compiled bundle.
    'internal/server/ui/design/**/*.{html,js}',
  ],
  theme: {
    container: {
      center: true,
      padding: '1.5rem',
      screens: { '2xl': '1400px' },
    },
    // v1.16 phase 3 — narrow `xs:` breakpoint for iPhone-SE-class
    // viewports (375px). Tailwind's default `sm:` starts at 640px,
    // which is too wide for "actually a phone". Pages opt into the
    // mobile-card layout by gating with xs:hidden / xs:block.
    screens: {
      xs: '400px',
      sm: '640px',
      md: '768px',
      lg: '1024px',
      xl: '1280px',
      '2xl': '1536px',
    },
    extend: {
      colors: {
        border: 'hsl(var(--border))',
        input: 'hsl(var(--input))',
        ring: 'hsl(var(--ring))',
        background: 'hsl(var(--background))',
        foreground: 'hsl(var(--foreground))',
        primary: {
          DEFAULT: 'hsl(var(--primary))',
          foreground: 'hsl(var(--primary-foreground))',
          glow: 'hsl(var(--primary-glow))',
        },
        secondary: {
          DEFAULT: 'hsl(var(--secondary))',
          foreground: 'hsl(var(--secondary-foreground))',
        },
        muted: {
          DEFAULT: 'hsl(var(--muted))',
          foreground: 'hsl(var(--muted-foreground))',
        },
        accent: {
          DEFAULT: 'hsl(var(--accent))',
          foreground: 'hsl(var(--accent-foreground))',
        },
        card: {
          DEFAULT: 'hsl(var(--card))',
          foreground: 'hsl(var(--card-foreground))',
        },
        popover: {
          DEFAULT: 'hsl(var(--popover))',
          foreground: 'hsl(var(--popover-foreground))',
        },
        destructive: {
          DEFAULT: 'hsl(var(--destructive))',
          foreground: 'hsl(var(--destructive-foreground))',
        },
        success: {
          DEFAULT: 'hsl(var(--success))',
          foreground: 'hsl(var(--success-foreground))',
        },
        warning: {
          DEFAULT: 'hsl(var(--warning))',
          foreground: 'hsl(var(--warning-foreground))',
        },
        severity: {
          critical: 'hsl(var(--severity-critical))',
          'critical-bg': 'hsl(var(--severity-critical-bg))',
          high: 'hsl(var(--severity-high))',
          'high-bg': 'hsl(var(--severity-high-bg))',
          medium: 'hsl(var(--severity-medium))',
          'medium-bg': 'hsl(var(--severity-medium-bg))',
          low: 'hsl(var(--severity-low))',
          'low-bg': 'hsl(var(--severity-low-bg))',
          info: 'hsl(var(--severity-info))',
          'info-bg': 'hsl(var(--severity-info-bg))',
        },
        status: {
          open: 'hsl(var(--status-open))',
          acknowledged: 'hsl(var(--status-acknowledged))',
          resolved: 'hsl(var(--status-resolved))',
          'false-positive': 'hsl(var(--status-false-positive))',
          running: 'hsl(var(--status-running))',
          completed: 'hsl(var(--status-completed))',
          failed: 'hsl(var(--status-failed))',
          pending: 'hsl(var(--status-pending))',
        },
        resource: {
          droplet: 'hsl(var(--resource-droplet))',
          database: 'hsl(var(--resource-database))',
          kubernetes: 'hsl(var(--resource-kubernetes))',
          spaces: 'hsl(var(--resource-spaces))',
          'load-balancer': 'hsl(var(--resource-load-balancer))',
          firewall: 'hsl(var(--resource-firewall))',
          vpc: 'hsl(var(--resource-vpc))',
          domain: 'hsl(var(--resource-domain))',
        },
        sidebar: {
          DEFAULT: 'hsl(var(--sidebar))',
          foreground: 'hsl(var(--sidebar-foreground))',
          primary: 'hsl(var(--sidebar-primary))',
          'primary-foreground': 'hsl(var(--sidebar-primary-foreground))',
          accent: 'hsl(var(--sidebar-accent))',
          'accent-foreground': 'hsl(var(--sidebar-accent-foreground))',
          border: 'hsl(var(--sidebar-border))',
        },
      },
      backgroundImage: {
        'gradient-primary': 'linear-gradient(135deg, hsl(var(--primary)), hsl(var(--primary-glow)))',
        'gradient-critical': 'linear-gradient(135deg, hsl(var(--severity-critical)), hsl(0 75% 50%))',
        'gradient-high': 'linear-gradient(135deg, hsl(var(--severity-high)), hsl(25 88% 45%))',
        'gradient-medium': 'linear-gradient(135deg, hsl(var(--severity-medium)), hsl(38 92% 50%))',
        'gradient-low': 'linear-gradient(135deg, hsl(var(--severity-low)), hsl(189 94% 43%))',
      },
      boxShadow: {
        soft: 'var(--shadow-soft)',
        elevated: 'var(--shadow-elevated)',
        floating: 'var(--shadow-floating)',
      },
      borderRadius: {
        lg: 'var(--radius)',
        md: 'calc(var(--radius) - 2px)',
        sm: 'calc(var(--radius) - 4px)',
      },
      // v1.18 phase 0 — typography tokens. System fonts only per
      // ADR-015. The `2xs` (11px) tier is reserved for table column
      // labels + uppercase eyebrow text.
      fontFamily: {
        sans: 'var(--font-sans)',
        mono: 'var(--font-mono)',
      },
      fontSize: {
        '2xs': ['var(--text-2xs)', { lineHeight: 'var(--leading-snug)' }],
      },
      // v1.18 phase 0 — motion tokens. 4 standard durations + 6 Framer-
      // style easings. Phase 8 wires skeletons + nprogress on top.
      transitionDuration: {
        75: 'var(--motion-75)',
        150: 'var(--motion-150)',
        250: 'var(--motion-250)',
        400: 'var(--motion-400)',
      },
      transitionTimingFunction: {
        'in-quad': 'var(--ease-in-quad)',
        'out-quad': 'var(--ease-out-quad)',
        'in-out-quad': 'var(--ease-in-out-quad)',
        'spring': 'var(--ease-spring)',
        'soft-in': 'var(--ease-soft-in)',
        'soft-out': 'var(--ease-soft-out)',
      },
    },
  },
  plugins: [],
};
