/** @type {import('tailwindcss').Config} */
// v1.4 Phase 0 Tailwind config. Tokens live in src/input.css under
// :root and .dark; this file maps Tailwind color/shadow keys onto
// the CSS variables so utilities like bg-primary, text-severity-critical,
// shadow-soft work out of the box. v1.18 design-system milestone
// expands this further (per-domain palettes for every provider).
module.exports = {
  darkMode: ['class'],
  content: [
    'internal/server/ui/templates/**/*.html',
    'internal/server/ui/src/**/*.{html,js}',
  ],
  theme: {
    container: {
      center: true,
      padding: '1.5rem',
      screens: { '2xl': '1400px' },
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
    },
  },
  plugins: [],
};
