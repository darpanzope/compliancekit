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
          // v1.3 baseline (DigitalOcean unprefixed).
          droplet: 'hsl(var(--resource-droplet))',
          database: 'hsl(var(--resource-database))',
          kubernetes: 'hsl(var(--resource-kubernetes))',
          spaces: 'hsl(var(--resource-spaces))',
          'load-balancer': 'hsl(var(--resource-load-balancer))',
          firewall: 'hsl(var(--resource-firewall))',
          vpc: 'hsl(var(--resource-vpc))',
          domain: 'hsl(var(--resource-domain))',
          // v1.18 phase 1 — provider-prefixed taxonomy. Each key here
          // maps to a token in design/tokens.css.
          'aws-ec2': 'hsl(var(--resource-aws-ec2))',
          'aws-s3': 'hsl(var(--resource-aws-s3))',
          'aws-iam': 'hsl(var(--resource-aws-iam))',
          'aws-rds': 'hsl(var(--resource-aws-rds))',
          'aws-eks': 'hsl(var(--resource-aws-eks))',
          'aws-kms': 'hsl(var(--resource-aws-kms))',
          'aws-cloudtrail': 'hsl(var(--resource-aws-cloudtrail))',
          'aws-configservice': 'hsl(var(--resource-aws-configservice))',
          'aws-guardduty': 'hsl(var(--resource-aws-guardduty))',
          'gcp-compute': 'hsl(var(--resource-gcp-compute))',
          'gcp-storage': 'hsl(var(--resource-gcp-storage))',
          'gcp-iam': 'hsl(var(--resource-gcp-iam))',
          'gcp-gke': 'hsl(var(--resource-gcp-gke))',
          'gcp-kms': 'hsl(var(--resource-gcp-kms))',
          'gcp-bigquery': 'hsl(var(--resource-gcp-bigquery))',
          'gcp-sqladmin': 'hsl(var(--resource-gcp-sqladmin))',
          'gcp-logging': 'hsl(var(--resource-gcp-logging))',
          'hetzner-server': 'hsl(var(--resource-hetzner-server))',
          'hetzner-volume': 'hsl(var(--resource-hetzner-volume))',
          'hetzner-network': 'hsl(var(--resource-hetzner-network))',
          'hetzner-firewall': 'hsl(var(--resource-hetzner-firewall))',
          'hetzner-load-balancer': 'hsl(var(--resource-hetzner-load-balancer))',
          'hetzner-floating-ip': 'hsl(var(--resource-hetzner-floating-ip))',
          'k8s-pod': 'hsl(var(--resource-k8s-pod))',
          'k8s-deployment': 'hsl(var(--resource-k8s-deployment))',
          'k8s-service': 'hsl(var(--resource-k8s-service))',
          'k8s-ingress': 'hsl(var(--resource-k8s-ingress))',
          'k8s-configmap': 'hsl(var(--resource-k8s-configmap))',
          'k8s-secret': 'hsl(var(--resource-k8s-secret))',
          'k8s-namespace': 'hsl(var(--resource-k8s-namespace))',
          'k8s-node': 'hsl(var(--resource-k8s-node))',
          'k8s-statefulset': 'hsl(var(--resource-k8s-statefulset))',
          'k8s-daemonset': 'hsl(var(--resource-k8s-daemonset))',
          'k8s-role': 'hsl(var(--resource-k8s-role))',
          'k8s-clusterrole': 'hsl(var(--resource-k8s-clusterrole))',
          'linux-host': 'hsl(var(--resource-linux-host))',
          'linux-package': 'hsl(var(--resource-linux-package))',
          'linux-service': 'hsl(var(--resource-linux-service))',
          'linux-user': 'hsl(var(--resource-linux-user))',
          'linux-group': 'hsl(var(--resource-linux-group))',
          'linux-file': 'hsl(var(--resource-linux-file))',
          'linux-firewall': 'hsl(var(--resource-linux-firewall))',
          'linux-kernel': 'hsl(var(--resource-linux-kernel))',
          'linux-ssh': 'hsl(var(--resource-linux-ssh))',
          'linux-audit': 'hsl(var(--resource-linux-audit))',
          'linux-filesystem': 'hsl(var(--resource-linux-filesystem))',
        },
        // v1.18 phase 1 — provider brand colors. Drives provider
        // badges, sidebar headings, header logos. Phase 11 wires the
        // provider sprite using these tokens.
        brand: {
          aws: 'hsl(var(--brand-aws))',
          gcp: 'hsl(var(--brand-gcp))',
          do: 'hsl(var(--brand-do))',
          hetzner: 'hsl(var(--brand-hetzner))',
          kubernetes: 'hsl(var(--brand-kubernetes))',
          linux: 'hsl(var(--brand-linux))',
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
      // v1.18 phase 2 — gradient utilities. Each utility resolves to a
      // `--gradient-*` token in design/tokens.css so dark mode + the
      // high-contrast palette can override the stops without touching
      // tailwind.config.js. New gradients land in tokens.css, not here.
      backgroundImage: {
        'gradient-primary':  'var(--gradient-primary)',
        'gradient-critical': 'var(--gradient-critical)',
        'gradient-high':     'var(--gradient-high)',
        'gradient-medium':   'var(--gradient-medium)',
        'gradient-low':      'var(--gradient-low)',
        'gradient-success':  'var(--gradient-success)',
        'gradient-info':     'var(--gradient-info)',
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
