/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./templates/**/*.html"],
  corePlugins: { preflight: false },
  theme: {
    extend: {
      colors: {
        ink: {
          950: '#12131f', 900: '#1a1b2e', 850: '#1e1f2e',
          800: '#1e2040', 700: '#2a2b3d', 600: '#2e3050',
        },
        line:       '#2e3050',
        accent:     { DEFAULT: '#3b5bdb', hover: '#4c6ce8', soft: 'rgba(59,91,219,0.13)' },
        consultant: '#6b46c1',
        sev:        { crit: '#ff3b3b', high: '#f97316', med: '#f59e0b', low: '#6b7280' },
        ok:         '#1a7f3c',
        tx:         { 1: '#e2e4ea', 2: '#9ea3b0', 3: '#6b7280' },
      },
      fontFamily: {
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', 'monospace'],
      },
    },
  },
};
