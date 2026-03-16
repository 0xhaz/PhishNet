/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: '#0d0f14',
        surface: '#141720',
        border: '#1f2433',
        muted: '#4a5568',
        text: '#e2e8f0',
        'text-dim': '#718096',
        red: { DEFAULT: '#f56565', dim: '#742a2a' },
        yellow: { DEFAULT: '#ecc94b', dim: '#744210' },
        green: { DEFAULT: '#48bb78', dim: '#22543d' },
        blue: { DEFAULT: '#63b3ed', dim: '#2a4365' },
        purple: { DEFAULT: '#b794f4', dim: '#44337a' },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
}
