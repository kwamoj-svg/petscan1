import type { Config } from 'tailwindcss';

const config: Config = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        pitch: '#1a472a',
        'pitch-light': '#2d6b3f',
        'scout-dark': '#0a0f1a',
        'scout-card': '#111827',
        'scout-border': '#1f2937',
        'scout-accent': '#3b82f6',
        'confidence-high': '#22c55e',
        'confidence-medium': '#eab308',
        'confidence-conflict': '#ef4444',
      },
    },
  },
  plugins: [],
};

export default config;
