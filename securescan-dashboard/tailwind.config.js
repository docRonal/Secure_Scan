/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        base: "#0B1120",       // фон приложения
        surface: "#121A2B",    // карточки/панели
        surface2: "#182338",   // вложенные поверхности (hover, header)
        line: "#1F2A3D",       // границы
        ink: "#E6EDF5",        // основной текст
        muted: "#8B99AE",      // вторичный текст
        accent: "#35D1A6",     // primary — "жив/сканирует"
        accentDim: "#1F7A5D",
        sev: {
          info: "#5B7083",
          low: "#3E8FB0",
          medium: "#D8A23A",
          high: "#D9662B",
          critical: "#C23B3B",
        },
      },
      fontFamily: {
        display: ["'Space Grotesk'", "sans-serif"],
        body: ["'Inter'", "sans-serif"],
        mono: ["'IBM Plex Mono'", "monospace"],
      },
      boxShadow: {
        panel: "0 1px 0 0 rgba(255,255,255,0.03) inset, 0 8px 24px -12px rgba(0,0,0,0.6)",
      },
      keyframes: {
        pulseRing: {
          "0%": { transform: "scale(0.6)", opacity: "0.8" },
          "100%": { transform: "scale(2.2)", opacity: "0" },
        },
      },
      animation: {
        "pulse-ring": "pulseRing 1.6s cubic-bezier(0.2, 0.6, 0.4, 1) infinite",
      },
    },
  },
  plugins: [],
};
