/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#18212f",
        muted: "#5f6f83",
        accent: { DEFAULT: "#0f766e", strong: "#115e59" },
        sev: {
          low: "#067647",
          medium: "#b54708",
          high: "#b42318",
          critical: "#912018",
        },
      },
      fontFamily: {
        sans: ["Avenir Next", "Inter", "ui-sans-serif", "system-ui", "-apple-system", "Segoe UI", "sans-serif"],
        display: ["Iowan Old Style", "Palatino Linotype", "Book Antiqua", "Georgia", "serif"],
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "Monaco", "Consolas", "monospace"],
      },
    },
  },
  plugins: [],
};
