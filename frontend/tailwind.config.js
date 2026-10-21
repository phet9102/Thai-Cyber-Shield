/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./public/**/*.html", "./public/assets/app.js"],
  theme: {
    extend: {
      colors: {
        night: "#0D1330",
        glass: "#18214A",
        signal: "#5CE1E6",
        safe: "#7BE495",
        caution: "#FFB547",
        danger: "#FF5D73",
        ink: "#E8ECFF",
        muted: "#9AA3C7",
      },
      fontFamily: {
        display: ['"Anuphan"', '"IBM Plex Sans Thai"', "system-ui", "sans-serif"],
        body: ['"IBM Plex Sans Thai"', "system-ui", "sans-serif"],
      },
    },
  },
  plugins: [],
};
