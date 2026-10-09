/**
 * VaultShare 3.0 — theme-init.js
 * Loaded first thing in <head> on every page, BEFORE the body paints, so
 * there is no flash of the wrong theme. Only touches the "data-theme"
 * attribute on <html> — all actual colors live in CSS variables
 * (css/style.css). Three states: "dark" (explicit), "light" (explicit),
 * or no attribute at all = follow the OS (Feature 25: system theme).
 */
(function () {
  try {
    var saved = localStorage.getItem('vsTheme'); // 'dark' | 'light' | null (= system)
    if (saved === 'dark' || saved === 'light') {
      document.documentElement.setAttribute('data-theme', saved);
    }
  } catch (e) { /* localStorage unavailable (e.g. private mode) — default to system/dark */ }
})();
