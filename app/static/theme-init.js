(function () {
  // Page background of each theme, used to derive a readable --accent-text.
  // Keep in sync with theme.css.
  var THEME_BG = {
    oled: '#000000', graphite: '#1b1c1f', umber: '#1c1915', ink: '#121821',
    slate: '#e9ebee', flashbang: '#ffffff',
  };
  var THEMES = Object.keys(THEME_BG);
  var DEFAULT_THEME = 'slate';
  var DEFAULT_ACCENT = '#d4a017';  // brass; the stylesheets carry its derived tokens
  var HEX = /^#[0-9a-fA-F]{6}$/;
  // Tokens derived from a custom accent. With no custom accent these are left
  // to the stylesheets, so the default look is exactly what the CSS declares.
  var DERIVED = ['--accent', '--accent-hover', '--accent-2', '--accent-text', '--on-accent'];
  var root = document.documentElement;

  function channel(v) { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }
  function rgb(hex) { return [1, 3, 5].map(function (i) { return parseInt(hex.substr(i, 2), 16); }); }
  function lum(c) { return 0.2126 * channel(c[0]) + 0.7152 * channel(c[1]) + 0.0722 * channel(c[2]); }
  function contrast(a, b) { var x = lum(a), y = lum(b); return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05); }
  function toHex(c) { return '#' + c.map(function (v) { return Math.round(v).toString(16).padStart(2, '0'); }).join(''); }

  function toHsl(c) {
    var r = c[0] / 255, g = c[1] / 255, b = c[2] / 255;
    var max = Math.max(r, g, b), min = Math.min(r, g, b), l = (max + min) / 2, d = max - min, h = 0, s = 0;
    if (d) {
      s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
      h = max === r ? (g - b) / d + (g < b ? 6 : 0) : max === g ? (b - r) / d + 2 : (r - g) / d + 4;
      h *= 60;
    }
    return [h, s, l];
  }
  function fromHsl(h, s, l) {
    h = ((h % 360) + 360) % 360; l = Math.max(0, Math.min(1, l));
    function f(n) {
      var k = (n + h / 30) % 12, a = s * Math.min(l, 1 - l);
      return 255 * (l - a * Math.max(-1, Math.min(k - 3, 9 - k, 1)));
    }
    return [f(0), f(8), f(4)];
  }

  // Text on accent-tinted badges sits on the page background with a 15% accent
  // wash. Walk the accent's lightness away from the background (darker on a
  // light theme, lighter on a dark one) until that text clears WCAG AA
  // (4.5:1), with a little margin for the rounding to hex.
  function accentText(c, theme) {
    var bg = rgb(THEME_BG[theme] || THEME_BG[DEFAULT_THEME]);
    var light = lum(bg) > 0.4;
    var tint = bg.map(function (v, i) { return v * 0.85 + c[i] * 0.15; });
    var hsl = toHsl(c), step = light ? -0.02 : 0.02, out = c;
    for (var i = 0; i < 50 && contrast(out, tint) < 4.6; i++) {
      hsl[2] += step;
      out = fromHsl(hsl[0], hsl[1], hsl[2]);
    }
    return toHex(out);
  }

  function normalise(v) { return v && HEX.test(v) && v.toLowerCase() !== DEFAULT_ACCENT ? v.toLowerCase() : null; }

  var accent = null;
  try { accent = normalise(localStorage.getItem('accent')); } catch (e) { /* storage blocked — default accent */ }

  function applyAccent() {
    if (!accent) {
      DERIVED.forEach(function (p) { root.style.removeProperty(p); });
      return;
    }
    var c = rgb(accent), hsl = toHsl(c), theme = root.getAttribute('data-theme');
    var dark = [11, 11, 15], white = [255, 255, 255];
    root.style.setProperty('--accent', accent);
    root.style.setProperty('--accent-hover', toHex(fromHsl(hsl[0], hsl[1], Math.min(hsl[2] + 0.08, 0.85))));
    // Gradient partner: a small hue step toward red and slightly deeper, so it
    // stays in the same colour family (a +30° step turns brass into lime) and
    // gold reads as bronze rather than olive.
    root.style.setProperty('--accent-2', toHex(fromHsl(hsl[0] - 12, hsl[1], hsl[2] - 0.06)));
    root.style.setProperty('--accent-text', accentText(c, theme));
    root.style.setProperty('--on-accent', contrast(c, white) >= contrast(c, dark) ? '#ffffff' : '#0b0b0f');
  }

  function setAccent(hex) {
    accent = normalise(hex);
    try {
      if (accent) localStorage.setItem('accent', accent);
      else localStorage.removeItem('accent');
    } catch (e) { /* storage blocked — the colour still applies to this page view */ }
    applyAccent();
  }

  function setThemeAttr(name) {
    root.setAttribute('data-theme', THEMES.indexOf(name) >= 0 ? name : DEFAULT_THEME);
    applyAccent();  // --accent-text depends on the background
  }

  var theme = DEFAULT_THEME;
  try {
    theme = localStorage.getItem('theme') || DEFAULT_THEME;
  } catch (e) { /* storage blocked (private mode, etc.) — fall back to default theme */ }
  setThemeAttr(theme);

  window.CertTheme = {
    DEFAULT_ACCENT: DEFAULT_ACCENT,
    THEMES: THEMES,
    getAccent: function () { return accent || DEFAULT_ACCENT; },
    setAccent: setAccent,
    setTheme: function (name) {
      setThemeAttr(name);
      try { localStorage.setItem('theme', root.getAttribute('data-theme')); } catch (e) { /* storage blocked */ }
    },
  };
})();
