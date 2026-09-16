(function () {
  var theme = 'oled';
  try {
    theme = localStorage.getItem('theme') || 'oled';
  } catch (e) { /* storage blocked (private mode, etc.) — fall back to default theme */ }
  document.documentElement.setAttribute('data-theme', theme);
})();
