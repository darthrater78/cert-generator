(function () {
  try {
    var theme = localStorage.getItem('theme');
    if (theme && theme !== 'dark') document.documentElement.setAttribute('data-theme', theme);
  } catch (e) { /* storage blocked (private mode, etc.) — fall back to default theme */ }
})();
