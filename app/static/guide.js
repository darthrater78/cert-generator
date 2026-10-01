// Tab switching for a guide opened in its own window (no app.js on that page).
document.addEventListener('click', (event) => {
  const tab = event.target.closest('.guide-tab[data-arg]');
  if (!tab) return;
  document.querySelectorAll('.guide-content').forEach((el) => el.classList.add('hidden'));
  document.querySelectorAll('.guide-tab').forEach((el) => el.classList.remove('active'));
  const panel = document.getElementById(tab.dataset.arg);
  if (panel) panel.classList.remove('hidden');
  tab.classList.add('active');
});
