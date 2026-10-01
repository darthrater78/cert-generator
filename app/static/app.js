function toggleMobileMenu() {
  const sidebar = document.getElementById('sidebar');
  const backdrop = document.getElementById('sidebarBackdrop');
  const btn = document.getElementById('hamburgerBtn');
  const open = sidebar.classList.toggle('open');
  if (open) { backdrop.classList.add('open'); btn.style.display = 'none'; }
  else { backdrop.classList.remove('open'); btn.style.display = ''; }
}
function closeMobileMenu() {
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('sidebarBackdrop').classList.remove('open');
  document.getElementById('hamburgerBtn').style.display = '';
}

function setTheme(name) {
  window.CertTheme.setTheme(name);
  updateThemeSwitcherUI(document.documentElement.dataset.theme);
}

function updateThemeSwitcherUI(name) {
  document.querySelectorAll('.theme-opt').forEach((btn) => {
    const on = btn.dataset.arg === name;
    btn.classList.toggle('active', on);
    btn.setAttribute('aria-pressed', String(on));
    if (on) document.getElementById('appearanceLabel').textContent = btn.textContent.trim();
  });
}

function setAccent(hex) {
  window.CertTheme.setAccent(hex || null);
  updateAccentUI();
}

function updateAccentUI({ keepHexField = false } = {}) {
  const current = window.CertTheme.getAccent();
  document.getElementById('accentInput').value = current;
  if (!keepHexField) {
    document.getElementById('accentHex').value = current;
    setAccentHexValidity(true);
  }
  document.querySelectorAll('.accent-preset').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.arg === current);
  });
}

// Accepts "#d4a017", "d4a017", "#fa0" or "fa0"; returns "#rrggbb" or null.
function parseAccentHex(value) {
  let hex = value.trim().toLowerCase();
  if (!hex.startsWith('#')) hex = `#${hex}`;
  if (/^#[0-9a-f]{3}$/.test(hex)) hex = `#${[...hex.slice(1)].map((c) => c + c).join('')}`;
  return /^#[0-9a-f]{6}$/.test(hex) ? hex : null;
}

function setAccentHexValidity(valid) {
  document.getElementById('accentHex').setAttribute('aria-invalid', String(!valid));
  const hint = document.getElementById('accentHexHint');
  hint.classList.toggle('invalid', !valid);
  hint.textContent = valid ? 'Type a hex colour, like #d4a017' : 'Not a hex colour. Use six digits, like #d4a017';
}

// Live preview while typing: apply as soon as the field holds a valid colour,
// without rewriting what the user is typing.
function onAccentHexInput(event) {
  const hex = parseAccentHex(event.target.value);
  if (!hex) return;
  window.CertTheme.setAccent(hex);
  updateAccentUI({ keepHexField: true });
  setAccentHexValidity(true);
}

// On Enter or leaving the field: normalise a valid value, flag an invalid one.
function onAccentHexCommit(event) {
  const hex = parseAccentHex(event.target.value);
  if (hex) setAccent(hex);
  else setAccentHexValidity(false);
}

function toggleAccentMenu(_arg, _el, open) {
  const menu = document.getElementById('accentMenu');
  const show = typeof open === 'boolean' ? open : menu.hidden;
  menu.hidden = !show;
  document.getElementById('accentBtn').setAttribute('aria-expanded', String(show));
}

const SERVER_MODE = document.body.dataset.serverMode === 'true';
let currentCAId = null;
let currentSSHKeyId = null;
let exportCertId = null;

const TEMPLATE_LABELS = {
  'web-server': 'Web Server',
  'computer': 'Computer',
  'client-auth': 'Client Auth',
  'user': 'User',
  'code-signing': 'Code Signing',
  'email': 'Email (S/MIME)',
};

// Short labels for the index and the register; long names for the particulars.
const ALGO_SHORT = {
  'ecdsa-p256': 'P-256', 'ecdsa-p384': 'P-384', 'rsa-2048': 'RSA 2048', 'rsa-4096': 'RSA 4096', 'ed25519': 'Ed25519',
};
const ALGO_LONG = {
  'ecdsa-p256': 'ECDSA P-256', 'ecdsa-p384': 'ECDSA P-384', 'rsa-2048': 'RSA 2048', 'rsa-4096': 'RSA 4096', 'ed25519': 'Ed25519',
};
const algoShort = (a) => ALGO_SHORT[a] || a;
const algoLong = (a) => ALGO_LONG[a] || a;
const EXPIRY_WARNING_DAYS = 30;

// Certificate authorities by id, from the last list load (for "issued by").
const caIndex = new Map();
// Issued certificates of the open CA by id, from the last table render.
const certIndex = new Map();

// "0x7cff2c0d6fb3…" or "7C:FF:2C:…" → "7C:FF:2C:0D:6F:B3", the leading bytes of a serial.
function shortSerial(serial) {
  let hex = String(serial || '').replace(/^0x/i, '').replace(/:/g, '').toUpperCase();
  if (hex.length % 2) hex = '0' + hex;
  return (hex.match(/../g) || []).slice(0, 6).join(':');
}
const TEMPLATE_DESCS = {
  'web-server': 'Server Authentication',
  'computer': 'Client Authentication, Server Authentication',
  'client-auth': 'Client Authentication',
  'user': 'Client Authentication, Smart Card Logon',
  'code-signing': 'Code Signing',
  'email': 'Email Protection',
};

// A reload or navigation aborts requests in flight, and Firefox rejects them (NetworkError,
// AbortError) as soon as it starts. Background loads have no one to report to by then.
let pageUnloading = false;
window.addEventListener('beforeunload', () => { pageUnloading = true; });
window.addEventListener('pageshow', () => { pageUnloading = false; });
window.addEventListener('unhandledrejection', (event) => {
  if (pageUnloading) event.preventDefault();
});

async function api(url, opts = {}, retried = false) {
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...opts.headers },
    ...opts,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }));
    if (res.status === 423 && err.locked) {
      document.getElementById('unlockOverlay').classList.remove('hidden');
    }
    // Private keys and backups need a recent sign-in: ask, then repeat the request once.
    if (res.status === 403 && err.reauth_required && !retried) {
      if (await promptReauth(err.mfa)) return api(url, opts, true);
      throw new Error('Cancelled. Confirm it\'s you to continue.');
    }
    throw new Error(err.error || 'Request failed');
  }
  return res;
}

// ── Re-authentication ───────────────────────────────────────────────
let reauthPending = null;

function promptReauth(mfa) {
  if (reauthPending) return reauthPending.promise;
  let resolve;
  const promise = new Promise((r) => { resolve = r; });
  reauthPending = { promise, resolve };
  document.getElementById('reauthLabel').textContent = mfa ? 'Password or authenticator code' : 'Password';
  document.getElementById('reauthError').textContent = '';
  const input = document.getElementById('reauthSecret');
  input.value = '';
  showModal('reauthModal');
  input.focus();
  return promise;
}

function finishReauth(ok) {
  hideModal('reauthModal');
  document.getElementById('reauthSecret').value = '';
  const pending = reauthPending;
  reauthPending = null;
  if (pending) pending.resolve(ok);
}

async function submitReauth() {
  const input = document.getElementById('reauthSecret');
  const errorBox = document.getElementById('reauthError');
  if (!input.value) { errorBox.textContent = 'Enter your password'; return; }
  const res = await fetch('/api/reauth', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ secret: input.value }),
  });
  if (res.ok) { finishReauth(true); return; }
  const err = await res.json().catch(() => ({}));
  errorBox.textContent = err.error || 'Request failed';
  input.select();
}

function cancelReauth() { finishReauth(false); }

function toast(msg, type = 'success') {
  const el = document.createElement('div');
  el.className = 'toast toast-' + type;
  el.textContent = msg;
  document.getElementById('toasts').appendChild(el);
  setTimeout(() => el.remove(), 3000);
}

function showModal(id) { closeMobileMenu(); document.getElementById(id).classList.remove('hidden'); }
function hideModal(id) { document.getElementById(id).classList.add('hidden'); }

function showCreateCA() { showModal('createCAModal'); document.getElementById('caDomain').focus(); }
function showIssueCert() {
  updateCrlDpFields();
  showModal('issueCertModal');
  document.getElementById('certCN').focus();
}

// The distribution point choice: this server (server mode only) or the offline placeholder.
function updateCrlDpFields() {
  const include = document.getElementById('certIncludeCRL').checked;
  const select = document.getElementById('certCrlDp');
  select.querySelector('option[value="server"]').disabled = !SERVER_MODE;
  if (!SERVER_MODE) select.value = 'placeholder';
  const server = select.value === 'server';
  const baseUrl = document.getElementById('certCrlBaseUrl');
  if (!baseUrl.value) baseUrl.value = window.location.origin;

  document.getElementById('crlDpRow').hidden = !include;
  document.getElementById('crlBaseUrlGroup').hidden = !server;
  const ca = caIndex.get(currentCAId);
  document.getElementById('crlDpHint').textContent = server
    ? 'Clients fetch ' + baseUrl.value.replace(/\/+$/, '') + '/crl/' + currentCAId + '.crl without signing in. ' +
      'This server signs that CRL itself, republishes it on every revocation and renews it before it expires.'
    : 'Points at http://pki.' + (ca ? ca.domain : '<domain>') + '/crl/… — nothing answers there; ' +
      'import the exported CRL on each machine (see Import Guide).' +
      (SERVER_MODE ? '' : ' For a CRL clients fetch over the network, use the Docker version; ' +
        'move your CAs there with Backup and Restore.');
}

async function loadCAs() {
  const res = await api('/api/ca');
  const cas = await res.json();
  const list = document.getElementById('caList');
  list.innerHTML = '';

  caIndex.clear();
  cas.forEach(c => caIndex.set(c.id, c));
  const roots = cas.filter(c => !c.parent_ca_id);
  const childrenOf = (pid) => cas.filter(c => c.parent_ca_id === pid);

  roots.forEach(ca => {
    const li = document.createElement('li');
    li.className = 'ca-item' + (ca.id === currentCAId ? ' active' : '');
    li.innerHTML = '<span class="dot"></span><span class="ca-name">' +
      escapeHtml(ca.name) + '</span><span class="ca-alg">' + escapeHtml(algoShort(ca.algorithm)) + '</span>';
    li.onclick = () => selectCA(ca.id);
    list.appendChild(li);

    childrenOf(ca.id).forEach(child => {
      const cli = document.createElement('li');
      cli.className = 'ca-item intermediate' + (child.id === currentCAId ? ' active' : '');
      cli.innerHTML = '<span class="dot"></span><span class="ca-name">' +
        escapeHtml(child.name) + '</span><span class="ca-alg">' + escapeHtml(algoShort(child.algorithm)) + '</span>';
      cli.onclick = () => selectCA(child.id);
      list.appendChild(cli);
    });
  });

  document.getElementById('caCount').textContent = cas.length;
  if (currentSSHKeyId) return cas.length;
  if (currentCAId && !caIndex.has(currentCAId)) currentCAId = null;
  if (cas.length === 0) {
    document.getElementById('welcomeView').classList.remove('hidden');
    document.getElementById('caView').classList.add('hidden');
  } else if (!currentCAId) {
    // Nothing selected yet (fresh sign-in, or the open CA was deleted): open the
    // first authority instead of leaving the "No authorities yet" screen up.
    selectCA((roots[0] || cas[0]).id);
  }
  return cas.length;
}

async function selectCA(caId) {
  closeMobileMenu();
  currentCAId = caId;
  currentSSHKeyId = null;
  const res = await api('/api/ca/' + caId);
  const ca = await res.json();

  document.getElementById('welcomeView').classList.add('hidden');
  document.getElementById('sshKeyView').classList.add('hidden');
  document.getElementById('caView').classList.remove('hidden');
  document.getElementById('caViewTitle').textContent = ca.name;

  const isRoot = ca.is_root;
  document.getElementById('caViewEyebrow').textContent =
    (isRoot ? 'Root authority' : 'Intermediate authority') + ' · No. ' + shortSerial(ca.serial);
  const parent = caIndex.get(ca.parent_ca_id);
  document.getElementById('caViewChain').textContent = isRoot
    ? 'self-signed · for ' + ca.domain
    : 'issued by ' + (parent ? parent.name : 'its parent CA') + ' · for ' + ca.domain;
  document.getElementById('btnCreateIntermediate').classList.toggle('hidden', !ca.can_issue_intermediate);

  const expired = new Date(ca.not_after) < new Date();
  const typeBadge = isRoot
    ? '<span class="badge badge-active">Root</span>'
    : '<span class="badge badge-algo">Intermediate</span>';
  document.getElementById('caInfo').innerHTML =
    infoItem('Type', typeBadge) +
    infoItem('Domain', escapeHtml(ca.domain)) +
    infoItem('Algorithm', '<span class="badge badge-algo">' + escapeHtml(algoLong(ca.algorithm)) + '</span>') +
    infoItem('Serial', serialToggle(ca.serial)) +
    infoItem('Created', formatDate(ca.not_before)) +
    infoItem('Expires', formatDate(ca.not_after)) +
    (SERVER_MODE && ca.crl_served
      ? infoItem('Published CRL', servedCrlBadge(ca.crl_served_next_update) +
          '<div class="crl-url">' + escapeHtml(window.location.origin + '/crl/' + ca.id + '.crl') + '</div>')
      : '') +
    infoItem('Exported CRL', crlStatusBadge(ca.crl_next_update)) +
    infoItem('Status', expired
      ? '<span class="badge badge-expired">Expired</span>'
      : '<span class="badge badge-active">Active</span>');

  updateCaPasswordVisibility();
  loadCerts(caId);
  loadCAs();
}

async function loadCerts(caId) {
  const res = await api('/api/ca/' + caId + '/certs');
  const certs = await res.json();
  const tbody = document.getElementById('certTableBody');
  const noCerts = document.getElementById('noCerts');

  if (certs.length === 0) {
    document.getElementById('certCountNote').textContent = '';
    tbody.innerHTML = '';
    noCerts.classList.remove('hidden');
    document.getElementById('certTableContainer').querySelector('table').classList.add('hidden');
    return;
  }

  noCerts.classList.add('hidden');
  const revokedCount = certs.filter(c => c.revoked).length;
  document.getElementById('certCountNote').textContent =
    certs.length + (certs.length === 1 ? ' entry' : ' entries') + (revokedCount ? ' · ' + revokedCount + ' revoked' : '');
  document.getElementById('certTableContainer').querySelector('table').classList.remove('hidden');

  closeImportHelp();
  certIndex.clear();
  certs.forEach(c => certIndex.set(c.id, c));
  tbody.innerHTML = certs.map(c => {
    const tmplLabel = TEMPLATE_LABELS[c.template] || c.template || 'Web Server';
    return '<tr' + (c.revoked ? ' class="revoked"' : '') + '>' +
      '<td><button type="button" class="cert-link" data-action="viewCert" data-arg="' + c.id + '">' + escapeHtml(c.common_name) + '</button></td>' +
      '<td>' + escapeHtml(tmplLabel) + '</td>' +
      '<td class="sans" title="' + escapeHtml(c.san_domains) + '">' + escapeHtml(c.san_domains) + '</td>' +
      '<td>' + escapeHtml(algoShort(c.algorithm)) + '</td>' +
      '<td>' + formatDate(c.not_after) + '</td>' +
      '<td>' + certStatusBadge(c.not_after, c.revoked) + '</td>' +
      '<td>' + crlDpBadge(c.crl_dp) + '</td>' +
      '<td><div class="row-actions">' +
        '<button class="btn btn-ghost btn-sm" data-action="viewCert" data-arg="' + c.id + '\">View</button> ' +
        '<button class="btn btn-ghost btn-sm" data-action="showExportCert" data-arg="' + c.id + '\">Export</button> ' +
        (!c.revoked ? '<button type="button" class="import-chip" data-action="toggleImportHelp" data-arg="' + c.id + '" aria-haspopup="dialog" aria-expanded="false">Endpoint import ▾</button> ' : '') +
        (!c.revoked ? '<button class="btn btn-ghost btn-sm" data-action="revokeCert" data-arg="' + c.id + '\">Revoke</button> ' : '') +
        '<button class="btn btn-danger btn-sm" data-action="deleteCert" data-arg="' + c.id + '\">Delete</button>' +
      '</div></td></tr>';
  }).join('');
}

function lifetimeDaysFromInputs(valueId, unitId) {
  const value = parseInt(document.getElementById(valueId).value);
  const unit = document.getElementById(unitId).value;
  return unit === 'years' ? value * 365 : value;
}

async function createCA() {
  const domain = document.getElementById('caDomain').value.trim();
  if (!domain) { toast('Domain is required', 'error'); return; }

  try {
    const res = await api('/api/ca', {
      method: 'POST',
      body: JSON.stringify({
        domain,
        name: document.getElementById('caName').value.trim(),
        algorithm: document.getElementById('caAlgorithm').value,
        lifetime_days: lifetimeDaysFromInputs('caLifetime', 'caLifetimeUnit'),
      }),
    });
    const ca = await res.json();
    hideModal('createCAModal');
    document.getElementById('caDomain').value = '';
    document.getElementById('caName').value = '';
    toast('CA created: ' + ca.name);
    selectCA(ca.id);
  } catch (e) {
    toast(e.message, 'error');
  }
}

async function deleteCurrentCA() {
  if (!currentCAId) return;
  if (!confirm('Delete this CA and all its certificates?')) return;
  try {
    await api('/api/ca/' + currentCAId, { method: 'DELETE' });
    currentCAId = null;
    document.getElementById('caView').classList.add('hidden');
    document.getElementById('welcomeView').classList.remove('hidden');
    toast('CA deleted');
    loadCAs();
  } catch (e) {
    toast(e.message, 'error');
  }
}

function showCreateIntermediate() {
  document.getElementById('intermediateParent').value = document.getElementById('caViewTitle').textContent;
  showModal('createIntermediateModal');
  document.getElementById('intermediateDomain').focus();
}

async function createIntermediate() {
  const domain = document.getElementById('intermediateDomain').value.trim();
  if (!domain) { toast('Domain is required', 'error'); return; }

  try {
    const res = await api('/api/ca/' + currentCAId + '/intermediate', {
      method: 'POST',
      body: JSON.stringify({
        domain,
        name: document.getElementById('intermediateName').value.trim(),
        algorithm: document.getElementById('intermediateAlgorithm').value,
        lifetime_days: lifetimeDaysFromInputs('intermediateLifetime', 'intermediateLifetimeUnit'),
      }),
    });
    const ca = await res.json();
    hideModal('createIntermediateModal');
    document.getElementById('intermediateDomain').value = '';
    document.getElementById('intermediateName').value = '';
    toast('Intermediate CA created: ' + ca.name);
    selectCA(ca.id);
  } catch (e) {
    toast(e.message, 'error');
  }
}

function onTemplateChange() {
  const tmpl = document.getElementById('certTemplate').value;
  document.getElementById('templateDesc').textContent = TEMPLATE_DESCS[tmpl] || '';
  const showEmail = tmpl === 'email' || tmpl === 'user';
  document.getElementById('emailRow').style.display = showEmail ? '' : 'none';
  if (!showEmail) document.getElementById('certEmail').value = '';
  document.getElementById('upnRow').style.display = tmpl === 'user' ? '' : 'none';
  if (tmpl !== 'user') document.getElementById('certUPN').value = '';
}

async function issueCert() {
  const cn = document.getElementById('certCN').value.trim();
  if (!cn) { toast('Common name is required', 'error'); return; }

  const template = document.getElementById('certTemplate').value;
  const email = document.getElementById('certEmail').value.trim();
  const upn = document.getElementById('certUPN').value.trim();
  const crlDp = document.getElementById('certIncludeCRL').checked ? document.getElementById('certCrlDp').value : 'none';

  try {
    const res = await api('/api/ca/' + currentCAId + '/certs', {
      method: 'POST',
      body: JSON.stringify({
        common_name: cn,
        san_domains: document.getElementById('certSANs').value.trim() || cn,
        algorithm: document.getElementById('certAlgorithm').value,
        lifetime_days: lifetimeDaysFromInputs('certLifetime', 'certLifetimeUnit'),
        template: template,
        email: email || undefined,
        upn: upn || undefined,
        crl_dp: crlDp,
        crl_base_url: crlDp === 'server' ? document.getElementById('certCrlBaseUrl').value.trim() : undefined,
      }),
    });
    const cert = await res.json();
    hideModal('issueCertModal');
    document.getElementById('certCN').value = '';
    document.getElementById('certSANs').value = '';
    document.getElementById('certEmail').value = '';
    document.getElementById('certUPN').value = '';
    document.getElementById('certIncludeCRL').checked = false;
    updateCrlDpFields();
    toast('Certificate issued: ' + cert.common_name);
    selectCA(currentCAId);  // also refreshes the CA's published CRL
  } catch (e) {
    toast(e.message, 'error');
  }
}

function showExportCert(certId) {
  exportCertId = certId;
  document.getElementById('certExportFormat').value = 'pkcs12';
  document.getElementById('certExportPart').value = 'both';
  document.getElementById('certExportPassword').value = 'changeit';
  document.getElementById('certExportChain').checked = false;
  updateCertPasswordVisibility();
  showModal('exportCertModal');
}

let viewCertId = null;

function certStatusBadge(notAfter, revoked) {
  const daysLeft = Math.ceil((new Date(notAfter) - new Date()) / 86400000);
  if (revoked) return '<span class="badge badge-revoked">Revoked</span>';
  if (daysLeft < 0) return '<span class="badge badge-expired">Expired</span>';
  if (daysLeft <= EXPIRY_WARNING_DAYS) return '<span class="badge badge-expired">Expires in ' + daysLeft + 'd</span>';
  return '<span class="badge badge-active">Active</span>';
}

// Where a certificate tells clients to check revocation, and whether anything answers there.
const CRL_DP_LABELS = {
  none: ['badge-algo', 'None', 'No distribution point: clients can only learn of a revocation from a CRL you import yourself.'],
  placeholder: ['badge-expired', 'Placeholder', 'Placeholder URL: nothing answers there. Import the exported CRL on each machine.'],
  server_live: ['badge-active', 'This server', 'Served by this server, which keeps the CRL current automatically.'],
  server_pending: ['badge-expired', 'Not published', 'Points at this server, but no CRL is published yet. It publishes once the database is unlocked.'],
  other: ['badge-algo', 'External', 'Points at an address this app does not manage.'],
};

function crlDpKey(dp) {
  if (!dp) return 'none';
  if (dp.kind === 'server') return dp.published ? 'server_live' : 'server_pending';
  return CRL_DP_LABELS[dp.kind] ? dp.kind : 'other';
}

function crlDpBadge(dp) {
  const [cls, label, note] = CRL_DP_LABELS[crlDpKey(dp)];
  return '<span class="badge ' + cls + '" title="' + escapeHtml(note) + '">' + escapeHtml(label) + '</span>';
}

function crlDpDetail(dp) {
  const [, , note] = CRL_DP_LABELS[crlDpKey(dp)];
  return crlDpBadge(dp) + (dp && dp.url ? '<div class="mono">' + escapeHtml(dp.url) + '</div>' : '') +
    '<div class="dim crl-note">' + escapeHtml(note) + '</div>' +
    (dp && dp.kind === 'server' ? '<div class="crl-probe dim" id="crlProbe"></div>' : '');
}

// Ask the distribution point for its CRL, when the page's CSP lets us (same origin only).
async function probeCrlDp(dp) {
  const out = document.getElementById('crlProbe');
  if (!out || !dp || !dp.url) return;
  let url;
  try { url = new URL(dp.url); } catch { return; }
  if (url.origin !== window.location.origin) {
    out.textContent = 'Reachability: can\'t check from this page (' + url.origin + ' is a different address).';
    return;
  }
  out.textContent = 'Reachability: checking…';
  try {
    const res = await fetch(url.pathname, { method: 'HEAD', credentials: 'omit', cache: 'no-store' });
    out.textContent = res.ok
      ? 'Reachability: answers from this browser (HTTP ' + res.status + ').'
      : 'Reachability: failed, HTTP ' + res.status + (res.status === 404 ? '. No CRL is published yet.' : '.');
  } catch {
    out.textContent = 'Reachability: no answer from ' + url.origin + '.';
  }
}

function formatDateTime(iso) {
  if (!iso) return '-';
  return new Date(iso).toLocaleString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', timeZoneName: 'short',
  });
}

function detailRows(rows) {
  return '<dl class="cert-detail">' + rows.map(([label, value]) =>
    '<dt>' + escapeHtml(label) + '</dt><dd>' + value + '</dd>').join('') + '</dl>';
}

function detailSection(title, rows) {
  return rows.length ? '<div class="card"><h3>' + escapeHtml(title) + '</h3>' + detailRows(rows) + '</div>' : '';
}

// The viewer's sections as HTML; every value from the certificate is escaped.
function certDetailHtml(d) {
  const issuerCA = caIndex.get(d.ca_id);
  const nameRows = (attrs) => attrs.map(a => [a.name, escapeHtml(a.value)]);
  const general = [
    ['Status', certStatusBadge(d.not_after, d.revoked) +
      (d.revoked && d.revoked_at ? ' <span class="dim">on ' + escapeHtml(formatDateTime(d.revoked_at)) + '</span>' : '')],
    ['Issued by', escapeHtml(issuerCA ? issuerCA.name : d.issuer.map(a => a.value).join(', '))],
    ['Valid from', escapeHtml(formatDateTime(d.not_before))],
    ['Valid until', escapeHtml(formatDateTime(d.not_after))],
    ['Serial number', '<span class="mono">' + escapeHtml(d.serial) + '</span>'],
    ['Version', 'v' + escapeHtml(d.version)],
    ['Public key', escapeHtml(d.public_key)],
    ['Signature', escapeHtml(d.signature_algorithm)],
    ['CRL', crlDpDetail(d.crl_dp)],
  ];
  const extensions = d.extensions.map(e => [
    e.name + (e.critical ? ' (critical)' : ''),
    e.values.length ? e.values.map(v => '<div>' + escapeHtml(v) + '</div>').join('') : '<span class="dim">—</span>',
  ]);
  const fingerprints = [
    ['SHA-256', '<span class="mono">' + escapeHtml(d.fingerprints.sha256) + '</span>'],
    ['SHA-1', '<span class="mono">' + escapeHtml(d.fingerprints.sha1) + '</span>'],
  ];
  return detailSection('General', general) +
    detailSection('Subject', nameRows(d.subject)) +
    detailSection('Issuer', nameRows(d.issuer)) +
    detailSection('Extensions', extensions) +
    detailSection('Fingerprints', fingerprints);
}

async function viewCert(certId) {
  try {
    const res = await api('/api/certs/' + certId + '/details');
    const d = await res.json();
    viewCertId = certId;
    document.getElementById('certViewEyebrow').textContent =
      (TEMPLATE_LABELS[d.template] || d.template || 'Certificate') + ' · No. ' + shortSerial(d.serial);
    document.getElementById('certViewTitle').textContent = d.common_name;
    document.getElementById('certViewBody').innerHTML = certDetailHtml(d);
    probeCrlDp(d.crl_dp);
    document.getElementById('certViewPem').value = d.pem;
    await renderCertCrl();
    showModal('viewCertModal');
  } catch (e) {
    toast(e.message, 'error');
  }
}

async function renderCertCrl() {
  const box = document.getElementById('certViewCrl');
  const show = document.getElementById('certViewShowCrl').checked;
  box.classList.toggle('hidden', !show);
  if (!show || !viewCertId) return;
  box.innerHTML = '';
  try {
    const res = await api('/api/certs/' + viewCertId + '/crl');
    const c = await res.json();
    const [cls, label, note] = c.cert_revoked
      ? ['badge-revoked', 'Revoked', c.published_path
          ? 'Listed in the CRL this server publishes.'
          : 'Listed in this CA\'s CRL. Export it and import it on machines that should stop trusting this certificate.']
      : ['badge-active', 'Not revoked', 'This certificate is not on the CRL.'];
    const revoked = c.revoked.length
      ? c.revoked.map(r => '<div class="crl-entry' + (r.this ? ' crl-this' : '') + '">' + escapeHtml(r.serial) +
          '<div class="dim">revoked ' + escapeHtml(formatDateTime(r.revoked_at)) + (r.this ? ' · this certificate' : '') + (r.deleted ? ' · deleted certificate' : '') +
          '</div></div>').join('')
      : '<span class="dim">None</span>';
    box.innerHTML = detailSection('Revocation (CRL)', [
      ['This certificate', '<span class="badge ' + cls + '">' + escapeHtml(label) + '</span>' +
        (note ? '<div class="dim crl-note">' + escapeHtml(note) + '</div>' : '')],
      ['Issuing CA', escapeHtml(c.ca_name)],
      ['Distribution point', c.distribution_points.length
        ? c.distribution_points.map(u => '<div>' + escapeHtml(u) + '</div>').join('')
        : '<span class="dim">None in this certificate — clients won\'t check a CRL automatically</span>'],
      ['Published here', c.published_path
        ? '<span class="mono">' + escapeHtml(window.location.origin + c.published_path) + '</span>'
        : c.served
          ? '<span class="dim">Not yet: it publishes at /crl/' + escapeHtml(c.ca_id) + '.crl once the database is unlocked</span>'
          : '<span class="dim">No — none of this CA\'s certificates use this server as their distribution point</span>'],
      ['Next update', c.published_path ? servedCrlBadge(c.served_next_update) : crlStatusBadge(c.next_update)],
      ['Revoked serials (' + c.revoked.length + ')', revoked],
    ]) + '<p><button class="btn btn-ghost btn-sm" data-action="viewCRL" data-arg="' + escapeHtml(c.ca_id) + '">Open in CRL viewer</button></p>';
  } catch (e) {
    box.innerHTML = '<p class="dim">' + escapeHtml(e.message) + '</p>';
  }
}

function toggleCertCrl() {
  renderCertCrl();
}

async function copyCertPem() {
  try {
    await navigator.clipboard.writeText(document.getElementById('certViewPem').value);
    toast('Certificate PEM copied');
  } catch {
    toast('Copy failed', 'error');
  }
}

function exportFromCertView() {
  hideModal('viewCertModal');
  showExportCert(viewCertId);
}

async function doExportCert() {
  const fmt = document.getElementById('certExportFormat').value;
  const part = document.getElementById('certExportPart').value;
  const password = document.getElementById('certExportPassword').value;
  const includeChain = document.getElementById('certExportChain').checked;
  await saveExport('/api/export/cert/' + exportCertId, { format: fmt, part, password: password || undefined, include_chain: includeChain });
  hideModal('exportCertModal');
}

async function exportCA() {
  const fmt = document.getElementById('caExportFormat').value;
  const part = document.getElementById('caExportPart').value;
  const password = document.getElementById('caExportPassword').value;
  await saveExport('/api/export/ca/' + currentCAId, { format: fmt, part, password: password || undefined });
}

async function exportCRL() {
  if (!currentCAId) return;
  const days = document.getElementById('crlLifetime').value;
  try {
    const res = await api('/api/ca/' + currentCAId + '/crl?days=' + encodeURIComponent(days));
    const result = await handleExportResponse(res);
    if (result.nextUpdate) {
      toast('CRL valid until ' + formatDate(result.nextUpdate) + '. Re-export and re-import before then.');
    }
    selectCA(currentCAId);
  } catch (e) {
    toast(e.message, 'error');
  }
}

const CRL_WARNING_DAYS = 30;

function crlStatusBadge(nextUpdate) {
  if (!nextUpdate) return '<span class="badge badge-algo">Not exported</span>';
  const daysLeft = (new Date(nextUpdate) - new Date()) / 86400000;
  const label = escapeHtml(formatDate(nextUpdate));
  if (daysLeft < 0) return '<span class="badge badge-expired">Expired ' + label + '</span>';
  if (daysLeft < CRL_WARNING_DAYS) return '<span class="badge badge-revoked">' + label + ' (re-export soon)</span>';
  return '<span class="badge badge-active">' + label + '</span>';
}

function updateCaPasswordVisibility() {
  const fmt = document.getElementById('caExportFormat').value;
  const part = document.getElementById('caExportPart').value;
  const show = part === 'both' && fmt !== 'der' && fmt !== 'crt';
  document.getElementById('caExportPassword').style.display = show ? '' : 'none';
  document.getElementById('caExportPasswordNote').style.display = show ? '' : 'none';
  if (!show) document.getElementById('caExportPassword').value = '';
  else if (!document.getElementById('caExportPassword').value) document.getElementById('caExportPassword').value = 'changeit';
}

function filenameFromDisposition(header) {
  const encoded = /filename\*=UTF-8''([^;]+)/i.exec(header);
  if (encoded) return decodeURIComponent(encoded[1]);
  const plain = /filename="?([^";]+)"?/i.exec(header);
  return plain ? plain[1] : 'download';
}

// Server mode streams the file back; desktop mode saves it and returns the path.
// Returns { name, nextUpdate } for callers that show extra details.
async function handleExportResponse(res) {
  if (!SERVER_MODE) {
    const result = await res.json();
    toast('Saved to ' + result.path);
    return { name: result.path, nextUpdate: result.next_update };
  }
  const nextUpdate = res.headers.get('X-Next-Update');
  const name = filenameFromDisposition(res.headers.get('Content-Disposition') || '');
  const url = URL.createObjectURL(await res.blob());
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
  toast('Downloaded ' + name);
  return { name, nextUpdate };
}

async function saveExport(url, body) {
  try {
    const res = await api(url, { method: 'POST', body: JSON.stringify(body) });
    await handleExportResponse(res);
  } catch (e) {
    toast(e.message, 'error');
  }
}

async function revokeCert(certId) {
  if (!confirm('Revoke this certificate?')) return;
  let result;
  try {
    result = await (await api('/api/certs/' + certId + '/revoke', { method: 'POST' })).json();
  } catch (e) {
    toast(e.message, 'error');
    return;
  }
  selectCA(currentCAId);
  // Served CRLs are republished by the server; anything else needs a CRL imported by hand.
  if (!result.download_crl) {
    toast('Certificate revoked. ' + result.note);
  } else if (confirm('Certificate revoked. ' + result.note + '\n\nDownload the updated CRL now?')) {
    await exportCRL();
  }
}

function servedCrlBadge(nextUpdate) {
  if (!nextUpdate) return '<span class="badge badge-expired">Not published</span>';
  const overdue = new Date(nextUpdate) < new Date();
  return (overdue
    ? '<span class="badge badge-expired">Overdue: unlock the database</span>'
    : '<span class="badge badge-active">Renews automatically</span>') +
    ' <span class="dim">next update ' + escapeHtml(formatDateTime(nextUpdate)) + '</span>';
}

// ── CRL viewer ──────────────────────────────────────────────────────
async function viewCRL(caId) {
  const id = typeof caId === 'number' ? caId : currentCAId;
  if (!id) return;
  let c;
  try {
    c = await (await api('/api/ca/' + id + '/crl/view')).json();
  } catch (e) {
    toast(e.message, 'error');
    return;
  }
  const crl = c.crl;
  document.getElementById('crlViewEyebrow').textContent = crl ? 'Published CRL' : 'Revocations (not published here)';
  document.getElementById('crlViewTitle').textContent = c.ca_name;
  const general = crl ? [
    ['Issuer', escapeHtml(crl.issuer.map(a => a.value).join(', '))],
    ['This update', escapeHtml(formatDateTime(crl.last_update))],
    ['Next update', servedCrlBadge(crl.next_update)],
    ['Signature', escapeHtml(crl.signature_algorithm)],
    ['Served at', '<span class="mono">' + escapeHtml(window.location.origin + c.published_path) + '</span>'],
  ] : [
    ['Published', '<span class="dim">No. None of this CA\'s certificates use this server as their distribution point, ' +
      'so clients get revocations from a CRL you export and import.</span>'],
    ['Last export', crlStatusBadge(c.exported_next_update)],
  ];
  if (c.out_of_date) {
    general.push(['Status', '<span class="badge badge-expired">Out of date</span> ' +
      '<span class="dim">Revocations since this CRL was signed publish once the database is unlocked.</span>']);
  }
  const entries = c.entries.length
    ? c.entries.map(e => '<div class="crl-entry"><span class="mono">' + escapeHtml(e.serial) + '</span>' +
        '<div class="dim">revoked ' + escapeHtml(formatDateTime(e.revoked_at)) +
        (e.cert_id
          ? ' · <a href="#" data-action="viewCertFromCrl" data-arg="' + escapeHtml(e.cert_id) + '">' + escapeHtml(e.common_name) + '</a>'
          : '') +
        (e.deleted ? ' · deleted certificate' : '') + '</div></div>').join('')
    : '<span class="dim">None</span>';
  const fingerprints = crl ? [
    ['SHA-256', '<span class="mono">' + escapeHtml(crl.fingerprints.sha256) + '</span>'],
    ['SHA-1', '<span class="mono">' + escapeHtml(crl.fingerprints.sha1) + '</span>'],
  ] : [];
  document.getElementById('crlViewBody').innerHTML = detailSection('General', general) +
    detailSection('Revoked certificates (' + c.entries.length + ')', [['Entries', entries]]) +
    detailSection('Fingerprints', fingerprints);
  document.getElementById('crlViewPemCard').hidden = !crl;
  document.getElementById('crlViewCopyBtn').hidden = !crl;
  document.getElementById('crlViewPem').value = crl ? crl.pem : '';
  showModal('viewCrlModal');
}

function viewCertFromCrl(certId) {
  hideModal('viewCrlModal');
  viewCert(certId);
  return false;
}

async function copyCrlPem() {
  try {
    await navigator.clipboard.writeText(document.getElementById('crlViewPem').value);
    toast('CRL PEM copied');
  } catch {
    toast('Copy failed', 'error');
  }
}

async function deleteCert(certId) {
  let revoked = false;
  try {
    revoked = Boolean((await (await api('/api/certs/' + certId)).json()).revoked);
  } catch (e) {
    toast(e.message, 'error');
    return;
  }
  const question = revoked
    ? 'Permanently delete this certificate? It stays on the CA\'s CRL until it expires.'
    : 'This certificate is not revoked, so clients keep trusting it until it expires even after you delete it. ' +
      'Revoke it first to put it on the CRL.\n\nDelete it anyway?';
  if (!confirm(question)) return;
  try {
    await api('/api/certs/' + certId, { method: 'DELETE' });
    toast('Certificate deleted');
    loadCerts(currentCAId);
  } catch (e) {
    toast(e.message, 'error');
  }
}

function updateCertPasswordVisibility() {
  const fmt = document.getElementById('certExportFormat').value;
  const part = document.getElementById('certExportPart').value;
  const showPw = part === 'both' && fmt !== 'der' && fmt !== 'crt';
  document.getElementById('pfxPasswordRow').style.display = showPw ? '' : 'none';
  if (!showPw) document.getElementById('certExportPassword').value = '';
  else if (!document.getElementById('certExportPassword').value) document.getElementById('certExportPassword').value = 'changeit';
  const showChain = (part === 'both' || part === 'chain') && fmt !== 'der' && fmt !== 'crt';
  document.getElementById('chainRow').style.display = showChain ? '' : 'none';
  if (!showChain) document.getElementById('certExportChain').checked = false;
}
document.getElementById('certExportFormat').addEventListener('change', updateCertPasswordVisibility);
document.getElementById('certCrlBaseUrl').addEventListener('input', updateCrlDpFields);
document.getElementById('certExportPart').addEventListener('change', updateCertPasswordVisibility);

function infoItem(label, value, cls = '') {
  return '<div class="info-item' + (cls ? ' ' + cls : '') + '"><label>' + label + '</label><span>' + value + '</span></div>';
}

function serialToggle(serial) {
  const esc = escapeHtml(serial);
  const short = escapeHtml(serial.substring(0, 16)) + '…';
  return '<span class="serial-toggle" data-full="' + esc + '" data-short="' + escapeHtml(short) + '" data-action="toggleSerial" title="Click to expand">' + short + '</span>';
}

function toggleSerial(_arg, el) {
  const expanded = el.dataset.expanded === '1';
  el.textContent = expanded ? el.dataset.short : el.dataset.full;
  el.dataset.expanded = expanded ? '' : '1';
}

function formatDate(iso) {
  if (!iso) return '-';
  const d = new Date(iso);
  return d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
}

function escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ── Import help: per-OS commands for an issued certificate ─────────

const MACHINE_TEMPLATES = new Set(['web-server', 'computer']);
let importState = null;  // { certId, os, anchor, steps }
let lastImportOs = null;  // the tab last used, kept for the next popover

function defaultImportOs() {
  const platform = (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || '';
  if (/win/i.test(platform)) return 'windows';
  if (/mac/i.test(platform)) return 'macos';
  return 'linux';
}

// The name the server gives a download (web.safe_filename), so the commands match the files.
function exportFileName(name) {
  const cleaned = String(name).replace(/[<>:"/\\|?*\x00-\x1f]/g, '_').replace(/^[. ]+|[. ]+$/g, '');
  return cleaned || 'export';
}

// Quote for PowerShell and POSIX shells, so an odd name can't break out of the string.
// The server's pki._safe_name, used in CA export names.
const safeName = (s) => String(s).replace(/[^a-zA-Z0-9_.-]/g, '_');

const psQuote = (s) => "'" + String(s).replace(/'/g, "''") + "'";
const shQuote = (s) => "'" + String(s).replace(/'/g, "'\\''") + "'";
const winPath = (file) => '(Join-Path $HOME ' + psQuote('Downloads\\' + file) + ')';
const nixPath = (file) => '~/Downloads/' + shQuote(file);

// The issuing CA first, the root last.
function caChain(caId) {
  const chain = [];
  const seen = new Set();
  let ca = caIndex.get(caId);
  while (ca && !seen.has(ca.id)) {
    seen.add(ca.id);
    chain.push(ca);
    ca = ca.parent_ca_id ? caIndex.get(ca.parent_ca_id) : null;
  }
  return chain;
}

function importWindows(cert, root, intermediates, files, withTrust) {
  const machine = MACHINE_TEMPLATES.has(cert.template);
  const store = machine ? 'LocalMachine' : 'CurrentUser';
  if (!withTrust) intermediates = [];
  const steps = withTrust ? [{ label: 'Trust the root CA (once per machine)',
    code: 'Import-Certificate -FilePath ' + winPath(files.caDer(root)) + ' -CertStoreLocation Cert:\\LocalMachine\\Root' }] : [];
  if (intermediates.length) {
    steps.push({ label: 'Intermediate CA' + (intermediates.length > 1 ? 's' : ''),
      code: intermediates.map(ca => 'Import-Certificate -FilePath ' + winPath(files.caDer(ca)) + ' -CertStoreLocation Cert:\\LocalMachine\\CA').join('\n') });
  }
  steps.push({ label: 'Certificate and key',
    code: '$pw = Read-Host -AsSecureString ' + psQuote('PFX password') + '\n' +
      'Import-PfxCertificate -FilePath ' + winPath(files.pfx) + ' -CertStoreLocation Cert:\\' + store + '\\My -Password $pw' });
  if (cert.template === 'code-signing') {
    steps.push({ label: 'On machines that run the signed code',
      code: 'Import-Certificate -FilePath ' + winPath(files.der) + ' -CertStoreLocation Cert:\\LocalMachine\\TrustedPublisher' });
  }
  return {
    where: (machine || withTrust || cert.template === 'code-signing' ? 'PowerShell as Administrator · ' : 'PowerShell · ') +
      (withTrust ? 'root → Trusted Root Certification Authorities' +
        (intermediates.length ? ', intermediate → Intermediate Certification Authorities' : '') + ', ' : '') +
      'certificate → ' + (machine ? 'Local Computer' : 'Current User') + ' › Personal' +
      (cert.template === 'code-signing' ? ', publisher → Trusted Publishers' : ''),
    steps,
    hint: 'Export ' + (withTrust ? 'each CA as DER (Certificate Only) and ' : '') + 'this certificate as PKCS12 (.pfx)' +
      (cert.template === 'code-signing' ? ' and DER (Certificate Only)' : '') + ' first.',
  };
}

function importMac(cert, root, intermediates, files, withTrust) {
  const machine = MACHINE_TEMPLATES.has(cert.template);
  const keychain = machine ? '/Library/Keychains/System.keychain' : '~/Library/Keychains/login.keychain-db';
  if (!withTrust) intermediates = [];
  const steps = withTrust ? [{ label: 'Trust the root CA (admin)',
    code: 'sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ' + nixPath(files.caDer(root)) }] : [];
  if (intermediates.length) {
    steps.push({ label: 'Intermediate CA' + (intermediates.length > 1 ? 's' : ''),
      code: intermediates.map(ca => 'sudo security add-certificates -k /Library/Keychains/System.keychain ' + nixPath(files.caDer(ca))).join('\n') });
  }
  steps.push({ label: 'Certificate and key (asks for the PFX password)',
    code: (machine ? 'sudo ' : '') + 'security import ' + nixPath(files.pfx) + ' -k ' + keychain +
      (cert.template === 'code-signing' ? ' -T /usr/bin/codesign' : '') });
  return {
    where: 'Terminal · ' + (withTrust ? 'CAs → System keychain, ' : '') + 'certificate → ' + (machine ? 'System keychain' : 'your login keychain'),
    steps,
    hint: 'Export ' + (withTrust ? 'each CA as DER (Certificate Only) and ' : '') + 'this certificate as PKCS12 (.pfx) first.',
  };
}

function importLinux(cert, root, files, withTrust) {
  const rootPem = nixPath(files.caPem(root));
  const anchor = shQuote('cert-generator-' + safeName(root.name) + '.crt');
  const steps = withTrust ? [
    { label: 'Trust the root CA — Debian / Ubuntu',
      code: 'sudo cp ' + rootPem + ' /usr/local/share/ca-certificates/' + anchor + ' && sudo update-ca-certificates' },
    { label: 'Trust the root CA — RHEL / Fedora',
      code: 'sudo cp ' + rootPem + ' /etc/pki/ca-trust/source/anchors/' + anchor + ' && sudo update-ca-trust' },
  ] : [];
  const rootHint = withTrust ? 'the root CA as PEM (Certificate Only), and ' : '';
  let hint = withTrust ? 'Export the root CA as PEM (Certificate Only) first.' : 'Nothing to install for this certificate on Linux.';
  if (MACHINE_TEMPLATES.has(cert.template)) {
    const base = exportFileName(cert.common_name);
    steps.push({ label: 'Certificate chain and key',
      code: 'sudo install -m 644 ' + nixPath(files.fullchain) + ' /etc/ssl/certs/' + shQuote(base + '.pem') + '\n' +
        'sudo install -m 600 ' + nixPath(files.key) + ' /etc/ssl/private/' + shQuote(base + '.key') });
    hint = 'Export ' + rootHint + 'this certificate as Full Chain and as Private Key Only (PEM). Point nginx or Apache at these paths.';
  } else if (cert.template === 'code-signing') {
    hint = 'Export this certificate as PKCS12 (.pfx) for your signing tool, such as osslsigncode.';
  } else {
    steps.push({ label: 'Certificate and key — Chrome / Chromium',
      code: 'pk12util -d sql:$HOME/.pki/nssdb -i ' + nixPath(files.pfx) });
    hint = 'Export ' + rootHint + 'this certificate as PKCS12 (.pfx). Firefox: Settings › Certificates › Import.';
  }
  const where = [withTrust && 'root → the system CA bundle', MACHINE_TEMPLATES.has(cert.template) && 'certificate → /etc/ssl'].filter(Boolean);
  return { where: 'Shell' + (where.length ? ' · ' + where.join(', ') : ''), steps, hint };
}

function importHelp(cert, os, withTrust) {
  const chain = caChain(currentCAId);
  if (!chain.length) return null;
  const root = chain[chain.length - 1];
  const intermediates = chain.slice(0, -1).reverse();  // top-down, the order Windows and macOS want them
  const cn = exportFileName(cert.common_name);
  const files = {
    pfx: exportFileName(cert.common_name + '-certificate.pfx'),
    der: exportFileName(cert.common_name + '-certificate.der'),
    fullchain: exportFileName(cert.common_name + '-fullchain.pem'),
    key: exportFileName(cert.common_name + '-private_key.pem'),
    caDer: (ca) => exportFileName('ca-' + safeName(ca.name) + '-certificate.der'),
    caPem: (ca) => exportFileName('ca-' + safeName(ca.name) + '-certificate.pem'),
  };
  const help = os === 'windows' ? importWindows(cert, root, intermediates, files, withTrust)
    : os === 'macos' ? importMac(cert, root, intermediates, files, withTrust)
    : importLinux(cert, root, files, withTrust);
  help.title = 'Install ' + cn + ' (' + (TEMPLATE_LABELS[cert.template] || cert.template) + ')';
  // The files the commands expect, and where they come from.
  const caFormat = os === 'linux' ? 'pem' : 'der';
  const caFiles = !withTrust ? [] : (os === 'linux' ? [root] : [root, ...intermediates]).map(ca => ({
    caId: ca.id,
    role: ca === root ? 'Root CA' : 'Intermediate CA',
    name: ca.name,
    file: caFormat === 'pem' ? files.caPem(ca) : files.caDer(ca),
    how: 'Or select ' + ca.name + ' in the sidebar → Export: ' + caFormat.toUpperCase() + ', Certificate Only → Download.',
  }));
  const linuxServer = os === 'linux' && MACHINE_TEMPLATES.has(cert.template);
  help.files = { cas: caFiles,
    cert: { file: linuxServer ? files.fullchain + ' + ' + files.key : files.pfx,
      how: linuxServer ? 'Export twice: Full Chain (cert + CA), then Private Key Only, both PEM.'
        : 'Export as PKCS12 (.pfx), Certificate + Key' + (cert.template === 'code-signing' && os === 'windows' ? '; and once more as DER, Certificate Only.' : '.') } };
  help.question = 'Has ' + root.name + (intermediates.length ? ' and its intermediate' + (intermediates.length > 1 ? 's' : '') : '') +
    ' already been imported on this machine?';
  return help;
}

function renderImportHelp() {
  const cert = certIndex.get(importState.certId);
  const answered = importState.trusted !== null;
  const help = cert && importHelp(cert, importState.os, importState.trusted === false);
  if (!help) { closeImportHelp(); return; }
  document.getElementById('importPopTitle').textContent = help.title;
  document.getElementById('importPopQuestion').textContent = help.question;
  document.querySelectorAll('#importPopAsk button').forEach((b) => {
    b.setAttribute('aria-pressed', String(answered && (b.dataset.arg === 'yes') === importState.trusted));
  });
  // Nothing to copy until the trust question is answered: the steps depend on it.
  document.getElementById('importPopWhere').textContent = answered ? help.where : '';
  document.getElementById('importPopHint').textContent = !answered ? 'Answer the question to see the steps.'
    : help.steps.length ? 'Get the files above, then run the steps in order.' : help.hint;
  document.getElementById('importPopCopy').disabled = !answered || !help.steps.length;
  if (!answered) help.steps = [];
  document.querySelectorAll('#importPop .os-tabs button').forEach((b) => {
    b.setAttribute('aria-selected', String(b.dataset.arg === importState.os));
  });
  const stepsEl = document.getElementById('importPopSteps');
  const filesEl = answered ? [importFilesBlock(help.files, cert)] : [];
  stepsEl.replaceChildren(...filesEl, ...help.steps.flatMap((step, i) => {
    const label = document.createElement('div');
    label.className = 'step';
    label.textContent = (i + 1) + ' · ' + step.label;
    const pre = document.createElement('pre');
    pre.textContent = step.code;
    return [label, pre];
  }));
  importState.steps = help.steps;
  positionImportHelp();
}

function importFileRow(title, file, how, button) {
  const row = document.createElement('div');
  row.className = 'import-file';
  const text = document.createElement('div');
  const strong = document.createElement('strong');
  strong.textContent = title;
  const name = document.createElement('code');
  name.textContent = file;
  const note = document.createElement('small');
  note.textContent = how;
  text.append(strong, ' → ', name, note);
  row.append(text, button);
  return row;
}

function importFilesBlock(files, cert) {
  const block = document.createElement('div');
  block.className = 'import-files';
  const label = document.createElement('div');
  label.className = 'step';
  label.textContent = 'First · get the files (into Downloads)';
  block.append(label);
  for (const ca of files.cas) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'btn btn-ghost btn-sm';
    btn.dataset.action = 'downloadImportCA';
    btn.dataset.arg = String(ca.caId);
    btn.textContent = 'Download';
    block.append(importFileRow(ca.role + ' · ' + ca.name, ca.file, ca.how, btn));
  }
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'btn btn-ghost btn-sm';
  btn.dataset.action = 'exportFromImport';
  btn.dataset.arg = String(cert.id);
  btn.textContent = 'Export…';
  block.append(importFileRow('This certificate', files.cert.file, files.cert.how, btn));
  return block;
}

async function downloadImportCA(caId) {
  if (!importState) return;
  const format = importState.os === 'linux' ? 'pem' : 'der';
  await saveExport('/api/export/ca/' + caId, { format, part: 'public' });
}

function exportFromImport(certId) {
  closeImportHelp();
  showExportCert(certId);
}

function positionImportHelp() {
  const pop = document.getElementById('importPop');
  const r = importState.anchor.getBoundingClientRect();
  const w = pop.offsetWidth;
  const h = pop.offsetHeight;
  const left = Math.min(Math.max(8, r.right - w), window.innerWidth - w - 8);
  let top = r.bottom + 8;
  if (top + h > window.innerHeight - 8) top = Math.max(8, r.top - h - 8);
  pop.style.left = left + 'px';
  pop.style.top = top + 'px';
}

function toggleImportHelp(certId, el) {
  const wasOpen = importState && importState.certId === certId;
  closeImportHelp();
  if (wasOpen) return;
  // The trust question is asked every time: the answer depends on the machine.
  importState = { certId, os: lastImportOs || defaultImportOs(), anchor: el, trusted: null };
  el.setAttribute('aria-expanded', 'true');
  document.getElementById('importPop').classList.remove('hidden');
  renderImportHelp();
}

function closeImportHelp() {
  if (!importState) return;
  importState.anchor.setAttribute('aria-expanded', 'false');
  document.getElementById('importPop').classList.add('hidden');
  lastImportOs = importState.os;
  importState = null;
}


function setImportTrusted(answer) {
  if (!importState) return;
  importState.trusted = answer === 'yes';
  renderImportHelp();
}

function setImportOs(os) {
  if (!importState) return;
  importState.os = os;
  renderImportHelp();
}

async function copyImportCommands() {
  if (!importState || !importState.steps.length) return;
  const text = importState.steps.map(s => '# ' + s.label + '\n' + s.code).join('\n\n') + '\n';
  try {
    await navigator.clipboard.writeText(text);
    toast('Import commands copied');
  } catch (e) {
    toast('Copy failed, select the commands and copy them by hand', 'error');
  }
}

document.addEventListener('click', (event) => {
  // Only a real click outside closes it: a download clicks a hidden link programmatically.
  if (event.isTrusted && importState && !event.target.closest('#importPop, .import-chip')) closeImportHelp();
});
document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && importState) {
    const anchor = importState.anchor;
    closeImportHelp();
    anchor.focus();
  }
});
window.addEventListener('resize', () => { if (importState) positionImportHelp(); });
document.addEventListener('scroll', () => { if (importState) positionImportHelp(); }, true);

function showGuideTab(tabId, btn) {
  document.querySelectorAll('.guide-content').forEach(el => el.classList.add('hidden'));
  document.querySelectorAll('.guide-tab').forEach(el => el.classList.remove('active'));
  document.getElementById(tabId).classList.remove('hidden');
  btn.classList.add('active');
}

function showGuide() {
  showGuideTab('guide-general', document.querySelector('.guide-tab'));
  showModal('guideModal');
}

// The Quick Start guide opens by itself once when there are no authorities yet,
// after any first-run dialog (sign-in prompt, recovery key) has been dealt with.
let quickStartPending = false;

function showQuickStartIfPending() {
  if (!quickStartPending) return;
  quickStartPending = false;
  showGuide();
}

function popOutGuide(kind) {
  const modal = kind === 'ssh' ? 'sshGuideModal' : 'guideModal';
  if (window.pywebview && window.pywebview.api && window.pywebview.api.open_guide) {
    window.pywebview.api.open_guide(kind);
  } else if (!window.open('/guide/' + kind, 'cert-generator-guide-' + kind, 'width=960,height=760')) {
    toast('Allow pop-ups for this site to open the guide in its own window', 'error');
    return;
  }
  hideModal(modal);
}

function openExternalLink(_arg, el, event) {
  return openExternal(event, el.href);
}

function openExternal(event, url) {
  event.preventDefault();
  if (window.pywebview && window.pywebview.api && window.pywebview.api.open_external) {
    window.pywebview.api.open_external(url);
  } else {
    window.open(url, '_blank');
  }
  return false;
}

function toggleSection(section) {
  const chevron = document.getElementById(section + 'Chevron');
  const list = document.getElementById(section === 'ca' ? 'caList' : 'sshList');
  const isOpen = chevron.classList.contains('open');
  chevron.classList.toggle('open', !isOpen);
  list.style.display = isOpen ? 'none' : '';
}

async function loadSSHKeys() {
  const res = await api('/api/ssh-keys');
  const keys = await res.json();
  const list = document.getElementById('sshList');
  list.innerHTML = '';
  document.getElementById('sshCount').textContent = keys.length;

  keys.forEach(k => {
    const li = document.createElement('li');
    li.className = 'ssh-item' + (k.id === currentSSHKeyId ? ' active' : '');
    const algoBadge = algoShort(k.algorithm);
    const importedBadge = k.imported ? '<span class="ca-type-badge imported">IMPORTED</span>' : '';
    li.innerHTML = '<svg class="ssh-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg><span class="ssh-name">' +
      escapeHtml(k.name) + '</span>' + importedBadge + '<span class="ca-type-badge">' + escapeHtml(algoBadge) + '</span>';
    li.onclick = () => selectSSHKey(k.id);
    list.appendChild(li);
  });
}

async function selectSSHKey(keyId) {
  closeMobileMenu();
  currentSSHKeyId = keyId;
  currentCAId = null;
  const res = await api('/api/ssh-keys/' + keyId);
  const key = await res.json();

  document.getElementById('welcomeView').classList.add('hidden');
  document.getElementById('caView').classList.add('hidden');
  document.getElementById('sshKeyView').classList.remove('hidden');
  document.getElementById('sshKeyViewTitle').textContent = key.name;
  document.getElementById('sshKeyViewEyebrow').textContent =
    'SSH key · ' + algoLong(key.algorithm) + (key.imported ? ' · imported' : '');
  document.getElementById('sshKeyViewChain').textContent = key.fingerprint;

  document.getElementById('sshKeyInfo').innerHTML =
    infoItem('Algorithm', '<span class="badge badge-algo">' + escapeHtml(algoLong(key.algorithm)) + '</span>') +
    infoItem('Source', key.imported ? '<span class="badge badge-accent">Imported</span>' : '<span class="badge badge-algo">Generated here</span>') +
    infoItem('Passphrase', key.has_passphrase ? '<span class="badge badge-active">Yes</span>' : '<span class="badge badge-expired">No</span>') +
    infoItem('Created', formatDate(key.created_at)) +
    infoItem('Fingerprint', escapeHtml(key.fingerprint), 'span-3') +
    infoItem('Comment', escapeHtml(key.comment || '(none)'));

  document.getElementById('sshPubKey').textContent = key.public_key || '';
  document.getElementById('sshOriginalPassphrase').value = '';
  document.getElementById('sshOriginalPassphrase').style.display = key.has_passphrase ? '' : 'none';
  document.getElementById('sshExportPassphrase').value = '';

  loadCAs();
  loadSSHKeys();
}

function showCreateSSHKey() {
  document.getElementById('sshKeyName').value = '';
  document.getElementById('sshKeyAlgorithm').value = 'rsa-4096';
  document.getElementById('sshKeyPassphrase').value = '';
  document.getElementById('sshKeyComment').value = '';
  showModal('createSSHKeyModal');
  document.getElementById('sshKeyName').focus();
}

async function generateSSHKey() {
  const name = document.getElementById('sshKeyName').value.trim();
  if (!name) { toast('Key name is required', 'error'); return; }

  try {
    const res = await api('/api/ssh-keys', {
      method: 'POST',
      body: JSON.stringify({
        name,
        algorithm: document.getElementById('sshKeyAlgorithm').value,
        passphrase: document.getElementById('sshKeyPassphrase').value || undefined,
        comment: document.getElementById('sshKeyComment').value.trim() || undefined,
      }),
    });
    const key = await res.json();
    hideModal('createSSHKeyModal');
    toast('SSH key generated: ' + key.name);
    selectSSHKey(key.id);
  } catch (e) {
    toast(e.message, 'error');
  }
}

function showImportSSHKey() {
  document.getElementById('importSSHKeyName').value = '';
  document.getElementById('importSSHKeyData').value = '';
  document.getElementById('importSSHKeyPassphrase').value = '';
  document.getElementById('importSSHKeyComment').value = '';
  showModal('importSSHKeyModal');
  document.getElementById('importSSHKeyName').focus();
}

async function importSSHKey() {
  const name = document.getElementById('importSSHKeyName').value.trim();
  const privateKey = document.getElementById('importSSHKeyData').value.trim();
  const passphrase = document.getElementById('importSSHKeyPassphrase').value || undefined;
  const comment = document.getElementById('importSSHKeyComment').value.trim() || undefined;

  if (!name) { toast('Key name is required', 'error'); return; }
  if (!privateKey) { toast('Private key is required', 'error'); return; }

  try {
    const res = await api('/api/ssh-keys/import', {
      method: 'POST',
      body: JSON.stringify({ name, private_key: privateKey, passphrase, comment }),
    });
    const key = await res.json();
    hideModal('importSSHKeyModal');
    toast('SSH key imported: ' + key.name + ' (' + key.algorithm + ')');
    selectSSHKey(key.id);
  } catch (e) {
    toast(e.message, 'error');
  }
}

async function deleteSSHKey() {
  if (!currentSSHKeyId) return;
  if (!confirm('Delete this SSH key pair?')) return;
  try {
    await api('/api/ssh-keys/' + currentSSHKeyId, { method: 'DELETE' });
    currentSSHKeyId = null;
    document.getElementById('sshKeyView').classList.add('hidden');
    document.getElementById('welcomeView').classList.remove('hidden');
    toast('SSH key deleted');
    loadSSHKeys();
  } catch (e) {
    toast(e.message, 'error');
  }
}

async function exportSSHKey() {
  if (!currentSSHKeyId) return;
  const part = document.getElementById('sshExportPart').value;
  const fmt = document.getElementById('sshExportFormat').value;
  const passphrase = document.getElementById('sshExportPassphrase').value;
  const originalPassphrase = document.getElementById('sshOriginalPassphrase').value;
  try {
    const res = await api('/api/export/ssh-key/' + currentSSHKeyId, {
      method: 'POST',
      body: JSON.stringify({ part, format: fmt, passphrase: passphrase || undefined, original_passphrase: originalPassphrase || undefined }),
    });
    await handleExportResponse(res);
  } catch (e) {
    toast(e.message, 'error');
  }
}

async function copyPublicKey() {
  const text = document.getElementById('sshPubKey').textContent;
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    toast('Public key copied to clipboard');
  } catch (e) {
    toast('Failed to copy: ' + e.message, 'error');
  }
}

async function copyPrivateKey() {
  if (!currentSSHKeyId) return;
  try {
    const res = await api('/api/ssh-keys/' + currentSSHKeyId + '/private');
    const data = await res.json();
    await navigator.clipboard.writeText(data.private_key);
    toast('Private key copied — paste into Bitwarden SSH import');
  } catch (e) {
    toast(e.message, 'error');
  }
}

function showBackupModal() {
  document.getElementById('backupPassword').value = '';
  document.getElementById('backupPasswordConfirm').value = '';
  showModal('backupModal');
  document.getElementById('backupPassword').focus();
}

async function createBackup() {
  const pw = document.getElementById('backupPassword').value;
  const pw2 = document.getElementById('backupPasswordConfirm').value;
  if (!pw) { toast('Password is required', 'error'); return; }
  if (pw !== pw2) { toast('Passwords do not match', 'error'); return; }
  try {
    const res = await api('/api/backup', {
      method: 'POST',
      body: JSON.stringify({ password: pw }),
    });
    hideModal('backupModal');
    await handleExportResponse(res);
  } catch (e) {
    toast(e.message, 'error');
  }
}

function showRestoreModal() {
  document.getElementById('restoreFile').value = '';
  document.getElementById('restorePassword').value = '';
  showModal('restoreModal');
}

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

async function restoreBackup() {
  const fileInput = document.getElementById('restoreFile');
  const pw = document.getElementById('restorePassword').value;
  if (!fileInput.files.length) { toast('Select a backup file', 'error'); return; }
  if (!pw) { toast('Password is required', 'error'); return; }
  if (!confirm('This will REPLACE ALL existing data. Are you sure?')) return;

  const file = fileInput.files[0];
  const arrayBuffer = await file.arrayBuffer();
  const base64 = arrayBufferToBase64(arrayBuffer);

  try {
    const res = await api('/api/restore', {
      method: 'POST',
      body: JSON.stringify({ password: pw, file_data: base64 }),
    });
    const result = await res.json();
    hideModal('restoreModal');
    toast('Restored: ' + result.counts.cas + ' CAs, ' +
          result.counts.certs + ' certs, ' +
          result.counts.ssh_keys + ' SSH keys');
    currentCAId = null;
    currentSSHKeyId = null;
    document.getElementById('caView').classList.add('hidden');
    document.getElementById('sshKeyView').classList.add('hidden');
    document.getElementById('welcomeView').classList.remove('hidden');
    loadCAs();
    loadSSHKeys();
  } catch (e) {
    toast(e.message, 'error');
  }
}

function showSSHGuide() {
  showSSHGuideTab('sshguide-overview', document.querySelector('#sshGuideTabs .guide-tab'));
  showModal('sshGuideModal');
}

function showSSHGuideTab(tabId, btn) {
  document.querySelectorAll('#sshGuideModal .guide-content').forEach(el => el.classList.add('hidden'));
  document.querySelectorAll('#sshGuideTabs .guide-tab').forEach(el => el.classList.remove('active'));
  document.getElementById(tabId).classList.remove('hidden');
  btn.classList.add('active');
}

let encryptionStatus = null;

async function checkEncryptionStatus() {
  try {
    const res = await api('/api/settings/encryption');
    const status = await res.json();
    encryptionStatus = status;

    if (status.enabled && !status.unlocked) {
      const usernameEl = document.getElementById('unlockUsername');
      usernameEl.classList.toggle('hidden', !status.username_required);
      document.getElementById('unlockSubtitle').textContent = status.username_required
        ? 'Sign in to decrypt your private keys'
        : 'Enter your master password to decrypt private keys';
      document.getElementById('unlockOverlay').classList.remove('hidden');
      (status.username_required ? usernameEl : document.getElementById('unlockPassword')).focus();
      return false;
    }

    if (!status.enabled && !status.dismissed) {
      document.getElementById('encryptionBanner').classList.remove('hidden');
    }
    document.getElementById('recoveryBanner').classList.toggle('hidden', !status.enabled || status.recovery_key);

    return true;
  } catch (e) {
    return true;
  }
}

async function doUnlock() {
  const usernameEl = document.getElementById('unlockUsername');
  const needsUsername = !usernameEl.classList.contains('hidden');
  const username = usernameEl.value.trim();
  const pw = document.getElementById('unlockPassword').value;
  if (needsUsername && !username) { document.getElementById('unlockError').textContent = 'Enter your username'; return; }
  if (!pw) { document.getElementById('unlockError').textContent = 'Enter your password'; return; }
  document.getElementById('unlockError').textContent = '';
  try {
    await api('/api/settings/encryption/unlock', {
      method: 'POST',
      body: JSON.stringify({ username, password: pw }),
    });
    document.getElementById('unlockOverlay').classList.add('hidden');
    document.getElementById('unlockPassword').value = '';
    loadSSHKeys();
    checkEncryptionStatus();
    if (await loadCAs() === 0) quickStartPending = true;
    showQuickStartIfPending();
  } catch (e) {
    document.getElementById('unlockError').textContent = e.message;
    document.getElementById('unlockPassword').value = '';
    document.getElementById('unlockPassword').focus();
  }
}

function showUnlockRecovery(useRecovery) {
  const needsUsername = !document.getElementById('unlockUsername').classList.contains('hidden');
  document.getElementById('unlockByPassword').classList.toggle('hidden', !!useRecovery);
  document.getElementById('unlockByRecovery').classList.toggle('hidden', !useRecovery);
  document.getElementById('unlockSubtitle').textContent = useRecovery
    ? 'Enter your recovery key and choose a new master password'
    : needsUsername ? 'Sign in to decrypt your private keys' : 'Enter your master password to decrypt private keys';
  document.getElementById(useRecovery ? 'recoverKey' : needsUsername ? 'unlockUsername' : 'unlockPassword').focus();
}

async function doRecover() {
  const key = document.getElementById('recoverKey').value;
  const pw = document.getElementById('recoverPassword').value;
  const confirmPw = document.getElementById('recoverConfirm').value;
  const errorEl = document.getElementById('recoverError');
  if (!key.trim()) { errorEl.textContent = 'Enter your recovery key'; return; }
  if (pw.length < 8) { errorEl.textContent = 'Password must be at least 8 characters'; return; }
  if (pw !== confirmPw) { errorEl.textContent = 'Passwords do not match'; return; }
  errorEl.textContent = '';
  try {
    const res = await api('/api/settings/encryption/recover', {
      method: 'POST',
      body: JSON.stringify({ recovery_key: key, password: pw, confirm: confirmPw }),
    });
    const data = await res.json();
    ['recoverKey', 'recoverPassword', 'recoverConfirm'].forEach((id) => { document.getElementById(id).value = ''; });
    showUnlockRecovery(0);
    document.getElementById('unlockOverlay').classList.add('hidden');
    loadSSHKeys();
    if (await loadCAs() === 0) quickStartPending = true;
    showRecoveryKey(data.recovery_key,
      'Your master password was reset and the database is unlocked. '
      + (data.username ? 'Your username is ' + data.username + '. ' : '')
      + 'The recovery key you used no longer works; this one replaces it.');
  } catch (e) {
    errorEl.textContent = e.message;
  }
}

// ── Recovery key ────────────────────────────────────────────────────

function showRecoveryKey(key, intro) {
  document.getElementById('recoveryKeyValue').textContent = key;
  document.getElementById('recoveryKeyIntro').textContent = intro;
  document.getElementById('recoveryKeySaved').checked = false;
  document.getElementById('recoveryKeyDone').disabled = true;
  // The desktop window has no browser downloads; Copy covers it there.
  document.getElementById('recoveryKeyDownload').classList.toggle('hidden', !SERVER_MODE);
  document.getElementById('recoveryBanner').classList.add('hidden');
  showModal('recoveryKeyModal');
}

function updateRecoveryKeyDone() {
  document.getElementById('recoveryKeyDone').disabled = !document.getElementById('recoveryKeySaved').checked;
}

function closeRecoveryKey() {
  document.getElementById('recoveryKeyValue').textContent = '';
  hideModal('recoveryKeyModal');
  showQuickStartIfPending();
}

async function copyRecoveryKey() {
  try {
    await navigator.clipboard.writeText(document.getElementById('recoveryKeyValue').textContent);
    toast('Recovery key copied to clipboard');
  } catch (e) {
    toast('Copy failed, select the key and copy it by hand', 'error');
  }
}

function downloadRecoveryKey() {
  const key = document.getElementById('recoveryKeyValue').textContent;
  const text = 'Cert Generator encryption recovery key\n\n' + key + '\n\n'
    + 'Created ' + new Date().toISOString() + ' for ' + location.host + '.\n'
    + 'Use it on the unlock screen if you forget the master password. Keep it away from the server.\n';
  const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = 'cert-generator-recovery-key.txt';
  a.click();
  URL.revokeObjectURL(url);
}

async function createRecoveryKey() {
  const passwordEl = document.getElementById('recoveryKeyPassword');
  const replacing = !document.getElementById('recoveryKeyPasswordRow').classList.contains('hidden')
    && !document.getElementById('encryptionModal').classList.contains('hidden');
  if (replacing && !passwordEl.value) { toast('Enter your current password to replace the recovery key', 'error'); return; }
  if (replacing && !confirm('Replace the recovery key? The current one stops working.')) return;
  try {
    const res = await api('/api/settings/encryption/recovery-key', {
      method: 'POST',
      body: JSON.stringify({ password: replacing ? passwordEl.value : '' }),
    });
    const data = await res.json();
    passwordEl.value = '';
    hideModal('encryptionModal');
    showRecoveryKey(data.recovery_key, replacing
      ? 'This replaces your previous recovery key, which no longer works.'
      : 'If you forget your master password, this key unlocks the database and lets you set a new one.');
  } catch (e) {
    toast(e.message, 'error');
  }
}

async function showEncryptionSettings() {
  try {
    const res = await api('/api/settings/encryption');
    const status = await res.json();
    if (status.enabled) {
      document.getElementById('encryptionOff').classList.add('hidden');
      document.getElementById('encryptionOn').classList.remove('hidden');
      document.getElementById('encChangeOld').value = '';
      document.getElementById('encChangeNew').value = '';
      document.getElementById('encChangeConfirm').value = '';
      document.getElementById('encDisablePassword').value = '';
      document.getElementById('recoveryKeyPassword').value = '';
      document.getElementById('recoveryKeyStatus').textContent = status.recovery_key
        ? 'A recovery key is set. Replacing it needs your current password, and the old key stops working.'
        : 'No recovery key yet. Without one, a forgotten password means your private keys are lost.';
      document.getElementById('recoveryKeyPasswordRow').classList.toggle('hidden', !status.recovery_key);
      document.getElementById('recoveryKeyButton').textContent = status.recovery_key ? 'Replace recovery key' : 'Create recovery key';
      document.getElementById('encUsernameNote').classList.toggle('hidden', !status.username);
      document.getElementById('encUsernameValue').textContent = status.username || '';
    } else {
      document.getElementById('encryptionOff').classList.remove('hidden');
      document.getElementById('encryptionOn').classList.add('hidden');
      const usernameEl = document.getElementById('encEnableUsername');
      if (usernameEl) usernameEl.value = '';
      document.getElementById('encEnablePassword').value = '';
      document.getElementById('encEnableConfirm').value = '';
    }
    showModal('encryptionModal');
  } catch (e) {
    toast(e.message, 'error');
  }
}

async function enableEncryption(username, pw, confirmPw) {
  if (!pw) { toast('Password is required', 'error'); return false; }
  if (pw !== confirmPw) { toast('Passwords do not match', 'error'); return false; }
  if (pw.length < 8) { toast('Password must be at least 8 characters', 'error'); return false; }
  try {
    const res = await api('/api/settings/encryption/enable', {
      method: 'POST',
      body: JSON.stringify({ username, password: pw, confirm: confirmPw }),
    });
    const data = await res.json();
    document.getElementById('encryptionBanner').classList.add('hidden');
    toast('Encryption enabled — private keys are now encrypted at rest');
    showRecoveryKey(data.recovery_key, username
      ? 'Sign-in is on: the app asks for ' + username + ' and your password at every start. '
        + 'If you forget the password, this key resets it on the sign-in screen.'
      : 'Encryption is on. If you forget your master password, this key unlocks the database and lets you set a new one.');
    return true;
  } catch (e) {
    toast(e.message, 'error');
    return false;
  }
}

async function doEnableEncryption() {
  const usernameEl = document.getElementById('encEnableUsername');
  const ok = await enableEncryption(usernameEl ? usernameEl.value.trim() : '',
    document.getElementById('encEnablePassword').value, document.getElementById('encEnableConfirm').value);
  if (ok) hideModal('encryptionModal');
}

// ── Desktop first run: offer a sign-in ──────────────────────────────

function offerProtect() {
  ['protectUsername', 'protectPassword', 'protectConfirm'].forEach((id) => { document.getElementById(id).value = ''; });
  document.getElementById('protectDontAsk').checked = false;
  showModal('protectModal');
  document.getElementById('protectUsername').focus();
}

async function doProtect() {
  const username = document.getElementById('protectUsername').value.trim();
  if (!username) { toast('Choose a username', 'error'); return; }
  const ok = await enableEncryption(username,
    document.getElementById('protectPassword').value, document.getElementById('protectConfirm').value);
  if (!ok) return;
  ['protectPassword', 'protectConfirm'].forEach((id) => { document.getElementById(id).value = ''; });
  hideModal('protectModal');
}

async function skipProtect() {
  hideModal('protectModal');
  if (document.getElementById('protectDontAsk').checked) {
    document.getElementById('encryptionBanner').classList.add('hidden');
    try { await api('/api/settings/encryption/dismiss', { method: 'POST' }); } catch (e) {}
  }
  showQuickStartIfPending();
}

async function doDisableEncryption() {
  const pw = document.getElementById('encDisablePassword').value;
  if (!pw) { toast('Password is required', 'error'); return; }
  if (!confirm('Disable encryption? Private keys will be stored in plaintext.')) return;
  try {
    await api('/api/settings/encryption/disable', {
      method: 'POST',
      body: JSON.stringify({ password: pw }),
    });
    hideModal('encryptionModal');
    document.getElementById('recoveryBanner').classList.add('hidden');
    toast('Encryption disabled — private keys are now stored in plaintext');
  } catch (e) {
    toast(e.message, 'error');
  }
}

async function doChangePassword() {
  const old_password = document.getElementById('encChangeOld').value;
  const new_password = document.getElementById('encChangeNew').value;
  const confirmPw = document.getElementById('encChangeConfirm').value;
  if (!old_password || !new_password) { toast('Both passwords are required', 'error'); return; }
  if (new_password !== confirmPw) { toast('New passwords do not match', 'error'); return; }
  if (new_password.length < 8) { toast('Password must be at least 8 characters', 'error'); return; }
  try {
    await api('/api/settings/encryption/change-password', {
      method: 'POST',
      body: JSON.stringify({ old_password, new_password, confirm: confirmPw }),
    });
    hideModal('encryptionModal');
    toast('Master password changed');
  } catch (e) {
    toast(e.message, 'error');
  }
}

function renderDeviceList(devices, containerId) {
  const el = document.getElementById(containerId);
  if (!devices.length) {
    el.innerHTML = '<p style="font-size:12px;color:var(--text-dim)">No trusted devices.</p>';
    return;
  }
  el.innerHTML = devices.map(function(d) {
    const label = escapeHtml(d.label || 'Unknown device');
    const created = formatDate(d.created_at);
    const expires = formatDate(d.expires_at);
    return '<div style="display:flex;align-items:center;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border)">' +
      '<div style="min-width:0">' +
        '<div style="font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">' + label + '</div>' +
        '<div style="font-size:11px;color:var(--text-dim)">Trusted ' + created + ' · Expires ' + expires + '</div>' +
      '</div>' +
      '<button class="btn btn-ghost btn-sm" style="flex-shrink:0;margin-left:8px;color:var(--danger)" data-action="doRevokeDevice" data-arg="' + d.id + '\">Revoke</button>' +
    '</div>';
  }).join('');
}

async function loadDeviceList(containerId) {
  const res = await api('/api/devices');
  const data = await res.json();
  renderDeviceList(data.devices, containerId);
  return data.devices.length;
}

async function showMFASettings() {
  try {
    const res = await api('/api/mfa/status');
    const status = await res.json();
    if (status.enabled) {
      document.getElementById('mfaOff').classList.add('hidden');
      document.getElementById('mfaSetup').classList.add('hidden');
      document.getElementById('mfaOn').classList.remove('hidden');
      document.getElementById('mfaDisablePassword').value = '';
      document.getElementById('mfaDisableCode').value = '';
      await loadDeviceList('mfaDeviceList');
    } else {
      document.getElementById('mfaOff').classList.remove('hidden');
      document.getElementById('mfaSetup').classList.add('hidden');
      document.getElementById('mfaOn').classList.add('hidden');
    }
    showModal('mfaModal');
  } catch (e) {
    toast(e.message, 'error');
  }
}

async function doMFASetup() {
  try {
    const res = await api('/api/mfa/setup', { method: 'POST' });
    const data = await res.json();
    document.getElementById('mfaOff').classList.add('hidden');
    document.getElementById('mfaSetup').classList.remove('hidden');
    document.getElementById('mfaQRCode').innerHTML = data.qr_svg;
    document.getElementById('mfaSecretKey').textContent = data.secret;
    document.getElementById('mfaSetupCode').value = '';
    document.getElementById('mfaSetupCode').focus();
  } catch (e) {
    toast(e.message, 'error');
  }
}

function cancelMFASetup() {
  document.getElementById('mfaSetup').classList.add('hidden');
  document.getElementById('mfaOff').classList.remove('hidden');
}

async function doMFAConfirm() {
  const code = document.getElementById('mfaSetupCode').value.trim();
  if (!code || code.length !== 6) { toast('Enter the 6-digit code from your authenticator app', 'error'); return; }
  try {
    await api('/api/mfa/confirm', {
      method: 'POST',
      body: JSON.stringify({ code }),
    });
    hideModal('mfaModal');
    toast('MFA enabled — verification codes are now required when signing in');
  } catch (e) {
    toast(e.message, 'error');
  }
}

async function doMFADisable() {
  const password = document.getElementById('mfaDisablePassword').value;
  const code = document.getElementById('mfaDisableCode').value.trim();
  if (!password || !code) { toast('Password and verification code are required', 'error'); return; }
  if (!confirm('Disable MFA? Verification codes will no longer be required when signing in.')) return;
  try {
    await api('/api/mfa/disable', {
      method: 'POST',
      body: JSON.stringify({ password, code }),
    });
    hideModal('mfaModal');
    toast('MFA disabled');
  } catch (e) {
    toast(e.message, 'error');
  }
}

async function doRevokeDevice(deviceId) {
  if (!confirm('Revoke this trusted device?')) return;
  try {
    await api('/api/devices/' + deviceId, { method: 'DELETE' });
    toast('Device revoked');
    // Refresh whichever device list is visible
    if (!document.getElementById('mfaModal').classList.contains('hidden')) {
      await loadDeviceList('mfaDeviceList');
    }
    if (!document.getElementById('accountModal').classList.contains('hidden')) {
      await loadDeviceList('acctDeviceList');
    }
  } catch (e) {
    toast(e.message, 'error');
  }
}

async function doRevokeDevices() {
  if (!confirm('Revoke all trusted devices? Everyone will need to re-authenticate.')) return;
  try {
    const res = await api('/api/mfa/revoke-devices', { method: 'POST' });
    const data = await res.json();
    toast('Revoked ' + data.revoked + ' trusted device(s)');
    if (!document.getElementById('mfaModal').classList.contains('hidden')) {
      await loadDeviceList('mfaDeviceList');
    }
    if (!document.getElementById('accountModal').classList.contains('hidden')) {
      await loadDeviceList('acctDeviceList');
    }
  } catch (e) {
    toast(e.message, 'error');
  }
}

async function doRevokeDevicesAcct() {
  return doRevokeDevices();
}

async function showAccountSettings() {
  try {
    const res = await api('/api/account/status');
    const status = await res.json();
    document.getElementById('acctRequirePassword').checked = status.require_password;
    await loadDeviceList('acctDeviceList');
    showModal('accountModal');
  } catch (e) {
    toast(e.message, 'error');
  }
}

async function doToggleRequirePasswordAcct() {
  const require_password = document.getElementById('acctRequirePassword').checked;
  try {
    await api('/api/account/require-password', {
      method: 'POST',
      body: JSON.stringify({ require_password }),
    });
    toast(require_password ? 'Password required on every visit' : 'Trusted devices will auto-login');
  } catch (e) {
    document.getElementById('acctRequirePassword').checked = !require_password;
    toast(e.message, 'error');
  }
}

function toggleBannerMore(_arg, btn) {
  const banner = btn.closest('.encryption-banner');
  const expanded = banner.classList.toggle('expanded');
  btn.textContent = expanded ? 'Less' : 'More';
  btn.setAttribute('aria-expanded', String(expanded));
}

async function dismissEncryptionBanner() {
  const permanently = document.getElementById('bannerDismissCheck').checked;
  document.getElementById('encryptionBanner').classList.add('hidden');
  if (permanently) {
    try { await api('/api/settings/encryption/dismiss', { method: 'POST' }); } catch (e) {}
  }
}

async function checkLegacyExports() {
  if (!SERVER_MODE) return;
  try {
    const res = await api('/api/settings/legacy-exports');
    const status = await res.json();
    const banner = document.getElementById('legacyExportsBanner');
    banner.classList.toggle('hidden', status.files.length === 0);
    document.getElementById('legacyExportsCount').textContent = status.files.length;
    document.getElementById('legacyExportsDir').textContent = status.directory || '';
    banner.dataset.files = JSON.stringify(status.files);
  } catch (e) {
    // Non-critical: leave the banner hidden.
  }
}

async function deleteLegacyExports() {
  const banner = document.getElementById('legacyExportsBanner');
  const files = JSON.parse(banner.dataset.files || '[]');
  const listed = files.slice(0, 20).join('\n') + (files.length > 20 ? '\n… and ' + (files.length - 20) + ' more' : '');
  if (!confirm('Permanently delete these ' + files.length + ' files from the server?\n\n' + listed)) return;
  try {
    const res = await api('/api/settings/legacy-exports/delete', { method: 'POST' });
    const result = await res.json();
    if (result.failed.length) {
      toast('Deleted ' + result.deleted + ' files; could not delete ' + result.failed.length, 'error');
    } else {
      toast('Deleted ' + result.deleted + ' old export files');
    }
    checkLegacyExports();
  } catch (e) {
    toast(e.message, 'error');
  }
}

async function initApp() {
  updateThemeSwitcherUI(document.documentElement.dataset.theme || 'oled');
  updateAccentUI();
  const ready = await checkEncryptionStatus();
  if (ready) {
    loadSSHKeys();
    if (await loadCAs() === 0) quickStartPending = true;
    const status = encryptionStatus;
    if (!SERVER_MODE && status && !status.enabled && !status.dismissed) offerProtect();
    else showQuickStartIfPending();
  }
  checkLegacyExports();
}


// ── Event delegation ────────────────────────────────────────────────
// Markup declares handlers as data-action / data-change / data-enter instead of
// inline on* attributes, so the Content-Security-Policy can forbid inline script.
// Handlers receive (data-arg, element, event); numeric args become numbers.
const UI_ACTIONS = new Set([
  'deleteLegacyExports',
  'cancelMFASetup',
  'cancelReauth',
  'closeRecoveryKey',
  'copyImportCommands',
  'copyPrivateKey',
  'copyRecoveryKey',
  'copyCertPem',
  'copyCrlPem',
  'copyPublicKey',
  'createBackup',
  'createCA',
  'createIntermediate',
  'createRecoveryKey',
  'deleteCert',
  'deleteCurrentCA',
  'deleteSSHKey',
  'downloadImportCA',
  'downloadRecoveryKey',
  'dismissEncryptionBanner',
  'doProtect',
  'popOutGuide',
  'skipProtect',
  'doChangePassword',
  'doDisableEncryption',
  'doEnableEncryption',
  'doExportCert',
  'doMFAConfirm',
  'doMFADisable',
  'doMFASetup',
  'doRecover',
  'doRevokeDevice',
  'doRevokeDevices',
  'doRevokeDevicesAcct',
  'doToggleRequirePasswordAcct',
  'doUnlock',
  'exportCA',
  'exportCRL',
  'exportFromCertView',
  'exportFromImport',
  'exportSSHKey',
  'generateSSHKey',
  'hideModal',
  'importSSHKey',
  'issueCert',
  'onTemplateChange',
  'openExternalLink',
  'restoreBackup',
  'revokeCert',
  'showAccountSettings',
  'showBackupModal',
  'showCreateCA',
  'showCreateIntermediate',
  'showCreateSSHKey',
  'showEncryptionSettings',
  'showExportCert',
  'showGuide',
  'showGuideTab',
  'showImportSSHKey',
  'showIssueCert',
  'showMFASettings',
  'showRestoreModal',
  'showSSHGuide',
  'showSSHGuideTab',
  'setImportOs',
  'setImportTrusted',
  'showUnlockRecovery',
  'submitReauth',
  'setAccent',
  'setTheme',
  'toggleAccentMenu',
  'toggleCertCrl',
  'toggleBannerMore',
  'toggleImportHelp',
  'toggleMobileMenu',
  'toggleSection',
  'toggleSerial',
  'updateCaPasswordVisibility',
  'updateCrlDpFields',
  'updateRecoveryKeyDone',
  'viewCRL',
  'viewCert',
  'viewCertFromCrl',
]);

function runAction(name, el, event) {
  if (!UI_ACTIONS.has(name) || typeof window[name] !== 'function') {
    console.error('Unknown UI action:', name);
    return undefined;
  }
  let arg = el.dataset.arg;
  if (arg !== undefined && /^\d+$/.test(arg)) arg = Number(arg);
  return window[name](arg, el, event);
}

document.addEventListener('click', (event) => {
  const el = event.target.closest('[data-action]');
  if (el && runAction(el.dataset.action, el, event) === false) event.preventDefault();
});

document.addEventListener('change', (event) => {
  const el = event.target.closest('[data-change]');
  if (el) runAction(el.dataset.change, el, event);
});

document.getElementById('accentInput').addEventListener('input', (event) => setAccent(event.target.value));
document.getElementById('accentHex').addEventListener('input', onAccentHexInput);
document.getElementById('accentHex').addEventListener('change', onAccentHexCommit);

// Close the accent menu on a click outside it, or on Escape.
document.addEventListener('click', (event) => {
  if (!document.getElementById('accentMenu').hidden && !event.target.closest('.theme-row')) toggleAccentMenu(null, null, false);
});

document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && !document.getElementById('accentMenu').hidden) {
    toggleAccentMenu(null, null, false);
    document.getElementById('accentBtn').focus();
  }
});

document.addEventListener('keydown', (event) => {
  if (event.key !== 'Enter') return;
  const el = event.target.closest('[data-enter]');
  if (el) runAction(el.dataset.enter, el, event);
});

initApp();
