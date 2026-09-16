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
  document.documentElement.setAttribute('data-theme', name);
  try { localStorage.setItem('theme', name); } catch (e) { /* storage blocked */ }
  updateThemeSwitcherUI(name);
}

function updateThemeSwitcherUI(name) {
  document.querySelectorAll('.theme-swatch').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.arg === name);
  });
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
const TEMPLATE_DESCS = {
  'web-server': 'Server Authentication',
  'computer': 'Client Authentication, Server Authentication',
  'client-auth': 'Client Authentication',
  'user': 'Client Authentication, Smart Card Logon',
  'code-signing': 'Code Signing',
  'email': 'Email Protection',
};

async function api(url, opts = {}) {
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...opts.headers },
    ...opts,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Request failed' }));
    if (res.status === 423 && err.locked) {
      document.getElementById('unlockOverlay').classList.remove('hidden');
    }
    throw new Error(err.error || 'Request failed');
  }
  return res;
}

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
function showIssueCert() { showModal('issueCertModal'); document.getElementById('certCN').focus(); }

async function loadCAs() {
  const res = await api('/api/ca');
  const cas = await res.json();
  const list = document.getElementById('caList');
  list.innerHTML = '';

  const roots = cas.filter(c => !c.parent_ca_id);
  const childrenOf = (pid) => cas.filter(c => c.parent_ca_id === pid);

  roots.forEach(ca => {
    const li = document.createElement('li');
    li.className = 'ca-item' + (ca.id === currentCAId ? ' active' : '');
    li.innerHTML = '<span class="dot"></span><span class="ca-name">' +
      escapeHtml(ca.name) + '</span>';
    li.onclick = () => selectCA(ca.id);
    list.appendChild(li);

    childrenOf(ca.id).forEach(child => {
      const cli = document.createElement('li');
      cli.className = 'ca-item intermediate' + (child.id === currentCAId ? ' active' : '');
      cli.innerHTML = '<span class="dot"></span><span class="ca-name">' +
        escapeHtml(child.name) + '</span>';
      cli.onclick = () => selectCA(child.id);
      list.appendChild(cli);
    });
  });

  document.getElementById('caCount').textContent = cas.length;
  if (cas.length === 0 && !currentSSHKeyId) {
    document.getElementById('welcomeView').classList.remove('hidden');
    document.getElementById('caView').classList.add('hidden');
  }
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
  document.getElementById('btnCreateIntermediate').classList.toggle('hidden', !ca.can_issue_intermediate);

  const expired = new Date(ca.not_after) < new Date();
  const typeBadge = isRoot
    ? '<span class="badge badge-active">Root</span>'
    : '<span class="badge badge-algo">Intermediate</span>';
  document.getElementById('caInfo').innerHTML =
    infoItem('Type', typeBadge) +
    infoItem('Domain', escapeHtml(ca.domain)) +
    infoItem('Algorithm', '<span class="badge badge-algo">' + escapeHtml(ca.algorithm) + '</span>') +
    infoItem('Serial', serialToggle(ca.serial)) +
    infoItem('Created', formatDate(ca.not_before)) +
    infoItem('Expires', formatDate(ca.not_after)) +
    infoItem('CRL Next Update', crlStatusBadge(ca.crl_next_update)) +
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
    tbody.innerHTML = '';
    noCerts.classList.remove('hidden');
    document.getElementById('certTableContainer').querySelector('table').classList.add('hidden');
    return;
  }

  noCerts.classList.add('hidden');
  document.getElementById('certTableContainer').querySelector('table').classList.remove('hidden');

  tbody.innerHTML = certs.map(c => {
    const expired = new Date(c.not_after) < new Date();
    let status = '';
    if (c.revoked) status = '<span class="badge badge-revoked">Revoked</span>';
    else if (expired) status = '<span class="badge badge-expired">Expired</span>';
    else status = '<span class="badge badge-active">Active</span>';

    const tmplLabel = TEMPLATE_LABELS[c.template] || c.template || 'Web Server';
    return '<tr>' +
      '<td>' + escapeHtml(c.common_name) + '</td>' +
      '<td><span class="badge badge-algo">' + escapeHtml(tmplLabel) + '</span></td>' +
      '<td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + escapeHtml(c.san_domains) + '</td>' +
      '<td><span class="badge badge-algo">' + escapeHtml(c.algorithm) + '</span></td>' +
      '<td>' + formatDate(c.not_after) + '</td>' +
      '<td>' + status + '</td>' +
      '<td>' +
        '<button class="btn btn-ghost btn-sm" data-action="showExportCert" data-arg="' + c.id + '\">Export</button> ' +
        (!c.revoked ? '<button class="btn btn-ghost btn-sm" data-action="revokeCert" data-arg="' + c.id + '\">Revoke</button> ' : '') +
        '<button class="btn btn-danger btn-sm" data-action="deleteCert" data-arg="' + c.id + '\">Delete</button>' +
      '</td></tr>';
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
  const includeCrlDp = document.getElementById('certIncludeCRL').checked;

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
        include_crl_dp: includeCrlDp,
      }),
    });
    const cert = await res.json();
    hideModal('issueCertModal');
    document.getElementById('certCN').value = '';
    document.getElementById('certSANs').value = '';
    document.getElementById('certEmail').value = '';
    document.getElementById('certUPN').value = '';
    document.getElementById('certIncludeCRL').checked = false;
    toast('Certificate issued: ' + cert.common_name);
    loadCerts(currentCAId);
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
  try {
    await api('/api/certs/' + certId + '/revoke', { method: 'POST' });
    toast('Certificate revoked');
    loadCerts(currentCAId);
  } catch (e) {
    toast(e.message, 'error');
  }
}

async function deleteCert(certId) {
  if (!confirm('Permanently delete this certificate?')) return;
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
document.getElementById('certExportPart').addEventListener('change', updateCertPasswordVisibility);

function infoItem(label, value) {
  return '<div class="info-item"><label>' + label + '</label><span>' + value + '</span></div>';
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
    const algoBadge = k.algorithm.toUpperCase().replace('-', ' ');
    const importedBadge = k.imported ? '<span class="ca-type-badge" style="background:var(--accent);color:#fff;font-size:9px;padding:1px 5px">IMPORTED</span>' : '';
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

  document.getElementById('sshKeyInfo').innerHTML =
    infoItem('Algorithm', '<span class="badge badge-algo">' + escapeHtml(key.algorithm.toUpperCase().replace('-', ' ')) + '</span>') +
    infoItem('Source', key.imported ? '<span class="badge" style="background:var(--accent);color:#fff">Imported</span>' : '<span class="badge badge-algo">Generated</span>') +
    infoItem('Fingerprint', '<span style="font-family:monospace;font-size:11px">' + escapeHtml(key.fingerprint) + '</span>') +
    infoItem('Comment', escapeHtml(key.comment || '(none)')) +
    infoItem('Passphrase', key.has_passphrase ? '<span class="badge badge-active">Yes</span>' : '<span class="badge badge-expired">No</span>') +
    infoItem('Created', formatDate(key.created_at));

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

async function checkEncryptionStatus() {
  try {
    const res = await api('/api/settings/encryption');
    const status = await res.json();

    if (status.enabled && !status.unlocked) {
      document.getElementById('unlockOverlay').classList.remove('hidden');
      document.getElementById('unlockPassword').focus();
      return false;
    }

    if (!status.enabled && !status.dismissed) {
      document.getElementById('encryptionBanner').classList.remove('hidden');
    }

    return true;
  } catch (e) {
    return true;
  }
}

async function doUnlock() {
  const pw = document.getElementById('unlockPassword').value;
  if (!pw) { document.getElementById('unlockError').textContent = 'Enter your password'; return; }
  document.getElementById('unlockError').textContent = '';
  try {
    await api('/api/settings/encryption/unlock', {
      method: 'POST',
      body: JSON.stringify({ password: pw }),
    });
    document.getElementById('unlockOverlay').classList.add('hidden');
    loadCAs();
    loadSSHKeys();
  } catch (e) {
    document.getElementById('unlockError').textContent = e.message;
    document.getElementById('unlockPassword').value = '';
    document.getElementById('unlockPassword').focus();
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
    } else {
      document.getElementById('encryptionOff').classList.remove('hidden');
      document.getElementById('encryptionOn').classList.add('hidden');
      document.getElementById('encEnablePassword').value = '';
      document.getElementById('encEnableConfirm').value = '';
    }
    showModal('encryptionModal');
  } catch (e) {
    toast(e.message, 'error');
  }
}

async function doEnableEncryption() {
  const pw = document.getElementById('encEnablePassword').value;
  const confirmPw = document.getElementById('encEnableConfirm').value;
  if (!pw) { toast('Password is required', 'error'); return; }
  if (pw !== confirmPw) { toast('Passwords do not match', 'error'); return; }
  if (pw.length < 8) { toast('Password must be at least 8 characters', 'error'); return; }
  try {
    await api('/api/settings/encryption/enable', {
      method: 'POST',
      body: JSON.stringify({ password: pw, confirm: confirmPw }),
    });
    hideModal('encryptionModal');
    document.getElementById('encryptionBanner').classList.add('hidden');
    toast('Encryption enabled — private keys are now encrypted at rest');
  } catch (e) {
    toast(e.message, 'error');
  }
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
  const ready = await checkEncryptionStatus();
  if (ready) {
    loadCAs();
    loadSSHKeys();
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
  'copyPrivateKey',
  'copyPublicKey',
  'createBackup',
  'createCA',
  'createIntermediate',
  'deleteCert',
  'deleteCurrentCA',
  'deleteSSHKey',
  'dismissEncryptionBanner',
  'doChangePassword',
  'doDisableEncryption',
  'doEnableEncryption',
  'doExportCert',
  'doMFAConfirm',
  'doMFADisable',
  'doMFASetup',
  'doRevokeDevice',
  'doRevokeDevices',
  'doRevokeDevicesAcct',
  'doToggleRequirePasswordAcct',
  'doUnlock',
  'exportCA',
  'exportCRL',
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
  'setTheme',
  'toggleMobileMenu',
  'toggleSection',
  'toggleSerial',
  'updateCaPasswordVisibility',
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

document.addEventListener('keydown', (event) => {
  if (event.key !== 'Enter') return;
  const el = event.target.closest('[data-enter]');
  if (el) runAction(el.dataset.enter, el, event);
});

initApp();
