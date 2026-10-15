'use strict';

/* global discovery */

const COLUMNS = ['product', 'ip', 'mac', 'hostname', 'version'];

const state = {
  devices: new Map(),
  selected: new Set(),
  anchor: null,
  sort: { col: null, dir: 1 },
  filter: '',
};

const $ = (sel) => document.querySelector(sel);
const tbody = $('#devices tbody');
const scanBtn = $('#scan');
const menu = $('#menu');
const tooltip = $('#tooltip');

// ---------- helpers ----------

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = v;
    else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) node.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat()) if (c != null) node.append(c.nodeType ? c : String(c));
  return node;
}

function ipKey(ip) {
  return (ip || '').split('.').map((n) => n.padStart(3, '0')).join('.');
}

// Search box: plain text, with * and ? wildcards, matched against every column.
function filterRegex(text) {
  const t = text.trim();
  if (!t) return null;
  const pattern = t.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
  return new RegExp(pattern, 'i');
}

function visibleDevices() {
  const re = filterRegex(state.filter);
  let list = [...state.devices.values()];
  if (re) list = list.filter((d) => [...COLUMNS.map((c) => d[c]), d.essid].some((v) => re.test(v || '')));
  const { col, dir } = state.sort;
  if (col) {
    list.sort((a, b) => {
      const va = col === 'ip' ? ipKey(a.ip) : String(a[col] || '').toLowerCase();
      const vb = col === 'ip' ? ipKey(b.ip) : String(b[col] || '').toLowerCase();
      return va < vb ? -dir : va > vb ? dir : 0;
    });
  }
  return list;
}

function webUrl(device) {
  return `http://${device.ip}`;
}

// ---------- table ----------

function render() {
  const list = visibleDevices();
  tbody.replaceChildren(
    ...list.map((d) =>
      el(
        'tr',
        { 'data-id': d.id, class: state.selected.has(d.id) ? 'selected' : '' },
        el('td', {}, d.product),
        el('td', {}, d.ip || ''),
        el('td', { class: 'mono' }, d.mac),
        el('td', {}, d.hostname),
        el('td', {}, d.version),
      ),
    ),
  );
  $('#total').textContent = String(state.devices.size);
  document.querySelectorAll('th').forEach((th) => {
    th.classList.toggle('sorted-asc', th.dataset.col === state.sort.col && state.sort.dir === 1);
    th.classList.toggle('sorted-desc', th.dataset.col === state.sort.col && state.sort.dir === -1);
  });
}

function selectedDevices() {
  return visibleDevices().filter((d) => state.selected.has(d.id));
}

function rowId(event) {
  const tr = event.target.closest('tr[data-id]');
  return tr ? tr.dataset.id : null;
}

tbody.addEventListener('mousedown', (e) => {
  const id = rowId(e);
  if (!id) return;
  const ids = visibleDevices().map((d) => d.id);
  if (e.button === 2 && state.selected.has(id)) return;
  if (e.shiftKey && state.anchor) {
    const [a, b] = [ids.indexOf(state.anchor), ids.indexOf(id)].sort((x, y) => x - y);
    state.selected = new Set(ids.slice(a, b + 1));
  } else if (e.ctrlKey || e.metaKey) {
    if (state.selected.has(id)) state.selected.delete(id);
    else state.selected.add(id);
    state.anchor = id;
  } else {
    state.selected = new Set([id]);
    state.anchor = id;
  }
  render();
});

tbody.addEventListener('dblclick', (e) => {
  const id = rowId(e);
  if (id) showDetails(state.devices.get(id));
});

document.querySelector('thead').addEventListener('click', (e) => {
  const col = e.target.dataset.col;
  if (!col) return;
  state.sort = state.sort.col === col ? { col, dir: -state.sort.dir } : { col, dir: 1 };
  render();
});

// ---------- tooltip (same fields as the original) ----------

let tooltipTimer = null;
tbody.addEventListener('mousemove', (e) => {
  const id = rowId(e);
  clearTimeout(tooltipTimer);
  tooltip.hidden = true;
  if (!id || !menu.hidden) return;
  const { clientX, clientY } = e;
  tooltipTimer = setTimeout(() => showTooltip(state.devices.get(id), clientX, clientY), 700);
});
tbody.addEventListener('mouseleave', () => {
  clearTimeout(tooltipTimer);
  tooltip.hidden = true;
});

function showTooltip(d, x, y) {
  if (!d) return;
  tooltip.replaceChildren(
    el('div', { class: 'tt-product' }, el('h2', {}, d.product), el('span', { class: 'tt-ssid' }, '  ', d.essid || '', ' ', el('b', {}, d.isAp ? '(AP)' : ''))),
    el('span', { class: 'k' }, 'HW Address:'), el('b', {}, d.mac),
    el('span', { class: 'k' }, 'IP Address:'), el('b', {}, d.ip || ''),
    el('span', { class: 'k' }, 'Version:'), el('b', {}, d.version),
    el('span', { class: 'k' }, 'Build Number:'), el('b', {}, d.build || ''),
  );
  tooltip.hidden = false;
  const r = tooltip.getBoundingClientRect();
  tooltip.style.left = `${Math.min(x + 14, window.innerWidth - r.width - 8)}px`;
  tooltip.style.top = `${Math.min(y + 18, window.innerHeight - r.height - 8)}px`;
}

// ---------- context menu ----------

tbody.addEventListener('contextmenu', (e) => {
  e.preventDefault();
  if (!rowId(e)) return;
  tooltip.hidden = true;
  const single = selectedDevices().length === 1;
  menu.querySelectorAll('li[data-action]').forEach((li) => {
    li.classList.toggle('disabled', li.dataset.action !== 'copy' && !single);
  });
  menu.hidden = false;
  const r = menu.getBoundingClientRect();
  menu.style.left = `${Math.min(e.clientX, window.innerWidth - r.width - 4)}px`;
  menu.style.top = `${Math.min(e.clientY, window.innerHeight - r.height - 4)}px`;
});

document.addEventListener('mousedown', (e) => {
  if (!menu.hidden && !menu.contains(e.target)) menu.hidden = true;
});

menu.addEventListener('click', (e) => {
  const action = e.target.dataset.action;
  if (!action) return;
  menu.hidden = true;
  const devices = selectedDevices();
  const d = devices[0];
  switch (action) {
    case 'web': openWeb(d); break;
    case 'rescue': showRescue(d); break;
    case 'details': showDetails(d); break;
    case 'reboot': showReboot(d); break;
    case 'copy': copyRows(devices); break;
    default: break;
  }
});

function copyRows(devices) {
  const text = devices.map((d) => COLUMNS.map((c) => d[c] || '').join('\t')).join('\n');
  discovery.copy(text);
}

document.addEventListener('keydown', (e) => {
  if (document.querySelector('.backdrop')) return;
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'c' && document.activeElement !== $('#search')) {
    const devices = selectedDevices();
    if (devices.length) {
      e.preventDefault();
      copyRows(devices);
    }
  } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'a' && document.activeElement !== $('#search')) {
    e.preventDefault();
    state.selected = new Set(visibleDevices().map((d) => d.id));
    render();
  } else if (e.key === 'Enter' && document.activeElement !== $('#search')) {
    const devices = selectedDevices();
    if (devices.length === 1) showDetails(devices[0]);
  }
});

async function openWeb(d) {
  const url = webUrl(d);
  const ok = await discovery.openWeb(url);
  if (!ok) discovery.errorBox('Web UI', `Failed launching WEB browser. Please, open ${url} manually.`);
}

// ---------- dialogs ----------

function modal({ title, body, buttons, onKey }) {
  const root = $('#modal-root');
  const dlg = el('div', { class: 'dialog', role: 'dialog', 'aria-label': title }, el('h1', {}, title), el('div', { class: 'body' }, body), el('div', { class: 'buttons' }, buttons));
  const backdrop = el('div', { class: 'backdrop' }, dlg);
  const close = () => backdrop.remove();
  backdrop.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      e.preventDefault();
      (onKey && onKey('Escape')) || close();
    }
  });
  root.append(backdrop);
  const first = dlg.querySelector('input, select, button.primary, button');
  if (first) first.focus();
  return { close, dialog: dlg };
}

function showDetails(d) {
  if (!d) return;
  const addrRows = (d.addresses.length ? d.addresses : [{ ip: d.ip, mac: d.mac }]).map((a) => el('tr', {}, el('td', {}, a.ip), el('td', {}, a.mac)));
  const body = [
    el('div', { class: 'details-head' },
      el('img', { src: 'icon-64x64.png', alt: '' }),
      el('div', {}, el('div', { class: 'name' }, d.product), el('div', { class: 'sub' }, d.hostname || '', d.essid ? ` [${d.essid}]` : ''))),
    el('div', { class: 'kv' },
      el('span', { class: 'k' }, 'HW Address:'), el('span', { class: 'v' }, d.mac),
      el('span', { class: 'k' }, 'IP Address:'), el('span', { class: 'v' }, d.ip || 'Unknown'),
      el('span', { class: 'k' }, 'Version:'), el('span', { class: 'v' }, d.fullVersion || d.version),
      el('span', { class: 'k' }, 'Build Number:'), el('span', { class: 'v' }, d.build || 'Unknown'),
      el('span', { class: 'k' }, 'Uptime:'), el('span', { class: 'v' }, d.uptimeText || 'Unknown'),
      d.essid ? [el('span', { class: 'k' }, 'SSID:'), el('span', { class: 'v' }, `${d.essid}${d.isAp ? ' (AP)' : ''}`)] : null,
      el('span', { class: 'k' }, 'Rescue IP Address:'), el('span', { class: 'v' }, d.rescueIp)),
    el('fieldset', {}, el('legend', {}, 'Device Network Addresses'),
      el('table', { class: 'addr-table' }, el('thead', {}, el('tr', {}, el('th', {}, 'IP'), el('th', {}, 'HW Address'))), el('tbody', {}, addrRows))),
  ];
  const m = modal({
    title: d.hostname || d.product,
    body,
    buttons: [
      el('button', { type: 'button', class: 'left', onclick: () => { m.close(); showReboot(d); } }, 'Reboot'),
      el('button', { type: 'button', onclick: () => { m.close(); showRescue(d); } }, 'Rescue Web UI'),
      el('button', { type: 'button', onclick: () => openWeb(d) }, 'Web UI'),
      el('button', { type: 'button', class: 'primary', onclick: () => m.close() }, 'Close'),
    ],
  });
}

function loginForm({ advanced }) {
  const user = el('input', { type: 'text', value: 'ubnt', spellcheck: 'false' });
  const pass = el('input', { type: 'password' });
  const fields = { user, pass };
  const rows = [el('label', {}, 'Username:'), user, el('label', {}, 'Password:'), pass];
  if (advanced) {
    const toggle = el('input', { type: 'checkbox' });
    fields.sshPort = el('input', { type: 'number', min: 1, max: 65535, value: 22 });
    fields.remotePort = el('input', { type: 'number', min: 1, max: 65535, value: 443 });
    fields.localPort = el('input', { type: 'number', min: 1, max: 65535, value: 17114 });
    fields.scope = el('select');
    const adv = [
      el('label', {}, 'Remote SSH port:'), fields.sshPort,
      el('label', {}, 'Remote web UI port:'), fields.remotePort,
      el('label', {}, 'Local web UI port:'), fields.localPort,
      el('label', {}, 'Local interface name:'), fields.scope,
    ];
    discovery.interfaces().then((list) => {
      fields.scope.replaceChildren(...list.map((i) => el('option', { value: i.scope }, i.name)));
    });
    const setAdv = () => adv.forEach((n) => { n.hidden = !toggle.checked; });
    toggle.addEventListener('change', setAdv);
    setAdv();
    rows.push(el('label', { class: 'full check' }, toggle, 'Show advanced options'), ...adv);
  }
  return { form: el('div', { class: 'form' }, rows), fields };
}

function showReboot(d) {
  if (!d) return;
  const { form, fields } = loginForm({ advanced: false });
  const status = el('p', {});
  const ok = el('button', { type: 'button', class: 'primary' }, 'Ok');
  const m = modal({
    title: `Login ${d.hostname || d.product}`,
    body: [el('p', {}, el('b', {}, 'Reboot Credentials')), form, status],
    buttons: [ok, el('button', { type: 'button', onclick: () => m.close() }, 'Cancel')],
  });
  const submit = async () => {
    if (!fields.user.value || !fields.pass.value) return;
    ok.disabled = true;
    status.className = '';
    status.textContent = 'Sending reboot command...';
    const res = await discovery.reboot({ id: d.id, username: fields.user.value, password: fields.pass.value });
    if (res.ok) {
      status.className = 'ok';
      status.textContent = 'Reboot command sent.';
      setTimeout(() => m.close(), 1200);
    } else {
      status.className = 'error';
      status.textContent = res.error;
      ok.disabled = false;
    }
  };
  ok.addEventListener('click', submit);
  m.dialog.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
}

const TUNNEL_ERRORS = {
  auth: () => 'Authentication failed.',
  timeout: () => 'Connection timed out.',
  connection: (d, p) => `Failed to connect to ${d.rescueIp} on port ${p.sshPort}.`,
  port: (_d, p) => `Failed to bind local port ${p.localPort}.`,
  noresponse: (_d, p) => `Web UI is not responding on remote port ${p.remotePort}.`,
};

function showRescue(d) {
  if (!d) return;
  const { form, fields } = loginForm({ advanced: true });
  const status = el('p', {});
  const ok = el('button', { type: 'button', class: 'primary' }, 'Ok');
  const m = modal({
    title: `Login ${d.hostname || d.product}`,
    body: [
      el('div', { class: 'description' }, el('b', {}, 'Description'), el('br'),
        "Use this feature if the device's web UI is not accessible. The device must be on the same physical network and IPv6 support must be enabled on the device. Remote web UI port will be forwarded to a local port making the web UI accessible on the local port. A web browser will be opened once the port forwarding is established."),
      el('p', {}, el('b', {}, 'SSH Credentials')),
      form,
      status,
    ],
    buttons: [ok, el('button', { type: 'button', onclick: () => m.close() }, 'Cancel')],
  });
  const submit = async () => {
    if (!fields.user.value || !fields.pass.value) return;
    const params = {
      host: d.rescueIp,
      scope: fields.scope.value,
      sshPort: Number(fields.sshPort.value) || 22,
      remotePort: Number(fields.remotePort.value) || 443,
      localPort: Number(fields.localPort.value) || 17114,
      username: fields.user.value,
      password: fields.pass.value,
    };
    ok.disabled = true;
    status.className = '';
    status.textContent = `Connecting to ${d.rescueIp}...`;
    const res = await discovery.openTunnel(params);
    if (!res.ok) {
      status.className = 'error';
      status.textContent = (TUNNEL_ERRORS[res.code] || (() => `Failed to forward Web UI. ${res.error}`))(d, params);
      ok.disabled = false;
      return;
    }
    m.close();
    showTunnel(res.url);
  };
  ok.addEventListener('click', submit);
  m.dialog.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
}

function showTunnel(url) {
  const m = modal({
    title: 'SSH Tunnel',
    body: [
      el('p', {}, el('b', {}, 'Connected')),
      el('p', {}, 'SSH tunnel is active.'),
      el('p', {}, 'Web UI is accessible at ', el('b', {}, url), '.'),
      el('p', {}, 'Closing this dialog will close the SSH tunnel.'),
    ],
    buttons: [
      el('button', { type: 'button', onclick: () => discovery.openWeb(url) }, 'Web UI'),
      el('button', { type: 'button', class: 'primary', onclick: () => { discovery.closeTunnel(); m.close(); } }, 'Close'),
    ],
    onKey: () => { discovery.closeTunnel(); m.close(); return true; },
  });
}

discovery.onConfirmExit(() => {
  if (document.querySelector('.backdrop.exit')) return;
  const dontAsk = el('input', { type: 'checkbox' });
  const m = modal({
    title: 'Exit',
    body: [el('p', {}, 'Are you sure you want to exit?'), el('label', { class: 'check' }, dontAsk, ' Do not ask this again')],
    buttons: [
      el('button', { type: 'button', class: 'primary', onclick: () => discovery.exit({ dontAskAgain: dontAsk.checked }) }, 'Ok'),
      el('button', { type: 'button', onclick: () => m.close() }, 'Cancel'),
    ],
  });
  m.dialog.parentElement.classList.add('exit');
});

// ---------- scan / search ----------

scanBtn.addEventListener('click', () => discovery.scan());

discovery.onProgress(({ scanning, remaining }) => {
  scanBtn.disabled = scanning;
  scanBtn.textContent = scanning ? `Scanning (${remaining}s)` : 'Scan';
});

discovery.onDevice((d) => {
  state.devices.set(d.id, d);
  render();
});

discovery.onCleared(() => {
  state.devices.clear();
  state.selected.clear();
  render();
});

$('#search').addEventListener('input', (e) => {
  state.filter = e.target.value;
  render();
});
$('#clear-search').addEventListener('click', () => {
  $('#search').value = '';
  state.filter = '';
  render();
});

discovery.info().then(({ version }) => {
  document.title = `Ubiquiti Discovery  [ v${version} ]`;
});
discovery.devices().then((list) => {
  list.forEach((d) => state.devices.set(d.id, d));
  render();
});

// ---------- themes ----------

const themeSelect = $('#theme');
let systemDark = true;

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme === 'system' ? (systemDark ? 'dark' : 'light') : theme;
}

discovery.getTheme().then(({ theme, systemDark: dark }) => {
  systemDark = dark;
  themeSelect.value = theme;
  applyTheme(theme);
});

themeSelect.addEventListener('change', () => {
  applyTheme(themeSelect.value);
  discovery.setTheme(themeSelect.value);
});

discovery.onSystemTheme((dark) => {
  systemDark = dark;
  if (themeSelect.value === 'system') applyTheme('system');
});
