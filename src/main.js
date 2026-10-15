'use strict';

const path = require('path');
const fs = require('fs');
const os = require('os');
const { app, BrowserWindow, ipcMain, shell, clipboard, dialog, nativeTheme } = require('electron');
const { Scanner } = require('./lib/scanner');
const { SshTunnel } = require('./lib/tunnel');
const pkg = require('../package.json');

// A second launch focuses the running window instead of failing silently.
if (!app.requestSingleInstanceLock()) {
  app.quit();
  process.exit(0);
}

// Same rule as the original: pressing Scan more than 5.5 s after the previous
// scan starts over with an empty list.
const RESCAN_CLEAR_MS = 5500;

const settingsFile = () => path.join(app.getPath('userData'), 'settings.json');

function loadSettings() {
  try {
    return JSON.parse(fs.readFileSync(settingsFile(), 'utf8'));
  } catch {
    return {};
  }
}

function saveSettings(settings) {
  try {
    fs.mkdirSync(path.dirname(settingsFile()), { recursive: true });
    fs.writeFileSync(settingsFile(), JSON.stringify(settings, null, 2));
  } catch {
    // Settings are a convenience only.
  }
}

let settings = {};
let win = null;
let lastScanAt = 0;
let quitting = false;
const devices = new Map();
const scanner = new Scanner();
const tunnel = new SshTunnel();

function send(channel, payload) {
  if (win && !win.isDestroyed()) win.webContents.send(channel, payload);
}

scanner.on('device', (device) => {
  const previous = devices.get(device.id);
  devices.set(device.id, previous ? { ...previous, ...device } : device);
  send('device', devices.get(device.id));
});
scanner.on('progress', (p) => send('progress', p));
scanner.on('log', (msg) => console.log(msg));

function startScan() {
  const now = Date.now();
  if (now > lastScanAt + RESCAN_CLEAR_MS) {
    devices.clear();
    send('cleared');
  }
  lastScanAt = now;
  scanner.scan();
}

// IPv6-capable interfaces for the rescue tunnel's link-local scope.
function ipv6Interfaces() {
  const out = [];
  for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
    const ll = (addrs || []).find((a) => a.family === 'IPv6' && !a.internal && a.address.toLowerCase().startsWith('fe80'));
    if (ll) out.push({ name, scope: process.platform === 'win32' ? String(ll.scopeid) : name });
  }
  return out;
}

// Window background per theme, so the window never flashes a different color while loading.
const THEME_BACKGROUNDS = {
  light: '#eef0f3',
  dark: '#1e2127',
  midnight: '#05070a',
  ubiquiti: '#0b1f3a',
  terminal: '#0a120b',
  sand: '#f3eee4',
  contrast: '#000000',
};

function resolvedTheme() {
  const theme = settings.theme || 'system';
  if (theme === 'system') return nativeTheme.shouldUseDarkColors ? 'dark' : 'light';
  return theme;
}

function themeBackground() {
  return THEME_BACKGROUNDS[resolvedTheme()] || THEME_BACKGROUNDS.dark;
}

function createWindow() {
  const bounds = settings.window || { width: 900, height: 520 };
  win = new BrowserWindow({
    ...bounds,
    minWidth: 640,
    minHeight: 360,
    show: false,
    backgroundColor: themeBackground(),
    title: `Ubiquiti Discovery  [ v${pkg.version} ]`,
    icon: path.join(__dirname, 'renderer', 'icon-256x256.png'),
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  win.removeMenu();
  win.once('ready-to-show', () => win.show());
  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));

  win.on('close', (e) => {
    settings.window = win.getBounds();
    saveSettings(settings);
    if (quitting || settings.skipExitConfirm) return;
    e.preventDefault();
    send('confirm-exit');
  });
  win.on('closed', () => {
    win = null;
  });
}

app.on('second-instance', () => {
  if (!win) {
    createWindow();
    return;
  }
  if (win.isMinimized()) win.restore();
  win.show();
  win.focus();
});

ipcMain.handle('info', () => ({ version: pkg.version, platform: process.platform }));

ipcMain.handle('theme-get', () => ({ theme: settings.theme || 'system', systemDark: nativeTheme.shouldUseDarkColors }));
ipcMain.handle('theme-set', (_e, theme) => {
  if (!Object.hasOwn(THEME_BACKGROUNDS, theme) && theme !== 'system') return;
  settings.theme = theme;
  saveSettings(settings);
  if (win) win.setBackgroundColor(themeBackground());
});
nativeTheme.on('updated', () => send('system-theme', nativeTheme.shouldUseDarkColors));
ipcMain.handle('scan', () => startScan());
ipcMain.handle('devices', () => [...devices.values()]);
ipcMain.handle('interfaces', () => ipv6Interfaces());

ipcMain.handle('open-web', (_e, url) => {
  if (!/^https?:\/\//i.test(url)) return false;
  return shell.openExternal(url).then(
    () => true,
    () => false,
  );
});

ipcMain.handle('copy', (_e, text) => {
  clipboard.writeText(String(text));
});

ipcMain.handle('reboot', async (_e, { id, username, password }) => {
  try {
    await scanner.reboot(id, username, password);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
});

ipcMain.handle('tunnel-open', async (_e, params) => {
  try {
    const url = await tunnel.open(params);
    shell.openExternal(url);
    return { ok: true, url };
  } catch (err) {
    return { ok: false, code: err.code || 'forwarding', error: err.message };
  }
});

ipcMain.handle('tunnel-close', () => tunnel.close());

ipcMain.handle('exit', (_e, { dontAskAgain }) => {
  if (dontAskAgain) {
    settings.skipExitConfirm = true;
    saveSettings(settings);
  }
  quitting = true;
  app.quit();
});

ipcMain.handle('error-box', (_e, { title, message }) => {
  dialog.showMessageBox(win, { type: 'error', title, message });
});

app.whenReady().then(() => {
  settings = loadSettings();
  createWindow();
  win.webContents.once('did-finish-load', () => {
    startScan();
    // Smoke test: UBNT_SMOKE_SCREENSHOT=<file.png> captures the window after the scan starts, then quits.
    //   UBNT_SMOKE_SIZE=WxH       content size for the captures
    //   UBNT_SMOKE_DELAY=ms       wait before capturing (default 4000)
    //   UBNT_SMOKE_THEMES=a,b,... also captures <shot>-<theme>.png per theme
    //   UBNT_SMOKE_JS=<code>      runs in the page before the final capture
    const shot = process.env.UBNT_SMOKE_SCREENSHOT;
    if (shot) {
      const size = /^(\d+)x(\d+)$/.exec(process.env.UBNT_SMOKE_SIZE || '');
      if (size) win.setContentSize(Number(size[1]), Number(size[2]));
      setTimeout(async () => {
        for (const theme of (process.env.UBNT_SMOKE_THEMES || '').split(',').filter(Boolean)) {
          const t = JSON.stringify(theme);
          await win.webContents.executeJavaScript(`document.documentElement.dataset.theme = ${t}; document.querySelector('#theme').value = ${t};`);
          await new Promise((r) => setTimeout(r, 300));
          fs.writeFileSync(shot.replace(/\.png$/, `-${theme}.png`), (await win.webContents.capturePage()).toPNG());
        }
        if (process.env.UBNT_SMOKE_JS) {
          await win.webContents.executeJavaScript(process.env.UBNT_SMOKE_JS);
          await new Promise((r) => setTimeout(r, 500));
        }
        fs.writeFileSync(shot, (await win.webContents.capturePage()).toPNG());
        quitting = true;
        app.quit();
      }, Number(process.env.UBNT_SMOKE_DELAY) || 4000);
    }
  });
});

app.on('window-all-closed', () => {
  scanner.close();
  tunnel.close();
  app.quit();
});
