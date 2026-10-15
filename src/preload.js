'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('discovery', {
  info: () => ipcRenderer.invoke('info'),
  getTheme: () => ipcRenderer.invoke('theme-get'),
  setTheme: (theme) => ipcRenderer.invoke('theme-set', theme),
  onSystemTheme: (cb) => ipcRenderer.on('system-theme', (_e, dark) => cb(dark)),
  scan: () => ipcRenderer.invoke('scan'),
  devices: () => ipcRenderer.invoke('devices'),
  interfaces: () => ipcRenderer.invoke('interfaces'),
  openWeb: (url) => ipcRenderer.invoke('open-web', url),
  copy: (text) => ipcRenderer.invoke('copy', text),
  reboot: (params) => ipcRenderer.invoke('reboot', params),
  openTunnel: (params) => ipcRenderer.invoke('tunnel-open', params),
  closeTunnel: () => ipcRenderer.invoke('tunnel-close'),
  exit: (params) => ipcRenderer.invoke('exit', params),
  errorBox: (title, message) => ipcRenderer.invoke('error-box', { title, message }),
  onDevice: (cb) => ipcRenderer.on('device', (_e, d) => cb(d)),
  onCleared: (cb) => ipcRenderer.on('cleared', () => cb()),
  onProgress: (cb) => ipcRenderer.on('progress', (_e, p) => cb(p)),
  onConfirmExit: (cb) => ipcRenderer.on('confirm-exit', () => cb()),
});
