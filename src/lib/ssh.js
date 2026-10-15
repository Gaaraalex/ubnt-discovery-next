'use strict';

const { Client } = require('ssh2');

// Old airOS / UniFi firmware only offers legacy algorithms.
const LEGACY_ALGORITHMS = {
  kex: { append: ['diffie-hellman-group14-sha1', 'diffie-hellman-group1-sha1', 'diffie-hellman-group-exchange-sha1'] },
  serverHostKey: { append: ['ssh-rsa', 'ssh-dss'] },
  cipher: { append: ['aes128-cbc', 'aes256-cbc', '3des-cbc'] },
  hmac: { append: ['hmac-sha1', 'hmac-md5'] },
};

function sshError(err, target, port) {
  if (err.level === 'client-authentication') return Object.assign(new Error('Usuario o contraseña incorrectos.'), { code: 'auth' });
  if (err.level === 'client-timeout') return Object.assign(new Error('Tiempo de conexión agotado.'), { code: 'timeout' });
  return Object.assign(new Error(`No se pudo conectar a ${target} en el puerto ${port}.`), { code: 'connection' });
}

function connect({ host, port = 22, username, password }) {
  const client = new Client();
  return new Promise((resolve, reject) => {
    client
      .once('ready', () => resolve(client))
      .once('error', (err) => reject(sshError(err, host, port)))
      .on('keyboard-interactive', (_n, _i, _l, prompts, finish) => finish(prompts.map(() => password)))
      .connect({ host, port, username, password, readyTimeout: 15000, tryKeyboard: true, algorithms: LEGACY_ALGORITHMS });
  });
}

// Run one command and return its output (stdout + stderr).
async function exec(params, command, { timeoutMs = 20000 } = {}) {
  const client = await connect(params);
  try {
    return await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('El comando tardó demasiado.')), timeoutMs);
      client.exec(command, (err, stream) => {
        if (err) {
          clearTimeout(timer);
          reject(err);
          return;
        }
        let out = '';
        stream.on('data', (d) => (out += d)).stderr.on('data', (d) => (out += d));
        stream.on('close', (code) => {
          clearTimeout(timer);
          resolve({ code, output: out.trim() });
        });
      });
    });
  } finally {
    client.end();
  }
}

// UniFi: point the device at a controller (the usual first step of adoption).
function setInform(params, url) {
  const safe = String(url).replace(/[^A-Za-z0-9:/._?=&%-]/g, '');
  return exec(params, `mca-cli-op set-inform ${safe} || /usr/bin/syswrapper.sh set-inform ${safe}`);
}

function sshReboot(params) {
  // The connection drops while rebooting; that is success.
  return exec(params, 'reboot', { timeoutMs: 8000 }).catch((err) => {
    if (err.code === 'auth' || err.code === 'connection' || err.code === 'timeout') throw err;
    return { code: 0, output: '' };
  });
}

module.exports = { connect, exec, setInform, sshReboot, LEGACY_ALGORITHMS };
