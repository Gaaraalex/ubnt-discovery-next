'use strict';

// "Rescue Web UI": SSH to the device over its IPv6 link-local address and
// forward a local port to the device's web UI port (defaults 22 / 443 -> 17114).

const net = require('net');
const http = require('http');
const https = require('https');
const ssh = require('./ssh');

class SshTunnel {
  constructor() {
    this.client = null;
    this.server = null;
  }

  async open({ host, scope, sshPort, username, password, remotePort, localPort }) {
    this.close();
    const target = scope ? `${host}%${scope}` : host;
    const client = await ssh.connect({ host: target, port: sshPort, username, password });
    this.client = client;

    const server = net.createServer((sock) => {
      client.forwardOut('127.0.0.1', sock.remotePort || 0, '127.0.0.1', remotePort, (err, stream) => {
        if (err) {
          sock.destroy();
          return;
        }
        sock.pipe(stream).pipe(sock);
        sock.on('error', () => stream.close());
        stream.on('error', () => sock.destroy());
      });
    });
    try {
      await new Promise((resolve, reject) => {
        server.once('error', () => reject(Object.assign(new Error(`No se pudo usar el puerto local ${localPort}.`), { code: 'port' })));
        server.listen(localPort, '127.0.0.1', resolve);
      });
    } catch (err) {
      this.close();
      throw err;
    }
    this.server = server;

    const scheme = await this.detectScheme(localPort, remotePort);
    if (!scheme) {
      this.close();
      throw Object.assign(new Error(`La interfaz web no responde en el puerto remoto ${remotePort}.`), { code: 'noresponse' });
    }
    return `${scheme}://localhost:${localPort}`;
  }

  // Probe the forwarded port like the original: prefer the port's natural
  // scheme, and switch to https when http redirects there.
  async detectScheme(localPort, remotePort) {
    const order = remotePort === 80 ? ['http', 'https'] : ['https', 'http'];
    for (const scheme of order) {
      const res = await probe(scheme, localPort);
      if (!res) continue;
      if (scheme === 'http' && (res.status === 301 || res.status === 302) && /^https:/i.test(res.location || '')) return 'https';
      return scheme;
    }
    return null;
  }

  close() {
    if (this.server) {
      this.server.close();
      this.server = null;
    }
    if (this.client) {
      this.client.end();
      this.client = null;
    }
  }
}

function probe(scheme, port) {
  const mod = scheme === 'https' ? https : http;
  return new Promise((resolve) => {
    const req = mod.get({ host: '127.0.0.1', port, path: '/', timeout: 8000, rejectUnauthorized: false }, (res) => {
      res.resume();
      resolve({ status: res.statusCode, location: res.headers.location });
    });
    req.on('timeout', () => {
      req.destroy();
      resolve(null);
    });
    req.on('error', () => resolve(null));
  });
}

module.exports = { SshTunnel };
