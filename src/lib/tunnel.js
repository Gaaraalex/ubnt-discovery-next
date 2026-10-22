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

  // scope: an interface scope id, or "auto" with `scopes` (all local IPv6
  // interfaces) so the right one is found by trying them all at once.
  // fallbackHost (the device's IPv4 address) is tried too when in auto mode.
  async open({ host, scope, scopes = [], fallbackHost, sshPort, username, password, remotePort, localPort }) {
    this.close();
    let target = scope ? `${host}%${scope}` : host;
    if (scope === 'auto') {
      const candidates = scopes.map((s) => `${host}%${s}`);
      if (fallbackHost) candidates.push(fallbackHost);
      target = await firstReachable(candidates, sshPort);
      if (!target) {
        throw Object.assign(new Error(`SSH port ${sshPort} is not reachable on ${host} through any network interface.`), { code: 'unreachable' });
      }
    }
    this.target = target;
    const client = await ssh.connect({ host: target, port: sshPort, username, password });
    this.client = client;

    // Where the device should send the forwarded traffic. airOS serves its web
    // UI on 127.0.0.1 (what the original used); EdgeSwitch and others only on
    // their management IP, so that is tried next.
    const destinations = ['127.0.0.1', fallbackHost].filter(Boolean);
    let destIndex = 0;
    let forwardError = null;
    const server = net.createServer((sock) => {
      client.forwardOut('127.0.0.1', sock.remotePort || 0, destinations[destIndex], remotePort, (err, stream) => {
        if (err) {
          forwardError = err;
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

    let scheme = await this.detectScheme(localPort, remotePort);
    while (!scheme && !isForwardingDenied(forwardError) && destIndex < destinations.length - 1) {
      destIndex++;
      forwardError = null;
      scheme = await this.detectScheme(localPort, remotePort);
    }
    if (!scheme) {
      this.close();
      if (isForwardingDenied(forwardError)) {
        throw Object.assign(new Error(`The device does not allow SSH port forwarding (${forwardError.message}).`), { code: 'forwarding-denied' });
      }
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

// reason 1 = SSH_OPEN_ADMINISTRATIVELY_PROHIBITED: the server forbids port
// forwarding (OpenSSH "AllowTcpForwarding no", Dropbear -j). Reason 2 means
// the forward was allowed but nothing listens on the remote port.
function isForwardingDenied(err) {
  return !!err && (err.reason === 1 || /prohibited/i.test(err.message || ''));
}

// TCP-connect to every candidate at once; resolve with the first that accepts.
function firstReachable(hosts, port, timeoutMs = 4000) {
  return new Promise((resolve) => {
    let pending = hosts.length;
    let done = false;
    if (pending === 0) resolve(null);
    for (const host of hosts) {
      const sock = net.connect({ host, port, timeout: timeoutMs });
      const fail = () => {
        sock.destroy();
        if (--pending === 0 && !done) resolve(null);
      };
      sock.once('connect', () => {
        sock.destroy();
        if (!done) {
          done = true;
          resolve(host);
        }
      });
      sock.once('timeout', fail);
      sock.once('error', fail);
    }
  });
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

module.exports = { SshTunnel, firstReachable, isForwardingDenied };
