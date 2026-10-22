'use strict';

const dgram = require('dgram');
const os = require('os');
const { EventEmitter } = require('events');
const proto = require('./protocol');
const { challengeResponse } = require('./crypt');

// Same timing as the original: a scan lasts 10 s and sends 20 queries (one every 500 ms).
const SCAN_DURATION_MS = 10000;
const SCAN_REPEATS = 20;
const REBOOT_TIMEOUT_MS = 5000;

function localIPv4Addresses() {
  const out = [];
  for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
    for (const a of addrs || []) {
      if (a.family === 'IPv4' && !a.internal) out.push({ name, address: a.address });
    }
  }
  return out;
}

function sameSubnet24(a, b) {
  return typeof a === 'string' && typeof b === 'string' && a.split('.').slice(0, 3).join('.') === b.split('.').slice(0, 3).join('.');
}

class Scanner extends EventEmitter {
  constructor() {
    super();
    this.sockets = new Map(); // local address -> dgram socket
    this.timer = null;
    this.pendingChallenges = new Map(); // mac key -> resolver
    this.routes = new Map(); // device id -> local address whose socket heard it
    this.rebooting = new Set(); // device ids with a reboot in progress
  }

  async openSockets() {
    const wanted = localIPv4Addresses();
    const wantedSet = new Set(wanted.map((w) => w.address));
    for (const [addr, sock] of this.sockets) {
      if (!wantedSet.has(addr)) {
        sock.close();
        this.sockets.delete(addr);
      }
    }
    await Promise.all(
      wanted
        .filter((w) => !this.sockets.has(w.address))
        .map((w) => this.bind(w.address).catch((err) => this.emit('log', `Failed binding on ${w.address}: ${err.message}`))),
    );
  }

  bind(address) {
    return new Promise((resolve, reject) => {
      const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
      sock.once('error', reject);
      sock.bind({ address, port: 0, exclusive: false }, () => {
        sock.removeListener('error', reject);
        sock.setBroadcast(true);
        try {
          sock.setMulticastInterface(address);
          sock.setMulticastTTL(1);
        } catch {
          // Multicast is optional; broadcast still works.
        }
        sock.on('message', (msg, rinfo) => this.onMessage(msg, rinfo, address));
        sock.on('error', (err) => this.emit('log', `Socket ${address}: ${err.message}`));
        this.sockets.set(address, sock);
        resolve(sock);
      });
    });
  }

  onMessage(msg, rinfo, localAddress) {
    const result = proto.parsePacket(msg, rinfo.address);
    if (!result) return;
    if (result.kind === 'device') {
      // Prefer the interface on the device's own subnet when several hear it.
      const known = this.routes.get(result.device.id);
      if (!known || sameSubnet24(localAddress, result.device.ip)) this.routes.set(result.device.id, localAddress);
      this.emit('device', result.device);
    } else if (result.kind === 'challenge') {
      const resolver = (result.mac && this.pendingChallenges.get(result.mac)) || [...this.pendingChallenges.values()][0];
      if (resolver) resolver(result);
    }
  }

  // Commands go out on the one interface the device answered on: a device that
  // hears the challenge request twice issues a new challenge each time.
  sendCommand(deviceId, packet) {
    const route = this.routes.get(deviceId);
    const targets = route && this.sockets.has(route) ? [this.sockets.get(route)] : [...this.sockets.values()];
    for (const sock of targets) sock.send(packet, proto.PORT, proto.BROADCAST_ADDR);
  }

  sendQuery() {
    for (const sock of this.sockets.values()) {
      for (const query of [proto.QUERY, proto.QUERY_V2]) {
        sock.send(query, proto.PORT, proto.MULTICAST_ADDR);
        sock.send(query, proto.PORT, proto.BROADCAST_ADDR);
      }
    }
  }

  get scanning() {
    return this.timer !== null;
  }

  async scan() {
    this.stop();
    await this.openSockets();
    if (this.sockets.size === 0) {
      this.emit('log', 'No IPv4 network interfaces available.');
    }
    const interval = Math.max(100, SCAN_DURATION_MS / SCAN_REPEATS);
    let sent = 0;
    const started = Date.now();
    const tick = () => {
      this.sendQuery();
      sent++;
      const remaining = Math.max(0, Math.ceil((SCAN_DURATION_MS - (Date.now() - started)) / 1000));
      this.emit('progress', { scanning: true, remaining });
      if (sent >= SCAN_REPEATS) {
        this.stop();
      }
    };
    this.timer = setInterval(tick, interval);
    tick();
  }

  stop() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
      this.emit('progress', { scanning: false, remaining: 0 });
    }
  }

  // Ask the device for its current uptime with a few discovery queries.
  probeUptime(macKey, timeoutMs = 2000) {
    return new Promise((resolve) => {
      const onDevice = (d) => {
        if (d.id !== macKey) return;
        cleanup();
        resolve(d.uptime);
      };
      const timer = setInterval(() => this.sendQuery(), 500);
      const timeout = setTimeout(() => {
        cleanup();
        resolve(null);
      }, timeoutMs);
      const cleanup = () => {
        clearInterval(timer);
        clearTimeout(timeout);
        this.removeListener('device', onDevice);
      };
      this.on('device', onDevice);
      this.sendQuery();
    });
  }

  // The device does not acknowledge a reboot (a wrong password is silently
  // ignored), so confirm it by watching discovery: it either stops answering
  // or comes back with a smaller uptime.
  confirmReboot(macKey, uptimeBefore, { windowMs = 15000, silenceMs = 5000 } = {}) {
    return new Promise((resolve) => {
      const started = Date.now();
      let lastReply = Date.now();
      const onDevice = (d) => {
        if (d.id !== macKey) return;
        lastReply = Date.now();
        if (uptimeBefore > 0 && d.uptime >= 0 && d.uptime < uptimeBefore) finish(true);
      };
      const timer = setInterval(() => {
        if (Date.now() - lastReply >= silenceMs) finish(true);
        else if (Date.now() - started >= windowMs) finish(false);
        else this.sendQuery();
      }, 1000);
      const finish = (rebooted) => {
        clearInterval(timer);
        this.removeListener('device', onDevice);
        resolve(rebooted);
      };
      this.on('device', onDevice);
    });
  }

  // Reboot: ask for a challenge (cmd 2), then answer with cmd 1 and
  // SHA-256(crypt(password, salt) || challenge). Resolves to true when the
  // device was seen restarting, false when it kept running.
  async reboot(macKey, username, password) {
    if (this.rebooting.has(macKey)) throw new Error('A reboot request for this device is already in progress.');
    this.rebooting.add(macKey);
    try {
      return await this.rebootOnce(macKey, username, password);
    } finally {
      this.rebooting.delete(macKey);
    }
  }

  async rebootOnce(macKey, username, password) {
    await this.openSockets();
    const uptimeBefore = await this.probeUptime(macKey);
    const mac = proto.macBytesFromKey(macKey);
    const challenge = await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pendingChallenges.delete(macKey);
        reject(new Error('The device did not answer the reboot request. Only airOS devices support reboot from Discovery; EdgeSwitch, EdgeRouter and UniFi devices must be restarted from their web UI or SSH.'));
      }, REBOOT_TIMEOUT_MS);
      this.pendingChallenges.set(macKey, (c) => {
        clearTimeout(timeout);
        this.pendingChallenges.delete(macKey);
        resolve(c);
      });
      this.sendCommand(macKey, proto.buildPacket(proto.CMD.CHALLENGE, [[proto.TLV.MAC, mac], [proto.TLV.USERNAME, username]]));
    });
    const response = challengeResponse(password, challenge.salt, challenge.challenge);
    this.sendCommand(
      macKey,
      proto.buildPacket(proto.CMD.REBOOT, [
        [proto.TLV.MAC, mac],
        [proto.TLV.USERNAME, username],
        [proto.TLV.RESPONSE, response],
      ]),
    );
    return this.confirmReboot(macKey, uptimeBefore);
  }

  close() {
    this.stop();
    for (const sock of this.sockets.values()) sock.close();
    this.sockets.clear();
  }
}

module.exports = { Scanner, localIPv4Addresses, SCAN_DURATION_MS };
