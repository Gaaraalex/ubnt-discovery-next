'use strict';

// Ubiquiti discovery protocol ("LiteStationQueryServer"), reconstructed from
// ubnt-discovery-v2.5.1.jar (classes com.OoOO.super.A.o0oO / int / C / if),
// extended with the v2 / UniFi fields documented by Wireshark's UBDP dissector
// and nmap's ubiquiti-discovery script.
//
// Query v1:  01 00 00 00                    -> UDP 10001 (255.255.255.255 and 233.89.188.1)
// Query v2:  02 08 00 00                    (UniFi devices)
// Reply:     <ver:1|2> <cmd> <len:u16> { <type:u8> <len:u16> <data> }*
// Reply v0:  00 <mac:6> <ip:4> <len:u32> <firmware>

const PRODUCTS = require('./products');
const UNIFI_MODELS = require('./unifi-models');

const PORT = 10001;
const BROADCAST_ADDR = '255.255.255.255';
const MULTICAST_ADDR = '233.89.188.1';
const QUERY = Buffer.from([0x01, 0x00, 0x00, 0x00]);
const QUERY_V2 = Buffer.from([0x02, 0x08, 0x00, 0x00]);

// Command codes (byte 1 of a v1 packet).
const CMD = { DISCOVERY: 0, REBOOT: 1, CHALLENGE: 2 };
// Discovery reply commands seen in v2 packets.
const V2_REPLY_CMDS = new Set([6, 9, 11]);

const TLV = {
  MAC: 0x01,
  MAC_IP: 0x02,
  FIRMWARE: 0x03,
  IP: 0x04,
  MAC2: 0x05,
  USERNAME: 0x06,
  SALT: 0x07,
  CHALLENGE: 0x08,
  RESPONSE: 0x09,
  UPTIME: 0x0a,
  HOSTNAME: 0x0b,
  PLATFORM: 0x0c,
  ESSID: 0x0d,
  WMODE: 0x0e,
  WEBUI: 0x0f,
  SYSTEM_ID: 0x10,
  SEQ: 0x12,
  SERIAL: 0x13,
  MODEL_SHORT: 0x14,
  MODEL: 0x15,
  VERSION: 0x16,
  DEFAULT: 0x17,
  LOCATING: 0x18,
  DHCP: 0x19,
  DHCP_BOUND: 0x1a,
  REQ_FIRMWARE: 0x1b,
  SSH_PORT: 0x1c,
};

const WIRELESS_MODES = ['auto', 'adhoc', 'station', 'ap', 'repeater', 'secondary', 'monitor'];
const WMODE_AP = 3;
const UNKNOWN = 'Unknown';

// Firmware platform prefixes of UniFi products (airOS / UISP use XM, XW, XC, WA, TI, SW...).
const UNIFI_FW_PREFIXES = ['BZ', 'U', 'US'];

function readUInt(buf) {
  let v = 0;
  for (const b of buf) v = v * 256 + b;
  return v;
}

function formatMac(mac) {
  if (!mac || mac.length < 6) return '';
  return [...mac].map((b) => b.toString(16).padStart(2, '0').toUpperCase()).join('-');
}

function macKey(mac) {
  return Buffer.from(mac).toString('hex');
}

function parseIPv4(buf) {
  return [...buf].join('.');
}

// fe80::<EUI-64 from MAC>, used by "Rescue Web UI" (o0~.Ö00000).
function linkLocalFromMac(mac) {
  const b = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, mac[0] ^ 0x02, mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5]];
  const groups = [];
  for (let i = 8; i < 16; i += 2) groups.push(((b[i] << 8) | b[i + 1]).toString(16));
  return `fe80::${groups.join(':')}`;
}

function productName(code) {
  for (const [prefix, name] of PRODUCTS) {
    if (code.startsWith(prefix)) return name;
  }
  return code;
}

function unifiModelName(code) {
  if (!code) return '';
  return UNIFI_MODELS[code] || code;
}

// Firmware string, e.g. "XW.ar934x.v6.1.7.32555.180523.1754":
//   platform . arch . <version tokens...> . build . date . time
function parseFirmware(fw) {
  const tokens = (fw || '').split('.').filter((t) => t.length > 0);
  if (tokens.length < 6) {
    return { platform: UNKNOWN, arch: UNKNOWN, version: UNKNOWN, build: '', date: '', time: '', full: UNKNOWN };
  }
  const versionCount = tokens.length - 5;
  const version = tokens.slice(2, 2 + versionCount).join('.');
  const [build, date, time] = tokens.slice(2 + versionCount);
  // Pre-release versions ("v6.0-beta") show build/date/time too.
  const full = version.indexOf('-') > 0 ? `${version}.${build}.${date}.${time}` : version;
  return { platform: tokens[0], arch: tokens[1], version, build, date, time, full };
}

function formatUptime(seconds) {
  if (seconds == null || seconds < 0) return '';
  const days = Math.floor(seconds / 86400);
  const pad = (n) => String(n).padStart(2, '0');
  const hms = `${pad(Math.floor(seconds / 3600) % 24)}:${pad(Math.floor(seconds / 60) % 60)}:${pad(seconds % 60)}`;
  if (days <= 0) return hms;
  return `${days} ${days === 1 ? 'day' : 'days'} ${hms}`;
}

function* iterTlv(buf, start, end) {
  let p = start;
  while (p < end) {
    if (p + 3 > end) throw new Error('truncated TLV header');
    const type = buf[p];
    const len = buf.readUInt16BE(p + 1);
    p += 3;
    if (p + len > end) throw new Error(`invalid length (${len}) for item ${type}`);
    yield { type, data: buf.subarray(p, p + len) };
    p += len;
  }
}

function makeDevice({ mac, ip, firmware, version }) {
  const fw = parseFirmware(firmware);
  return {
    id: macKey(mac),
    family: 'airos',
    mac: formatMac(mac),
    macBytes: [...mac],
    ip,
    addresses: [],
    firmware,
    platformCode: fw.platform,
    product: productName(fw.platform),
    version: fw.version,
    fullVersion: fw.full,
    build: fw.build,
    hostname: '',
    essid: '',
    wmode: -1,
    wmodeName: '',
    uptime: -1,
    uptimeText: '',
    model: '',
    serial: '',
    isDefault: null,
    webPort: 0,
    webHttps: false,
    sshPort: 22,
    protocolVersion: version,
    rescueIp: linkLocalFromMac(mac),
  };
}

function isUnifi(d, raw) {
  if (d.protocolVersion === 2) return true;
  if (raw.isDefault !== null || raw.versionStr) return true;
  const code = raw.model || raw.modelShort || raw.platform || '';
  if (/^U/.test(code)) return true;
  return UNIFI_FW_PREFIXES.some((p) => (p === 'U' ? /^U[A-Z0-9]/.test(d.platformCode) : d.platformCode === p));
}

// Returns { kind: 'device', device } | { kind: 'challenge', mac, salt, challenge } | null
function parsePacket(buf, sourceIp) {
  if (!buf || buf.length === 0) return null;
  if (buf[0] === 0) return parseV0(buf);
  if (buf[0] === 1 || buf[0] === 2) return parseTlvPacket(buf, sourceIp);
  return null;
}

function parseV0(buf) {
  if (buf.length < 15) return null;
  const mac = buf.subarray(1, 7);
  const ip = parseIPv4(buf.subarray(7, 11));
  const len = buf.readUInt32BE(11);
  let firmware = 'unknown';
  if (len > 0 && buf.length >= 15 + len) firmware = buf.toString('latin1', 15, 15 + len).trim();
  const device = makeDevice({ mac, ip, firmware, version: 0 });
  device.product = firmware;
  device.addresses.push({ mac: device.mac, ip });
  return { kind: 'device', device };
}

function parseTlvPacket(buf, sourceIp) {
  if (buf.length < 4) return null;
  const version = buf[0];
  const cmd = buf[1];
  const dataLen = buf.readUInt16BE(2);
  if (4 + dataLen > buf.length) return null;

  const raw = {
    mac: null,
    addresses: [],
    firmware: 'unknown',
    hostname: '',
    platform: '',
    essid: '',
    wmode: -1,
    uptime: -1,
    salt: null,
    challenge: null,
    model: '',
    modelShort: '',
    versionStr: '',
    serial: null,
    isDefault: null,
    webui: null,
    sshPort: null,
    ip: null,
  };

  try {
    for (const { type, data } of iterTlv(buf, 4, 4 + dataLen)) {
      switch (type) {
        case TLV.MAC:
        case TLV.MAC2:
          if (data.length === 6 && !raw.mac) raw.mac = Buffer.from(data);
          break;
        case TLV.MAC_IP:
          if (data.length === 10) raw.addresses.push({ mac: Buffer.from(data.subarray(0, 6)), ip: parseIPv4(data.subarray(6, 10)) });
          else if (data.length === 4) raw.ip = parseIPv4(data);
          break;
        case TLV.IP:
          if (data.length === 4) raw.ip = parseIPv4(data);
          break;
        case TLV.FIRMWARE:
          raw.firmware = data.toString('latin1').trim();
          break;
        case TLV.SALT:
          raw.salt = Buffer.from(data);
          break;
        case TLV.CHALLENGE:
          raw.challenge = Buffer.from(data);
          break;
        case TLV.UPTIME:
          raw.uptime = readUInt(data);
          break;
        case TLV.HOSTNAME:
          raw.hostname = data.toString('utf8');
          break;
        case TLV.PLATFORM:
          raw.platform = data.toString('latin1');
          break;
        case TLV.ESSID:
          raw.essid = data.toString('utf8');
          break;
        case TLV.WMODE:
          raw.wmode = readUInt(data);
          break;
        case TLV.WEBUI:
          raw.webui = readUInt(data);
          break;
        case TLV.SERIAL:
          if (data.length === 6) raw.serial = Buffer.from(data);
          break;
        case TLV.MODEL_SHORT:
          raw.modelShort = data.toString('latin1');
          break;
        case TLV.MODEL:
          raw.model = data.toString('latin1');
          break;
        case TLV.VERSION:
          raw.versionStr = data.toString('latin1');
          break;
        case TLV.DEFAULT:
          raw.isDefault = readUInt(data) === 1;
          break;
        case TLV.SSH_PORT:
          raw.sshPort = readUInt(data);
          break;
        default:
          break;
      }
    }
  } catch {
    return null;
  }

  const isDiscovery = version === 1 ? cmd === CMD.DISCOVERY : V2_REPLY_CMDS.has(cmd);
  if (isDiscovery) {
    if (raw.addresses.length === 0 && !raw.mac) return null;
    const primaryMac = raw.mac || raw.addresses[0].mac;
    const primaryIp = raw.addresses.length > 0 ? raw.addresses[0].ip : raw.ip || sourceIp;
    const device = makeDevice({ mac: primaryMac, ip: primaryIp, firmware: raw.firmware, version });
    device.uptime = raw.uptime;
    device.uptimeText = raw.uptime > 0 ? formatUptime(raw.uptime) : '';
    device.hostname = raw.hostname;
    if (raw.platform.length > 0) device.product = productName(raw.platform);
    device.platform = raw.platform;
    device.essid = raw.essid;
    device.wmode = raw.wmode;
    device.wmodeName = raw.wmode >= 0 && raw.wmode < WIRELESS_MODES.length ? WIRELESS_MODES[raw.wmode] : '';
    device.isAp = raw.wmode === WMODE_AP;
    device.addresses = raw.addresses.map((a) => ({ mac: formatMac(a.mac), ip: a.ip }));
    device.isDefault = raw.isDefault;
    device.serial = raw.serial ? formatMac(raw.serial).replace(/-/g, '') : '';
    if (raw.sshPort) device.sshPort = raw.sshPort;
    if (raw.webui != null) {
      // Low 16 bits = port; upper bits flag HTTPS.
      device.webPort = raw.webui & 0xffff;
      device.webHttps = raw.webui > 0xffff || device.webPort === 443;
    }
    const answering = raw.addresses.find((a) => a.ip === sourceIp);
    if (answering) device.rescueIp = linkLocalFromMac(answering.mac);

    if (isUnifi(device, raw)) {
      device.family = 'unifi';
      const code = raw.model || raw.modelShort || raw.platform || device.platformCode;
      device.model = code;
      device.product = unifiModelName(code);
      if (raw.versionStr) device.version = raw.versionStr;
    }
    return { kind: 'device', device };
  }

  if (version === 1 && cmd === CMD.CHALLENGE) {
    if (!raw.salt || !raw.challenge) return null;
    return { kind: 'challenge', mac: raw.mac ? macKey(raw.mac) : null, salt: raw.salt, challenge: raw.challenge };
  }

  return null;
}

// Packet builder (com.OoOO.super.A.if): 01 <cmd> <len:u16> TLVs...
function buildPacket(cmd, items) {
  const parts = [];
  for (const [type, value] of items) {
    if (value == null) continue;
    const data = Buffer.isBuffer(value) ? value : Buffer.from(value, 'latin1');
    const head = Buffer.alloc(3);
    head[0] = type;
    head.writeUInt16BE(data.length, 1);
    parts.push(head, data);
  }
  const body = Buffer.concat(parts);
  const header = Buffer.from([0x01, cmd, 0, 0]);
  header.writeUInt16BE(body.length, 2);
  return Buffer.concat([header, body]);
}

function macBytesFromKey(key) {
  return Buffer.from(key, 'hex');
}

function webUrl(device) {
  const https = device.webHttps;
  const port = device.webPort;
  const scheme = https ? 'https' : 'http';
  const showPort = port && !((https && port === 443) || (!https && port === 80));
  return `${scheme}://${device.ip}${showPort ? `:${port}` : ''}`;
}

module.exports = {
  PORT,
  BROADCAST_ADDR,
  MULTICAST_ADDR,
  QUERY,
  QUERY_V2,
  CMD,
  TLV,
  WIRELESS_MODES,
  parsePacket,
  buildPacket,
  parseFirmware,
  productName,
  unifiModelName,
  formatMac,
  formatUptime,
  linkLocalFromMac,
  macKey,
  macBytesFromKey,
  webUrl,
};
