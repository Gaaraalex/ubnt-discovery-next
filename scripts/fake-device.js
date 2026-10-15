'use strict';

// Simulated Ubiquiti device for testing: answers discovery on UDP 10001 and
// implements the reboot challenge (user "ubnt", password "ubnt").
//   node scripts/fake-device.js [ip-to-report] [--demo]
// --demo also answers for a small example network (used for README screenshots).
const dgram = require('dgram');
const crypto = require('crypto');
const proto = require('../src/lib/protocol');
const { challengeResponse } = require('../src/lib/crypt');

const args = process.argv.slice(2);
const DEMO = args.includes('--demo');
const MAC = Buffer.from([0x24, 0xa4, 0x3c, 0xde, 0xad, 0x01]);
const IP = (args.find((a) => !a.startsWith('--')) || '10.0.0.5').split('.').map(Number);
const SALT = Buffer.from('$1$fakesalt');
let challenge = null;

// [mac last byte, ip last octet, firmware, hostname, platform, essid, wmode, uptime s]
const DEMO_AIROS = [
  [0x11, 20, 'XW.ar934x.v6.3.11.33396.230425.1742', 'Torre-Norte', 'R5N', 'Enlace-Norte', 3, 3456789],
  [0x12, 21, 'XW.ar934x.v6.3.11.33396.230425.1742', 'Enlace-Bodega', 'NB5', 'Enlace-Norte', 2, 1234567],
  [0x13, 22, 'XW.ar934x.v6.3.6.33330.210818.1758', 'Cliente-Lopez', 'N5N', 'Sector-Este', 2, 98765],
  [0x14, 23, 'XM.ar7240.v6.1.7.32555.180523.1754', 'PtP-Cerro', 'AG5-HP', 'PtP-Cerro', 3, 7654321],
];
// [mac last byte, ip last octet, firmware, hostname, model, version, isDefault]
const DEMO_UNIFI = [
  [0x31, 40, 'US.bcm5334x.v6.6.61.15207.231211.1609', 'Switch-Rack', 'US24P250', '6.6.61.15207', 0],
  [0x32, 41, 'UAL6.mt7621.v6.6.55.15189.231108.1704', 'AP-Recepcion', 'UAL6', '6.6.55.15189', 0],
  [0x33, 42, 'U7PG2.qca956x.v6.5.62.14788.230403.1453', 'AP-Almacen', 'U7PG2', '6.5.62.14788', 1],
];

function demoMac(last) {
  return Buffer.from([0x74, 0x83, 0xc2, 0x10, 0x20, last]);
}

function demoIp(last) {
  return Buffer.from([192, 168, 1, last]);
}

function sendDemoAiros(rinfo) {
  for (const [m, ip, fw, host, platform, essid, wmode, up] of DEMO_AIROS) {
    const mac = demoMac(m);
    const uptime = Buffer.alloc(4);
    uptime.writeUInt32BE(up);
    const reply = proto.buildPacket(0, [
      [proto.TLV.MAC, mac],
      [proto.TLV.MAC_IP, Buffer.concat([mac, demoIp(ip)])],
      [proto.TLV.FIRMWARE, fw],
      [proto.TLV.UPTIME, uptime],
      [proto.TLV.HOSTNAME, host],
      [proto.TLV.PLATFORM, platform],
      [proto.TLV.ESSID, essid],
      [proto.TLV.WMODE, Buffer.from([wmode])],
    ]);
    sock.send(reply, rinfo.port, rinfo.address);
  }
}

function sendDemoUnifi(rinfo) {
  for (const [m, ip, fw, host, model, version, isDefault] of DEMO_UNIFI) {
    const mac = demoMac(m);
    const reply = proto.buildPacket(6, [
      [proto.TLV.MAC, mac],
      [proto.TLV.MAC_IP, Buffer.concat([mac, demoIp(ip)])],
      [proto.TLV.FIRMWARE, fw],
      [proto.TLV.HOSTNAME, host],
      [proto.TLV.MODEL, model],
      [proto.TLV.VERSION, version],
      [proto.TLV.DEFAULT, Buffer.from([isDefault])],
    ]);
    reply[0] = 2;
    sock.send(reply, rinfo.port, rinfo.address);
  }
}

const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
sock.on('message', (msg, rinfo) => {
  if (msg.length === 4 && msg[0] === 1 && msg[1] === 0) {
    const uptime = Buffer.alloc(4);
    uptime.writeUInt32BE(Math.floor(process.uptime()) + 123456);
    const reply = proto.buildPacket(0, [
      [proto.TLV.MAC, MAC],
      [proto.TLV.MAC_IP, Buffer.concat([MAC, Buffer.from(IP)])],
      [proto.TLV.FIRMWARE, 'XW.ar934x.v6.3.11.33396.230425.1742'],
      [proto.TLV.UPTIME, uptime],
      [proto.TLV.HOSTNAME, 'Fake-NanoStation'],
      [proto.TLV.PLATFORM, 'N5N'],
      [proto.TLV.ESSID, 'TestSSID'],
      [proto.TLV.WMODE, Buffer.from([3])],
    ]);
    if (DEMO) sendDemoAiros(rinfo);
    else sock.send(reply, rinfo.port, rinfo.address);
    console.log(`discovery reply -> ${rinfo.address}:${rinfo.port}`);
  } else if (msg.length === 4 && msg[0] === 2 && msg[1] === 8) {
    // A second simulated device: a factory-default UniFi AP answering the v2 query.
    const umac = Buffer.from([0x78, 0x8a, 0x20, 0xbe, 0xef, 0x02]);
    const items = [
      [proto.TLV.MAC, umac],
      [proto.TLV.MAC_IP, Buffer.concat([umac, Buffer.from(IP.slice(0, 3).concat([77]))])],
      [proto.TLV.FIRMWARE, 'U7PG2.qca956x.v6.5.62.14788.230403.1453'],
      [proto.TLV.HOSTNAME, 'UAP-Oficina'],
      [proto.TLV.MODEL, 'U7PG2'],
      [proto.TLV.VERSION, '6.5.62.14788'],
      [proto.TLV.DEFAULT, Buffer.from([1])],
    ];
    const reply = proto.buildPacket(6, items);
    reply[0] = 2;
    if (DEMO) sendDemoUnifi(rinfo);
    else sock.send(reply, rinfo.port, rinfo.address);
    console.log(`unifi v2 reply -> ${rinfo.address}:${rinfo.port}`);
  } else if (msg[0] === 1 && msg[1] === proto.CMD.CHALLENGE) {
    challenge = crypto.randomBytes(16);
    sock.send(proto.buildPacket(proto.CMD.CHALLENGE, [[proto.TLV.MAC, MAC], [proto.TLV.SALT, SALT], [proto.TLV.CHALLENGE, challenge]]), rinfo.port, rinfo.address);
    console.log('reboot challenge sent');
  } else if (msg[0] === 1 && msg[1] === proto.CMD.REBOOT) {
    const tlvs = {};
    for (let p = 4; p + 3 <= msg.length; ) {
      const len = msg.readUInt16BE(p + 1);
      tlvs[msg[p]] = msg.subarray(p + 3, p + 3 + len);
      p += 3 + len;
    }
    const ok = challenge && tlvs[9] && tlvs[9].equals(challengeResponse('ubnt', SALT, challenge));
    console.log(ok ? 'REBOOT accepted (valid credentials)' : 'REBOOT rejected (bad credentials)');
  }
});
sock.bind(proto.PORT, () => {
  sock.setBroadcast(true);
  try {
    sock.addMembership(proto.MULTICAST_ADDR);
  } catch {
    // ignore
  }
  console.log('fake device listening on UDP', proto.PORT);
});
