'use strict';

// Simulated Ubiquiti device for testing: answers discovery on UDP 10001 and
// implements the reboot challenge (user "ubnt", password "ubnt").
//   node scripts/fake-device.js [ip-to-report]
const dgram = require('dgram');
const crypto = require('crypto');
const proto = require('../src/lib/protocol');
const { challengeResponse } = require('../src/lib/crypt');

const MAC = Buffer.from([0x24, 0xa4, 0x3c, 0xde, 0xad, 0x01]);
const IP = (process.argv[2] || '10.0.0.5').split('.').map(Number);
const SALT = Buffer.from('$1$fakesalt');
let challenge = null;

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
    sock.send(reply, rinfo.port, rinfo.address);
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
    sock.send(reply, rinfo.port, rinfo.address);
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
