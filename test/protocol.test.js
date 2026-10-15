'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const proto = require('../src/lib/protocol');
const { crypt, sha512Crypt, md5Crypt, challengeResponse } = require('../src/lib/crypt');

const MAC = Buffer.from([0x24, 0xa4, 0x3c, 0x12, 0x34, 0x56]);

function tlv(type, data) {
  const d = Buffer.isBuffer(data) ? data : Buffer.from(data, 'latin1');
  const h = Buffer.alloc(3);
  h[0] = type;
  h.writeUInt16BE(d.length, 1);
  return Buffer.concat([h, d]);
}

function v1(cmd, ...items) {
  const body = Buffer.concat(items);
  const head = Buffer.from([1, cmd, 0, 0]);
  head.writeUInt16BE(body.length, 2);
  return Buffer.concat([head, body]);
}

test('query packet matches the original', () => {
  assert.deepEqual([...proto.QUERY], [1, 0, 0, 0]);
});

test('parses a full v1 discovery reply', () => {
  const uptime = Buffer.alloc(4);
  uptime.writeUInt32BE(90061); // 1 day 01:01:01
  const pkt = v1(
    0,
    tlv(1, MAC),
    tlv(2, Buffer.concat([MAC, Buffer.from([192, 168, 1, 20])])),
    tlv(2, Buffer.concat([Buffer.from([0x26, 0xa4, 0x3c, 0x12, 0x34, 0x56]), Buffer.from([10, 0, 0, 1])])),
    tlv(3, 'XW.ar934x.v6.1.7.32555.180523.1754'),
    tlv(10, uptime),
    tlv(11, 'Torre-Norte'),
    tlv(12, 'N5N'),
    tlv(13, 'MiRed'),
    tlv(14, Buffer.from([3])),
    tlv(99, 'ignored'),
  );
  const r = proto.parsePacket(pkt, '192.168.1.20');
  assert.equal(r.kind, 'device');
  const d = r.device;
  assert.equal(d.mac, '24-A4-3C-12-34-56');
  assert.equal(d.ip, '192.168.1.20');
  assert.equal(d.product, 'NanoStation M5');
  assert.equal(d.version, 'v6.1.7');
  assert.equal(d.build, '32555');
  assert.equal(d.hostname, 'Torre-Norte');
  assert.equal(d.essid, 'MiRed');
  assert.equal(d.wmodeName, 'ap');
  assert.equal(d.isAp, true);
  assert.equal(d.uptimeText, '1 day 01:01:01');
  assert.equal(d.addresses.length, 2);
  assert.equal(d.rescueIp, 'fe80::26a4:3cff:fe12:3456');
});

test('product falls back to firmware platform code when TLV 12 is missing', () => {
  const pkt = v1(0, tlv(2, Buffer.concat([MAC, Buffer.from([10, 1, 1, 1])])), tlv(3, 'TI.ar7240.v1.3.2.4767.150520.1105'));
  const d = proto.parsePacket(pkt, '10.1.1.1').device;
  assert.equal(d.product, 'TI');
  assert.equal(d.version, 'v1.3.2');
});

test('product table keeps first-prefix-match order', () => {
  assert.equal(proto.productName('TSW-8-POE'), 'TOUGHSwitch 8 PoE');
  assert.equal(proto.productName('TSW-8'), 'TOUGHSwitch 8');
  assert.equal(proto.productName('ZZZ-unknown'), 'ZZZ-unknown');
});

test('short firmware strings become Unknown', () => {
  const fw = proto.parseFirmware('foo.bar');
  assert.equal(fw.version, 'Unknown');
});

test('beta firmware shows build/date/time in full version', () => {
  const fw = proto.parseFirmware('XM.ar7240.v6.0-beta8.28417.161005.1404');
  assert.equal(fw.version, 'v6.0-beta8');
  assert.equal(fw.full, 'v6.0-beta8.28417.161005.1404');
});

test('parses a legacy v0 reply', () => {
  const fw = Buffer.from('XS2.ar2316.v3.6.1.4873.100616.1713', 'latin1');
  const len = Buffer.alloc(4);
  len.writeUInt32BE(fw.length);
  const pkt = Buffer.concat([Buffer.from([0]), MAC, Buffer.from([192, 168, 1, 50]), len, fw]);
  const d = proto.parsePacket(pkt, '192.168.1.50').device;
  assert.equal(d.ip, '192.168.1.50');
  assert.equal(d.product, fw.toString());
});

test('rejects truncated / oversized TLVs', () => {
  const bad = Buffer.from([1, 0, 0, 5, 3, 0, 50, 0x41, 0x42]);
  assert.equal(proto.parsePacket(bad, '1.2.3.4'), null);
  assert.equal(proto.parsePacket(Buffer.from([7, 0, 0, 0]), '1.2.3.4'), null);
});

test('parses a reboot challenge (cmd 2)', () => {
  const pkt = v1(2, tlv(1, MAC), tlv(7, '$1$abcdefgh'), tlv(8, Buffer.from('0123456789abcdef')));
  const r = proto.parsePacket(pkt, '192.168.1.20');
  assert.equal(r.kind, 'challenge');
  assert.equal(r.mac, '24a43c123456');
  assert.equal(r.salt.toString(), '$1$abcdefgh');
});

test('builds request packets like com.OoOO.super.A.if', () => {
  const pkt = proto.buildPacket(2, [[1, MAC], [6, 'ubnt']]);
  assert.deepEqual([...pkt], [1, 2, 0, 16, 1, 0, 6, ...MAC, 6, 0, 4, 0x75, 0x62, 0x6e, 0x74]);
});

test('uptime formatting', () => {
  assert.equal(proto.formatUptime(59), '00:00:59');
  assert.equal(proto.formatUptime(3 * 86400 + 3725), '3 days 01:02:05');
});

// Reference vectors from the SHA-crypt specification (also embedded in the original jar).
test('sha512crypt reference vectors', () => {
  assert.equal(
    sha512Crypt('Hello world!', '$6$saltstring'),
    '$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1',
  );
  assert.equal(
    sha512Crypt('Hello world!', '$6$rounds=10000$saltstringsaltstring'),
    '$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.',
  );
});

test('md5crypt reference vector', () => {
  // Cross-checked against the apache-md5 package.
  assert.equal(md5Crypt('password', '$1$saltsalt'), '$1$saltsalt$qjXMvbEw8oaL.CzflDtaK/');
});

test('DES crypt reference vector', () => {
  assert.equal(crypt('test', 'aa'), 'aaqPiZY5xR5l.');
});

test('challenge response = SHA-256(crypt(password, salt) || challenge)', () => {
  const salt = Buffer.from('$1$saltsalt');
  const challenge = Buffer.from([1, 2, 3, 4]);
  const expected = crypto.createHash('sha256').update('$1$saltsalt$qjXMvbEw8oaL.CzflDtaK/').update(challenge).digest();
  assert.deepEqual(challengeResponse('password', salt, challenge), expected);
});

test('v2 query packet', () => {
  assert.deepEqual([...proto.QUERY_V2], [2, 8, 0, 0]);
});

test('UniFi v2 reply is classified as UniFi with model, version and adoption state', () => {
  const body = Buffer.concat([
    tlv(1, MAC),
    tlv(2, Buffer.concat([MAC, Buffer.from([192, 168, 1, 30])])),
    tlv(3, 'U7PG2.qca956x.v6.5.62.14788.230403.1453'),
    tlv(0x0b, 'AP-Oficina'),
    tlv(0x15, 'U7PG2'),
    tlv(0x16, '6.5.62.14788'),
    tlv(0x17, Buffer.from([1])),
  ]);
  const head = Buffer.from([2, 6, 0, 0]);
  head.writeUInt16BE(body.length, 2);
  const d = proto.parsePacket(Buffer.concat([head, body]), '192.168.1.30').device;
  assert.equal(d.family, 'unifi');
  assert.equal(d.product, 'UAP-AC-Pro');
  assert.equal(d.version, '6.5.62.14788');
  assert.equal(d.isDefault, true);
  assert.equal(d.hostname, 'AP-Oficina');
});

test('airOS v1 reply stays airOS', () => {
  const pkt = v1(0, tlv(2, Buffer.concat([MAC, Buffer.from([10, 1, 1, 1])])), tlv(3, 'XW.ar934x.v6.1.7.32555.180523.1754'), tlv(12, 'N5N'));
  assert.equal(proto.parsePacket(pkt, '10.1.1.1').device.family, 'airos');
});