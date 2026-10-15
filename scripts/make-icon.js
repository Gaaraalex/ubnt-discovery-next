'use strict';

// Draws the app icon (rounded blue square with a discovery "radar") as PNG.
//   node scripts/make-icon.js   -> src/renderer/icon-256x256.png, icon-64x64.png
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});

function crc32(buf) {
  let c = 0xffffffff;
  for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}

function encodePng(size, rgba) {
  const raw = Buffer.alloc(size * (size * 4 + 1));
  for (let y = 0; y < size; y++) {
    raw[y * (size * 4 + 1)] = 0;
    rgba.copy(raw, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

// Shape test in unit coordinates (0..1). Returns [r, g, b, a] or null.
function shade(x, y) {
  const r = 0.2;
  const cx = Math.min(Math.max(x, r), 1 - r);
  const cy = Math.min(Math.max(y, r), 1 - r);
  if ((x - cx) ** 2 + (y - cy) ** 2 > r * r) return null;

  // Radar centred near the bottom-left corner.
  const ox = 0.27;
  const oy = 0.73;
  const d = Math.hypot(x - ox, y - oy);
  const angle = Math.atan2(oy - y, x - ox);
  const inSweep = angle >= -0.05 && angle <= Math.PI / 2 + 0.05;
  const white = [255, 255, 255, 255];
  if (d <= 0.075) return white;
  if (inSweep) {
    for (const ring of [0.22, 0.36, 0.5]) {
      if (Math.abs(d - ring) <= 0.035) return white;
    }
  }
  // Vertical gradient from bright to deep blue.
  const t = y;
  return [Math.round(30 + 10 * (1 - t)), Math.round(140 - 70 * t), Math.round(240 - 60 * t), 255];
}

function render(size) {
  const ss = 4;
  const out = Buffer.alloc(size * size * 4);
  for (let py = 0; py < size; py++) {
    for (let px = 0; px < size; px++) {
      let rs = 0;
      let gs = 0;
      let bs = 0;
      let as = 0;
      for (let sy = 0; sy < ss; sy++) {
        for (let sx = 0; sx < ss; sx++) {
          const c = shade((px + (sx + 0.5) / ss) / size, (py + (sy + 0.5) / ss) / size);
          if (!c) continue;
          rs += c[0] * c[3];
          gs += c[1] * c[3];
          bs += c[2] * c[3];
          as += c[3];
        }
      }
      const o = (py * size + px) * 4;
      if (as > 0) {
        out[o] = Math.round(rs / as);
        out[o + 1] = Math.round(gs / as);
        out[o + 2] = Math.round(bs / as);
      }
      out[o + 3] = Math.round(as / (ss * ss));
    }
  }
  return encodePng(size, out);
}

const dir = path.join(__dirname, '..', 'src', 'renderer');
for (const size of [256, 64]) {
  fs.writeFileSync(path.join(dir, `icon-${size}x${size}.png`), render(size));
}
console.log('Icons written to', dir);
