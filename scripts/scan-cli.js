'use strict';

// Headless scan: node scripts/scan-cli.js  (prints every device found in 10 s)
const { Scanner, localIPv4Addresses } = require('../src/lib/scanner');

const scanner = new Scanner();
const found = new Map();

console.log('Interfaces:', localIPv4Addresses().map((i) => `${i.name} ${i.address}`).join(', ') || '(none)');
scanner.on('log', (m) => console.log('[log]', m));
scanner.on('device', (d) => {
  if (!found.has(d.id)) console.log(`+ ${d.product.padEnd(24)} ${String(d.ip).padEnd(15)} ${d.mac}  ${d.hostname}  ${d.version}`);
  found.set(d.id, d);
});
scanner.on('progress', ({ scanning }) => {
  if (!scanning) {
    console.log(`Scan finished: ${found.size} device(s).`);
    scanner.close();
  }
});
scanner.scan();
