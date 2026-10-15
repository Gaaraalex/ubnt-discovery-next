'use strict';

// crypt(3) variants used by the device reboot challenge:
//   "$6$..." -> SHA-512 crypt, "$1$..." -> MD5 crypt, anything else -> traditional DES crypt.
// The original tool bundled its own implementations (com.OoOO.super.if / o0oO / P).

const crypto = require('crypto');
const unixCryptDes = require('unix-crypt-td-js');

const ITOA64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

function to64(value, length) {
  let out = '';
  for (let i = 0; i < length; i++) {
    out += ITOA64[value & 0x3f];
    value >>>= 6;
  }
  return out;
}

function md5Crypt(password, setting, magic = '$1$') {
  let salt = setting.startsWith(magic) ? setting.slice(magic.length) : setting;
  const end = salt.indexOf('$');
  if (end >= 0) salt = salt.slice(0, end);
  salt = salt.slice(0, 8);

  const pw = Buffer.from(password, 'utf8');
  const sl = Buffer.from(salt, 'utf8');
  const md5 = () => crypto.createHash('md5');

  const alt = md5().update(pw).update(sl).update(pw).digest();
  const ctx = md5().update(pw).update(magic).update(sl);
  for (let pl = pw.length; pl > 0; pl -= 16) ctx.update(alt.subarray(0, Math.min(16, pl)));
  for (let i = pw.length; i; i >>= 1) ctx.update(i & 1 ? Buffer.from([0]) : pw.subarray(0, 1));
  let final = ctx.digest();

  for (let i = 0; i < 1000; i++) {
    const c = md5();
    c.update(i & 1 ? pw : final);
    if (i % 3) c.update(sl);
    if (i % 7) c.update(pw);
    c.update(i & 1 ? final : pw);
    final = c.digest();
  }

  const f = final;
  const enc =
    to64((f[0] << 16) | (f[6] << 8) | f[12], 4) +
    to64((f[1] << 16) | (f[7] << 8) | f[13], 4) +
    to64((f[2] << 16) | (f[8] << 8) | f[14], 4) +
    to64((f[3] << 16) | (f[9] << 8) | f[15], 4) +
    to64((f[4] << 16) | (f[10] << 8) | f[5], 4) +
    to64(f[11], 2);
  return `${magic}${salt}$${enc}`;
}

function sha512Crypt(password, setting) {
  const ROUNDS_DEFAULT = 5000;
  let rest = setting.startsWith('$6$') ? setting.slice(3) : setting;
  let rounds = ROUNDS_DEFAULT;
  let roundsCustom = false;
  if (rest.startsWith('rounds=')) {
    const end = rest.indexOf('$');
    const n = parseInt(rest.slice(7, end), 10);
    if (!Number.isNaN(n)) {
      rounds = Math.max(1000, Math.min(999999999, n));
      roundsCustom = true;
    }
    rest = rest.slice(end + 1);
  }
  const end = rest.indexOf('$');
  const salt = (end >= 0 ? rest.slice(0, end) : rest).slice(0, 16);

  const P = Buffer.from(password, 'utf8');
  const S = Buffer.from(salt, 'utf8');
  const sha = () => crypto.createHash('sha512');

  const B = sha().update(P).update(S).update(P).digest();
  const a = sha().update(P).update(S);
  let pl = P.length;
  for (; pl > 64; pl -= 64) a.update(B);
  a.update(B.subarray(0, pl));
  for (let i = P.length; i > 0; i >>= 1) a.update(i & 1 ? B : P);
  let A = a.digest();

  const dp = sha();
  for (let i = 0; i < P.length; i++) dp.update(P);
  const DP = dp.digest();
  const Pseq = Buffer.alloc(P.length);
  for (let i = 0; i < P.length; i++) Pseq[i] = DP[i % 64];

  const ds = sha();
  for (let i = 0; i < 16 + A[0]; i++) ds.update(S);
  const DS = ds.digest();
  const Sseq = Buffer.alloc(S.length);
  for (let i = 0; i < S.length; i++) Sseq[i] = DS[i % 64];

  let C = A;
  for (let r = 0; r < rounds; r++) {
    const c = sha();
    c.update(r & 1 ? Pseq : C);
    if (r % 3) c.update(Sseq);
    if (r % 7) c.update(Pseq);
    c.update(r & 1 ? C : Pseq);
    C = c.digest();
  }

  const order = [
    [0, 21, 42], [22, 43, 1], [44, 2, 23], [3, 24, 45], [25, 46, 4], [47, 5, 26], [6, 27, 48],
    [28, 49, 7], [50, 8, 29], [9, 30, 51], [31, 52, 10], [53, 11, 32], [12, 33, 54], [34, 55, 13],
    [56, 14, 35], [15, 36, 57], [37, 58, 16], [59, 17, 38], [18, 39, 60], [40, 61, 19], [62, 20, 41],
  ];
  let enc = '';
  for (const [x, y, z] of order) enc += to64((C[x] << 16) | (C[y] << 8) | C[z], 4);
  enc += to64(C[63], 2);

  return `$6$${roundsCustom ? `rounds=${rounds}$` : ''}${salt}$${enc}`;
}

function desCrypt(password, salt) {
  return unixCryptDes(password, salt.slice(0, 2));
}

function crypt(password, salt) {
  if (salt.startsWith('$6')) return sha512Crypt(password, salt);
  if (salt.startsWith('$1')) return md5Crypt(password, salt);
  return desCrypt(password, salt);
}

// TLV 9 of the reboot command: SHA-256( crypt(password, salt) || challenge ).
function challengeResponse(password, saltBytes, challengeBytes) {
  const crypted = Buffer.from(crypt(password, Buffer.from(saltBytes).toString('latin1')), 'latin1');
  return crypto.createHash('sha256').update(crypted).update(challengeBytes).digest();
}

module.exports = { crypt, md5Crypt, sha512Crypt, desCrypt, challengeResponse };
