'use strict';
/* readings.js -- build the 5 base64 readings of rev7's displayed string,
 * score the RAW readings on every endpoint family, and compare their
 * summary statistics against a RESTRICTED-ALPHABET null (random 1092-char
 * strings over 0-9A-F, base64-decoded). Reuses ../encoded/endpoints.js and
 * ../cascade/cascade_lib.js verbatim. */
const fs = require('fs');
const path = require('path');
const ep = require('../encoded/endpoints.js');
const cl = require('../cascade/cascade_lib.js');

const HEXCHARS = '0123456789ABCDEF';
const raw = fs.readFileSync(path.join(__dirname, '..', 'rev7_hex.txt'), 'utf8').trim();

function readingsOf(s) {
  const o = cl.orientations(s);               // displayed/fullReversed/bytePairReversed/nibbleSwap
  o.lowercased = s.toLowerCase();
  const out = {};
  for (const k of Object.keys(o)) out[k] = Buffer.from(o[k], 'base64');
  return out;
}

function stats(buf) {
  const h = ep.histOf(buf, 0);
  let distinct = 0;
  for (let i = 0; i < 256; i++) if (h[i]) distinct++;
  let print = 0;
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i];
    if (b === 9 || b === 10 || b === 13 || (b >= 32 && b <= 126)) print++;
  }
  let ent = 0;
  for (let i = 0; i < 256; i++) if (h[i]) { const p = h[i] / buf.length; ent -= p * Math.log2(p); }
  const fr = ep.fractionsFromHist(h, buf.length);
  const runs = {};
  for (const n of ep.NAMES) runs[n] = ep.longestRun(buf, 0, n);
  let s1_26 = 0, s0_31 = 0;
  for (let i = 0; i < buf.length; i++) { const b = buf[i]; if (b >= 1 && b <= 26) s1_26++; if (b <= 31) s0_31++; }
  const u = cl.scoreTail(buf, 0);
  return {
    len: buf.length, distinct, printable: print / buf.length, entropy: ent,
    frac: fr, longestRun: runs,
    small_1_26: s1_26 / buf.length, small_0_31: s0_31 / buf.length,
    utf8_longestRun: u.longestRun, utf8_validFrac: u.validCount / u.tailLen,
  };
}

const R = readingsOf(raw);
const realStats = {};
for (const k of Object.keys(R)) realStats[k] = stats(R[k]);

// ---------- restricted-alphabet null ----------
const crypto = require('crypto');
function randHexStr(n) {
  const b = crypto.randomBytes(n);
  let s = '';
  for (let i = 0; i < n; i++) s += HEXCHARS[b[i] & 15];
  return s;
}
const N = 2000;
const acc = {};
function push(key, v) { (acc[key] = acc[key] || []).push(v); }
for (let t = 0; t < N; t++) {
  const st = stats(Buffer.from(randHexStr(1092), 'base64'));
  push('distinct', st.distinct); push('printable', st.printable); push('entropy', st.entropy);
  push('utf8_longestRun', st.utf8_longestRun); push('utf8_validFrac', st.utf8_validFrac);
  push('small_1_26', st.small_1_26); push('small_0_31', st.small_0_31);
  for (const n of ep.NAMES) { push('frac.' + n, st.frac[n]); push('run.' + n, st.longestRun[n]); }
}
function summ(a) {
  const s = a.slice().sort((x, y) => x - y);
  const mean = a.reduce((p, c) => p + c, 0) / a.length;
  const sd = Math.sqrt(a.reduce((p, c) => p + (c - mean) ** 2, 0) / a.length);
  return { mean, sd, min: s[0], p50: s[Math.floor(a.length * 0.5)], p99: s[Math.floor(a.length * 0.99)], max: s[a.length - 1] };
}
const nullSumm = {};
for (const k of Object.keys(acc)) nullSumm[k] = summ(acc[k]);

// z-scores for the real readings
const z = {};
for (const rk of Object.keys(realStats)) {
  const st = realStats[rk]; z[rk] = {};
  const flat = { distinct: st.distinct, printable: st.printable, entropy: st.entropy,
    utf8_longestRun: st.utf8_longestRun, utf8_validFrac: st.utf8_validFrac,
    small_1_26: st.small_1_26, small_0_31: st.small_0_31 };
  for (const n of ep.NAMES) { flat['frac.' + n] = st.frac[n]; flat['run.' + n] = st.longestRun[n]; }
  for (const k of Object.keys(flat)) {
    const s = nullSumm[k];
    z[rk][k] = { value: flat[k], nullMean: s.mean, nullSd: s.sd, nullMax: s.max,
      z: s.sd > 0 ? (flat[k] - s.mean) / s.sd : 0, beatsNullMax: flat[k] > s.max };
  }
}

fs.writeFileSync(path.join(__dirname, 'readings.json'),
  JSON.stringify({ nullTrials: N, real: realStats, null: nullSumm, z }, null, 1));

for (const k of Object.keys(realStats)) {
  const s = realStats[k];
  console.log(k.padEnd(18), 'distinct=' + s.distinct, 'print=' + s.printable.toFixed(3),
    'H=' + s.entropy.toFixed(3), 'utf8run=' + s.utf8_longestRun,
    'b64run=' + s.longestRun.base64std, 'printrun=' + s.longestRun.printable);
}
console.log('NULL distinct', JSON.stringify(nullSumm.distinct));
console.log('NULL printable', JSON.stringify(nullSumm.printable));
console.log('NULL entropy', JSON.stringify(nullSumm.entropy));
console.log('NULL utf8_longestRun', JSON.stringify(nullSumm.utf8_longestRun));
console.log('NULL run.printable', JSON.stringify(nullSumm['run.printable']));
