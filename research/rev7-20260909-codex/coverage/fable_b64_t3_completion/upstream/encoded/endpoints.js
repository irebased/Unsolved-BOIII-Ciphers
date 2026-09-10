'use strict';
/* endpoints.js -- ENCODED-INTERMEDIATE alphabets + EN/DE language scoring.
 * Reuses ../dictkey2/lib.js and ../cascade/cascade_lib.js for all crypto
 * plumbing; nothing here re-implements mcrypt. */
const fs = require('fs');
const path = require('path');

function set(str) { const s = new Set(); for (const c of str) s.add(c.charCodeAt(0)); return s; }
const WS = ' \t\r\n';
const UP = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LO = 'abcdefghijklmnopqrstuvwxyz';
const D = '0123456789';
let PRINT = ''; for (let i = 32; i <= 126; i++) PRINT += String.fromCharCode(i);

const ALPHABETS = {
  base64std:  UP + LO + D + '+/=',
  base64url:  UP + LO + D + '-_=',
  hexupper:   D + 'ABCDEF',
  hexlower:   D + 'abcdef',
  hexmixed:   D + 'ABCDEFabcdef',
  decimal:    D,
  decimalsep: D + WS,
  octal:      '01234567',
  octalsep:   '01234567' + WS,
  binary:     '01',
  binarysep:  '01' + WS,
  base32:     UP + '234567=',
  upperspace: UP + ' ',
  printable:  PRINT + '\t\n\r',
};
const NAMES = Object.keys(ALPHABETS);
// membership table: MEMBERS[name] = Uint8Array of byte values in alphabet
const MEMBERS = {};
const THEORY = {};
for (const n of NAMES) {
  const s = set(ALPHABETS[n]);
  MEMBERS[n] = Uint8Array.from([...s].sort((a, b) => a - b));
  THEORY[n] = s.size / 256;
}

/* fractions of every endpoint from one histogram pass */
function histOf(buf, start) {
  const h = new Uint32Array(256);
  for (let i = start; i < buf.length; i++) h[buf[i]]++;
  return h;
}
function fractionsFromHist(h, n) {
  const out = {};
  for (const name of NAMES) {
    const m = MEMBERS[name];
    let c = 0;
    for (let i = 0; i < m.length; i++) c += h[m[i]];
    out[name] = c / n;
  }
  return out;
}
function longestRun(buf, start, name) {
  const s = set(ALPHABETS[name]);
  const tbl = new Uint8Array(256);
  for (const v of s) tbl[v] = 1;
  let best = 0, cur = 0;
  for (let i = start; i < buf.length; i++) {
    if (tbl[buf[i]]) { cur++; if (cur > best) best = cur; } else cur = 0;
  }
  return best;
}

/* ---------------- language scoring (EN + DE letter quadgrams) ------------- */
function loadQuad(fp) {
  const txt = fs.readFileSync(fp, 'utf8');
  const map = new Map();
  let total = 0;
  for (const line of txt.split('\n')) {
    if (!line) continue;
    const sp = line.indexOf(' ');
    if (sp < 0) continue;
    const g = line.slice(0, sp), c = +line.slice(sp + 1);
    if (!c) continue;
    map.set(g, c); total += c;
  }
  const logs = new Map();
  for (const [g, c] of map) logs.set(g, Math.log10(c / total));
  return { logs, floor: Math.log10(0.01 / total) };
}
function normalizeEN(s) { return s.toUpperCase().replace(/[^A-Z]/g, ''); }
function normalizeDE(s) {
  return s.toUpperCase()
    .replace(/Ä/g, 'AE').replace(/Ö/g, 'OE').replace(/Ü/g, 'UE')
    .replace(/ß/g, 'SS').replace(/ẞ/g, 'SS')
    .replace(/[^A-Z]/g, '');
}
function quadScore(model, letters) {
  if (letters.length < 4) return -99;
  let s = 0;
  for (let i = 0; i + 4 <= letters.length; i++) {
    const v = model.logs.get(letters.slice(i, i + 4));
    s += (v === undefined ? model.floor : v);
  }
  return s / (letters.length - 3); // per-quadgram, comparable across models
}
module.exports = { ALPHABETS, NAMES, MEMBERS, THEORY, histOf, fractionsFromHist, longestRun, loadQuad, normalizeEN, normalizeDE, quadScore };
