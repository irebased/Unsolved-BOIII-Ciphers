'use strict';
/* worker.js -- one reading, all ciphers x modes x keys. Scores every trial
 * on the three endpoint families. Reuses ../dictkey2/lib.js,
 * ../cascade/cascade_lib.js, ../encoded/endpoints.js verbatim. */
const { parentPort, workerData } = require('worker_threads');
const lib = require('../dictkey2/lib.js');
const cl = require('../cascade/cascade_lib.js');
const ep = require('../encoded/endpoints.js');

const MODES = [
  { name: 'cfb8', int: lib.MODE_CFB8 },
  { name: 'ncfb', int: lib.MODE_NCFB },
  { name: 'ofb', int: lib.MODE_OFB },
  { name: 'ctr', int: lib.MODE_CTR },
];

// per-endpoint running maxima
function newBest() { return { value: -Infinity, params: null }; }
const ENDPOINTS = ['utf8_longestRun', 'utf8_validFrac', 'printableFrac', 'small_1_26', 'small_0_31']
  .concat(ep.NAMES.map((n) => 'frac.' + n))
  .concat(ep.NAMES.map((n) => 'run.' + n));

function makeMembers() {
  const tbl = {};
  for (const n of ep.NAMES) {
    const t = new Uint8Array(256);
    for (const v of ep.MEMBERS[n]) t[v] = 1;
    tbl[n] = t;
  }
  return tbl;
}
const MEMTBL = makeMembers();

function scoreBuf(buf, skip) {
  const n = buf.length - skip;
  const h = new Uint32Array(256);
  let print = 0, s126 = 0, s031 = 0;
  for (let i = skip; i < buf.length; i++) {
    const b = buf[i];
    h[b]++;
    if (b === 9 || b === 10 || b === 13 || (b >= 32 && b <= 126)) print++;
    if (b >= 1 && b <= 26) s126++;
    if (b <= 31) s031++;
  }
  const out = { printableFrac: print / n, small_1_26: s126 / n, small_0_31: s031 / n };
  for (const name of ep.NAMES) {
    const m = ep.MEMBERS[name];
    let c = 0;
    for (let i = 0; i < m.length; i++) c += h[m[i]];
    out['frac.' + name] = c / n;
  }
  // longest runs (only for alphabets whose fraction is high enough to matter,
  // but cheap enough to always do for the small set that matters most)
  for (const name of ep.NAMES) {
    const t = MEMTBL[name];
    let best = 0, cur = 0;
    for (let i = skip; i < buf.length; i++) { if (t[buf[i]]) { cur++; if (cur > best) best = cur; } else cur = 0; }
    out['run.' + name] = best;
  }
  const u = cl.scoreTail(buf, skip);
  out.utf8_longestRun = u.longestRun;
  out.utf8_validFrac = u.validCount / u.tailLen;
  return out;
}

(async () => {
  const ctx = await lib.loadMcrypt();
  const data = Buffer.from(workerData.dataB64, 'base64');
  const keys = workerData.keys;
  const readingName = workerData.reading;
  const label = workerData.label;
  const best = {}; for (const e of ENDPOINTS) best[e] = newBest();
  const topUtf8 = []; // keep top 25 by utf8_longestRun
  let trials = 0, errors = 0;

  function consider(sc, params) {
    for (const e of ENDPOINTS) {
      const v = sc[e];
      if (v > best[e].value) { best[e] = { value: v, params }; }
    }
    if (topUtf8.length < 25 || sc.utf8_longestRun > topUtf8[topUtf8.length - 1].v) {
      topUtf8.push({ v: sc.utf8_longestRun, params, printableFrac: sc.printableFrac });
      topUtf8.sort((a, b) => b.v - a.v);
      if (topUtf8.length > 25) topUtf8.length = 25;
    }
  }

  for (const cipher of lib.ALL_CIPHERS) {
    const info = lib.CIPHER_INFO[cipher];
    const modes = info.stream ? [{ name: 'stream', int: null }] : MODES;
    for (const mode of modes) {
      for (const key of keys) {
        const kb = cl.keyBytesForCipher(cipher, key);
        const iv = cl.ivFor(info.blockSize || 8);
        let out;
        try {
          out = lib.decryptOnce(ctx, cipher, kb, iv, data, mode.int === null ? undefined : mode.int);
        } catch (e) { errors++; continue; }
        if (!out || out.length < 32) { errors++; continue; }
        const buf = Buffer.from(out);
        const skip = info.stream ? 0 : Math.min(info.blockSize, buf.length - 1);
        const sc = scoreBuf(buf, skip);
        trials++;
        consider(sc, { reading: readingName, cipher, mode: mode.name, key });
      }
    }
  }
  parentPort.postMessage({ reading: readingName, label, trials, errors, best, topUtf8 });
})().catch((e) => { parentPort.postMessage({ error: String(e && e.stack || e) }); });
