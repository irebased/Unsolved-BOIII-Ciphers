'use strict';
/* assemble.js -- merge tier outputs into results.json */
const fs = require('fs');
const path = require('path');
const readings = require('./readings.json');
const plantNote = require('./plant_note.json');

const tiers = [];
for (const t of ['t0', 't1', 't2', 't3']) {
  const fp = path.join(__dirname, 'out_' + t + '.json');
  if (fs.existsSync(fp)) tiers.push({ tier: t, data: JSON.parse(fs.readFileSync(fp, 'utf8')) });
}

// merge per (label/reading) across tiers: keep global max per endpoint
const merged = {};
let totalTrials = 0;
for (const { tier, data } of tiers) {
  for (const r of data.results) {
    if (r.error) continue;
    totalTrials += r.trials;
    const k = r.label + '/' + r.reading;
    if (!merged[k]) merged[k] = { label: r.label, reading: r.reading, trials: 0, best: {}, topUtf8: [] };
    merged[k].trials += r.trials;
    for (const e of Object.keys(r.best)) {
      const cur = merged[k].best[e];
      if (!cur || r.best[e].value > cur.value) merged[k].best[e] = { ...r.best[e], tier };
    }
    merged[k].topUtf8 = merged[k].topUtf8.concat(r.topUtf8.map((x) => ({ ...x, tier })))
      .sort((a, b) => b.v - a.v).slice(0, 10);
  }
}

const KEY_ENDPOINTS = ['utf8_longestRun', 'utf8_validFrac', 'printableFrac', 'run.printable',
  'small_1_26', 'small_0_31', 'frac.base64std', 'run.base64std', 'frac.decimal', 'run.decimal',
  'frac.octal', 'run.octal', 'frac.hexupper', 'run.hexupper', 'frac.upperspace', 'run.upperspace',
  'frac.base32', 'run.base32'];

const neg = merged['NEG/random_hexalpha'];
const summary = {};
for (const k of Object.keys(merged)) {
  const s = {};
  for (const e of KEY_ENDPOINTS) {
    const b = merged[k].best[e];
    if (!b) continue;
    s[e] = { value: b.value, params: b.params, tier: b.tier,
      negMax: neg && neg.best[e] ? neg.best[e].value : null,
      beatsNegative: neg && neg.best[e] ? b.value > neg.best[e].value : null };
  }
  summary[k] = { trials: merged[k].trials, endpoints: s, topUtf8: merged[k].topUtf8 };
}

const out = {
  question: 'Does rev7 displayed string read as BASE64 (819 bytes) rather than hex (546 bytes)?',
  verdict: 'NO DECODE. No reading, cipher, mode or key produced plaintext or an encoded intermediate on any endpoint family; every real reading is at or below the restricted-alphabet negative control.',
  string: { length: 1092, alphabet: '0123456789ABCDEF', b64DecodedBytes: 819, b64RoundTripClean: true },
  structuralObjection: {
    note: 'A real base64 encoding of 819 cipher-grade bytes would use the full 64-char alphabet. Observing all 1092 chars inside the 16-char hex subset has probability (1/4)^1092 under any cipher.',
    plantB64CharsInHexAlphabet: plantNote.charsInHexAlphabet + '/1092 (' + (plantNote.fracInHexAlphabet * 100).toFixed(1) + '%)',
    probability: plantNote.probAllInHexAlphabet,
  },
  readingsVsRestrictedNull: readings,
  sweep: {
    ciphers: 23, modes: ['cfb8', 'ncfb', 'ofb', 'ctr', '(stream ciphers: no mode)'],
    iv: "ASCII '0' bytes", loki97: 'explicit 32-byte NUL-padded key buffer (../loki97fix/)',
    skipBytes: 'blockSize (CFB8 IV-dependent prefix); 0 for stream ciphers',
    tiers: tiers.map((t) => ({ tier: t.tier, nKeys: t.data.meta.nKeys, seconds: t.data.meta.seconds })),
    totalTrials,
  },
  results: summary,
};
fs.writeFileSync(path.join(__dirname, 'results.json'), JSON.stringify(out, null, 1));

console.log('total trials', totalTrials);
for (const k of Object.keys(summary)) {
  const e = summary[k].endpoints;
  console.log(k.padEnd(34), 'n=' + summary[k].trials,
    'utf8run=' + e.utf8_longestRun.value,
    'printfrac=' + e.printableFrac.value.toFixed(3),
    'printrun=' + e['run.printable'].value,
    'b64frac=' + e['frac.base64std'].value.toFixed(3),
    'decfrac=' + e['frac.decimal'].value.toFixed(3),
    'upsp=' + e['frac.upperspace'].value.toFixed(3),
    's1_26=' + e.small_1_26.value.toFixed(3));
}
console.log('\nBest utf8 hits per REAL reading:');
for (const k of Object.keys(summary)) {
  if (!k.startsWith('REAL')) continue;
  const t = summary[k].topUtf8[0];
  console.log(' ', k, JSON.stringify(t));
}
