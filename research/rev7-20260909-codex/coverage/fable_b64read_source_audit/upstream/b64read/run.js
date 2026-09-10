'use strict';
/* run.js -- dispatcher. usage: node run.js <targetsJson> <keyTier> <outJson> */
const fs = require('fs');
const path = require('path');
const { Worker } = require('worker_threads');
const lib = require('../dictkey2/lib.js');
const cl = require('../cascade/cascade_lib.js');

const targetsFile = process.argv[2];
const tier = process.argv[3];
const outFile = process.argv[4];

const TIERS = {
  t0: () => ['Zombies', 'ZOMBIES', 'zombies'],
  t1: () => lib.readKeyFile(path.join(__dirname, '..', 'authorkeys', 'keys.txt')),
  t2: () => lib.readKeyFile(path.join(__dirname, '..', 'sibvocab', 'keys.txt')),
  t3: () => {
    const d = path.join(__dirname, '..', 'dictkey');
    let a = [];
    for (const f of ['keys_dict.txt', 'keys_lore.txt', 'keys_artifacts.txt']) {
      const fp = path.join(d, f);
      if (fs.existsSync(fp)) a = a.concat(lib.readKeyFile(fp));
    }
    return [...new Set(a)];
  },
};
const keys = TIERS[tier]();
const targets = JSON.parse(fs.readFileSync(targetsFile, 'utf8')); // [{label, reading, b64string}]

(async () => {
  const results = [];
  const t0 = Date.now();
  await Promise.all(targets.map((t) => new Promise((res, rej) => {
    const data = Buffer.from(t.b64string, 'base64');
    const w = new Worker(path.join(__dirname, 'worker.js'), {
      workerData: { dataB64: data.toString('base64'), keys, reading: t.reading, label: t.label },
    });
    w.on('message', (m) => { results.push(m); res(); });
    w.on('error', (e) => { results.push({ error: String(e), reading: t.reading, label: t.label }); res(); });
  })));
  const meta = { tier, nKeys: keys.length, targets: targets.map((t) => t.label + ':' + t.reading), seconds: (Date.now() - t0) / 1000 };
  fs.writeFileSync(outFile, JSON.stringify({ meta, results }, null, 1));
  console.log(JSON.stringify(meta));
  for (const r of results) {
    if (r.error) { console.log('ERR', r.reading, r.error.slice(0, 200)); continue; }
    console.log(r.label + '/' + r.reading, 'trials=' + r.trials, 'err=' + r.errors,
      'utf8run=' + r.best.utf8_longestRun.value,
      'print=' + r.best.printableFrac.value.toFixed(3),
      'printrun=' + r.best['run.printable'].value,
      'b64frac=' + r.best['frac.base64std'].value.toFixed(3),
      'decfrac=' + r.best['frac.decimal'].value.toFixed(3),
      's1_26=' + r.best.small_1_26.value.toFixed(3));
  }
})();
