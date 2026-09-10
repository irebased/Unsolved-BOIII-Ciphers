'use strict';
/* verify.js -- emits vectors for independent (pycryptodome) comparison and
 * runs the two divergence checks (vs ofb8, vs wrapper mode 4). */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const L = require('./lib.js');

const N_PER_CIPHER = 60;
const CROSS = [
  { cipher: 'des', keyLen: 8, bs: 8 },
  { cipher: 'rijndael-128', keyLen: 16, bs: 16 },
  { cipher: 'blowfish', keyLen: 16, bs: 8 },
];

(async () => {
  const ctx = await L.loadMcrypt();
  const vectors = [];
  for (const c of CROSS) {
    for (let i = 0; i < N_PER_CIPHER; i++) {
      const key = crypto.randomBytes(c.keyLen);
      const iv = crypto.randomBytes(c.bs);
      const dlen = 1 + Math.floor(Math.random() * 200);
      const data = crypto.randomBytes(dlen);
      const out = L.nofbProcess(ctx, c.cipher, new Uint8Array(key), new Uint8Array(iv), new Uint8Array(data));
      vectors.push({
        cipher: c.cipher,
        key: key.toString('hex'), iv: iv.toString('hex'),
        data: data.toString('hex'), out: Buffer.from(out).toString('hex'),
      });
    }
  }
  fs.writeFileSync(path.join(__dirname, 'vectors.json'), JSON.stringify(vectors));

  // --- divergence checks ---
  const div = { vs_ofb8: [], vs_mode4: [] };
  let ofb8Same = 0, mode4SameAsNofb = 0, mode4SameAsOfb8 = 0, trials = 0;
  for (const c of CROSS) {
    for (let i = 0; i < 20; i++) {
      trials++;
      const key = crypto.randomBytes(c.keyLen);
      const iv = crypto.randomBytes(c.bs);
      const data = crypto.randomBytes(128);
      const kb = new Uint8Array(key), ib = new Uint8Array(iv), db = new Uint8Array(data);
      const a = Buffer.from(L.nofbProcess(ctx, c.cipher, kb, ib, db));
      const b = Buffer.from(L.ofb8Process(ctx, c.cipher, kb, ib, db));
      const m4 = Buffer.from(L.blockWideOFB(ctx, c.cipher, kb, ib, db));
      let firstDiff = -1;
      for (let j = 0; j < a.length; j++) if (a[j] !== b[j]) { firstDiff = j; break; }
      if (firstDiff === -1) ofb8Same++;
      if (i === 0) div.vs_ofb8.push({ cipher: c.cipher, firstDiffIndex: firstDiff });
      if (m4.equals(a)) mode4SameAsNofb++;
      if (m4.equals(b)) mode4SameAsOfb8++;
      if (i === 0) {
        let fdN = -1, fdO = -1;
        for (let j = 0; j < a.length; j++) if (m4[j] !== a[j]) { fdN = j; break; }
        for (let j = 0; j < b.length; j++) if (m4[j] !== b[j]) { fdO = j; break; }
        div.vs_mode4.push({ cipher: c.cipher, firstDiffVsNofb: fdN, firstDiffVsOfb8: fdO });
      }
    }
  }
  div.summary = { trials, ofb8_identical_count: ofb8Same, mode4_equals_nofb: mode4SameAsNofb, mode4_equals_ofb8: mode4SameAsOfb8 };
  fs.writeFileSync(path.join(__dirname, 'divergence.json'), JSON.stringify(div, null, 2));
  console.log(JSON.stringify(div, null, 2));
})();
