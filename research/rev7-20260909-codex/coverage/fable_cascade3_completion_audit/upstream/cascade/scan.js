'use strict';
/* scan.js -- exhaustive decrypt->decrypt (binary-intermediate) cascade
 * search over the 46-option-per-layer alphabet (23 ciphers x {Zombies,
 * ZOMBIES}), unconstrained by the text-only survival gate that prunes
 * ../chainsearch/search.js. Scores every chain, not just pass/fail.
 */
const C = require('./cascade_lib.js');

const CIPHERS = C.ALL_CIPHERS; // 23
const KEYS = C.KEYS; // ['Zombies', 'ZOMBIES']

function layerOptions() {
  const opts = [];
  for (const c of CIPHERS) for (const k of KEYS) opts.push({ cipher: c, key: k, label: `decrypt:${c}:${k}` });
  return opts; // 46
}
const LAYER_OPTS = layerOptions();

function blockSizeFor(cipher) { return C.CIPHER_INFO[cipher].blockSize || 0; }

function applyLayer(ctx, buf, opt) {
  return C.decryptWith(ctx, opt.cipher, opt.key, buf);
}

/* Full depth-2 exhaustive sweep on one orientation's hex text:
 *   hexDecode -> [b0?] -> layer1 -> [b1?] -> layer2 -> [b2?]
 * b0/b1/b2 = optional codepoint-aware reverse, 2^3 = 8 combinations.
 * Returns array of {path, longestRun, validCount, tailLen}. */
function scanDepth2(ctx, hexStr, opts) {
  opts = opts || {};
  const buf0 = Buffer.from(hexStr, 'ascii');
  let hexDecoded;
  try { hexDecoded = Buffer.from(hexStr, 'hex'); } catch (e) { hexDecoded = null; }
  if (!hexDecoded || hexDecoded.length * 2 !== hexStr.length) {
    // guard against silently-truncated hex decode on odd-length/bad input
    hexDecoded = Buffer.from(hexStr.replace(/[^0-9a-fA-F]/g, ''), 'hex');
  }
  const results = [];
  for (let bmask = 0; bmask < 8; bmask++) {
    const b0 = !!(bmask & 1), b1 = !!(bmask & 2), b2 = !!(bmask & 4);
    const start = b0 ? C.reverseBuf(hexDecoded) : hexDecoded;
    for (const l1 of LAYER_OPTS) {
      let after1;
      try { after1 = applyLayer(ctx, start, l1); } catch (e) { continue; }
      const mid = b1 ? C.reverseBuf(after1) : after1;
      for (const l2 of LAYER_OPTS) {
        let after2;
        try { after2 = applyLayer(ctx, mid, l2); } catch (e) { continue; }
        const final = b2 ? C.reverseBuf(after2) : after2;
        const skip = blockSizeFor(l2.cipher);
        const sc = C.scoreTail(final, skip);
        results.push({
          path: [b0 ? 'reverse' : null, l1.label, b1 ? 'reverse' : null, l2.label, b2 ? 'reverse' : null].filter(Boolean),
          longestRun: sc.longestRun, validCount: sc.validCount, tailLen: sc.tailLen,
          finalHexSample: final.length <= 80 ? final.toString('hex') : final.subarray(0, 40).toString('hex') + '...',
        });
      }
    }
  }
  return results;
}

/* Full depth-3 exhaustive sweep, NO reverse boundaries (fallback scope for
 * budget, per task spec). 46^3 chains per orientation. */
function scanDepth3NoReverse(ctx, hexStr) {
  const hexDecoded = Buffer.from(hexStr, 'hex');
  const results = [];
  for (const l1 of LAYER_OPTS) {
    let after1;
    try { after1 = applyLayer(ctx, hexDecoded, l1); } catch (e) { continue; }
    for (const l2 of LAYER_OPTS) {
      let after2;
      try { after2 = applyLayer(ctx, after1, l2); } catch (e) { continue; }
      for (const l3 of LAYER_OPTS) {
        let after3;
        try { after3 = applyLayer(ctx, after2, l3); } catch (e) { continue; }
        const skip = blockSizeFor(l3.cipher);
        const sc = C.scoreTail(after3, skip);
        results.push({
          path: [l1.label, l2.label, l3.label],
          longestRun: sc.longestRun, validCount: sc.validCount, tailLen: sc.tailLen,
        });
      }
    }
  }
  return results;
}

/* depth-3 WITH reverse boundaries (2^4=16), restricted to a fixed
 * (layer1,layer2) candidate list -- used to extend the leading depth-2
 * ciphers by one more layer with reverses, without paying the full 6.2M
 * combinatorial cost. */
function scanDepth3ReverseExtension(ctx, hexStr, layer1List, layer2List) {
  const hexDecoded = Buffer.from(hexStr, 'hex');
  const results = [];
  for (let bmask = 0; bmask < 16; bmask++) {
    const b0 = !!(bmask & 1), b1 = !!(bmask & 2), b2 = !!(bmask & 4), b3 = !!(bmask & 8);
    const start = b0 ? C.reverseBuf(hexDecoded) : hexDecoded;
    for (const l1 of layer1List) {
      let after1;
      try { after1 = applyLayer(ctx, start, l1); } catch (e) { continue; }
      const mid1 = b1 ? C.reverseBuf(after1) : after1;
      for (const l2 of layer2List) {
        let after2;
        try { after2 = applyLayer(ctx, mid1, l2); } catch (e) { continue; }
        const mid2 = b2 ? C.reverseBuf(after2) : after2;
        for (const l3 of LAYER_OPTS) {
          let after3;
          try { after3 = applyLayer(ctx, mid2, l3); } catch (e) { continue; }
          const final = b3 ? C.reverseBuf(after3) : after3;
          const skip = blockSizeFor(l3.cipher);
          const sc = C.scoreTail(final, skip);
          results.push({
            path: [b0 ? 'reverse' : null, l1.label, b1 ? 'reverse' : null, l2.label, b2 ? 'reverse' : null, l3.label, b3 ? 'reverse' : null].filter(Boolean),
            longestRun: sc.longestRun, validCount: sc.validCount, tailLen: sc.tailLen,
          });
        }
      }
    }
  }
  return results;
}

function sortByScore(results) {
  return results.slice().sort((a, b) => (b.longestRun - a.longestRun) || (b.validCount - a.validCount));
}
function topK(results, k) { return sortByScore(results).slice(0, k); }

function histogram(results) {
  const byLongestRun = {};
  const byValidCount = {};
  for (const r of results) {
    byLongestRun[r.longestRun] = (byLongestRun[r.longestRun] || 0) + 1;
    const bucket = Math.floor(r.validCount / 20) * 20;
    byValidCount[bucket] = (byValidCount[bucket] || 0) + 1;
  }
  return { byLongestRun, byValidCountBucket20: byValidCount, n: results.length };
}

function rankOfPath(results, pathLabels) {
  const sorted = sortByScore(results);
  const key = pathLabels.join(',');
  for (let i = 0; i < sorted.length; i++) {
    if (sorted[i].path.join(',') === key) return { rank: i + 1, total: sorted.length, entry: sorted[i] };
  }
  return { rank: null, total: sorted.length, entry: null };
}

module.exports = {
  LAYER_OPTS, scanDepth2, scanDepth3NoReverse, scanDepth3ReverseExtension,
  sortByScore, topK, histogram, rankOfPath, blockSizeFor,
};
