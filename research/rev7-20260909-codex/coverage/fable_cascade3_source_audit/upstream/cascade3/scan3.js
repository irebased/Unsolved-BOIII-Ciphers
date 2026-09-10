'use strict';
/* scan3.js -- exhaustive depth-3 decrypt->decrypt->decrypt cascade WITH
 * optional codepoint-aware reverse at all 4 boundaries (2^4=16), over the
 * full 46-option-per-layer alphabet and all 4 orientations:
 *   4 x 46^3 x 16 = 6,229,504 chains
 *
 * Reuses ../cascade/cascade_lib.js verbatim (decryptWith, reverseBuf,
 * scoreTail, CIPHER_INFO, ALL_CIPHERS) and ../cascade/scan.js's LAYER_OPTS
 * shape/blockSizeFor -- not rewritten, only referenced/mirrored where scan.js
 * does not already export a usable memoized entry point (scan.js's own
 * scanDepth3ReverseExtension is restricted-candidate, not exhaustive; this
 * file adds the exhaustive path scan.js does not provide).
 *
 * Optimisation: layer-1 output depends only on (orientation, cipher1, key1,
 * b0) -> 4*46*2 = 368 distinct buffers, computed once. layer-2 output
 * (after optional b1 reverse) depends on that + (cipher2,key2) -> memoised
 * once per (orientation,cipher1,key1,b0,b1,cipher2,key2) = 33,856 buffers.
 * Each is then extended by all 46 layer3 options x 2 (b2) x 2 (b3) = 184
 * leaves, giving exactly 33,856 x 184 = 6,229,504 total scored chains.
 */
const C = require('../cascade/cascade_lib.js');
const S = require('../cascade/scan.js');

const LAYER_OPTS = S.LAYER_OPTS; // 46, reused verbatim
const blockSizeFor = S.blockSizeFor;

function applyLayer(ctx, buf, opt) {
  return C.decryptWith(ctx, opt.cipher, opt.key, buf);
}

/* Runs the full exhaustive sweep for one orientation's hex string.
 * onLeaf(scoreObj, pathArr) is called for every one of the 46^3*16 chains;
 * caller is responsible for keeping only what it needs (top-K, planted-
 * chain rank, histogram) to avoid holding 1.5M-per-orientation objects. */
function scanDepth3FullExhaustive(ctx, hexStr, onLeaf) {
  const hexDecoded = Buffer.from(hexStr, 'hex');
  let count = 0;

  for (let b0i = 0; b0i < 2; b0i++) {
    const b0 = !!b0i;
    const start = b0 ? C.reverseBuf(hexDecoded) : hexDecoded;
    for (const l1 of LAYER_OPTS) {
      let after1;
      try { after1 = applyLayer(ctx, start, l1); } catch (e) { continue; }
      for (let b1i = 0; b1i < 2; b1i++) {
        const b1 = !!b1i;
        const mid1 = b1 ? C.reverseBuf(after1) : after1;
        for (const l2 of LAYER_OPTS) {
          let after2;
          try { after2 = applyLayer(ctx, mid1, l2); } catch (e) { continue; }
          for (let b2i = 0; b2i < 2; b2i++) {
            const b2 = !!b2i;
            const mid2 = b2 ? C.reverseBuf(after2) : after2;
            for (const l3 of LAYER_OPTS) {
              let after3;
              try { after3 = applyLayer(ctx, mid2, l3); } catch (e) { continue; }
              const skip = blockSizeFor(l3.cipher);
              for (let b3i = 0; b3i < 2; b3i++) {
                const b3 = !!b3i;
                const final = b3 ? C.reverseBuf(after3) : after3;
                const sc = C.scoreTail(final, skip);
                count++;
                onLeaf(sc, b0, l1, b1, l2, b2, l3, b3);
              }
            }
          }
        }
      }
    }
  }
  return count;
}

function pathFromFlags(b0, l1, b1, l2, b2, l3, b3) {
  return [b0 ? 'reverse' : null, l1.label, b1 ? 'reverse' : null, l2.label, b2 ? 'reverse' : null, l3.label, b3 ? 'reverse' : null].filter(Boolean);
}

module.exports = { LAYER_OPTS, blockSizeFor, scanDepth3FullExhaustive, pathFromFlags };
