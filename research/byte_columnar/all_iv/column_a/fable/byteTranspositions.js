'use strict';
/*
 * Byte-granularity wrapper around transpositions.js's index-mapping
 * builders. transpositions.js already works purely in terms of an
 * abstract unit count n and produces a dstOfSrc index array; only its
 * applyInverse() assumes 1-char string units. Here we do the same gather
 * over a raw byte Buffer instead (n = 546 bytes for Rev 7).
 */
const T = require('./transpositions');

// candidate[i] = ciphertext[dstOfSrc[i]]  (byte-for-byte gather)
function applyInverseBytes(ciphertextBuf, dstOfSrc) {
  const n = dstOfSrc.length;
  const out = Buffer.allocUnsafe(n);
  for (let i = 0; i < n; i++) out[i] = ciphertextBuf[dstOfSrc[i]];
  return out;
}

module.exports = { ...T, applyInverseBytes };
