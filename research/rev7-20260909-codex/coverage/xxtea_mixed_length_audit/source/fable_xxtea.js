'use strict';
/* xxtea.js -- pure-JS ports of the two XXTEA variants exposed by
 * ../../old-ciphers/js/app.js ('xxtea' == wrapper/xxtea.c pecl-framed,
 * 'xxtea-raw' == jsXxtea plain btea). Reimplemented here (not editing
 * app.js) so we can run both from Node without the WASM module, since the
 * core is pure 32-bit integer arithmetic and both source files were
 * consulted to get the exact semantics:
 *   - wasm/xxtea.c: xxtea_to_uint_array(data,len,inc_len,...) -- inc_len=1
 *     appends a length word BEFORE encrypt / expects one after decrypt to
 *     trim output, per the xxtea-pecl framing.
 *   - js/app.js lines 343-405 ('xxtea-raw'): plain btea, min 2 words,
 *     zero-padded, trailing-zero-stripped on decrypt (mirrors wrapper's
 *     zero_unpad for the *key*, not a length field).
 */

const DELTA = 0x9e3779b9;

function u32(x) { return x >>> 0; }

function bytesToWordsPecl(bytes) {
  // n = ceil(len/4), no minimum-2 floor (matches xxtea_to_uint_array with inc_len=0)
  const n = bytes.length === 0 ? 0 : (((bytes.length & 3) === 0) ? (bytes.length >>> 2) : ((bytes.length >>> 2) + 1));
  const words = new Uint32Array(n);
  for (let i = 0; i < bytes.length; i++) {
    words[i >> 2] = u32(words[i >> 2] | (bytes[i] << ((i & 3) << 3)));
  }
  return words;
}

function bytesToWordsRaw(bytes) {
  // matches app.js xxteaToWords: minimum 2 words
  const n = Math.max(2, Math.ceil(bytes.length / 4));
  const words = new Uint32Array(n);
  for (let i = 0; i < bytes.length; i++) {
    words[i >> 2] = u32(words[i >> 2] | (bytes[i] << ((i & 3) << 3)));
  }
  return words;
}

function mx(sum, y, z, p, e, key) {
  return u32(u32((u32(z >>> 5) ^ u32(y << 2)) + (u32(y >>> 3) ^ u32(z << 4))) ^
             u32(u32(sum ^ y) + u32(key[(p & 3) ^ e] ^ z)));
}

function btea_decrypt(words, key) {
  const n = words.length;
  if (n < 2) return words;
  let rounds = 6 + Math.floor(52 / n);
  let sum = u32(rounds * DELTA);
  let y = words[0], z, e, p;
  while (rounds-- > 0) {
    e = (sum >>> 2) & 3;
    for (p = n - 1; p > 0; p--) {
      z = words[p - 1];
      y = words[p] = u32(words[p] - mx(sum, y, z, p, e, key));
    }
    z = words[n - 1];
    y = words[0] = u32(words[0] - mx(sum, y, z, 0, e, key));
    sum = u32(sum - DELTA);
  }
  return words;
}

function keyToWords16(keyBytes) {
  const fixed = new Uint8Array(16);
  fixed.set(keyBytes.subarray(0, Math.min(16, keyBytes.length)));
  const w = new Uint32Array(4);
  for (let i = 0; i < 16; i++) w[i >> 2] = u32(w[i >> 2] | (fixed[i] << ((i & 3) << 3)));
  return w;
}

/* xxtea-pecl-framed decrypt (matches wasm/xxtea.c xxtea_decrypt_bytes).
 * Returns null if the framing/length check fails (this is the intended
 * gate -- xxtea-pecl decrypt fails outright on data it didn't encrypt). */
function xxteaPeclDecrypt(dataBytes, keyBytes) {
  if (dataBytes.length === 0) return null;
  const dataWords = bytesToWordsPecl(dataBytes);
  if (dataWords.length < 2) return null; // n-1 must be >=1 for the core loop
  const keyWords = keyToWords16(keyBytes);
  btea_decrypt(dataWords, keyWords);
  // xxtea_to_ubyte_array(data, len, inc_len=1, ...)
  const len = dataWords.length;
  const nBytesTotal = len << 2;
  const m = dataWords[len - 1];
  const nAfterHeader = nBytesTotal - 4;
  if (m < nAfterHeader - 3 || m > nAfterHeader) return null;
  const out = Buffer.alloc(m);
  for (let i = 0; i < m; i++) out[i] = (dataWords[i >> 2] >>> ((i & 3) << 3)) & 0xff;
  return out;
}

/* xxtea-raw decrypt (matches app.js jsXxtea path): plain btea, min 2
 * words, trailing zero bytes stripped (mirrors the wrapper's zero_unpad
 * behavior applied to the whole buffer, not just the key). */
function xxteaRawDecrypt(dataBytes, keyBytes) {
  if (dataBytes.length < 8) return null; // app.js: `if (inputBytes.length < 8) return null;`
  const dataWords = bytesToWordsRaw(dataBytes);
  const keyWords = keyToWords16(keyBytes);
  btea_decrypt(dataWords, keyWords);
  const out = Buffer.alloc(dataWords.length * 4);
  for (let i = 0; i < out.length; i++) out[i] = (dataWords[i >> 2] >>> ((i & 3) << 3)) & 0xff;
  let end = out.length;
  while (end > 0 && out[end - 1] === 0) end--;
  return out.subarray(0, end);
}

/* --- encrypt side (for controls only) --- */
function btea_encrypt(words, key) {
  const n = words.length;
  if (n < 2) return words;
  let rounds = 6 + Math.floor(52 / n);
  let sum = 0;
  let z = words[n - 1], y, e, p;
  while (rounds-- > 0) {
    sum = u32(sum + DELTA);
    e = (sum >>> 2) & 3;
    for (p = 0; p < n - 1; p++) {
      y = words[p + 1];
      z = words[p] = u32(words[p] + mx(sum, y, z, p, e, key));
    }
    y = words[0];
    z = words[n - 1] = u32(words[n - 1] + mx(sum, y, z, n - 1, e, key));
  }
  return words;
}

function xxteaPeclEncrypt(dataBytes, keyBytes) {
  // inc_len=1 on the way in: append a length word holding dataBytes.length
  const n = dataBytes.length === 0 ? 0 : (((dataBytes.length & 3) === 0) ? (dataBytes.length >>> 2) : ((dataBytes.length >>> 2) + 1));
  const words = new Uint32Array(n + 1);
  for (let i = 0; i < dataBytes.length; i++) words[i >> 2] = u32(words[i >> 2] | (dataBytes[i] << ((i & 3) << 3)));
  words[n] = dataBytes.length;
  const keyWords = keyToWords16(keyBytes);
  btea_encrypt(words, keyWords);
  const out = Buffer.alloc(words.length * 4);
  for (let i = 0; i < out.length; i++) out[i] = (words[i >> 2] >>> ((i & 3) << 3)) & 0xff;
  return out;
}

module.exports = { xxteaPeclDecrypt, xxteaRawDecrypt, xxteaPeclEncrypt };
