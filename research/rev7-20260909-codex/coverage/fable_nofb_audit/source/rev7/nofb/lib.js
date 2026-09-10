'use strict';
/* nofb/lib.js -- FULL-BLOCK OFB (PHP mcrypt "nofb" mode), built on the
 * ECB *encryption* primitive the WASM wrapper already exports.
 *
 *   register = IV
 *   repeat: register = E_key(register); keystream_block = register
 *   out = in XOR keystream   (final block truncated)
 *
 * Encryption and decryption are the identical operation.
 *
 * Reuses (does NOT modify): ../ofb8/lib.js  -> blockEncrypt, blockWideOFB,
 *   ofb8Process, CIPHER_INFO, loadMcrypt, readKeyFile, hexDecodeFile
 *   ../cascade/cascade_lib.js -> scoreTail, orientations
 */
const ofb8 = require('../ofb8/lib.js');

const CIPHER_INFO = ofb8.CIPHER_INFO;
const ALL_CIPHERS = ofb8.ALL_CIPHERS; // the 19 block ciphers

/* Full-block OFB keystream of `n` bytes for (cipher, key, iv). */
function nofbKeystream(ctx, cipher, keyBytes, ivBytes, n) {
  const bs = CIPHER_INFO[cipher].blockSize;
  const R = new Uint8Array(bs);
  R.set(ivBytes.subarray(0, bs));
  const ks = new Uint8Array(n);
  let off = 0;
  let reg = R;
  while (off < n) {
    reg = ofb8.blockEncrypt(ctx, cipher, keyBytes, reg); // register = E_k(register)
    const take = Math.min(bs, n - off);
    ks.set(reg.subarray(0, take), off);                  // truncate final block
    off += take;
  }
  return ks;
}

function nofbProcess(ctx, cipher, keyBytes, ivBytes, dataBytes) {
  const ks = nofbKeystream(ctx, cipher, keyBytes, ivBytes, dataBytes.length);
  const out = new Uint8Array(dataBytes.length);
  for (let i = 0; i < dataBytes.length; i++) out[i] = dataBytes[i] ^ ks[i];
  return out;
}

/* loki97 heap-history fix (see ../loki97fix/): always hand loki97 an
 * explicit 32-byte NUL-padded key buffer. */
function keyBytesForCipher(cipher, keyStr) {
  if (cipher === 'loki97') {
    const b = new Uint8Array(32);
    const k = Buffer.from(keyStr, 'binary');
    b.set(k.subarray(0, 32));
    return b;
  }
  return new Uint8Array(Buffer.from(keyStr, 'binary'));
}

module.exports = {
  CIPHER_INFO, ALL_CIPHERS,
  loadMcrypt: ofb8.loadMcrypt,
  blockEncrypt: ofb8.blockEncrypt,
  blockWideOFB: ofb8.blockWideOFB,
  ofb8Process: ofb8.ofb8Process,
  readKeyFile: ofb8.readKeyFile,
  hexDecodeFile: ofb8.hexDecodeFile,
  nofbKeystream, nofbProcess, keyBytesForCipher,
};
