'use strict';
/* lib.js -- shared helpers for the rev7 OFB8 (8-bit output feedback) attack.
 * Copies the CIPHER_INFO table and general patterns from
 * ../dictkey/lib.js (not edited, not imported -- own copy per spec).
 * Loads ../../old-ciphers/js/mcrypt.js directly.
 */
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const MCRYPT_JS = path.join(__dirname, '..', '..', 'old-ciphers', 'js', 'mcrypt.js');

const MODE_ECB = 1; // wrapper mode int for ECB (used here only to get raw blockEncrypt)
const MODE_OFB_BLOCKWIDE = 4; // wrapper's existing block-wide OFB, used for the divergence check

const CIPHER_INFO = {
  '3-way':           { fn: 'threeway_process',        blockSize: 12, keySizes: [12] },
  'blowfish':        { fn: 'blowfish_process',        blockSize: 8,  keySizes: [56], rawKey: true },
  'blowfish-compat': { fn: 'blowfish_compat_process', blockSize: 8,  keySizes: [56], rawKey: true },
  'cast-128':        { fn: 'cast128_process',         blockSize: 8,  keySizes: [16], rawKey: true },
  'cast-256':        { fn: 'cast256_process',         blockSize: 16, keySizes: [16, 24, 32] },
  'des':             { fn: 'des_process',             blockSize: 8,  keySizes: [8] },
  'tripledes':       { fn: 'tripledes_process',       blockSize: 8,  keySizes: [24] },
  'gost':            { fn: 'gost_process',            blockSize: 8,  keySizes: [32] },
  'loki97':          { fn: 'loki97_process',          blockSize: 16, keySizes: [16, 24, 32] },
  'rc2':             { fn: 'rc2_process',             blockSize: 8,  keySizes: [128], rawKey: true },
  'rijndael-128':    { fn: 'rijndael128_process',     blockSize: 16, keySizes: [16, 24, 32] },
  'rijndael-192':    { fn: 'rijndael192_process',     blockSize: 24, keySizes: [16, 24, 32] },
  'rijndael-256':    { fn: 'rijndael256_process',     blockSize: 32, keySizes: [16, 24, 32] },
  'safer-64':        { fn: 'safer64_process',         blockSize: 8,  keySizes: [8] },
  'safer-128':       { fn: 'safer128_process',        blockSize: 8,  keySizes: [16] },
  'saferplus':       { fn: 'saferplus_process',       blockSize: 16, keySizes: [16, 24, 32] },
  'serpent':         { fn: 'serpent_process',         blockSize: 16, keySizes: [16, 24, 32] },
  'twofish':         { fn: 'twofish_process',         blockSize: 16, keySizes: [16, 24, 32] },
  'xtea':            { fn: 'xtea_process',            blockSize: 8,  keySizes: [16] },
};

const ALL_CIPHERS = Object.keys(CIPHER_INFO);

async function loadMcrypt() {
  const McryptModule = require(MCRYPT_JS);
  const mcrypt = await McryptModule();
  const bufPtr = mcrypt._get_buf();
  const ivPtr = mcrypt._get_iv();
  const keyPtr = mcrypt._get_key();
  return { mcrypt, bufPtr, ivPtr, keyPtr };
}

/* Raw single-block encryption E_k(block) via the wrapper's ECB mode
 * (datalen == blockSize, so zero_pad is a no-op and this is exactly one
 * call to the cipher's block encrypt function). Returns a NEW Uint8Array
 * (copied out, since the shared buffer will be reused). */
function blockEncrypt(ctx, cipher, keyBytes, blockBytes) {
  const info = CIPHER_INFO[cipher];
  const { mcrypt, bufPtr, keyPtr } = ctx;
  mcrypt.HEAPU8.set(keyBytes, keyPtr);
  mcrypt.HEAPU8.set(blockBytes, bufPtr);
  const outLen = mcrypt['_' + info.fn](keyBytes.length, info.blockSize, info.blockSize, 1 /* encrypt */, MODE_ECB);
  if (outLen !== info.blockSize) throw new Error('blockEncrypt bad outLen=' + outLen + ' for ' + cipher);
  return new Uint8Array(mcrypt.HEAPU8.buffer, bufPtr, info.blockSize).slice();
}

/* Wrapper's existing block-wide OFB (mode 4), used only for the divergence
 * sanity check against our OFB8. direction: 1=encrypt, 0=decrypt (mode is
 * symmetric so either works). */
function blockWideOFB(ctx, cipher, keyBytes, ivBytes, dataBytes) {
  const info = CIPHER_INFO[cipher];
  const { mcrypt, bufPtr, ivPtr, keyPtr } = ctx;
  mcrypt.HEAPU8.set(keyBytes, keyPtr);
  mcrypt.HEAPU8.set(dataBytes, bufPtr);
  const ivFull = new Uint8Array(info.blockSize);
  ivFull.set(ivBytes.subarray(0, info.blockSize));
  mcrypt.HEAPU8.set(ivFull, ivPtr);
  const outLen = mcrypt['_' + info.fn](keyBytes.length, ivFull.length, dataBytes.length, 0, MODE_OFB_BLOCKWIDE);
  if (outLen < 0) throw new Error('blockWideOFB process failed (outLen=' + outLen + ')');
  return new Uint8Array(mcrypt.HEAPU8.buffer, bufPtr, outLen).slice();
}

/* OFB8 (8-bit output feedback) as PHP mcrypt's "ofb" mode:
 *   R = IV (blockSize bytes)
 *   for each byte i:
 *     E = blockEncrypt(R)
 *     k = E[0]
 *     out[i] = data[i] XOR k
 *     R = R[1:] . k     <-- shift the KEYSTREAM byte in (NOT the ciphertext
 *                            byte -- that would be CFB8)
 * Encryption and decryption are the identical XOR-with-keystream operation.
 */
function ofb8Process(ctx, cipher, keyBytes, ivBytes, dataBytes) {
  const info = CIPHER_INFO[cipher];
  const bs = info.blockSize;
  const R = new Uint8Array(bs);
  R.set(ivBytes.subarray(0, bs));
  const out = new Uint8Array(dataBytes.length);
  for (let i = 0; i < dataBytes.length; i++) {
    const E = blockEncrypt(ctx, cipher, keyBytes, R);
    const k = E[0];
    out[i] = dataBytes[i] ^ k;
    // shift R left by one, append k
    for (let j = 0; j < bs - 1; j++) R[j] = R[j + 1];
    R[bs - 1] = k;
  }
  return out;
}

function isPrintable(byte) {
  return byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126);
}

function printableFraction(bytes, start, end) {
  let ok = 0;
  const n = Math.max(0, end - start);
  if (n === 0) return 1;
  for (let i = start; i < end; i++) if (isPrintable(bytes[i])) ok++;
  return ok / n;
}

function keyVariants(cipher, keyStrBytes) {
  const info = CIPHER_INFO[cipher];
  const variants = [{ label: 'literal', bytes: keyStrBytes }];
  if (info.rawKey) {
    if (keyStrBytes.length < 8) {
      const p = new Uint8Array(8);
      p.set(keyStrBytes);
      variants.push({ label: 'pad8', bytes: p });
    }
    if (keyStrBytes.length < 16) {
      const p = new Uint8Array(16);
      p.set(keyStrBytes);
      variants.push({ label: 'pad16', bytes: p });
    }
  }
  return variants;
}

function unescapeKeyLine(line) {
  let out = '';
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '\\' && i + 1 < line.length) {
      const n = line[i + 1];
      if (n === 'n') { out += '\n'; i++; continue; }
      if (n === 'r') { out += '\r'; i++; continue; }
      if (n === 't') { out += '\t'; i++; continue; }
      if (n === '\\') { out += '\\'; i++; continue; }
    }
    out += c;
  }
  return out;
}

function readKeyFile(fp) {
  const raw = fs.readFileSync(fp, 'utf8').split('\n');
  const out = [];
  for (const line of raw) {
    if (line.length === 0) continue;
    out.push(unescapeKeyLine(line));
  }
  return out;
}

function hexDecodeFile(fp) {
  const raw = fs.readFileSync(fp, 'utf8').replace(/\s+/g, '');
  return Buffer.from(raw, 'hex');
}

function nibbleSwap(buf) {
  const out = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i];
    out[i] = ((b & 0x0f) << 4) | ((b & 0xf0) >> 4);
  }
  return out;
}

// byte-pair-reversed: reverse order of bytes in adjacent pairs (0,1),(2,3),...
function bytePairReversed(buf) {
  const out = Buffer.from(buf);
  for (let i = 0; i + 1 < out.length; i += 2) {
    const t = out[i]; out[i] = out[i + 1]; out[i + 1] = t;
  }
  return out;
}

function ivFor(kind, keytext, blockSize) {
  if (kind === 'zero_ascii') return new Uint8Array(blockSize).fill(0x30);
  if (kind === 'zero_null') return new Uint8Array(blockSize).fill(0x00);
  if (kind === 'sha1_key') {
    const h = crypto.createHash('sha1').update(keytext, 'binary').digest();
    return new Uint8Array(h.subarray(0, blockSize));
  }
  throw new Error('unknown iv kind ' + kind);
}

module.exports = {
  CIPHER_INFO, ALL_CIPHERS, MODE_ECB, MODE_OFB_BLOCKWIDE,
  loadMcrypt, blockEncrypt, blockWideOFB, ofb8Process,
  isPrintable, printableFraction, keyVariants, readKeyFile, hexDecodeFile,
  unescapeKeyLine, nibbleSwap, bytePairReversed, ivFor,
};
