'use strict';
/* lib.js -- shared helpers for the rev7 dictionary key attack, extended
 * (dictkey2) to cover the remaining mcrypt wrapper modes: ncfb=3, ofb=4,
 * ctr=5, cbc=2, ecb=1 (mode numbers per ../../old-ciphers/js/app.js's
 * MODE_MAP -- cfb8=0 was already covered by ../dictkey/).
 * Loads ../../old-ciphers/js/mcrypt.js directly (own copy of the WASM
 * loading logic mirrored from mcrypt_cli.js's CIPHER_INFO table -- NOT an
 * edit of mcrypt_cli.js, mcrypt_oracle.py, or controls.py; this repo does
 * not import those files at all).
 */
const path = require('path');
const fs = require('fs');

const MCRYPT_JS = path.join(__dirname, '..', '..', 'old-ciphers', 'js', 'mcrypt.js');

const MODE_CFB8 = 0; // wrapper mode 0 == PHP mcrypt "cfb" == 8-bit CFB
// New scope for dictkey2 (per ../../old-ciphers/js/app.js MODE_MAP):
const MODE_ECB = 1;
const MODE_CBC = 2;
const MODE_NCFB = 3; // block-wide CFB ("cfb" in the wrapper's MODE_MAP)
const MODE_OFB = 4;
const MODE_CTR = 5;
const NEW_MODES = [
  { name: 'ncfb', int: MODE_NCFB },
  { name: 'cbc', int: MODE_CBC },
  { name: 'ecb', int: MODE_ECB },
  { name: 'ofb', int: MODE_OFB },
  { name: 'ctr', int: MODE_CTR },
];

// Mirrors mcrypt_cli.js's CIPHER_INFO exactly (same source of truth: the
// wrapper table in ../old-ciphers/js/app.js).
const CIPHER_INFO = {
  '3-way':           { fn: 'threeway_process',        blockSize: 12, stream: false, keySizes: [12] },
  'blowfish':        { fn: 'blowfish_process',        blockSize: 8,  stream: false, keySizes: [56], rawKey: true },
  'blowfish-compat': { fn: 'blowfish_compat_process', blockSize: 8,  stream: false, keySizes: [56], rawKey: true },
  'cast-128':        { fn: 'cast128_process',         blockSize: 8,  stream: false, keySizes: [16], rawKey: true },
  'cast-256':        { fn: 'cast256_process',         blockSize: 16, stream: false, keySizes: [16, 24, 32] },
  'des':             { fn: 'des_process',             blockSize: 8,  stream: false, keySizes: [8] },
  'tripledes':       { fn: 'tripledes_process',       blockSize: 8,  stream: false, keySizes: [24] },
  'gost':            { fn: 'gost_process',            blockSize: 8,  stream: false, keySizes: [32] },
  'loki97':          { fn: 'loki97_process',          blockSize: 16, stream: false, keySizes: [16, 24, 32] },
  'rc2':             { fn: 'rc2_process',             blockSize: 8,  stream: false, keySizes: [128], rawKey: true },
  'rijndael-128':    { fn: 'rijndael128_process',     blockSize: 16, stream: false, keySizes: [16, 24, 32] },
  'rijndael-192':    { fn: 'rijndael192_process',     blockSize: 24, stream: false, keySizes: [16, 24, 32] },
  'rijndael-256':    { fn: 'rijndael256_process',     blockSize: 32, stream: false, keySizes: [16, 24, 32] },
  'safer-64':        { fn: 'safer64_process',         blockSize: 8,  stream: false, keySizes: [8] },
  'safer-128':       { fn: 'safer128_process',        blockSize: 8,  stream: false, keySizes: [16] },
  'saferplus':       { fn: 'saferplus_process',       blockSize: 16, stream: false, keySizes: [16, 24, 32] },
  'serpent':         { fn: 'serpent_process',         blockSize: 16, stream: false, keySizes: [16, 24, 32] },
  'twofish':         { fn: 'twofish_process',         blockSize: 16, stream: false, keySizes: [16, 24, 32] },
  'xtea':            { fn: 'xtea_process',            blockSize: 8,  stream: false, keySizes: [16] },
  'enigma':          { fn: 'enigma_process',          blockSize: 0, stream: true, keySizes: [13] },
  'panama':          { fn: 'panama_process',          blockSize: 0, stream: true, keySizes: [32] },
  'arcfour':         { fn: 'rc4_process',             blockSize: 0, stream: true, keySizes: [256], rawKey: true },
  'wake':            { fn: 'wake_process',            blockSize: 0, stream: true, keySizes: [32] },
};

const ALL_CIPHERS = Object.keys(CIPHER_INFO);

// dictkey2 scope: only the 19 block ciphers (stream ciphers have no modes).
const BLOCK_CIPHERS = ALL_CIPHERS.filter((c) => !CIPHER_INFO[c].stream);

// ECB screening window per cipher: the largest prefix of the 64-byte
// screen buffer that is an exact multiple of the cipher's block size (so
// mcrypt's ecb entry point, which requires block-aligned input, doesn't
// reject it). 64 is a multiple of 8/16/32; 3-way (12) and rijndael-192
// (24) instead get 48 (4x12, 2x24).
const SCREEN_LEN = 64;
function ecbWindowLen(cipher) {
  const bs = CIPHER_INFO[cipher].blockSize;
  return Math.floor(SCREEN_LEN / bs) * bs;
}

// Priority order (ciphers the solved Revelations siblings used, per
// controls.py: des, rc2 (ecb elsewhere), blowfish, blowfish-compat,
// twofish, serpent, loki97, saferplus, xtea, arcfour -- plus the rest of
// the "prioritize" list from the task spec).
const PRIORITY_CIPHERS = [
  'des', 'tripledes', 'rc2', 'blowfish', 'blowfish-compat', 'twofish', 'serpent',
  'loki97', 'saferplus', 'xtea', 'arcfour', 'rijndael-128', 'rijndael-192',
  'rijndael-256', 'cast-128', 'cast-256', 'gost', 'wake', 'enigma',
];

async function loadMcrypt() {
  const McryptModule = require(MCRYPT_JS);
  const mcrypt = await McryptModule();
  const bufPtr = mcrypt._get_buf();
  const ivPtr = mcrypt._get_iv();
  const keyPtr = mcrypt._get_key();
  return { mcrypt, bufPtr, ivPtr, keyPtr };
}

/* Runs one decrypt call. keyBytes/ivBytes/dataBytes are Uint8Array. Returns
 * a Uint8Array view (caller must copy before the next call reuses the
 * shared buffer). */
function decryptOnce(ctx, cipher, keyBytes, ivBytes, dataBytes, mode) {
  const info = CIPHER_INFO[cipher];
  const { mcrypt, bufPtr, ivPtr, keyPtr } = ctx;
  mcrypt.HEAPU8.set(keyBytes, keyPtr);
  mcrypt.HEAPU8.set(dataBytes, bufPtr);

  if (info.stream) {
    mcrypt['_' + info.fn](keyBytes.length, dataBytes.length, 0 /* decrypt */);
    return new Uint8Array(mcrypt.HEAPU8.buffer, bufPtr, dataBytes.length);
  }

  const modeInt = mode === undefined ? MODE_CFB8 : mode;
  const ivFull = new Uint8Array(info.blockSize);
  if (modeInt !== MODE_ECB) ivFull.set(ivBytes.subarray(0, info.blockSize));
  mcrypt.HEAPU8.set(ivFull, ivPtr);
  const outLen = mcrypt['_' + info.fn](keyBytes.length, ivFull.length, dataBytes.length, 0, modeInt);
  if (outLen < 0) throw new Error('cipher process failed (outLen=' + outLen + ')');
  return new Uint8Array(mcrypt.HEAPU8.buffer, bufPtr, outLen);
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

/* Builds the list of key-byte-variants to try for a given cipher + literal
 * key string, per the spec: rawKey ciphers get literal + NUL-pad-to-8 +
 * NUL-pad-to-16 variants; fixed-key-size ciphers get just the literal bytes
 * (the wrapper pads internally). */
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
  // reverses build_keys.js's escapeKey()
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

/* encryptOnce -- mirrors decryptOnce but with the wrapper's encrypt flag
 * set (used only by make_plants.js to build the positive controls). */
function encryptOnce(ctx, cipher, keyBytes, ivBytes, dataBytes, mode) {
  const info = CIPHER_INFO[cipher];
  const { mcrypt, bufPtr, ivPtr, keyPtr } = ctx;
  mcrypt.HEAPU8.set(keyBytes, keyPtr);
  mcrypt.HEAPU8.set(dataBytes, bufPtr);
  const modeInt = mode === undefined ? MODE_CFB8 : mode;
  const ivFull = new Uint8Array(info.blockSize);
  if (modeInt !== MODE_ECB) ivFull.set(ivBytes.subarray(0, info.blockSize));
  mcrypt.HEAPU8.set(ivFull, ivPtr);
  const outLen = mcrypt['_' + info.fn](keyBytes.length, ivFull.length, dataBytes.length, 1, modeInt);
  if (outLen < 0) throw new Error('cipher process failed (outLen=' + outLen + ')');
  return new Uint8Array(mcrypt.HEAPU8.buffer, bufPtr, outLen).slice();
}

module.exports = {
  CIPHER_INFO, ALL_CIPHERS, PRIORITY_CIPHERS, BLOCK_CIPHERS, MODE_CFB8,
  MODE_ECB, MODE_CBC, MODE_NCFB, MODE_OFB, MODE_CTR, NEW_MODES, SCREEN_LEN,
  ecbWindowLen,
  loadMcrypt, decryptOnce, encryptOnce, isPrintable, printableFraction,
  keyVariants, readKeyFile, hexDecodeFile, unescapeKeyLine,
};
