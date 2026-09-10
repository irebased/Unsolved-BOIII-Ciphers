'use strict';
/* cascade_lib.js -- shared helpers for the decrypt->decrypt binary-cascade
 * search. Reuses ../dictkey2/lib.js (WASM mcrypt wrapper: loadMcrypt,
 * decryptOnce, CIPHER_INFO, ALL_CIPHERS) and ../utf8gate/utf8gate.js
 * (corrected plaintext gate). Does not modify either file.
 * Adds an encryptOnce (direction=1) alongside lib.js's decrypt-only
 * decryptOnce, using the exact same low-level WASM call shape that
 * ../mcrypt_cli.js already uses for its "encrypt" op (read, not copied
 * wholesale, but mirrors the documented direction-flag convention: 0 =
 * decrypt, 1 = encrypt, 4th positional arg to the block-cipher *_process
 * functions / 3rd to the stream *_process functions).
 */
const path = require('path');
const lib = require('../dictkey2/lib.js');
const { validateUtf8Window } = require('../utf8gate/utf8gate.js');

const KEYS = ['Zombies', 'ZOMBIES'];
const MODE_CFB8 = 0;

function keyBytesFor(str) { return Buffer.from(str, 'ascii'); }
function ivFor(len) { return Buffer.alloc(len, 0x30); } // ASCII '0'

// loki97 heap-history fix (see ../loki97fix/): always supply an explicit
// 32-byte key buffer so pad_key_16_24_32's memset branch never fires on
// stale heap.
function loki97Key(str) {
  const b = Buffer.alloc(32);
  Buffer.from(str, 'ascii').copy(b);
  return b;
}

function keyBytesForCipher(cipher, keyStr) {
  return cipher === 'loki97' ? loki97Key(keyStr) : keyBytesFor(keyStr);
}

/* Same call shape as lib.decryptOnce but with direction=1 (encrypt). Not a
 * copy of lib.js's file; a sibling function using the same ctx/module. */
function encryptOnce(ctx, cipher, keyBytes, ivBytes, dataBytes) {
  const info = lib.CIPHER_INFO[cipher];
  const { mcrypt, bufPtr, ivPtr, keyPtr } = ctx;
  mcrypt.HEAPU8.set(keyBytes, keyPtr);
  mcrypt.HEAPU8.set(dataBytes, bufPtr);
  if (info.stream) {
    mcrypt['_' + info.fn](keyBytes.length, dataBytes.length, 1 /* encrypt */);
    return Buffer.from(new Uint8Array(mcrypt.HEAPU8.buffer, bufPtr, dataBytes.length));
  }
  const ivFull = new Uint8Array(info.blockSize);
  ivFull.set(ivBytes.subarray(0, info.blockSize));
  mcrypt.HEAPU8.set(ivFull, ivPtr);
  const outLen = mcrypt['_' + info.fn](keyBytes.length, ivFull.length, dataBytes.length, 1, MODE_CFB8);
  if (outLen < 0) throw new Error('cipher encrypt failed (outLen=' + outLen + ')');
  return Buffer.from(new Uint8Array(mcrypt.HEAPU8.buffer, bufPtr, outLen));
}

function decryptWith(ctx, cipher, keyStr, buf) {
  const info = lib.CIPHER_INFO[cipher];
  const keyBytes = keyBytesForCipher(cipher, keyStr);
  const ivBytes = info.blockSize ? ivFor(info.blockSize) : ivFor(8);
  const out = lib.decryptOnce(ctx, cipher, keyBytes, ivBytes, buf, MODE_CFB8);
  return Buffer.from(out);
}

function encryptWith(ctx, cipher, keyStr, buf) {
  const info = lib.CIPHER_INFO[cipher];
  const keyBytes = keyBytesForCipher(cipher, keyStr);
  const ivBytes = info.blockSize ? ivFor(info.blockSize) : ivFor(8);
  return encryptOnce(ctx, cipher, keyBytes, ivBytes, buf);
}

// codepoint-aware reverse, identical semantics to chainsearch/search.js's
// reverseBuf: reverse UTF-8 codepoints if valid UTF-8, else raw byte
// reverse (there is no character structure to respect in binary noise).
const utf8Decoder = new TextDecoder('utf-8', { fatal: true });
function reverseBuf(buf) {
  try {
    const s = utf8Decoder.decode(buf);
    const reversed = Array.from(s).reverse().join('');
    return Buffer.from(reversed, 'utf8');
  } catch (e) {
    return Buffer.from(buf).reverse();
  }
}

function orientations(hexStr) {
  const displayed = hexStr;
  const fullReversed = hexStr.split('').reverse().join('');
  const pairs = hexStr.match(/../g);
  const bytePairReversed = pairs.slice().reverse().join('');
  const nibbleSwap = pairs.map((p) => p[1] + p[0]).join('');
  return { displayed, fullReversed, bytePairReversed, nibbleSwap };
}

// ---------- scoring ----------
// Graded score over bytes[blockSize:] (skip first block -- IV-dependent
// under CFB8, per task spec): longest run of consecutive gate-valid bytes,
// and total count of gate-valid bytes. "gate-valid" per byte here means:
// treating each byte position i as the start of a 1-byte window that is
// itself independently valid UTF-8 continuation-tolerant, i.e. we scan the
// whole tail with the streaming validator and measure runs of allowed
// bytes/codepoints rather than an all-or-nothing verdict.
function scoreTail(buf, skipBytes) {
  const start = Math.min(skipBytes, buf.length);
  const tail = buf.subarray(start);
  if (tail.length === 0) return { longestRun: 0, validCount: 0, tailLen: 0 };
  // Walk the tail with the same UTF-8 state machine as the gate, but count
  // per-codepoint validity contiguously instead of an all-or-nothing
  // boolean over the whole window.
  let i = 0;
  let longestRun = 0, curRun = 0, validCount = 0;
  while (i < tail.length) {
    // Try to validate a window starting at i of length 1..4 (longest valid
    // codepoint consumes up to 4 bytes); use validateUtf8Window on
    // progressively larger single-codepoint slices by leveraging the
    // classifyLead logic indirectly: simplest robust approach is to ask
    // whether [i, i+1) is a valid *complete* single-byte allowed codepoint,
    // OR whether a longer lead sequence starting at i validates as a
    // complete (non-truncated) window of exactly that codepoint length.
    const b = tail[i];
    if (b < 0x80) {
      const ok = validateUtf8Window(tail, i, i + 1);
      if (ok) { validCount++; curRun++; longestRun = Math.max(longestRun, curRun); i += 1; continue; }
      curRun = 0; i += 1; continue;
    }
    // multi-byte lead: find its declared length, check completeness+validity
    let len;
    if ((b & 0xe0) === 0xc0) len = 2;
    else if ((b & 0xf0) === 0xe0) len = 3;
    else if ((b & 0xf8) === 0xf0) len = 4;
    else { curRun = 0; i += 1; continue; } // stray continuation / invalid lead
    if (i + len > tail.length) { curRun = 0; i += 1; continue; } // truncated at tail end, not a complete codepoint
    const ok = validateUtf8Window(tail, i, i + len);
    if (ok) {
      validCount += len; curRun += len; longestRun = Math.max(longestRun, curRun); i += len;
    } else {
      curRun = 0; i += 1;
    }
  }
  return { longestRun, validCount, tailLen: tail.length };
}

module.exports = {
  KEYS, MODE_CFB8, keyBytesFor, ivFor, loki97Key, keyBytesForCipher,
  encryptOnce, decryptWith, encryptWith, reverseBuf, orientations, scoreTail,
  loadMcrypt: lib.loadMcrypt, ALL_CIPHERS: lib.ALL_CIPHERS, CIPHER_INFO: lib.CIPHER_INFO,
};
