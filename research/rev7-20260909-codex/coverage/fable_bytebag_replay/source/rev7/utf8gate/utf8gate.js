'use strict';
/* utf8gate.js -- the corrected plaintext-endpoint gate.
 *
 * Old gate (dictkey/dictkey2/selfkeys): >=95% of bytes in [start,end) are
 * ASCII TAB/LF/CR/32-126. That gate rejects real plaintext containing
 * UTF-8 punctuation (curly quotes, dashes, ellipsis) because their
 * continuation bytes (0x80-0xBF) and lead bytes (0xC0-0xF4) are not in
 * that ASCII range.
 *
 * New gate: a proper streaming UTF-8 state machine over the window that:
 *   - allows an incomplete multi-byte sequence at the very START of the
 *     window (we may be looking at a byte range that begins mid-sequence)
 *   - allows an incomplete multi-byte sequence at the very END of the
 *     window (ditto, ends mid-sequence)
 *   - rejects overlong encodings, surrogates, codepoints > 0x10FFFF, and
 *     malformed continuation bytes
 *   - requires every FULLY DECODED codepoint to be in the allowed set
 */

// Codepoints allowed beyond plain printable ASCII + TAB/LF/CR.
const EXTRA_PUNCT = new Set([
  0x2013, // en dash
  0x2014, // em dash
  0x2018, // left single curly quote
  0x2019, // right single curly quote
  0x201C, // left double curly quote
  0x201D, // right double curly quote
  0x2026, // ellipsis
]);

function isAllowedCodepoint(cp) {
  if (cp === 0x09 || cp === 0x0a || cp === 0x0d) return true;
  if (cp >= 0x20 && cp <= 0x7e) return true;
  if (cp >= 0x00a0 && cp <= 0x00ff) return true; // Latin-1 supplement letters/punctuation
  if (EXTRA_PUNCT.has(cp)) return true;
  return false;
}

// Classifies a lead byte. Returns null if it's not a valid UTF-8 lead byte
// (i.e. it's a stray continuation byte 0x80-0xBF, or 0xF8-0xFF which are
// not valid in RFC 3629 UTF-8).
function classifyLead(b) {
  if (b < 0x80) return { len: 1, bits: b };
  if ((b & 0xe0) === 0xc0) return { len: 2, bits: b & 0x1f };
  if ((b & 0xf0) === 0xe0) return { len: 3, bits: b & 0x0f };
  if ((b & 0xf8) === 0xf0) return { len: 4, bits: b & 0x07 };
  return null;
}

const MIN_FOR_LEN = { 1: 0, 2: 0x80, 3: 0x800, 4: 0x10000 };

/* validateUtf8Window(bytes, start, end) -> boolean
 * bytes: Buffer/Uint8Array, [start,end) is the window (end exclusive). */
function validateUtf8Window(bytes, start, end) {
  let i = start;

  // Tolerate a run of stray continuation bytes at the very start of the
  // window -- the window may begin mid-sequence relative to whatever
  // preceded it (out of scope / not part of this window).
  while (i < end && (bytes[i] & 0xc0) === 0x80) i++;

  while (i < end) {
    const b = bytes[i];
    if (b < 0x80) {
      if (!isAllowedCodepoint(b)) return false;
      i++;
      continue;
    }
    const lead = classifyLead(b);
    if (!lead) return false; // stray continuation byte or invalid 0xF8-0xFF lead
    const { len } = lead;
    let cp = lead.bits;
    let j = i + 1;
    let complete = true;
    for (let k = 1; k < len; k++) {
      if (j >= end) { complete = false; break; } // truncated at window end: tolerated
      const cb = bytes[j];
      if ((cb & 0xc0) !== 0x80) return false; // malformed continuation byte
      cp = (cp << 6) | (cb & 0x3f);
      j++;
    }
    if (!complete) {
      // Incomplete multi-byte sequence at the end of the window: allowed,
      // and there is nothing further to validate.
      return true;
    }
    if (cp < MIN_FOR_LEN[len]) return false; // overlong encoding
    if (cp >= 0xd800 && cp <= 0xdfff) return false; // surrogate half
    if (cp > 0x10ffff) return false;
    if (!isAllowedCodepoint(cp)) return false;
    i = j;
  }
  return true;
}

module.exports = { validateUtf8Window, isAllowedCodepoint, EXTRA_PUNCT };
