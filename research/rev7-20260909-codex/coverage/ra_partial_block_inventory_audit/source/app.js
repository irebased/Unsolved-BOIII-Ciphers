// Main application logic — uses libmcrypt compiled to WASM

var mcrypt = null; // WASM module instance
var bufPtr, ivPtr, keyPtr;

// Initialize WASM
McryptModule().then(function(mod) {
  mcrypt = mod;
  bufPtr = mcrypt._get_buf();
  ivPtr = mcrypt._get_iv();
  keyPtr = mcrypt._get_key();
  console.log('WASM loaded. bufPtr=' + bufPtr + ' ivPtr=' + ivPtr + ' keyPtr=' + keyPtr);
  document.getElementById('run-btn').disabled = false;
}).catch(function(e) {
  console.error('WASM load failed:', e);
  document.getElementById('error').textContent = 'WASM failed to load: ' + (e.message || e);
  document.getElementById('error').hidden = false;
});

var MODE_MAP = { cfb8: 0, ecb: 1, cbc: 2, cfb: 3, ofb: 4, ctr: 5 };
var ALL_MODES = ['cfb8', 'ecb', 'cbc', 'cfb', 'ofb', 'ctr'];
var MODE_LABELS = { cfb8: 'CFB-8', ecb: 'ECB', cbc: 'CBC', cfb: 'CFB', ofb: 'OFB', ctr: 'CTR' };

/*
 * keySizes — key lengths (bytes, ascending) each cipher accepts, from libmcrypt's
 *   _mcrypt_get_supported_key_sizes / _mcrypt_get_key_size. Ciphers that take any
 *   length up to a maximum are listed with that maximum only, since null-padding a
 *   short key is only meaningful up to the full key size.
 * rawKey — true when mcrypt_wrapper.c passes the key through at the length we give
 *   it, leaving the cipher's own key schedule to stretch a short key (Blowfish and
 *   RC4 cycle it, others expand it). The rest are already null-padded to a supported
 *   size by the wrapper, so the null-padded key variant would be a duplicate there.
 */
var CIPHER_INFO = {
  /* Block ciphers (need IV for most modes) */
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
  'serpent':         { fn: 'serpent_process',          blockSize: 16, stream: false, keySizes: [16, 24, 32] },
  'twofish':         { fn: 'twofish_process',         blockSize: 16, stream: false, keySizes: [16, 24, 32] },
  'xtea':            { fn: 'xtea_process',            blockSize: 8,  stream: false, keySizes: [16] },

  /* Stream ciphers (no IV) */
  /* Enigma's key schedule ignores trailing NUL bytes, so it is not marked rawKey:
     padding its key is verifiably a no-op. */
  'enigma':          { fn: 'enigma_process',          blockSize: 0,  stream: true, keySizes: [13] },
  'panama':          { fn: 'panama_process',          blockSize: 0,  stream: true, keySizes: [32] },
  'rc4':             { fn: 'rc4_process',             blockSize: 0,  stream: true, keySizes: [256], rawKey: true },
  'wake':            { fn: 'wake_process',            blockSize: 0,  stream: true, keySizes: [32] },

  /* XXTEA (no IV, variable-length output). Two incompatible framings are in the
     wild: xxtea.c implements the xxtea-pecl one, which appends the plaintext
     length as a trailing word and rejects anything without it, so plain btea
     ciphertext needs the second entry. Both null-pad the key to 16 bytes. */
  'xxtea':           { fn: 'xxtea_process',           blockSize: 0,  stream: false, xxtea: true, keySizes: [16] },
  'xxtea-raw':       { fn: null, jsXxtea: true,       blockSize: 0,  stream: false, xxtea: true, keySizes: [16] }
};

var cipherSelect = document.getElementById('cipher');
var modeSelect   = document.getElementById('mode');
var modeGroup    = document.getElementById('mode-group');
var ivGroup      = document.getElementById('iv-group');
var keyInput     = document.getElementById('key');
var ivInput      = document.getElementById('iv');
var inputArea    = document.getElementById('input');
var outputArea   = document.getElementById('output');
var outputGroup  = document.getElementById('output-group');
var runBtn       = document.getElementById('run-btn');
var reverseBtn   = document.getElementById('reverse-btn');
var padKeyCb     = document.getElementById('pad-key');
var padKeyGroup  = document.getElementById('pad-key-group');
var padKeyNote   = document.getElementById('pad-key-note');
var errorDiv     = document.getElementById('error');

var tryAllGroup     = document.getElementById('try-all-group');
var tryAllCheckbox  = document.getElementById('try-all');
var tryAllOptions   = document.getElementById('try-all-options');
var tryAllResults   = document.getElementById('try-all-results');
var tryAllResultsList = document.getElementById('try-all-results-list');
var tryAllCount     = document.getElementById('try-all-count');
var customPatternInput = document.getElementById('custom-pattern');
var reverseInputCb  = document.getElementById('reverse-input');
var reverseInputNote = document.getElementById('reverse-input-note');
var reverseKeyCb    = document.getElementById('reverse-key');
var caseVariantsCb  = document.getElementById('case-variants');
var nullPadKeyCb    = document.getElementById('null-pad-key');
var tryAllModesCb   = document.getElementById('try-all-modes');
var sortBySelect    = document.getElementById('sort-by');

runBtn.disabled = true; // disabled until WASM loads

// Nothing calls updateVisibility() on load, so seed the key-padding note here.
updateKeyPadState();

function getOperation() {
  return document.querySelector('input[name="operation"]:checked').value;
}
function getEncoding() {
  return document.querySelector('input[name="encoding"]:checked').value;
}
function getPatternPreset() {
  return document.querySelector('input[name="pattern-preset"]:checked').value;
}
function getMode() {
  return modeSelect.value;
}
function getModeInt(modeStr) {
  return MODE_MAP[modeStr] || 0;
}

function updateVisibility() {
  var info = CIPHER_INFO[cipherSelect.value];
  var isStreamOrXxtea = info && (info.stream || info.xxtea);
  var isEcb = modeSelect.value === 'ecb';

  // Hide mode selector for stream ciphers and XXTEA
  modeGroup.hidden = isStreamOrXxtea;
  // Hide IV for stream ciphers, XXTEA, or ECB mode
  ivGroup.hidden = isStreamOrXxtea || isEcb;

  updateKeyPadState();
}

// The single-run null-pad checkbox is replaced by its own brute-force variant
// while Try All Ciphers is running, and the note explains when padding is a no-op
// for the selected cipher.
function updateKeyPadState() {
  padKeyGroup.hidden = tryAllCheckbox.checked && getOperation() === 'decrypt';
  if (padKeyGroup.hidden) return;

  var info = CIPHER_INFO[cipherSelect.value];
  var keyLen = keyInput.value.length;
  if (!info || nullPaddingApplies(info, keyLen)) {
    padKeyNote.hidden = true;
    return;
  }
  padKeyNote.textContent = keyLen >= keySizeFor(info, keyLen)
    ? 'The key already fills ' + cipherSelect.value + "'s " + keySizeFor(info, keyLen) +
      '-byte key size — nothing to pad.'
    : cipherSelect.value + ' already null-pads short keys to ' + keySizeFor(info, keyLen) +
      ' bytes, so this option changes nothing for it.';
  padKeyNote.hidden = false;
}

cipherSelect.addEventListener('change', updateVisibility);
modeSelect.addEventListener('change', updateVisibility);

// Show "Try All" group only when decrypt is selected
document.querySelectorAll('input[name="operation"]').forEach(function(radio) {
  radio.addEventListener('change', function() {
    var isDecrypt = getOperation() === 'decrypt';
    tryAllGroup.hidden = !isDecrypt;
    if (!isDecrypt) {
      tryAllCheckbox.checked = false;
      tryAllOptions.hidden = true;
      tryAllResults.hidden = true;
    }
    updateKeyPadState();
  });
});

tryAllCheckbox.addEventListener('change', function() {
  tryAllOptions.hidden = !tryAllCheckbox.checked;
  if (!tryAllCheckbox.checked) {
    tryAllResults.hidden = true;
  }
  updateReverseInputState();
  updateKeyPadState();
});

// Show custom pattern input when "Custom regex" is selected
document.querySelectorAll('input[name="pattern-preset"]').forEach(function(radio) {
  radio.addEventListener('change', function() {
    customPatternInput.hidden = getPatternPreset() !== 'custom';
  });
});

keyInput.addEventListener('input', updateKeyPadState);

// Update reversed-input checkbox state based on input content
inputArea.addEventListener('input', updateReverseInputState);
document.querySelectorAll('input[name="encoding"]').forEach(function(radio) {
  radio.addEventListener('change', updateReverseInputState);
});

function isBase64WithPadding(str) {
  return getEncoding() === 'base64' && /=\s*$/.test(str.trim());
}

function updateReverseInputState() {
  var hasPadding = isBase64WithPadding(inputArea.value);
  reverseInputCb.disabled = hasPadding;
  if (hasPadding) reverseInputCb.checked = false;
  reverseInputNote.hidden = !hasPadding;
}

// Real messages carry punctuation, and text encoded as UTF-8 arrives here one byte
// per character — an ellipsis or curly quote shows up as a couple of high bytes. A
// character class strict enough to be useful rejects all of that, so prose is scored
// instead: overwhelmingly printable, mostly letters and spaces, and containing at
// least two adjacent words.
var PROSE_MATCHER = {
  test: function (s) {
    if (s.length < 12) return false;
    var printable = 0, letters = 0;
    for (var i = 0; i < s.length; i++) {
      var c = s.charCodeAt(i);
      if ((c >= 0x20 && c <= 0x7e) || c === 0x09 || c === 0x0a || c === 0x0d) printable++;
      if ((c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 32) letters++;
    }
    return printable / s.length >= 0.9 &&
           letters / s.length >= 0.7 &&
           /[A-Za-z]{2,} [A-Za-z]{2,}/.test(s);
  }
};

// Returns a matcher — anything with a .test(string). Not always a RegExp.
function getMatcher() {
  var preset = getPatternPreset();
  switch (preset) {
    case 'alnum':   return /^[A-Za-z0-9 ]+$/;
    case 'prose':   return PROSE_MATCHER;
    case 'alpha':   return /^[A-Za-z ]+$/;
    case 'numeric': return /^[0-9 ]+$/;
    case 'base64':  return /^[A-Za-z0-9+/=]+$/;
    case 'custom':
      var pat = customPatternInput.value.trim();
      if (!pat) throw new Error('Custom regex pattern is empty');
      return new RegExp(pat);
  }
}

function showError(msg) {
  errorDiv.textContent = msg;
  errorDiv.hidden = false;
}
function clearError() {
  errorDiv.hidden = true;
}

function asciiToBytes(str) {
  var bytes = new Uint8Array(str.length);
  for (var i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i) & 0xff;
  return bytes;
}

/*
 * Cipher output is bytes, and plaintext is usually text — an ellipsis is the three
 * UTF-8 bytes E2 80 A6, which one-char-per-byte renders as "\u00e2\u0080\u00a6".
 * Decode as UTF-8 when the bytes are valid UTF-8 and fall back to one char per byte
 * otherwise, since a wrong key produces arbitrary bytes that still have to render
 * for the brute forcer to pattern-match them. ignoreBOM keeps a leading BOM in the
 * plaintext instead of silently eating it.
 */
var UTF8_DECODER = typeof TextDecoder !== 'undefined'
  ? new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })
  : null;

function bytesToText(bytes) {
  if (UTF8_DECODER) {
    try { return UTF8_DECODER.decode(bytes); } catch (e) { /* not valid UTF-8 */ }
  }
  var text = '';
  for (var i = 0; i < bytes.length; i++) text += String.fromCharCode(bytes[i]);
  return text;
}

// Typed plaintext goes out as UTF-8 so non-ASCII characters survive a round trip.
// (The key stays byte-per-char — the field is labelled ASCII and changing how key
// bytes are derived would change every existing key's ciphertext.)
var UTF8_ENCODER = typeof TextEncoder !== 'undefined' ? new TextEncoder() : null;

function textToBytes(str) {
  return UTF8_ENCODER ? UTF8_ENCODER.encode(str) : asciiToBytes(str);
}

// Smallest key size the cipher accepts that holds keyLen bytes (its largest if
// the key is longer than anything it supports).
function keySizeFor(info, keyLen) {
  for (var i = 0; i < info.keySizes.length; i++) {
    if (info.keySizes[i] >= keyLen) return info.keySizes[i];
  }
  return info.keySizes[info.keySizes.length - 1];
}

// True when right-padding the key with NUL bytes gives this cipher something
// different from the key as-is — i.e. the cipher would otherwise stretch the short
// key itself (Blowfish and RC4 cycle it) rather than being handed a padded one.
function nullPaddingApplies(info, keyLen) {
  return !!info.rawKey && keyLen < keySizeFor(info, keyLen);
}

// Key bytes to hand the cipher: the raw ASCII key, or that key right-padded with
// NUL bytes up to the cipher's key size.
function buildKeyBytes(keyStr, info, nullPad) {
  var raw = asciiToBytes(keyStr);
  if (!nullPad) return raw;
  var size = keySizeFor(info, raw.length);
  if (raw.length >= size) return raw;
  var padded = new Uint8Array(size);
  padded.set(raw);
  return padded;
}

function hexToBytes(hex) {
  hex = hex.replace(/\s+/g, '');
  if (hex.length % 2 !== 0) throw new Error('Invalid hex string');
  var bytes = new Uint8Array(hex.length / 2);
  for (var i = 0; i < bytes.length; i++) {
    var hi = parseInt(hex[i * 2], 16);
    var lo = parseInt(hex[i * 2 + 1], 16);
    if (isNaN(hi) || isNaN(lo)) throw new Error('Invalid hex character');
    bytes[i] = (hi << 4) | lo;
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
}

function base64ToBytes(b64) {
  var bin = atob(b64);
  var bytes = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

/* ========================================================
 * Plain XXTEA (btea), no embedded length header — the framing xxtea.c cannot
 * read. Operates on 32-bit little-endian words, so data is zero-padded to a
 * 4-byte boundary (minimum two words), matching the wrapper's zero padding.
 * ======================================================== */

var XXTEA_DELTA = 0x9e3779b9;

function xxteaToWords(bytes) {
  var n = Math.max(2, Math.ceil(bytes.length / 4));
  var words = new Uint32Array(n);
  for (var i = 0; i < bytes.length; i++) words[i >> 2] |= bytes[i] << ((i & 3) << 3);
  return words;
}

function xxteaToBytes(words) {
  var bytes = new Uint8Array(words.length * 4);
  for (var i = 0; i < bytes.length; i++) bytes[i] = (words[i >> 2] >>> ((i & 3) << 3)) & 0xff;
  return bytes;
}

function xxteaMx(sum, y, z, p, e, key) {
  return ((((z >>> 5) ^ (y << 2)) + ((y >>> 3) ^ (z << 4))) ^
          (((sum ^ y) >>> 0) + ((key[(p & 3) ^ e] ^ z) >>> 0))) >>> 0;
}

function xxteaRawEncrypt(words, key) {
  var n = words.length, rounds = 6 + Math.floor(52 / n);
  var sum = 0, y, z = words[n - 1], e, p;
  while (rounds-- > 0) {
    sum = (sum + XXTEA_DELTA) >>> 0;
    e = (sum >>> 2) & 3;
    for (p = 0; p < n - 1; p++) {
      y = words[p + 1];
      z = words[p] = (words[p] + xxteaMx(sum, y, z, p, e, key)) >>> 0;
    }
    y = words[0];
    z = words[n - 1] = (words[n - 1] + xxteaMx(sum, y, z, n - 1, e, key)) >>> 0;
  }
  return words;
}

function xxteaRawDecrypt(words, key) {
  var n = words.length, rounds = 6 + Math.floor(52 / n);
  var sum = (rounds * XXTEA_DELTA) >>> 0, y = words[0], z, e, p;
  while (rounds-- > 0) {
    e = (sum >>> 2) & 3;
    for (p = n - 1; p > 0; p--) {
      z = words[p - 1];
      y = words[p] = (words[p] - xxteaMx(sum, y, z, p, e, key)) >>> 0;
    }
    z = words[n - 1];
    y = words[0] = (words[0] - xxteaMx(sum, y, z, 0, e, key)) >>> 0;
    sum = (sum - XXTEA_DELTA) >>> 0;
  }
  return words;
}

// XXTEA always takes a 16-byte key, NUL-padded and truncated like xxtea.c does.
function xxteaKeyWords(keyStr) {
  var key = new Uint8Array(16);
  key.set(asciiToBytes(keyStr).subarray(0, 16));
  return xxteaToWords(key);
}

function bytesToBase64(bytes) {
  var bin = '';
  for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

// Decrypt a single cipher with given parameters. Returns plaintext string or null on failure.
function decryptOne(cipherName, keyStr, ivStr, inputStr, encoding, modeStr, nullPadKey) {
  var info = CIPHER_INFO[cipherName];
  if (!info) return null;

  try {
    var keyBytes = buildKeyBytes(keyStr, info, nullPadKey);
    mcrypt.HEAPU8.set(keyBytes, keyPtr);

    var inputBytes = encoding === 'base64' ? base64ToBytes(inputStr) : hexToBytes(inputStr);

    if (info.jsXxtea) {
      if (inputBytes.length < 8) return null;
      var plain = xxteaToBytes(xxteaRawDecrypt(xxteaToWords(inputBytes), xxteaKeyWords(keyStr)));
      var end = plain.length;
      while (end > 0 && plain[end - 1] === 0) end--; // mirror the wrapper's zero_unpad
      return bytesToText(plain.subarray(0, end));
    }

    if (info.stream) {
      mcrypt.HEAPU8.set(inputBytes, bufPtr);
      mcrypt['_' + info.fn](keyBytes.length, inputBytes.length, 0);
      var result = new Uint8Array(mcrypt.HEAPU8.buffer, bufPtr, inputBytes.length);
      return bytesToText(result);
    }

    if (info.xxtea) {
      mcrypt.HEAPU8.set(inputBytes, bufPtr);
      var outLen = mcrypt['_' + info.fn](keyBytes.length, inputBytes.length, 0);
      if (outLen < 0) return null;
      var result = new Uint8Array(mcrypt.HEAPU8.buffer, bufPtr, outLen);
      return bytesToText(result);
    }

    // Block cipher — set up IV
    var modeInt = getModeInt(modeStr || 'cfb8');
    var ivBytes;
    if (modeInt === MODE_MAP.ecb) {
      // ECB doesn't use IV, but we still need to pass ivlen
      ivBytes = new Uint8Array(info.blockSize);
    } else {
      if (!ivStr) ivStr = '';
      var rawIv = ivStr.replace(/\s+/g, '');
      ivBytes = rawIv ? hexToBytes(rawIv) : new Uint8Array(info.blockSize);
      if (ivBytes.length < info.blockSize) {
        var padded = new Uint8Array(info.blockSize);
        padded.set(ivBytes);
        ivBytes = padded;
      } else if (ivBytes.length > info.blockSize) {
        ivBytes = ivBytes.slice(0, info.blockSize);
      }
    }
    mcrypt.HEAPU8.set(ivBytes, ivPtr);

    mcrypt.HEAPU8.set(inputBytes, bufPtr);
    var outLen = mcrypt['_' + info.fn](keyBytes.length, ivBytes.length, inputBytes.length, 0, modeInt);
    if (outLen < 0) return null;
    var result = new Uint8Array(mcrypt.HEAPU8.buffer, bufPtr, outLen);
    return bytesToText(result);
  } catch (e) {
    return null;
  }
}

/* ========================================================
 * Result scoring — how closely a candidate plaintext fits a chosen encoded
 * format or natural language, as a percentage, used to sort brute-force results.
 * ======================================================== */

// Encoded formats: the share of non-whitespace characters legal in the format, so
// digits split across lines or spaced into groups still score as a clean match.
var FORMAT_ALPHABETS = {
  decimal: /[0-9]/,
  octal:   /[0-7]/,
  hex:     /[0-9A-Fa-f]/,
  base64:  /[A-Za-z0-9+/=]/
};

function formatScore(text, alphabet) {
  var counted = 0, hits = 0;
  for (var i = 0; i < text.length; i++) {
    var ch = text.charAt(i);
    if (/\s/.test(ch)) continue;
    counted++;
    if (alphabet.test(ch)) hits++;
  }
  return counted === 0 ? 0 : 100 * hits / counted;
}

// Relative letter frequencies (%), a-z. Accented letters fold onto their base letter
// before counting, so "resume" and "resume" with acutes score the same.
var LETTER_FREQ = {
  english: [8.17,1.49,2.78,4.25,12.70,2.23,2.02,6.09,6.97,0.15,0.77,4.03,2.41,
            6.75,7.51,1.93,0.10,5.99,6.33,9.06,2.76,0.98,2.36,0.15,1.97,0.07],
  german:  [6.51,1.89,3.06,5.08,17.40,1.66,3.01,4.76,7.55,0.27,1.21,3.44,2.53,
            9.78,2.51,0.79,0.02,7.00,7.27,6.15,4.35,0.67,1.89,0.03,0.04,1.13],
  french:  [7.64,0.90,3.26,3.67,14.72,1.07,0.87,0.74,7.53,0.55,0.05,5.46,2.97,
            7.10,5.80,2.52,1.36,6.55,7.95,7.24,6.31,1.84,0.04,0.43,0.13,0.33]
};

var STOPWORDS = {
  english: ('the of and to in is it you that was for on are with as be at this have from or '
    + 'one had by but not what all were we when your can said there use an each which she do '
    + 'how their if will up other about out many then them these so some her would make like '
    + 'him into time has two more no way could my than been who its now find long down did get').split(' '),
  german: ('der die das und in den von zu mit sich des auf fur ist im dem nicht ein eine als '
    + 'auch es an werden aus er hat dass sie nach wird bei einer um am sind noch wie einem '
    + 'uber einen so zum war haben nur oder aber vor zur bis mehr durch man sein wurde ich '
    + 'du wir ihr wenn schon kann diese alle').split(' '),
  french: ('le la les de des du un une et est en que qui dans pour pas sur au aux ce il elle '
    + 'nous vous ils avec ne se plus par mais comme tout son sa ses on je tu ont ete etre '
    + 'avoir fait faire si ou mon ma mes cette leur bien tres sont ainsi cet').split(' ')
};

// Letters that effectively only occur in one of these languages.
var LANG_ACCENTS = { english: '', german: 'äöüß',
                     french: 'éèêàçùîôûïœ' };

var ACCENT_FOLD = {
  'à':'a','á':'a','â':'a','ã':'a','ä':'a','å':'a','æ':'ae',
  'ç':'c','è':'e','é':'e','ê':'e','ë':'e','ì':'i','í':'i',
  'î':'i','ï':'i','ñ':'n','ò':'o','ó':'o','ô':'o','õ':'o',
  'ö':'o','ø':'o','ù':'u','ú':'u','û':'u','ü':'u','ý':'y',
  'ÿ':'y','ß':'ss','œ':'oe'
};

function foldAccents(lower) {
  var out = '';
  for (var i = 0; i < lower.length; i++) {
    var ch = lower.charAt(i);
    out += ACCENT_FOLD[ch] !== undefined ? ACCENT_FOLD[ch] : ch;
  }
  return out;
}

function cosineSimilarity(a, b) {
  var dot = 0, na = 0, nb = 0;
  for (var i = 0; i < a.length; i++) { dot += a[i] * b[i]; na += a[i] * a[i]; nb += b[i] * b[i]; }
  return (na === 0 || nb === 0) ? 0 : dot / (Math.sqrt(na) * Math.sqrt(nb));
}

/*
 * A language score blends three signals, because no one of them is enough: letter
 * frequency separates text from noise but barely separates English from German,
 * stopwords separate the languages, and the printable share stops a run of bytes
 * that happens to have plausible letter ratios from scoring like prose.
 */
function languageScore(text, lang) {
  var lower = foldAccents(text.toLowerCase());

  var printable = 0;
  for (var i = 0; i < text.length; i++) {
    var c = text.charCodeAt(i);
    if ((c >= 0x20 && c <= 0x7e) || c === 0x09 || c === 0x0a || c === 0x0d ||
        LANG_ACCENTS[lang].indexOf(text.charAt(i).toLowerCase()) >= 0) printable++;
  }
  var printShare = text.length === 0 ? 0 : printable / text.length;

  var counts = [], total = 0;
  for (i = 0; i < 26; i++) counts.push(0);
  for (i = 0; i < lower.length; i++) {
    var code = lower.charCodeAt(i);
    if (code >= 97 && code <= 122) { counts[code - 97]++; total++; }
  }
  if (total < 12) return 0;

  var freqFit = Math.max(0, (cosineSimilarity(counts, LETTER_FREQ[lang]) - 0.55) / 0.45);

  var words = lower.replace(/[^a-z]+/g, ' ').split(' ');
  var tokens = 0, stops = 0;
  for (i = 0; i < words.length; i++) {
    if (!words[i]) continue;
    tokens++;
    if (STOPWORDS[lang].indexOf(words[i]) >= 0) stops++;
  }
  var wordFit = tokens === 0 ? 0 : Math.min(1, (stops / tokens) / 0.3);

  // A letter unique to this language is strong evidence; one unique to another is not.
  var bonus = 0;
  for (var other in LANG_ACCENTS) {
    if (!LANG_ACCENTS[other]) continue;
    var seen = 0;
    for (i = 0; i < text.length; i++) {
      if (LANG_ACCENTS[other].indexOf(text.charAt(i).toLowerCase()) >= 0) seen++;
    }
    if (seen) bonus += (other === lang ? 0.08 : -0.05);
  }

  // printShare gates rather than adds: a wall of one repeated letter is perfectly
  // printable but not language, and an additive term would floor it at 30%.
  var score = printShare * (0.40 * freqFit + 0.60 * wordFit) + bonus;
  return Math.max(0, Math.min(100, 100 * score));
}

var PATTERN_LABELS = {
  alnum: 'alphanumeric', prose: 'English prose', alpha: 'alphabetic',
  numeric: 'numeric', base64: 'base64', custom: 'custom regex'
};

var SORT_LABELS = {
  english: 'English', german: 'German', french: 'French',
  decimal: 'decimal', octal: 'octal', hex: 'hex', base64: 'base64'
};

function scoreText(text, metric) {
  if (FORMAT_ALPHABETS[metric]) return formatScore(text, FORMAT_ALPHABETS[metric]);
  if (LETTER_FREQ[metric]) return languageScore(text, metric);
  return 0;
}

// Reverse encoded input (reverses the underlying bytes, then re-encodes)
function reverseEncodedInput(inputStr, encoding) {
  if (encoding === 'base64') {
    var bytes = base64ToBytes(inputStr);
    var reversed = new Uint8Array(bytes.length);
    for (var i = 0; i < bytes.length; i++) reversed[i] = bytes[bytes.length - 1 - i];
    return bytesToBase64(reversed);
  } else {
    var hex = inputStr.replace(/\s+/g, '');
    var pairs = [];
    for (var i = 0; i < hex.length; i += 2) pairs.push(hex.substr(i, 2));
    return pairs.reverse().join('');
  }
}

function runTryAll() {
  clearError();
  while (tryAllResultsList.firstChild) tryAllResultsList.removeChild(tryAllResultsList.firstChild);
  tryAllResults.hidden = false;
  outputArea.value = '';

  if (!mcrypt) { showError('WASM module not yet loaded'); return; }

  var encoding = getEncoding();
  var keyStr   = keyInput.value;
  var ivStr    = ivInput.value;
  var inputStr = inputArea.value.trim();

  if (!keyStr) { showError('Key is required'); return; }
  if (!inputStr) { showError('Input is required'); return; }

  var matcher;
  try { matcher = getMatcher(); } catch (e) { showError(e.message); return; }

  var doReverseInput = reverseInputCb.checked;
  var doReverseKey   = reverseKeyCb.checked;
  var doCaseVariants = caseVariantsCb.checked;
  var doTryAllModes  = tryAllModesCb.checked;
  var doNullPadKey   = nullPadKeyCb.checked;
  var sortBy         = sortBySelect.value;

  // Build input variants
  var inputVariants = [{ value: inputStr, label: 'forward' }];
  if (doReverseInput) {
    try {
      inputVariants.push({ value: reverseEncodedInput(inputStr, encoding), label: 'reversed' });
    } catch (e) { /* skip if reversing fails */ }
  }

  // Build key variants: casing first, then optionally reverse each
  var baseKeys = [{ value: keyStr, label: 'as-is' }];
  if (doCaseVariants) {
    var upper = keyStr.toUpperCase();
    var lower = keyStr.toLowerCase();
    if (upper !== keyStr) baseKeys.push({ value: upper, label: 'UPPER' });
    if (lower !== keyStr && lower !== upper) baseKeys.push({ value: lower, label: 'lower' });
  }

  var keyForms = [];
  for (var k = 0; k < baseKeys.length; k++) {
    keyForms.push({ value: baseKeys[k].value, label: 'key ' + baseKeys[k].label });
    if (doReverseKey) {
      var rev = baseKeys[k].value.split('').reverse().join('');
      if (rev !== baseKeys[k].value) {
        keyForms.push({ value: rev, label: 'key ' + baseKeys[k].label + ' reversed' });
      }
    }
  }

  // Each key form is tried as-is and, optionally, right-padded with NUL bytes to
  // the cipher's key size instead of letting the cipher stretch the short key.
  var keyVariants = [];
  for (var f = 0; f < keyForms.length; f++) {
    keyVariants.push({ value: keyForms[f].value, label: keyForms[f].label, nullPad: false });
    if (doNullPadKey) {
      keyVariants.push({ value: keyForms[f].value, label: keyForms[f].label + ' null-padded', nullPad: true });
    }
  }

  // Build mode variants for block ciphers
  var modeVariants = doTryAllModes ? ALL_MODES : [getMode()];

  var matches = [];
  var attempts = 0, decoded = 0;
  var cipherNames = Object.keys(CIPHER_INFO);

  for (var ci = 0; ci < cipherNames.length; ci++) {
    var cipherName = cipherNames[ci];
    var info = CIPHER_INFO[cipherName];

    // For stream ciphers and XXTEA, modes don't apply
    var modes = (info.stream || info.xxtea) ? [null] : modeVariants;

    for (var mi = 0; mi < modes.length; mi++) {
      for (var iv = 0; iv < inputVariants.length; iv++) {
        for (var kv = 0; kv < keyVariants.length; kv++) {
          var keyVariant = keyVariants[kv];
          // Skip null-padding where it would just repeat the unpadded run: the WASM
          // wrapper already null-pads keys for every cipher but the rawKey ones.
          if (keyVariant.nullPad && !nullPaddingApplies(info, keyVariant.value.length)) continue;
          attempts++;
          var plaintext = decryptOne(cipherName, keyVariant.value, ivStr, inputVariants[iv].value, encoding, modes[mi], keyVariant.nullPad);
          if (!plaintext) continue;
          decoded++;
          var trimmed = plaintext.replace(/[\r\n\x00]+$/g, '');
          if (trimmed && matcher.test(trimmed)) {
            matches.push({
              cipher: cipherName,
              mode: modes[mi],
              inputLabel: inputVariants[iv].label,
              keyLabel: keyVariant.label,
              keyValue: keyVariant.value,
              keyPadTo: keyVariant.nullPad ? keySizeFor(info, keyVariant.value.length) : 0,
              inputValue: inputVariants[iv].value,
              output: plaintext,
              score: sortBy === 'none' ? null : scoreText(trimmed, sortBy)
            });
          }
        }
      }
    }
  }

  if (sortBy !== 'none') {
    matches.sort(function (a, b) { return b.score - a.score; });
  }

  var countText = '(' + matches.length + ' match' + (matches.length !== 1 ? 'es' : '');
  if (sortBy !== 'none' && matches.length) countText += ', best ' + SORT_LABELS[sortBy] + ' first';
  tryAllCount.textContent = countText + ')';

  if (matches.length === 0) {
    var patternLabel = PATTERN_LABELS[getPatternPreset()] || 'selected';
    var empty = document.createElement('div');
    empty.className = 'no-results';

    var emptyTitle = document.createElement('div');
    emptyTitle.className = 'no-results-title';
    emptyTitle.textContent = 'No results';

    var emptyDetail = document.createElement('div');
    emptyDetail.className = 'no-results-detail';
    emptyDetail.textContent = 'Tried ' + attempts + ' decryption' + (attempts !== 1 ? 's' : '') +
      ' across ' + cipherNames.length + ' ciphers. ' + decoded + ' produced output; none matched the ' +
      patternLabel + ' pattern.';

    var emptyHint = document.createElement('div');
    emptyHint.className = 'no-results-detail';
    emptyHint.textContent = decoded === 0
      ? 'Every cipher rejected this input — check the input encoding and that the data length suits the cipher.'
      : 'Try a looser output pattern, or turn on more key, input and mode variations above.';

    empty.appendChild(emptyTitle);
    empty.appendChild(emptyDetail);
    empty.appendChild(emptyHint);
    tryAllResultsList.appendChild(empty);
    return;
  }

  for (var m = 0; m < matches.length; m++) {
    var card = document.createElement('div');
    card.className = 'result-card';

    var header = document.createElement('div');
    header.className = 'result-card-header';
    var headerText = matches[m].cipher;
    if (matches[m].mode) headerText += ' [' + MODE_LABELS[matches[m].mode] + ']';
    header.textContent = headerText;

    if (matches[m].score !== null) {
      var scoreEl = document.createElement('span');
      scoreEl.className = 'result-card-score';
      scoreEl.textContent = Math.round(matches[m].score) + '% ' + SORT_LABELS[sortBy];
      header.appendChild(scoreEl);
    }

    var detail = document.createElement('div');
    detail.className = 'result-card-detail';
    detail.textContent = 'input: ' + matches[m].inputLabel + ' / ' + matches[m].keyLabel;

    var keyRow = document.createElement('div');
    keyRow.className = 'result-card-field';
    var keyLbl = document.createElement('span');
    keyLbl.className = 'result-card-field-label';
    keyLbl.textContent = 'Key: ';
    var keyVal = document.createElement('span');
    keyVal.className = 'result-card-field-value';
    keyVal.textContent = matches[m].keyPadTo
      ? matches[m].keyValue + ' + NUL \u00d7 ' + (matches[m].keyPadTo - matches[m].keyValue.length) +
        ' (' + matches[m].keyPadTo + ' bytes)'
      : matches[m].keyValue;
    keyRow.appendChild(keyLbl);
    keyRow.appendChild(keyVal);

    var ctRow = document.createElement('div');
    ctRow.className = 'result-card-field';
    var ctLbl = document.createElement('span');
    ctLbl.className = 'result-card-field-label';
    ctLbl.textContent = 'Ciphertext: ';
    var ctVal = document.createElement('span');
    ctVal.className = 'result-card-field-value';
    ctVal.textContent = matches[m].inputValue;
    ctRow.appendChild(ctLbl);
    ctRow.appendChild(ctVal);

    var outputLabel = document.createElement('div');
    outputLabel.className = 'result-card-field-label';
    outputLabel.style.marginTop = '0.25rem';
    outputLabel.textContent = 'Output:';

    var output = document.createElement('div');
    output.className = 'result-card-output';
    output.textContent = matches[m].output;

    card.appendChild(header);
    card.appendChild(detail);
    card.appendChild(keyRow);
    card.appendChild(ctRow);
    card.appendChild(outputLabel);
    card.appendChild(output);
    tryAllResultsList.appendChild(card);
  }
}

runBtn.addEventListener('click', function() {
  clearError();
  tryAllResults.hidden = true;

  if (tryAllCheckbox.checked && getOperation() === 'decrypt') {
    runTryAll();
    return;
  }

  outputArea.value = '';

  try {
    if (!mcrypt) throw new Error('WASM module not yet loaded');

    var cipherName = cipherSelect.value;
    var op         = getOperation();
    var encoding   = getEncoding();
    var keyStr     = keyInput.value;
    var ivStr      = ivInput.value;
    var inputStr   = inputArea.value.trim();
    var info       = CIPHER_INFO[cipherName];

    if (!keyStr) throw new Error('Key is required');
    if (!inputStr) throw new Error('Input is required');

    // For single decrypt, reuse decryptOne
    if (op === 'decrypt') {
      var modeStr = (info.stream || info.xxtea) ? null : getMode();
      var plaintext = decryptOne(cipherName, keyStr, ivStr, inputStr, encoding, modeStr, padKeyCb.checked);
      if (plaintext === null) throw new Error('Decryption failed');
      outputArea.value = plaintext;
      return;
    }

    // Encrypt path
    var keyBytes = buildKeyBytes(keyStr, info, padKeyCb.checked);
    mcrypt.HEAPU8.set(keyBytes, keyPtr);

    if (info.jsXxtea) {
      var result = xxteaToBytes(xxteaRawEncrypt(xxteaToWords(textToBytes(inputStr)), xxteaKeyWords(keyStr)));
      outputArea.value = encoding === 'base64' ? bytesToBase64(result) : bytesToHex(result);
      return;
    }

    if (info.stream) {
      var inputBytes = textToBytes(inputStr);
      mcrypt.HEAPU8.set(inputBytes, bufPtr);
      mcrypt['_' + info.fn](keyBytes.length, inputBytes.length, 1);
      var result = new Uint8Array(mcrypt.HEAPU8.buffer, bufPtr, inputBytes.length);
      outputArea.value = encoding === 'base64' ? bytesToBase64(result) : bytesToHex(result);
      return;
    }

    if (info.xxtea) {
      var inputBytes = textToBytes(inputStr);
      mcrypt.HEAPU8.set(inputBytes, bufPtr);
      var outLen = mcrypt['_' + info.fn](keyBytes.length, inputBytes.length, 1);
      if (outLen < 0) throw new Error('XXTEA processing failed');
      var result = new Uint8Array(mcrypt.HEAPU8.buffer, bufPtr, outLen);
      outputArea.value = encoding === 'base64' ? bytesToBase64(result) : bytesToHex(result);
      return;
    }

    // Block cipher encrypt
    var modeStr = getMode();
    var modeInt = getModeInt(modeStr);

    var ivBytes;
    if (modeInt === MODE_MAP.ecb) {
      ivBytes = new Uint8Array(info.blockSize);
    } else {
      if (!ivStr) throw new Error('IV is required for ' + cipherName + ' in ' + MODE_LABELS[modeStr] + ' mode');
      ivBytes = hexToBytes(ivStr.replace(/\s+/g, ''));
      if (ivBytes.length < info.blockSize) {
        var padded = new Uint8Array(info.blockSize);
        padded.set(ivBytes);
        ivBytes = padded;
      } else if (ivBytes.length > info.blockSize) {
        ivBytes = ivBytes.slice(0, info.blockSize);
      }
    }
    mcrypt.HEAPU8.set(ivBytes, ivPtr);

    var inputBytes = textToBytes(inputStr);
    mcrypt.HEAPU8.set(inputBytes, bufPtr);
    var outLen = mcrypt['_' + info.fn](keyBytes.length, ivBytes.length, inputBytes.length, 1, modeInt);
    if (outLen < 0) throw new Error('Encryption failed');
    var result = new Uint8Array(mcrypt.HEAPU8.buffer, bufPtr, outLen);
    outputArea.value = encoding === 'base64' ? bytesToBase64(result) : bytesToHex(result);

  } catch (e) {
    showError(e.message || 'An error occurred');
  }
});

reverseBtn.addEventListener('click', function() {
  var text = outputArea.value;
  if (text) {
    outputArea.value = text.split('').reverse().join('');
  }
});
