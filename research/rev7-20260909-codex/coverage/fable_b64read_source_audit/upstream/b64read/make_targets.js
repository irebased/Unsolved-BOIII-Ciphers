'use strict';
/* make_targets.js -- real readings, negative control, positive control. */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const lib = require('../dictkey2/lib.js');
const cl = require('../cascade/cascade_lib.js');

const HEX = '0123456789ABCDEF';
const raw = fs.readFileSync(path.join(__dirname, '..', 'rev7_hex.txt'), 'utf8').trim();

function readings(s) {
  const o = cl.orientations(s);
  o.lowercased = s.toLowerCase();
  return o;
}

const PLAIN = ('THE GIANT AWOKE BENEATH THE ICE AND THE ELEMENT ONE ONE FIVE SANG IN THE HOLLOW OF THE WORLD. '
  + 'RICHTOFEN WROTE THAT THE AETHER REMEMBERS EVERY CHOICE WE NEVER MADE AND THAT THE CYCLE MUST BE BROKEN '
  + 'BEFORE THE KEEPERS RETURN TO CLAIM WHAT THE APOTHICONS LEFT BEHIND IN THE SUMMONING KEY. '
  + 'MAXIS SPOKE OF A HOUSE WHERE THE CHILDREN WAIT AND OF A CORRUPTED FRACTURE IN TIME ITSELF. '
  + 'THE BLOOD OF THE ANCIENTS OPENS THE GATEWAY AND THE SHADOWS OF EVIL GATHER AT THE RIFT. '
  + 'WE ARE THE SHADOW MEN AND WE HAVE ALWAYS BEEN HERE WAITING FOR THE STORY TO BEGIN AGAIN. '
  + 'ORIGINS REVELATIONS AND THE END OF ALL THINGS COME TO PASS WHEN THE MOON IS BROKEN OPEN. ').repeat(2).slice(0, 819);

(async () => {
  const ctx = await lib.loadMcrypt();
  const targets = [];
  const R = readings(raw);
  for (const k of Object.keys(R)) targets.push({ label: 'REAL', reading: k, b64string: R[k] });

  // NEGATIVE: random 1092 chars over 0-9A-F
  const rb = crypto.randomBytes(1092);
  let neg = ''; for (let i = 0; i < 1092; i++) neg += HEX[rb[i] & 15];
  targets.push({ label: 'NEG', reading: 'random_hexalpha', b64string: neg });

  // POSITIVE: English -> encrypt -> base64 of ciphertext (full b64 alphabet)
  const PLANT_CIPHER = 'twofish', PLANT_MODE = lib.MODE_CFB8, PLANT_KEY = 'Zombies';
  const info = lib.CIPHER_INFO[PLANT_CIPHER];
  const pt = Buffer.from(PLAIN, 'ascii');
  if (pt.length !== 819) throw new Error('plaintext len ' + pt.length);
  const ct = Buffer.from(lib.encryptOnce(ctx, PLANT_CIPHER, cl.keyBytesForCipher(PLANT_CIPHER, PLANT_KEY),
    cl.ivFor(info.blockSize), pt, PLANT_MODE));
  const b64 = ct.toString('base64').replace(/=+$/, '');
  if (b64.length !== 1092) throw new Error('b64 len ' + b64.length);
  targets.push({ label: 'POS', reading: 'plant_twofish_cfb8_Zombies', b64string: b64 });
  fs.writeFileSync(path.join(__dirname, 'plant_plaintext.txt'), PLAIN);
  fs.writeFileSync(path.join(__dirname, 'plant_b64.txt'), b64);

  // how far is the plant's base64 from the 0-9A-F alphabet?
  let inHex = 0; for (const c of b64) if (HEX.includes(c)) inHex++;
  const restrictedNote = { plantB64Len: b64.length, charsInHexAlphabet: inHex,
    fracInHexAlphabet: inHex / b64.length,
    probAllInHexAlphabet: '(1/4)^1092 = 10^' + (1092 * Math.log10(0.25)).toFixed(1) };
  fs.writeFileSync(path.join(__dirname, 'plant_note.json'), JSON.stringify(restrictedNote, null, 1));
  console.log(JSON.stringify(restrictedNote));

  fs.writeFileSync(path.join(__dirname, 'targets.json'), JSON.stringify(targets, null, 1));
  console.log('targets', targets.map((t) => t.label + ':' + t.reading + ':' + t.b64string.length).join(' '));
})();
