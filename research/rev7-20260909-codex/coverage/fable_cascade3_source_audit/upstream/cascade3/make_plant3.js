'use strict';
/* make_plant3.js -- positive control for cascade3: a depth-3 decrypt->decrypt
 * chain WITH a codepoint-aware reverse at one INTERIOR boundary (b1, between
 * layer1 and layer2), exercising exactly the reverse machinery cascade3 adds
 * over ../cascade's no-reverse depth-3 sweep. Reuses ../cascade/cascade_lib.js
 * verbatim (encryptWith, reverseBuf) -- not copied/rewritten.
 */
const fs = require('fs');
const path = require('path');
const C = require('../cascade/cascade_lib.js');

const PARAGRAPH = "Every winter the harbor master counted the boats twice, once at dawn and " +
  "once before the tide turned mean. He kept no ledger anyone else could read, only a private " +
  "code of knots and chalk marks on the piling. Zombies did not frighten him half as much as an " +
  "empty slip where a boat should have been, and he never once wrote down why.";

async function main() {
  const ctx = await C.loadMcrypt();
  const pt = Buffer.from(PARAGRAPH, 'utf8');

  // Decrypt chain we want the sweep to recover:
  //   ct -[decrypt:serpent:Zombies]-> mid1 -[reverse@b1]-> mid1r
  //      -[decrypt:blowfish:Zombies]-> mid2 -[decrypt:twofish:Zombies]-> pt
  // So forward construction (encrypt) is the exact inverse, built back to front:
  const step3 = C.encryptWith(ctx, 'twofish', 'Zombies', pt);        // inverse of layer3 decrypt
  const step2 = C.encryptWith(ctx, 'blowfish', 'Zombies', step3);    // inverse of layer2 decrypt
  const reversedMid = C.reverseBuf(step2);                            // inverse of b1 reverse (involution)
  const ct = C.encryptWith(ctx, 'serpent', 'Zombies', reversedMid);  // inverse of layer1 decrypt

  const hex = ct.toString('hex').toUpperCase();
  fs.writeFileSync(path.join(__dirname, 'plant3_hex.txt'), hex);
  fs.writeFileSync(path.join(__dirname, 'plant3_plaintext.txt'), PARAGRAPH);

  const trueChain = ['decrypt:serpent:Zombies', 'reverse', 'decrypt:blowfish:Zombies', 'decrypt:twofish:Zombies'];
  console.log(JSON.stringify({
    plaintextLen: pt.length,
    ctLen: ct.length,
    hexLen: hex.length,
    encryptOrder: ['twofish:Zombies', 'blowfish:Zombies', 'reverse', 'serpent:Zombies'],
    trueDecryptChain: trueChain,
    bmask: 'b1 only (bit1=2)',
  }, null, 2));
}
main().catch((e) => { console.error(e); process.exit(1); });
