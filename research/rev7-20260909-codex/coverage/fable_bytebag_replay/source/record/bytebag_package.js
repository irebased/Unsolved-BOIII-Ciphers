'use strict';
// Produce a replayable package of the 184 direct-decryption rows with the
// provenance ASTRA asked for: per-context outside-byte count, output hash,
// exact key bytes, backend, mode, block size, evaluated suffix length.
const L = require('../cascade/cascade_lib.js');
const fs=require('fs'), crypto=require('crypto');
const EXTRA=[0x2013,0x2014,0x2018,0x2019,0x201C,0x201D,0x2026];
const bag=new Set();
for (const cp of [0x09,0x0a,0x0d]) bag.add(cp);
for (let cp=0x20;cp<=0x7e;cp++) bag.add(cp);
for (let cp=0x00a0;cp<=0x00ff;cp++) for (const b of Buffer.from(String.fromCodePoint(cp),'utf8')) bag.add(b);
for (const cp of EXTRA) for (const b of Buffer.from(String.fromCodePoint(cp),'utf8')) bag.add(b);
(async()=>{
  const ctx=await L.loadMcrypt();
  const hex=fs.readFileSync('../rev7_hex.txt','utf8').trim();
  const or=L.orientations(hex);
  const rows=[];
  for (const [orientation,ohex] of Object.entries(or)){
    const input=Buffer.from(ohex,'hex');
    for (const cipher of L.ALL_CIPHERS) for (const keyStr of L.KEYS){
      const info=L.CIPHER_INFO[cipher];
      const isStream=!!info.stream;
      const blockSize=info.blockSize||0;
      const keyBytes=L.keyBytesForCipher(cipher,keyStr);
      let out; try{ out=L.decryptWith(ctx,cipher,keyStr,input);}catch(e){ continue; }
      const skip=blockSize||8;
      let outside=0; for(let i=skip;i<out.length;i++) if(!bag.has(out[i])) outside++;
      rows.push({
        orientation, cipher,
        // CORRECTION (found by ASTRA): decryptOnce branches on info.stream and calls the
        // dedicated stream export with NO mode and NO IV. Those rows are not CFB8.
        mode: isStream ? 'stream' : 'cfb8',
        isStreamCipher: isStream,
        inheritsCfb8DamageBound: !isStream,
        keyString:keyStr,
        keyBytesHex:Buffer.from(keyBytes).toString('hex'), keyByteLength:keyBytes.length,
        blockSize,
        ivConvention: isStream ? 'none - stream ciphers take no IV in this wrapper'
                               : "ASCII '0' (0x30) repeated to block size",
        skippedPrefixMeaning: isStream ? 'CHOSEN TRUNCATION of 8 bytes, not an IV-dependent block'
                                       : 'IV-dependent first block, discarded',
        inputSha256: crypto.createHash('sha256').update(input).digest('hex'),
        outputSha256: crypto.createHash('sha256').update(out).digest('hex'),
        outputLength: out.length, skippedPrefixBytes: skip,
        evaluatedSuffixLength: out.length-skip,
        bytesOutsideBag: outside
      });
    }
  }
  const pkg={
    producedBy:'FABLE', test:'ASTRA byte-bag necessary condition (permutation-invariant)',
    bagSize:bag.size, bagBytesHex:[...bag].sort((a,b)=>a-b).map(b=>b.toString(16).padStart(2,'0')).join(''),
    bagComposition:'98 ASCII/whitespace + 64 continuation bytes 0x80-0xBF + leads C2, C3, E2',
    necessaryCondition:'an UNDAMAGED transposed message requires bytesOutsideBag == 0; any positive count is a deterministic contradiction',
    damageBoundScope:'ASTRA damage theorem (<= b+1 outside bytes for a single substitution/insertion, <= b for deletion) applies ONLY to the CFB8 rows. The stream-cipher rows reject the UNDAMAGED endpoint only and inherit NO damage bound.',
    ciphertextSha256: crypto.createHash('sha256').update(hex).digest('hex'),
    ciphertextLengthHexSymbols: hex.length,
    rowCount: rows.length,
    minBytesOutsideBag: Math.min(...rows.map(r=>r.bytesOutsideBag)),
    rows
  };
  fs.writeFileSync('bytebag_184rows.json', JSON.stringify(pkg,null,1));
  console.log('rows=%d  bag=%d  min outside=%d', rows.length, bag.size, pkg.minBytesOutsideBag);
  console.log('sha256(bytebag_184rows.json)=%s',
    crypto.createHash('sha256').update(fs.readFileSync('bytebag_184rows.json')).digest('hex'));
})();
