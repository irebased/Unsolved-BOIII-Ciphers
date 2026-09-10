'use strict';
const fs = require('fs'), path = require('path'), crypto = require('crypto'), assert = require('assert');
const here = __dirname, hash = b => crypto.createHash('sha256').update(b).digest('hex');
const manifest = JSON.parse(fs.readFileSync(path.join(here, 'manifest.json')));
for (const f of manifest.files) { const b=fs.readFileSync(path.join(here,f.local_path)); assert.equal(b.length,f.bytes); assert.equal(hash(b),f.sha256); }
const original = JSON.parse(fs.readFileSync(path.join(here,'source/record/bytebag_184rows.json')));
const text = fs.readFileSync(path.join(here,'source/record/rev7_hex.txt'),'utf8').trim();
assert.equal(hash(text.toUpperCase()),'5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c');
assert.equal(hash(text),original.ciphertextSha256);
const pairs = text.match(/../g);
const inputs = {displayed:text,fullReversed:[...text].reverse().join(''),bytePairReversed:[...pairs].reverse().join(''),nibbleSwap:pairs.map(p=>p[1]+p[0]).join('')};
const points=[9,10,13,...Array.from({length:95},(_,i)=>32+i),...Array.from({length:96},(_,i)=>160+i),0x2013,0x2014,0x2018,0x2019,0x201c,0x201d,0x2026];
const bag=new Set(points.flatMap(cp=>[...Buffer.from(String.fromCodePoint(cp),'utf8')]));
assert.equal(bag.size,165); assert.equal([...bag].sort((a,b)=>a-b).map(b=>b.toString(16).padStart(2,'0')).join(''),original.bagBytesHex);
const L=require('./source/rev7/cascade/cascade_lib.js');
(async()=>{
 const ctx=await L.loadMcrypt(), results=[], seen=new Set();
 assert.equal(original.rows.length,184);
 for(const r of original.rows){
  const id=[r.orientation,r.cipher,r.keyString].join('|'); assert(!seen.has(id));seen.add(id);
  assert(r.orientation in inputs);assert(L.ALL_CIPHERS.includes(r.cipher));assert(L.KEYS.includes(r.keyString));
  const input=Buffer.from(inputs[r.orientation],'hex'),info=L.CIPHER_INFO[r.cipher];
  assert.equal(hash(input),r.inputSha256);assert.equal(info.blockSize,r.blockSize);
  assert.equal(Buffer.from(L.keyBytesForCipher(r.cipher,r.keyString)).toString('hex'),r.keyBytesHex);
  assert.equal(r.keyByteLength,r.keyBytesHex.length/2);
  const out=L.decryptWith(ctx,r.cipher,r.keyString,input);assert.equal(out.length,r.outputLength);assert.equal(hash(out),r.outputSha256);
  assert.equal(r.skippedPrefixBytes,info.blockSize||8);assert.equal(r.evaluatedSuffixLength,out.length-r.skippedPrefixBytes);
  const outside=[...out.subarray(r.skippedPrefixBytes)].filter(b=>!bag.has(b)).length;assert.equal(outside,r.bytesOutsideBag);
  results.push({...r,reportedMode:r.mode,mode:info.stream?'stream':'cfb8',ivSemantics:info.stream?'No IV passed by the stream invocation':r.ivConvention,prefixSemantics:info.stream?'Eight-byte chosen truncation; no CFB8 IV claim':'First block discarded; CFB8 suffix independent of the external IV',outputHex:out.toString('hex'),singleEditCFB8Margin:info.stream?null:outside-(info.blockSize+1)});
 }
 assert.equal(seen.size,4*L.ALL_CIPHERS.length*L.KEYS.length);
 const block=results.filter(r=>r.mode==='cfb8'),stream=results.filter(r=>r.mode==='stream');assert.equal(block.length,152);assert.equal(stream.length,32);
 const result={identity:'ASTRA',verificationOf:'FABLE saved 184 outputs; no new contexts',primitiveIndependence:'Same pinned WASM runtime as FABLE; source paths repaired without editing source bytes. Independent byte-set construction/count and input orientation checks.',sourceManifestSHA256:hash(fs.readFileSync(path.join(here,'manifest.json'))),scriptSHA256:hash(fs.readFileSync(__filename)),originalLedgerSHA256:hash(fs.readFileSync(path.join(here,'source/record/bytebag_184rows.json'))),allSavedOutputHashesAndCountsMatch:true,rows:results,summary:{rows:results.length,cfb8Rows:block.length,streamRows:stream.length,minimumOutside:Math.min(...results.map(r=>r.bytesOutsideBag)),minimumCFB8SingleEditMargin:Math.min(...block.map(r=>r.singleEditCFB8Margin))}};
 const p=path.join(here,'verified_outputs.json');fs.writeFileSync(p,JSON.stringify(result,null,2)+'\n',{flag:'wx'});
 console.log(JSON.stringify({identity:'ASTRA',verified:true,...result.summary,output:p,sha256:hash(fs.readFileSync(p))}));
})().catch(e=>{console.error(e.stack);process.exitCode=1;});
