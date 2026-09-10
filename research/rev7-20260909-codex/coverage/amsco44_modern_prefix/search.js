#!/usr/bin/env node
'use strict';
// ASTRA: outer equal-cut4 AMSCO followed by a known-key modern cipher.
const fs=require('fs'),path=require('path'),crypto=require('crypto');
const HERE=__dirname,ROOT=path.resolve(HERE,'../../../..');
const R=require('../first_layer_occupancy/runtime.js');
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const fail=(ok,msg)=>{if(!ok)throw Error(msg)};
const COLS=7,ROWS=39,CELL_BYTES=2,N=546;
const KEYS=['Zombies','ZOMBIES'],ORIENTATIONS=['forward','full_hex_reverse'];
function* permutations(a=[0,1,2,3,4,5,6],at=0){if(at===a.length){yield a.slice();return;}for(let i=at;i<a.length;i++){[a[at],a[i]]=[a[i],a[at]];yield* permutations(a,at+1);[a[at],a[i]]=[a[i],a[at]];}}
function indices(order){fail(order.length===7&&new Set(order).size===7,'order');const rank=new Array(7);order.forEach((c,r)=>rank[c]=r);return Uint16Array.from({length:N},(_,i)=>rank[Math.floor(i/2)%7]*(ROWS*2)+Math.floor(i/14)*2+i%2);}
function gather(input,map,n=N){return Buffer.from(Array.from({length:n},(_,i)=>input[map[i]]));}
function encodeIndependent(input,order){const chunks=[];for(const col of order)for(let row=0;row<ROWS;row++)chunks.push(input.subarray((row*7+col)*2,(row*7+col)*2+2));return Buffer.concat(chunks);}
function reverseHex(input){return Buffer.from(input.toString('hex').split('').reverse().join(''),'hex');}
function contexts(){return [...R.BLOCK_CIPHERS.flatMap(cipher=>KEYS.map(key=>({cipher,key,iv:'ascii0',mode:'cfb8',skip:R.CIPHER_INFO[cipher].blockSize}))),...R.STREAM_CIPHERS.flatMap(cipher=>KEYS.map(key=>({cipher,key,iv:null,mode:null,skip:0})))];}
function inspect(output,skip){const tail=output.subarray(skip,skip+128);fail(tail.length===128,'screen length');const D=new Set(tail).size;let printable=0;for(const b of tail)if(b===9||b===10||b===13||b>=32&&b<=126)printable++;return {D,printable,flagged:D<=69||printable>=96};}
function canonical(){const raw=JSON.parse(fs.readFileSync(path.join(ROOT,'lavender/src/data/ciphers/revelations.json'))).find(r=>r.id==='rev7').ciphertext;const hex=raw.replace(/\s/g,'');fail(hex.length===1092&&sha(hex)==='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c','canonical');return Buffer.from(hex,'hex');}
async function controls(ctx){
const orders=[...permutations()];fail(orders.length===5040&&new Set(orders.map(x=>x.join(','))).size===5040,'permutation count');
const natural=Buffer.from(Array.from({length:N},(_,i)=>(i*197+Math.floor(i/19)*31)%256));
const digest=crypto.createHash('sha256');
for(const order of orders){const map=indices(order);fail(new Set(map).size===N,'bijection');const packed=encodeIndependent(natural,order);fail(gather(packed,map).equals(natural),'geometry');digest.update(packed);}
const plain=Buffer.from(Array.from({length:N},(_,i)=>32+(i*17+Math.floor(i/23))%40));
const plantedOrder=[3,5,4,2,1,6,0],map=indices(plantedOrder),plants=[];let calls=0;
for(const c of contexts()){
 const encrypted=R.encrypt(ctx,c.cipher,c.key,c.mode?'zero':null,plain,c.mode);calls++;
 const packed=encodeIndependent(encrypted,plantedOrder);
 for(const orientation of ORIENTATIONS){
  const observed=orientation==='forward'?packed:reverseHex(packed);
  const normalized=orientation==='forward'?observed:reverseHex(observed);
  const prepared=gather(normalized,map,c.skip+128);
  const out=R.decrypt(ctx,c.cipher,c.key,c.iv,prepared,c.mode);calls++;
  fail(out.subarray(c.skip).equals(plain.subarray(c.skip,c.skip+128)),'plant '+JSON.stringify(c));
  const score=inspect(out,c.skip);fail(score.flagged,'missed plant');plants.push({orientation,...c,score});
 }
}
const noise=Buffer.from(Array.from({length:128},(_,i)=>128+i));fail(!inspect(noise,0).flagged,'negative scorer fixture');
return {identity:'ASTRA',target_evaluated:false,orders:5040,geometry_digest:digest.digest('hex'),plants:plants.length,calls,plant_records:plants,runtime_sha256:R.shaFile(path.resolve(HERE,'../first_layer_occupancy/runtime.js')),script_sha256:sha(fs.readFileSync(__filename))};
}
async function target(ctx){
const output=path.join(HERE,'target_results.json');fail(!fs.existsSync(output),'refuse existing target result');
const control=JSON.parse(fs.readFileSync(path.join(HERE,'controls.json')));fail(control.script_sha256===sha(fs.readFileSync(__filename)),'control source pin');fail(control.plants===92&&control.orders===5040,'controls');fail(control.runtime_sha256===R.shaFile(path.resolve(HERE,'../first_layer_occupancy/runtime.js')),'runtime source pin');
const raw=canonical(),cx=contexts(),maps=[...permutations()].map(order=>({order,map:indices(order)})),rows=[],hits=[],histD={},histPrint={},digest=crypto.createHash('sha256');let count=0,minD=129,maxPrintable=0;const best=[],started=Date.now();
for(const orientation of ORIENTATIONS){
 const input=orientation==='forward'?raw:reverseHex(raw);
 for(const {order,map} of maps){
  const prepared=gather(input,map,160);
  for(const c of cx){
   const out=R.decrypt(ctx,c.cipher,c.key,c.iv,prepared.subarray(0,c.skip+128),c.mode);
   const score=inspect(out,c.skip),id=[orientation,order.join(''),c.cipher,c.key].join('|');
   digest.update(id+'\n');digest.update(out);
   count++;histD[score.D]=(histD[score.D]||0)+1;histPrint[score.printable]=(histPrint[score.printable]||0)+1;
   minD=Math.min(minD,score.D);maxPrintable=Math.max(maxPrintable,score.printable);
   if(score.flagged){const fullCiphertext=gather(input,map);const full=R.decrypt(ctx,c.cipher,c.key,c.iv,fullCiphertext,c.mode);hits.push({id,orientation,order,...c,score,output_hex:full.toString('hex'),output_text:full.toString('utf8')});}
   const rec={id,score,output_hex:out.toString('hex')};
   if(best.length<20||score.printable>best[best.length-1].score.printable){best.push(rec);best.sort((a,b)=>b.score.printable-a.score.printable||a.score.D-b.score.D||a.id.localeCompare(b.id));if(best.length>20)best.pop();}
  }
 }
 console.log(JSON.stringify({identity:'ASTRA',progress:orientation,completed:count,seconds:(Date.now()-started)/1000}));
}
fail(count===2*5040*46,'accounting');
const result={identity:'ASTRA',target_evaluated:true,status:'complete',scope:{orientations:ORIENTATIONS,columns:7,rows:39,cut_hex_symbols:4,orders:5040,contexts:cx,iv_scope:'For CFB8, skip one native block; the next128 plaintext bytes are independent of the initial IV. Stream ciphers use their recorded fixed initialization.',scoring:'Exactly128 bytes after skipped native block; retain if distinct-byte count<=69 OR ASCII-printable count>=96. This is a lead screen, not a universal language exclusion.',direction:'Undo conventional equal-cut4 column transposition; no other cuts, row layouts, modern modes or unknown keys.'},script_sha256:sha(fs.readFileSync(__filename)),controls_sha256:sha(fs.readFileSync(path.join(HERE,'controls.json'))),canonical_hex_sha256:sha(raw.toString('hex').toUpperCase()),count,output_digest:digest.digest('hex'),histD,histPrint,minD,maxPrintable,hits,best_printable:best,seconds:(Date.now()-started)/1000};
fs.writeFileSync(output,JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify({identity:'ASTRA',status:'complete',count,hits:hits.length,minD,maxPrintable,seconds:result.seconds,result_sha256:sha(fs.readFileSync(output))}));
}
async function main(){R.verifySources();const ctx=await R.load();if(process.argv[2]==='--controls'){fail(!fs.existsSync(path.join(HERE,'controls.json')),'existing controls');const result=await controls(ctx);fs.writeFileSync(path.join(HERE,'controls.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify({identity:'ASTRA',status:'PASS',orders:result.orders,plants:result.plants,calls:result.calls,script_sha256:result.script_sha256,controls_sha256:sha(fs.readFileSync(path.join(HERE,'controls.json')))}));}else if(process.argv[2]==='--run-target')await target(ctx);else throw Error('usage: node search.js --controls|--run-target');}
main().catch(e=>{console.error(e.stack);process.exitCode=1});
