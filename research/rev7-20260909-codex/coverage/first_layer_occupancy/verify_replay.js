#!/usr/bin/env node
'use strict';
// Identity: ASTRA. Read-only result replay; independent orientation/scoring loops,
// shared pinned crypto runtime. This is not independent cipher conformance.
const fs=require('fs'),path=require('path'),crypto=require('crypto'),assert=require('assert/strict');
const HERE=__dirname,ROOT=path.resolve(HERE,'../../../..');
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const fileSha=p=>sha(fs.readFileSync(p));
const TARGET_SHA='313899571bc5e9ca5152b245d6e94238891d8bcdf6081569a55fff80b0ad2d3c';
const tablePath=path.resolve(HERE,'../occupancy_screen_controls/threshold_table.json');
assert.equal(fileSha(tablePath),'2d084a536141c8e51045b1fa1052ddfc713e0e5f7a869fd62676cf788dfbb447');
const table=JSON.parse(fs.readFileSync(tablePath));
const cutoffs=Object.fromEntries(table.rows.map(r=>[r.n,r.d]));
function score(bytes){
 const histogram=new Uint32Array(256);for(let i=0;i<bytes.length;i++)histogram[bytes[i]]++;
 let D=0;for(let i=0;i<256;i++)if(histogram[i]>0)D++;
 const n=bytes.length;
 if(n<128)return {n,D,status:'short',screen_hit:null};
 if(n>1092)return {n,D,status:'out-of-range',screen_hit:null};
 const d=cutoffs[n];assert.ok(Number.isInteger(d));return {n,D,threshold_d:d,status:D<=d?'flagged':'unflagged',screen_hit:D<=d};
}
function orientations(bytes,tokens){
 const flip=x=>((x&15)<<4)|(x>>4),n=bytes.length;
 const reverse=Buffer.alloc(n),swap=Buffer.alloc(n),both=Buffer.alloc(n);
 for(let i=0;i<n;i++){reverse[i]=bytes[n-i-1];swap[i]=flip(bytes[i]);both[i]=flip(bytes[n-i-1]);}
 let wordHex='';for(let i=tokens.length-1;i>=0;i--)wordHex+=tokens[i];
 return {forward:Buffer.from(bytes),full_hex_reverse:both,byte_pair_reverse:reverse,nibble_swap:swap,visible_token_reverse:Buffer.from(wordHex,'hex')};
}
function controls(){
 const o=orientations(Buffer.from('12345678','hex'),['123','45','678']);
 assert.deepEqual(Object.fromEntries(Object.entries(o).map(([k,v])=>[k,v.toString('hex')])),{forward:'12345678',full_hex_reverse:'87654321',byte_pair_reverse:'78563412',nibble_swap:'21436587',visible_token_reverse:'67845123'});
 let count=1;
 for(const n of [514,530,534,538,546])for(const d of [cutoffs[n]-1,cutoffs[n],cutoffs[n]+1]){
  const b=Buffer.from(Array.from({length:n},(_,i)=>(73*(i%d)+41)%256));
  const s=score(b);assert.equal(s.D,d);assert.equal(s.screen_hit,d<=cutoffs[n]);count++;
 }
 for(const n of [0,127,1093]){assert.equal(score(Buffer.alloc(n)).screen_hit,null);count++;}
 return count;
}
async function main(){
 assert.ok(process.argv.length===2||process.argv.length===3&&process.argv[2]==='--controls-only','usage: verify_replay.js [--controls-only]');
 const controlCount=controls();if(process.argv.includes('--controls-only')){console.log(JSON.stringify({identity:'ASTRA',status:'PASS',target_evaluated:false,controls:controlCount}));return;}
 const resultPath=path.join(HERE,'target_results.json');assert.equal(fileSha(resultPath),TARGET_SHA);
 const doc=JSON.parse(fs.readFileSync(resultPath));
 assert.equal(fileSha(path.join(HERE,'runtime.js')),'fd9d62dd20105757ec41c9affca23375b7276e4bda306feed05eeb0782fd3e30');
 const R=require('./runtime.js');R.verifySources();
 const mdxPath=path.join(ROOT,'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx');
 assert.equal(fileSha(mdxPath),doc.source.mdx_sha256);
 const raw=fs.readFileSync(mdxPath,'utf8').match(/code=\{\s*`([0-9A-F\s]+)`\s*\}/)[1];
 const tokens=raw.trim().split(/\s+/),hex=tokens.join('');assert.equal(sha(Buffer.from(hex)),'5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c');
 assert.equal(tokens.length,219);assert.equal(tokens[0].length,2);assert.ok(tokens.slice(1).every(t=>t.length===5));
 const inputs=orientations(Buffer.from(hex,'hex'),tokens);
 const grid=[];
 for(const [name,input] of Object.entries(inputs)){
  for(const cipher of ['3-way','blowfish','blowfish-compat','cast-128','cast-256','des','tripledes','gost','loki97','rc2','rijndael-128','rijndael-192','rijndael-256','safer-64','safer-128','saferplus','serpent','twofish','xtea'])
   for(const mode of ['cfb8','ncfb','ofb','ctr'])for(const key of ['Zombies','ZOMBIES'])for(const iv of ['zero','ascii0'])grid.push({name,input,cipher,mode,key,iv,kind:'block'});
  for(const cipher of ['enigma','panama','arcfour','wake'])for(const key of ['Zombies','ZOMBIES'])grid.push({name,input,cipher,mode:null,key,iv:null,kind:'stream'});
 }
 assert.equal(grid.length,1560);assert.equal(doc.rows.length,1560);
 const rows=new Map(doc.rows.map(r=>[r.id,r]));assert.equal(rows.size,1560);
 const ctx=await R.load(),min={full:{D:Infinity,tied_context_ids:[]},tail:{D:Infinity,tied_context_ids:[]}},ranges={full:[],tail:[]};let flags=0,windows=0;
 function checkWindow(which,bytes,stored,id){const actual=score(bytes);assert.deepEqual(stored,actual,id+' '+which);windows++;if(actual.screen_hit)flags++;ranges[which].push(actual.D);if(actual.D<min[which].D)min[which]={D:actual.D,tied_context_ids:[id]};else if(actual.D===min[which].D)min[which].tied_context_ids.push(id);}
 for(const c of grid){
  const id=[c.name,c.cipher,c.mode||'stream',c.key,c.iv||'none'].join('|'),r=rows.get(id);assert.ok(r,id);assert.equal(r.status,'ok');
  assert.equal(r.orientation,c.name);assert.equal(r.kind,c.kind);assert.equal(r.cipher,c.cipher);assert.equal(r.mode,c.mode);assert.equal(r.key,c.key);assert.equal(r.iv,c.iv);
  const b=R.decrypt(ctx,c.cipher,c.key,c.iv,c.input,c.mode);assert.equal(b.length,546);assert.equal(r.output_length,b.length);assert.equal(r.output_sha256,sha(b),id);
  checkWindow('full',b,r.full,id);
  const expectedFlags=r.full.screen_hit?['full']:[];
  if(c.kind==='block'){assert.equal(r.block_size,R.CIPHER_INFO[c.cipher].blockSize);checkWindow('tail',b.slice(r.block_size),r.tail,id);if(r.tail.screen_hit)expectedFlags.push('tail');}else assert.equal(r.tail,null);
  assert.deepEqual(r.flagged_windows,expectedFlags);if(expectedFlags.length)assert.equal(r.output_hex,b.toString('hex').toUpperCase());
 }
 assert.equal(windows,3080);assert.equal(flags,0);assert.deepEqual(ctx.metrics,doc.runtime_metrics);assert.deepEqual(min,doc.summary.global_minima);
 assert.deepEqual(doc.summary.status_counts,{ok:1560});assert.deepEqual(doc.summary.output_length_histogram,{'546':1560});
 assert.equal(doc.summary.scored_windows,windows);assert.equal(doc.summary.flagged_rows,0);assert.equal(doc.summary.flagged_windows,0);
 const out={identity:'ASTRA',status:'PASS',target_result_sha256:TARGET_SHA,verifier_sha256:fileSha(__filename),controls:controlCount,replayed_decryptions:1560,verified_windows:3080,output_hashes_verified:1560,flags:0,runtime_metrics:ctx.metrics,global_minima:min,ranges:Object.fromEntries(Object.entries(ranges).map(([k,v])=>[k,{min:Math.min(...v),max:Math.max(...v)}])),scope:'Independent orientation reconstruction and histogram scoring; same pinned cipher runtime. Verifies recorded hashes and scoring, not independent cryptographic conformance.'};
 console.log(JSON.stringify(out,null,2));
}
main().catch(e=>{console.error(e.stack||String(e));process.exitCode=1;});
