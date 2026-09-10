#!/usr/bin/env node
'use strict';
const fs=require('fs'),path=require('path'),crypto=require('crypto');
const HERE=__dirname,R=require('./runtime.js'),M=require('./model.js');
const OUTPUT=path.join(HERE,'controls.json');
const OCC_LEDGER=path.resolve(HERE,'../occupancy_screen_controls/controls.json');
const OCC_LEDGER_SHA='54f5861811e5b91db0341593cbe9486dc74251ec7280dd971cf7b3f55d9caf8c';
function sha(b){return crypto.createHash('sha256').update(b).digest('hex');}
function fileSha(p){return sha(fs.readFileSync(p));}
function stable(x){return JSON.stringify(x,null,2)+'\n';}
function assert(x,m){if(!x)throw Error(m);}
function sourcePins(){
  const p={};
  for(const f of ['runtime.js','model.js','controls.js'])p[f]=fileSha(path.join(HERE,f));
  p['../occupancy_screen_controls/controls.json']=fileSha(OCC_LEDGER);
  for(const [f,h] of Object.entries(R.PINS))p[path.relative(HERE,f)]=h;
  p[path.relative(HERE,M.SCORE_PATH)]=M.SCORE_SHA;
  p[path.relative(HERE,M.TABLE_PATH)]=M.TABLE_SHA;
  assert(p['../occupancy_screen_controls/controls.json']===OCC_LEDGER_SHA,'occupancy ledger hash');
  return p;
}
function plant(){return Buffer.from(Array.from({length:546},(_,i)=>0x80+(i%40)));}
function orientationControls(){
  const hex=Buffer.from(Array.from({length:546},(_,i)=>(i*73+19)&255)).toString('hex').toUpperCase();
  const tokens=[hex.slice(0,2)];for(let i=2;i<hex.length;i+=5)tokens.push(hex.slice(i,i+5));
  assert(tokens.length===219&&tokens.slice(1).every(x=>x.length===5),'token geometry');
  const o=M.orientations(hex,tokens);
  const pairs=hex.match(/../g);
  assert(o.full_hex_reverse===[...hex].reverse().join(''),'full reverse');
  assert(o.byte_pair_reverse===pairs.slice().reverse().join(''),'pair reverse');
  assert(o.nibble_swap===pairs.map(x=>x[1]+x[0]).join(''),'nibble swap');
  assert(o.visible_token_reverse===tokens.slice().reverse().join(''),'token reverse');
  assert(new Set(Object.values(o)).size===5,'orientation fixture distinct');
  return {input_sha256:sha(Buffer.from(hex)),tokens:tokens.length,token_lengths:{first:2,remaining:5},
    outputs:Object.fromEntries(M.ORIENTATIONS.map(k=>[k,{length:o[k].length,sha256:sha(Buffer.from(o[k]))}]))};
}
async function compute(){
  R.verifySources();const ctx=await R.load(),pt=plant(),rows=[];
  assert(new Set(pt).size===40,'plant D');
  for(const c of M.contexts()){
    ctx.mcrypt.HEAPU8.fill(0xa5,ctx.keyPtr,ctx.keyPtr+256);
    const ct=R.encrypt(ctx,c.cipher,c.key,c.iv,pt,c.mode);
    ctx.mcrypt.HEAPU8.fill(0x5a,ctx.keyPtr,ctx.keyPtr+256);
    const got=R.decrypt(ctx,c.cipher,c.key,c.iv,ct,c.mode);
    assert(got.equals(pt),'roundtrip '+JSON.stringify(c));
    const sc=M.screenOutput(got,c);
    assert(sc.output_length===546&&sc.full.D===40&&sc.full.screen_hit===true,'full score');
    if(c.kind==='block')assert(sc.tail.n===546-c.block_size&&sc.tail.D===40&&sc.tail.screen_hit===true,'tail score');
    else assert(sc.tail===null,'stream tail');
    const kb=R.keyBytes(c.cipher,c.key);
    if(c.cipher==='loki97')assert(kb.length===32&&kb.subarray(7).every(x=>x===0),'loki key backing');
    else assert(kb.length===7,'raw literal key');
    rows.push({...c,key_bytes:kb.length,key_sha256:sha(kb),ciphertext_length:ct.length,
      ciphertext_sha256:sha(ct),recovered_sha256:sha(got),screen:sc});
  }
  assert(rows.length===312,'row count');
  assert(ctx.metrics.calls===624&&ctx.metrics.key_clears===624&&ctx.metrics.iv_clears===608,'clear/call metrics');
  const blockRows=rows.filter(x=>x.kind==='block').length,streamRows=rows.length-blockRows;
  assert(blockRows===304&&streamRows===8,'kind counts');
  return {identity:'ASTRA',status:'synthetic controls complete',target_evaluated:false,
    model:{plaintext_length:546,plaintext_distinct_bytes:40,plaintext_alphabet_hex:'80-A7',
      contexts:312,block_contexts:304,stream_contexts:8,
      modes:R.MODES,keys:R.KEYS,ivs:['zero','ascii0'],
      key_rule:'literal seven-byte ASCII; Loki97 uses explicit 32-byte zero backing with the literal in bytes 0..6',
      key_heap_clear_bytes_per_call:256,iv_heap_clear_bytes_per_block_call:32},
    source_pins:sourcePins(),orientation_controls:orientationControls(),
    runtime_metrics:ctx.metrics,plant_sha256:sha(pt),rows};
}
async function main(){
  let generate=null;
  if(process.argv.length===4&&process.argv[2]==='--generate')generate=path.resolve(process.argv[3]);
  else if(process.argv.length!==2)throw Error('usage: node controls.js [--generate NEW_PATH]');
  const got=await compute();
  if(generate){if(fs.existsSync(generate))throw Error('refuse existing output');fs.writeFileSync(generate,stable(got));console.log(JSON.stringify({identity:'ASTRA',generated:generate,sha256:fileSha(generate),rows:got.rows.length}));}
  else {if(!fs.existsSync(OUTPUT))throw Error('controls.json absent; use --generate NEW_PATH');const want=JSON.parse(fs.readFileSync(OUTPUT,'utf8'));assert(stable(got)===stable(want),'controls mismatch');console.log(JSON.stringify({identity:'ASTRA',status:'PASS',target_evaluated:false,rows:got.rows.length,ledger_sha256:fileSha(OUTPUT)}));}
}
main().catch(e=>{console.error(e.stack||String(e));process.exitCode=1;});
