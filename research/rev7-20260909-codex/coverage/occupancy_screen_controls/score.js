#!/usr/bin/env node
'use strict';
// ASTRA standalone exact-table occupancy scorer. Node.js standard library only.
const fs = require('fs');
const path = require('path');
function loadTable(filename) {
  const data=JSON.parse(fs.readFileSync(filename,'utf8'));
  if(data.identity!=='ASTRA'||!data.model||data.model.labels!==256||data.model.n_min!==128||data.model.n_max!==1092||data.model.threshold_probability!=='1/10^15'||!Array.isArray(data.rows)||data.rows.length!==965)throw new Error('invalid table profile');
  const byN=new Map();
  for(const r of data.rows){if(!Number.isInteger(r.n)||!Number.isInteger(r.d)||r.d<0||r.d>Math.min(r.n,256)||byN.has(r.n))throw new Error('invalid row');byN.set(r.n,r.d);}
  for(let n=128;n<=1092;n++)if(!byN.has(n))throw new Error('missing n '+n);
  return byN;
}
function scoreBytes(bytes, table) {
  if(!Buffer.isBuffer(bytes)&&!(bytes instanceof Uint8Array))throw new TypeError('bytes');
  const n=bytes.length;const D=new Set(bytes).size;
  if(n<128)return {n,D,status:'short',screen_hit:null};
  if(n>1092)return {n,D,status:'out-of-range',screen_hit:null};
  const d=table.get(n);if(!Number.isInteger(d))throw new Error('no threshold for n '+n);
  const hit=D<=d;return {n,D,threshold_d:d,status:hit?'flagged':'unflagged',screen_hit:hit};
}
function fromHex(text){if(typeof text!=='string'||text.length%2||!/^[0-9a-fA-F]*$/.test(text))throw new Error('invalid hex');return Buffer.from(text,'hex');}
function main(argv){
 let tablePath=path.join(__dirname,'threshold_table.json'),batchPath=null;
 for(let i=2;i<argv.length;i++){if(argv[i]==='--table')tablePath=argv[++i];else if(argv[i]==='--batch')batchPath=argv[++i];else throw new Error('usage: score.js [--table FILE] --batch FILE');}
 if(!batchPath)throw new Error('batch file required');
 const table=loadTable(tablePath);const input=JSON.parse(fs.readFileSync(batchPath,'utf8'));
 if(!Array.isArray(input))throw new Error('batch must be array');
 const rows=input.map(x=>({id:x.id,...scoreBytes(fromHex(x.hex),table)}));
 process.stdout.write(JSON.stringify({identity:'ASTRA',rows})+'\n');
}
if(require.main===module){try{main(process.argv);}catch(e){process.stderr.write(String(e.message||e)+'\n');process.exitCode=2;}}
module.exports={loadTable,scoreBytes,fromHex};
