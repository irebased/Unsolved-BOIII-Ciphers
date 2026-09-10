#!/usr/bin/env node
'use strict';
const fs=require('fs'),path=require('path'),crypto=require('crypto');
const HERE=__dirname,ROOT=path.resolve(HERE,'../../../..');
const SCORE=path.join(ROOT,'research/rev7-20260909-codex/coverage/occupancy_screen_controls/score.js');
const TABLE=path.join(ROOT,'research/rev7-20260909-codex/coverage/occupancy_screen_controls/threshold_table.json');
const SCORE_SHA='6ff228f71ef8e9441c3ba12418d8b49c7238ff4e66ed0eef0f24471a3573ae27';
const TABLE_SHA='2d084a536141c8e51045b1fa1052ddfc713e0e5f7a869fd62676cf788dfbb447';
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function main(argv){let input,output;for(let i=2;i<argv.length;i++){if(argv[i]==='--input')input=argv[++i];else if(argv[i]==='--output')output=argv[++i];else throw Error('usage: score_inventory.js --input FILE --output NEW_FILE');}
 if(!input||!output||fs.existsSync(output))throw Error('input and absent output required');
 if(sha(fs.readFileSync(SCORE))!==SCORE_SHA||sha(fs.readFileSync(TABLE))!==TABLE_SHA)throw Error('occupancy pin');
 const S=require(SCORE),table=S.loadTable(TABLE),doc=JSON.parse(fs.readFileSync(input,'utf8'));
 if(doc.identity!=='ASTRA'||doc.scope.labels!==16128||doc.rows.length!==16128)throw Error('inventory scope');
 let scored=0,unsupported=0;
 for(const r of doc.rows){if(r.status==='ready'||r.status==='ready_empty'){const b=S.fromHex(r.bytes_hex);if(b.length!==r.length||sha(b)!==r.sha256)throw Error('row bytes '+r.id);const h=Array(256).fill(0);for(const x of b)h[x]++;if(JSON.stringify(h)!==JSON.stringify(r.histogram)||h.filter(x=>x).length!==r.distinct_bytes)throw Error('row histogram '+r.id);r.occupancy=S.scoreBytes(b,table);scored++;if(r.occupancy.screen_hit===null)unsupported++;}else{if('bytes_hex'in r)throw Error('failed row has bytes');r.occupancy=null;}}
 doc.occupancy={source_sha256:SCORE_SHA,table_sha256:TABLE_SHA,window:'full output only',supported_n:[128,1092],ready_rows_scored:scored,unsupported_ready_rows:unsupported};
 fs.writeFileSync(output,JSON.stringify(doc));
}
try{main(process.argv);}catch(e){process.stderr.write(String(e.message||e)+'\n');process.exitCode=2;}
