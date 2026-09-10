#!/usr/bin/env node
'use strict';
// Synthetic scoreTail controls only. This module never calls loadMcrypt.
const crypto=require('crypto');
const C=require('./upstream/cascade/cascade_lib.js');
function ascii546(alphabet){let s='';while(s.length<546)s+=alphabet;return Buffer.from(s.slice(0,546),'ascii');}
function utf8546(text){const pieces=[];let n=0;const unit=Buffer.from(text,'utf8');while(n<546){if(n+unit.length<=546){pieces.push(unit);n+=unit.length;}else{pieces.push(Buffer.alloc(546-n,0x20));n=546;}}return Buffer.concat(pieces);}
const samples=[
 ['binary',ascii546('01')],['octal',ascii546('01234567')],['decimal',ascii546('0123456789')],
 ['hex_upper',ascii546('0123456789ABCDEF')],['hex_lower',ascii546('0123456789abcdef')],
 ['base32',ascii546('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=')],
 ['base64',ascii546('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')],
 ['german_utf8',utf8546('Übermäßig große Füße auf der Straße; ÄÖÜ äöü ß – — ‘ ’ “ ” … ')]
];
const rows=samples.map(([name,buf])=>{const score=C.scoreTail(buf,0);if(score.longestRun!==546||score.validCount!==546||score.tailLen!==546)throw new Error(name+' did not fully pass');return {name,bytes:buf.length,sha256:crypto.createHash('sha256').update(buf).digest('hex'),score};});
process.stdout.write(JSON.stringify({identity:'ASTRA',target_evaluated:false,rev7_read:false,node_version:process.version,score_function:'upstream/cascade/cascade_lib.js scoreTail(buf,0)',samples:rows,assertions:{all_passed:true,all_eight_full_tails:rows.every(x=>x.score.longestRun===546&&x.score.validCount===546&&x.score.tailLen===546)}},null,2)+'\n');
