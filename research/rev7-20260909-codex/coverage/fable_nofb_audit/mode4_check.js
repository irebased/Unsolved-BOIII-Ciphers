'use strict';

const path = require('path');
function seq(n, seed) { const out=Buffer.alloc(n); for(let i=0;i<n;i++) out[i]=(seed+29*i+7*i*i)&255; return out; }
function diff(a,b){ for(let i=0;i<Math.min(a.length,b.length);i++) if(a[i]!==b[i]) return i; return a.length===b.length?-1:Math.min(a.length,b.length); }
(async()=>{
 if(process.argv.length!==3) throw new Error('usage: node mode4_check.js TEMP_SOURCE_ROOT');
 const L=require(path.join(path.resolve(process.argv[2]),'rev7/nofb/lib.js')); const ctx=await L.loadMcrypt();
 const specs=[['des',8,8],['rijndael-128',16,16],['blowfish',16,8]]; const rows=[];
 for(let ci=0;ci<specs.length;ci++){ const [cipher,keyLen,bs]=specs[ci];
  for(const [case_id,n] of [['partial',37],['multiblock',128]]){ const key=seq(keyLen,11+ci*41),iv=seq(bs,23+ci*37),data=seq(n,31+ci*43+(case_id==='partial'?0:9));
   const nofb=Buffer.from(L.nofbProcess(ctx,cipher,key,iv,data)), mode4=Buffer.from(L.blockWideOFB(ctx,cipher,key,iv,data)), ofb8=Buffer.from(L.ofb8Process(ctx,cipher,key,iv,data));
   rows.push({cipher,case_id,key_hex:key.toString('hex'),iv_hex:iv.toString('hex'),data_hex:data.toString('hex'),nofb_hex:nofb.toString('hex'),mode4_hex:mode4.toString('hex'),ofb8_hex:ofb8.toString('hex'),mode4_equals_nofb:mode4.equals(nofb),mode4_equals_ofb8:mode4.equals(ofb8),first_diff_nofb_ofb8:diff(nofb,ofb8)});
 }} process.stdout.write(JSON.stringify({identity:'ASTRA',target_evaluated:false,rows}));
})().catch(e=>{console.error(e.stack||String(e));process.exit(1)});
