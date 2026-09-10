'use strict';
const fs=require('fs'), path=require('path'), crypto=require('crypto');
const {Worker}=require('worker_threads');
const HERE=__dirname;
const lib=require('./upstream/dictkey2/lib.js');
const cl=require('./upstream/cascade/cascade_lib.js');
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
(async()=>{
 const targets=JSON.parse(fs.readFileSync(path.join(HERE,'upstream/b64read/targets.json'),'utf8'));
 const row=targets.find(x=>x.label==='POS'&&x.reading==='plant_twofish_cfb8_Zombies');
 if(!row)throw Error('stored POS absent');
 const txt=fs.readFileSync(path.join(HERE,'upstream/b64read/plant_b64.txt'),'utf8');
 const pt=fs.readFileSync(path.join(HERE,'upstream/b64read/plant_plaintext.txt'));
 if(row.b64string!==txt||txt.length!==1092||pt.length!==819)throw Error('plant fixture mismatch');
 const ct=Buffer.from(txt,'base64');
 if(ct.length!==819||ct.toString('base64')!==txt)throw Error('base64 roundtrip');
 const ctx=await lib.loadMcrypt();
 const key=cl.keyBytesForCipher('twofish','Zombies'),iv=cl.ivFor(16);
 const dec=Buffer.from(lib.decryptOnce(ctx,'twofish',key,iv,ct,lib.MODE_CFB8));
 const enc=Buffer.from(lib.encryptOnce(ctx,'twofish',key,iv,pt,lib.MODE_CFB8));
 if(!dec.equals(pt)||!enc.equals(ct))throw Error('plant crypto replay');
 const canonical=fs.readFileSync(path.join(HERE,'upstream/rev7_hex.txt'),'utf8').trim();
 const b64decoded=Buffer.from(canonical,'base64');
 if(canonical.length!==1092||b64decoded.length!==819||b64decoded.toString('base64')!==canonical)throw Error('hex glyph Base64 roundtrip');
 const HEX='0123456789ABCDEF'; let n=0;for(const c of txt)if(HEX.includes(c))n++;
 const workerResult=await new Promise((resolve,reject)=>{
  const w=new Worker(path.join(HERE,'upstream/b64read/worker.js'),{workerData:{dataB64:ct.toString('base64'),keys:['Zombies'],reading:row.reading,label:row.label}});
  w.once('message',resolve);w.once('error',reject);
 });
 if(workerResult.error||workerResult.trials!==80||workerResult.errors!==0)throw Error('worker positive accounting');
 const hit=workerResult.best.utf8_longestRun;
 if(hit.value!==803||hit.params.cipher!=='twofish'||hit.params.mode!=='cfb8'||hit.params.key!=='Zombies')throw Error('worker did not recover planted full scored tail');
 const out={identity:'ASTRA',target_evaluated:false,full_sweep_replayed:false,control:'stored_positive_only',node_version:process.version,
  plant:{cipher:'twofish',mode:'CFB8',key_text:'Zombies',iv_hex:iv.toString('hex'),plaintext_length:pt.length,ciphertext_length:ct.length,base64_length:txt.length,plaintext_sha256:sha(pt),ciphertext_sha256:sha(ct),base64_sha256:sha(Buffer.from(txt)),chars_in_upper_hex:n,decrypt_matches:true,reencrypt_matches:true,worker_path:{trials:workerResult.trials,errors:workerResult.errors,best_utf8_longest_run:hit,top_utf8_first:workerResult.topUtf8[0],endpoint_best:workerResult.best}},
  canonical_glyph_fact:{length:canonical.length,alphabet:[...new Set(canonical)].sort().join(''),is_legal_base64:true,decoded_length:b64decoded.length,roundtrip_exact:true,decoded_sha256:sha(b64decoded)}};
 process.stdout.write(JSON.stringify(out));
})().catch(e=>{console.error(e.stack||e);process.exit(1)});
