'use strict';
const fs=require('fs'),path=require('path'),zlib=require('zlib'),os=require('os'),crypto=require('crypto');
const HERE=__dirname,U=path.join(HERE,'upstream'),lib=require('./upstream/dictkey2/lib.js');
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'astra-b64-t3-'));
try{
 const raw=zlib.gunzipSync(fs.readFileSync(path.join(U,'dictkey','keys_dict.txt.gz')),{maxOutputLength:7449349});
 if(raw.length!==7449348||sha(raw)!=='a6a970dcd6335844976d2834e6279fece5ec687ce9a65e91f79056caa7532d91')throw Error('dictionary transport');
 const d=path.join(tmp,'keys_dict.txt');fs.writeFileSync(d,raw);
 const files=[d,path.join(U,'dictkey','keys_lore.txt'),path.join(U,'dictkey','keys_artifacts.txt')];
 const parts=files.map(f=>lib.readKeyFile(f));
 const union=[...new Set(parts.flat())];
 if(JSON.stringify(parts.map(x=>x.length))!==JSON.stringify([703344,636,801])||union.length!==704667)throw Error('key accounting');
 const joined=Buffer.from(union.join('\0'),'utf8');
 const out={identity:'ASTRA',target_evaluated:false,full_sweep_replayed:false,node:process.version,raw_dictionary:{bytes:raw.length,sha256:sha(raw),transport_sha256:sha(fs.readFileSync(path.join(U,'dictkey','keys_dict.txt.gz')))},readKeyFile_counts:parts.map((x,i)=>({name:['keys_dict.txt','keys_lore.txt','keys_artifacts.txt'][i],count:x.length,unique:new Set(x).size})),concat_count:parts.flat().length,dedup_count:union.length,duplicates_removed:parts.flat().length-union.length,ordered_union_nul_join_sha256:sha(joined),first_keys:union.slice(0,8),last_keys:union.slice(-8)};
 process.stdout.write(JSON.stringify(out));
}finally{fs.rmSync(tmp,{recursive:true,force:true});}
