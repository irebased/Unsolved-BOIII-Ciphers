// Layer-2 D census, v2: per-row records + explicit alias/skip accounting, saved for audit.
const fs=require('fs'),crypto=require('crypto'); const C=require(process.env.SCRATCH+'/rev7/cascade/cascade_lib.js');
const man=JSON.parse(fs.readFileSync(process.env.SCRATCH+'/depth3/corpus_rev7/stageA_manifest.json')).intermediates;
const rev=JSON.parse(fs.readFileSync(process.env.SCRATCH+'/depth3/corpus_rev7/revelations.json')); const ct={}; for(const c of rev) if(man[c.id]) ct[c.id]=Buffer.from(c.ciphertext.replace(/\s+/g,''),'hex');
const PRIMS=['des','rc2','blowfish','blowfish-compat','twofish','serpent','xtea','rijndael-128','rijndael-256','saferplus','loki97','tripledes','cast-128','idea','arcfour','salsa20','gost','cast-256','wake','enigma','rijndael-192'];
(async()=>{const ctx=await C.loadMcrypt(); const rows=[]; const skipped={}; const seen={};
 for(const [id,buf] of Object.entries(ct)) for(const xf of ['identity','reverse']){ const inp=xf==='reverse'?Buffer.from([...buf].reverse()):buf;
   for(const p of PRIMS){ if(!C.CIPHER_INFO[p]){skipped['no-such-primitive-in-oracle:'+p]=(skipped['no-such-primitive-in-oracle:'+p]||0)+1;continue;}
     for(const k of ['Zombies','ZOMBIES']){ let out; try{out=C.decryptWith(ctx,p,k,inp);}catch(e){const key='decrypt-error:'+p+':'+String(e).slice(0,40);skipped[key]=(skipped[key]||0)+1;continue;}
       const h=crypto.createHash('sha256').update(out).digest('hex'); const D=new Set(out).size; const rec={id,xf,prim:p,key:k,mode:'cfb8',in_len:inp.length,out_len:out.length,D,sha256:h,alias_of:seen[h]||null}; if(!seen[h])seen[h]=`${id}/${xf}/${p}/${k}`; rows.push(rec);}}}
 const planned=Object.keys(ct).length*2*PRIMS.length*2; const distinct=new Set(rows.map(r=>r.sha256)).size;
 const summary={planned_labels:planned,evaluated:rows.length,skipped,distinct_outputs:distinct,minD:Math.min(...rows.map(r=>r.D)),D_le_64:rows.filter(r=>r.D<=64).length,D_le_70:rows.filter(r=>r.D<=70).length,D_le_100:rows.filter(r=>r.D<=100).length,fulllen_minD:Math.min(...rows.filter(r=>r.in_len>=546).map(r=>r.D)),oracle:'old-ciphers WASM libmcrypt via cascade_lib.decryptWith (CFB-8, key null-padded per cipher, IV ASCII 0)',stageA_manifest_sha256:crypto.createHash('sha256').update(fs.readFileSync(process.env.SCRATCH+'/depth3/corpus_rev7/stageA_manifest.json')).digest('hex')};
 fs.writeFileSync(process.env.SCRATCH+'/depth3/l2census_rows.json',JSON.stringify(rows)); fs.writeFileSync(process.env.SCRATCH+'/depth3/l2census_summary.json',JSON.stringify(summary,null,1)); console.log(JSON.stringify(summary,null,1));})();
