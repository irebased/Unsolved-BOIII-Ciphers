// Direct strict-Base64 check of every layer-2 row with D <= 71 (ASTRA 790 bound: 64 + '=' + 6 whitespace).
const fs=require('fs'); const C=require(process.env.SCRATCH+'/rev7/cascade/cascade_lib.js');
const rows=JSON.parse(fs.readFileSync(process.env.SCRATCH+'/depth3/l2census_rows.json')).filter(r=>r.D<=71);
const rev=JSON.parse(fs.readFileSync(process.env.SCRATCH+'/depth3/corpus_rev7/revelations.json')); const ct={}; for(const c of rev) ct[c.id]=Buffer.from(c.ciphertext.replace(/\s+/g,''),'hex');
const B64=new Set([...'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='].map(c=>c.charCodeAt(0))); const WS=new Set([32,9,10,13,11,12]);
(async()=>{const ctx=await C.loadMcrypt(); let n=0,pass=0; const detail=[];
 for(const r of rows){ const inp=r.xf==='reverse'?Buffer.from([...ct[r.id]].reverse()):ct[r.id]; const out=C.decryptWith(ctx,r.prim,r.key,inp); n++;
   const nonb64=[...out].filter(b=>!B64.has(b)&&!WS.has(b)).length; const b64frac=1-nonb64/out.length; if(nonb64===0)pass++; detail.push({...r,non_b64_bytes:nonb64,b64_fraction:+b64frac.toFixed(3)}); }
 detail.sort((a,b)=>a.non_b64_bytes-b.non_b64_bytes); fs.writeFileSync(process.env.SCRATCH+'/depth3/l2_lowD_check.json',JSON.stringify(detail,null,1));
 console.log(`rows with D<=71: ${n}; rows that are entirely Base64-alphabet+'='+whitespace: ${pass}`); console.log('closest rows (fewest non-base64 bytes):',JSON.stringify(detail.slice(0,3).map(d=>({id:d.id,prim:d.prim,key:d.key,len:d.out_len,D:d.D,non_b64:d.non_b64_bytes,frac:d.b64_fraction}))));
 const worstfrac=Math.max(...detail.map(d=>d.b64_fraction)); console.log(`highest base64-alphabet fraction among them: ${worstfrac} (a genuine Base64 string = 1.000; uniform bytes ~ 0.27)`);})();
