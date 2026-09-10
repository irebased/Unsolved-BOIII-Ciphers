#!/usr/bin/env python3
"""ASTRA inert completion driver for fresh periods in a fixed one-square Bifid16 family."""
from __future__ import annotations
import argparse,gzip,hashlib,json,os,sys,time
from pathlib import Path
HERE=Path(__file__).resolve().parent;PACKAGE=HERE.parent;REPO=HERE.parents[3]
sys.path.insert(0,str(PACKAGE));import bagmode,bifid16,symmetry_probe
z3=bagmode.z3
IDENTITY='ASTRA';ORIENTS=('forward','reverse','byte_reverse','nibble_swap');PERIODS=tuple(range(1,1093));BAG=213;PREFIX=546;TIMEOUT_MS=10000
MDX=REPO/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx';DATASET=REPO/'lavender/src/data/ciphers/revelations.json';EVEN=PACKAGE/'even_target/target_results.json';PILOT=PACKAGE/'odd_pilot/target_results.json';FULL=PACKAGE/'odd_fullbag/target_results.json';GATE=HERE/'target_gate.json';OUTPUT=HERE/'target_results.json';TMP=HERE/'target_results.json.tmp';CHECKPOINT=HERE/'checkpoint.jsonl';STATUS=HERE/'status.json';DUMPS=HERE/'smt'
TEXT_SHA='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c'
PINS={'bagmode.py':'ec21d22691016d2a331a0c8a14c0573306b88ac6db772c8a6c5de64409597e06','bifid16.py':'a80c5f839511454a11a473cbfa4734bf3452656c8015e15ac759f65f45bf9af7','audit.json':'d984d8c9ea8118e85d7f21bb226df28925392141bbf4af6d9f8e1951c6892aec','symmetry_probe.py':'8bf072deccafabe1e98db126178207d9cf3c8eccdcab6902a28b0c0d123a26e0','dependency/dependency.json':'e88e7bf34243264705ca5fcaa66acb5c9db96f289192a862e0e063a915897e4e','dependency/runtime/z3/lib/libz3.dylib':'3164e079c221c23a843396a485a6e912ee423918ee64ea03943e584305439a98','even_target/target_results.json':'acc7df78f141e79b9d3c4e23dba3124ddb7665d5cb5f7450eabd5d9a88ce1dc8','even_target/run_target.py':'b86fdd8402319753eb0292e75b9f0712a1ed2044038761e5d7a23af30cd4ff85','even_target/verify_results.py':'547eccc6b2dc6b5ec808b857934e26af86ea209271fcac6fc2f11e16a4cb023a','even_period_invariant.py':'1fa72b75ff59028ed256dbf6853dd44669cd53b07bcce998331e212b65d2a2a2','even_period_invariant.json':'f6f2d01801992bb145c583fdc83284ea100c99d30bf4f3e5a477b56317a84a36','odd_pilot/target_results.json':'5ffb45b7191689e119bbb4e930f124eda5f78d8ddbb229085e9c522245c5a4a1','odd_pilot/run_target.py':'52972d35244709e87f2de69b6f760b9cdc2029e82d93af9789bfffe2c34bb3eb','odd_pilot/target_gate.json':'fef5128cd5a7d80fb31a48fdfc479e215271b250d9e423d69cbb53021d0d6654','odd_pilot/verify_results.py':'bd2d2a58d2493b1e87e19bf0ca9e12f795c4c1b7fb26bbaa58be1bbbba276375','odd_fullbag/target_results.json':'3bbb8ccd756ea29082b2394108544601c79eb0fe19d2259b2c8ba732294225a3','odd_fullbag/run_target.py':'cd6f5abdbd63862dcb8cb84131b454e8dd9a8da6a24677b2a9b6992045edc338','odd_fullbag/target_gate.json':'9fa88c99738acce0ad230699fa46ee29b71a9264ea660e0dace2c29b5970b1a2','odd_fullbag/verify_results.py':'37f657c01ed2ecefdf08e992da7c0a62725942e25e11c005f998a40c81ab46c0','rev7_mdx':'085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91','dataset':'68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e'}
BAG_VALUES=frozenset([9,10,13,*range(32,127),*range(0x80,0xC0),*range(0xC2,0xF5)])
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def sources():
 d={k:sha(PACKAGE/k) for k in PINS if k not in ('rev7_mdx','dataset')};d['rev7_mdx']=sha(MDX);d['dataset']=sha(DATASET);return d
def orientation(value,name):
 pairs=[value[i:i+2] for i in range(0,len(value),2)]
 if name=='forward':out=value
 elif name=='reverse':out=value[::-1]
 elif name=='byte_reverse':out=''.join(reversed(pairs))
 elif name=='nibble_swap':out=''.join(x[::-1] for x in pairs)
 else:raise ValueError(name)
 assert len(out)==len(value) and sorted(out)==sorted(value);return out
def cell_id(o,p):return f'{o}_p{p}'
def derive_scope():
 even=json.loads(EVEN.read_text());pilot=json.loads(PILOT.read_text());full=json.loads(FULL.read_text());norm={'forward':'forward','full_hex_reverse':'reverse','byte_reverse':'byte_reverse','nibble_swap':'nibble_swap'}
 even_excluded={(norm[x['orientation']],x['period']) for x in even['cells'] if x['bound_213']=='excluded_all_squares'};even_residual={(norm[x['orientation']],x['period']) for x in even['cells'] if x['bound_213']=='unresolved'}
 assert len(even_excluded)==2177 and even_residual=={('forward',562),('forward',972),('reverse',16),('reverse',514),('byte_reverse',16),('nibble_swap',850),('nibble_swap',972)}
 pilot_unsat={(x['orientation'],x['period']) for x in pilot['cells'] if x['status']=='unsat'};full_unsat={(x['orientation'],x['period']) for x in full['cells'] if x['status']=='unsat'};assert len(pilot_unsat)==7 and len(full_unsat)==9 and not pilot_unsat&full_unsat;odd_excluded=pilot_unsat|full_unsat;assert len(odd_excluded)==16 and all(p%2 for _,p in odd_excluded)
 universe=[(o,p) for o in ORIENTS for p in PERIODS];excluded=even_excluded|odd_excluded;fresh=[x for x in universe if x not in excluded];assert len(universe)==4368 and len(excluded)==2193 and len(fresh)==2175 and sum(p%2==0 for _,p in fresh)==7 and sum(p%2 for _,p in fresh)==2168
 payload=json.dumps([cell_id(*x) for x in fresh],separators=(',',':')).encode()
 return {'universe_cells':4368,'existing_even_invariant_exclusions':2177,'existing_odd_solver_exclusions':16,'existing_exclusions_total':2193,'fresh_cells':2175,'fresh_odd_cells':2168,'fresh_even_residual_cells':7,'fresh_cell_ids_sha256':hashlib.sha256(payload).hexdigest(),'fresh':fresh,'even_residual':sorted(even_residual),'periods':[1,1092],'orientations':list(ORIENTS),'bag':BAG,'prefix_bytes':PREFIX,'timeout_ms_per_cell':TIMEOUT_MS,'nominal_periods_at_or_above_1092_represented_by':1092}
def public_scope(s):return {k:([{'orientation':o,'period':p} for o,p in v] if k=='even_residual' else v) for k,v in s.items() if k!='fresh'}
def selftest():
 assert sources()==PINS and z3.get_version_string()=='4.15.3';s=derive_scope();return {'identity':IDENTITY,'target_evaluated':False,'handling':'canonical MDX/dataset hashed only; ciphertext not extracted','scope':public_scope(s),'source_hashes':sources(),'normalized_text_sha256_expected':TEXT_SHA}
def extract():
 mdx=MDX.read_text();tick=chr(96);a=mdx.index(tick+'83 B57B2')+1;b=mdx.index(tick,a);x=''.join(mdx[a:b].split()).upper();rows=json.loads(DATASET.read_text());y=''.join(next(r for r in rows if r['id']=='rev7')['ciphertext'].split()).upper();assert x==y and len(x)==1092 and hashlib.sha256(x.encode()).hexdigest()==TEXT_SHA;return x
def sqs(s):return ''.join(format(x,'X') for x in s)
def probe_decrypt(c,s,p):return bytes.fromhex(symmetry_probe.decode(c.hex().upper(),sqs(s),p))
def probe_encrypt(x,s,p):return bytes.fromhex(symmetry_probe.encode(x.hex().upper(),sqs(s),p))
def utf8_info(data):
 try:data.decode('utf-8');valid=True
 except UnicodeDecodeError:valid=False
 return {'full_bag213':all(x in BAG_VALUES for x in data),'full_utf8_valid':valid,'full_exact_endpoint':bifid16.endpoint_accepts(data)}
def solve_cell(cipher,orient,period,dump_path,fixed=None,timeout_ms=TIMEOUT_MS):
 solver,k,p,_,limit=bagmode.build(cipher,period,BAG,prefix_bytes=len(cipher),fixed=fixed,timeout_ms=timeout_ms);raw=solver.sexpr().encode();payload=gzip.compress(raw,9,mtime=0);dump_path.write_bytes(payload);t=time.perf_counter();st=solver.check();elapsed=time.perf_counter()-t;row={'cell_id':cell_id(orient,period),'orientation':orient,'period':period,'bag':BAG,'prefix_bytes':limit,'timeout_ms':timeout_ms,'ciphertext_sha256':hashlib.sha256(cipher).hexdigest(),'status':str(st),'reason_unknown':solver.reason_unknown() if st==z3.unknown else None,'elapsed_seconds':elapsed,'classified_as_negative':st==z3.unsat,'smt_dump':{'path':(str(dump_path.relative_to(HERE)) if dump_path.is_relative_to(HERE) else str(dump_path)),'smt2_sha256':hashlib.sha256(raw).hexdigest(),'gzip_sha256':sha(dump_path),'gzip_bytes':len(payload)}}
 if st==z3.sat:
  m=solver.model();square=bagmode.square(m,k);plain=bagmode.plaintext(m,p);assert plain==probe_decrypt(cipher,square,period) and probe_encrypt(plain,square,period)==cipher and all(x in BAG_VALUES for x in plain);row.update({'square':square,'plaintext_hex':plain.hex(),'plaintext_sha256':hashlib.sha256(plain).hexdigest(),'independent_decrypt_reencrypt':True,**utf8_info(plain)})
 return row
def atomic_status(state):
 tmp=STATUS.with_suffix('.json.tmp');tmp.write_text(json.dumps(state,sort_keys=True,indent=2)+'\n');os.replace(tmp,STATUS)
def require_gate():
 g=json.loads(GATE.read_text());scope=public_scope(derive_scope());assert g['identity']==IDENTITY and g['authorized'] is True and g['scope']==scope and g['driver_sha256']==sha(Path(__file__)) and g['source_hashes']==sources();return g
def run():
 if any(x.exists() for x in (OUTPUT,TMP,CHECKPOINT,STATUS,DUMPS)):raise SystemExit('refusing existing target/checkpoint/status/formula artifacts')
 gate=require_gate();s=derive_scope();text=extract();oriented={o:bytes.fromhex(orientation(text,o)) for o in ORIENTS};DUMPS.mkdir();started=time.time();rows=[];atomic_status({'identity':IDENTITY,'state':'running','completed_cells':0,'total_cells':2175,'fresh_cell_ids_sha256':s['fresh_cell_ids_sha256']})
 with CHECKPOINT.open('x') as f:
  for i,(orient,period) in enumerate(s['fresh'],1):
   row=solve_cell(oriented[orient],orient,period,DUMPS/f'{cell_id(orient,period)}.smt2.gz');f.write(json.dumps(row,sort_keys=True,separators=(',',':'))+'\n');f.flush();os.fsync(f.fileno());rows.append(row);atomic_status({'identity':IDENTITY,'state':'running','completed_cells':i,'total_cells':2175,'last_cell_id':row['cell_id'],'counts':{q:sum(x['status']==q for x in rows) for q in ('sat','unsat','unknown')},'fresh_cell_ids_sha256':s['fresh_cell_ids_sha256']})
   if i%16==0:print(json.dumps({'identity':IDENTITY,'progress':i,'total':2175,'last':row['cell_id']}),flush=True)
 summary={q:sum(x['status']==q for x in rows) for q in ('sat','unsat','unknown')};summary['negative_claims']=sum(x['classified_as_negative'] for x in rows);result={'identity':IDENTITY,'target_evaluated':True,'status':'complete','scope':gate['scope'],'normalized_text_sha256':TEXT_SHA,'source_hashes':sources(),'driver_sha256':sha(Path(__file__)),'gate_sha256':sha(GATE),'checkpoint_sha256':sha(CHECKPOINT),'cells':rows,'summary':summary,'elapsed_wall_seconds':time.time()-started,'limits':'UNSAT applies only to a fixed orientation/period under full bag213. SAT is necessary compatibility only. UNKNOWN and any interrupted partial job are unresolved.'};TMP.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');os.replace(TMP,OUTPUT);atomic_status({'identity':IDENTITY,'state':'complete','completed_cells':2175,'total_cells':2175,'summary':summary,'result_sha256':sha(OUTPUT),'checkpoint_sha256':sha(CHECKPOINT)});print(json.dumps({'identity':IDENTITY,'state':'complete','result_sha256':sha(OUTPUT),'summary':summary}))
def main():
 ap=argparse.ArgumentParser();g=ap.add_mutually_exclusive_group(required=True);g.add_argument('--selftest',action='store_true');g.add_argument('--run-target',action='store_true');a=ap.parse_args();print(json.dumps(selftest(),sort_keys=True,indent=2)) if a.selftest else run()
if __name__=='__main__':main()
