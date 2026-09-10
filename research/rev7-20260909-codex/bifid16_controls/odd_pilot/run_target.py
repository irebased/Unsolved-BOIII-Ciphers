#!/usr/bin/env python3
"""ASTRA inert odd-period Bifid16 QF_BV prefix-bag pilot."""
from __future__ import annotations
import argparse,gzip,hashlib,json,os,sys,time
from pathlib import Path
HERE=Path(__file__).resolve().parent;PACKAGE=HERE.parent;REPO=HERE.parents[3]
sys.path.insert(0,str(PACKAGE));import bagmode,bifid16,symmetry_probe
z3=bagmode.z3
IDENTITY="ASTRA";PERIODS=(3,31,99,1091);ORIENTS=("forward","reverse","byte_reverse","nibble_swap")
PREFIX=128;BAG=213;TIMEOUT_MS=10000
MDX=REPO/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx';DATASET=REPO/'lavender/src/data/ciphers/revelations.json';OUTPUT=HERE/'target_results.json';GATE=HERE/'target_gate.json';DUMPS=HERE/'smt'
TEXT_SHA='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c'
PINS={
'bagmode.py':'ec21d22691016d2a331a0c8a14c0573306b88ac6db772c8a6c5de64409597e06','bifid16.py':'a80c5f839511454a11a473cbfa4734bf3452656c8015e15ac759f65f45bf9af7','bagmode_controls.py':'6aa56ea3298ab53b6a862a724b481d9078f529dee569d0b5bb4e438e4326dda8','bagmode_controls.json':'380c7e0573e7e541e19d66331847e5d71c2f8ee6bc735d6b8aa9dbf45ce311bb','audit_controls.py':'4261a5df90d45e3b04482ddbddf5a793f4209f3a12678c23b068a171243c6b25','audit.json':'d984d8c9ea8118e85d7f21bb226df28925392141bbf4af6d9f8e1951c6892aec','symmetry_probe.py':'8bf072deccafabe1e98db126178207d9cf3c8eccdcab6902a28b0c0d123a26e0','dependency/dependency.json':'e88e7bf34243264705ca5fcaa66acb5c9db96f289192a862e0e063a915897e4e','dependency/runtime/z3/lib/libz3.dylib':'3164e079c221c23a843396a485a6e912ee423918ee64ea03943e584305439a98','rev7_mdx':'085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91','dataset':'68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e'}
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
def selftest():
 assert sources()==PINS
 assert z3.get_version_string()=='4.15.3'
 for n in ORIENTS:assert orientation('123456',n)=={'forward':'123456','reverse':'654321','byte_reverse':'563412','nibble_swap':'214365'}[n]
 return {'identity':IDENTITY,'target_evaluated':False,'handling':'canonical source files hashed only; ciphertext not extracted','scope':{'periods':list(PERIODS),'orientations':list(ORIENTS),'cells':16,'bag':BAG,'prefix_bytes':PREFIX,'timeout_ms_per_cell':TIMEOUT_MS},'source_hashes':sources(),'normalized_text_sha256_expected':TEXT_SHA}
def extract():
 mdx=MDX.read_text();tick=chr(96);start=mdx.index(tick+'83 B57B2')+1;end=mdx.index(tick,start);a=''.join(mdx[start:end].split()).upper()
 rows=json.loads(DATASET.read_text());b=''.join(next(x for x in rows if x['id']=='rev7')['ciphertext'].split()).upper()
 assert a==b and len(a)==1092 and hashlib.sha256(a.encode()).hexdigest()==TEXT_SHA
 return a
def probe_decrypt(cipher,square,period):
 return bytes.fromhex(symmetry_probe.decode(cipher.hex().upper(),''.join(format(x,'X') for x in square),period))
def probe_encrypt(plain,square,period):
 return bytes.fromhex(symmetry_probe.encode(plain.hex().upper(),''.join(format(x,'X') for x in square),period))
def utf8_info(data):
 try:data.decode('utf-8');valid=True
 except UnicodeDecodeError:valid=False
 return {'full_bag213':all(x in BAG_VALUES for x in data),'full_utf8_valid':valid,'full_exact_endpoint':bifid16.endpoint_accepts(data)}
def solve_cell(cipher,orientation_name,period,dump_path=None,fixed=None,timeout_ms=TIMEOUT_MS):
 solver,k,p,_,limit=bagmode.build(cipher,period,BAG,prefix_bytes=PREFIX,fixed=fixed,timeout_ms=timeout_ms)
 sexpr=solver.sexpr().encode();dump_sha=hashlib.sha256(sexpr).hexdigest()
 if dump_path is not None:
  payload=gzip.compress(sexpr,compresslevel=9,mtime=0);dump_path.write_bytes(payload)
  dump_rel=str(dump_path.relative_to(HERE)) if dump_path.is_relative_to(HERE) else str(dump_path)
  dump={'path':dump_rel,'smt2_sha256':dump_sha,'gzip_sha256':sha(dump_path),'gzip_bytes':len(payload)}
 else:dump={'path':None,'smt2_sha256':dump_sha,'gzip_sha256':None,'gzip_bytes':None}
 t=time.perf_counter();status=solver.check();elapsed=time.perf_counter()-t
 row={'cell_id':f'{orientation_name}_p{period}','orientation':orientation_name,'period':period,'bag':BAG,'prefix_bytes':limit,'timeout_ms':timeout_ms,'ciphertext_sha256':hashlib.sha256(cipher).hexdigest(),'status':str(status),'reason_unknown':solver.reason_unknown() if status==z3.unknown else None,'elapsed_seconds':elapsed,'classified_as_negative':status==z3.unsat,'smt_dump':dump}
 if status==z3.sat:
  m=solver.model();square=bagmode.square(m,k);plain=bagmode.plaintext(m,p)
  independent=probe_decrypt(cipher,square,period)
  assert plain==independent==bifid16.decrypt_bytes(cipher,square,period) and probe_encrypt(plain,square,period)==cipher and bifid16.encrypt_bytes(plain,square,period)==cipher and all(x in BAG_VALUES for x in plain[:limit])
  row.update({'square':square,'plaintext_hex':plain.hex(),'plaintext_sha256':hashlib.sha256(plain).hexdigest(),'independent_complete_decrypt_equal':True,'independent_reencrypt_equal':True,'prefix_bag213':True,**utf8_info(plain)})
 return row
def require_gate():
 g=json.loads(GATE.read_text());assert g['identity']==IDENTITY and g['authorized'] is True and g['scope']=={'periods':list(PERIODS),'orientations':list(ORIENTS),'bag':BAG,'prefix_bytes':PREFIX,'timeout_ms_per_cell':TIMEOUT_MS,'cells':16};assert g['driver_sha256']==sha(Path(__file__));assert g['source_hashes']==sources();return g
def run():
 if OUTPUT.exists() or OUTPUT.with_suffix('.json.tmp').exists():raise SystemExit('refusing existing target output')
 gate=require_gate();text=extract();DUMPS.mkdir(exist_ok=False);cells=[]
 for orient in ORIENTS:
  cipher=bytes.fromhex(orientation(text,orient))
  for period in PERIODS:cells.append(solve_cell(cipher,orient,period,DUMPS/f'{orient}_p{period}.smt2.gz'))
 result={'identity':IDENTITY,'target_evaluated':True,'scope':gate['scope'],'normalized_text_sha256':TEXT_SHA,'source_hashes':sources(),'driver_sha256':sha(Path(__file__)),'gate_sha256':sha(GATE),'cells':cells,'summary':{'sat':sum(x['status']=='sat' for x in cells),'unsat':sum(x['status']=='unsat' for x in cells),'unknown':sum(x['status']=='unknown' for x in cells),'negative_claims':sum(x['classified_as_negative'] for x in cells)},'limits':'UNSAT excludes only the exact orientation/period under the first-128-byte bag213 necessary condition. SAT is compatibility only; UNKNOWN is unresolved.'}
 tmp=OUTPUT.with_suffix('.json.tmp');tmp.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');os.replace(tmp,OUTPUT);print(json.dumps({'identity':IDENTITY,'result_sha256':sha(OUTPUT),'summary':result['summary']}))
def main():
 ap=argparse.ArgumentParser();g=ap.add_mutually_exclusive_group(required=True);g.add_argument('--selftest',action='store_true');g.add_argument('--run-target',action='store_true');a=ap.parse_args();print(json.dumps(selftest(),sort_keys=True,indent=2)) if a.selftest else run()
if __name__=='__main__':main()
