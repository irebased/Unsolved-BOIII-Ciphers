#!/usr/bin/env python3
"""ASTRA inert 2184-cell odd-period single-typed-graph target driver."""
from __future__ import annotations
import argparse,hashlib,importlib.util,itertools,json,os,sys,time
from pathlib import Path
IDENTITY='ASTRA';HERE=Path(__file__).resolve().parent;PKG=HERE.parent;ROOT=HERE.parents[3]
MODEL=PKG/'odd_single_graph_filter/model.py';MDX=ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx';DATA=ROOT/'lavender/src/data/ciphers/revelations.json'
GATE=HERE/'target_gate.json';RESULT=HERE/'target_results.json';TMP=HERE/'target_results.json.tmp'
ORIENTS=('forward','reverse','byte_reverse','nibble_swap');PERIODS=tuple(range(1,1092,2));KINDS=('RR','RC','CR','CC');N=1092
MDX_SHA='085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91';DATA_SHA='68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e';TEXT_SHA='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c'
PARENT_PINS={
'odd_single_graph_filter/model.py':'924ea3a4acc7618be25b1cbf92952115805fa898448c402727e922d1f4526014',
'odd_single_graph_filter/controls.py':'637d1aae658dc93e68872b54ce100240bba93c64b91fa91aa8f577ca4f624827',
'odd_single_graph_filter/controls.json':'afb1eb9bafb4221c86feef4f1e32120dde790255a982a458b04365fb3cfbe3a2',
'odd_single_graph_filter/README.md':'4136e2206426ae8830f0bef7544e6869e1c58380307535e25ba0c384ecbc0882',
'odd_typed_rectangles/controls.py':'31f9b11bb8849be786548508ad7d5843eff991a0de9ff538cd8d377c430b1426',
'odd_typed_rectangles/controls.json':'e931ff2d471d089cb498f8e01733c82c62c2f2400d86fa527ff0d956bf9ecb6a',
'odd_typed_rectangles/README.md':'df5d2438fdcfb9b57a1ad93bdda72d4db991beea1acc4379f228c5c63d38195a'}
def hb(x):return hashlib.sha256(x).hexdigest()
def sha(p):return hb(Path(p).read_bytes())
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':')).encode()
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
MODEL_MOD=load('astra_single_graph_model',MODEL)
def orient(s,name):
 assert len(s)%2==0
 if name=='forward':return s
 if name=='reverse':return s[::-1]
 pairs=[s[i:i+2] for i in range(0,len(s),2)]
 if name=='byte_reverse':return ''.join(reversed(pairs))
 if name=='nibble_swap':return ''.join(x[::-1] for x in pairs)
 raise ValueError(name)
def scope():return {'identity':IDENTITY,'model':'two arbitrary fixed 4x4 Bifid squares; any individually impossible nonempty typed high-nibble graph excludes bag213','orientations':list(ORIENTS),'odd_periods':[1,1091,2],'period_count':546,'cells':2184,'ciphertext_symbols':N,'plaintext_bytes':546,'typed_graphs':list(KINDS),'endpoint':'bag213 necessary condition via absence of high nibble 1 only','retention':'compact edge masks, source-index metadata digest, per-type first-set feasible counts and deterministic all-1820-record digests; feasible means unresolved'}
def source_pins():
 out={f'research/rev7-20260909-codex/bifid16_controls/{k}':v for k,v in PARENT_PINS.items()}
 for rel in ('driver_controls.py','driver_controls.json','README.md'):
  q=HERE/rel
  if q.exists():out[f'research/rev7-20260909-codex/bifid16_controls/odd_single_graph_target/{rel}']=sha(q)
 out['lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx']=sha(MDX);out['lavender/src/data/ciphers/revelations.json']=sha(DATA)
 return out
def check_parents():
 for rel,want in PARENT_PINS.items():assert sha(PKG/rel)==want,(rel,sha(PKG/rel),want)
 assert sha(MDX)==MDX_SHA and sha(DATA)==DATA_SHA
def metadata(n,p):
 assert n%2==0 and 1<=p<=n and p%2==1
 rows=[]
 for start in range(0,n,p):
  L=min(p,n-start);meta=[]
  for j in range(L):meta.extend((('R',start+j),('C',start+j)))
  for i in range(L):
   if (start+i)%2==0:
    a,b=meta[i],meta[L+i];rows.append((a[0]+b[0],a[1],b[1],start,L,i))
 assert len(rows)==n//2
 return rows
def graph_from(cipher,rows,kind):return {(cipher[ai],cipher[bi]) for k,ai,bi,_s,_L,_i in rows if k==kind}
def graph_hex(edges):return format(sum(1<<(16*a+b) for a,b in edges),'064x')
def edges_from_hex(value):
 g=int(value,16);return [(i//16,i%16) for i in range(256) if g>>i&1]
def mask_digest(records):return hb(canonical(records))
def type_record(cipher,rows,kind):
 edges=graph_from(cipher,rows,kind);gh=graph_hex(edges)
 if not edges:return {'kind':kind,'edge_count':0,'graph_hex':gh,'classification':'no_constraints','feasible':True,'surviving_first_sets':1820,'checked_first_sets':0,'all_first_set_records_sha256':None,'exclusion_certificate':None}
 got=MODEL_MOD.analyze(edges,kind,4,retain=True);digest=mask_digest(got['records'])
 exclusion=None
 if not got['feasible']:exclusion={'method':'all 1820 allowed first classes rejected by exact intersection test','all_first_set_records_sha256':digest,'graph_hex':gh}
 return {'kind':kind,'edge_count':len(edges),'graph_hex':gh,'classification':'feasible_unresolved' if got['feasible'] else 'impossible_excluded','feasible':got['feasible'],'surviving_first_sets':got['surviving_first_sets'],'checked_first_sets':got['checked_first_sets'],'first_witness':got['witness'],'all_first_set_records_sha256':digest,'exclusion_certificate':exclusion}
def scan_cell(cipher,orientation,period):
 assert len(cipher)==N and all(0<=x<16 for x in cipher) and period in PERIODS
 rows=metadata(N,period);types=[type_record(cipher,rows,k) for k in KINDS];bad=[x['kind'] for x in types if x['classification']=='impossible_excluded']
 meta=[{'type':k,'a_index':a,'b_index':b,'block_start':s,'block_length':L,'local_nibble':i} for k,a,b,s,L,i in rows]
 return {'id':f'{orientation}:p{period}','orientation':orientation,'period':period,'actual_block_lengths':[min(period,N-a) for a in range(0,N,period)],'source_index_metadata_sha256':hb(canonical(meta)),'high_nibble_positions':len(rows),'type_position_counts':{k:sum(x[0]==k for x in rows) for k in KINDS},'types':types,'excluded_two_square_bag213':bool(bad),'impossible_types':bad,'status':'excluded' if bad else 'unresolved'}
def extract():
 text=MDX.read_text();a=text.index('`83 B57B2')+1;b=text.index('`',a);raw=''.join(text[a:b].split()).upper();data=''.join(next(x for x in json.loads(DATA.read_text()) if x.get('id')=='rev7')['ciphertext'].split()).upper();assert raw==data and len(raw)==N and hb(raw.encode())==TEXT_SHA and set(raw)==set('0123456789ABCDEF');return raw
def require_gate():
 g=json.loads(GATE.read_text());assert g['identity']==IDENTITY and g['target_evaluated'] is False and g['authorized'] is True and g['scope']==scope();assert g['driver_sha256']==sha(Path(__file__)) and g['source_pins']==source_pins();return g
def independent_metadata(n,p):
 # Independent direct flat-index derivation; does not call metadata().
 out=[]
 for start in range(0,n,p):
  L=min(p,n-start)
  for i in range(L):
   if (start+i)%2:continue
   lf=i;rf=L+i;la='R' if lf%2==0 else 'C';ra='R' if rf%2==0 else 'C'
   out.append((la+ra,start+lf//2,start+rf//2,start,L,i))
 assert len(out)==n//2
 return out
def verify_cell(row,cipher):
 rebuilt=scan_cell(cipher,row['orientation'],row['period']);assert row==rebuilt
 direct=independent_metadata(len(cipher),row['period'])
 material=[{'type':k,'a_index':a,'b_index':b,'block_start':st,'block_length':L,'local_nibble':i} for k,a,b,st,L,i in direct]
 assert hb(canonical(material))==row['source_index_metadata_sha256']
 for tr in row['types']:
  edges={(cipher[a],cipher[b]) for k,a,b,_st,_L,_i in direct if k==tr['kind']}
  assert graph_hex(edges)==tr['graph_hex'] and len(edges)==tr['edge_count']
  if tr['edge_count']:
   got=MODEL_MOD.analyze(edges_from_hex(tr['graph_hex']),tr['kind'],4,retain=True);assert got['surviving_first_sets']==tr['surviving_first_sets'] and got['checked_first_sets']==1820 and mask_digest(got['records'])==tr['all_first_set_records_sha256']
 return True
def verify_results():
 check_parents();g=require_gate();d=json.loads(RESULT.read_text());assert d['identity']==IDENTITY and d['target_evaluated'] is True and d['scope']==scope() and d['configuration']['gate_sha256']==sha(GATE) and d['configuration']['driver_sha256']==sha(Path(__file__)) and d['configuration']['source_pins']==source_pins()
 raw=extract();expected=[(o,p) for o in ORIENTS for p in PERIODS];assert len(d['cells'])==len(expected)==2184
 counts={'excluded':0,'unresolved':0}
 for row,(o,p) in zip(d['cells'],expected):
  assert (row['orientation'],row['period'])==(o,p);cipher=[int(x,16) for x in orient(raw,o)];verify_cell(row,cipher);counts[row['status']]+=1
 expected_by_type={k:sum(k in x['impossible_types'] for x in d['cells']) for k in KINDS}
 assert d['status']=='complete' and d['summary']['cells']==2184 and d['summary']['status_counts']==counts and d['summary']['excluded_by_type']==expected_by_type and counts['excluded']+counts['unresolved']==2184
 assert d['configuration']['mdx_sha256']==MDX_SHA and d['configuration']['dataset_sha256']==DATA_SHA and d['configuration']['canonical_text_sha256']==TEXT_SHA
 print(json.dumps({'identity':IDENTITY,'verification_only':True,'new_target_search':False,'result_sha256':sha(RESULT),'cells':2184,'status_counts':counts,'excluded_by_type':expected_by_type},sort_keys=True))
def run_target():
 check_parents();g=require_gate();assert not RESULT.exists() and not TMP.exists(),'refusing existing result/tmp';raw=extract();cells=[];t=time.time()
 for o in ORIENTS:
  cipher=[int(x,16) for x in orient(raw,o)]
  for p in PERIODS:cells.append(scan_cell(cipher,o,p))
 counts={s:sum(x['status']==s for x in cells) for s in ('excluded','unresolved')};out={'identity':IDENTITY,'target_evaluated':True,'status':'complete','scope':scope(),'configuration':{'gate_sha256':sha(GATE),'driver_sha256':sha(Path(__file__)),'source_pins':source_pins(),'mdx_sha256':MDX_SHA,'dataset_sha256':DATA_SHA,'canonical_text_sha256':TEXT_SHA},'cells':cells,'summary':{'cells':len(cells),'status_counts':counts,'excluded_by_type':{k:sum(k in x['impossible_types'] for x in cells) for k in KINDS},'elapsed_seconds':time.time()-t}}
 TMP.write_text(json.dumps(out,sort_keys=True,indent=2)+'\n');os.replace(TMP,RESULT);print(json.dumps({'identity':IDENTITY,'result_sha256':sha(RESULT),**out['summary']},sort_keys=True))
def main():
 ap=argparse.ArgumentParser();g=ap.add_mutually_exclusive_group();g.add_argument('--run-target',action='store_true');g.add_argument('--verify',action='store_true');a=ap.parse_args()
 if a.run_target:run_target()
 elif a.verify:verify_results()
 else:check_parents();print(json.dumps({'identity':IDENTITY,'target_evaluated':False,'canonical_handling':'MDX and dataset hashes checked only; target ciphertext not extracted','scope':scope(),'driver_sha256':sha(Path(__file__)),'gate_present':GATE.exists()},sort_keys=True,indent=2))
if __name__=='__main__':main()
