#!/usr/bin/env python3
"""Inert-until-gated 64,000-cell CrypTool100 whole-integer decoder."""
from pathlib import Path
import argparse,hashlib,json,math,os,sys
HERE=Path(__file__).resolve().parent;PKG=HERE.parent;ROOT=HERE.parents[4]
sys.path.insert(0,str(PKG));import controls as core
IDENTITY='ASTRA';MDX=ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx';DATA=ROOT/'lavender/src/data/ciphers/revelations.json'
MDX_SHA='085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91';TEXT_SHA='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c';DATA_SHA='68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e'
HEX_ORIENTS=('forward','full_hex_reverse','byte_reverse','nibble_swap');DEC_ORIENTS=('identity','digit_reverse','pair_reverse','swap_within_pair')
GATE=HERE/'target_gate.json';RESULT=HERE/'target_results.ndjson';SUMMARY=HERE/'target_summary.json'
REQUIRED=('research/rev7-20260909-codex/homophonic/cryptool100/controls.py','research/rev7-20260909-codex/homophonic/cryptool100/controls.json','research/rev7-20260909-codex/homophonic/cryptool100/build_model.py','research/rev7-20260909-codex/homophonic/cryptool100/sibling_tetragrams.json','research/rev7-20260909-codex/homophonic/cryptool100/README.md','research/rev7-20260909-codex/homophonic/cryptool100/source/functions.homo.php','research/rev7-20260909-codex/homophonic/cryptool100/source/default_tool.php','research/rev7-20260909-codex/homophonic/cryptool100/source/alfa_dat.php.base64','research/rev7-20260909-codex/homophonic/cryptool100/target/driver_controls.py','research/rev7-20260909-codex/homophonic/cryptool100/target/controls.json','research/rev7-20260909-codex/homophonic/cryptool100/target/README.md','research/rev7-20260909-codex/homophonic/cryptool100/target/prepare_gate.py','lavender/src/data/ciphers/revelations.json')
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def canon(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True)
def decimal_orient(s,name):
 assert len(s)%2==0 and s.isdigit()
 if name=='identity':return s
 if name=='digit_reverse':return s[::-1]
 if name=='pair_reverse':return ''.join(reversed([s[i:i+2] for i in range(0,len(s),2)]))
 if name=='swap_within_pair':return ''.join(s[i+1]+s[i] for i in range(0,len(s),2))
 raise ValueError(name)
def hex_orient(s,name):return core.orient(s,name)
def construct(code_stream,dname,hname):
 directed=decimal_orient(code_stream,dname); minimal_hex=format(int(directed),'X'); even_hex=('0'+minimal_hex) if len(minimal_hex)%2 else minimal_hex
 return hex_orient(even_hex,hname),{'directed_decimal_sha256':sha_bytes(directed.encode()),'minimal_hex_length':len(minimal_hex),'hex_parity_zero':len(even_hex)-len(minimal_hex)}
def recover(canonical_hex,dname,hname):
 even_hex=hex_orient(canonical_hex,hname); minimal_decimal=str(int(even_hex,16)); restored=('0'+minimal_decimal) if len(minimal_decimal)%2 else minimal_decimal
 natural=decimal_orient(restored,dname)
 side='suffix' if dname in ('digit_reverse','pair_reverse') else 'prefix'
 return natural,{'oriented_hex_sha256':sha_bytes(even_hex.encode()),'minimal_decimal_length':len(minimal_decimal),'parity_zero_restored':len(restored)-len(minimal_decimal),'additional_zero_pair_ambiguity_side':side}
def sha_bytes(b):return hashlib.sha256(b).hexdigest()
def score_model():
 counts,meta=core.train_model();return counts,sum(counts.values()),meta
def candidate_row(code_stream,dname,hname,a,b,canonical_hex,counts,total):
 plain=core.decode(code_stream,a,b); pairs=[code_stream[i:i+2] for i in range(0,len(code_stream),2)]; bd=core.decoder(a,b)
 membership=all(bd[c]==ch for c,ch in zip(pairs,plain)); rebuilt,_=construct(code_stream,dname,hname)
 return {'id':f'h={hname}|d={dname}|a={a:02d}|b={b:02d}','hex_orientation':hname,'decimal_orientation':dname,'a':a,'b':b,'plaintext':plain,'plaintext_sha256':sha_bytes(plain.encode()),'letters':len(plain),'score_per_tetragram':core.score(plain,counts,total),'observed_codes_valid_for_board':membership,'exact_integer_reencryption':rebuilt==canonical_hex}
def scope():return {'identity':IDENTITY,'hex_orientations':list(HEX_ORIENTS),'decimal_orientations':list(DEC_ORIENTS),'multipliers':list(core.coprimes100()),'rotations':100,'rows':64000,'retention':'every plaintext row; score ranks only','representation':'two-digit homophones -> decimal orientation -> whole integer -> uppercase even-length hex -> hex orientation','leading_zero_ambiguity':'restore one decimal zero for pair phase; further 00 pairs are unknown prefix or suffix according to decimal orientation'}
def parse_target():
 assert sha(MDX)==MDX_SHA and sha(DATA)==DATA_SHA
 t=MDX.read_text();a=t.index('`83 B57B2')+1;b=t.index('`',a);raw=''.join(t[a:b].split()).upper();assert len(raw)==1092 and sha_bytes(raw.encode())==TEXT_SHA
 rows=json.loads(DATA.read_text()); rec=next(r for r in rows if r.get('id')=='rev7')
 dataset_raw=''.join(rec['ciphertext'].split()).upper();assert dataset_raw==raw and sha_bytes(dataset_raw.encode())==TEXT_SHA
 return raw
def require_gate():
 g=json.loads(GATE.read_text());assert g['identity']==IDENTITY and g['target_evaluated'] is False and g['scope']==scope();assert g['driver_sha256']==sha(Path(__file__)) and g['mdx_sha256']==MDX_SHA and g['canonical_text_sha256']==TEXT_SHA and g['dataset_sha256']==DATA_SHA
 assert sha(MDX)==MDX_SHA and sha(DATA)==DATA_SHA and core.verify_sources()==core.EXPECTED_H
 assert set(g['artifact_hashes'])==set(REQUIRED)
 for rel,h in g['artifact_hashes'].items():assert sha(ROOT/rel)==h
 return g
def execute(canonical_hex,row_sink):
 counts,total,_=score_model();alphas=core.coprimes100();paths=[];tops={};n=0
 for hn in HEX_ORIENTS:
  for dn in DEC_ORIENTS:
   codes,meta=recover(canonical_hex,dn,hn);assert len(codes)%2==0 and codes.isdigit()
   path=f'h={hn}|d={dn}';path_rows=[]
   for a in alphas:
    for b in range(100):
     r=candidate_row(codes,dn,hn,a,b,canonical_hex,counts,total);assert r['observed_codes_valid_for_board'] and r['exact_integer_reencryption'];row_sink(r);path_rows.append(r);n+=1
   best=sorted(path_rows,key=lambda r:(-r['score_per_tetragram'],r['a'],r['b']))[:20]
   tops[path]=[{k:r[k] for k in ('id','a','b','score_per_tetragram','plaintext_sha256','plaintext')} for r in best]
   paths.append({'id':path,'code_stream':codes,'code_stream_sha256':sha_bytes(codes.encode()),'digits':len(codes),**meta,'rows':4000})
 assert n==64000
 return {'paths':paths,'top20_by_path':tops,'rows':n}
def run_target():
 tmp=RESULT.with_suffix('.ndjson.tmp'); summary_tmp=SUMMARY.with_suffix('.json.tmp')
 if any(x.exists() for x in (RESULT,SUMMARY,tmp,summary_tmp)):raise SystemExit('refusing existing target output or temporary file')
 gate=require_gate();raw=parse_target();digest=hashlib.sha256()
 with tmp.open('w') as f:
  header={'identity':IDENTITY,'record':'header','target_evaluated':True,'scope':scope(),'gate_sha256':sha(GATE),'driver_sha256':sha(Path(__file__)),'canonical_text_sha256':TEXT_SHA};line=canon(header)+'\n';f.write(line);digest.update(line.encode())
  def sink(r):
   line=canon({'identity':IDENTITY,'record':'candidate',**r})+'\n';f.write(line);digest.update(line.encode())
  agg=execute(raw,sink)
 os.replace(tmp,RESULT)
 summary={'identity':IDENTITY,'target_evaluated':True,'scope':scope(),'result_path':RESULT.name,'result_sha256':sha(RESULT),'result_bytes':RESULT.stat().st_size,'record_count':64001,'aggregate':agg,'configuration':{'gate_sha256':sha(GATE),'driver_sha256':sha(Path(__file__)),'artifact_hashes':gate['artifact_hashes'],'mdx_sha256':MDX_SHA,'dataset_sha256':DATA_SHA,'canonical_text_sha256':TEXT_SHA}}
 t=summary_tmp;t.write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n');os.replace(t,SUMMARY);print(json.dumps({'identity':IDENTITY,'rows':64000,'result_sha256':sha(RESULT),'summary_sha256':sha(SUMMARY)},sort_keys=True))
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--run-target',action='store_true');a=ap.parse_args()
 if a.run_target:run_target()
 else:
  if GATE.exists():require_gate()
  assert sha(MDX)==MDX_SHA and sha(DATA)==DATA_SHA
  print(json.dumps({'identity':IDENTITY,'target_evaluated':False,'handling':'MDX and dataset bytes hashed only; ciphertext not extracted, converted, decoded, or scored','scope':scope(),'driver_sha256':sha(Path(__file__)),'gate_present':GATE.exists()},indent=2,sort_keys=True))
if __name__=='__main__':main()
