#!/usr/bin/env python3
"""ASTRA inert limb-local decimal/checkerboard target driver; root gate required."""
from pathlib import Path
from collections import Counter
import argparse,hashlib,importlib.util,itertools,json,subprocess,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
MODEL=HERE/'model.py';ANNEAL=HERE/'anneal.py';CHAR_MODEL=HERE/'sibling_char4.json';OUT=HERE/'target_results.json';TMP=HERE/'target_results.tmp';GATE=HERE/'target_gate.json'
MDX=ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx';DATA=ROOT/'lavender/src/data/ciphers/revelations.json'
MDX_SHA='085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91';DATA_SHA='68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e';TEXT_SHA='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c'
PINS={'model.py': '1f479f1697d84ee16a2cd9f89568756b9d30878418fe810206da9c683bc14725', 'controls.py': 'f771d92d014a02a423585d6d27adf79ae89702ba57d634770bee0560d80cb632', 'controls.json': '51ae541d6f08c62521630d4ac4bb19c786e0348170567abb1986dae005778a96', 'anneal.py': '6937961a714e4ec0e26b5d1c5584f001d8b6a381155f76b0e79c8477246c6d79', 'build_char_model.py': '2a97582daab4507f1fed524568ad3ceccdc73b2c581383590402ee1e1af7434b', 'sibling_char4.json': '7752ce6f93d12079cf9e567d9f0dddf37178f8b40f7907ee6d7c733383969b01', 'anneal_controls.py': 'e2b4befefd0ecd6c3338063976c73a63bf516c4a9c1ae499f02cd2118976d072', 'anneal_controls.json': '43392045bdf475a16ad80fb391a1d6e54b40cfe3b62a2d0334a7da780e621615', 'README.md': '8271108a3e820f2aeb17853705a6d8e6e9fa8dbdd107df0247387c2263ccb06f'}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def shab(b):return hashlib.sha256(b).hexdigest()
def load(name,p):
 s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
def preflight(require_gate=False):
 for name,want in PINS.items():assert sha(HERE/name)==want,(name,sha(HERE/name),want)
 if require_gate:
  g=json.loads(GATE.read_text());assert g['identity']=='ASTRA' and g['authorization']['root_go_required'] is True and g['authorization']['go_granted'] is True
  assert g['driver_sha256']==sha(Path(__file__)) and g['scope']==scope()
def scope():return {'canonical_bytes':546,'limb_framing':'136 unsigned 4-byte limbs width10 plus exact unsigned 2-byte tail width5','orientations':['forward','full_hex_reverse','byte_reverse','nibble_swap'],'endianness':['big','little'],'limb_orders':['forward','reverse'],'digit_directions':['forward','reverse'],'serializers':32,'header_pairs':'all 45 unordered pairs in lexicographic order','exact_cells':1440,'unknown_board_capacity':28,'fixed_rev3':{'headers':[3,7],'alphabet':'FKMCPDYEHBIGQROSAZLUTJNWVX'},'heuristic':{'deduplicate':'exact token tuples','selection':'top 20 by descending token IoC, then stable first recipe id','alphabet':'ABCDEFGHIJKLMNOPQRSTUVWXYZ .','restarts':4,'steps_per_restart':6000,'base_seed':20260910}}
def extract():
 assert sha(MDX)==MDX_SHA and sha(DATA)==DATA_SHA
 text=MDX.read_text();a=text.index('`83 B57B')+1;z=text.index('`',a);x=''.join(text[a:z].split()).upper()
 d=''.join(next(r for r in json.loads(DATA.read_text()) if r.get('id')=='rev7')['ciphertext'].split()).upper()
 assert x==d and len(x)==1092 and shab(x.encode())==TEXT_SHA;return x
def ioc(tokens):
 n=len(tokens)
 if n<2:return 0.0
 c=Counter(tokens);return sum(v*(v-1) for v in c.values())/(n*(n-1))
def scan(canonical):
 m=load('limb32_target_model',MODEL);serializers=[];rows=[];patterns={}
 for ori,endian,order,direction in itertools.product(m.ORIENTATIONS,m.ENDIANS,m.ORDERS,m.DIRECTIONS):
  hx=m.orient_hex(canonical,ori);raw=bytes.fromhex(hx);digits=m.serialize(raw,endian,order,direction)
  assert len(digits)==sum(m.decimal_width(n) for n in m.chunk_lengths(len(raw))) and m.deserialize(digits,len(raw),endian,order,direction)==raw
  sid=f'ori={ori}|endian={endian}|limbs={order}|digits={direction}'
  serializers.append({'id':sid,'orientation':ori,'oriented_hex_sha256':shab(hx.encode()),'oriented_bytes_sha256':shab(raw),'endianness':endian,'limb_order':order,'digit_direction':direction,'decimal_digits':digits,'decimal_sha256':shab(digits.encode()),'decimal_length':len(digits),'roundtrip_exact':True})
  for headers in m.all_headers():
   tokens=m.parse_tokens(digits,headers);rid=f'{sid}|headers={headers[0]},{headers[1]}'
   row={'id':rid,'serializer_id':sid,'headers':list(headers),'complete':tokens is not None}
   if tokens is not None:
    rebuilt=''.join(tokens);assert rebuilt==digits
    key='|'.join(tokens);row.update({'token_count':len(tokens),'distinct_tokens':len(set(tokens)),'token_ioc':ioc(tokens),'token_sequence_sha256':shab(key.encode()),'capacity_28_compatible':len(set(tokens))<=28})
    patterns.setdefault(tuple(tokens),[]).append(rid)
    if headers==m.REV3_HEADERS:
     plain=m.decode_fixed(digits);row['fixed_rev3_plaintext']=plain;row['fixed_rev3_complete']=plain is not None
     if plain is not None:assert m.encode_fixed(plain)==digits
   else:row.update({'token_count':None,'distinct_tokens':None,'token_ioc':None,'token_sequence_sha256':None,'capacity_28_compatible':False})
   rows.append(row)
 assert len(serializers)==32 and len(rows)==1440
 pats=[]
 for tokens,aliases in patterns.items():
  pats.append({'tokens':list(tokens),'token_sequence_sha256':shab('|'.join(tokens).encode()),'aliases':aliases,'first_id':aliases[0],'token_count':len(tokens),'distinct_tokens':len(set(tokens)),'token_ioc':ioc(tokens)})
 pats.sort(key=lambda r:(-r['token_ioc'],r['first_id']))
 return serializers,rows,pats
def build():
 m=load('limb32_target_model_build',MODEL);a=load('limb32_target_anneal',ANNEAL);canonical=extract();serializers,rows,patterns=scan(canonical);lang=json.loads(CHAR_MODEL.read_text());selected=[]
 for rank,p in enumerate(patterns[:20],1):
  fit=a.anneal(p['tokens'],lang,restarts=4,steps=6000,seed=20260910+(rank-1)*100)
  for rr in fit['restarts_retained']:
   assert rr['plaintext']==''.join(rr['mapping'][t] for t in p['tokens']) and rr['plaintext_sha256']==shab(rr['plaintext'].encode())
  selected.append({**p,'selection_rank':rank,'anneal':fit})
 fixed=[r for r in rows if r['headers']==[3,7] and r.get('fixed_rev3_complete')]
 return {'identity':'ASTRA','status':'complete','target_evaluated':True,'scope':scope(),'configuration':{'source_hashes':{**PINS,'run_target.py':sha(Path(__file__))},'target_gate_sha256':sha(GATE),'mdx_sha256':MDX_SHA,'dataset_sha256':DATA_SHA,'canonical_text_sha256':TEXT_SHA},'serializers':serializers,'cells':rows,'pattern_summary':{'complete_cells':sum(r['complete'] for r in rows),'incomplete_cells':sum(not r['complete'] for r in rows),'unique_complete_token_sequences':len(patterns),'distinct_cell_distribution':dict(sorted(Counter(r['distinct_tokens'] for r in rows if r['complete']).items())),'fixed_rev3_complete':len(fixed)},'selected_heuristic_candidates':selected,'fixed_rev3_complete_outputs':fixed,'limits':['The exact portion is representation, parsing, deduplication, capacity and reconstruction.','IoC selection and substitution annealing are heuristic; a negative cannot exclude other patterns or assignments.','The 32-bit/u16-tail framing is a bounded invented hypothesis motivated by the solved-corpus representation boundary, not recovered source behavior.']}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--run-target',action='store_true');z=ap.parse_args();preflight(z.run_target)
 if z.run_target:
  assert not OUT.exists() and not TMP.exists(),'refusing existing result/tmp';out=build();TMP.write_text(json.dumps(out,sort_keys=True,indent=2)+'\n');TMP.replace(OUT);print(json.dumps({'identity':'ASTRA','complete':True,'result_sha256':sha(OUT),'bytes':OUT.stat().st_size,'summary':out['pattern_summary']},sort_keys=True));return
 print(json.dumps({'identity':'ASTRA','preflight':True,'target_evaluated':False,'gate_exists':GATE.exists(),'result_exists':OUT.exists(),'scope':scope(),'run_command':'python3 -B research/rev7-20260909-codex/coverage/limb32_checkerboard/run_target.py --run-target'},sort_keys=True))
if __name__=='__main__':main()
