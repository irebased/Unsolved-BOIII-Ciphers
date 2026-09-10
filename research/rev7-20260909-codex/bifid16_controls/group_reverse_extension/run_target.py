#!/usr/bin/env python3
"""Inert driver for one visible-token reversal G; canonical evaluation requires --run-target and a root gate."""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,os
from pathlib import Path
IDENTITY='ASTRA';HERE=Path(__file__).resolve().parent;PKG=HERE.parent;ROOT=HERE.parents[3]
MDX=ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx';DATA=ROOT/'lavender/src/data/ciphers/revelations.json'
MDX_SHA='085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91';DATA_SHA='68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e';TEXT_SHA='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c'
OUT=HERE/'target_results.json';TMP=HERE/'target_results.json.tmp';CHECK=HERE/'checkpoint.jsonl';GATE=HERE/'target_gate.json'
JOIN_CAP=1_000_000;CROSS_CAP=10_000
DEPS={
'bifid16_controls/bifid16.py':'a80c5f839511454a11a473cbfa4734bf3452656c8015e15ac759f65f45bf9af7',
'bifid16_controls/even_period_invariant.py':'1fa72b75ff59028ed256dbf6853dd44669cd53b07bcce998331e212b65d2a2a2',
'bifid16_controls/even_period_invariant.json':'f6f2d01801992bb145c583fdc83284ea100c99d30bf4f3e5a477b56317a84a36',
'bifid16_controls/even_rectangle_controls/model.py':'46c1f18e473450aba5dde3675b594d9f0b86f28d4a670514e10a806a92942e84',
'bifid16_controls/even_rectangle_controls/controls.json':'9f443af6c503d7fc377551b2842d5f701a21649d910d9aebdaf30597efe17f57',
'bifid16_controls/odd_single_graph_filter/model.py':'924ea3a4acc7618be25b1cbf92952115805fa898448c402727e922d1f4526014',
'bifid16_controls/odd_single_graph_filter/controls.json':'afb1eb9bafb4221c86feef4f1e32120dde790255a982a458b04365fb3cfbe3a2',
'bifid16_controls/odd_rectangle_join/model.py':'221ea25d48f80a26476e1fe4abea0e89e099bf35f4325ed8e8f7aef6bd00be45',
'bifid16_controls/odd_rectangle_join/controls.json':'62c78645ffd10d892e54225a88917a63ad7e8fee99f80f1b1feae3788440dc23',
'bifid16_controls/odd_typed_rectangles/controls.json':'e931ff2d471d089cb498f8e01733c82c62c2f2400d86fa527ff0d956bf9ecb6a'}
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
BASE=PKG;EVEN=load('gre_even',BASE/'even_rectangle_controls/model.py');SINGLE=load('gre_single',BASE/'odd_single_graph_filter/model.py');JOIN=load('gre_join',BASE/'odd_rectangle_join/model.py')
def chunks_left(seq,w=5):return [seq[i:i+w] for i in range(0,len(seq),w)]
def group_reverse_forward(seq,w=5):return type(seq)().join(reversed(chunks_left(seq,w))) if isinstance(seq,str) else sum((list(x) for x in reversed(chunks_left(seq,w))),[])
def group_reverse_inverse(seq,w=5):
 r=len(seq)%w;parts=(([seq[:r]] if r else [])+[seq[i:i+w] for i in range(r,len(seq),w)])
 return type(seq)().join(reversed(parts)) if isinstance(seq,str) else sum((list(x) for x in reversed(parts)),[])
def block_lengths(n,p):return [min(p,n-a) for a in range(0,n,p)]
def even_pairs(s,p):
 out=[]
 for a in range(0,len(s),p):
  b=s[a:a+p];assert len(b)%2==0;h=len(b)//2;out += [(b[j]<<4)|b[h+j] for j in range(h)]
 return bytes(out)
def odd_graphs(s,p):
 graphs={k:set() for k in ('RC','CR','RR','CC')};positions=[]
 for a in range(0,len(s),p):
  L=min(p,len(s)-a)
  for i in range(L):
   g=a+i
   if g&1:continue
   lf=i;rf=L+i;kind=('R' if lf%2==0 else 'C')+('R' if rf%2==0 else 'C')
   x=a+lf//2;y=a+rf//2;assert x<len(s) and y<len(s)
   graphs[kind].add((s[x],s[y]));positions.append((g,x,y,kind))
 return graphs,positions
def analyze_cipher(s,p,join_cap=JOIN_CAP,cross_cap=CROSS_CAP):
 if len(s)%2:raise ValueError('even symbol stream required')
 lens=block_lengths(len(s),p)
 if all(L%2==0 for L in lens):
  bs=even_pairs(s,p);edges={(v>>4,v&15) for v in bs};distinct=len(set(bs))
  base={'parity':'all_blocks_even','block_lengths':lens,'pair_count':len(bs),'pair_stream_sha256':hashlib.sha256(bs).hexdigest(),'distinct_pair_count':distinct}
  if distinct>213:return base|{'status':'excluded','method':'pair_cardinality_213'}
  rect=EVEN.analyze(edges);base['rectangle']={'directed_edge_count':rect['directed_edge_count'],'row_sets_examined':rect['row_sets_examined'],'max_common_missing_count':rect['max_common_missing_count'],'excluded_bag213':rect['excluded_bag213']}
  return base|({'status':'excluded','method':'empty_rectangle'} if rect['excluded_bag213'] else {'status':'unresolved','method':'even_necessary_tests_survive'})
 graphs,pos=odd_graphs(s,p);base={'parity':'contains_odd_block','block_lengths':lens,'typed_edge_counts':{k:len(v) for k,v in graphs.items()},'typed_edge_sha256':hashlib.sha256(json.dumps({k:sorted(v) for k,v in graphs.items()},separators=(',',':'),sort_keys=True).encode()).hexdigest(),'plaintext_byte_positions':len(pos)}
 filters={k:SINGLE.analyze(graphs[k],k,side=4,retain=False) for k in graphs};bad=next((k for k,x in filters.items() if not x['feasible']),None)
 base['single_filters']={k:{'feasible':v['feasible'],'surviving_first_sets':v['surviving_first_sets'],'checked_first_sets':v['checked_first_sets']} for k,v in filters.items()}
 if bad:return base|{'status':'excluded','method':'single_typed_graph','excluding_type':bad}
 joined=JOIN.analyze(graphs,side=4,max_join_pairs=join_cap,max_cross_candidates=cross_cap);base['join']=joined
 if joined['status']=='unsat':return base|{'status':'excluded','method':'coupled_join'}
 if joined['status']=='incomplete':return base|{'status':'incomplete','method':'coupled_join_cap'}
 return base|{'status':'unresolved','method':'coupled_join_sat'}
def verify_deps():
 for rel,want in DEPS.items():assert sha(ROOT/'research/rev7-20260909-codex'/rel)==want,(rel,sha(ROOT/'research/rev7-20260909-codex'/rel),want)
def canonical():
 assert sha(MDX)==MDX_SHA and sha(DATA)==DATA_SHA
 t=MDX.read_text();a=t.index('`83 B57B')+1;b=t.index('`',a);m=''.join(t[a:b].split()).upper()
 raw=next(x for x in json.loads(DATA.read_text()) if x.get('id')=='rev7')['ciphertext'];tokens=raw.split();assert list(map(len,tokens))==[2]+[5]*218
 d=''.join(tokens).upper()
 assert m==d and len(m)==1092 and hashlib.sha256(m.encode()).hexdigest()==TEXT_SHA
 return m
def require_gate():
 assert GATE.exists(),'root-created target_gate.json required';g=json.loads(GATE.read_text());expected={'identity','target_evaluated','authorized','scope','driver_sha256','controls_sha256','controls_source_sha256','readme_sha256','prepare_gate_sha256','dependency_hashes','mdx_sha256','dataset_sha256','canonical_sha256','fable_reference'};assert set(g)==expected
 assert g['identity']==IDENTITY and g['target_evaluated'] is False and g['authorized'] is True and isinstance(g['fable_reference'],str) and g['fable_reference'].strip() and 'ASTRA' in g['fable_reference'] and g['scope']==scope()
 assert g['driver_sha256']==sha(__file__) and g['controls_sha256']==sha(HERE/'controls.json') and g['controls_source_sha256']==sha(HERE/'controls.py') and g['readme_sha256']==sha(HERE/'README.md') and g['prepare_gate_sha256']==sha(HERE/'prepare_gate.py') and g['dependency_hashes']==DEPS and g['mdx_sha256']==MDX_SHA and g['dataset_sha256']==DATA_SHA and g['canonical_sha256']==TEXT_SHA
 verify_deps();assert sha(MDX)==MDX_SHA and sha(DATA)==DATA_SHA
 return g
def scope():return {'orientation':'reverse_width5_visible_token_order','direction':'standard Bifid DECRYPT','group_width':5,'periods':list(range(1,1093)),'cells':1092,'symbol_length':1092,'two_hex_nibbles_per_output_byte':True,'endpoint_name':'bag213','endpoint_bytes':[9,10,13]+list(range(32,127))+list(range(128,192))+list(range(194,245)),'endpoint_bound':213,'forbidden_output_high_nibble':1,'square_family':'two arbitrary fixed 4x4 squares; same-square is included','join_pair_cap':JOIN_CAP,'cross_candidate_cap':CROSS_CAP}
def main(run=False):
 verify_deps()
 if not run:
  print(json.dumps({'identity':IDENTITY,'target_evaluated':False,'scope':scope(),'driver_sha256':sha(__file__),'controls_present':(HERE/'controls.json').exists(),'gate_present':GATE.exists()},sort_keys=True,indent=2));return
 require_gate();assert not any(x.exists() for x in (OUT,TMP,CHECK)), 'refuse existing output/tmp/checkpoint'
 observed=canonical();natural=group_reverse_inverse(observed,5);assert group_reverse_forward(natural,5)==observed
 cells=[]
 with CHECK.open('x') as f:
  for p in range(1,1093):
   row={'id':f'group_reverse_width5:p{p}','period':p}|analyze_cipher([int(x,16) for x in natural],p)
   cells.append(row);f.write(json.dumps(row,sort_keys=True,separators=(',',':'))+'\n');f.flush();os.fsync(f.fileno())
 out={'identity':IDENTITY,'target_evaluated':True,'status':'complete','scope':scope(),'configuration':{'driver_sha256':sha(__file__),'gate_sha256':sha(GATE),'controls_sha256':sha(HERE/'controls.json'),'dependency_hashes':DEPS,'mdx_sha256':MDX_SHA,'dataset_sha256':DATA_SHA,'canonical_sha256':TEXT_SHA,'natural_after_inverse_sha256':hashlib.sha256(natural.encode()).hexdigest()},'cells':cells,'summary':{x:sum(r['status']==x for r in cells) for x in ('excluded','unresolved','incomplete')}}
 TMP.write_text(json.dumps(out,sort_keys=True,indent=2)+'\n');os.replace(TMP,OUT);print(json.dumps({'status':'complete','result_sha256':sha(OUT),'summary':out['summary']},sort_keys=True))
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('--run-target',action='store_true');a=ap.parse_args();main(a.run_target)
