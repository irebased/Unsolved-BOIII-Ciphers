#!/usr/bin/env python3
"""Independent structural/mathematical replay of the saved one-G result; does not run the target driver."""
from __future__ import annotations
import argparse,hashlib,itertools,json
from collections import Counter
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];RESULT=HERE/'target_results.json';CHECK=HERE/'checkpoint.jsonl';GATE=HERE/'target_gate.json'
MDX=ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx';DATA=ROOT/'lavender/src/data/ciphers/revelations.json'
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def canonical_observed():
 g=json.loads(GATE.read_text());assert sha(MDX)==g['mdx_sha256'] and sha(DATA)==g['dataset_sha256']
 d=json.loads(DATA.read_text());raw=next(x for x in d if x.get('id')=='rev7')['ciphertext'];tokens=raw.split();assert list(map(len,tokens))==[2]+[5]*218
 s=''.join(tokens).upper();assert len(s)==1092 and hashlib.sha256(s.encode()).hexdigest()==g['canonical_sha256']
 t=MDX.read_text();a=t.index('`83 B57B')+1;b=t.index('`',a);assert ''.join(t[a:b].split()).upper()==s
 return s
def inverse_g(observed):
 n=len(observed);r=n%5
 # Independent closed-form forward index map: obs[i]=natural[fwd[i]]. Invert it.
 fwd=[]
 for i in range(n):fwd.append(n-r+i if i<r else 5*((n-r)//5-1-(i-r)//5)+(i-r)%5)
 assert sorted(fwd)==list(range(n));natural=['']*n
 for i,j in enumerate(fwd):natural[j]=observed[i]
 return ''.join(natural),fwd
def blocks(n,p):return [(a,min(p,n-a)) for a in range(0,n,p)]
def even_pairs(s,p):
 out=[]
 for a,L in blocks(len(s),p):
  assert L%2==0;h=L//2
  for j in range(h):out.append((s[a+j]<<4)|s[a+h+j])
 return bytes(out)
def typed(s,p):
 graphs={k:set() for k in ('RC','CR','RR','CC')};pos=[]
 for a,L in blocks(len(s),p):
  flat=[]
  for j in range(L):flat.extend(((s[a+j],'R',a+j),(s[a+j],'C',a+j)))
  for i in range(L):
   if (a+i)%2:continue
   x,y=flat[i],flat[L+i];k=x[1]+y[1];graphs[k].add((x[0],y[0]));pos.append((a+i,x[2],y[2],k))
 assert len(pos)==len(s)//2
 return graphs,pos
def graph_digest(graphs):return hashlib.sha256(json.dumps({k:sorted(v) for k,v in graphs.items()},sort_keys=True,separators=(',',':')).encode()).hexdigest()
def masks(edges):
 m=[0]*16
 for a,b in edges:m[a]|=1<<b
 return m
def rectangle(edges):
 m=masks(edges);full=65535;best=-1
 for A in itertools.combinations(range(16),4):
  missing=full
  for a in A:missing&=full^m[a]
  best=max(best,bin(missing).count('1'))
 return best
def single(edges,kind):
 m=masks(edges);full=65535;accepted=0
 for A0 in itertools.combinations(range(16),4):
  A=sum(1<<x for x in A0);missing=full
  for a in A0:missing&=full^m[a]
  inside=bin(missing&A).count('1');outside=bin(missing&(full^A)).count('1')
  ok=(inside>=1 and outside>=3) if kind[0]!=kind[1] else ((missing&A)==A or outside>=4)
  accepted+=ok
 return accepted
def cross(edges):
 # Independent construction: select the unique intersection element, then three outside A.
 m=masks(edges);full=65535;out=[]
 for A in itertools.combinations(range(16),4):
  missing=full
  for a in A:missing&=full^m[a]
  inside=[x for x in A if missing>>x&1];outside=[x for x in range(16) if x not in A and missing>>x&1]
  for x in inside:
   for tail in itertools.combinations(outside,3):out.append((A,tuple(sorted((x,)+tail))))
 return iter(sorted(out))
def geometry(A,B,C,D):
 if A==D and C==B:return 'diagonal'
 if set(A).isdisjoint(D) and set(C).isdisjoint(B) and all(len(set(x)&set(y))==1 for x,y in ((A,C),(A,B),(D,C),(D,B))):return 'off_diagonal'
def absent(edges,A,B):return all((a,b) not in edges for a in A for b in B)
def join_unsat(graphs,saved):
 rc=list(cross(graphs['RC']));cr=list(cross(graphs['CR']));assert len(rc)<=10000 and len(cr)<=10000
 reasons={};digest=hashlib.sha256();examined=0
 for i,(A,B) in enumerate(rc):
  for j,(C,D) in enumerate(cr):
   assert examined<1_000_000;examined+=1
   if geometry(A,B,C,D) is None:reason='geometry'
   elif not absent(graphs['RR'],A,D):reason='RR_edge'
   elif not absent(graphs['CC'],C,B):reason='CC_edge'
   else:raise AssertionError('unexpected surviving coupled witness')
   reasons[reason]=reasons.get(reason,0)+1;digest.update(json.dumps([i,j,reason],separators=(',',':')).encode()+b'\n')
 a=saved['join'];assert a['status']=='unsat' and a['complete'] is True and a['candidate_counts']=={'RC':len(rc),'CR':len(cr),'join_space':len(rc)*len(cr),'joins_examined':examined};assert a['obstruction_counts']==reasons and a['all_pairs_obstruction_digest']==digest.hexdigest()
def build():
 result=json.loads(RESULT.read_text());gate=json.loads(GATE.read_text());expected_scope={'orientation':'reverse_width5_visible_token_order','direction':'standard Bifid DECRYPT','group_width':5,'periods':list(range(1,1093)),'cells':1092,'symbol_length':1092,'two_hex_nibbles_per_output_byte':True,'endpoint_name':'bag213','endpoint_bytes':[9,10,13]+list(range(32,127))+list(range(128,192))+list(range(194,245)),'endpoint_bound':213,'forbidden_output_high_nibble':1,'square_family':'two arbitrary fixed 4x4 squares; same-square is included','join_pair_cap':1_000_000,'cross_candidate_cap':10_000}
 assert gate['identity']=='ASTRA' and gate['authorized'] is True and gate['target_evaluated'] is False and isinstance(gate['fable_reference'],str) and gate['fable_reference'].strip() and 'ASTRA' in gate['fable_reference'];assert result['identity']=='ASTRA' and result['status']=='complete' and result['target_evaluated'] is True;assert result['scope']==gate['scope']==expected_scope
 assert sha(HERE/'run_target.py')==gate['driver_sha256']==result['configuration']['driver_sha256'];assert sha(HERE/'controls.py')==gate['controls_source_sha256'];assert sha(HERE/'controls.json')==gate['controls_sha256']==result['configuration']['controls_sha256'];assert sha(HERE/'README.md')==gate['readme_sha256'] and sha(HERE/'prepare_gate.py')==gate['prepare_gate_sha256'];assert gate['mdx_sha256']==result['configuration']['mdx_sha256'] and gate['dataset_sha256']==result['configuration']['dataset_sha256'] and gate['canonical_sha256']==result['configuration']['canonical_sha256'];assert gate['dependency_hashes']==result['configuration']['dependency_hashes'];assert sha(GATE)==result['configuration']['gate_sha256']
 for rel,want in gate['dependency_hashes'].items():assert sha(ROOT/'research/rev7-20260909-codex'/rel)==want
 observed=canonical_observed();natural,fwd=inverse_g(observed);assert hashlib.sha256(natural.encode()).hexdigest()==result['configuration']['natural_after_inverse_sha256']
 cells=result['cells'];assert [x['id'] for x in cells]==[f'group_reverse_width5:p{p}' for p in range(1,1093)]
 checkpoint=[json.loads(x) for x in CHECK.read_text().splitlines()];assert checkpoint==cells
 methods=Counter();coupled=[]
 s=[int(x,16) for x in natural]
 for p,row in enumerate(cells,1):
  assert row['period']==p and row['status']=='excluded';lens=[L for _,L in blocks(1092,p)];assert row['block_lengths']==lens
  if all(L%2==0 for L in lens):
   assert row['parity']=='all_blocks_even'
   ps=even_pairs(s,p);assert row['pair_count']==546 and row['pair_stream_sha256']==hashlib.sha256(ps).hexdigest() and row['distinct_pair_count']==len(set(ps))
   if row['method']=='pair_cardinality_213':assert len(set(ps))>213
   else:
    assert row['method']=='empty_rectangle' and len(set(ps))<=213;edges={(v>>4,v&15) for v in ps};best=rectangle(edges);assert best<4;rr=row['rectangle'];assert rr['max_common_missing_count']==best and rr['row_sets_examined']==1820 and rr['excluded_bag213'] is True and rr['directed_edge_count']==len(edges)
  else:
   assert row['parity']=='contains_odd_block'
   graphs,pos=typed(s,p);assert row['plaintext_byte_positions']==546 and row['typed_edge_counts']=={k:len(v) for k,v in graphs.items()} and row['typed_edge_sha256']==graph_digest(graphs)
   counts={k:single(graphs[k],k) for k in graphs};assert all(row['single_filters'][k]['surviving_first_sets']==counts[k] and row['single_filters'][k]['feasible']==(counts[k]>0) and row['single_filters'][k]['checked_first_sets']==1820 for k in graphs)
   bad=next((k for k in ('RC','CR','RR','CC') if counts[k]==0),None)
   if bad is not None:assert row['method']=='single_typed_graph' and row['excluding_type']==bad
   else:assert row['method']=='coupled_join';join_unsat(graphs,row);coupled.append(p)
  methods[row['method']]+=1
 assert result['summary']=={'excluded':1092,'unresolved':0,'incomplete':0}
 out={'identity':'ASTRA','verification_only':True,'new_target_search':False,'target_evaluated':True,'status':'PASS','verifier_source_sha256':sha(Path(__file__)),'result_sha256':sha(RESULT),'checkpoint_sha256':sha(CHECK),'gate_sha256':sha(GATE),'canonical_sha256':hashlib.sha256(observed.encode()).hexdigest(),'natural_after_inverse_sha256':hashlib.sha256(natural.encode()).hexdigest(),'forward_index_permutation_sha256':hashlib.sha256(b''.join(x.to_bytes(2,'big') for x in fwd)).hexdigest(),'cells_verified':len(cells),'method_counts':dict(sorted(methods.items())),'coupled_join_periods':coupled,'coupled_join_count':len(coupled),'limits':'Independent replay of saved finite evidence; it is not a second target-driver execution.'}
 return out
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--generate',type=Path);a=ap.parse_args();out=build()
 if a.generate is not None:
  assert not a.generate.exists(),'refuse overwrite';a.generate.write_text(json.dumps(out,sort_keys=True,indent=2)+'\n');print(json.dumps({'identity':'ASTRA','status':'GENERATED','path':str(a.generate),'sha256':sha(a.generate)},sort_keys=True));return
 saved=json.loads((HERE/'verification.json').read_text());assert out==saved;print(json.dumps({'identity':'ASTRA','status':'PASS','verification_sha256':sha(HERE/'verification.json'),'cells_verified':out['cells_verified']},sort_keys=True))
if __name__=='__main__':main()
