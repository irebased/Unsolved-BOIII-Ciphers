#!/usr/bin/env python3
"""ASTRA target-free typed high-nibble graph controls for 4x4 Bifid."""
from __future__ import annotations
import argparse,hashlib,json,random
from pathlib import Path
HERE=Path(__file__).resolve().parent;PKG=HERE.parent;IDENTITY='ASTRA';SYMS=tuple(range(16));SEED=20260911
PINS={'odd_math/odd_math.py':'d4c60fabfb8335140564f5c15135d16dab484fb57d11867a6ede145748d9b925','odd_math/odd_math_results.json':'899b368f0cbae05297074982d89390e82271cf65fc699218e95098ec63b36265','odd_math/DESIGN.md':'3f9e7b85d05d38c5648db553a13c5dc1d586f59b52d778f6efdf19099e3d6d2a','even_rectangle_controls/model.py':'46c1f18e473450aba5dde3675b594d9f0b86f28d4a670514e10a806a92942e84','even_rectangle_controls/controls.json':'9f443af6c503d7fc377551b2842d5f701a21649d910d9aebdaf30597efe17f57','even_rectangle_controls/README.md':'dd1e8b44938de3032c656dd76ee9b8f3638d17b3b6be5100b6b883ca5b65c03a','symmetry_probe.py':'8bf072deccafabe1e98db126178207d9cf3c8eccdcab6902a28b0c0d123a26e0'}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def tables(square):
 pos=[0]*16
 for i,s in enumerate(square):pos[s]=i
 return [(x//4,x%4) for x in pos]
def inv(square,r,c):return square[4*r+c]
def axis(coords,s,kind):return coords[s][0 if kind=='R' else 1]
def blocks_for_period(n,p):return [min(p,n-a) for a in range(0,n,p)]
def typed_high_edges(cipher,cipher_square,lengths):
 assert sum(lengths)==len(cipher);coords=tables(cipher_square);edges=[];start=0
 for L in lengths:
  block=cipher[start:start+L];meta=[]
  for s in block:meta.extend((('R',s),('C',s)))
  for i in range(L):
   if (start+i)%2==0:
    left,right=meta[i],meta[L+i];edges.append({'global_nibble':start+i,'block_start':start,'block_length':L,'local_nibble':i,'type':left[0]+right[0],'a':left[1],'b':right[1],'coordinate':[axis(coords,left[1],left[0]),axis(coords,right[1],right[0])]})
  start+=L
 assert len(edges)==(len(cipher)+1)//2
 return edges
def decrypt(cipher,cipher_square,plain_square,lengths):
 cc=tables(cipher_square);out=[];start=0
 for L in lengths:
  block=cipher[start:start+L];digits=[]
  for s in block:digits.extend(cc[s])
  out.extend(inv(plain_square,digits[i],digits[L+i]) for i in range(L));start+=L
 return out
def candidates(edges,cipher_square,only_type=None):
 coords=tables(cipher_square);out=[]
 for u in range(4):
  for v in range(4):
   if all(not(axis(coords,e['a'],e['type'][0])==u and axis(coords,e['b'],e['type'][1])==v) for e in edges if only_type is None or e['type']==only_type):out.append([u,v])
 return out
def graph_edges_except(coords,kind,empty_uv):
 X,Y=kind;u,v=empty_uv;return [{'type':kind,'a':a,'b':b} for a in SYMS for b in SYMS if not(axis(coords,a,X)==u and axis(coords,b,Y)==v)]
def build():
 for rel,want in PINS.items():assert sha(PKG/rel)==want
 rng=random.Random(SEED);rows=[];types=set();type_counts={x:0 for x in ('RC','CR','RR','CC')}
 # Constant odd periods exercise RC/CR and real short tails; same and distinct output squares.
 for case in range(80):
  cs=list(SYMS);rng.shuffle(cs);ps=cs[:] if case%2==0 else rng.sample(list(SYMS),16);n=2*(8+case%19);p=(3,5,7,15,31)[case%5];cipher=[rng.randrange(16) for _ in range(n)];lengths=blocks_for_period(n,p);edges=typed_high_edges(cipher,cs,lengths);plain=decrypt(cipher,cs,ps,lengths);assert [plain[2*i] for i in range(n//2)]==[inv(ps,*e['coordinate']) for e in edges]
  actual=list(tables(ps)[1]);joint=candidates(edges,cs);assert (actual in joint)==all(x!=1 for x in plain[::2])
  for e in edges:types.add(e['type']);type_counts[e['type']]+=1
  rows.append({'case':case,'same_square':ps==cs,'symbols':n,'period':p,'block_lengths':lengths,'types':sorted(set(e['type'] for e in edges)),'edge_digest':hashlib.sha256(json.dumps(edges,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'actual_symbol1_coordinate':actual,'actual_coordinate_survives_iff_no_high1':True,'joint_candidate_count':len(joint)})
 # A deliberately mixed segmentation proves even blocks at even/odd starts yield RR/CC.
 cs=list(SYMS);ps=list(reversed(SYMS));cipher=list(range(8));mixed=[2,1,2,3];edges=typed_high_edges(cipher,cs,mixed);plain=decrypt(cipher,cs,ps,mixed);assert [plain[2*i] for i in range(4)]==[inv(ps,*e['coordinate']) for e in edges];assert {'RC','CR','RR','CC'}<=set(e['type'] for e in edges);types|=set(e['type'] for e in edges)
 # Axis-class geometry: same-axis classes equal/disjoint; cross-axis classes meet once.
 coords=tables(cs);classes={'R':[{s for s in SYMS if axis(coords,s,'R')==u} for u in range(4)],'C':[{s for s in SYMS if axis(coords,s,'C')==u} for u in range(4)]}
 for X in 'RC':
  for u in range(4):
   for v in range(4):
    got=len(classes[X][u]&classes[X][v]);assert got==(4 if u==v else 0)
 for u in range(4):
  for v in range(4):assert len(classes['R'][u]&classes['C'][v])==1
 # Any single complete typed graph has no candidate coordinate and suffices.
 complete=[{'type':'RC','a':a,'b':b} for a in SYMS for b in SYMS];assert candidates(complete,cs,'RC')==[]
 # Each graph alone can survive while their coupled (u,v) intersection is empty.
 rc=graph_edges_except(coords,'RC',(0,0));cr=graph_edges_except(coords,'CR',(1,1));assert candidates(rc,cs,'RC')==[[0,0]] and candidates(cr,cs,'CR')==[[1,1]] and candidates(rc+cr,cs)==[]
 result={'identity':IDENTITY,'target_evaluated':False,'rev7_read':False,'seed':SEED,'source_hashes':{**PINS,'controls.py':sha(Path(__file__))},'constant_period_cases':rows,'mixed_block_fixture':{'cipher_symbols':cipher,'cipher_square':cs,'plaintext_square':ps,'block_lengths':mixed,'edges':edges,'plaintext_symbols':plain,'types':sorted(set(e['type'] for e in edges))},'type_counts_constant_period':type_counts,'all_types_covered':sorted(types),'geometry':{'same_axis_intersections':'4 when class labels equal, otherwise 0','cross_axis_intersections':'exactly 1','all_checked':True},'single_graph_sufficiency':{'type':'RC','edges':256,'candidate_coordinates':[],'no_empty_rectangle':True},'coupled_graph_example':{'RC_candidate_coordinates':[[0,0]],'CR_candidate_coordinates':[[1,1]],'joint_candidate_coordinates':[],'each_alone_unresolved_but_joint_impossible':True},'assertions':{'generic_flatten_typed_edges_equal_concrete_high_nibbles':True,'same_and_distinct_squares_checked':True,'constant_odd_periods_and_short_tails_checked':True,'RR_CC_mixed_start_fixture_checked':True,'actual_symbol1_coordinate_survives_iff_no_high1':True,'single_typed_graph_can_suffice':True,'typed_candidate_intersection_can_be_stronger':True}}
 return result
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args();built=build();out=HERE/'controls.json'
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit('refusing existing output')
  a.regenerate.write_text(json.dumps(built,sort_keys=True,indent=2)+'\n');print(json.dumps({'identity':IDENTITY,'sha256':sha(a.regenerate),'cases':len(built['constant_period_cases'])}));return
 saved=json.loads(out.read_text());assert saved==json.loads(json.dumps(built));print(json.dumps({'identity':IDENTITY,'ok':True,'sha256':sha(out),'types':built['all_types_covered'],'target_evaluated':False},sort_keys=True))
if __name__=='__main__':main()
