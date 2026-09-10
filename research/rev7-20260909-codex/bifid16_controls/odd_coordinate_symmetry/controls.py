#!/usr/bin/env python3
"""Target-free controls for common coordinate-label permutation symmetry."""
from __future__ import annotations
import argparse,hashlib,itertools,json,random,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;PKG=HERE.parent;IDENTITY='ASTRA';SEED=20260911
sys.path.insert(0,str(PKG/'odd_coordinate_avoidance'));import model
z3=model.z3
PINS={
 'odd_coordinate_avoidance/model.py':'145341fe27c8e73ff4c62f009538631acf99d240f8f40fd8d88cbf76df1cca76',
 'odd_coordinate_avoidance/controls.py':'61b2e271fd0d8329a98e68561f045bf088a2a3a375c98f678da06dfc5a4a2ca3',
 'odd_coordinate_avoidance/controls.json':'ab4219cfcbca6cf13a13a7c8bb1e63f915198be4ac4539bc23074ca3d70bd5bb',
 'dependency/dependency.json':'e88e7bf34243264705ca5fcaa66acb5c9db96f289192a862e0e063a915897e4e',
 'dependency/runtime/z3/lib/libz3.4.15.dylib':'3164e079c221c23a843396a485a6e912ee423918ee64ea03943e584305439a98',
 'dependency/runtime/z3/z3.py':'a175fce3e5e6f7cbe7aefb54a5d01d63addc206811a9cbd3e58f87f48c10432b',
 'dependency/runtime/z3/z3core.py':'c5859f1938aa7b5ce1c35ab52295ccb1405daa1ae224cb4ec292efbe98b1064e',
}
def sha_bytes(x):return hashlib.sha256(x).hexdigest()
def sha_path(p):return sha_bytes(Path(p).read_bytes())
def ax(pos,kind,side):return pos//side if kind=='R' else pos%side
def cell(r,c,side):return side*r+c
def transform_pos(pos,sigma,side):return cell(sigma[pos//side],sigma[pos%side],side)
def transform_mapping(mapping,sigma,side):return tuple(transform_pos(x,sigma,side) for x in mapping)
def relation(mapping,t,a,b,kind,side):return cell(ax(mapping[a],kind[0],side),ax(mapping[b],kind[1],side),side)!=t
def representative_sigma(t,side):
 u,v=divmod(t,side);sigma=[None]*side
 if u==v:
  sigma[u]=0;remaining=[x for x in range(side) if x!=u]
  for label,x in enumerate(remaining,1):sigma[x]=label
  rep=0
 else:
  sigma[u]=0;sigma[v]=1;remaining=[x for x in range(side) if x not in (u,v)]
  for label,x in enumerate(remaining,2):sigma[x]=label
  rep=1
 assert sorted(sigma)==list(range(side)) and transform_pos(t,sigma,side)==rep
 return tuple(sigma),rep
def restricted_status(side,edges,one_square,prefix):
 solver,k,t,_=model.build(side,edges,one_square,prefix);solver.add(z3.Or(t==z3.BitVecVal(0,t.size()),t==z3.BitVecVal(1,t.size())));status=solver.check();return str(status),solver.to_smt2()
def accepted_reduced_graphs():
 rng=random.Random(SEED);complete=[(a,b,'RC') for a in range(4) for b in range(4)];mapping=(2,0,3,1);t=3
 planted=[(a,b,k) for k in ('RC','CR','RR','CC') for a in range(4) for b in range(4) if cell(ax(mapping[a],k[0],2),ax(mapping[b],k[1],2),2)!=t]
 rows=[('empty',[]),('complete_rc',complete),('planted_mixed',planted),('same_symbol_mixed',[(0,0,'RC'),(0,0,'CR'),(1,1,'RR'),(2,2,'CC')])]
 for i in range(8):
  edges=[]
  for a in range(4):
   for b in range(4):
    for k in ('RC','CR','RR','CC'):
     if rng.random()<(0.10+0.09*i):edges.append((a,b,k))
  rows.append((f'random_{i}',edges))
 return rows
def build():
 for rel,want in PINS.items():assert sha_path(PKG/rel)==want,(rel,sha_path(PKG/rel))
 accepted=json.loads((PKG/'odd_coordinate_avoidance/controls.json').read_text());assert accepted['identity']==IDENTITY and accepted['target_evaluated'] is False
 # Exhaustive reduced theorem: 24 maps x 4 t x 2 label permutations x every typed symbol pair.
 checks=0;one_square_checks=0
 for mapping in itertools.permutations(range(4)):
  for t in range(4):
   for sigma in itertools.permutations(range(2)):
    mt=transform_mapping(mapping,sigma,2);tt=transform_pos(t,sigma,2)
    assert sorted(mt)==list(range(4));assert (t==mapping[1])==(tt==mt[1]);one_square_checks+=1
    for kind in ('RC','CR','RR','CC'):
     for a in range(4):
      for b in range(4):
       assert relation(mapping,t,a,b,kind,2)==relation(mt,tt,a,b,kind,2);checks+=1
 # Explicit representative construction for all full coordinates.
 reps=[]
 for t in range(16):
  sigma,rep=representative_sigma(t,4);assert rep==(0 if t//4==t%4 else 1);reps.append({'coordinate':t,'row':t//4,'column':t%4,'orbit':'diagonal' if rep==0 else 'off_diagonal','representative':rep,'sigma':list(sigma)})
 # Full 4x4 checks: 8 deterministic maps x all t x all 24 sigmas x all types x 256 pairs.
 rng=random.Random(SEED+1);full_checks=0;full_one_square=0;map_digests=[]
 for mi in range(8):
  mapping=list(range(16));rng.shuffle(mapping);map_digests.append(sha_bytes(bytes(mapping)))
  for t in range(16):
   for sigma in itertools.permutations(range(4)):
    mt=transform_mapping(mapping,sigma,4);tt=transform_pos(t,sigma,4);assert sorted(mt)==list(range(16));assert (t==mapping[1])==(tt==mt[1]);full_one_square+=1
    for kind in ('RC','CR','RR','CC'):
     for a in range(16):
      for b in range(16):assert relation(mapping,t,a,b,kind,4)==relation(mt,tt,a,b,kind,4);full_checks+=1
 # Reconstruct exact twelve accepted reduced fixtures and compare unrestricted existence with t in {0,1}.
 graph_rows=[];accepted_rows={x['name']:x for x in accepted['reduced_cases']}
 for i,(name,edges) in enumerate(accepted_reduced_graphs()):
  edge_digest=sha_bytes(json.dumps(edges,separators=(',',':')).encode());assert edge_digest==accepted_rows[name]['edge_sha256']
  row={'name':name,'edge_count':len(edges),'edge_sha256':edge_digest}
  for one,label in ((False,'free'),(True,'one_square')):
   raw=accepted_rows[name][label+'_model'];raw_sat=raw['solution_count']>0;status,smt=restricted_status(2,edges,one,f'g{i}_{int(one)}');assert status in ('sat','unsat') and (status=='sat')==raw_sat
   row[label]={'raw_solution_count':raw['solution_count'],'raw_exists':raw_sat,'restricted_status':status,'existence_equal':True,'restricted_smt2_sha256':sha_bytes(smt.encode()),'restricted_smt2_bytes':len(smt.encode())}
  graph_rows.append(row)
 return {'identity':IDENTITY,'target_evaluated':False,'rev7_read':False,'model':'common permutation of row and column labels; t representatives 0 diagonal and 1 off-diagonal','source_hashes':{**PINS,'controls.py':sha_path(Path(__file__))},'runtime':{'python':sys.version.split()[0],'z3':z3.get_version_string()},'reduced_exhaustive':{'mappings':24,'coordinates':4,'label_permutations':2,'typed_relation_checks':checks,'one_square_equivalence_checks':one_square_checks,'all_passed':True},'full_deterministic':{'mappings':8,'coordinates_per_mapping':16,'label_permutations':24,'typed_relation_checks':full_checks,'one_square_equivalence_checks':full_one_square,'mapping_digests':map_digests,'all_passed':True},'representative_construction':reps,'accepted_reduced_graphs':graph_rows,'assertions':{'bijection_preserved':True,'every_t_maps_to_correct_orbit_representative':True,'every_typed_inequality_preserved':True,'optional_t_equals_k1_preserved':True,'restricted_existence_equals_raw_on_all_12_graphs':True},'limits':['Only a single common permutation sigma is applied to both coordinate axes.','No independent row/column relabeling, transpose, arbitrary 16-cell symmetry, target-data result, or solver-speed claim is made.','The restriction is an equisatisfiable symmetry reduction for the coordinate-avoidance model, not for additional constraints unless their invariance is proved separately.']}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args();got=build();out=HERE/'controls.json'
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit('refusing existing output')
  a.regenerate.write_text(json.dumps(got,sort_keys=True,indent=2)+chr(10));print(json.dumps({'identity':IDENTITY,'output':str(a.regenerate),'sha256':sha_path(a.regenerate),'typed_checks':got['full_deterministic']['typed_relation_checks']}));return
 assert json.loads(out.read_text())==got;print(json.dumps({'identity':IDENTITY,'verified':True,'ledger_sha256':sha_path(out),'target_evaluated':False,'restricted_graphs':len(got['accepted_reduced_graphs'])}))
if __name__=='__main__':main()
