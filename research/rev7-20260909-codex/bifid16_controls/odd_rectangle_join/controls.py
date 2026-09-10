#!/usr/bin/env python3
"""Target-free controls for exact coupled typed-rectangle joins."""
from __future__ import annotations
import argparse,hashlib,itertools,json,random,time,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;PKG=HERE.parent;IDENTITY='ASTRA';SEED=20260911
sys.path.insert(0,str(HERE));import model as join
PINS={'odd_coordinate_avoidance/model.py':'145341fe27c8e73ff4c62f009538631acf99d240f8f40fd8d88cbf76df1cca76','odd_coordinate_avoidance/controls.py':'61b2e271fd0d8329a98e68561f045bf088a2a3a375c98f678da06dfc5a4a2ca3','odd_coordinate_avoidance/controls.json':'ab4219cfcbca6cf13a13a7c8bb1e63f915198be4ac4539bc23074ca3d70bd5bb','odd_typed_rectangles/controls.py':'31f9b11bb8849be786548508ad7d5843eff991a0de9ff538cd8d377c430b1426','odd_typed_rectangles/controls.json':'e931ff2d471d089cb498f8e01733c82c62c2f2400d86fa527ff0d956bf9ecb6a'}
def sha_bytes(x):return hashlib.sha256(x).hexdigest()
def sha_path(p):return sha_bytes(Path(p).read_bytes())
def ax(pos,kind,side):return pos//side if kind=='R' else pos%side
def positions(square,side=4):
 out=[0]*(side*side)
 for i,v in enumerate(square):out[v]=i
 return out
def plain_bytes(case):
 base=b'THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG 0123456789; COORDINATE AVOIDANCE CONTROL. '
 return (base*((546//len(base))+2))[case:case+546]
def encrypt(plain,cipher_square,plain_square,period):
 pp=positions(plain_square);out=[]
 for start in range(0,len(plain),period):
  block=plain[start:start+period];digits=[pp[x]//4 for x in block]+[pp[x]%4 for x in block]
  out.extend(cipher_square[4*digits[i]+digits[i+1]] for i in range(0,len(digits),2))
 return out
def decrypt(cipher,cipher_square,plain_square,period):
 cp=positions(cipher_square);out=[]
 for start in range(0,len(cipher),period):
  block=cipher[start:start+period];digits=[]
  for x in block:digits.extend(divmod(cp[x],4))
  L=len(block);out.extend(plain_square[4*digits[i]+digits[L+i]] for i in range(L))
 return out
def typed_edges(cipher,period):
 out=[]
 for start in range(0,len(cipher),period):
  block=cipher[start:start+period];L=len(block);meta=[]
  for x in block:meta.extend((('R',x),('C',x)))
  for i in range(L):
   if (start+i)%2==0:
    a,b=meta[i],meta[L+i];out.append((a[1],b[1],a[0]+b[0]))
 return out
def literal_valid(graphs,witness,side):
 mapping=witness['mapping'];t=witness['forbidden_coordinate']
 if sorted(mapping)!=list(range(side*side)) or not 0<=t<side*side:return False
 for kind in join.TYPES:
  for a,b in graphs.get(kind,set()):
   value=side*ax(mapping[a],kind[0],side)+ax(mapping[b],kind[1],side)
   if value==t:return False
 return True
def graph(edges):
 return {k:{(a,b) for a,b,t in edges if t==k} for k in join.TYPES}
def oracle(side,graphs):
 for mapping in itertools.permutations(range(side*side)):
  for t in range(side*side):
   w={'mapping':list(mapping),'forbidden_coordinate':t}
   if literal_valid(graphs,w,side):return True,w
 return False,None
def geometry_quadruples(side):
 subsets=list(itertools.combinations(range(side*side),side));out=set()
 for A in subsets:
  for B in subsets:
   if len(set(A)&set(B))!=1:continue
   for C in subsets:
    for D in subsets:
     if len(set(C)&set(D))==1 and join.geometry(A,B,C,D):out.add((A,B,C,D))
 return out
def accepted_graphs():
 rng=random.Random(SEED);complete=[(a,b,'RC') for a in range(4) for b in range(4)];mapping=(2,0,3,1);t=3
 planted=[(a,b,k) for k in join.TYPES for a in range(4) for b in range(4) if 2*ax(mapping[a],k[0],2)+ax(mapping[b],k[1],2)!=t]
 rows=[('empty',[]),('complete_rc',complete),('planted_mixed',planted),('same_symbol_mixed',[(0,0,'RC'),(0,0,'CR'),(1,1,'RR'),(2,2,'CC')])]
 for i in range(8):
  edges=[]
  for a in range(4):
   for b in range(4):
    for k in join.TYPES:
     if rng.random()<(0.10+0.09*i):edges.append((a,b,k))
  rows.append((f'random_{i}',edges))
 return rows
def deterministic(x):
 x=json.loads(json.dumps(x))
 for group in ('reduced_cases','full_plants','full_unsat'):
  for row in x[group]:row.pop('elapsed_seconds',None)
 return x
def build():
 for rel,want in PINS.items():assert sha_path(PKG/rel)==want,(rel,sha_path(PKG/rel))
 rng=random.Random(SEED);reduced=[]
 accepted=json.loads((PKG/'odd_coordinate_avoidance/controls.json').read_text());lookup={x['name']:x for x in accepted['reduced_cases']}
 defs=accepted_graphs()
 # Add deterministic random/mixed graphs beyond the accepted twelve.
 for i in range(8):
  edges=[(a,b,k) for a in range(4) for b in range(4) for k in join.TYPES if rng.random()<(0.12+0.1*i)];defs.append((f'extra_random_{i}',edges))
 for name,edges in defs:
  g=graph(edges);t0=time.perf_counter();joined=join.analyze(g,2);elapsed=time.perf_counter()-t0;raw,w=oracle(2,g);assert (joined['status']=='sat')==raw and joined['status'] in ('sat','unsat')
  if joined['status']=='sat':assert literal_valid(g,joined['witness'],2)
  else:assert joined['complete'] and joined['candidate_counts']['joins_examined']==joined['candidate_counts']['join_space'] and 'all_pairs_obstruction_digest' in joined
  row_digest=sha_bytes(json.dumps(edges,separators=(',',':')).encode())
  if name in lookup:assert row_digest==lookup[name]['edge_sha256'] and raw==(lookup[name]['free_model']['solution_count']>0)
  reduced.append({'name':name,'edge_count':len(edges),'edge_sha256':row_digest,'oracle_sat':raw,'join':joined,'elapsed_seconds':elapsed})
 # Side-2 geometry is sufficient: all abstract feasible quadruples equal those induced by a square and t.
 abstract=geometry_quadruples(2);induced=set()
 for mapping in itertools.permutations(range(4)):
  for t in range(4):
   u,v=divmod(t,2);rows=[tuple(s for s,p in enumerate(mapping) if p//2==r) for r in range(2)];cols=[tuple(s for s,p in enumerate(mapping) if p%2==c) for c in range(2)];induced.add((rows[u],cols[v],cols[u],rows[v]))
 assert abstract==induced
 for A,B,C,D in abstract:
  witness=join.complete_square(A,B,C,D,2);assert literal_valid({'RC':set(),'CR':set(),'RR':set(),'CC':set()},witness,2)
 # Rebuild the six accepted full plants and exercise the exact join.
 periods=(3,5,31,99,1091,1091);plants=[];rng=random.Random(SEED)
 for _ in range(8*4*4*4):rng.random() # accepted reduced-random fixture draws before its plants
 for i,p in enumerate(periods):
  cs=list(range(16));rng.shuffle(cs);ps=cs[:] if i in (0,3) else list(range(16));rng.shuffle(ps) if ps!=cs else None
  raw=plain_bytes(i);plain=[v for byte in raw for v in (byte>>4,byte&15)];cipher=encrypt(plain,cs,ps,p);assert decrypt(cipher,cs,ps,p)==plain;edges=typed_edges(cipher,p);g=graph(edges)
  t0=time.perf_counter();joined=join.analyze(g,4);elapsed=time.perf_counter()-t0;assert joined['status']=='sat' and literal_valid(g,joined['witness'],4)
  cp=positions(cs);actual={'mapping':cp,'forbidden_coordinate':positions(ps)[1]};assert literal_valid(g,actual,4)
  cipher_sha=sha_bytes(bytes(cipher));edge_sha=sha_bytes(json.dumps(edges,separators=(',',':')).encode());accepted_plant=accepted['full_plants'][i];assert cipher_sha==accepted_plant['cipher_sha256'] and edge_sha==accepted_plant['edge_sha256']
  plants.append({'case':i,'period':p,'same_square':cs==ps,'cipher_sha256':cipher_sha,'edge_sha256':edge_sha,'accepted_coordinate_control_metadata_exact':True,'actual_distinct_square_witness_valid':True,'join':joined,'elapsed_seconds':elapsed})
 # Immediate exhaustive UNSAT controls for complete RC and complete CR graphs.
 full=[]
 for kind in ('RC','CR'):
  g={k:set() for k in join.TYPES};g[kind]={(a,b) for a in range(16) for b in range(16)};t0=time.perf_counter();joined=join.analyze(g,4);elapsed=time.perf_counter()-t0;assert joined['status']=='unsat' and joined['complete'] and joined['candidate_counts']['join_space']==0
  full.append({'complete_type':kind,'edges':256,'join':joined,'elapsed_seconds':elapsed,'independent_reason':'a complete typed graph realizes every coordinate for every square'})
 # Cap semantics: a nonempty empty-graph join stops incomplete, never excludes.
 empty={k:set() for k in join.TYPES};capped=join.analyze(empty,4,max_join_pairs=1);assert capped['status']=='incomplete' and not capped['complete'] and capped['phase']=='RC_candidate_generation' and capped['candidate_counts']['joins_examined']==0 and capped['witness'] is None
 return {'identity':IDENTITY,'target_evaluated':False,'rev7_read':False,'seed':SEED,'source_hashes':{**PINS,'model.py':sha_path(HERE/'model.py'),'controls.py':sha_path(Path(__file__))},'runtime':{'python':sys.version.split()[0]},'reduced_cases':reduced,'side2_geometry':{'abstract_quadruples':len(abstract),'induced_quadruples':len(induced),'sets_equal':True,'every_completion_valid':True},'full_plants':plants,'full_unsat':full,'cap_control':capped,'assertions':{'accepted_12_plus_8_extra_reduced_exact_oracle':True,'diagonal_and_offdiagonal_geometry_sufficient_side2':True,'six_full_ascii_plants_retain_actual_and_constructed_witnesses':True,'complete_RC_and_CR_immediate_exhaustive_unsat':True,'capped_join_never_excludes':True},'limits':['SAT witnesses establish only absence of one coordinate, not text or UTF-8.','An UNSAT result is emitted only after all feasible RC x CR candidates are obstructed; capped joins are incomplete.','Worst-case RC and CR candidate lists can each be large and their Cartesian join can be impractical; empty graphs deliberately use early SAT exit.','No target graph was read or profiled.']}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args();got=build();out=HERE/'controls.json'
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit('refusing existing output')
  a.regenerate.write_text(json.dumps(got,sort_keys=True,indent=2)+chr(10));print(json.dumps({'identity':IDENTITY,'output':str(a.regenerate),'sha256':sha_path(a.regenerate),'reduced':len(got['reduced_cases']),'plants':len(got['full_plants'])}));return
 assert deterministic(json.loads(out.read_text()))==deterministic(got);print(json.dumps({'identity':IDENTITY,'verified':True,'ledger_sha256':sha_path(out),'target_evaluated':False}))
if __name__=='__main__':main()
