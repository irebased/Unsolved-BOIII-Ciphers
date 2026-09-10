#!/usr/bin/env python3
"""Target-free exhaustive reduced and synthetic 4x4 controls for coordinate avoidance."""
from __future__ import annotations
import argparse,hashlib,itertools,json,random,time,importlib.util
from pathlib import Path
HERE=Path(__file__).resolve().parent;PKG=HERE.parent;IDENTITY='ASTRA';SEED=20260911
import model
PINS={
 'odd_typed_rectangles/controls.py':'31f9b11bb8849be786548508ad7d5843eff991a0de9ff538cd8d377c430b1426',
 'odd_typed_rectangles/controls.json':'e931ff2d471d089cb498f8e01733c82c62c2f2400d86fa527ff0d956bf9ecb6a',
 'odd_typed_rectangles/README.md':'df5d2438fdcfb9b57a1ad93bdda72d4db991beea1acc4379f228c5c63d38195a',
 'dependency/dependency.json':'e88e7bf34243264705ca5fcaa66acb5c9db96f289192a862e0e063a915897e4e',
 'dependency/LICENSE.txt':'e617cad2ab9347e3129c2b171e87909332174e17961c5c3412d0799469111337',
 'dependency/runtime/z3/lib/libz3.4.15.dylib':'3164e079c221c23a843396a485a6e912ee423918ee64ea03943e584305439a98',
 'dependency/runtime/z3/__init__.py':'53c4529a01f38e7c0d593b7548c79e0d7398aa09f7d7cbd1773470859ee2febd',
 'dependency/runtime/z3/z3.py':'a175fce3e5e6f7cbe7aefb54a5d01d63addc206811a9cbd3e58f87f48c10432b',
 'dependency/runtime/z3/z3core.py':'c5859f1938aa7b5ce1c35ab52295ccb1405daa1ae224cb4ec292efbe98b1064e',
 'dependency/runtime/z3/z3types.py':'ba728354b4a9ee40bcfbd899f405d904bc4bb023e41807044c06c318548c3080',
 'dependency/runtime/z3/z3consts.py':'59737a55612e9bddb33f7ec4a27db9fbc880a92053fa8a88919fcc934e1f7573',
}
def sha_bytes(x):return hashlib.sha256(x).hexdigest()
def sha_path(p):return sha_bytes(Path(p).read_bytes())
def load_parent():
 spec=importlib.util.spec_from_file_location('typed_parent',PKG/'odd_typed_rectangles/controls.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def ax(pos,kind,side):return pos//side if kind=='R' else pos%side
def oracle(side,edges,one_square=False):
 symbols=side*side;out=[]
 for mapping in itertools.permutations(range(symbols)):
  for t in range(symbols):
   if one_square and t!=mapping[1]:continue
   if all(side*ax(mapping[a],kind[0],side)+ax(mapping[b],kind[1],side)!=t for a,b,kind in edges):out.append((mapping,t))
 return sorted(out)
def positions(square,side=4):
 out=[0]*(side*side)
 for i,s in enumerate(square):out[s]=i
 return out
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
  for s in block:digits.extend(divmod(cp[s],4))
  L=len(block);out.extend(plain_square[4*digits[i]+digits[L+i]] for i in range(L))
 return out
def typed_edges(cipher,period):
 edges=[]
 for start in range(0,len(cipher),period):
  block=cipher[start:start+period];L=len(block);meta=[]
  for s in block:meta.extend((('R',s),('C',s)))
  for local in range(L):
   if (start+local)%2==0:
    x,y=meta[local],meta[L+local];edges.append((x[1],y[1],x[0]+y[0]))
 return edges
def valid_mapping(edges,mapping,t,side=4):return model.satisfies(side,edges,mapping,t,False)
def plain_bytes(case):
 base=(b'THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG 0123456789; COORDINATE AVOIDANCE CONTROL. ')
 return (base*((546//len(base))+2))[case:case+546]
def compact_solve(side,edges,one_square,prefix,timeout_ms=10000):
 t0=time.perf_counter();r=model.solve(side,edges,one_square,timeout_ms,prefix);elapsed=time.perf_counter()-t0;smt=r['smt2'];r['smt2_sha256']=sha_bytes(smt.encode());r['smt2_bytes']=len(smt.encode());r['elapsed_seconds']=elapsed;return r
def deterministic(row):
 row=json.loads(json.dumps(row));
 for group in ('reduced_cases','full_plants','full_graphs'):
  for x in row.get(group,[]):
   for key in ('free_model','one_square_model','fixed_mapping_model'):
    if key in x:x[key].pop('elapsed_seconds',None)
 return row
def build():
 for rel,want in PINS.items():assert sha_path(PKG/rel)==want,(rel,sha_path(PKG/rel))
 parent=load_parent();rng=random.Random(SEED)
 # Reduced 2x2: exact all 24 squares x all four t values, with and without t=k[1].
 complete_rc=[(a,b,'RC') for a in range(4) for b in range(4)]
 planted_map=(2,0,3,1);planted_t=3
 planted=[(a,b,k) for k in ('RC','CR','RR','CC') for a in range(4) for b in range(4) if 2*ax(planted_map[a],k[0],2)+ax(planted_map[b],k[1],2)!=planted_t]
 reduced_defs=[('empty',[]),('complete_rc',complete_rc),('planted_mixed',planted),('same_symbol_mixed',[(0,0,'RC'),(0,0,'CR'),(1,1,'RR'),(2,2,'CC')])]
 for i in range(8):
  edges=[]
  for a in range(4):
   for b in range(4):
    for k in ('RC','CR','RR','CC'):
     if rng.random()<(0.10+0.09*i):edges.append((a,b,k))
  reduced_defs.append((f'random_{i}',edges))
 reduced=[]
 for ci,(name,edges) in enumerate(reduced_defs):
  row={'name':name,'edge_count':len(edges),'edge_sha256':sha_bytes(json.dumps(edges,separators=(',',':')).encode())}
  for one,label in ((False,'free_model'),(True,'one_square_model')):
   want=oracle(2,edges,one);got=model.enumerate_solutions(2,edges,one,prefix=f'r{ci}_{int(one)}');assert got['complete_enumeration'] and got['terminal_status']=='unsat' and got['reason_unknown'] is None;actual=sorted((tuple(x),t) for x,t in got['solutions']);assert actual==want
   smt=got['smt2'];row[label]={'status':'sat' if want else 'unsat','solution_count':len(want),'solution_digest':sha_bytes(json.dumps(want,separators=(',',':')).encode()),'smt2':smt,'smt2_sha256':sha_bytes(smt.encode()),'smt2_bytes':len(smt.encode()),'exact_oracle_equal':True}
  reduced.append(row)
 assert any(x['free_model']['solution_count']!=x['one_square_model']['solution_count'] for x in reduced)
 # Six 1092-nibble/546-byte ASCII plants: distinct and same squares, odd blocks and odd tails.
 periods=(3,5,31,99,1091,1091);plants=[];all_types=set()
 for i,p in enumerate(periods):
  cs=list(range(16));rng.shuffle(cs);ps=cs[:] if i in (0,3) else list(range(16));rng.shuffle(ps) if ps!=cs else None
  raw=plain_bytes(i);plain=[v for byte in raw for v in (byte>>4,byte&15)];assert len(plain)==1092 and all((v!=1) for v in plain[::2])
  cipher=encrypt(plain,cs,ps,p);assert decrypt(cipher,cs,ps,p)==plain
  edges=typed_edges(cipher,p);lengths=[min(p,len(cipher)-s) for s in range(0,len(cipher),p)];assert len(edges)==546
  parent_edges=parent.typed_high_edges(cipher,cs,lengths);assert edges==[(e['a'],e['b'],e['type']) for e in parent_edges]
  cp=positions(cs);pp=positions(ps);actual_t=pp[1]
  reconstructed=[]
  for edge,e in zip(edges,parent_edges):
   a,b,kind=edge;coord=(ax(cp[a],kind[0],4),ax(cp[b],kind[1],4));symbol=ps[4*coord[0]+coord[1]];reconstructed.append(symbol);assert coord==tuple(e['coordinate'])
  assert reconstructed==plain[::2] and 1 not in reconstructed and valid_mapping(edges,cp,actual_t)
  free=compact_solve(4,edges,False,f'p{i}');assert free['status']=='sat' and free['witness'] and valid_mapping(edges,free['witness']['mapping'],free['witness']['forbidden_coordinate'])
  row={'case':i,'period':p,'same_square':cs==ps,'block_lengths':lengths,'has_odd_tail':lengths[-1]%2==1,'global_even_nibbles':546,'edge_types':sorted(set(k for _,_,k in edges)),'edge_sha256':sha_bytes(json.dumps(edges,separators=(',',':')).encode()),'cipher_sha256':sha_bytes(bytes(cipher)),'plaintext_sha256':sha_bytes(raw),'actual_cipher_mapping':cp,'actual_plain_symbol1_coordinate':actual_t,'actual_mapping_satisfies_free_model':True,'literal_coordinate_roundtrip':True,'accepted_parent_typed_edges_exact':True,'free_model':free}
  if cs==ps:
   one=compact_solve(4,edges,True,f'po{i}');assert one['status']=='sat';row['one_square_model']=one
  plants.append(row);all_types.update(row['edge_types'])
 assert all_types=={'RC','CR','RR'} and any(x['has_odd_tail'] for x in plants)
 # A complete RC or RR typed graph alone covers every coordinate and is UNSAT even with free t.
 full=[]
 for kind in ('RC','RR'):
  edges=[(a,b,kind) for a in range(16) for b in range(16)];literal=[]
  for j in range(8):
   mapping=list(range(16));rng.shuffle(mapping);coords={4*ax(mapping[a],kind[0],4)+ax(mapping[b],kind[1],4) for a in range(16) for b in range(16)};assert coords==set(range(16));literal.append({'mapping':mapping,'coordinates':sorted(coords)})
  mapping=literal[0]['mapping'];t0=time.perf_counter();fixed=model.solve(4,edges,False,10000,f'f{kind}',mapping);elapsed=time.perf_counter()-t0;smt=fixed['smt2'];fixed['smt2_sha256']=sha_bytes(smt.encode());fixed['smt2_bytes']=len(smt.encode());fixed['elapsed_seconds']=elapsed;assert fixed['status']=='unsat'
  full.append({'type':kind,'edge_count':256,'fixed_mapping_model':fixed,'literal_mappings':literal,'literal_all_256_symbol_pairs_cover_all_16_coordinates':True,'general_unsat_reason':'for any bijective mapping, each selected axis has four nonempty classes, so the Cartesian product over all symbol pairs contains all 16 coordinate pairs'})
 result={'identity':IDENTITY,'target_evaluated':False,'rev7_read':False,'seed':SEED,'model':'typed coordinate avoidance; free forbidden coordinate primary, t=k[1] separate one-square option','source_hashes':{**PINS,'model.py':sha_path(HERE/'model.py'),'controls.py':sha_path(Path(__file__))},'runtime':{'python':__import__('sys').version.split()[0],'z3':model.z3.get_version_string()},'reduced_cases':reduced,'full_plants':plants,'full_graphs':full,'assertions':{'reduced_all_24_squares_times_4_coordinates_exact':True,'reduced_free_and_one_square_options_exact':True,'all_four_edge_types_covered_across_reduced_controls':True,'constant_odd_period_N1092_reachable_types':['CR','RC','RR'],'global_nibble_parity_and_odd_tails_covered':True,'six_full_ascii_plants_literal_roundtrip':True,'accepted_parent_edge_metadata_exact':True,'complete_RC_and_RR_fixed_mapping_solver_unsat_and_general_cartesian_theorem':True},'limits':['SAT means only that some coordinate can be absent; it does not establish valid UTF-8 or text.','This necessary bag213 filter does not encode the output-square inverse lookup.','No symmetry breaking, Rev7 data, target solver run, or completeness claim for a target grid is present.']}
 return result
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args();built=build();out=HERE/'controls.json'
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit('refusing existing output')
  a.regenerate.write_text(json.dumps(built,sort_keys=True,indent=2)+'\n');print(json.dumps({'identity':IDENTITY,'output':str(a.regenerate),'sha256':sha_path(a.regenerate),'reduced_cases':len(built['reduced_cases']),'full_plants':len(built['full_plants'])}));return
 saved=json.loads(out.read_text());assert deterministic(saved)==deterministic(built);print(json.dumps({'identity':IDENTITY,'verified':True,'ledger_sha256':sha_path(out),'reduced_cases':len(built['reduced_cases']),'full_plants':len(built['full_plants']),'target_evaluated':False}))
if __name__=='__main__':main()
