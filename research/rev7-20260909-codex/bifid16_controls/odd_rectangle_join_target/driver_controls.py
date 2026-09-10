#!/usr/bin/env python3
"""ASTRA synthetic controls for the inert 80-cell join wrapper."""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,random,sys
from pathlib import Path
IDENTITY='ASTRA';HERE=Path(__file__).resolve().parent;PKG=HERE.parent;SEED=20260911
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
RT=load('astra_join_wrapper_controls',HERE/'run_target.py');JC=load('astra_join_accepted_controls',PKG/'odd_rectangle_join/controls.py')
PINS={'run_target.py':None,'selection_controls.py':None,'selection_controls.json':None,'../odd_rectangle_join/model.py':'221ea25d48f80a26476e1fe4abea0e89e099bf35f4325ed8e8f7aef6bd00be45','../odd_rectangle_join/controls.py':'ba95fb05db8608dfeada0fd953f4d7d53b9c860c35922553a0b215faf21d7f8d','../odd_rectangle_join/controls.json':'62c78645ffd10d892e54225a88917a63ad7e8fee99f80f1b1feae3788440dc23','../odd_rectangle_join/cap_semantics.py':'747c504148e5bd502c89bbbd57c918b24da5900593bb52cb05503b7ebd6ac249','../odd_rectangle_join/cap_semantics.json':'f2defd85271236da7928c1ab1156fc66c7b41523dae417e4502b922053f89bbe'}
def build():
 for rel,want in PINS.items():
  if want is not None:assert sha(HERE/rel)==want
 selection=json.loads((HERE/'selection_controls.json').read_text());assert selection['selected_count']==80
 # Reduced side-2 cases use the identical wrapper entry point and an independent full mapping oracle.
 reduced=[]
 for name,edges in JC.accepted_graphs()[:4]:
  graphs=JC.graph(edges);row=RT.execute_graph_cell(name,graphs,side=2,max_join_pairs=1_000_000,max_cross_candidates=1_000_000);oracle_sat,w=JC.oracle(2,graphs);assert row['analysis']['status'] in ('sat','unsat') and (row['analysis']['status']=='sat')==oracle_sat
  if row['analysis']['status']=='unsat':assert not oracle_sat and row['analysis']['complete']
  if row['analysis']['status']=='sat':assert oracle_sat and RT.literal_witness_valid(graphs,row['analysis']['witness'],2)
  reduced.append({'name':name,'oracle_sat':oracle_sat,'row':row})
 # Six accepted 546-byte plants. At the registered 10k preprocessing cap they remain incomplete;
 # their independently known actual square coordinate witness proves this cannot become exclusion.
 rng=random.Random(SEED)
 for _ in range(8*4*4*4):rng.random()
 plants=[]
 for i,period in enumerate((3,5,31,99,1091,1091)):
  cipher_square=list(range(16));rng.shuffle(cipher_square);plain_square=cipher_square[:] if i in (0,3) else list(range(16));rng.shuffle(plain_square) if plain_square!=cipher_square else None
  raw=JC.plain_bytes(i);plain=[v for byte in raw for v in (byte>>4,byte&15)];cipher=JC.encrypt(plain,cipher_square,plain_square,period);assert JC.decrypt(cipher,cipher_square,plain_square,period)==plain
  graphs=JC.graph(JC.typed_edges(cipher,period));row=RT.execute_graph_cell(f'plant_{i}',graphs);cp=JC.positions(cipher_square);actual={'mapping':cp,'forbidden_coordinate':JC.positions(plain_square)[1]};assert JC.literal_valid(graphs,actual,4) and RT.literal_witness_valid(graphs,actual,4);assert row['analysis']['status'] in ('sat','incomplete')
  plants.append({'case':i,'period':period,'cipher_sha256':hashlib.sha256(bytes(cipher)).hexdigest(),'actual_witness_valid':True,'row':row})
 # Dense manufactured full-4x4 graph with a known coordinate witness exercises the
 # wrapper's SAT branch under the registered caps. It is graph-only, not a plaintext claim.
 mapping=list(range(16));forbidden=1
 dense={}
 for kind in RT.TYPES:
  edges=set()
  for a in range(16):
   for b in range(16):
    left=mapping[a]//4 if kind[0]=='R' else mapping[a]%4;right=mapping[b]//4 if kind[1]=='R' else mapping[b]%4
    if 4*left+right!=forbidden:edges.add((a,b))
  dense[kind]=edges
 dense_sat=RT.execute_graph_cell('dense_graph_sat',dense);assert dense_sat['analysis']['status']=='sat' and RT.literal_witness_valid(dense,dense_sat['analysis']['witness'],4);assert RT.literal_witness_valid(dense,{'mapping':mapping,'forbidden_coordinate':forbidden},4)
 # Reachable p=1 binary negative: RC contains every diagonal symbol pair. For any two
 # row/column partitions, the forbidden row and column meet in a symbol s, so (s,s) obstructs it.
 cipher=[(i//2)%16 for i in range(1092)];graphs=RT.graphs_from_cipher(cipher,1);assert graphs['RC']=={(s,s) for s in range(16)} and not graphs['RR'] and not graphs['CR'] and not graphs['CC'];negative=RT.execute_graph_cell('binary_p1_negative',graphs);assert negative['analysis']['status']=='unsat' and negative['analysis']['complete'] and negative['analysis']['candidate_counts']['RC']==0
 # Force the actual join-cap branch independently of preprocessing on side 2.
 empty={k:set() for k in RT.TYPES};capped=RT.execute_graph_cell('side2_join_cap',empty,side=2,max_join_pairs=0,max_cross_candidates=1000);assert capped['analysis']['status']=='incomplete' and capped['analysis']['complete'] is False and capped['analysis']['candidate_counts']['joins_examined']==0 and capped['analysis']['witness'] is None
 return {'identity':IDENTITY,'target_evaluated':False,'canonical_ciphertext_extracted':False,'prior_target_ledger_read':True,'new_target_search':False,'seed':SEED,'registered_caps':{'max_cross_candidates':RT.MAX_CROSS_CANDIDATES,'max_join_pairs':RT.MAX_JOIN_PAIRS},'source_hashes':{'run_target.py':sha(HERE/'run_target.py'),'selection_controls.py':sha(HERE/'selection_controls.py'),'selection_controls.json':sha(HERE/'selection_controls.json'),'driver_controls.py':sha(Path(__file__)),**{k:sha(HERE/k) for k in PINS if k.startswith('../')}},'selection':{'count':80,'selection_sha256':selection['selection_sha256'],'first_id':selection['ordered_ids'][0],'last_id':selection['ordered_ids'][-1]},'reduced_same_path':reduced,'full_plants_same_path':plants,'dense_graph_sat_same_path':dense_sat,'binary_p1_negative':negative,'join_cap_same_path':capped,'assertions':{'four_reduced_cases_match_independent_full_mapping_oracle':True,'six_full_plants_preserve_independently_known_coordinate_witness':True,'dense_full4x4_graph_exercises_sat_branch':True,'binary_p1_negative_exhaustive_unsat':True,'join_cap_is_incomplete_without_witness':True},'limits':['The six full plants reaching a cap test non-exclusion semantics; they do not claim the registered cap usually finds a SAT witness.','The binary p=1 negative is not a text plant.','No Rev7 ciphertext was extracted or joined; only the accepted prior 80-row selection ledger was read.']}
def deterministic(x):
 x=json.loads(json.dumps(x))
 for group in ('reduced_same_path','full_plants_same_path'):
  for row in x[group]:row['row'].pop('elapsed_seconds',None)
 x['dense_graph_sat_same_path'].pop('elapsed_seconds',None);x['binary_p1_negative'].pop('elapsed_seconds',None);x['join_cap_same_path'].pop('elapsed_seconds',None)
 return x
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args();got=build();out=HERE/'driver_controls.json'
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit('refusing existing output')
  a.regenerate.write_text(json.dumps(got,sort_keys=True,indent=2)+'\n');print(json.dumps({'identity':IDENTITY,'output':str(a.regenerate),'sha256':sha(a.regenerate),'plants':6,'target_evaluated':False},sort_keys=True));return
 assert deterministic(json.loads(out.read_text()))==deterministic(got);print(json.dumps({'identity':IDENTITY,'verified':True,'ledger_sha256':sha(out),'target_evaluated':False},sort_keys=True))
if __name__=='__main__':main()
