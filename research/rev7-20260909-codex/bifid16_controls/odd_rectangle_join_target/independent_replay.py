#!/usr/bin/env python3
"""ASTRA independent saved-graph replay; does not import the production join model."""
from __future__ import annotations
import argparse,hashlib,itertools,json
from pathlib import Path
IDENTITY='ASTRA';HERE=Path(__file__).resolve().parent;PKG=HERE.parent;TYPES=('RR','RC','CR','CC');SIDE=4
FILES={
 'parent_result':(PKG/'odd_single_graph_target/target_results.json','1c90eaaf17af19b51d20ee29e720e4ee14fb7cd3c15ea9b919ff2ada28b1443d'),
 'parent_receipt':(PKG/'odd_single_graph_target/verification.json','5552bcbad04d7019c13bd22f32bde1d1f1bba8036262b69a6688fc5784142952'),
 'join_result':(HERE/'target_results.json','46fe703714c05abf9fe32127f9e1517a1e8a6db8b4184b4825130611e66b6df4'),
 'join_receipt':(HERE/'verification.json','3facf405ef174105bec0b51438f74532b5fc603a15260e335349f4a677ba3ff8'),
 'join_driver':(HERE/'run_target.py','0520c0f710b281735e594f29a3375c922ad4eb5acba7aa83d7872ea4832b3d8d'),
 'join_gate':(HERE/'target_gate.json','0ab98eb9ce6f8e5018a515aeec4e3db1a0a1aa67ebf405e7ba599ddd504b2151'),
 'even_broad_reconciliation':(PKG/'even_rectangle_target/broad_reconciliation.json','a5dbf6d4dd79769daf7756160f7f3d861c2aa3dfdebc6dfc1514aae238434295')}
def hb(x):return hashlib.sha256(x).hexdigest()
def sha(p):return hb(Path(p).read_bytes())
def canon(x):return json.dumps(x,sort_keys=True,separators=(',',':')).encode()
def graph_rows(value):
 assert len(value)==64 and all(c in '0123456789abcdef' for c in value)
 bits=int(value,16);rows=[0]*16
 for i in range(256):
  if bits>>i&1:rows[i//16]|=1<<(i%16)
 return tuple(rows)
def pair_candidates(rows):
 # Independent construction: choose the unique shared member first, then three
 # members outside A. This differs from the production all-4-subsets-and-filter loop.
 full=(1<<16)-1;out=[]
 for A in itertools.combinations(range(16),4):
  missing=full
  for a in A:missing&=full^rows[a]
  shared=[x for x in A if missing>>x&1]
  outside=[x for x in range(16) if missing>>x&1 and x not in A]
  for s in shared:
   for tail in itertools.combinations(outside,3):out.append((A,tuple(sorted((s,)+tail))))
 return sorted(out)
def union_rows(rows,left):
 value=0
 for a in left:value|=rows[a]
 return value
def geometry_reason(A,B,C,D,rr,cc):
 if A==D and B==C:kind='diagonal'
 elif not(set(A)&set(D)) and not(set(B)&set(C)) and all(len(set(x)&set(y))==1 for x,y in ((A,C),(A,B),(D,C),(D,B))):kind='off_diagonal'
 else:return 'geometry'
 if union_rows(rr,A)&sum(1<<x for x in D):return 'RR_edge'
 if union_rows(cc,C)&sum(1<<x for x in B):return 'CC_edge'
 return None
def replay_cell(saved,parent):
 assert saved['id']==parent['id'] and saved['orientation']==parent['orientation'] and saved['period']==parent['period'] and saved['source_index_metadata_sha256']==parent['source_index_metadata_sha256']
 parent_graphs={x['kind']:x['graph_hex'] for x in parent['types']};assert saved['graph_hex']==parent_graphs and saved['edge_counts']=={x['kind']:x['edge_count'] for x in parent['types']}
 rows={k:graph_rows(parent_graphs[k]) for k in TYPES};rc=pair_candidates(rows['RC']);cr=pair_candidates(rows['CR']);trace=[];reasons={}
 for i,(A,B) in enumerate(rc):
  for j,(C,D) in enumerate(cr):
   reason=geometry_reason(A,B,C,D,rows['RR'],rows['CC']);assert reason is not None,'unexpected coordinate witness in saved UNSAT cell';trace.append([i,j,reason]);reasons[reason]=reasons.get(reason,0)+1
 digest=hashlib.sha256()
 for record in trace:digest.update(json.dumps(record,separators=(',',':')).encode()+b'\n')
 a=saved['analysis'];want={'RC':len(rc),'CR':len(cr),'join_space':len(rc)*len(cr),'joins_examined':len(trace)}
 assert a['status']=='unsat' and a['complete'] is True and a['witness'] is None and a['candidate_counts']==want and a['obstruction_counts']==reasons and a['all_pairs_obstruction_digest']==digest.hexdigest()
 return {'id':saved['id'],'orientation':saved['orientation'],'period':saved['period'],'graph_hex':parent_graphs,'graph_bundle_sha256':hb(canon(parent_graphs)),'RC_candidates':[[list(a),list(b)] for a,b in rc],'CR_candidates':[[list(c),list(d)] for c,d in cr],'candidate_counts':want,'obstruction_counts':reasons,'full_join_trace':trace,'full_join_trace_sha256':digest.hexdigest(),'independent_status':'unsat'}
def build():
 for _name,(path,want) in FILES.items():assert sha(path)==want,(_name,sha(path),want)
 parent=json.loads(FILES['parent_result'][0].read_text());target=json.loads(FILES['join_result'][0].read_text());unresolved=[r for r in parent['cells'] if r['status']=='unresolved'];assert len(unresolved)==80 and len(target['cells'])==80 and [r['id'] for r in unresolved]==[r['id'] for r in target['cells']]
 cells=[replay_cell(saved,prior) for saved,prior in zip(target['cells'],unresolved)];assert sum(x['candidate_counts']['joins_examined'] for x in cells)==5329
 assert sum(x['obstruction_counts'].get('geometry',0) for x in cells)==5165 and sum(x['obstruction_counts'].get('RR_edge',0) for x in cells)==164 and not any(x['obstruction_counts'].get('CC_edge',0) for x in cells)
 broad=json.loads(FILES['even_broad_reconciliation'][0].read_text());assert broad['proof_accounting']['even_cells_excluded_for_any_ordered_pair_of_fixed_cipher_and_plain_squares']==2184
 return {'identity':IDENTITY,'target_evaluated':True,'verification_only':True,'new_target_search':False,'algorithm':'unique-shared-member RC/CR candidate construction plus direct bitmask joins; no production join imports','source_hashes':{name:want for name,(_path,want) in FILES.items()}|{'independent_replay.py':sha(Path(__file__))},'cells':cells,'summary':{'cells':80,'independent_status_counts':{'unsat':80,'sat':0,'incomplete':0},'RC_candidates_total':sum(x['candidate_counts']['RC'] for x in cells),'CR_candidates_total':sum(x['candidate_counts']['CR'] for x in cells),'join_pairs_total':5329,'obstruction_counts':{'geometry':5165,'RR_edge':164,'CC_edge':0},'all_ids_sha256':hb(canon([x['id'] for x in cells]))},'coverage_inputs':{'even_two_fixed_square_cells':2184,'odd_single_graph_excluded':2104,'odd_join_complement_excluded':80,'two_fixed_square_cells_total':4368},'limits':['This replays saved target graph masks and is not a new ciphertext experiment.','The proof uses only absence of high nibble 1, a necessary consequence of bag213; it does not validate complete UTF-8 or plaintext.','Coverage is direct one-layer standard 4x4 Bifid decryption with two fixed squares, four registered orientations, and periods represented by 1..1092.']}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args();got=build();out=HERE/'independent_replay.json'
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit('refusing existing output')
  a.regenerate.write_text(json.dumps(got,sort_keys=True,indent=2)+'\n');print(json.dumps({'identity':IDENTITY,'output':str(a.regenerate),'sha256':sha(a.regenerate),'cells':80,'join_pairs':5329},sort_keys=True));return
 assert json.loads(out.read_text())==got;print(json.dumps({'identity':IDENTITY,'verified':True,'verification_only':True,'new_target_search':False,'ledger_sha256':sha(out),'cells':80,'join_pairs':5329},sort_keys=True))
if __name__=='__main__':main()
