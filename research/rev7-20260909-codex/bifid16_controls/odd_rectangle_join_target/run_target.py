#!/usr/bin/env python3
"""ASTRA inert 80-cell exact/capped typed-rectangle join wrapper."""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,os,sys,time
from pathlib import Path
IDENTITY='ASTRA';HERE=Path(__file__).resolve().parent;PKG=HERE.parent;ROOT=HERE.parents[3]
JOIN_PATH=PKG/'odd_rectangle_join/model.py';PARENT_DIR=PKG/'odd_single_graph_target'
PARENT_DRIVER=PARENT_DIR/'run_target.py';PARENT_RESULT=PARENT_DIR/'target_results.json';PARENT_RECEIPT=PARENT_DIR/'verification.json'
SELECT=HERE/'selection_controls.json';GATE=HERE/'target_gate.json';RESULT=HERE/'target_results.json';TMP=HERE/'target_results.json.tmp'
TYPES=('RR','RC','CR','CC');N=1092;MAX_JOIN_PAIRS=1_000_000;MAX_CROSS_CANDIDATES=10_000
PINS={
'odd_rectangle_join/model.py':'221ea25d48f80a26476e1fe4abea0e89e099bf35f4325ed8e8f7aef6bd00be45',
'odd_rectangle_join/controls.py':'ba95fb05db8608dfeada0fd953f4d7d53b9c860c35922553a0b215faf21d7f8d',
'odd_rectangle_join/controls.json':'62c78645ffd10d892e54225a88917a63ad7e8fee99f80f1b1feae3788440dc23',
'odd_rectangle_join/README.md':'61c9586e8fd2573b3db12bdee54479c8a9281975950fd13021524a264d9a4ddc'
,'odd_rectangle_join/cap_semantics.py':'747c504148e5bd502c89bbbd57c918b24da5900593bb52cb05503b7ebd6ac249'
,'odd_rectangle_join/cap_semantics.json':'f2defd85271236da7928c1ab1156fc66c7b41523dae417e4502b922053f89bbe',
'odd_single_graph_target/run_target.py':'3c7ba1c60150a000018da4a1b14d523a827f8ed6b9f2187be39e169135babe06',
'odd_single_graph_target/target_results.json':'1c90eaaf17af19b51d20ee29e720e4ee14fb7cd3c15ea9b919ff2ada28b1443d',
'odd_single_graph_target/verification.json':'5552bcbad04d7019c13bd22f32bde1d1f1bba8036262b69a6688fc5784142952',
}
def hb(x):return hashlib.sha256(x).hexdigest()
def sha(p):return hb(Path(p).read_bytes())
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':')).encode()
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
JOIN=load('astra_odd_rectangle_join_target_model',JOIN_PATH)
def decode_graph(value):
 if len(value)!=64 or any(c not in '0123456789abcdef' for c in value):raise ValueError(value)
 bits=int(value,16);return {(i//16,i%16) for i in range(256) if bits>>i&1}
def graph_hex(edges):return format(sum(1<<(16*a+b) for a,b in edges),'064x')
def independent_metadata(n,p):
 out=[]
 for start in range(0,n,p):
  L=min(p,n-start)
  for i in range(L):
   if (start+i)%2:continue
   lf=i;rf=L+i
   out.append((('R' if lf%2==0 else 'C')+('R' if rf%2==0 else 'C'),start+lf//2,start+rf//2,start,L,i))
 assert len(out)==n//2
 return out
def graphs_from_cipher(cipher,period):
 rows=independent_metadata(len(cipher),period)
 return {k:{(cipher[a],cipher[b]) for typ,a,b,_s,_L,_i in rows if typ==k} for k in TYPES}
def literal_witness_valid(graphs,witness,side=4):
 # Direct coordinate evaluation, independent of JOIN.validate_witness's rectangle sets.
 mapping=witness['mapping'];t=witness['forbidden_coordinate']
 if sorted(mapping)!=list(range(side*side)) or not 0<=t<side*side:return False
 for kind in TYPES:
  for a,b in graphs[kind]:
   left=mapping[a]//side if kind[0]=='R' else mapping[a]%side
   right=mapping[b]//side if kind[1]=='R' else mapping[b]%side
   if side*left+right==t:return False
 return True
def execute_graph_cell(cell_id,graphs,side=4,max_join_pairs=MAX_JOIN_PAIRS,max_cross_candidates=MAX_CROSS_CANDIDATES):
 graphs={k:set(graphs.get(k,set())) for k in TYPES};t=time.perf_counter();analysis=JOIN.analyze(graphs,side=side,max_join_pairs=max_join_pairs,max_cross_candidates=max_cross_candidates);elapsed=time.perf_counter()-t
 assert analysis['status'] in ('sat','unsat','incomplete')
 if analysis['status']=='unsat':assert analysis['complete'] and analysis['candidate_counts']['joins_examined']==analysis['candidate_counts']['join_space'] and 'all_pairs_obstruction_digest' in analysis
 if analysis['status']=='sat':assert not analysis['complete'] and analysis['witness'] is not None and JOIN.validate_witness(graphs,analysis['witness'],side) and literal_witness_valid(graphs,analysis['witness'],side)
 if analysis['status']=='incomplete':assert not analysis['complete'] and analysis['witness'] is None
 return {'id':cell_id,'graph_hex':{k:graph_hex(graphs[k]) for k in TYPES},'edge_counts':{k:len(graphs[k]) for k in TYPES},'analysis':analysis,'elapsed_seconds':elapsed}
def selection_rows():
 s=json.loads(SELECT.read_text());assert s['identity']==IDENTITY and s['selected_count']==80
 return s['selected']
def scope():return {'identity':IDENTITY,'model':'joint typed-rectangle coordinate avoidance for two arbitrary fixed 4x4 Bifid squares under bag213','input':'exact 80 unresolved cells selected from the accepted odd single-graph result','cells':80,'side':4,'typed_graphs':list(TYPES),'max_join_pairs_per_cell':MAX_JOIN_PAIRS,'max_cross_candidates_per_type_per_cell':MAX_CROSS_CANDIDATES,'status_meaning':{'unsat':'exhaustive coordinate-avoidance exclusion','sat':'coordinate witness only; unresolved','incomplete':'cap reached; unresolved'},'maximum_join_pairs_examined':80*MAX_JOIN_PAIRS}
def source_pins():
 out={f'research/rev7-20260909-codex/bifid16_controls/{k}':v for k,v in PINS.items()}
 out['research/rev7-20260909-codex/bifid16_controls/odd_rectangle_join_target/selection_controls.py']=sha(HERE/'selection_controls.py')
 out['research/rev7-20260909-codex/bifid16_controls/odd_rectangle_join_target/selection_controls.json']=sha(SELECT)
 for name in ('driver_controls.py','driver_controls.json','README.md','preflight.py','build_gate.py','target_gate.template.json'):
  q=HERE/name
  if q.exists():out[f'research/rev7-20260909-codex/bifid16_controls/odd_rectangle_join_target/{name}']=sha(q)
 return out
def check_pins():
 for rel,want in PINS.items():assert sha(PKG/rel)==want,(rel,sha(PKG/rel),want)
def require_gate():
 g=json.loads(GATE.read_text());assert g['identity']==IDENTITY and g['authorized'] is True and g['target_evaluated'] is False and g['scope']==scope();assert g['driver_sha256']==sha(Path(__file__)) and g['source_pins']==source_pins();return g
def bind_selected_to_parent():
 # This is deliberately target-mode only: it reuses the accepted parent extraction and
 # independently checks each source-index tuple and graph against the canonical input.
 parent=load('astra_join_parent_driver',PARENT_DRIVER);parent.check_parents();raw=parent.extract();prior=json.loads(PARENT_RESULT.read_text());selected=selection_rows();unresolved=[r for r in prior['cells'] if r['status']=='unresolved'];assert [x['id'] for x in selected]==[x['id'] for x in unresolved] and len({x['id'] for x in selected})==80;by_id={r['id']:r for r in prior['cells']};out=[]
 for sel in selected:
  row=by_id[sel['id']];assert row['status']=='unresolved' and row['orientation']==sel['orientation'] and row['period']==sel['period'] and row['source_index_metadata_sha256']==sel['source_index_metadata_sha256'];cipher=[int(x,16) for x in parent.orient(raw,row['orientation'])];parent.verify_cell(row,cipher)
  graphs=graphs_from_cipher(cipher,row['period']);assert {k:graph_hex(graphs[k]) for k in TYPES}==sel['graphs'];assert {k:len(graphs[k]) for k in TYPES}==sel['edge_counts']
  out.append((sel,row,graphs))
 return out
def run_target():
 check_pins();gate=require_gate();assert not RESULT.exists() and not TMP.exists(),'refusing existing result/tmp';cells=[];started=time.time()
 for sel,_prior,graphs in bind_selected_to_parent():
  row=execute_graph_cell(sel['id'],graphs);row.update({'orientation':sel['orientation'],'period':sel['period'],'source_index_metadata_sha256':sel['source_index_metadata_sha256']});cells.append(row)
  checkpoint={'identity':IDENTITY,'target_evaluated':True,'status':'running','completed_cells':len(cells),'cells':cells};TMP.write_text(json.dumps(checkpoint,sort_keys=True,indent=2)+'\n')
 counts={s:sum(r['analysis']['status']==s for r in cells) for s in ('unsat','sat','incomplete')}
 out={'identity':IDENTITY,'target_evaluated':True,'status':'complete','scope':scope(),'configuration':{'gate_sha256':sha(GATE),'driver_sha256':sha(Path(__file__)),'source_pins':source_pins(),'prior_result_sha256':PINS['odd_single_graph_target/target_results.json'],'prior_receipt_sha256':PINS['odd_single_graph_target/verification.json']},'cells':cells,'summary':{'cells':80,'status_counts':counts,'join_pairs_examined':sum(r['analysis']['candidate_counts']['joins_examined'] for r in cells),'elapsed_seconds':time.time()-started}}
 TMP.write_text(json.dumps(out,sort_keys=True,indent=2)+'\n');os.replace(TMP,RESULT);print(json.dumps({'identity':IDENTITY,'result_sha256':sha(RESULT),**out['summary']},sort_keys=True))
def verify_results():
 check_pins();require_gate();d=json.loads(RESULT.read_text());assert d['identity']==IDENTITY and d['target_evaluated'] is True and d['status']=='complete' and d['scope']==scope();assert d['configuration']['gate_sha256']==sha(GATE) and d['configuration']['driver_sha256']==sha(Path(__file__)) and d['configuration']['source_pins']==source_pins() and d['configuration']['prior_result_sha256']==PINS['odd_single_graph_target/target_results.json'] and d['configuration']['prior_receipt_sha256']==PINS['odd_single_graph_target/verification.json']
 bound=bind_selected_to_parent();assert len(d['cells'])==len(bound)==80;counts={s:0 for s in ('unsat','sat','incomplete')};examined=0
 for saved,(sel,_prior,graphs) in zip(d['cells'],bound):
  assert saved['id']==sel['id'] and saved['orientation']==sel['orientation'] and saved['period']==sel['period'] and saved['source_index_metadata_sha256']==sel['source_index_metadata_sha256'];rebuilt=execute_graph_cell(sel['id'],graphs);rebuilt.pop('elapsed_seconds');copy=dict(saved);copy.pop('elapsed_seconds');assert rebuilt=={k:copy[k] for k in rebuilt};counts[saved['analysis']['status']]+=1;examined+=saved['analysis']['candidate_counts']['joins_examined']
 assert d['summary']['cells']==80 and d['summary']['status_counts']==counts and d['summary']['join_pairs_examined']==examined
 print(json.dumps({'identity':IDENTITY,'verification_only':True,'new_target_search':False,'result_sha256':sha(RESULT),'cells':80,'status_counts':counts,'join_pairs_examined':examined},sort_keys=True))
def main():
 ap=argparse.ArgumentParser();g=ap.add_mutually_exclusive_group();g.add_argument('--run-target',action='store_true');g.add_argument('--verify',action='store_true');a=ap.parse_args()
 if a.run_target:run_target()
 elif a.verify:verify_results()
 else:check_pins();print(json.dumps({'identity':IDENTITY,'target_evaluated':False,'canonical_ciphertext_extracted':False,'scope':scope(),'driver_sha256':sha(Path(__file__)),'source_pins':source_pins(),'gate_present':GATE.exists()},sort_keys=True,indent=2))
if __name__=='__main__':main()
