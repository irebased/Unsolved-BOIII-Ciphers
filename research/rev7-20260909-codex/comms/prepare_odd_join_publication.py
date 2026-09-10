#!/usr/bin/env python3
"""ASTRA explicit frozen join-evidence publication manifest; no network."""
from pathlib import Path
import ast,hashlib,json
B=Path('research/rev7-20260909-codex');PKG=B/'bifid16_controls';COMMS=B/'comms'
PARENT='f1df87c53a2f403d6557adc83f09c90440489215'
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def record(p):
 p=Path(p);b=p.read_bytes();b.decode('utf-8')
 return {'path':str(p),'bytes':len(b),'sha256':sha(p),'git_blob_sha1':hashlib.sha1(('blob '+str(len(b))+'\0').encode()+b).hexdigest()}
folders={
 'odd_rectangle_join':['model.py','controls.py','controls.json','README.md','cap_semantics.py','cap_semantics.json'],
 'odd_rectangle_join_target':['run_target.py','selection_controls.py','selection_controls.json','driver_controls.py','driver_controls.json','preflight.py','build_gate.py','target_gate.template.json','target_gate.json','README.md','target_results.json','verification.json','RESULTS.md','independent_replay.py','independent_replay.json','reconcile_two_squares.py','two_square_coverage.json','COVERAGE_FINAL.md']}
paths={str(PKG/d/n) for d,names in folders.items() for n in names}
paths|={str(COMMS/n) for n in ['odd-join-go-20260910.json','join-result-and-interpretation-20260910.json','prepare_odd_join_publication.py','publish_odd_join_trees.py']}
coverage=json.loads((PKG/'odd_rectangle_join_target/two_square_coverage.json').read_text())
assert coverage['identity']=='ASTRA' and coverage['verification_only'] is True and coverage['new_target_search'] is False and coverage['excluded_cells']==4368 and coverage['unresolved_cells']==0
assert coverage['all_partitions_pairwise_disjoint'] and coverage['union_equals_complete_cartesian_grid']
receipt=json.loads((PKG/'odd_rectangle_join_target/verification.json').read_text())
assert receipt=={'cells':80,'identity':'ASTRA','join_pairs_examined':5329,'new_target_search':False,'result_sha256':sha(PKG/'odd_rectangle_join_target/target_results.json'),'status_counts':{'incomplete':0,'sat':0,'unsat':80},'verification_only':True}
oldtree=json.loads((COMMS/'odd_graph_recursive_tree.json').read_text());assert oldtree['sha']=='74d0d112edbbd1be8f45b92c38cfb212de3e586e' and not oldtree['truncated'];remote={x['path']:x for x in oldtree['tree']}
# Preserve the already verified prior-stage transitive dependency closure.
old=json.loads((COMMS/'odd_graph_publication_manifest.json').read_text());deps={r['path'] for r in old['artifacts']+old['existing_dependencies']}
for rel in ['odd_rectangle_join/controls.py','odd_rectangle_join_target/run_target.py','odd_rectangle_join_target/driver_controls.py','odd_rectangle_join_target/selection_controls.py','odd_rectangle_join_target/reconcile_two_squares.py']:
 for node in ast.parse((PKG/rel).read_text()).body:
  if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='PINS' for t in node.targets):
   for k,v in ast.literal_eval(node.value).items():
    f=((PKG/rel).parent/k if rel=='odd_rectangle_join_target/driver_controls.py' else PKG/k).resolve().relative_to(Path.cwd())
    if v is None:
     assert rel=='odd_rectangle_join_target/driver_controls.py' and k in ('run_target.py','selection_controls.py','selection_controls.json');v=sha(f)
    assert sha(f)==v,(str(f),v);deps.add(str(f))
for g in ['odd_rectangle_join_target/target_gate.json','odd_single_graph_target/target_gate.json']:
 gate=json.loads((PKG/g).read_text());assert gate['driver_sha256']==sha((PKG/g).parent/'run_target.py')
 for rel,w in gate['source_pins'].items():assert sha(rel)==w;deps.add(rel)
for rel,w in coverage['source_hashes'].items():assert sha(PKG/rel)==w;deps.add(str(PKG/rel))
for rel in list(deps):
 rec=record(rel)
 if rel not in remote:paths.add(rel)
 elif remote[rel]['sha']!=rec['git_blob_sha1']:raise AssertionError(('changed published dependency',rel))
deps-=paths
artifacts=[record(p) for p in sorted(paths)];existing=[record(p) for p in sorted(deps)];batches=[];batch=[];size=0
for r in artifacts:
 if size+r['bytes']>6000000 and batch:batches.append(batch);batch=[];size=0
 batch.append(r['path']);size+=r['bytes']
if batch:batches.append(batch)
m={'identity':'ASTRA','parent_commit':PARENT,'base_tree':oldtree['sha'],'artifacts':artifacts,'existing_dependencies':existing,'total_bytes':sum(r['bytes'] for r in artifacts),'batches':batches,'runtime':'Current join/control/independent/coverage replay uses Python standard library only. Old reference SMT controls retain their separate published Z3 runtime instructions.'}
out=COMMS/'odd_join_publication_manifest.json'
with out.open('x') as f:json.dump(m,f,sort_keys=True,indent=2);f.write('\n')
print(json.dumps({'identity':'ASTRA','artifacts':len(artifacts),'existing_dependencies':len(existing),'bytes':m['total_bytes'],'batches':len(batches),'manifest_sha256':sha(out)}))
