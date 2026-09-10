#!/usr/bin/env python3
"""Synthetic-only wiring and wrapper controls for the inert 48-cell logical driver."""
from pathlib import Path
import argparse,hashlib,importlib.util,json
from Crypto.Cipher import DES
HERE=Path(__file__).resolve().parent;LEDGER=HERE/'controls.json';IDENTITY='ASTRA'
def hb(x):return hashlib.sha256(x).hexdigest()
def sha(p):return hb(Path(p).read_bytes())
def load(path,name):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def summarize(row,truth_cipher,truth_suffix):
 truth=[x for x in row['solutions'] if bytes.fromhex(x['ciphertext_hex'])==truth_cipher and bytes.fromhex(x['suffix_plaintext_hex'])==truth_suffix]
 assert row['complete'] and len(truth)==1
 return {'id':row['id'],'initial_registers_total':row['initial_registers_total'],'complete':True,'solution_count':row['solution_count'],'accepted_states':row['accepted_states'],'block_calls':row['block_calls'],'max_live_frontier_per_root':row['max_live_frontier_per_root'],'roots_completed':row['roots_completed'],'truth_retained_exactly_once':True,'terminal_solution_material_sha256':row['terminal_solution_material_sha256'],'validation':row['validation']}
def generate():
 d=load(HERE/'run_target.py','astra_lossy4_driver_controls');maps=d.classes();assert len(maps)==12
 wiring=[];plan=[]
 for meta in maps:
  fixture=d.controls.deterministic_hex(1310,'ASTRA lossy4 driver wiring '+meta['class_id']+' ');observed=d.controls.source_emit(fixture,meta['representative_key']);assert len(observed)==1092
  for orientation in d.ORIENTATIONS:
   canonical=d.orient(observed,orientation);assert d.orient(canonical,orientation)==observed
   action='reuse_prior' if meta['class_id']=='N1310-C01' else 'new_search';cid=f"{meta['class_id']}|{orientation}";wiring.append({'id':cid,'source_observation_sha256':hb(observed.encode()),'canonical_sha256':hb(canonical.encode()),'inverse_exact':True});plan.append({'id':cid,'action':action})
 assert [x['id'] for x in plan]==d.logical_ids() and sum(x['action']=='reuse_prior' for x in plan)==4 and sum(x['action']=='new_search' for x in plan)==44
 c01=maps[0];identity=d.validate_map_identity(c01);assert identity==c01['map_sha256']
 rows=[];caps=[]
 for index,drop in enumerate((1,3)):
  meta=next(x for x in maps if x['dropped_column']==drop);n=99;plain=d.controls.repeat('Short production wrapper plant with printable ASCII 0123456789 !?., ',n);iv=(index+17).to_bytes(8,'big');cipher=DES.new(d.core.KEY,DES.MODE_CFB,iv=iv,segment_size=8).encrypt(plain);observed=d.controls.source_emit(cipher.hex().upper(),meta['representative_key']);orientation=('full_hex_reverse' if drop==1 else 'nibble_swap');canonical=d.orient(observed,orientation)
  row=d.execute_cell(canonical,meta,orientation,nbytes=n);rows.append(summarize(row,cipher,plain[8:]));assert row['initial_registers_total']==(4096 if drop==1 else 256)
  capped=d.execute_cell(canonical,meta,orientation,nbytes=n,max_accepted=1)
  assert not capped['complete'] and capped['capped_reason']=='max_accepted' and capped['solution_count']==0 and capped['partial_root'] and capped['accepted_states']==1
  caps.append({'id':capped['id'],'root_shape':capped['initial_registers_total'],'complete':False,'capped_reason':'max_accepted','accepted_states':1,'roots_completed':capped['roots_completed'],'roots_unexamined':capped['roots_unexamined'],'partial_root':capped['partial_root'],'solutions':[]})
 return {'identity':IDENTITY,'target_evaluated':False,'crypto_evaluated':True,'scope':'Synthetic driver wiring: exact 48 IDs, 4 reuse/44 new plan, and one short exact-wrapper plant plus cap path for each dynamic root shape.','driver_sha256':sha(HERE/'run_target.py'),'parent_core_sha256':d.CORE_SHA,'parent_controls_source_sha256':d.CONTROLS_SHA,'parent_pack_sha256':d.PACK_SHA,'inventory_sha256':d.INVENTORY_SHA,'prior_result_sha256':d.PRIOR_RESULT_SHA,'prior_gate_sha256':d.PRIOR_GATE_SHA,'prior_map_identity_sha256':identity,'plan':plan,'orientation_wiring':wiring,'wrapper_plants':rows,'cap_paths':caps,'assertions':{'exact_48_ordered_ids':True,'exact_4_reused_and_44_new':True,'prior_2013_map_identical':True,'no_reused_cell_scheduled_for_new_search':all(x['action']=='reuse_prior' for x in plan if x['id'].startswith('N1310-C01|')),'all_48_orientation_inverses_exact':True,'both_dynamic_root_shapes_execute_exact_wrapper':{x['initial_registers_total'] for x in rows}=={256,4096},'both_truth_pairs_retained_once':True,'both_cap_paths_incomplete_without_partial_solutions':True,'no_target_read_or_evaluation':True}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args();out=generate()
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit('refusing existing output')
  a.regenerate.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n');print(json.dumps({'identity':IDENTITY,'output':str(a.regenerate),'sha256':sha(a.regenerate)},sort_keys=True))
 else:
  assert json.loads(LEDGER.read_text())==out;print(json.dumps({'identity':IDENTITY,'verified':True,'ledger_sha256':sha(LEDGER),'logical_cells':48,'new_searches':44,'reused':4,'target_evaluated':False},sort_keys=True))
if __name__=='__main__':main()
