#!/usr/bin/env python3
"""Synthetic-only controls for the inert 48-cell Unicode target driver."""
from pathlib import Path
import argparse,hashlib,importlib.util,json
from Crypto.Cipher import DES
HERE=Path(__file__).resolve().parent;PACKAGE=HERE.parent;LEDGER=HERE/'controls.json';IDENTITY='ASTRA'
def hb(x):return hashlib.sha256(x).hexdigest()
def sha(p):return hb(Path(p).read_bytes())
def load(path,name):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def accounting(row):
 partial=row['partial_root'] is not None
 assert row['accepted_states']==sum(row['accepted_states_by_suffix_byte'])
 assert row['roots_started']==row['roots_completed']+partial
 assert row['roots_completed']+row['roots_unexamined']+partial==row['initial_registers_total']
 assert row['complete']==(row['roots_completed']==row['initial_registers_total'] and not partial)
 assert row['solution_count']==len(row['solutions']) and row['solutions_are_terminal_only']
def plant_summary(row,cipher,suffix):
 truth=sum(bytes.fromhex(x['ciphertext_hex'])==cipher and bytes.fromhex(x['suffix_plaintext_hex'])==suffix for x in row['solutions'])
 assert row['complete'] and truth==1;accounting(row)
 return {'id':row['id'],'initial_registers_total':row['initial_registers_total'],'complete':True,'solution_count':row['solution_count'],'accepted_states':row['accepted_states'],'block_calls':row['block_calls'],'max_live_frontier_per_root':row['max_live_frontier_per_root'],'roots_completed':row['roots_completed'],'truth_retained_exactly_once':True,'terminal_solution_material_sha256':row['terminal_solution_material_sha256'],'validation':row['validation']}
def generate():
 d=load(HERE/'run_target.py','astra_utf8_inert_driver');pack=load(PACKAGE/'pack_controls.py','astra_utf8_pack_binding');maps=d.classes();assert len(maps)==12
 parent=json.loads(pack.unpack_bytes());assert parent['identity']==IDENTITY and parent['target_evaluated'] is False and parent['controls_source_sha256']==d.CONTROLS_SHA
 full=next(x for x in parent['plants'] if x['id']=='full655|drop1|cut3');pr=full['search'];accounting(pr)
 assert not pr['complete'] and pr['capped_reason']=='max_accepted' and pr['accepted_states']==5_000_000 and pr['initial_registers_total']==4096 and pr['roots_completed']==3414 and pr['roots_started']==3415 and pr['roots_unexamined']==681 and pr['partial_root'] is not None and full['truth_retained_exactly_once'] is None
 seeded=json.loads((PACKAGE/'seeded_control.json').read_text());sr=seeded['search'];accounting(sr)
 assert seeded['identity']==IDENTITY and seeded['target_evaluated'] is False and seeded['truth_retained_exactly_once'] is True and sr['complete'] and sr['initial_registers_total']==1 and sr['roots_completed']==1 and sr['partial_root'] is None and sr['solution_count']==182
 wiring=[]
 for meta in maps:
  fixture=d.controls.deterministic_hex(1310,'ASTRA Unicode driver wiring '+meta['class_id']+' ');source=d.controls.source_emit(fixture,meta['representative_key']);assert len(source)==1092
  for orientation in d.ORIENTATIONS:
   canonical=d.orient(source,orientation);assert d.orient(canonical,orientation)==source
   wiring.append({'id':f"{meta['class_id']}|{orientation}",'source_observation_sha256':hb(source.encode()),'canonical_sha256':hb(canonical.encode()),'inverse_exact':True})
 assert [x['id'] for x in wiring]==d.cell_ids() and len({x['id'] for x in wiring})==48
 plants=[];caps=[]
 for k,(drop,cut,orientation) in enumerate(((1,'two','full_hex_reverse'),(3,'three','nibble_swap'))):
  meta=next(x for x in maps if x['dropped_column']==drop);n=24;plain=d.controls.build_plain(n,cut,False);iv=bytes((0x31+k,0x42,0x53,0x64,0x75,0x86,0x97,0xa8));cipher=DES.new(d.core.KEY,DES.MODE_CFB,iv=iv,segment_size=8).encrypt(plain);source=d.controls.source_emit(cipher.hex().upper(),meta['representative_key']);canonical=d.orient(source,orientation)
  row=d.execute_cell(canonical,meta,orientation,nbytes=n);assert row['initial_registers_total']==(4096 if drop==1 else 256);plants.append(plant_summary(row,cipher,plain[8:]))
  cap=d.execute_cell(canonical,meta,orientation,nbytes=n,max_accepted=1);accounting(cap);assert not cap['complete'] and cap['capped_reason']=='max_accepted' and cap['accepted_states']==1 and cap['solution_count']==0 and cap['partial_root'] is not None
  caps.append({'id':cap['id'],'initial_registers_total':cap['initial_registers_total'],'complete':False,'capped_reason':cap['capped_reason'],'accepted_states':cap['accepted_states'],'roots_started':cap['roots_started'],'roots_completed':cap['roots_completed'],'roots_unexamined':cap['roots_unexamined'],'partial_root':cap['partial_root'],'solution_count':0})
 return {'identity':IDENTITY,'target_evaluated':False,'crypto_evaluated':True,'scope':'Synthetic driver wiring for all 48 new Unicode endpoint contexts; two exact-wrapper plants and cap paths cover both dynamic root shapes.','driver_sha256':sha(HERE/'run_target.py'),'parent':{'core_sha256':d.CORE_SHA,'controls_source_sha256':d.CONTROLS_SHA,'pack_source_sha256':d.PACK_SOURCE_SHA,'packed_controls_sha256':d.PACK_SHA,'raw_controls_sha256':pack.RAW_SHA,'raw_controls_length':pack.RAW_LEN,'full_all_roots_control':{'id':full['id'],'status':'INCOMPLETE','initial_registers_total':pr['initial_registers_total'],'roots_started':pr['roots_started'],'roots_completed':pr['roots_completed'],'roots_unexamined':pr['roots_unexamined'],'partial_root_present':True,'accepted_states':pr['accepted_states'],'truth_retained_exactly_once':None}},'seeded':{'source_sha256':d.SEEDED_SOURCE_SHA,'ledger_sha256':d.SEEDED_LEDGER_SHA,'report_sha256':d.SEEDED_REPORT_SHA,'status':'COMPLETE single seeded initial register; synthetic evidence only','initial_registers_total':sr['initial_registers_total'],'roots_completed':sr['roots_completed'],'solution_count':sr['solution_count'],'accepted_states':sr['accepted_states'],'truth_retained_exactly_once':True},'ordered_cell_ids':d.cell_ids(),'orientation_wiring':wiring,'wrapper_plants':plants,'tiny_caps':caps,'assertions':{'parent_pack_losslessly_bound_to_raw_ledger':True,'parent_full_all_roots_control_honestly_incomplete_at_5m':True,'seeded_one_root_truth_honestly_complete_and_not_target_coverage':True,'exact_48_unique_new_cell_ids':True,'all_48_orientation_inverses_exact':True,'both_dynamic_root_shapes_execute_production_wrapper':True,'both_24byte_truths_retained_once':True,'both_cap_paths_incomplete_without_partial_solutions':True,'no_target_read_or_evaluation':True}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args();out=generate()
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit('refusing existing output')
  a.regenerate.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n');print(json.dumps({'identity':IDENTITY,'output':str(a.regenerate),'sha256':sha(a.regenerate)},sort_keys=True))
 else:
  assert json.loads(LEDGER.read_text())==out;print(json.dumps({'identity':IDENTITY,'verified':True,'ledger_sha256':sha(LEDGER),'contexts':48,'target_evaluated':False},sort_keys=True))
if __name__=='__main__':main()
