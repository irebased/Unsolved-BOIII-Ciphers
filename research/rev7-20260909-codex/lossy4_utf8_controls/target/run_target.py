#!/usr/bin/env python3
"""Inert gated 48-cell exact-201-codepoint lossy-map DES all-IV target driver."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,os
HERE=Path(__file__).resolve().parent;PACKAGE=HERE.parent;ROOT=HERE.parents[3];IDENTITY='ASTRA';ORIENTATIONS=('forward','full_hex_reverse','byte_reverse','nibble_swap');NBYTES=655;MAX_FRONTIER=100_000;MAX_ACCEPTED=5_000_000
MDX=ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx';DATA=ROOT/'lavender/src/data/ciphers/revelations.json';INVENTORY=ROOT/'research/char_amsco/astra/lossy4_onechar_inventory/inventory.json';GATE=HERE/'target_gate.json';RESULT=HERE/'target_results.json'
MDX_SHA='085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91';DATA_SHA='68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e';TEXT_SHA='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c';INVENTORY_SHA='fa9d7463848918d2eaddfe6afdf013f2d5b6b1d1c2011aa5d0aa5a197eec4fe2';CORE_SHA='7a10f904bbfdc027bae27816e3a8e4fff351869bd7cf063cb898a5fdbb7d2879';CONTROLS_SHA='9deac8ce129a8f5198eabebcb2d972722bfeb808e910cbae291d52b6396f660e';PACK_SHA='12cfbef7fd95c054251b2413ee6764da968bc71868b3e35797ba7685ffef366a';PACK_SOURCE_SHA='b05467c3a0a6bf5642c69dd00b74d88ae4c7d01b1174cca37d488407b748cbe0';SEEDED_SOURCE_SHA='0fb87d5c5863aba922a0eefc8cfcdcedf7c597ee802c0f4348d73783bdf994d9';SEEDED_LEDGER_SHA='f62b4798bf82c3d6f4c509ac783b05849a465331dab306dbbfe7cebf8e676c79';SEEDED_REPORT_SHA='42472b53a802f75b328b06dad434213c4ff8da6769c93929f389eddbd1ad6b73'
REQUIRED=('research/rev7-20260909-codex/lossy4_utf8_controls/core.py','research/rev7-20260909-codex/lossy4_utf8_controls/controls.py','research/rev7-20260909-codex/lossy4_utf8_controls/controls.pack.json','research/rev7-20260909-codex/lossy4_utf8_controls/pack_controls.py','research/rev7-20260909-codex/lossy4_utf8_controls/README.md','research/rev7-20260909-codex/lossy4_utf8_controls/REPORT.md','research/rev7-20260909-codex/lossy4_utf8_controls/seeded_control.py','research/rev7-20260909-codex/lossy4_utf8_controls/seeded_control.json','research/rev7-20260909-codex/lossy4_utf8_controls/SEEDED_CONTROL.md','research/rev7-20260909-codex/coverage/transposition_byte_bag/proof.py','research/rev7-20260909-codex/coverage/transposition_byte_bag/controls.json','research/rev7-20260909-codex/coverage/transposition_byte_bag/README.md','research/rev7-20260909-codex/coverage/transposition_byte_bag/REPORT.md','research/char_amsco/astra/lossy4_onechar_inventory/inventory.py','research/char_amsco/astra/lossy4_onechar_inventory/inventory.json','research/char_amsco/astra/lossy4_onechar_inventory/README.md','research/char_amsco/astra/lossy4_onechar_inventory/REPORT.md','research/char_amsco/astra/cryptool_bug/analyze.py','research/char_amsco/astra/cryptool_bug/evidence.json','research/char_amsco/astra/cryptool_bug/source/class.amsco.php.base64','research/char_amsco/astra/cryptool_bug/source/default_tool.php','research/char_amsco/astra/cryptool_bug/source/infobox.template','research/char_amsco/astra/amsco_geometry.py','research/rev7-20260909-codex/lossy4_utf8_controls/target/driver_controls.py','research/rev7-20260909-codex/lossy4_utf8_controls/target/controls.json','research/rev7-20260909-codex/lossy4_utf8_controls/target/README.md','research/rev7-20260909-codex/lossy4_utf8_controls/target/prepare_gate.py','lavender/src/data/ciphers/revelations.json')
def hb(x):return hashlib.sha256(x).hexdigest()
def sha(p):return hb(Path(p).read_bytes())
def load(path,name):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
assert sha(PACKAGE/'core.py')==CORE_SHA and sha(PACKAGE/'controls.py')==CONTROLS_SHA and sha(PACKAGE/'controls.pack.json')==PACK_SHA and sha(PACKAGE/'pack_controls.py')==PACK_SOURCE_SHA and sha(PACKAGE/'seeded_control.py')==SEEDED_SOURCE_SHA and sha(PACKAGE/'seeded_control.json')==SEEDED_LEDGER_SHA and sha(PACKAGE/'SEEDED_CONTROL.md')==SEEDED_REPORT_SHA and sha(INVENTORY)==INVENTORY_SHA
core=load(PACKAGE/'core.py','astra_utf8_target_core');controls=load(PACKAGE/'controls.py','astra_utf8_target_controls')
def orient(text,name):
 if name=='forward':return text
 if name=='full_hex_reverse':return text[::-1]
 pairs=[text[i:i+2] for i in range(0,len(text),2)]
 if name=='byte_reverse':return ''.join(reversed(pairs))
 if name=='nibble_swap':return ''.join(x[::-1] for x in pairs)
 raise ValueError(name)
def classes():
 inv=json.loads(INVENTORY.read_text());rows=[x for x in inv['map_classes'] if x['input_chars']==1310];assert len(rows)==12 and [x['class_id'] for x in rows]==[f'N1310-C{i:02d}' for i in range(1,13)]
 for x in rows:assert tuple(x['emission_indices'])==controls.source_indices(1310,x['representative_key'])
 return rows
def cell_ids():return [f"{x['class_id']}|{o}" for x in classes() for o in ORIENTATIONS]
def scope():return {'identity':IDENTITY,'contexts':48,'newly_evaluated_contexts':48,'reuse':None,'class_ids':[x['class_id'] for x in classes()],'orientations':list(ORIENTATIONS),'cipher':'DES','key_hex':core.KEY.hex(),'natural_ciphertext_bytes':NBYTES,'observed_hex_characters':1092,'iv_model':'every arbitrary original 8-byte IV through all observation-compatible C[0:8] registers (4096 or 256 by map)','known_suffix_offset':8,'unknown_plaintext_prefix_bytes':8,'endpoint':'exact 201 codepoints: TAB/LF/CR, U+0020..U+007E, U+00A0..U+00FF, U+2013/U+2014/U+2018/U+2019/U+201C/U+201D/U+2026','endpoint_initial_states':'boundary plus every proper codeword-prefix state','endpoint_terminal_rule':'boundary state is present in determinized state-set','max_live_frontier_per_root':MAX_FRONTIER,'max_global_accepted_states_per_context':MAX_ACCEPTED,'cap_semantics':'INCOMPLETE; exact completed/partial/unexamined roots; partial paths are never solutions','retention':'every completed-root terminal full-ciphertext/plaintext-suffix completion, including those retained before a later cap; no scoring or beam pruning'}
def extract_target():
 assert sha(MDX)==MDX_SHA and sha(DATA)==DATA_SHA;t=MDX.read_text();a=t.index('`83 B57B2')+1;b=t.index('`',a);s=''.join(t[a:b].split()).upper();d=''.join(next(x for x in json.loads(DATA.read_text()) if x.get('id')=='rev7')['ciphertext'].split()).upper();assert s==d and len(s)==1092 and hb(s.encode())==TEXT_SHA;return s
def execute_cell(canonical,meta,orientation,nbytes=NBYTES,max_frontier=MAX_FRONTIER,max_accepted=MAX_ACCEPTED):
 observed=orient(canonical,orientation);assert orient(observed,orientation)==canonical;indices=controls.source_indices(2*nbytes,meta['representative_key']);map_sha=hb(json.dumps(list(indices),separators=(',',':')).encode());
 if nbytes==NBYTES:assert map_sha==meta['map_sha256']
 row=core.search(observed,nbytes,indices,max_frontier,max_accepted);validation=controls.validate(row,observed,nbytes,meta['representative_key']);material=b''.join(bytes.fromhex(x['ciphertext_hex'])+bytes.fromhex(x['suffix_plaintext_hex']) for x in row['solutions'])
 return {'id':f"{meta['class_id']}|{orientation}",'class_id':meta['class_id'],'representative_key':meta['representative_key'],'map_sha256':map_sha,'dropped_column':meta['dropped_column'],'orientation':orientation,'observed_sha256':hb(observed.encode()),'observed_length':len(observed),'inverse_orientation_exact':True,'terminal_solution_material_sha256':hb(material),'validation':validation,**row}
def require_gate():
 gate=json.loads(GATE.read_text());assert gate['identity']==IDENTITY and gate['target_evaluated'] is False and gate['scope']==scope() and gate['driver_sha256']==sha(Path(__file__)) and gate['mdx_sha256']==MDX_SHA and gate['dataset_sha256']==DATA_SHA and gate['canonical_text_sha256']==TEXT_SHA and set(gate['artifact_hashes'])==set(REQUIRED)
 for rel,want in gate['artifact_hashes'].items():assert sha(ROOT/rel)==want,(rel,sha(ROOT/rel),want)
 return gate
def run_target():
 tmp=RESULT.with_suffix('.json.tmp')
 if RESULT.exists() or tmp.exists():raise SystemExit('refusing existing result or temporary file')
 gate=require_gate();canonical=extract_target();cells=[execute_cell(canonical,m,o) for m in classes() for o in ORIENTATIONS];assert [x['id'] for x in cells]==cell_ids()
 out={'identity':IDENTITY,'target_evaluated':True,'scope':scope(),'configuration':{'gate_sha256':sha(GATE),'driver_sha256':sha(Path(__file__)),'core_sha256':CORE_SHA,'controls_source_sha256':CONTROLS_SHA,'packed_controls_sha256':PACK_SHA,'seeded_source_sha256':SEEDED_SOURCE_SHA,'seeded_ledger_sha256':SEEDED_LEDGER_SHA,'inventory_sha256':INVENTORY_SHA,'mdx_sha256':MDX_SHA,'dataset_sha256':DATA_SHA,'canonical_text_sha256':TEXT_SHA,'artifact_hashes':gate['artifact_hashes']},'cells':cells,'summary':{'contexts':48,'complete_contexts':sum(x['complete'] for x in cells),'incomplete_contexts':sum(not x['complete'] for x in cells),'terminal_solutions':sum(x['solution_count'] for x in cells),'accepted_states':sum(x['accepted_states'] for x in cells),'block_calls':sum(x['block_calls'] for x in cells)}}
 tmp.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n');os.replace(tmp,RESULT);print(json.dumps({'identity':IDENTITY,'result_sha256':sha(RESULT),**out['summary']},sort_keys=True))
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--run-target',action='store_true');a=ap.parse_args()
 if a.run_target:run_target()
 else:
  if GATE.exists():require_gate()
  assert sha(MDX)==MDX_SHA and sha(DATA)==DATA_SHA
  print(json.dumps({'identity':IDENTITY,'target_evaluated':False,'handling':'MDX and dataset bytes hashed only; target text is not extracted or evaluated','gate_present':GATE.exists(),'driver_sha256':sha(Path(__file__)),'scope':scope()},indent=2,sort_keys=True))
if __name__=='__main__':main()
