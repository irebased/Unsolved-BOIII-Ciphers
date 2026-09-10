#!/usr/bin/env python3
"""Inert gated 48-cell logical / 44-cell new generic lossy-four-map target driver."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,os
HERE=Path(__file__).resolve().parent;PACKAGE=HERE.parent;ROOT=HERE.parents[3]
IDENTITY='ASTRA';ORIENTATIONS=('forward','full_hex_reverse','byte_reverse','nibble_swap');NBYTES=655;MAX_FRONTIER=100_000;MAX_ACCEPTED=5_000_000
MDX=ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx';DATA=ROOT/'lavender/src/data/ciphers/revelations.json';INVENTORY=ROOT/'research/char_amsco/astra/lossy4_onechar_inventory/inventory.json'
PRIOR_RESULT=ROOT/'research/rev7-20260909-codex/lossy2013_alliv_controls/target/target_results.json';PRIOR_GATE=ROOT/'research/rev7-20260909-codex/lossy2013_alliv_controls/target/target_gate.json';PRIOR_CERT=ROOT/'research/rev7-20260909-codex/lossy2013_alliv_controls/target/independent_prefix_certificates.json';OLD_CORE=ROOT/'research/char_amsco/astra/lossy2013/core.py'
MDX_SHA='085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91';DATA_SHA='68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e';TEXT_SHA='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c';INVENTORY_SHA='fa9d7463848918d2eaddfe6afdf013f2d5b6b1d1c2011aa5d0aa5a197eec4fe2';CORE_SHA='8e9727cbd15661002645a6fdd770dcb335b2a0e7eb5b61b15d990194595d9ef8';CONTROLS_SHA='2491ca2fc4764093a14886393087b89473193e8afad2a9ef3f384f3822f85ba8';PACK_SHA='9cf756743e0db8a95f094badedf33ed05181588ba2323005052d05c72bd4a363';PRIOR_RESULT_SHA='bbebe2a33edcdd11f335f2f8f6abc3377f4203e825702613d827128abf63862c';PRIOR_GATE_SHA='dbea147677ad626163cc44a6e49445db65c0ae82cbcd38bd542080c435a988ea';PRIOR_CERT_SHA='e194a07fecd25374d5809bd50435659ded7f54f5a16b13fcc3cb986ee0234abd';OLD_CORE_SHA='abadb49e68477b2875cffb712889798c8206ad3dde2357d7d71a5f5a09d1752e'
GATE=HERE/'target_gate.json';RESULT=HERE/'target_results.json'
REQUIRED=(
 'research/rev7-20260909-codex/lossy4_alliv_controls/core.py','research/rev7-20260909-codex/lossy4_alliv_controls/controls.py','research/rev7-20260909-codex/lossy4_alliv_controls/controls.pack.json','research/rev7-20260909-codex/lossy4_alliv_controls/pack_controls.py','research/rev7-20260909-codex/lossy4_alliv_controls/README.md','research/rev7-20260909-codex/lossy4_alliv_controls/REPORT.md',
 'research/char_amsco/astra/lossy4_onechar_inventory/inventory.py','research/char_amsco/astra/lossy4_onechar_inventory/inventory.json','research/char_amsco/astra/lossy4_onechar_inventory/README.md','research/char_amsco/astra/lossy4_onechar_inventory/REPORT.md',
 'research/char_amsco/astra/cryptool_bug/analyze.py','research/char_amsco/astra/cryptool_bug/evidence.json','research/char_amsco/astra/cryptool_bug/source/class.amsco.php.base64','research/char_amsco/astra/cryptool_bug/source/default_tool.php','research/char_amsco/astra/cryptool_bug/source/infobox.template','research/char_amsco/astra/amsco_geometry.py',
 'research/char_amsco/astra/lossy2013/core.py','research/rev7-20260909-codex/lossy2013_alliv_controls/run.py','research/rev7-20260909-codex/lossy2013_alliv_controls/controls.json','research/rev7-20260909-codex/lossy2013_alliv_controls/target/run_target.py','research/rev7-20260909-codex/lossy2013_alliv_controls/target/target_gate.json','research/rev7-20260909-codex/lossy2013_alliv_controls/target/target_results.json','research/rev7-20260909-codex/lossy2013_alliv_controls/target/verify_results.py','research/rev7-20260909-codex/lossy2013_alliv_controls/target/independent_prefix_certificates.json',
 'research/rev7-20260909-codex/lossy4_alliv_controls/target/driver_controls.py','research/rev7-20260909-codex/lossy4_alliv_controls/target/controls.json','research/rev7-20260909-codex/lossy4_alliv_controls/target/README.md','research/rev7-20260909-codex/lossy4_alliv_controls/target/prepare_gate.py','lavender/src/data/ciphers/revelations.json')
def hb(x):return hashlib.sha256(x).hexdigest()
def sha(p):return hb(Path(p).read_bytes())
def load(path,name):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
assert sha(PACKAGE/'core.py')==CORE_SHA and sha(PACKAGE/'controls.py')==CONTROLS_SHA and sha(PACKAGE/'controls.pack.json')==PACK_SHA and sha(INVENTORY)==INVENTORY_SHA and sha(PRIOR_RESULT)==PRIOR_RESULT_SHA and sha(PRIOR_GATE)==PRIOR_GATE_SHA and sha(PRIOR_CERT)==PRIOR_CERT_SHA and sha(OLD_CORE)==OLD_CORE_SHA
core=load(PACKAGE/'core.py','astra_lossy4_target_core');controls=load(PACKAGE/'controls.py','astra_lossy4_target_controls');old_core=load(OLD_CORE,'astra_lossy4_prior_geometry')
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
def logical_ids():return [f"{x['class_id']}|{o}" for x in classes() for o in ORIENTATIONS]
def scope():return {'identity':IDENTITY,'logical_contexts':48,'newly_evaluated_contexts':44,'reused_prior_contexts':4,'reuse_class_id':'N1310-C01','reuse_basis':'N1310-C01 representative key 2013 has an identical complete N=1310 source emission-index map to the pinned prior 2013/2014 scan','class_ids':[x['class_id'] for x in classes()],'orientations':list(ORIENTATIONS),'cipher':'DES','key_hex':core.KEY.hex(),'natural_ciphertext_bytes':655,'observed_hex_characters':1092,'iv_model':'every arbitrary original 8-byte IV through all observation-compatible C[0:8] registers (4096 or 256 by map)','known_suffix_offset':8,'unknown_plaintext_prefix_bytes':8,'allowed_suffix_bytes':'printable ASCII 32..126 inclusive','max_live_frontier_per_root':MAX_FRONTIER,'max_global_accepted_states_per_new_context':MAX_ACCEPTED,'cap_semantics':'INCOMPLETE; exact completed/partial/unexamined roots; partial paths are never solutions','retention':'every terminal full-ciphertext and plaintext-suffix completion; no scoring or beam pruning'}
def extract_target():
 assert sha(MDX)==MDX_SHA and sha(DATA)==DATA_SHA
 t=MDX.read_text();a=t.index('`83 B57B2')+1;b=t.index('`',a);s=''.join(t[a:b].split()).upper();d=''.join(next(x for x in json.loads(DATA.read_text()) if x.get('id')=='rev7')['ciphertext'].split()).upper();assert s==d and len(s)==1092 and hb(s.encode())==TEXT_SHA;return s
def validate_map_identity(meta):
 assert meta['class_id']=='N1310-C01' and meta['representative_key']=='2013' and meta['map_sha256']=='0cafd6af5245d6050eaf28174abbd0ba2682d919169a019f97dd286d908cef4e'
 current=controls.source_indices(1310,'2013');prior=old_core.emission_indices(1310,'2013');assert current==prior==tuple(meta['emission_indices']);return hb(json.dumps(list(current),separators=(',',':')).encode())
def execute_cell(canonical,meta,orientation,nbytes=NBYTES,max_frontier=MAX_FRONTIER,max_accepted=MAX_ACCEPTED):
 observed=orient(canonical,orientation);assert orient(observed,orientation)==canonical;indices=controls.source_indices(2*nbytes,meta['representative_key']);row=core.search(observed,nbytes,indices,max_frontier,max_accepted);validation=controls.validate(row,observed,nbytes,meta['representative_key']);material=b''.join(bytes.fromhex(x['ciphertext_hex'])+bytes.fromhex(x['suffix_plaintext_hex']) for x in row['solutions'])
 return {'id':f"{meta['class_id']}|{orientation}",'class_id':meta['class_id'],'representative_key':meta['representative_key'],'map_sha256':hb(json.dumps(list(indices),separators=(',',':')).encode()),'dropped_column':meta['dropped_column'],'orientation':orientation,'observed_sha256':hb(observed.encode()),'observed_length':len(observed),'inverse_orientation_exact':True,'evidence_kind':'new_search','terminal_solution_material_sha256':hb(material),'validation':validation,**row}
def reused_cells(canonical,meta):
 identity=validate_map_identity(meta);prior=json.loads(PRIOR_RESULT.read_text());cert=json.loads(PRIOR_CERT.read_text());assert prior['identity']=='ASTRA' and prior['target_evaluated'] is True and prior['summary']['complete_contexts']==4 and prior['summary']['incomplete_contexts']==0 and prior['summary']['terminal_solutions']==0 and prior['configuration']['gate_sha256']==PRIOR_GATE_SHA and prior['configuration']['canonical_text_sha256']==TEXT_SHA and [x['id'] for x in prior['cells']]==list(ORIENTATIONS);assert cert['identity']=='ASTRA' and cert['result_sha256']==PRIOR_RESULT_SHA and cert['gate_sha256']==PRIOR_GATE_SHA and cert['cells_verified']==4 and cert['all_zero_certificates_valid'] and [x['id'] for x in cert['rows']]==list(ORIENTATIONS)
 out=[]
 for orientation,old in zip(ORIENTATIONS,prior['cells']):
  observed=orient(canonical,orientation);assert old['orientation']==orientation and old['observed_sha256']==hb(observed.encode()) and old['observed_length']==1092
  controls.validate(old,observed,NBYTES,'2013')
  copied={k:v for k,v in old.items() if k not in ('id','orientation','observed_sha256','observed_length','inverse_orientation_exact','validation')}
  out.append({'id':f"{meta['class_id']}|{orientation}",'class_id':meta['class_id'],'representative_key':'2013','map_sha256':identity,'dropped_column':1,'orientation':orientation,'observed_sha256':old['observed_sha256'],'observed_length':old['observed_length'],'inverse_orientation_exact':True,'evidence_kind':'reused_prior_complete_search','prior_cell_id':old['id'],'prior_result_sha256':PRIOR_RESULT_SHA,'prior_gate_sha256':PRIOR_GATE_SHA,'validation':controls.validate(old,observed,NBYTES,'2013'),**copied})
 return out
def require_gate():
 gate=json.loads(GATE.read_text());assert gate['identity']==IDENTITY and gate['target_evaluated'] is False and gate['scope']==scope() and gate['driver_sha256']==sha(Path(__file__)) and gate['mdx_sha256']==MDX_SHA and gate['dataset_sha256']==DATA_SHA and gate['canonical_text_sha256']==TEXT_SHA and gate['prior_result_sha256']==PRIOR_RESULT_SHA and gate['prior_gate_sha256']==PRIOR_GATE_SHA and set(gate['artifact_hashes'])==set(REQUIRED)
 for rel,want in gate['artifact_hashes'].items():assert sha(ROOT/rel)==want,(rel,sha(ROOT/rel),want)
 return gate
def run_target():
 tmp=RESULT.with_suffix('.json.tmp')
 if RESULT.exists() or tmp.exists():raise SystemExit('refusing existing result or temporary file')
 gate=require_gate();canonical=extract_target();maps=classes();cells=[]
 for meta in maps:
  if meta['class_id']=='N1310-C01':cells.extend(reused_cells(canonical,meta))
  else:
   for orientation in ORIENTATIONS:cells.append(execute_cell(canonical,meta,orientation))
 assert [x['id'] for x in cells]==logical_ids() and sum(x['evidence_kind']=='new_search' for x in cells)==44 and sum(x['evidence_kind']=='reused_prior_complete_search' for x in cells)==4
 out={'identity':IDENTITY,'target_evaluated':True,'scope':scope(),'configuration':{'gate_sha256':sha(GATE),'driver_sha256':sha(Path(__file__)),'core_sha256':CORE_SHA,'controls_source_sha256':CONTROLS_SHA,'packed_controls_sha256':PACK_SHA,'inventory_sha256':INVENTORY_SHA,'prior_result_sha256':PRIOR_RESULT_SHA,'prior_gate_sha256':PRIOR_GATE_SHA,'mdx_sha256':MDX_SHA,'dataset_sha256':DATA_SHA,'canonical_text_sha256':TEXT_SHA,'artifact_hashes':gate['artifact_hashes']},'cells':cells,'summary':{'logical_contexts':48,'newly_evaluated_contexts':44,'reused_contexts':4,'complete_contexts':sum(x['complete'] for x in cells),'incomplete_contexts':sum(not x['complete'] for x in cells),'terminal_solutions':sum(x['solution_count'] for x in cells),'accepted_states':sum(x['accepted_states'] for x in cells),'block_calls':sum(x['block_calls'] for x in cells)}}
 tmp.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n');os.replace(tmp,RESULT);print(json.dumps({'identity':IDENTITY,'result_sha256':sha(RESULT),**out['summary']},sort_keys=True))
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--run-target',action='store_true');a=ap.parse_args()
 if a.run_target:run_target()
 else:
  if GATE.exists():require_gate()
  assert sha(MDX)==MDX_SHA and sha(DATA)==DATA_SHA
  print(json.dumps({'identity':IDENTITY,'target_evaluated':False,'handling':'MDX and dataset bytes hashed only; target text is not extracted or evaluated','gate_present':GATE.exists(),'driver_sha256':sha(Path(__file__)),'scope':scope()},indent=2,sort_keys=True))
if __name__=='__main__':main()
