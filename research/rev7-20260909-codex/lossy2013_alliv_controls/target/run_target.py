#!/usr/bin/env python3
"""Inert gated four-orientation all-IV DES suffix target driver."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,os,re
HERE=Path(__file__).resolve().parent
PACKAGE=HERE.parent
ROOT=HERE.parents[3]
IDENTITY='ASTRA'
ORIENTATIONS=('forward','full_hex_reverse','byte_reverse','nibble_swap')
NBYTES=655
MAX_FRONTIER=100_000
MAX_ACCEPTED=5_000_000
MDX=ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx'
DATA=ROOT/'lavender/src/data/ciphers/revelations.json'
MDX_SHA='085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91'
DATA_SHA='68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e'
TEXT_SHA='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c'
SOURCE_SHA='65494f3d65d5cb89e1678ef78113516f47fa2464de23ccbefca4ba0089d80496'
CONTROLS_SHA='5c8905b96efeb510a0e049e2fd857b480f51d42000f6b8b209f9bcd5b2fbdd61'
GATE=HERE/'target_gate.json';RESULT=HERE/'target_results.json'
REQUIRED=(
 'research/rev7-20260909-codex/lossy2013_alliv_controls/run.py',
 'research/rev7-20260909-codex/lossy2013_alliv_controls/controls.json',
 'research/rev7-20260909-codex/lossy2013_alliv_controls/README.md',
 'research/rev7-20260909-codex/lossy2013_alliv_controls/REPORT.md',
 'research/char_amsco/astra/lossy2013/core.py',
 'research/char_amsco/astra/cryptool_bug/analyze.py',
 'research/char_amsco/astra/cryptool_bug/evidence.json',
 'research/char_amsco/astra/cryptool_bug/source/class.amsco.php.base64',
 'research/char_amsco/astra/cryptool_bug/source/default_tool.php',
 'research/char_amsco/astra/cryptool_bug/source/infobox.template',
 'research/char_amsco/astra/amsco_geometry.py',
 'research/rev7-20260909-codex/lossy2013_alliv_controls/target/driver_controls.py',
 'research/rev7-20260909-codex/lossy2013_alliv_controls/target/controls.json',
 'research/rev7-20260909-codex/lossy2013_alliv_controls/target/README.md',
 'research/rev7-20260909-codex/lossy2013_alliv_controls/target/prepare_gate.py',
 'lavender/src/data/ciphers/revelations.json',
)
def hb(x):return hashlib.sha256(x).hexdigest()
def sha(p):return hb(Path(p).read_bytes())
def load(path,name):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
# Source is pinned before import.
assert sha(PACKAGE/'run.py')==SOURCE_SHA
alliv=load(PACKAGE/'run.py','astra_l13_alliv_target_source')
assert sha(PACKAGE/'controls.json')==CONTROLS_SHA

def orient(text,name):
 assert len(text)%2==0
 if name=='forward':return text
 if name=='full_hex_reverse':return text[::-1]
 pairs=[text[i:i+2] for i in range(0,len(text),2)]
 if name=='byte_reverse':return ''.join(reversed(pairs))
 if name=='nibble_swap':return ''.join(x[::-1] for x in pairs)
 raise ValueError(name)

def scope():return {
 'identity':IDENTITY,'contexts':4,'legacy_keys':['2013','2014'],'equivalent_emission_counted_once':True,
 'natural_ciphertext_bytes':NBYTES,'observed_hex_characters':1092,'cipher':'DES','key_hex':alliv.KEY.hex(),
 'orientations':list(ORIENTATIONS),'iv_model':'every arbitrary original 8-byte IV through all 4096 observation-compatible C[0:8] registers',
 'known_suffix_offset':8,'unknown_plaintext_prefix_bytes':8,'allowed_suffix_bytes':'printable ASCII 32..126 inclusive',
 'max_live_frontier_per_root':MAX_FRONTIER,'max_global_accepted_states_per_context':MAX_ACCEPTED,
 'cap_semantics':'INCOMPLETE with exact completed/partial/unexamined root accounting; partial paths are never solutions',
 'retention':'every terminal full-ciphertext and plaintext-suffix completion; no scoring or beam pruning'}

def extract_target():
 assert sha(MDX)==MDX_SHA and sha(DATA)==DATA_SHA
 text=MDX.read_text();a=text.index('`83 B57B2')+1;b=text.index('`',a);raw=''.join(text[a:b].split()).upper()
 assert len(raw)==1092 and hb(raw.encode())==TEXT_SHA
 data=''.join(next(x for x in json.loads(DATA.read_text()) if x.get('id')=='rev7')['ciphertext'].split()).upper()
 assert data==raw
 return raw

def run_cell(canonical,orientation):
 observed=orient(canonical,orientation);assert orient(observed,orientation)==canonical
 row=alliv.search(observed,NBYTES,MAX_FRONTIER,MAX_ACCEPTED)
 validation=alliv.independent_validate(row,observed,NBYTES)
 # Terminal solutions already contain complete ciphertext and suffix hashes; bind a compact per-cell digest too.
 serial=b''.join(bytes.fromhex(x['ciphertext_hex'])+bytes.fromhex(x['suffix_plaintext_hex']) for x in row['solutions'])
 return {'id':orientation,'orientation':orientation,'observed_sha256':hb(observed.encode()),'observed_length':len(observed),'inverse_orientation_exact':True,'terminal_solution_material_sha256':hb(serial),'validation':validation,**row}

def require_gate():
 gate=json.loads(GATE.read_text())
 assert gate['identity']==IDENTITY and gate['target_evaluated'] is False and gate['scope']==scope()
 assert gate['driver_sha256']==sha(Path(__file__)) and gate['mdx_sha256']==MDX_SHA and gate['dataset_sha256']==DATA_SHA and gate['canonical_text_sha256']==TEXT_SHA
 assert set(gate['artifact_hashes'])==set(REQUIRED)
 assert sha(MDX)==MDX_SHA and sha(DATA)==DATA_SHA and sha(PACKAGE/'run.py')==SOURCE_SHA and sha(PACKAGE/'controls.json')==CONTROLS_SHA
 for rel,want in gate['artifact_hashes'].items():assert sha(ROOT/rel)==want,(rel,sha(ROOT/rel),want)
 return gate

def run_target():
 tmp=RESULT.with_suffix('.json.tmp')
 if RESULT.exists() or tmp.exists():raise SystemExit('refusing existing result or temporary file')
 gate=require_gate();canonical=extract_target()
 cells=[run_cell(canonical,o) for o in ORIENTATIONS];assert [x['id'] for x in cells]==list(ORIENTATIONS)
 out={'identity':IDENTITY,'target_evaluated':True,'scope':scope(),'configuration':{'gate_sha256':sha(GATE),'driver_sha256':sha(Path(__file__)),'source_sha256':SOURCE_SHA,'controls_sha256':CONTROLS_SHA,'mdx_sha256':MDX_SHA,'dataset_sha256':DATA_SHA,'canonical_text_sha256':TEXT_SHA,'artifact_hashes':gate['artifact_hashes']},'cells':cells,'summary':{'complete_contexts':sum(x['complete'] for x in cells),'incomplete_contexts':sum(not x['complete'] for x in cells),'terminal_solutions':sum(x['solution_count'] for x in cells),'accepted_states':sum(x['accepted_states'] for x in cells),'block_calls':sum(x['block_calls'] for x in cells)}}
 tmp.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n');os.replace(tmp,RESULT)
 print(json.dumps({'identity':IDENTITY,'result_sha256':sha(RESULT),**out['summary']},sort_keys=True))

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--run-target',action='store_true');a=ap.parse_args()
 if a.run_target:run_target()
 else:
  if GATE.exists():require_gate()
  assert sha(MDX)==MDX_SHA and sha(DATA)==DATA_SHA
  print(json.dumps({'identity':IDENTITY,'target_evaluated':False,'handling':'MDX and dataset bytes hashed only; target text is not extracted or evaluated','gate_present':GATE.exists(),'driver_sha256':sha(Path(__file__)),'scope':scope()},indent=2,sort_keys=True))
if __name__=='__main__':main()
