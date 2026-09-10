#!/usr/bin/env python3
"""Synthetic full-driver wiring controls for all four registered orientations."""
from pathlib import Path
import argparse,hashlib,importlib.util,json
from Crypto.Cipher import DES
HERE=Path(__file__).resolve().parent
LEDGER=HERE/'controls.json'
IDENTITY='ASTRA'
def hb(x):return hashlib.sha256(x).hexdigest()
def sha(p):return hb(Path(p).read_bytes())
def load(path,name):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def generate():
 driver=load(HERE/'run_target.py','astra_l13_alliv_driver_control')
 source=driver.alliv
 plain=source.repeated('Synthetic all IV driver plant preserves printable punctuation !?., digits 0123456789 and letters through every registered orientation. ',driver.NBYTES)
 original_iv=bytes.fromhex('13579BDF2468ACE0')
 cipher=DES.new(source.KEY,DES.MODE_CFB,iv=original_iv,segment_size=8).encrypt(plain)
 observed=source.legacy.legacy_encode(cipher.hex().upper().encode(),'2013')['raw'].decode()
 assert observed==source.core.emit(cipher.hex().upper(),'2013')==source.core.emit(cipher.hex().upper(),'2014') and len(observed)==1092
 rows=[]
 for orientation in driver.ORIENTATIONS:
  canonical=driver.orient(observed,orientation);assert driver.orient(canonical,orientation)==observed
  row=driver.run_cell(canonical,orientation)
  truths=[x for x in row['solutions'] if bytes.fromhex(x['ciphertext_hex'])==cipher and bytes.fromhex(x['suffix_plaintext_hex'])==plain[8:]]
  assert row['complete'] and row['roots_completed']==4096 and row['roots_unexamined']==0 and row['partial_root'] is None and len(truths)==1
  assert row['validation']=={'all_terminal_lengths_exact':True,'all_suffixes_printable_ascii':True,'all_library_suffix_decryptions_exact':True,'all_manual_recurrences_exact':True,'all_2013_2014_source_emissions_exact':True,'all_hashes_exact':True}
  rows.append({'id':row['id'],'complete':row['complete'],'solution_count':row['solution_count'],'accepted_states':row['accepted_states'],'block_calls':row['block_calls'],'max_live_frontier_per_root':row['max_live_frontier_per_root'],'roots_completed':row['roots_completed'],'roots_unexamined':row['roots_unexamined'],'truth_retained_exactly_once':True,'observed_sha256':row['observed_sha256'],'terminal_solution_material_sha256':row['terminal_solution_material_sha256'],'canonical_sha256':hb(canonical.encode())})
 assert [x['id'] for x in rows]==list(driver.ORIENTATIONS)
 return {'identity':IDENTITY,'target_evaluated':False,'crypto_evaluated':True,'scope':'Synthetic 655-byte DES all-IV driver wiring across exactly four involutive hex orientations.','driver_sha256':sha(HERE/'run_target.py'),'source_sha256':sha(HERE.parent/'run.py'),'parent_controls_sha256':sha(HERE.parent/'controls.json'),'plant':{'natural_bytes':len(plain),'original_iv_hex':original_iv.hex(),'original_plaintext_prefix_unrecovered':True,'plaintext_sha256':hb(plain),'ciphertext_sha256':hb(cipher),'source_observed_sha256':hb(observed.encode())},'rows':rows,'assertions':{'exact_four_orientation_ids':True,'all_orientation_inverses_exact':True,'all_cells_complete':True,'truth_full_ciphertext_and_suffix_retained_once_in_every_cell':True,'all_terminal_solutions_independently_validated':True,'no_target_read_or_evaluation':True}}

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args();out=generate()
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit('refusing existing output')
  a.regenerate.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n');print(json.dumps({'identity':IDENTITY,'output':str(a.regenerate),'sha256':sha(a.regenerate)},sort_keys=True))
 else:
  assert json.loads(LEDGER.read_text())==out;print(json.dumps({'identity':IDENTITY,'verified':True,'ledger_sha256':sha(LEDGER),'contexts':len(out['rows']),'target_evaluated':False},sort_keys=True))
if __name__=='__main__':main()
