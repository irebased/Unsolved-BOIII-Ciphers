#!/usr/bin/env python3
"""Supplemental one-root positive for the capped full655 dropped-column-1 control."""
from pathlib import Path
import argparse,hashlib,importlib.util,json
from Crypto.Cipher import DES
HERE=Path(__file__).resolve().parent;LEDGER=HERE/'seeded_control.json';IDENTITY='ASTRA'
PINS={'core.py':'7a10f904bbfdc027bae27816e3a8e4fff351869bd7cf063cb898a5fdbb7d2879','controls.py':'9deac8ce129a8f5198eabebcb2d972722bfeb808e910cbae291d52b6396f660e','controls.pack.json':'12cfbef7fd95c054251b2413ee6764da968bc71868b3e35797ba7685ffef366a','pack_controls.py':'b05467c3a0a6bf5642c69dd00b74d88ae4c7d01b1174cca37d488407b748cbe0'}
PARENT={'id':'full655|drop1|cut3','representative_key':'1032','natural_bytes':655,'cut':'three','full':True,'original_iv_hex':'1122334455667788','plaintext_sha256':'f896fae4d844b9f96904c8244415e6c8ee782081897c79a14da8189f57b97b08','truth_ciphertext_sha256':'f8e2c961d522aef91eec356a26d2acfa443cc6311b8cb55dfcad8603ea6d6de2','original_observation_sha256':'609fa2445fe62acfe27c5957926fc32fe0158cf572ecc41a36447d6f0f41eae4','parent_status':'INCOMPLETE at global 5,000,000 accepted states; truth not claimed'}
def hb(x):return hashlib.sha256(x).hexdigest()
def sha(p):return hb(Path(p).read_bytes())
def load(path,name):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def generate():
 for rel,want in PINS.items():assert sha(HERE/rel)==want,(rel,sha(HERE/rel),want)
 c=load(HERE/'controls.py','astra_utf8_seed_parent');core=c.core;n=PARENT['natural_bytes'];key=PARENT['representative_key'];plain=c.build_plain(n,PARENT['cut'],PARENT['full']);iv=bytes.fromhex(PARENT['original_iv_hex']);cipher=DES.new(core.KEY,DES.MODE_CFB,iv=iv,segment_size=8).encrypt(plain);hx=cipher.hex().upper();original_indices=c.source_indices(2*n,key);original_observed=c.source_emit(hx,key)
 assert hb(plain)==PARENT['plaintext_sha256'] and hb(cipher)==PARENT['truth_ciphertext_sha256'] and hb(original_observed.encode())==PARENT['original_observation_sha256'] and original_observed==c.legacy.legacy_encode(hx.encode(),key)['raw'].decode()
 missing=tuple(i for i in range(16) if i not in set(original_indices));assert missing==(2,8,14)
 augmented_indices=tuple(original_indices)+missing;appended=''.join(hx[i] for i in missing);augmented_observed=original_observed+appended
 vals,masks=core.reconstruct(augmented_observed,n,augmented_indices);assert tuple(masks[:8])==(255,255,255,255,255,255,255,255)
 row=core.search(augmented_observed,n,augmented_indices);truth=0
 for x in row['solutions']:
  seed=bytes.fromhex(x['initial_register_hex']);ct=bytes.fromhex(x['ciphertext_hex']);pt=bytes.fromhex(x['suffix_plaintext_hex']);assert ct[:8]==seed and len(ct)==n and len(pt)==n-8 and core.BOUNDARY in x['endpoint_states']
  assert DES.new(core.KEY,DES.MODE_CFB,iv=seed,segment_size=8).decrypt(ct[8:])==pt==core.manual_suffix(seed,ct[8:]);w=c.oracle(pt);assert w and core.accepts_suffix(pt);x['independent_prefix_witnesses']=w
  candidate_hex=ct.hex().upper();assert c.source_emit(candidate_hex,key)==original_observed==c.legacy.legacy_encode(candidate_hex.encode(),key)['raw'].decode();assert ''.join(candidate_hex[i] for i in missing)==appended;assert hb(pt)==x['suffix_plaintext_sha256'] and hb(ct)==x['ciphertext_sha256']
  truth+=(ct==cipher and pt==plain[8:])
 assert row['complete'] and row['initial_registers_total']==1 and row['roots_completed']==1 and row['roots_unexamined']==0 and row['partial_root'] is None and truth==1
 return {'identity':IDENTITY,'target_evaluated':False,'rev7_read':False,'crypto_evaluated':True,'scope':'Supplemental seeded-initial-register positive only; fixes C[0:8] by appending the three missing observed hex nibbles to the original source map.','parent_full_control':PARENT,'augmentation':{'original_emission_indices_count':len(original_indices),'appended_natural_hex_indices':list(missing),'appended_truth_hex':appended,'augmented_indices_count':len(augmented_indices),'original_observation_length':len(original_observed),'augmented_observation_length':len(augmented_observed),'original_observation_sha256':hb(original_observed.encode()),'augmented_observation_sha256':hb(augmented_observed.encode()),'first_8_ciphertext_masks':['ff']*8,'compatible_initial_registers':1},'search':row,'truth_retained_exactly_once':True,'validation':{'every_terminal_pycryptodome_suffix_exact':True,'every_terminal_manual_recurrence_exact':True,'every_terminal_independent_unicode_oracle_accepts':True,'every_terminal_original_unaugmented_legacy_emission_exact':True,'every_terminal_appended_truth_nibbles_exact':True,'every_terminal_hash_and_length_exact':True},'limits':['This seeded control does not complete or extend the capped 4,096-root parent search.','The three appended nibbles are synthetic planted truth and are not known for Rev7.','No target data is read or evaluated.'],'source_pins':PINS,'source_sha256':sha(Path(__file__)),'assertions':{'same_parent_full655_recipe_exact':True,'only_missing_first16_indices_appended':True,'exactly_one_initial_register':True,'search_complete':True,'truth_retained_once':True,'all_terminal_candidates_independently_validated_against_original_emission':True,'no_target':True}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args();out=generate()
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit('refusing existing output')
  a.regenerate.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n');print(json.dumps({'identity':IDENTITY,'output':str(a.regenerate),'sha256':sha(a.regenerate)},sort_keys=True))
 else:
  assert json.loads(LEDGER.read_text())==out;print(json.dumps({'identity':IDENTITY,'verified':True,'ledger_sha256':sha(LEDGER),'solutions':out['search']['solution_count'],'target_evaluated':False},sort_keys=True))
if __name__=='__main__':main()
