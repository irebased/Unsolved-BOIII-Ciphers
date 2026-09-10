#!/usr/bin/env python3
"""Synthetic controls for all twelve source-derived N=1310 lossy-four-digit maps."""
from __future__ import annotations
from pathlib import Path
import argparse,hashlib,importlib.util,itertools,json,platform
import Crypto
from Crypto.Cipher import DES
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];LEDGER=HERE/'controls.json';IDENTITY='ASTRA'
CORE=HERE/'core.py';INVENTORY=ROOT/'research/char_amsco/astra/lossy4_onechar_inventory/inventory.json';ANALYZE=ROOT/'research/char_amsco/astra/cryptool_bug/analyze.py'
CORE_SHA='8e9727cbd15661002645a6fdd770dcb335b2a0e7eb5b61b15d990194595d9ef8'
INVENTORY_SHA='fa9d7463848918d2eaddfe6afdf013f2d5b6b1d1c2011aa5d0aa5a197eec4fe2'
PINS={
 'research/char_amsco/astra/lossy4_onechar_inventory/inventory.py':'6990162132bd5d2d3c77ef3fce00d07c1f807fb33845283021ebbf4fe4323b50',
 'research/char_amsco/astra/lossy4_onechar_inventory/README.md':'b3ddf71c31ea645c299f2986a133d0ef0552ee28fd3a5fb259872cb44abbbcfa',
 'research/char_amsco/astra/lossy4_onechar_inventory/REPORT.md':'fd02987bfdcbdab0311fd52d4a1bf5ac1acece3efc67afb88ec6ca09265401d1',
 'research/char_amsco/astra/cryptool_bug/analyze.py':'ba66b3c844cf5784749587af960a11163d5e47deddf523a04530bea4f5d9629b',
 'research/char_amsco/astra/cryptool_bug/evidence.json':'71ee944899ce7a202e07ee4b0d292309978f3a7eb3eb697d0c196f858844daab',
 'research/char_amsco/astra/cryptool_bug/source/class.amsco.php.base64':'25143ebd1a720d9fe35ac3aa2579be722a8ded03b67d6ff2da0f071e40f8c3ac',
 'research/char_amsco/astra/cryptool_bug/source/default_tool.php':'e71bcfe75ae9250b00f8adf38eaec4547b854bfafd23a559cfef482d0f81a7d6',
 'research/char_amsco/astra/cryptool_bug/source/infobox.template':'0e6f9a9f73a2aee868567fe082a342a75334a3944ca050599da6bfcb97c040af',
 'research/char_amsco/astra/amsco_geometry.py':'c43e6412cbf2ac34e137801e1fd9c13e8c46bb89296bb89484c01d28a505cae6',
}
def hb(x):return hashlib.sha256(x).hexdigest()
def sha(p):return hb(Path(p).read_bytes())
def load(path,name):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def verify_pins():
 assert sha(CORE)==CORE_SHA and INVENTORY_SHA!='__FINAL_INVENTORY_SHA__' and sha(INVENTORY)==INVENTORY_SHA
 for rel,want in PINS.items():assert sha(ROOT/rel)==want,(rel,sha(ROOT/rel),want)
verify_pins();core=load(CORE,'astra_lossy4_core');legacy=load(ANALYZE,'astra_lossy4_legacy');legacy.verify_pins()

def source_indices(length,key):
 if length<0 or len(key)!=4 or not key.isdigit():raise ValueError('four-digit key required')
 rows={};pos=cell=0;size=2
 while pos<length:
  take=min(size,length-pos);row=cell//4;col=cell%4
  rows.setdefault(row,{})[int(key[col])]=tuple(range(pos,pos+take))
  pos+=take;cell+=1;size=3-size
 out=[]
 for label in range(1,5):
  for row in range(max(rows,default=-1)+1):out.extend(rows.get(row,{}).get(label,()))
 return tuple(out)
def source_emit(text,key):return ''.join(text[i] for i in source_indices(len(text),key))
def orient(text,name):
 if name=='forward':return text
 if name=='full_hex_reverse':return text[::-1]
 pairs=[text[i:i+2] for i in range(0,len(text),2)]
 if name=='byte_reverse':return ''.join(reversed(pairs))
 if name=='nibble_swap':return ''.join(x[::-1] for x in pairs)
 raise ValueError(name)
ORIENTS=('forward','full_hex_reverse','byte_reverse','nibble_swap')
def repeat(text,n):return (text*((n+len(text)-1)//len(text)))[:n].encode('ascii')
def deterministic_hex(length,label):
 out='';i=0
 while len(out)<length:out+=hashlib.sha256((label+str(i)).encode()).hexdigest().upper();i+=1
 return out[:length]
def validate(row,observed,nbytes,key):
 for x in row['solutions']:
  seed=bytes.fromhex(x['initial_register_hex']);ct=bytes.fromhex(x['ciphertext_hex']);pt=bytes.fromhex(x['suffix_plaintext_hex'])
  assert len(seed)==8 and ct[:8]==seed and len(ct)==nbytes and len(pt)==nbytes-8 and set(pt)<=set(core.ALLOWED)
  assert DES.new(core.KEY,DES.MODE_CFB,iv=seed,segment_size=8).decrypt(ct[8:])==pt==core.manual_suffix(seed,ct[8:])
  hx=ct.hex().upper();assert source_emit(hx,key)==observed==legacy.legacy_encode(hx.encode(),key)['raw'].decode()
  assert hb(pt)==x['suffix_plaintext_sha256'] and hb(ct)==x['ciphertext_sha256']
 return {'all_lengths_and_hashes_exact':True,'all_suffixes_printable_ascii':True,'all_pycryptodome_suffixes_exact':True,'all_manual_suffixes_exact':True,'all_representative_source_emissions_exact':True}
def random_printable(n,label):
 raw=b'';i=0
 while len(raw)<n:raw+=hashlib.sha256((label+str(i)).encode()).digest();i+=1
 return bytes(32+(x%95) for x in raw[:n])
def plant(label,key,nbytes,original_iv,plain=None):
 plain=repeat('Generic source map control preserves printable ASCII punctuation !?., digits 0123456789 and exact suffix paths. ',nbytes) if plain is None else plain
 assert len(plain)==nbytes and set(plain)<=set(core.ALLOWED)
 cipher=DES.new(core.KEY,DES.MODE_CFB,iv=original_iv,segment_size=8).encrypt(plain);hx=cipher.hex().upper();indices=source_indices(2*nbytes,key)
 observed=source_emit(hx,key);assert observed==legacy.legacy_encode(hx.encode(),key)['raw'].decode()
 row=core.search(observed,nbytes,indices);check=validate(row,observed,nbytes,key)
 truth=[x for x in row['solutions'] if bytes.fromhex(x['ciphertext_hex'])==cipher and bytes.fromhex(x['suffix_plaintext_hex'])==plain[8:]]
 assert row['complete'] and len(truth)==1
 return {'id':label,'representative_key':key,'natural_bytes':nbytes,'original_iv_hex':original_iv.hex(),'first_8_plaintext_bytes_unrecovered':True,'plaintext_sha256':hb(plain),'truth_ciphertext_sha256':hb(cipher),'observation_length':len(observed),'observation_sha256':hb(observed.encode()),'map_sha256':hb(json.dumps(list(indices),separators=(',',':')).encode()),'truth_retained_exactly_once':True,'plaintext_generator':('repeated held-out sentence' if label!='full655|drop3' else 'SHA-256 bytes reduced modulo95 plus32; label ASTRA drop3 full random '),'search':row,'validation':check}
def null_control(class_id,key):
 indices=source_indices(1310,key);observed=deterministic_hex(len(indices),'ASTRA lossy4 null '+class_id+' ');row=core.search(observed,655,indices);check=validate(row,observed,655,key)
 return {'id':class_id,'representative_key':key,'observation_sha256':hb(observed.encode()),'observation_length':len(observed),'search':row,'validation':check}
def tiny_cap(class_id,key):
 n=99;plain=repeat('Tiny cap printable control ',n);ct=DES.new(core.KEY,DES.MODE_CFB,iv=bytes.fromhex('1234567890ABCDEF'),segment_size=8).encrypt(plain);hx=ct.hex().upper();idx=source_indices(2*n,key);obs=source_emit(hx,key);row=core.search(obs,n,idx,max_accepted=1)
 assert not row['complete'] and row['capped_reason']=='max_accepted' and row['partial_root'] and row['solution_count']==0 and row['accepted_states']==1
 return {'id':class_id,'representative_key':key,'root_count':row['initial_registers_total'],'search':row}
def small_dynamic_oracle():
 cases=[]
 for vals,masks in (((10,1,8),(15,3,12)),((1,2),(3,12))):
  domains=[core.compatible_values(v,m,range(16)) for v,m in zip(vals,masks)];via=list(itertools.product(*domains));direct=[x for x in itertools.product(range(16),repeat=len(vals)) if all((x[i]&masks[i])==(vals[i]&masks[i]) for i in range(len(vals)))];assert via==direct
  cases.append({'values':list(vals),'masks':list(masks),'count':len(via),'rows':[list(x) for x in via]})
 return {'domain':'0..15','cases':cases,'all_dynamic_products_equal_naive':True}
def generate():
 inventory=json.loads(INVENTORY.read_text());classes=[x for x in inventory['map_classes'] if x['input_chars']==1310];assert len(classes)==12
 meta=[]
 for g in classes:
  key=g['representative_key'];idx=source_indices(1310,key);assert list(idx)==g['emission_indices'] and len(idx)==1092
  fixture=deterministic_hex(1310,'ASTRA lossy4 map '+g['class_id']+' ');assert source_emit(fixture,key)==legacy.legacy_encode(fixture.encode(),key)['raw'].decode()
  vals,masks=core.reconstruct(source_emit(fixture,key),655,idx);roots,proof=core.root_proof(vals,masks);expected=4096 if g['dropped_column']==1 else 256;assert len(roots)==expected
  ow=[];obs=source_emit(fixture,key)
  for o in ORIENTS:
   canonical=orient(obs,o);assert orient(canonical,o)==obs;ow.append({'orientation':o,'canonical_sha256':hb(canonical.encode()),'inverse_recovers_observation':True})
  meta.append({'class_id':g['class_id'],'representative_key':key,'dropped_column':g['dropped_column'],'full_row_read_order':g['full_row_read_order'],'member_count':g['member_count'],'map_sha256':g['map_sha256'],'map_matches_independent_source_port':True,'root_count':expected,'root_proof':proof,'orientation_wiring':ow})
 short=[]
 for i,g in enumerate(classes):short.append(plant('short99|'+g['class_id'],g['representative_key'],99,(i+1).to_bytes(8,'big')))
 d1=next(g for g in classes if g['dropped_column']==1);d3=next(g for g in classes if g['dropped_column']==3)
 full=[plant('full655|drop1',d1['representative_key'],655,bytes.fromhex('1020304050607080')),plant('full655|drop3',d3['representative_key'],655,bytes.fromhex('90A0B0C0D0E0F001'),random_printable(655,'ASTRA drop3 full random '))]
 nulls=[null_control(g['class_id'],g['representative_key']) for g in classes]
 caps=[tiny_cap('drop1',d1['representative_key']),tiny_cap('drop3',d3['representative_key'])]
 return {'identity':IDENTITY,'target_evaluated':False,'rev7_read':False,'crypto_evaluated':True,'scope':'Synthetic-only generic explicit-source-map DES all-IV printable suffix controls for all twelve N=1310 lossy four-digit map classes.','model':{'natural_target_bytes':655,'cipher':'DES','key_hex':core.KEY.hex(),'known_suffix_offset':8,'first_8_plaintext_bytes':'unknown and not recovered','original_iv':'arbitrary and not recovered','allowed_suffix_bytes':'32..126 inclusive','root_processing':'sequential','max_live_frontier_per_root':core.MAX_FRONTIER,'max_global_accepted_states':core.MAX_ACCEPTED,'no_score_or_beam':True},'source':{'inventory_sha256':INVENTORY_SHA,'inventory_source_sha256':inventory['source_sha256'],'inventory_classes':12,'legacy_commit':'4fc443f0d87c0e86815695a47ab2d6174c725f82','pins':PINS},'class_metadata':meta,'short_all_class_plants':short,'full_length_shape_plants':full,'random_nulls_all_classes':nulls,'tiny_caps_both_root_shapes':caps,'small_dynamic_root_oracle':small_dynamic_oracle(),'orientation_reuse_proof':'For each class, orient(orient(source_observation,o),o) equals the identical source observation passed to search. Crypto is therefore run once per planted observation, not four redundantly identical times.','environment':{'python':platform.python_version(),'pycryptodome':Crypto.__version__,'platform':platform.platform()},'assertions':{'all_source_pins_checked_before_use':True,'all_12_maps_match_inventory_and_independent_source_port':True,'all_12_short_plants_complete_and_truth_retained_once':all(x['search']['complete'] and x['truth_retained_exactly_once'] for x in short),'both_full_length_root_shapes_complete_and_truth_retained_once':all(x['search']['complete'] and x['truth_retained_exactly_once'] for x in full),'all_12_nulls_complete':all(x['search']['complete'] for x in nulls),'all_terminal_candidates_independently_validated':True,'both_dynamic_root_counts_proved':{x['root_count'] for x in meta}=={256,4096},'all_48_orientation_wirings_inverse_exact':sum(len(x['orientation_wiring']) for x in meta)==48 and all(y['inverse_recovers_observation'] for x in meta for y in x['orientation_wiring']),'tiny_caps_incomplete_without_partial_solutions':all(not x['search']['complete'] and x['search']['solution_count']==0 for x in caps),'no_target_read_or_evaluation':True},'core_source_sha256':sha(CORE),'controls_source_sha256':sha(Path(__file__))}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args();out=generate()
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit('refusing existing output')
  a.regenerate.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n');print(json.dumps({'identity':IDENTITY,'output':str(a.regenerate),'sha256':sha(a.regenerate)},sort_keys=True))
 else:
  assert json.loads(LEDGER.read_text())==out;print(json.dumps({'identity':IDENTITY,'verified':True,'ledger_sha256':sha(LEDGER),'classes':12,'target_evaluated':False},sort_keys=True))
if __name__=='__main__':main()
