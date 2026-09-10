#!/usr/bin/env python3
"""Portable structural verifier for the completed byte-AMSCO target ledger."""
from __future__ import annotations
import hashlib,json,math,re
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[4];RESULT=HERE/'target_results.json';GATE=HERE/'target_gate.json';MDX=ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx'
IDENTITY='ASTRA';RESULT_SHA='baf3fc16f2eb84008b75fc80521502134945fdeece075183fa61050c19779cdd';GATE_SHA='61793d92916e57959f2cca9f5df32df8cc1cdcf4e06781eaa3f19193e33a49c2';DRIVER_SHA='a3b865878f889799fbbebb7d8de3956677fdad0696ee96434f7e30982cde3ec3';MDX_SHA='085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91';TEXT_SHA='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c'
BACKENDS=('aes128','des','blowfish','bfcompat','rc2','twofish','loki97');ORIENTATIONS=('forward','full_hex_reverse','byte_reverse','nibble_swap');NEGATIVE=('rejected_a105','rejected_fsa_transition','rejected_fsa_terminal');HEX64=re.compile(r'^[0-9a-f]{64}$')
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def orient(data,name):
 swap=lambda v:((v&15)<<4)|(v>>4)
 if name=='forward':return data
 if name=='byte_reverse':return data[::-1]
 if name=='nibble_swap':return bytes(swap(x) for x in data)
 if name=='full_hex_reverse':return bytes(swap(x) for x in reversed(data))
 raise AssertionError(name)
def canonical():
 text=MDX.read_text();a=text.index('`83 B57B2')+1;b=text.index('`',a);raw=''.join(text[a:b].split()).upper();assert len(raw)==1092 and hashlib.sha256(raw.encode()).hexdigest()==TEXT_SHA;return bytes.fromhex(raw)
def main():
 assert sha(RESULT)==RESULT_SHA and sha(GATE)==GATE_SHA and sha(HERE/'run_target.py')==DRIVER_SHA and sha(MDX)==MDX_SHA
 result=json.loads(RESULT.read_text());gate=json.loads(GATE.read_text());assert result['identity']==IDENTITY and result['target_evaluated'] is True and result['status']=='complete' and gate['identity']==IDENTITY and gate['target_evaluated'] is False
 config=result['configuration'];assert config['gate_sha256']==GATE_SHA and config['driver_sha256']==DRIVER_SHA and config['mdx_sha256']==MDX_SHA and config['canonical_text_sha256']==TEXT_SHA and config['scope']==gate['scope'] and config['artifact_hashes']==gate['artifact_hashes']
 for rel,want in gate['artifact_hashes'].items():assert sha(ROOT/rel)==want,rel
 raw=canonical();orientation_hash={x:hashlib.sha256(orient(raw,x)).hexdigest() for x in ORIENTATIONS};expected={(o,w,s) for o in ORIENTATIONS for w in range(2,10) for s in (1,2)};seen=set();total_classes={};total_orders=total_contexts=total_retained=0
 for cell in result['cells']:
  key=(cell['orientation'],cell['width'],cell['start']);assert key in expected and key not in seen;seen.add(key);o,w,start=key;fact=math.factorial(w);assert cell['identity']==IDENTITY and cell['cell_id']==o+'|w'+str(w)+'|s'+str(start) and cell['observed_sha256']==orientation_hash[o]
  assert cell['orders_examined']==cell['expected_orders']==fact and cell['backend_contexts_examined']==cell['expected_backend_contexts']==fact*7 and cell['unexamined_orders']==cell['unexamined_backend_contexts']==0 and cell['complete_uncapped']
  assert set(cell['counts_by_backend'])==set(BACKENDS)
  combined={}
  for name in BACKENDS:
   assert sum(cell['counts_by_backend'][name].values())==fact
   for cl,n in cell['counts_by_backend'][name].items():combined[cl]=combined.get(cl,0)+n
  assert combined==cell['classification_counts'] and sum(combined.values())==fact*7 and cell['negative_count']+cell['retained_count']==fact*7 and cell['retained_count']==len(cell['retained']) and cell['negative_count']==fact*7-len(cell['retained'])
  assert HEX64.fullmatch(cell['negative_rows_sha256']) and cell['negative_digest_serialization'].startswith('UTF-8 canonical JSON array') and len(cell['first_negative_examples'])<=3
  for ex in cell['first_negative_examples']:
   assert sorted(ex['order'])==list(range(w)) and ex['cipher'] in BACKENDS and ex['classification'] in NEGATIVE and HEX64.fullmatch(ex['tested_suffix_sha256']) and HEX64.fullmatch(ex['recovered_cipher_prefix_sha256']) and isinstance(ex['rejection'],dict)
  for survivor in cell['retained']:
   assert survivor['cipher'] in BACKENDS and sorted(survivor['order'])==list(range(w));suffix=bytes.fromhex(survivor['full_suffix_hex']);assert len(suffix)==survivor['suffix_bytes'] and hashlib.sha256(suffix).hexdigest()==survivor['suffix_sha256'] and len(survivor['two_iv_full_reference'])==2
   assert [x['iv_suite'] for x in survivor['two_iv_full_reference']]==[1,2] and all(x['suffix_exact'] and x['reencryption_exact'] and HEX64.fullmatch(x['full_plaintext_sha256']) for x in survivor['two_iv_full_reference'])
  total_orders+=fact;total_contexts+=fact*7;total_retained+=len(cell['retained'])
  for cl,n in combined.items():total_classes[cl]=total_classes.get(cl,0)+n
 assert seen==expected and total_orders==3272896 and total_contexts==22910272 and total_retained==0 and total_classes=={'rejected_a105':22463286,'rejected_fsa_transition':446986}
 summary=result['summary'];assert summary=={'geometries':64,'orders_examined':3272896,'backend_contexts_examined':22910272,'unexamined':0,'classification_counts':total_classes,'retained_count':0,'all_complete_uncapped':True}
 print(json.dumps({'identity':IDENTITY,'verified':True,'result_sha256':RESULT_SHA,'gate_sha256':GATE_SHA,'geometries':64,'orders':total_orders,'contexts':total_contexts,'classes':total_classes,'retained':0,'verification_scope':'artifact/gate/canonical orientation, Cartesian cells, factorial/backend/class accounting, digest/example format, and survivor-field structural checks; no second negative cryptographic enumeration'},indent=2,sort_keys=True))
if __name__=='__main__':main()
