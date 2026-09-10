#!/usr/bin/env python3
"""Synthetic audit controls for literal CrypTool keys 2013/2014 and all-IV DES CFB8 suffix recovery."""
from __future__ import annotations
from pathlib import Path
import argparse,hashlib,importlib.util,itertools,json,platform,sys
import Crypto
from Crypto.Cipher import DES

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
LEDGER=HERE/'controls.json'
IDENTITY='ASTRA'
KEY=b'Zombies\0'
ALLOWED=bytes(range(32,127))
MAX_FRONTIER=100_000
MAX_ACCEPTED=5_000_000
PINS={
 'research/char_amsco/astra/lossy2013/core.py':'abadb49e68477b2875cffb712889798c8206ad3dde2357d7d71a5f5a09d1752e',
 'research/char_amsco/astra/cryptool_bug/analyze.py':'ba66b3c844cf5784749587af960a11163d5e47deddf523a04530bea4f5d9629b',
 'research/char_amsco/astra/cryptool_bug/evidence.json':'71ee944899ce7a202e07ee4b0d292309978f3a7eb3eb697d0c196f858844daab',
 'research/char_amsco/astra/cryptool_bug/source/class.amsco.php.base64':'25143ebd1a720d9fe35ac3aa2579be722a8ded03b67d6ff2da0f071e40f8c3ac',
 'research/char_amsco/astra/cryptool_bug/source/default_tool.php':'e71bcfe75ae9250b00f8adf38eaec4547b854bfafd23a559cfef482d0f81a7d6',
 'research/char_amsco/astra/cryptool_bug/source/infobox.template':'0e6f9a9f73a2aee868567fe082a342a75334a3944ca050599da6bfcb97c040af',
 'research/char_amsco/astra/amsco_geometry.py':'c43e6412cbf2ac34e137801e1fd9c13e8c46bb89296bb89484c01d28a505cae6',
}

def hb(data:bytes)->str:return hashlib.sha256(data).hexdigest()
def sha(path)->str:return hb(Path(path).read_bytes())
def verify_file_pins():
 for rel,want in PINS.items():
  got=sha(ROOT/rel);assert got==want,(rel,got,want)

def load(rel,name):
 path=ROOT/rel;spec=importlib.util.spec_from_file_location(name,path);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod

# No source-derived function is imported or called until every transport/source pin passes.
verify_file_pins()
core=load('research/char_amsco/astra/lossy2013/core.py','astra_alliv_l13_core')
legacy=load('research/char_amsco/astra/cryptool_bug/analyze.py','astra_alliv_l13_legacy')
legacy.verify_pins()

def compatible_values(value:int,mask:int,domain=range(256)):
 return tuple(x for x in domain if (x&mask)==(value&mask))

def compatible_registers(vals:bytes,masks:bytes):
 """Lexicographic Cartesian generator for every C[0:8] consistent with the observed masks."""
 assert len(vals)>=8 and len(masks)>=8
 choices=[compatible_values(v,m) for v,m in zip(vals[:8],masks[:8])]
 for parts in itertools.product(*choices):yield bytes(parts)

def reconstruct_generator_proof(observed:str,nbytes:int):
 vals,masks=core.reconstruct(observed,nbytes,'2013')
 generated=list(compatible_registers(vals,masks))
 # The same direct predicate is evaluated independently without calling compatible_registers;
 # product is restricted to each independently filtered byte domain to avoid 256**8 work.
 direct={bytes(x) for x in itertools.product(*(tuple(c for c in range(256) if (c&m)==(v&m)) for v,m in zip(vals[:8],masks[:8])))}
 assert len(generated)==len(set(generated))==len(direct)==4096 and set(generated)==direct
 assert tuple(masks[:8])==(0xff,0x0f,0xff,0xff,0x0f,0xff,0xff,0x0f)
 return vals,masks,generated,{
  'mask_prefix':[f'{x:02x}' for x in masks[:8]],
  'compatible_counts_per_byte':[len(compatible_values(v,m)) for v,m in zip(vals[:8],masks[:8])],
  'generated_count':len(generated),'unique_count':len(set(generated)),'direct_product_count':len(direct),
  'generator_equals_direct_mask_product':True,'registers_digest_sha256':hb(b''.join(generated)),
 }

def manual_suffix(seed:bytes,cipher_suffix:bytes)->bytes:
 e=DES.new(KEY,DES.MODE_ECB);reg=bytearray(seed);out=bytearray()
 for c in cipher_suffix:
  out.append(c^e.encrypt(bytes(reg))[0]);reg[:]=reg[1:]+bytes((c,))
 return bytes(out)

def search(observed:str,nbytes:int,max_frontier=MAX_FRONTIER,max_accepted=MAX_ACCEPTED):
 if max_frontier<1 or max_accepted<0:raise ValueError('invalid cap')
 vals,masks,roots,proof=reconstruct_generator_proof(observed,nbytes)
 e=DES.new(KEY,DES.MODE_ECB)
 solutions=[];counts=[0]*(nbytes-8);accepted=0;calls=0;max_live=0;roots_completed=0;roots_started=0
 partial=None
 for root_index,seed in enumerate(roots):
  roots_started+=1;front=[(seed,b'',seed)]
  for pos in range(8,nbytes):
   nxt=[];parents_processed=0;choices_examined=0
   v=vals[pos];m=masks[pos]
   for reg,pt,ct in front:
    k=e.encrypt(reg)[0];calls+=1;parents_processed+=1
    choices=(bytes((v^k,)) if m==0xff else ALLOWED)
    for plain in choices:
     choices_examined+=1;c=v if m==0xff else plain^k
     if plain not in ALLOWED or (c&m)!=(v&m):continue
     if accepted>=max_accepted:
      partial={'root_index':root_index,'root_hex':seed.hex(),'position':pos,'reason':'max_accepted','frontier_before':len(front),'parents_processed':parents_processed,'choices_examined':choices_examined,'next_frontier_constructed':len(nxt),'next_valid_candidate_not_added':True}
      return finish(False,'max_accepted',nbytes,proof,solutions,counts,accepted,calls,max(max_live,len(nxt)),roots_started,roots_completed,len(roots)-root_index-1,partial)
     if len(nxt)>=max_frontier:
      partial={'root_index':root_index,'root_hex':seed.hex(),'position':pos,'reason':'max_frontier','frontier_before':len(front),'parents_processed':parents_processed,'choices_examined':choices_examined,'next_frontier_constructed':len(nxt),'next_valid_candidate_not_added':True}
      return finish(False,'max_frontier',nbytes,proof,solutions,counts,accepted,calls,max(max_live,len(nxt)),roots_started,roots_completed,len(roots)-root_index-1,partial)
     nxt.append((reg[1:]+bytes((c,)),pt+bytes((plain,)),ct+bytes((c,))))
     accepted+=1;counts[pos-8]+=1
   front=nxt;max_live=max(max_live,len(front))
   if not front:break
  # Only terminal states from a completely processed root are solutions.
  if front and pos==nbytes-1:
   for _,pt,ct in front:
    assert len(pt)==nbytes-8 and len(ct)==nbytes
    solutions.append({'initial_register_hex':seed.hex(),'suffix_plaintext_hex':pt.hex(),'ciphertext_hex':ct.hex(),'suffix_plaintext_sha256':hb(pt),'ciphertext_sha256':hb(ct)})
  roots_completed+=1
 return finish(True,None,nbytes,proof,solutions,counts,accepted,calls,max_live,roots_started,roots_completed,0,None)

def finish(complete,reason,nbytes,proof,solutions,counts,accepted,calls,max_live,started,completed,unexamined,partial):
 assert accepted==sum(counts)
 assert started==completed+(partial is not None)
 assert completed+unexamined+(partial is not None)==4096
 assert complete==(completed==4096 and partial is None)
 assert all(len(bytes.fromhex(x['suffix_plaintext_hex']))==nbytes-8 and len(bytes.fromhex(x['ciphertext_hex']))==nbytes for x in solutions)
 return {'complete':complete,'capped_reason':reason,'natural_bytes':nbytes,'initial_register_proof':proof,'initial_registers_total':4096,'roots_started':started,'roots_completed':completed,'roots_unexamined':unexamined,'partial_root':partial,'accepted_states':accepted,'accepted_states_by_suffix_byte':counts,'block_calls':calls,'max_live_frontier_per_root':max_live,'solutions_are_terminal_only':True,'solution_count':len(solutions),'solutions':solutions}

def independent_validate(row,observed,nbytes):
 for x in row['solutions']:
  seed=bytes.fromhex(x['initial_register_hex']);ct=bytes.fromhex(x['ciphertext_hex']);pt=bytes.fromhex(x['suffix_plaintext_hex'])
  assert len(seed)==8 and ct[:8]==seed and len(ct)==nbytes and len(pt)==nbytes-8
  lib=DES.new(KEY,DES.MODE_CFB,iv=seed,segment_size=8).decrypt(ct[8:])
  man=manual_suffix(seed,ct[8:]);assert lib==man==pt and set(pt)<=set(ALLOWED)
  hx=ct.hex().upper();assert core.emit(hx,'2013')==observed==core.emit(hx,'2014')
  assert legacy.legacy_encode(hx.encode(),'2013')['raw'].decode()==observed
  assert legacy.legacy_encode(hx.encode(),'2014')['raw'].decode()==observed
  assert hb(pt)==x['suffix_plaintext_sha256'] and hb(ct)==x['ciphertext_sha256']
 return {'all_terminal_lengths_exact':True,'all_suffixes_printable_ascii':True,'all_library_suffix_decryptions_exact':True,'all_manual_recurrences_exact':True,'all_2013_2014_source_emissions_exact':True,'all_hashes_exact':True}

def repeated(text,n):return (text*((n+len(text)-1)//len(text)))[:n].encode('ascii')
def plant(label,text,nbytes,original_iv):
 plain=repeated(text,nbytes)
 ct=DES.new(KEY,DES.MODE_CFB,iv=original_iv,segment_size=8).encrypt(plain)
 assert core.encrypt_cfb8('des',original_iv,plain)==ct
 observed=legacy.legacy_encode(ct.hex().upper().encode(),'2013')['raw'].decode()
 assert observed==core.emit(ct.hex().upper(),'2013')==core.emit(ct.hex().upper(),'2014')
 row=search(observed,nbytes)
 check=independent_validate(row,observed,nbytes)
 truth=[x for x in row['solutions'] if bytes.fromhex(x['ciphertext_hex'])==ct and bytes.fromhex(x['suffix_plaintext_hex'])==plain[8:]]
 assert row['complete'] and len(truth)==1
 return {'id':label,'natural_bytes':nbytes,'original_iv_hex':original_iv.hex(),'original_prefix_plaintext_unrecovered':True,'plaintext_sha256':hb(plain),'truth_ciphertext_sha256':hb(ct),'observed_length':len(observed),'observed_sha256':hb(observed.encode()),'truth_retained_exactly_once':True,'search':row,'validation':check}

def deterministic_hex(length,label):
 out='';i=0
 while len(out)<length:
  out+=hashlib.sha256((label+str(i)).encode()).hexdigest().upper();i+=1
 return out[:length]

def null_control():
 observed=deterministic_hex(1092,'ASTRA lossy2013 all-IV deterministic null ')
 row=search(observed,655);check=independent_validate(row,observed,655)
 return {'id':'deterministic_random_hex_1092','generator':'successive SHA-256 hex of label plus decimal counter; concatenated then truncated','label':'ASTRA lossy2013 all-IV deterministic null ','observed_length':1092,'observed_sha256':hb(observed.encode()),'search':row,'validation':check}

def small_generator_control():
 vals=(0xA,0x1,0x8);masks=(0xF,0x3,0xC);domain=range(16)
 via=[tuple(x) for x in itertools.product(*(compatible_values(v,m,domain) for v,m in zip(vals,masks)))]
 direct=[x for x in itertools.product(domain,repeat=3) if all((x[i]&masks[i])==(vals[i]&masks[i]) for i in range(3))]
 assert via==direct and len(via)==16
 return {'domain':'0..15','values':list(vals),'masks':list(masks),'count':16,'generator_equals_naive_full_domain':True,'rows':[list(x) for x in via]}

def generate():
 verify_file_pins();legacy.verify_pins()
 rows=[
  plant('original_short99','Quiet mixed ASCII words preserve every printable suffix. ',99,bytes.fromhex('1020304050607080')),
  plant('original_long655','A second synthetic passage tests all printable punctuation and letters through the entire suffix frontier. ',655,bytes.fromhex('90a0b0c0d0e0f001')),
 ]
 null=null_control()
 # Force an early accepted-state cap. Partial paths must never appear as terminal solutions.
 base=rows[0];obs=deterministic_hex(0,'')
 # Recreate the exact short observation from its unique truth ciphertext, without relying on stored observation bytes.
 truth=next(x for x in base['search']['solutions'] if x['ciphertext_sha256']==base['truth_ciphertext_sha256'])
 obs=core.emit(bytes.fromhex(truth['ciphertext_hex']).hex().upper(),'2013')
 tiny=search(obs,99,max_frontier=100000,max_accepted=1)
 assert not tiny['complete'] and tiny['capped_reason']=='max_accepted' and tiny['partial_root'] is not None and tiny['solution_count']==0 and tiny['accepted_states']==1 and tiny['roots_completed']<4096
 assert all(len(bytes.fromhex(x['suffix_plaintext_hex']))==91 for x in tiny['solutions'])
 return {
  'identity':IDENTITY,'target_evaluated':False,'rev7_read':False,'crypto_evaluated':True,
  'scope':'Synthetic-only exhaustive compatible-C[0:8] enumeration and printable-ASCII DES CFB8 suffix frontier for literal lossy CrypTool keys 2013/2014.',
  'model':{'cipher':'DES','key_ascii_nul':'Zombies\\0','block_size':8,'known_suffix_offset':8,'allowed_suffix_bytes':'32..126 inclusive','first_8_ciphertext_bytes':'enumerated across every observation-compatible register','first_8_plaintext_bytes':'unknown and not recovered','original_iv':'arbitrary and not recovered','no_score_or_beam':True,'root_order':'lexicographic C[0:8]','root_processing':'sequential','max_live_frontier_scope':'per root','accepted_budget_scope':'global across all roots; counts accepted suffix child states and excludes the 4096 initial registers'},
  'caps':{'max_live_frontier_per_root':MAX_FRONTIER,'max_global_accepted_states':MAX_ACCEPTED,'classification':'INCOMPLETE on cap; completed-root terminal solutions may be retained, but partial-root paths are never solutions'},
  'source_provenance':{'cryptool_repository':'cryptool-org/cto','commit':'4fc443f0d87c0e86815695a47ab2d6174c725f82','legacy_keys':['2013','2014'],'pins':PINS,'optional_original_latin1_class_sha256':'132d61ff8b794ab9717a0ce284d7bf21f82c8dbfe39bf9f1a3b5f7aa7eb91e4f','transport_note':'class.amsco.php.base64 is the exact bounded transport fallback for the optional Latin-1 original'},
  'environment':{'python':platform.python_version(),'pycryptodome':Crypto.__version__,'platform':platform.platform()},
  'small_4bit_generator':small_generator_control(),'plants':rows,'random_null':null,
  'tiny_cap':tiny,
  'assertions':{'all_source_pins_checked_before_use':True,'actual_prefix_has_exactly_4096_unique_registers':all(x['search']['initial_register_proof']['unique_count']==4096 for x in rows+[null]),'generator_equals_independent_mask_product':True,'both_original_plants_complete':all(x['search']['complete'] for x in rows),'both_truth_ciphertext_suffix_pairs_retained_exactly_once':all(x['truth_retained_exactly_once'] for x in rows),'every_complete_candidate_independently_verified':True,'tiny_cap_is_incomplete':True,'tiny_cap_has_no_partial_solution':True,'no_target_read_or_evaluation':True},
  'controls_source_sha256':sha(Path(__file__)),
 }

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args()
 out=generate()
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit('refusing existing output')
  a.regenerate.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n')
  print(json.dumps({'identity':IDENTITY,'output':str(a.regenerate),'sha256':sha(a.regenerate)},sort_keys=True))
 else:
  frozen=json.loads(LEDGER.read_text());assert frozen==out
  print(json.dumps({'identity':IDENTITY,'verified':True,'ledger_sha256':sha(LEDGER),'plants':len(out['plants']),'random_null_complete':out['random_null']['search']['complete'],'target_evaluated':False},sort_keys=True))
if __name__=='__main__':main()
