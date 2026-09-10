#!/usr/bin/env python3
"""Synthetic controls for the exact 201-codepoint lossy-map DES all-IV suffix frontier."""
from pathlib import Path
import argparse,hashlib,importlib.util,itertools,json,platform
import Crypto
from Crypto.Cipher import DES
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];LEDGER=HERE/'controls.json';IDENTITY='ASTRA';CORE=HERE/'core.py';INVENTORY=ROOT/'research/char_amsco/astra/lossy4_onechar_inventory/inventory.json';ANALYZE=ROOT/'research/char_amsco/astra/cryptool_bug/analyze.py';ENDPOINT=ROOT/'research/rev7-20260909-codex/coverage/transposition_byte_bag/proof.py'
CORE_SHA='7a10f904bbfdc027bae27816e3a8e4fff351869bd7cf063cb898a5fdbb7d2879';INVENTORY_SHA='fa9d7463848918d2eaddfe6afdf013f2d5b6b1d1c2011aa5d0aa5a197eec4fe2';ENDPOINT_SHA='cec1c5d70d2e9b7299864f34ffc42ba8dde9e3738b85e3319d4a1e476e06245d'
PINS={'research/char_amsco/astra/lossy4_onechar_inventory/inventory.py':'6990162132bd5d2d3c77ef3fce00d07c1f807fb33845283021ebbf4fe4323b50','research/char_amsco/astra/lossy4_onechar_inventory/README.md':'b3ddf71c31ea645c299f2986a133d0ef0552ee28fd3a5fb259872cb44abbbcfa','research/char_amsco/astra/lossy4_onechar_inventory/REPORT.md':'fd02987bfdcbdab0311fd52d4a1bf5ac1acece3efc67afb88ec6ca09265401d1','research/char_amsco/astra/cryptool_bug/analyze.py':'ba66b3c844cf5784749587af960a11163d5e47deddf523a04530bea4f5d9629b','research/char_amsco/astra/cryptool_bug/evidence.json':'71ee944899ce7a202e07ee4b0d292309978f3a7eb3eb697d0c196f858844daab','research/char_amsco/astra/cryptool_bug/source/class.amsco.php.base64':'25143ebd1a720d9fe35ac3aa2579be722a8ded03b67d6ff2da0f071e40f8c3ac','research/char_amsco/astra/cryptool_bug/source/default_tool.php':'e71bcfe75ae9250b00f8adf38eaec4547b854bfafd23a559cfef482d0f81a7d6','research/char_amsco/astra/cryptool_bug/source/infobox.template':'0e6f9a9f73a2aee868567fe082a342a75334a3944ca050599da6bfcb97c040af','research/char_amsco/astra/amsco_geometry.py':'c43e6412cbf2ac34e137801e1fd9c13e8c46bb89296bb89484c01d28a505cae6','research/rev7-20260909-codex/coverage/transposition_byte_bag/controls.json':'71a3314d0ea38714bf1cc49967edada8598482e49f8f7abac2f93748748f6c90','research/rev7-20260909-codex/coverage/transposition_byte_bag/README.md':'be6a92cadf3eb3637ff0d23844420c1213bbf3e71ff16761cd3fefc73aa9826f','research/rev7-20260909-codex/coverage/transposition_byte_bag/REPORT.md':'4977c8f24215078a56016cc60734fd693b713b5dd56f969fbce4c68d1baac023'}
def hb(x):return hashlib.sha256(x).hexdigest()
def sha(p):return hb(Path(p).read_bytes())
def load(path,name):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def verify_pins():
 assert sha(CORE)==CORE_SHA and sha(INVENTORY)==INVENTORY_SHA and sha(ENDPOINT)==ENDPOINT_SHA
 for rel,want in PINS.items():assert sha(ROOT/rel)==want,(rel,sha(ROOT/rel),want)
verify_pins();core=load(CORE,'astra_l4_utf8_core');legacy=load(ANALYZE,'astra_l4_utf8_legacy');endpoint=load(ENDPOINT,'astra_l4_utf8_endpoint');legacy.verify_pins();assert tuple(endpoint.CODEPOINTS)==core.CODEPOINTS and tuple(endpoint.WORDS)==core.WORDS
# Independent endpoint copy/oracle: do not call core.step or core.strict_prefix_oracle.
CP_SET=frozenset((9,10,13,*range(0x20,0x7f),*range(0xa0,0x100),0x2013,0x2014,0x2018,0x2019,0x201c,0x201d,0x2026));PREFIXES=(b'',b'\xc2',b'\xc3',b'\xe2',b'\xe2\x80')
def oracle(data):
 out=[]
 for prefix in PREFIXES:
  try:text=(prefix+data).decode('utf-8')
  except UnicodeDecodeError:continue
  if all(ord(ch) in CP_SET for ch in text):out.append(prefix.hex())
 return out
def source_indices(length,key):
 rows={};pos=cell=0;size=2
 while pos<length:
  take=min(size,length-pos);row=cell//4;col=cell%4;rows.setdefault(row,{})[int(key[col])]=tuple(range(pos,pos+take));pos+=take;cell+=1;size=3-size
 out=[]
 for label in range(1,5):
  for row in range(max(rows)+1):out.extend(rows.get(row,{}).get(label,()))
 return tuple(out)
def source_emit(text,key):return ''.join(text[i] for i in source_indices(len(text),key))
def deterministic_hex(length,label):
 out='';i=0
 while len(out)<length:out+=hashlib.sha256((label+str(i)).encode()).hexdigest().upper();i+=1
 return out[:length]
def endpoint_controls():
 words=[]
 for cp,word in zip(core.CODEPOINTS,core.WORDS):
  states=core.INITIAL
  for b in word:states=core.step(states,b)
  assert core.BOUNDARY in states and core.accepts_suffix(word) and oracle(word)
  words.append({'codepoint':f'U+{cp:04X}','hex':word.hex(),'initial_states_after':sorted(states),'oracle_prefixes':oracle(word)})
 # Exhaustive independent equivalence for every byte string of length 0,1,2.
 digest=hashlib.sha256();accepted=0;cases=0
 for n in range(3):
  for tup in itertools.product(range(256),repeat=n):
   data=bytes(tup);a=core.accepts_suffix(data);b=bool(oracle(data));assert a==b;cases+=1;accepted+=a;digest.update(data);digest.update(bytes((a,)))
 assert cases==65793
 examples=[b'\x80',b'\xa0',b'\xc2\xa0',b'\xc3\x80',b'\xe2\x80\x93',b'\xc2',b'\xe2\x80',b'\xe2\x93\x80',b'\xc2\x80',b'\xc4\x80',b'\x80A']
 ex=[]
 for data in examples:
  states=core.INITIAL
  for b in data:states=core.step(states,b)
  assert core.accepts_suffix(data)==bool(oracle(data));ex.append({'hex':data.hex(),'accepted':core.accepts_suffix(data),'ending_states':sorted(states),'oracle_prefixes':oracle(data),'all_bytes_in_165_union':set(data)<=set(core.BYTE_UNION)})
 single=next(x for x in ex if x['hex']=='80');assert single['accepted'] and single['ending_states']==[core.BOUNDARY,core.AFTER_E280] and single['oracle_prefixes']==['c3']
 bad=next(x for x in ex if x['hex']=='e29380');assert not bad['accepted'] and bad['all_bytes_in_165_union']
 return {'codewords':words,'all_201_codewords_accept':True,'exhaustive_lengths_0_to_2':{'cases':cases,'accepted':accepted,'all_equal_independent_strict_prefix_oracle':True,'digest_sha256':digest.hexdigest()},'examples':ex,'single_80_existential_boundary_control':True,'byte_union_is_not_endpoint_grammar_control':True}
def build_plain(n,cut,full):
 if cut=='two':out=bytearray(b'ABCDEFG'+chr(0x00e9).encode());assert out[7]==0xc3 and 0x80<=out[8]<=0xbf
 else:out=bytearray(b'ABCDEF'+chr(0x2013).encode());assert out[6:8]==b'\xe2\x80' and out[8]==0x93
 base=[b' lower UPPER Mixed \t\n\r ',*(chr(cp).encode() for cp in (0x2013,0x2014,0x2018,0x2019,0x201c,0x201d,0x2026))]
 if full:base.extend(chr(cp).encode() for cp in range(0xa0,0x100))
 else:base.extend(chr(cp).encode() for cp in range(0xa0,0xb0))
 i=0
 while len(out)<n:
  word=base[i%len(base)];i+=1
  if len(out)+len(word)<=n:out.extend(word)
  else:out.extend(b'X'*(n-len(out)))
 plain=bytes(out);assert len(plain)==n;plain.decode('utf-8');assert all(ord(ch) in CP_SET for ch in plain.decode('utf-8'))
 if full:
  cps=set(map(ord,plain.decode('utf-8')));assert set(range(0xa0,0x100))<=cps and {9,10,13,0x2013,0x2014,0x2018,0x2019,0x201c,0x201d,0x2026}<=cps
 assert oracle(plain[8:])
 return plain
def validate(row,observed,n,key):
 for x in row['solutions']:
  seed=bytes.fromhex(x['initial_register_hex']);ct=bytes.fromhex(x['ciphertext_hex']);pt=bytes.fromhex(x['suffix_plaintext_hex']);assert ct[:8]==seed and len(ct)==n and len(pt)==n-8 and core.BOUNDARY in x['endpoint_states']
  assert DES.new(core.KEY,DES.MODE_CFB,iv=seed,segment_size=8).decrypt(ct[8:])==pt==core.manual_suffix(seed,ct[8:])
  witnesses=oracle(pt);assert witnesses and core.accepts_suffix(pt);x['independent_prefix_witnesses']=witnesses
  hx=ct.hex().upper();assert source_emit(hx,key)==observed==legacy.legacy_encode(hx.encode(),key)['raw'].decode();assert hb(pt)==x['suffix_plaintext_sha256'] and hb(ct)==x['ciphertext_sha256']
 return {'all_terminal_lengths_hashes_exact':True,'all_pycryptodome_suffixes_exact':True,'all_manual_suffixes_exact':True,'all_independent_unicode_prefix_oracles_accept':True,'all_representative_source_emissions_exact':True}
def plant(label,key,n,iv,cut,full):
 plain=build_plain(n,cut,full);ct=DES.new(core.KEY,DES.MODE_CFB,iv=iv,segment_size=8).encrypt(plain);idx=source_indices(2*n,key);obs=source_emit(ct.hex().upper(),key);assert obs==legacy.legacy_encode(ct.hex().upper().encode(),key)['raw'].decode();row=core.search(obs,n,idx);check=validate(row,obs,n,key)
 truth=[x for x in row['solutions'] if bytes.fromhex(x['ciphertext_hex'])==ct and bytes.fromhex(x['suffix_plaintext_hex'])==plain[8:]] if row['complete'] else []
 if row['complete']:assert len(truth)==1
 return {'id':label,'representative_key':key,'root_shape':row['initial_registers_total'],'natural_bytes':n,'cut_at_suffix_start':cut,'full_endpoint_inventory_present':full,'original_iv_hex':iv.hex(),'plaintext_sha256':hb(plain),'truth_ciphertext_sha256':hb(ct),'observation_length':len(obs),'observation_sha256':hb(obs.encode()),'complete':row['complete'],'truth_retained_exactly_once':(len(truth)==1 if row['complete'] else None),'search':row,'validation':check}
def null(label,key):
 idx=source_indices(1310,key);obs=deterministic_hex(len(idx),'ASTRA lossy4 UTF8 null '+label+' ');row=core.search(obs,655,idx);return {'id':label,'representative_key':key,'observation_sha256':hb(obs.encode()),'search':row,'validation':validate(row,obs,655,key)}
def generate():
 inv=json.loads(INVENTORY.read_text());maps=[x for x in inv['map_classes'] if x['input_chars']==1310];assert len(maps)==12
 geometry=[]
 for g in maps:
  idx=source_indices(1310,g['representative_key']);assert list(idx)==g['emission_indices'];fixture=deterministic_hex(1310,'ASTRA UTF8 geometry '+g['class_id']+' ');obs=source_emit(fixture,g['representative_key']);assert obs==legacy.legacy_encode(fixture.encode(),g['representative_key'])['raw'].decode();vals,masks=core.reconstruct(obs,655,idx);roots,proof=core.roots_and_proof(vals,masks);assert len(roots)==(4096 if g['dropped_column']==1 else 256)
  geometry.append({'class_id':g['class_id'],'representative_key':g['representative_key'],'map_sha256':g['map_sha256'],'dropped_column':g['dropped_column'],'root_count':len(roots),'root_proof':proof,'source_map_and_emission_exact':True})
 d1=[x for x in maps if x['dropped_column']==1];d3=[x for x in maps if x['dropped_column']==3]
 plants=[plant('short99|drop1|cut2',d1[1]['representative_key'],99,bytes.fromhex('1020304050607080'),'two',False),plant('short99|drop3|cut3',d3[0]['representative_key'],99,bytes.fromhex('90A0B0C0D0E0F001'),'three',False),plant('full655|drop1|cut3',d1[-1]['representative_key'],655,bytes.fromhex('1122334455667788'),'three',True),plant('full655|drop3|cut2',d3[-1]['representative_key'],655,bytes.fromhex('8877665544332211'),'two',True)]
 nulls=[null('drop1',d1[2]['representative_key']),null('drop3',d3[2]['representative_key'])]
 caps=[]
 for src in (plants[0],plants[1]):
  # Reconstruct the deterministic plant rather than reading target data.
  plain=build_plain(src['natural_bytes'],src['cut_at_suffix_start'],False);ct=DES.new(core.KEY,DES.MODE_CFB,iv=bytes.fromhex(src['original_iv_hex']),segment_size=8).encrypt(plain);idx=source_indices(2*src['natural_bytes'],src['representative_key']);obs=source_emit(ct.hex().upper(),src['representative_key']);row=core.search(obs,src['natural_bytes'],idx,max_accepted=1);assert not row['complete'] and row['capped_reason']=='max_accepted' and row['solution_count']==0 and row['partial_root'] and row['accepted_states']==1;caps.append({'id':src['id'],'root_shape':row['initial_registers_total'],'search':row})
 return {'identity':IDENTITY,'target_evaluated':False,'rev7_read':False,'crypto_evaluated':True,'scope':'Synthetic-only exact 201-codepoint boundary-aware UTF-8 suffix frontier over the twelve source-map geometries; DES all-IV mechanics tested on both root shapes.','endpoint':{'codepoints':len(core.CODEPOINTS),'codeword_lengths':{str(n):sum(len(x)==n for x in core.WORDS) for n in (1,2,3)},'initial_state_set':sorted(core.INITIAL),'terminal_rule':'boundary state 0 is present; other unfinished initial-context alternatives do not invalidate an existential completed context','state_set_determinization':True,'byte_union_shortcut_forbidden':True},'automaton_controls':endpoint_controls(),'geometry_all_12_maps':geometry,'plants':plants,'random_nulls':nulls,'tiny_caps':caps,'limits':{'max_live_frontier_per_root':core.MAX_FRONTIER,'max_global_accepted_states':core.MAX_ACCEPTED,'cap_classification':'INCOMPLETE; no positive-control acceptance claim','first_8_plaintext_bytes':'unknown and not recovered','original_iv':'unknown and not recovered','no_score_or_beam':True},'source':{'endpoint_proof_sha256':ENDPOINT_SHA,'inventory_sha256':INVENTORY_SHA,'core_sha256':CORE_SHA,'pins':PINS},'environment':{'python':platform.python_version(),'pycryptodome':Crypto.__version__,'platform':platform.platform()},'assertions':{'all_source_pins_checked_before_use':True,'exact_201_codepoints_98_96_7':len(core.CODEPOINTS)==201 and [sum(len(x)==n for x in core.WORDS) for n in (1,2,3)]==[98,96,7],'all_codewords_and_exhaustive_len0to2_match_independent_oracle':True,'single_80_existential_boundary_semantics':True,'all12_source_maps_and_dynamic_roots_exact':True,'two_short_and_two_full_plants_cover_both_root_shapes_and_boundary_cuts':True,'all_complete_plant_truths_retained_once':all(x['truth_retained_exactly_once'] is True for x in plants if x['complete']),'all_terminal_candidates_independently_validated':True,'both_nulls_complete':all(x['search']['complete'] for x in nulls),'both_caps_incomplete_without_partial_solutions':all(not x['search']['complete'] and x['search']['solution_count']==0 for x in caps),'no_target_read_or_evaluation':True},'controls_source_sha256':sha(Path(__file__))}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args();out=generate()
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit('refusing existing output')
  a.regenerate.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n');print(json.dumps({'identity':IDENTITY,'output':str(a.regenerate),'sha256':sha(a.regenerate)},sort_keys=True))
 else:
  assert json.loads(LEDGER.read_text())==out;print(json.dumps({'identity':IDENTITY,'verified':True,'ledger_sha256':sha(LEDGER),'plants':4,'target_evaluated':False},sort_keys=True))
if __name__=='__main__':main()
