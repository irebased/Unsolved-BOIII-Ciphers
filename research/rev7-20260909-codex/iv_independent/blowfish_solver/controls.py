#!/usr/bin/env python3
"""Read-only verifier and explicit synthetic regenerator for native Blowfish searches."""
from __future__ import annotations
import argparse,hashlib,importlib.util,itertools,json,math,platform,random,shlex,subprocess,tempfile
from pathlib import Path
from Crypto.Cipher import Blowfish
import Crypto

HERE=Path(__file__).resolve().parent
REPO=HERE.parents[3]
LEDGER=HERE/"controls.json"
NATIVE=HERE/"native.cpp"
COMPAT=REPO/"research/byte_columnar/all_iv/column_a/compat_source"
BUILD_COMPAT=COMPAT/"build_compat.py"
KEY=b"Zombies"; BS=8; HEX="0123456789ABCDEF"
RELAXED={9,10,13}|set(range(32,127))|{0xE2,0x80,0x93,0x94,0x98,0x99,0xA6}
THIRDS={0x93,0x94,0x98,0x99,0xA6}
EXPECTED={
 "native.cpp":"b7f3a187f29705fc21f7a529b7722f9f9d936a4f66715e107ff52acfb11ca433",
 "compat_source/build_compat.py":"6c0ab4888febcf87d45515bd4ad8b34f11a85edb05d0cb99ad1f75b8dd24f0aa",
 "compat_source/blowfish-compat.c":"3584374a6bae4df8899e82d36255bbac0472904aed2095e3c08c57a5dd5b4cad",
 "compat_source/blowfish.h":"bb4a14ecbd5dc92105b290d9261ed562a980c6e42b0d9b4b56e62b4b6c39665b",
 "compat_source/COPYING.LIB":"ca0061fc1381a3ab242310e4b3f56389f28e3d460eb2fd822ed7a21c6f030532",
 "compat_source/PROVENANCE.md":"ffb5e443fa77844a31dbe84440c9cc452f2139a766e61b570602cbc4cfcaea3a",
}
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def dep_paths():
 return {
  "native.cpp":NATIVE,
  "compat_source/build_compat.py":BUILD_COMPAT,
  "compat_source/blowfish-compat.c":COMPAT/"blowfish-compat.c",
  "compat_source/blowfish.h":COMPAT/"blowfish.h",
  "compat_source/COPYING.LIB":COMPAT/"COPYING.LIB",
  "compat_source/PROVENANCE.md":COMPAT/"PROVENANCE.md",
 }
def verify_deps():
 actual={name:sha(path) for name,path in dep_paths().items()}
 assert actual==EXPECTED,(actual,EXPECTED)
 return actual
def word_reverse(x):return x[3::-1]+x[7:3:-1]
def strict_ok(data):
 states={0,1,2}
 for value in data:
  nxt=set()
  for state in states:
   if state==0:
    if value in (9,10,13) or 32<=value<=126:nxt.add(0)
    elif value==0xE2:nxt.add(1)
   elif state==1 and value==0x80:nxt.add(2)
   elif state==2 and value in THIRDS:nxt.add(0)
  states=nxt
  if not states:return False
 return 0 in states
def cfb_encrypt(pt,iv,block):
 reg=iv;out=bytearray()
 for value in pt:
  y=value^block(reg)[0];out.append(y);reg=reg[1:]+bytes([y])
 return bytes(out)
def cfb_decrypt(ct,iv,block):
 reg=iv;out=bytearray()
 for value in ct:
  out.append(value^block(reg)[0]);reg=reg[1:]+bytes([value])
 return bytes(out)
def encode_display(ct,mapping):
 inverse=[None]*16
 for displayed,actual in enumerate(mapping):inverse[actual]=displayed
 return "".join(HEX[inverse[b>>4]]+HEX[inverse[b&15]] for b in ct)
def decode_display(display,mapping):
 return bytes((mapping[int(display[i],16)]<<4)|mapping[int(display[i+1],16)] for i in range(0,len(display),2))
def seed_spec(mapping):
 return ",".join(f"{i}:{mapping[i]}" for i in range(12))
def canonical_solutions(rows):
 return sorted(
  [{"mapping":list(row["mapping"]),"plaintext_suffix_hex":row.get("plaintext_suffix_hex",row.get("suffix_hex"))} for row in rows],
  key=lambda row:(row["mapping"],row["plaintext_suffix_hex"])
 )
def naive(display,block,mapping_seed):
 unknown=[s for s in range(16) if s not in mapping_seed]
 free=[v for v in range(16) if v not in mapping_seed.values()]
 assert len(unknown)==len(free)==4
 solutions=[];relaxed_reject=0;strict_reject=0
 for values in itertools.permutations(free):
  mapping=[None]*16
  for s,v in mapping_seed.items():mapping[s]=v
  for s,v in zip(unknown,values):mapping[s]=v
  ct=decode_display(display,mapping)
  suffix=bytes(ct[i]^block(ct[i-BS:i])[0] for i in range(BS,len(ct)))
  if any(value not in RELAXED for value in suffix):
   relaxed_reject+=1
  elif not strict_ok(suffix):
   strict_reject+=1
  else:
   solutions.append({"mapping":mapping,"plaintext_suffix_hex":suffix.hex()})
 assert relaxed_reject+strict_reject+len(solutions)==math.factorial(4)
 return {
  "enumerated_mappings":math.factorial(4),
  "relaxed_rejected_complete_mappings":relaxed_reject,
  "strict_fsa_rejected_complete_mappings":strict_reject,
  "terminal_complete_mappings":len(solutions),
  "solutions":canonical_solutions(solutions),
 }
def native_call(binary,*args,check=True):
 return subprocess.run([str(binary),*map(str,args)],text=True,capture_output=True,check=check,timeout=120)
def native_search(binary,backend,display,mapping,cap):
 result=native_call(binary,backend,cap,display,seed_spec(mapping),HEX)
 return json.loads(result.stdout)
def make_plaintext():
 phrase="ALPHA – BETA — GAMMA ‘DELTA’ … CFB8 CONTROL. ".encode("utf-8")
 tail=b" EXACT END.\n"
 available=546-len(tail); repeats=available//len(phrase)
 body=phrase*repeats+b"X"*(available-repeats*len(phrase))
 value=body+tail
 assert len(value)==546 and strict_ok(value) and all(x in RELAXED for x in value)
 for seq in (b"\xe2\x80\x93",b"\xe2\x80\x94",b"\xe2\x80\x98",b"\xe2\x80\x99",b"\xe2\x80\xa6"):assert seq in value
 return value
def produce():
 verify_deps()
 spec=importlib.util.spec_from_file_location("column_a_compat_build",BUILD_COMPAT)
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 rng=random.Random(0xBF20260910);mapping=list(range(16));rng.shuffle(mapping)
 seed={i:mapping[i] for i in range(12)}
 plaintext=make_plaintext()
 ivs=(bytes.fromhex("0011223344556677"),bytes.fromhex("fedcba9876543210"))
 with tempfile.TemporaryDirectory(prefix="bf-solver-controls-") as td:
  temporary=Path(td);native_binary=temporary/"native"
  flags=shlex.split(subprocess.check_output(["pkg-config","--cflags","--libs","openssl"],text=True).strip())
  native_command=["clang++","-std=c++17","-O3","-Wno-deprecated-declarations",str(NATIVE),*flags,"-o",str(native_binary)]
  subprocess.run(native_command,check=True,capture_output=True,timeout=60)
  compat_library=temporary/"libblowfish_compat.so";module.build(compat_library);compat_actual=module.load(compat_library)
  py_ecb=Blowfish.new(KEY,Blowfish.MODE_ECB)
  std_block=py_ecb.encrypt
  compat_conjugation=lambda block:word_reverse(py_ecb.encrypt(word_reverse(block)))
  compat_c=lambda block:compat_actual(KEY,block)
  vector_rng=random.Random(0xC0A7B10F)
  blocks=[bytes(range(8)),bytes.fromhex("a1b2c3d4e5f60718")]+[bytes(vector_rng.randrange(256) for _ in range(8)) for _ in range(30)]
  block_vectors=[]
  for backend,reference,secondary in (("blowfish",std_block,None),("blowfish_compat",compat_c,compat_conjugation)):
   for index,block in enumerate(blocks):
    expected=reference(block)
    if secondary is not None:assert expected==secondary(block)
    actual=bytes.fromhex(native_call(native_binary,backend,"--block",block.hex()).stdout.strip())
    assert actual==expected
    block_vectors.append({"cipher":backend,"index":index,"input_hex":block.hex(),"output_hex":actual.hex(),"native_reference_equal":True,"compat_c_conjugation_equal":secondary is not None})
  cfb_rows=[];search_rows=[];cap_rows=[]
  references={"blowfish":std_block,"blowfish_compat":compat_c}
  for backend,reference in references.items():
   for iv_index,iv in enumerate(ivs):
    ciphertext=cfb_encrypt(plaintext,iv,reference)
    if backend=="blowfish":
     assert ciphertext==Blowfish.new(KEY,Blowfish.MODE_CFB,iv=iv,segment_size=8).encrypt(plaintext)
     assert Blowfish.new(KEY,Blowfish.MODE_CFB,iv=iv,segment_size=8).decrypt(ciphertext)==plaintext
     independent="PyCryptodome MODE_CFB segment_size=8"
    else:
     assert ciphertext==cfb_encrypt(plaintext,iv,compat_conjugation)
     assert cfb_decrypt(ciphertext,iv,compat_c)==plaintext
     independent="temporary historical C and PyCryptodome word-conjugation recurrences"
    native_ct=bytes.fromhex(native_call(native_binary,backend,"--cfb-encrypt",iv.hex(),plaintext.hex()).stdout.strip())
    assert native_ct==ciphertext and cfb_decrypt(native_ct,iv,reference)==plaintext
    cfb_rows.append({"cipher":backend,"iv_index":iv_index,"iv_hex":iv.hex(),"length":len(plaintext),"plaintext_sha256":hashlib.sha256(plaintext).hexdigest(),"ciphertext_sha256":hashlib.sha256(ciphertext).hexdigest(),"native_encrypt_equal":True,"independent_reference":independent,"roundtrip":True})
    display=encode_display(ciphertext,mapping);assert len(display)==1092 and set(display)==set(HEX)
    oracle=naive(display,reference,seed);actual=native_search(native_binary,backend,display,mapping,100000)
    actual_solutions=canonical_solutions(actual["solutions"])
    assert actual_solutions==oracle["solutions"]
    assert actual["expected_completion_weight"]==24
    assert actual["certificate_complete"] and actual["certificate_weight"]==24 and actual["unaccounted_mapping_weight"]==0
    assert actual["stats"]["rejected_completion_weight"]==oracle["relaxed_rejected_complete_mappings"]+oracle["strict_fsa_rejected_complete_mappings"]
    assert actual["stats"]["terminal_completion_weight"]==oracle["terminal_complete_mappings"]
    assert any(row["mapping"]==mapping and bytes.fromhex(row["plaintext_suffix_hex"])==plaintext[8:] for row in actual_solutions)
    search_rows.append({"case":"planted","cipher":backend,"iv_index":iv_index,"display_sha256":hashlib.sha256(display.encode()).hexdigest(),"display_length":len(display),"all_16_display_symbols_present":True,"seed_mapping":seed,"native":{k:actual[k] for k in ("node_limit","seeded_entries","expected_completion_weight","certificate_weight","certificate_complete","unaccounted_mapping_weight","geometry","stats","ecb_calls")},"oracle":oracle,"native_oracle_exact_solutions":True,"planted_mapping_recovered":True})
    if iv_index==0:
     capped=native_search(native_binary,backend,display,mapping,1)
     assert capped["stats"]["nodes"]==1 and capped["stats"]["aborted_at_node_limit"]
     assert not capped["certificate_complete"] and capped["certificate_weight"]+capped["unaccounted_mapping_weight"]==24
     cap_rows.append({"cipher":backend,"node_limit":1,"nodes":1,"aborted":True,"certificate_weight":capped["certificate_weight"],"unaccounted_mapping_weight":capped["unaccounted_mapping_weight"],"partition_total":24})
   random_ct=bytes(rng.randrange(256) for _ in range(546));random_display=encode_display(random_ct,mapping);assert set(random_display)==set(HEX)
   random_oracle=naive(random_display,reference,seed);random_actual=native_search(native_binary,backend,random_display,mapping,100000)
   assert canonical_solutions(random_actual["solutions"])==random_oracle["solutions"]==[]
   assert random_actual["certificate_complete"] and random_actual["certificate_weight"]==24 and random_actual["stats"]["terminal_completion_weight"]==0
   search_rows.append({"case":"deterministic_random_ciphertext_reject","cipher":backend,"display_sha256":hashlib.sha256(random_display.encode()).hexdigest(),"display_length":len(random_display),"all_16_display_symbols_present":True,"seed_mapping":seed,"native":{k:random_actual[k] for k in ("node_limit","seeded_entries","expected_completion_weight","certificate_weight","certificate_complete","unaccounted_mapping_weight","geometry","stats","ecb_calls")},"oracle":random_oracle,"native_oracle_exact_solutions":True})
   inverse=[None]*16
   for d,a in enumerate(mapping):inverse[a]=d
   reject_byte=next(value for value in range(256) if inverse[value>>4]<12 and inverse[value&15]<12 and (value^reference(bytes([value])*8)[0]) not in RELAXED)
   reject_ct=bytes([reject_byte])*546;reject_display=encode_display(reject_ct,mapping)
   reject_oracle=naive(reject_display,reference,seed);reject_actual=native_search(native_binary,backend,reject_display,mapping,100000)
   assert reject_oracle["solutions"]==[] and reject_oracle["relaxed_rejected_complete_mappings"]==24
   assert reject_actual["certificate_complete"] and reject_actual["stats"]["nodes"]==0 and reject_actual["stats"]["rejected_completion_weight"]==24
   assert canonical_solutions(reject_actual["solutions"])==reject_oracle["solutions"]
   search_rows.append({"case":"constructed_prebound_reject","cipher":backend,"repeated_ciphertext_byte":reject_byte,"display_sha256":hashlib.sha256(reject_display.encode()).hexdigest(),"display_length":len(reject_display),"seed_mapping":seed,"native":{k:reject_actual[k] for k in ("node_limit","seeded_entries","expected_completion_weight","certificate_weight","certificate_complete","unaccounted_mapping_weight","geometry","stats","ecb_calls")},"oracle":reject_oracle,"native_oracle_exact_solutions":True})
  invalid=[]
  for args in (("bad",1,"00"*9),("blowfish",0,"00"*9),("blowfish",1,"00"*8),("blowfish",1,"0")):
   row=native_call(native_binary,*args,check=False);assert row.returncode!=0 and row.stderr.strip()
   invalid.append({"arguments":list(map(str,args)),"returncode":row.returncode,"stderr":row.stderr.strip()})
  out={
   "identity":"ASTRA","target_evaluated":False,"rev7_read":False,
   "scope":"Synthetic-only exact 4! controls for the native standard and historical-compatibility Blowfish global displayed-hex CFB8 suffix solver; raw seven-byte Zombies key, two arbitrary IVs, 546-byte controls, A105 relaxed pruning and strict five-sequence terminal FSA.",
   "model_limits":["Only standard Blowfish and the pinned historical word-conjugated compatibility primitive.","The first eight plaintext bytes are omitted; suffix validation starts in any UTF-8 state and must terminate in state 0.","Twelve displayed-symbol mappings are seeded, leaving an exhaustive 4! control space; this is a control, not target coverage."],
   "mapping":{"meaning":"mapping[displayed_hex_symbol] = actual ciphertext nibble","planted":mapping,"seeded_symbols":list(range(12)),"seeded_mapping":seed},
   "block_vectors":block_vectors,"block_vector_count":len(block_vectors),
   "two_iv_cfb8_vectors":cfb_rows,"cfb8_vector_count":len(cfb_rows),
   "native_vs_naive_searches":search_rows,"search_count":len(search_rows),
   "cap_controls":cap_rows,"invalid_cli_controls":invalid,
   "source_hashes":{**verify_deps(),"controls.py":sha(Path(__file__))},
   "build_provenance":{"native_command":["clang++","-std=c++17","-O3","-Wno-deprecated-declarations","native.cpp",*flags,"-o","<temporary>/native"],"native_binary_sha256_machine_evidence":sha(native_binary),"compat_command":["clang","-shared","-fPIC","-O2","-I","compat_source","compat_source/blowfish-compat.c","-o","<temporary>/libblowfish_compat.so"],"compat_binary_sha256_machine_evidence":sha(compat_library),"compiler":subprocess.check_output(["clang++","--version"],text=True).splitlines()[0],"openssl":subprocess.check_output(["pkg-config","--modversion","openssl"],text=True).strip(),"python":platform.python_version(),"pycryptodome":Crypto.__version__},
   "assertions":{"all_passed":True,"all_64_native_blocks_match":len(block_vectors)==64,"compat_actual_c_conjugation_match":True,"all_four_two_iv_cfb_vectors_match":len(cfb_rows)==4,"all_eight_native_naive_searches_exact":len(search_rows)==8,"all_four_plants_recovered":sum(row["case"]=="planted" and row["planted_mapping_recovered"] for row in search_rows)==4,"both_random_cases_reject":sum(row["case"]=="deterministic_random_ciphertext_reject" and row["oracle"]["terminal_complete_mappings"]==0 for row in search_rows)==2,"both_prebound_cases_reject":sum(row["case"]=="constructed_prebound_reject" and row["native"]["stats"]["nodes"]==0 for row in search_rows)==2,"both_cap_partitions_exact":len(cap_rows)==2,"no_target_read_or_evaluation":True}
  }
 return out
def verify():
 verify_deps()
 data=json.loads(LEDGER.read_text())
 assert data["identity"]=="ASTRA" and data["target_evaluated"] is False and data["rev7_read"] is False
 assert data["source_hashes"]["controls.py"]==sha(Path(__file__))
 assert {k:data["source_hashes"][k] for k in EXPECTED}==EXPECTED
 assert data["block_vector_count"]==64 and data["cfb8_vector_count"]==4 and data["search_count"]==8
 assert len(data["cap_controls"])==2 and all(data["assertions"].values())
 assert sum(row["case"]=="planted" for row in data["native_vs_naive_searches"])==4
 assert sum(row["case"]=="deterministic_random_ciphertext_reject" for row in data["native_vs_naive_searches"])==2
 assert sum(row["case"]=="constructed_prebound_reject" for row in data["native_vs_naive_searches"])==2
 print(json.dumps({"identity":"ASTRA","verified":True,"read_only":True,"compiled_binary_required":False,"ledger_sha256":sha(LEDGER)},indent=2))
def main():
 parser=argparse.ArgumentParser();parser.add_argument("--regenerate",type=Path);args=parser.parse_args()
 if args.regenerate is None:verify();return
 if args.regenerate.exists():raise SystemExit("refusing existing output: "+str(args.regenerate))
 result=produce();args.regenerate.parent.mkdir(parents=True,exist_ok=True);args.regenerate.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
 print(json.dumps({"identity":"ASTRA","target_evaluated":False,"output":str(args.regenerate),"sha256":sha(args.regenerate)},indent=2))
if __name__=="__main__":main()
