#!/usr/bin/env python3
"""Frozen-gate draft driver for all-IV Blowfish CFB8 global-hex searches."""
from __future__ import annotations
import argparse,hashlib,json,math,os,subprocess
from pathlib import Path
from Crypto.Cipher import Blowfish

HERE=Path(__file__).resolve().parent;PACKAGE=HERE.parent;ROOT=HERE.parents[4]
NATIVE=PACKAGE/"native";GATE=HERE/"target_gate.json";MDX=ROOT/"lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
IDENTITY="ASTRA";KEY=b"Zombies";BS=8;LIMIT=1_000_000_000;FULL=math.factorial(16);TEXT_SHA="5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c";MDX_SHA="085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91"
BACKENDS=("blowfish","blowfish_compat");ORIENTATIONS=("forward","full_hex_reverse","byte_reverse","nibble_swap");HEX="0123456789ABCDEF";THIRDS={0x93,0x94,0x98,0x99,0xA6}
ARTIFACTS=(
 "research/rev7-20260909-codex/iv_independent/blowfish_solver/REPORT.md",
 "research/rev7-20260909-codex/iv_independent/blowfish_solver/controls.py",
 "research/rev7-20260909-codex/iv_independent/blowfish_solver/controls.json",
 "research/rev7-20260909-codex/iv_independent/blowfish_solver/native.cpp",
 "research/rev7-20260909-codex/iv_independent/blowfish_solver/native",
 "research/rev7-20260909-codex/iv_independent/blowfish_solver/native_build.json",
 "research/rev7-20260909-codex/iv_independent/blowfish_solver/target/benchmark.py",
 "research/rev7-20260909-codex/iv_independent/blowfish_solver/target/benchmark.json",
 "research/rev7-20260909-codex/iv_independent/blowfish_solver/target/README.md",
 "research/byte_columnar/all_iv/column_a/compat_source/build_compat.py",
 "research/byte_columnar/all_iv/column_a/compat_source/blowfish-compat.c",
 "research/byte_columnar/all_iv/column_a/compat_source/blowfish.h",
 "research/byte_columnar/all_iv/column_a/compat_source/libdefs.h",
 "research/byte_columnar/all_iv/column_a/compat_source/mcrypt_modules.h",
 "research/byte_columnar/all_iv/column_a/compat_source/COPYING.LIB",
 "research/byte_columnar/all_iv/column_a/compat_source/PROVENANCE.md",
)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def scope():
 return {"identity":IDENTITY,"ciphers":list(BACKENDS),"key_hex":KEY.hex(),"mode":"CFB8","external_iv":"arbitrary eight bytes; not recovered or searched","constraint":"for i>=8, P_i=C_i XOR E_key(C[i-8:i])[0]","compatibility_primitive":"word_reverse(BF(word_reverse(block))) using reversal inside each 32-bit word","unknown_representation":"global bijection of 16 displayed hex symbols to nibbles","relaxed_window_bytes":{"count":105,"ascii":"TAB LF CR and 32..126","additional_hex":["80","93","94","98","99","a6","e2"]},"strict_suffix":{"initial_state_set":[0,1,2],"terminal_state":0,"utf8":["e28093","e28094","e28098","e28099","e280a6"]},"orientations":list(ORIENTATIONS),"cells":8,"node_limit_per_cell":LIMIT,"order":"default frozen greedy geometry order; no explicit override","search_semantics":"fresh root per cell; caps are not additive","certificate":"16! mapping weight only when native reports complete; capped cells retain uncovered weight","survivors":"retain exact mapping and suffix bytes; independently reconstruct, validate and re-encrypt under two arbitrary IVs"}
def require_gate():
 gate=json.loads(GATE.read_text());assert gate["identity"]==IDENTITY and gate["target_evaluated"] is False and gate["authorization"]=="FABLE preregistered; root GO required"
 assert gate["scope"]==scope() and gate["driver_sha256"]==sha(Path(__file__)) and set(gate["artifact_hashes"])==set(ARTIFACTS)
 for rel,expected in gate["artifact_hashes"].items():assert sha(ROOT/rel)==expected,rel
 assert sha(MDX)==MDX_SHA and gate["mdx_sha256"]==MDX_SHA and gate["canonical_text_sha256"]==TEXT_SHA
 controls=json.loads((PACKAGE/"controls.json").read_text());benchmark=json.loads((HERE/"benchmark.json").read_text());build=json.loads((PACKAGE/"native_build.json").read_text())
 assert controls["identity"]==benchmark["identity"]==build["identity"]==IDENTITY
 assert controls["target_evaluated"] is benchmark["target_evaluated"] is build["target_evaluated"] is False
 assert controls["rev7_read"] is benchmark["rev7_read"] is False and all(controls["assertions"].values()) and all(benchmark["assertions"].values())
 assert build["source_sha256"]==sha(PACKAGE/"native.cpp") and build["binary_sha256"]==sha(NATIVE)
 return gate,sha(GATE)
def extract():
 text=MDX.read_text();start=text.index("`83 B57B2")+1;end=text.index("`",start);canonical="".join(text[start:end].split()).upper()
 assert len(canonical)==1092 and hashlib.sha256(canonical.encode()).hexdigest()==TEXT_SHA
 pairs=[canonical[i:i+2] for i in range(0,len(canonical),2)]
 return canonical,dict(zip(ORIENTATIONS,(canonical,canonical[::-1],"".join(reversed(pairs)),"".join(pair[::-1] for pair in pairs))))
def geometry(display):
 pairs=[(int(display[i],16),int(display[i+1],16)) for i in range(0,len(display),2)]
 windows=[set(x for pair in pairs[i-8:i+1] for x in pair) for i in range(8,len(pairs))]
 freq=[0]*16
 for a,b in pairs:freq[a]+=1;freq[b]+=1
 best=min(range(len(windows)),key=lambda i:(len(windows[i]),-sum(w<=windows[i] for w in windows),i));anchor=windows[best]
 order=sorted(anchor,key=lambda s:(-freq[s],s));selected=set(order);bound=sum(w<=selected for w in windows);counts=[bound]
 while len(order)<16:
  choices=[]
  for symbol in set(range(16))-selected:
   after=selected|{symbol};new=sum(w<=after for w in windows)-bound;contained=sum(symbol in w for w in windows);choices.append((new,contained,-symbol,symbol))
  _,_,_,symbol=max(choices);order.append(symbol);selected.add(symbol);bound=sum(w<=selected for w in windows);counts.append(bound)
 return {"anchor_window_suffix_index":best+8,"anchor_unique_symbols":len(anchor),"symbol_order":order,"fully_bound_window_counts":counts}
def block(backend):
 ecb=Blowfish.new(KEY,Blowfish.MODE_ECB)
 if backend=="blowfish":return ecb.encrypt
 def reverse_words(value):return value[3::-1]+value[7:3:-1]
 return lambda value:reverse_words(ecb.encrypt(reverse_words(value)))
def decode(display,mapping):return bytes((mapping[int(display[i],16)]<<4)|mapping[int(display[i+1],16)] for i in range(0,len(display),2))
def encode(ciphertext,mapping):
 inverse=[0]*16
 for shown,actual in enumerate(mapping):inverse[actual]=shown
 return "".join(HEX[inverse[x>>4]]+HEX[inverse[x&15]] for x in ciphertext)
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
def decrypt_cfb(ciphertext,iv,encrypt_block):
 reg=iv;out=bytearray()
 for value in ciphertext:out.append(value^encrypt_block(reg)[0]);reg=reg[1:]+bytes([value])
 return bytes(out)
def encrypt_cfb(plaintext,iv,encrypt_block):
 reg=iv;out=bytearray()
 for value in plaintext:
  ciphertext=value^encrypt_block(reg)[0];out.append(ciphertext);reg=reg[1:]+bytes([ciphertext])
 return bytes(out)
def validate_solutions(backend,display,solutions):
 encrypt_block=block(backend);seen=set();out=[];ivs=(bytes.fromhex("0001020304050607"),b"0"*8)
 for row in solutions:
  mapping=tuple(row["mapping"]);suffix=bytes.fromhex(row["plaintext_suffix_hex"])
  assert len(mapping)==16 and sorted(mapping)==list(range(16)) and mapping not in seen;seen.add(mapping)
  ciphertext=decode(display,mapping);expected=bytes(ciphertext[i]^encrypt_block(ciphertext[i-8:i])[0] for i in range(8,len(ciphertext)))
  assert len(ciphertext)==546 and suffix==expected and strict_ok(suffix) and encode(ciphertext,mapping)==display
  checks=[]
  for iv in ivs:
   if backend=="blowfish":
    plaintext=Blowfish.new(KEY,Blowfish.MODE_CFB,iv=iv,segment_size=8).decrypt(ciphertext)
    recipher=Blowfish.new(KEY,Blowfish.MODE_CFB,iv=iv,segment_size=8).encrypt(plaintext)
    reference="PyCryptodome MODE_CFB segment_size=8"
   else:
    plaintext=decrypt_cfb(ciphertext,iv,encrypt_block);recipher=encrypt_cfb(plaintext,iv,encrypt_block);reference="independent PyCryptodome word-conjugation recurrence"
   assert plaintext[8:]==suffix and recipher==ciphertext
   checks.append({"iv_hex":iv.hex(),"first_block_hex":plaintext[:8].hex(),"full_decryption_sha256":hashlib.sha256(plaintext).hexdigest(),"suffix_equals_native":True,"full_reencryption_exact":True,"reference":reference})
  out.append({"mapping_display_to_nibble":list(mapping),"ciphertext_sha256":hashlib.sha256(ciphertext).hexdigest(),"plaintext_suffix_hex":suffix.hex(),"plaintext_suffix_sha256":hashlib.sha256(suffix).hexdigest(),"suffix_length":len(suffix),"strict_suffix_terminal_state":0,"display_reconstruction_exact":True,"two_arbitrary_iv_checks":checks,"note":"Only bytes i>=8 are IV-independent; the first block is not recovered."})
 return out
def native(backend,display):
 result=json.loads(subprocess.check_output([str(NATIVE),backend,str(LIMIT),display,"-"],text=True))
 assert result["identity"]==IDENTITY and result["cipher"]==backend and result["node_limit"]==LIMIT and result["seeded_entries"]==0 and result["expected_completion_weight"]==FULL
 stats=result["stats"];cert=result["certificate_weight"]
 assert cert==stats["rejected_completion_weight"]+stats["terminal_completion_weight"] and result["unaccounted_mapping_weight"]==FULL-cert
 assert len(result["solutions"])==stats["terminal_completion_weight"] and result["geometry"]["explicit_order_override"] is False
 assert 0<stats["nodes"]<=LIMIT
 complete=not stats["aborted_at_node_limit"]
 assert result["certificate_complete"] is (complete and cert==FULL)
 if complete:assert cert==FULL
 else:assert stats["nodes"]==LIMIT and cert<FULL
 return result
def atomic(path,value):
 temporary=path.with_name(path.name+".tmp")
 if temporary.exists():raise RuntimeError("refusing stale temporary "+str(temporary))
 with temporary.open("x") as handle:json.dump(value,handle,indent=2,sort_keys=True);handle.write("\n")
 os.replace(temporary,path)
def initial(gate_sha,text_sha,artifacts):
 return {"identity":IDENTITY,"target_evaluated":True,"status":"running","configuration":{**scope(),"ciphertext_sha256":text_sha,"gate_sha256":gate_sha,"driver_sha256":sha(Path(__file__)),"artifact_hashes":artifacts},"cells":[]}
def run(output,checkpoint,resume):
 if output.exists():raise SystemExit("refusing existing output: "+str(output))
 gate,gate_sha=require_gate();canonical,oriented=extract();config=initial(gate_sha,hashlib.sha256(canonical.encode()).hexdigest(),gate["artifact_hashes"])["configuration"]
 if checkpoint.exists():
  if not resume:raise SystemExit("refusing checkpoint without --resume: "+str(checkpoint))
  result=json.loads(checkpoint.read_text());assert result["configuration"]==config and result["identity"]==IDENTITY and result["target_evaluated"] is True and result["status"]=="running"
 else:
  if resume:raise SystemExit("--resume requested without checkpoint")
  result=initial(gate_sha,config["ciphertext_sha256"],gate["artifact_hashes"])
 expected={(backend,orientation) for backend in BACKENDS for orientation in ORIENTATIONS};done={(row["cipher"],row["orientation"]) for row in result["cells"]}
 assert len(done)==len(result["cells"]) and done<=expected
 for backend in BACKENDS:
  for orientation in ORIENTATIONS:
   if (backend,orientation) in done:continue
   display=oriented[orientation];result_native=native(backend,display);expected_geometry=geometry(display)
   for key,value in expected_geometry.items():assert result_native["geometry"][key]==value,(backend,orientation,key)
   survivors=validate_solutions(backend,display,result_native["solutions"]);stats=result_native["stats"];cert=result_native["certificate_weight"];complete=result_native["certificate_complete"]
   cell={"identity":IDENTITY,"cipher":backend,"orientation":orientation,"display_sha256":hashlib.sha256(display.encode()).hexdigest(),"native_geometry":result_native["geometry"],"independent_geometry_exact":True,"stats":{**stats,"node_limit":LIMIT,"ecb_calls":result_native["ecb_calls"],"elapsed_seconds":result_native["elapsed_seconds"],"certificate_weight":cert,"expected_factorial_weight":FULL,"certificate_complete":complete,"search_status":"complete" if complete else "capped","unaccounted_mapping_weight":FULL-cert,"capped_interpretation":None if complete else "partial eliminated/accepted mapping weight only; reported remainder remains uncovered"},"survivor_count":len(survivors),"survivors":survivors,"all_survivors_independently_validated":True}
   result["cells"].append(cell);atomic(checkpoint,result)
   print(json.dumps({"identity":IDENTITY,"completed_cells":len(result["cells"]),"cipher":backend,"orientation":orientation,"status":cell["stats"]["search_status"],"nodes":stats["nodes"],"certificate_weight":cert,"unaccounted_mapping_weight":FULL-cert,"survivors":len(survivors),"seconds":result_native["elapsed_seconds"]}),flush=True)
 assert {(row["cipher"],row["orientation"]) for row in result["cells"]}==expected
 result["status"]="complete";result["summary"]={"cells":8,"complete_cells":sum(row["stats"]["certificate_complete"] for row in result["cells"]),"capped_cells":sum(not row["stats"]["certificate_complete"] for row in result["cells"]),"survivors":sum(row["survivor_count"] for row in result["cells"]),"total_nodes":sum(row["stats"]["nodes"] for row in result["cells"]),"total_ecb_calls":sum(row["stats"]["ecb_calls"] for row in result["cells"]),"total_native_elapsed_seconds":sum(row["stats"]["elapsed_seconds"] for row in result["cells"])}
 atomic(checkpoint,result);os.replace(checkpoint,output);print(json.dumps({"identity":IDENTITY,"output":str(output),"sha256":sha(output),"summary":result["summary"]},indent=2))
def main():
 parser=argparse.ArgumentParser();mode=parser.add_mutually_exclusive_group(required=True);mode.add_argument("--selftest",action="store_true");mode.add_argument("--run-target",action="store_true");parser.add_argument("--target-output",type=Path,default=HERE/"target_results.json");parser.add_argument("--checkpoint",type=Path,default=HERE/"target_checkpoint.json");parser.add_argument("--resume",action="store_true");args=parser.parse_args()
 if args.selftest:
  if args.resume:parser.error("--resume is target-only")
  _gate,gate_sha=require_gate();print(json.dumps({"identity":IDENTITY,"target_evaluated":False,"rev7_handling":"MDX bytes hashed only; ciphertext not extracted, parsed, oriented, or evaluated","driver_sha256":sha(Path(__file__)),"gate_sha256":gate_sha,"scope":scope()},indent=2,sort_keys=True))
 else:run(args.target_output,args.checkpoint,args.resume)
if __name__=="__main__":main()
