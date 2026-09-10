#!/usr/bin/env python3
"""Synthetic proof controls for IV forgetting through direct-binary CFB8 cascades."""
from __future__ import annotations
import argparse,hashlib,json,platform
from pathlib import Path

HERE=Path(__file__).resolve().parent;LEDGER=HERE/"controls.json"
SPECS={
 "aes128":{"module":"AES","key":b"Zombies"+b"\0"*9,"block_size":16,"effective_keylen":None},
 "des":{"module":"DES","key":b"Zombies\0","block_size":8,"effective_keylen":None},
 "blowfish":{"module":"Blowfish","key":b"Zombies","block_size":8,"effective_keylen":None},
 "arc2":{"module":"ARC2","key":b"Zombies","block_size":8,"effective_keylen":1024},
}
CHAINS=(
 ("aes128","des"),
 ("blowfish","aes128"),
 ("arc2","des"),
 ("aes128","blowfish","arc2"),
 ("des","aes128","blowfish"),
)
THIRDS={0x93,0x94,0x98,0x99,0xA6}
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def crypto_modules():
 from Crypto.Cipher import AES,ARC2,Blowfish,DES
 return {"AES":AES,"ARC2":ARC2,"Blowfish":Blowfish,"DES":DES}
def new_cipher(name,mode_name,iv=None):
 spec=SPECS[name];module=crypto_modules()[spec["module"]];mode=getattr(module,mode_name);kwargs={}
 if iv is not None:kwargs["iv"]=iv
 if mode_name=="MODE_CFB":kwargs["segment_size"]=8
 if name=="arc2":kwargs["effective_keylen"]=spec["effective_keylen"]
 return module.new(spec["key"],mode,**kwargs)
def mode_encrypt(name,plaintext,iv):return new_cipher(name,"MODE_CFB",iv).encrypt(plaintext)
def mode_decrypt(name,ciphertext,iv):return new_cipher(name,"MODE_CFB",iv).decrypt(ciphertext)
def ecb_block(name,block):return new_cipher(name,"MODE_ECB").encrypt(block)
def iv_free_layer(ciphertext,name):
 block_size=SPECS[name]["block_size"]
 return bytes(ciphertext[i]^ecb_block(name,ciphertext[i-block_size:i])[0] for i in range(block_size,len(ciphertext)))
def iv_free_cascade(ciphertext,decryption_layers):
 known=ciphertext
 for name in decryption_layers:known=iv_free_layer(known,name)
 return known
def encrypt_chain(plaintext,decryption_layers,ivs):
 value=plaintext
 for name,iv in reversed(tuple(zip(decryption_layers,ivs))):value=mode_encrypt(name,value,iv)
 return value
def decrypt_chain(ciphertext,decryption_layers,ivs):
 value=ciphertext
 for name,iv in zip(decryption_layers,ivs):value=mode_decrypt(name,value,iv)
 return value
def iv_suite(decryption_layers,suite):
 return tuple(bytes(((suite*83+layer*37+i*19)&255) for i in range(SPECS[name]["block_size"])) for layer,name in enumerate(decryption_layers))
def fsa(data,initial=(0,)):
 states=set(initial)
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
def vector(label,layers,plaintext):
 boundary=sum(SPECS[name]["block_size"] for name in layers);derived=[];rows=[]
 for suite in (1,2):
  ivs=iv_suite(layers,suite);ciphertext=encrypt_chain(plaintext,layers,ivs);library=decrypt_chain(ciphertext,layers,ivs);known=iv_free_cascade(ciphertext,layers)
  assert library==plaintext and known==plaintext[boundary:]
  derived.append(known)
  rows.append({"iv_suite":suite,"ivs_hex":[x.hex() for x in ivs],"ciphertext_sha256":hashlib.sha256(ciphertext).hexdigest(),"library_roundtrip":True,"iv_free_suffix_sha256":hashlib.sha256(known).hexdigest(),"iv_free_suffix_length":len(known),"suffix_equals_plaintext_from_sum_block_sizes":True})
 assert derived[0]==derived[1]
 return {"label":label,"decryption_layers":list(layers),"block_sizes":[SPECS[name]["block_size"] for name in layers],"boundary":boundary,"plaintext_length":len(plaintext),"plaintext_sha256":hashlib.sha256(plaintext).hexdigest(),"two_iv_suites":rows,"derived_suffix_identical_across_iv_suites":True}
def strict_text(boundary):
 all_five="EN – EM — LEFT ‘ RIGHT ’ ELLIPSIS … ".encode("utf-8");tail=b"STRICT END.\n"
 prefix=b"A"*(boundary+3);body=all_five*3
 value=prefix+body+tail
 assert fsa(value,(0,)) and fsa(value[boundary:],(0,1,2))
 return value
def partial(boundary,state):
 sequence=bytes.fromhex("e280a6");start=boundary-state
 value=b"A"*start+sequence+b" VALID UTF8 BOUNDARY END.\n"
 assert fsa(value,(0,)) and fsa(value[boundary:],(0,1,2))
 return value
def produce():
 import Crypto
 rows=[]
 for layers in CHAINS:
  boundary=sum(SPECS[name]["block_size"] for name in layers)
  for length,label in ((boundary-1,"below"),(boundary,"at"),(boundary+1,"above_one"),(boundary+17,"above_seventeen")):
   rows.append(vector("boundary_"+label,layers,bytes((i*73+length)&255 for i in range(length))))
  rows.append(vector("all_256_byte_values",layers,bytes(range(256))))
  text=strict_text(boundary);row=vector("strict_text_all_five_utf8",layers,text);assert fsa(text[boundary:],(0,1,2));row["strict_suffix_fsa"]=True;rows.append(row)
  for state in (1,2):
   value=partial(boundary,state);row=vector("utf8_partial_boundary_state_"+str(state),layers,value);assert fsa(value[boundary:],(0,1,2));row["strict_suffix_fsa"]=True;row["suffix_begins_hex"]=value[boundary:boundary+3].hex();rows.append(row)
 assert len(rows)==len(CHAINS)*8
 for row in rows:
  boundary=row["boundary"];length=row["plaintext_length"];expected=max(0,length-boundary)
  assert all(x["iv_free_suffix_length"]==expected for x in row["two_iv_suites"])
 sources={"nist_sp800_38a_section_6_3":"https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf"}
 return {"identity":"ASTRA","target_evaluated":False,"rev7_read":False,
  "theorem":{"statement":"For direct same-length binary CFB8 decryption layers in outer-to-inner decryption order with block sizes b_j, the final plaintext suffix beginning at sum(b_j) is determined by the outer ciphertext and fixed keys without any IV.","one_layer":"For i>=b, P[i]=C[i] XOR E_key(C[i-b:i])[0], because the CFB8 register then consists entirely of the preceding b ciphertext bytes.","induction":"After earlier layers expose their output from offset B, layer j needs only input positions i-b_j through i at output positions i>=B+b_j. Applying the one-layer recurrence to the known suffix exposes the next output from B+b_j.","unknown_prefix":"No bytes before sum(b_j) are recovered by this theorem."},
  "cipher_specs":{name:{"block_size":spec["block_size"],"key_hex":spec["key"].hex(),"arc2_effective_keylen":spec["effective_keylen"]} for name,spec in SPECS.items()},
  "chains":[list(x) for x in CHAINS],"vectors":rows,"vector_count":len(rows),"mode_comparisons":len(rows)*2,
  "coverage_note":"Local prior artifacts contain completed one-layer IV-independent and raw-IV-prefix proofs, but no completed direct-binary two/three-layer CFB8 cascade proof or synthetic ledger was found. This statement is limited to the retained local record.",
  "sources":sources,
  "limits":["Direct binary layers with unchanged byte length and alignment only.","Fixed known keys and ordinary CFB8 at every layer.","No interposed hex/Base64/numeric encoding, reversal, transposition, padding insertion/removal, truncation, or framing between layers.","No intermediate layer is required to be printable; only the final known suffix may be tested by an endpoint.","The unknown prefix of length sum(block sizes) is not recovered.","Compatibility ciphers outside PyCryptodome's standard AES/DES/Blowfish/ARC2 primitives are not controlled here."],
  "source_hashes":{"proof.py":sha(Path(__file__))},
  "runtime":{"python":platform.python_version(),"pycryptodome":Crypto.__version__},
  "assertions":{"all_passed":True,"five_mixed_chains":len(CHAINS)==5,"two_and_three_layer_chains":{len(x) for x in CHAINS}=={2,3},"all_four_primitives_used":set(x for chain in CHAINS for x in chain)==set(SPECS),"all_256_values_per_chain":sum(x["label"]=="all_256_byte_values" for x in rows)==5,"below_at_above_boundaries_per_chain":sum(x["label"].startswith("boundary_") for x in rows)==20,"two_iv_suites_every_vector":all(len(x["two_iv_suites"])==2 for x in rows),"mode_cfb_and_ecb_recurrence_agree":True,"utf8_initial_states_1_and_2_per_chain":sum(x["label"].startswith("utf8_partial") for x in rows)==10,"no_intermediate_printability_assumption":True,"no_target_read_or_evaluation":True}}
def verify():
 data=json.loads(LEDGER.read_text());assert data["identity"]=="ASTRA" and data["target_evaluated"] is False and data["rev7_read"] is False
 assert data["source_hashes"]["proof.py"]==sha(Path(__file__)) and data["vector_count"]==40 and data["mode_comparisons"]==80 and all(data["assertions"].values())
 assert len(data["chains"])==5 and all(len(row["two_iv_suites"])==2 and row["derived_suffix_identical_across_iv_suites"] for row in data["vectors"])
 print(json.dumps({"identity":"ASTRA","verified":True,"read_only":True,"ledger_sha256":sha(LEDGER),"vectors":40,"mode_comparisons":80},indent=2))
def main():
 parser=argparse.ArgumentParser();parser.add_argument("--regenerate",type=Path);args=parser.parse_args()
 if args.regenerate is None:verify();return
 if args.regenerate.exists():raise SystemExit("refusing existing output: "+str(args.regenerate))
 result=produce();args.regenerate.parent.mkdir(parents=True,exist_ok=True);args.regenerate.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n");print(json.dumps({"identity":"ASTRA","target_evaluated":False,"output":str(args.regenerate),"sha256":sha(args.regenerate)},indent=2))
if __name__=="__main__":main()
