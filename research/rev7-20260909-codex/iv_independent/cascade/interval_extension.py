#!/usr/bin/env python3
"""Synthetic controls for known intervals through CFB8 cascades and involutive transforms."""
from __future__ import annotations
import argparse,hashlib,json,platform
from pathlib import Path
HERE=Path(__file__).resolve().parent;LEDGER=HERE/"interval_extension.json"
DIRECT=HERE/"proof.py";DIRECT_LEDGER=HERE/"controls.json"
EXPECTED_DIRECT={"proof.py":"1152ff62572b5914c1840ddd4af14efdc1ff26c58051a566c62bfb2ed1a1f8c0","controls.json":"2b0b75c096da6e3333dfe3d7390cb1d8a458d551d895ab215401c32155408b87"}
SPECS={"aes128":{"module":"AES","key":b"Zombies"+b"\0"*9,"block_size":16,"effective_keylen":None},"des":{"module":"DES","key":b"Zombies\0","block_size":8,"effective_keylen":None},"blowfish":{"module":"Blowfish","key":b"Zombies","block_size":8,"effective_keylen":None},"arc2":{"module":"ARC2","key":b"Zombies","block_size":8,"effective_keylen":1024}}
TRANSFORMS=("forward","full_hex_reverse","byte_reverse","nibble_swap");THIRDS={0x93,0x94,0x98,0x99,0xA6}
RECIPES=tuple(
 [(("aes128","des"),(name,), "two_"+name) for name in TRANSFORMS]+
 [(("blowfish","aes128","arc2"),(first,second), "three_"+first+"_then_"+second) for first in TRANSFORMS for second in TRANSFORMS]
)
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def modules():
 from Crypto.Cipher import AES,ARC2,Blowfish,DES
 return {"AES":AES,"ARC2":ARC2,"Blowfish":Blowfish,"DES":DES}
def cipher(name,mode_name,iv=None):
 spec=SPECS[name];module=modules()[spec["module"]];kwargs={}
 if iv is not None:kwargs["iv"]=iv
 if mode_name=="MODE_CFB":kwargs["segment_size"]=8
 if name=="arc2":kwargs["effective_keylen"]=1024
 return module.new(spec["key"],getattr(module,mode_name),**kwargs)
def encrypt_layer(name,data,iv):return cipher(name,"MODE_CFB",iv).encrypt(data)
def decrypt_layer(name,data,iv):return cipher(name,"MODE_CFB",iv).decrypt(data)
def block(name,data):return cipher(name,"MODE_ECB").encrypt(data)
def swap(value):return ((value&15)<<4)|(value>>4)
def transform(data,name):
 if name=="forward":return data
 if name=="byte_reverse":return data[::-1]
 if name=="nibble_swap":return bytes(swap(x) for x in data)
 if name=="full_hex_reverse":return bytes(swap(x) for x in reversed(data))
 raise ValueError(name)
def transform_interval(left,right,data,total,name):
 if name=="forward":return left,right,data
 if name=="nibble_swap":return left,right,transform(data,name)
 if name in ("byte_reverse","full_hex_reverse"):return total-right,total-left,transform(data,name)
 raise ValueError(name)
def encrypt_chain(plaintext,layers,transforms,ivs):
 value=plaintext
 for index in range(len(layers)-1,-1,-1):
  value=encrypt_layer(layers[index],value,ivs[index])
  if index>0:value=transform(value,transforms[index-1])
 return value
def decrypt_chain(ciphertext,layers,transforms,ivs):
 value=ciphertext
 for index,name in enumerate(layers):
  value=decrypt_layer(name,value,ivs[index])
  if index<len(transforms):value=transform(value,transforms[index])
 return value
def known_interval(ciphertext,layers,transforms):
 total=len(ciphertext);left=0;right=total;data=ciphertext
 for index,name in enumerate(layers):
  b=SPECS[name]["block_size"];new_left=min(left+b,right)
  data=bytes(data[i]^block(name,data[i-b:i])[0] for i in range(b,len(data))) if len(data)>b else b""
  left=new_left
  if index<len(transforms):left,right,data=transform_interval(left,right,data,total,transforms[index])
  assert len(data)==right-left
 return left,right,data
def predicted_interval(total,layers,transforms):
 left=0;right=total
 for index,name in enumerate(layers):
  left=min(left+SPECS[name]["block_size"],right)
  if index<len(transforms) and transforms[index] in ("byte_reverse","full_hex_reverse"):left,right=total-right,total-left
 return left,right
def ivs(layers,suite):return tuple(bytes(((suite*71+i*23+j*41)&255) for j in range(SPECS[name]["block_size"])) for i,name in enumerate(layers))
def fsa_interval(data,left,right,total):
 if not data:return {"classification":"inconclusive_empty","accepted":None,"initial_states":[0] if left==0 else [0,1,2],"allowed_terminal_states":[0] if right==total else [0,1,2]}
 states={0} if left==0 else {0,1,2}
 for value in data:
  nxt=set()
  for state in states:
   if state==0:
    if value in (9,10,13) or 32<=value<=126:nxt.add(0)
    elif value==0xE2:nxt.add(1)
   elif state==1 and value==0x80:nxt.add(2)
   elif state==2 and value in THIRDS:nxt.add(0)
  states=nxt
  if not states:break
 terminal={0} if right==total else {0,1,2};accepted=bool(states&terminal)
 return {"classification":"tested_nonempty","accepted":accepted,"initial_states":[0] if left==0 else [0,1,2],"ending_states":sorted(states),"allowed_terminal_states":sorted(terminal)}
def base_text(total):
 phrase="INTERVAL – — ‘ ’ … CONTROL. ".encode("utf-8");tail=b"END.\n";room=total-len(tail);return phrase*(room//len(phrase))+b"X"*(room%len(phrase))+tail
def edge_text(total,left,right,side,amount):
 value=bytearray(b"A"*total);sequence=bytes.fromhex("e280a6")
 if side=="left":start=left-amount
 else:start=right-(3-amount)
 assert 0<=start<=total-3;value[start:start+3]=sequence;value[-5:]=b"END.\n"
 return bytes(value)
def record(label,layers,transforms,plaintext,require_fsa=False):
 expected_interval=predicted_interval(len(plaintext),layers,transforms);suite_rows=[];derived=[]
 for suite in (1,2):
  vector_ivs=ivs(layers,suite);ciphertext=encrypt_chain(plaintext,layers,transforms,vector_ivs);full=decrypt_chain(ciphertext,layers,transforms,vector_ivs);left,right,data=known_interval(ciphertext,layers,transforms)
  assert full==plaintext and (left,right)==expected_interval and data==plaintext[left:right]
  endpoint=fsa_interval(data,left,right,len(plaintext))
  if require_fsa and data:assert endpoint["accepted"] is True
  derived.append((left,right,data))
  suite_rows.append({"iv_suite":suite,"ivs_hex":[x.hex() for x in vector_ivs],"ciphertext_sha256":hashlib.sha256(ciphertext).hexdigest(),"full_mode_chain_roundtrip":True,"known_left":left,"known_right":right,"known_length":len(data),"known_sha256":hashlib.sha256(data).hexdigest(),"known_bytes_equal_plaintext_interval":True,"endpoint":endpoint})
 assert derived[0]==derived[1]
 fixed_ivs1=ivs(layers,1);fixed_ivs2=ivs(layers,2);fixed_ct=encrypt_chain(plaintext,layers,transforms,fixed_ivs1);full1=decrypt_chain(fixed_ct,layers,transforms,fixed_ivs1);full2=decrypt_chain(fixed_ct,layers,transforms,fixed_ivs2);left,right,data=known_interval(fixed_ct,layers,transforms)
 assert full1[left:right]==full2[left:right]==data
 outside=full1[:left]+full1[right:];outside2=full2[:left]+full2[right:]
 assert not data or outside!=outside2
 return {"label":label,"decryption_layers":list(layers),"interlayer_transforms":list(transforms),"block_sizes":[SPECS[x]["block_size"] for x in layers],"plaintext_length":len(plaintext),"predicted_known_interval":[*expected_interval],"two_fresh_ciphertexts":suite_rows,"known_interval_identical_across_fresh_iv_suites":True,"fixed_ciphertext_alternate_iv":{"ciphertext_sha256":hashlib.sha256(fixed_ct).hexdigest(),"suite1_plaintext_sha256":hashlib.sha256(full1).hexdigest(),"suite2_plaintext_sha256":hashlib.sha256(full2).hexdigest(),"known_interval_identical":True,"unknown_outside_differs":outside!=outside2,"claim":"Only the stored interval is IV-independent; bytes outside it are not recovered."}}
def produce():
 import Crypto
 rows=[];edge_rows=[]
 for layers,transforms,name in RECIPES:
  boundary=sum(SPECS[x]["block_size"] for x in layers)
  for length,label in ((boundary-1,"below"),(boundary,"at"),(boundary+1,"above_one"),(boundary+17,"above_seventeen")):
   rows.append(record(name+"_"+label,layers,transforms,bytes((length+i*61)&255 for i in range(length))))
  total=160;left,right=predicted_interval(total,layers,transforms);text=base_text(total);rows.append(record(name+"_strict_all_five",layers,transforms,text,True))
  for side in ("left","right"):
   if side=="right" and right==total:continue
   for amount in (1,2):
    label=("bytes_before_" if side=="left" else "bytes_outside_")+str(amount)
    plant=edge_text(total,left,right,side,amount);row=record(name+"_"+side+"_utf8_"+label,layers,transforms,plant,True)
    endpoint=row["two_fresh_ciphertexts"][0]["endpoint"]
    expected_state=amount if side=="left" else 3-amount
    if side=="right":assert expected_state in endpoint["ending_states"]
    else:assert expected_state in endpoint["initial_states"]
    row["edge_control"]={"side":side,"amount_semantics":label.rstrip("_0123456789"),"amount":amount,"expected_boundary_state":expected_state,"state_asserted":True};edge_rows.append(row);rows.append(row)
 assert len(RECIPES)==20 and all(len(t)==len(l)-1 for l,t,_ in RECIPES)
 empty=[row for row in rows if row["two_fresh_ciphertexts"][0]["known_length"]==0]
 assert len(empty)==2*len(RECIPES) and all(row["two_fresh_ciphertexts"][0]["endpoint"]["classification"]=="inconclusive_empty" for row in empty)
 return {"identity":"ASTRA","target_evaluated":False,"rev7_read":False,
  "scope":"Synthetic known-interval extension for direct CFB8 cascades with forward, full-symbol/hex reverse, byte reverse, or nibble swap between same-length binary layers.",
  "proof":{"cfb_interval":"Knowing input bytes [L,R) permits CFB8 decryption bytes [min(L+b,R),R), because each retained byte and its preceding b-byte register lie inside the known interval.","byte_reverse":"[L,R) maps to [N-R,N-L), with known bytes reversed.","nibble_swap":"[L,R) is preserved and each known byte has its nibbles swapped.","full_hex_reverse":"[L,R) maps to [N-R,N-L), with byte reversal and nibble swap.","composition":"Apply these interval maps in decryption order; no IV or unknown byte is fabricated."},
  "recipes":[{"label":name,"decryption_layers":list(layers),"interlayer_transforms":list(transforms)} for layers,transforms,name in RECIPES],
  "vectors":rows,"vector_count":len(rows),"edge_vector_count":len(edge_rows),"fixed_ciphertext_alternate_iv_count":len(rows),
  "endpoint_rule":{"empty_interval":"inconclusive, never rejection","initial_states":"{0} at L=0, otherwise {0,1,2}","terminal_states":"{0} at R=N, otherwise {0,1,2}","relaxed_bytes":"TAB/LF/CR, ASCII32..126, and E2/80/93/94/98/99/A6"},
  "source_hashes":{"interval_extension.py":sha(Path(__file__)),"direct/proof.py":sha(DIRECT),"direct/controls.json":sha(DIRECT_LEDGER)},
  "runtime":{"python":platform.python_version(),"pycryptodome":Crypto.__version__},
  "limits":["Same-length aligned direct binary layers only.","Only the four registered involutive transforms between layers.","No encoding, transposition, framing, truncation, padding insertion/removal, or other byte relocation.","An empty known interval is inconclusive; a nonempty interval is only an endpoint necessary condition.","Bytes outside the final interval are not recovered."],
  "assertions":{"all_passed":True,"direct_baseline_hashes_match":sha(DIRECT)==EXPECTED_DIRECT["proof.py"] and sha(DIRECT_LEDGER)==EXPECTED_DIRECT["controls.json"],"twenty_recipes":len(RECIPES)==20,"all_four_two_layer_transforms":set(t[0] for l,t,n in RECIPES if len(l)==2)==set(TRANSFORMS),"all_16_ordered_three_layer_transform_pairs":set(t for l,t,n in RECIPES if len(l)==3)=={(a,b) for a in TRANSFORMS for b in TRANSFORMS},"two_iv_fresh_ciphertexts_every_vector":all(len(row["two_fresh_ciphertexts"])==2 for row in rows),"fixed_ciphertext_alternate_iv_every_vector":all(row["fixed_ciphertext_alternate_iv"]["known_interval_identical"] for row in rows),"empty_intervals_inconclusive":True,"boundary_aware_fsa_edges":len(edge_rows)>0 and all(row["two_fresh_ciphertexts"][0]["endpoint"]["accepted"] for row in edge_rows),"no_target_read_or_evaluation":True}}
def verify():
 assert sha(DIRECT)==EXPECTED_DIRECT["proof.py"] and sha(DIRECT_LEDGER)==EXPECTED_DIRECT["controls.json"]
 data=json.loads(LEDGER.read_text());assert data["identity"]=="ASTRA" and data["target_evaluated"] is False and data["rev7_read"] is False and data["source_hashes"]["interval_extension.py"]==sha(Path(__file__))
 assert data["vector_count"]==len(data["vectors"]) and data["edge_vector_count"]>0 and data["fixed_ciphertext_alternate_iv_count"]==data["vector_count"] and all(data["assertions"].values())
 assert all(row["fixed_ciphertext_alternate_iv"]["known_interval_identical"] for row in data["vectors"])
 print(json.dumps({"identity":"ASTRA","verified":True,"read_only":True,"ledger_sha256":sha(LEDGER),"vectors":data["vector_count"],"edge_vectors":data["edge_vector_count"]},indent=2))
def main():
 parser=argparse.ArgumentParser();parser.add_argument("--regenerate",type=Path);args=parser.parse_args()
 if args.regenerate is None:verify();return
 if args.regenerate.exists():raise SystemExit("refusing existing output: "+str(args.regenerate))
 result=produce();args.regenerate.parent.mkdir(parents=True,exist_ok=True);args.regenerate.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n");print(json.dumps({"identity":"ASTRA","target_evaluated":False,"output":str(args.regenerate),"sha256":sha(args.regenerate)},indent=2))
if __name__=="__main__":main()
