#!/usr/bin/env python3
"""Independent PyCryptodome verification of all BF-compat target witnesses."""
import hashlib,json,math,sys
from pathlib import Path
from Crypto import __version__ as crypto_version
from Crypto.Cipher import Blowfish
HERE=Path(__file__).resolve().parent;REPO=HERE.parents[2]
TARGET=HERE/"target_results.json";OUT=HERE/"verification.json"
MDX=REPO/"lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
NATIVE=HERE.parent/"hex_cfb"/"native_compat"
KEY=b"Zombies";HEX="0123456789ABCDEF";FULL=math.factorial(16)
RELAXED={9,10,13}|set(range(32,127))|{226,128,147,148,152,153}
MODES=("ofb8","fullblock_ofb");IV_NAMES=("ascii_zero","nul","sha1_prefix")
ORIENT_NAMES=("forward","reverse","byte_reverse","nibble_swap")
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def word_reverse(x):
 assert len(x)==8
 return x[3::-1]+x[7:3:-1]
def compat_block(x):
 return word_reverse(Blowfish.new(KEY,Blowfish.MODE_ECB).encrypt(word_reverse(x)))
def ivs():return {"ascii_zero":b"0"*8,"nul":b"\0"*8,"sha1_prefix":hashlib.sha1(KEY).digest()[:8]}
def stream(mode,iv,n):
 if mode=="ofb8":
  reg=iv;out=bytearray()
  for _ in range(n):
   k=compat_block(reg)[0];out.append(k);reg=reg[1:]+bytes([k])
  return bytes(out)
 padded=((n+7)//8)*8
 raw=Blowfish.new(KEY,Blowfish.MODE_OFB,iv=word_reverse(iv)).encrypt(bytes(padded))
 return b"".join(word_reverse(raw[i:i+8]) for i in range(0,padded,8))[:n]
def orientations(value):
 pairs=[value[i:i+2] for i in range(0,len(value),2)]
 return {"forward":value,"reverse":value[::-1],"byte_reverse":"".join(reversed(pairs)),
 "nibble_swap":"".join(x[::-1] for x in pairs)}
def extract():
 text=MDX.read_text();q=chr(96);start=text.index(q+"83 B57B2")+1;end=text.index(q,start)
 value="".join(text[start:end].split()).upper()
 assert len(value)==1092 and hashlib.sha256(value.encode()).hexdigest()=="5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
 return value
def main():
 if OUT.exists():raise SystemExit("refusing existing verification.json")
 data=json.loads(TARGET.read_text());assert data["identity"]=="ASTRA" and data["target_evaluated"]
 assert data["summary"]=={"capped_cells":0,"complete_cells":24,"fsa_survivors":0,
 "relaxed_survivors":0,"root_unsat_cells":24,"unrestricted_witness_cells":24}
 oriented=orientations(extract());expected={(m,v,o) for m in MODES for v in IV_NAMES for o in ORIENT_NAMES}
 assert {(x["mode"],x["iv_kind"],x["orientation"]) for x in data["cells"]}==expected
 checks=[]
 for row in data["cells"]:
  mode,iv_name,orient=row["mode"],row["iv_kind"],row["orientation"];iv=ivs()[iv_name]
  assert row["identity"]=="ASTRA" and row["cipher"]=="blowfish_compat"
  assert row["key_hex"]==KEY.hex() and row["iv_hex"]==iv.hex()
  display=oriented[orient];ks=stream(mode,iv,len(display)//2)
  assert hashlib.sha256(ks).hexdigest()==row["keystream_sha256"]
  w=row["unrestricted_fixed_byte_witness"];assert w and w["direct_ciphertext_bytes_checked"]==256
  positions=w["positions"];pair=w["display_pair"]
  assert positions==sorted(positions) and all(display[2*i:2*i+2]==pair for i in positions)
  assert [ks[i] for i in positions]==w["keystream_bytes"]
  survivors=[c for c in range(256) if all((c^ks[i]) in RELAXED for i in positions)]
  assert survivors==[]==w["surviving_ciphertext_bytes"]
  cert=row["bijective_mapping_certificate"]
  assert cert=={"model":"16-symbol global bijection","full_bijections":FULL,
  "rejected_bijections":FULL,"relaxed_terminal_bijections":0,
  "accounted_bijections":FULL,"partition_complete":True}
  assert row["stats"]["capped"] is False and row["root_unsat"]
  assert row["relaxed_survivor_count"]==row["fsa_survivor_count"]==0 and row["survivors"]==[]
  checks.append({"mode":mode,"iv_kind":iv_name,"orientation":orient,
  "keystream_sha256":row["keystream_sha256"],"display_pair":pair,
  "positions":positions,"keystream_bytes":w["keystream_bytes"],
  "ciphertext_byte_candidates_checked":256,"surviving_candidates":0,
  "full_bijection_certificate":True})
 result={"identity":"ASTRA","target_evaluated":True,
 "verification":"independent PyCryptodome standard-Blowfish conjugation; no CSP/core/compat-stream/target-driver imports",
 "checked_cells":len(checks),"all_24_witnesses_directly_verified":True,
 "all_24_keystream_hashes_verified":True,"all_24_full_bijection_certificates_verified":True,
 "all_24_zero_survivor_records_verified":True,"checks":checks,
 "provenance":{"word_reverse_connection":"Pinned source reproduction proves raw7 actual-C compat = word_reverse(standard-BF(word_reverse(block))); separate 200-vector control establishes the transform on its supplied 16-byte-key vectors.",
 "source_check_reproduction_sha256":sha(NATIVE/"source_check_reproduction.json"),
 "bfcompat_control_sha256":sha(NATIVE/"controls.json"),"bfcompat_control_vector_count":200},
 "runtime":{"python":sys.version,"pycryptodome":crypto_version},
 "source_hashes":{"verify_witnesses.py":sha(Path(__file__)),"target_results.json":sha(TARGET),
 "rev7_mdx":sha(MDX),"source_check_reproduction.json":sha(NATIVE/"source_check_reproduction.json"),
 "native_compat_controls.json":sha(NATIVE/"controls.json"),
 "blowfish.c":sha(NATIVE/"source"/"blowfish.c"),
 "blowfish-compat.c":sha(NATIVE/"source"/"blowfish-compat.c")}}
 OUT.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
 print(json.dumps({"identity":"ASTRA","checked_cells":24,"verification_sha256":sha(OUT)},indent=2))
if __name__=="__main__":main()
