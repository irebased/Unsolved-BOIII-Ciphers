#!/usr/bin/env python3
"""Synthetic proof controls for raw IV-prefix CFB8 frames."""
import hashlib,importlib.util,itertools,json,platform,random,subprocess
from pathlib import Path
from Crypto import __version__ as crypto_version
from Crypto.Cipher import AES,DES,Blowfish
HERE=Path(__file__).resolve().parent;OUT=HERE/"results.json";ROOT=HERE.parents[3]
NC=ROOT/"research/rev7-20260909-codex/hex_cfb/native_compat"
FABLE=Path("/private/tmp/rev7-fable-20260909/bytelevel/lib/byteTranspositions.js")
IDENTITY="ASTRA";P3={147,148,152,153,166}
SPECS={"aes128":(16,b"Zombies"+bytes(9)),"des":(8,b"Zombies\0"),
 "blowfish":(8,b"Zombies"),"blowfish_compat":(8,b"Zombies")}
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def wr(x):return x[3::-1]+x[7:3:-1]
def load_compat():
 spec=importlib.util.spec_from_file_location("source_check_ivprefix",NC/"source_check.py")
 mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
 return mod.load_algorithm(NC/"source_build/libblowfish_compat.so","blowfish_compat")[0]
COMPAT=load_compat()
def block(name,b):
 if name=="aes128":return AES.new(SPECS[name][1],AES.MODE_ECB).encrypt(b)
 if name=="des":return DES.new(SPECS[name][1],DES.MODE_ECB).encrypt(b)
 if name=="blowfish":return Blowfish.new(SPECS[name][1],Blowfish.MODE_ECB).encrypt(b)
 return COMPAT(SPECS[name][1],b)
def independent_block(name,b):
 if name=="aes128":return AES.new(SPECS[name][1],AES.MODE_ECB).encrypt(b)
 if name=="des":return DES.new(SPECS[name][1],DES.MODE_ECB).encrypt(b)
 if name=="blowfish":return Blowfish.new(SPECS[name][1],Blowfish.MODE_ECB).encrypt(b)
 return wr(Blowfish.new(b"Zombies",Blowfish.MODE_ECB).encrypt(wr(b)))
def manual(data,name,iv,decrypt,independent=False):
 b=len(iv);reg=iv;out=bytearray();fn=independent_block if independent else block
 for x in data:
  y=x^fn(name,reg)[0];ct=x if decrypt else y;out.append(y);reg=reg[1:]+bytes([ct])
 return bytes(out)
def library(data,name,iv,decrypt):
 key=SPECS[name][1]
 if name=="aes128":mod=AES
 elif name=="des":mod=DES
 elif name=="blowfish":mod=Blowfish
 else:return manual(data,name,iv,decrypt,True)
 c=mod.new(key,mod.MODE_CFB,iv=iv,segment_size=8)
 return c.decrypt(data) if decrypt else c.encrypt(data)
def step(s,x):
 if s==0:
  if x in {9,10,13} or 32<=x<=126:return 0
  return 1 if x==226 else None
 if s==1:return 2 if x==128 else None
 return 0 if x in P3 else None
def propagate(states,data):
 states=set(states)
 for x in data:
  states={v for s in states if (v:=step(s,x)) is not None}
  if not states:break
 return states
def valid(data):return propagate({0},data)=={0}
def lens(n,w,conv):
 q,r=divmod(n,w)
 if not r:return [q]*w
 return [q+1 if (c<r if conv=="first" else c>=w-r) else q for c in range(w)]
def offsets(n,w,conv):
 out=[];z=0
 for x in lens(n,w,conv):out.append(z);z+=x
 return out
def enc_b(natural,w,order,conv):
 ls=lens(len(natural),w,conv);off=offsets(len(natural),w,conv);out=bytearray()
 for row in range(max(ls)):
  for col in order:
   if row<ls[col]:out.append(natural[off[col]+row])
 return bytes(out)
def inv_b(obs,w,order,conv):
 ls=lens(len(obs),w,conv);off=offsets(len(obs),w,conv);out=bytearray(len(obs));pos=0
 for row in range(max(ls)):
  for col in order:
   if row<ls[col]:out[off[col]+row]=obs[pos];pos+=1
 return bytes(out)
def make_payload(n,starts):
 out=bytearray(b"A"*n);seqs=[bytes.fromhex(x) for x in ("e28093","e28094","e28098","e28099","e280a6")]
 positions=[3,20,37,54,71]
 for p,s in zip(positions,seqs):out[p:p+3]=s
 a=next(x for x in starts if 4<x<n-2)
 out[a-1:a+2]=bytes.fromhex("e28093")
 assert valid(out);return bytes(out)
def fable_fixture():
 js=f"""const B=require({json.dumps(str(FABLE))});const n=14,w=4,o=[2,0,3,1],b=Buffer.from([...Array(n).keys()]);for(const c of ['first','last']){{let m=B.columnarB(n,w,o,c);console.log(JSON.stringify({{c,h:B.applyInverseBytes(b,m).toString('hex')}}));}}"""
 rows=[json.loads(x) for x in subprocess.check_output(["node","-e",js],text=True).splitlines()]
 assert {x["c"]:x["h"] for x in rows}=={"first":"0105090c03070b0d00040802060a","last":"01050903070b0004080c02060a0d"}
 return rows
def main():
 if OUT.exists():raise SystemExit("refusing existing "+str(OUT))
 fixture=fable_fixture();rng=random.Random(20260910);rows=[];vectors=[]
 for name,(bs,key) in SPECS.items():
  for ivindex in range(2):
   iv=hashlib.sha256(f"{name}-raw-iv-{ivindex}".encode()).digest()[:bs]
   base="ALL FIVE: – — ‘ ’ … END.\r\n".encode()+b"A"*600
   payload=base[:546-bs];assert valid(payload)
   ct=library(payload,name,iv,False);assert manual(payload,name,iv,False)==ct
   assert library(ct,name,iv,True)==payload==manual(ct,name,iv,True)
   assert independent_block(name,bytes(range(bs)))==block(name,bytes(range(bs)))
   frame=iv+ct;assert len(frame)==546
   whole_suffix=bytes(frame[i]^independent_block(name,frame[i-bs:i])[0] for i in range(bs,len(frame)))
   assert whole_suffix==payload and valid(whole_suffix) and 0 in propagate({0,1,2},whole_suffix)
   vectors.append({"cipher":name,"block_size":bs,"iv_hex":iv.hex(),"frame_bytes":len(frame),"payload_bytes":len(payload),
    "frame_sha256":hashlib.sha256(frame).hexdigest(),"payload_sha256":hashlib.sha256(payload).hexdigest(),
    "ciphertext_sha256":hashlib.sha256(ct).hexdigest(),"full_frame_suffix_sha256":hashlib.sha256(whole_suffix).hexdigest(),
    "full_frame_suffix_equals_payload":True,"strict_payload_valid":True,
    "full_frame_suffix_end_states_from_all_boundaries":sorted(propagate({0,1,2},whole_suffix)),
    "register_boundary_indices":{"first_payload":{"frame_index":bs,"payload_index":0,"register_slice":[0,bs],"composition":"all IV"},
      "mixed":{"first_frame_index":bs+1,"last_frame_index":2*bs-1,"first_register_slice":[1,bs+1],"last_register_slice":[bs-1,2*bs-1]},
      "first_full_ciphertext_register":{"frame_index":2*bs,"payload_index":bs,"register_slice":[bs,2*bs]}},
    "mode_or_independent_recurrence_encrypt_decrypt_equal":True,"distinct_compat_block_source_vs_conjugation":name=="blowfish_compat"})
  widths=(13,32,33) if bs==16 else (17,60,61)
  for w in widths:
   q=546//w
   for conv in ("first","last"):
    iv=hashlib.sha256(f"{name}-{w}-{conv}-iv".encode()).digest()[:bs]
    starts=offsets(546,w,conv)
    payload=make_payload(546-bs,starts)
    ct=library(payload,name,iv,False);frame=iv+ct;assert len(frame)==546
    order=list(range(w));rng.shuffle(order);order=tuple(order);obs=enc_b(frame,w,order,conv)
    assert inv_b(obs,w,order,conv)==frame
    chunks=[];allretained=True
    if q>bs:
     for rank,col in enumerate(order):
      p=obs[rank:q*w:w];a=starts[col];direct=bytes(p[i]^independent_block(name,p[i-bs:i])[0] for i in range(bs,len(p)))
      expected=payload[a:a+q-bs]
      assert direct==expected
      assert manual(p,name,bytes(bs),True,True)[bs:]==direct
      end=propagate({0,1,2},direct);allretained&=bool(end)
      chunks.append({"rank":rank,"natural_column":col,"frame_offset":a,"prefix_sha256":hashlib.sha256(p).hexdigest(),
       "suffix_hex":direct.hex(),"expected_payload_slice":{"start":a,"stop":a+q-bs},
       "exact_payload_slice_match":True,"end_states":sorted(end),
       "starts_inside_utf8_sequence":a>0 and payload[a-1]==0xe2 and payload[a]==0x80})
     assert allretained and any(x["starts_inside_utf8_sequence"] for x in chunks)
    else:assert q==bs
    rows.append({"cipher":name,"block_size":bs,"width":w,"q":q,"r":546%w,"convention":conv,
     "iv_hex":iv.hex(),"payload_bytes":len(payload),"order":list(order),"supported":q>bs,
     "all_chunk_suffixes_match_payload_slices":q>bs,"all_necessary_fsa_prefixes_retained":allretained if q>bs else None,
     "chunks":chunks})
 result={"identity":IDENTITY,"target_evaluated":False,"rev7_file_read":False,
  "theorem":{"frame":"S = IV || C, with exactly one block-size raw binary IV included in the transformed 546-byte stream",
   "equation":"For frame index i >= b: P[i-b] = S[i] XOR E_key(S[i-b:i])[0]. For a contiguous natural chunk starting at frame offset a, its locally decrypted suffix at relative i >= b equals payload P[a+i-b].",
   "consequence":"Any chunk suffix rejected from all reachable endpoint boundary states is impossible for every IV value; an existing whole-frame variant-B unavoidable-chunk rejection transfers unchanged to raw-IV-prefix framing.",
   "requirements":["the map or column transform acts on the entire IV||ciphertext frame","the IV is exactly b raw bytes at frame start","CFB segment size is 8 bits","natural chunks are contiguous frame slices"]},
  "limits":{"not_covered":["ASCII/hex-encoded IV fields","an IV stored outside the transformed region","extra prepended bytes beyond the raw IV block","trailing framing bytes","transforms applied only to ciphertext","other feedback modes or segment sizes"],
   "endpoint_applies_to":"payload plaintext only; IV bytes are unrestricted","retained_chunk":"necessary only, not a recovered plaintext or IV"},
  "source_hashes":{"proof.py":sha(__file__),"fable_byteTranspositions.js":sha(FABLE),
   "compat_source_check.py":sha(NC/"source_check.py"),"compat_source_check_reproduction.json":sha(NC/"source_check_reproduction.json"),
   "compat_c_source":sha(NC/"source/blowfish-compat.c"),"compat_library":sha(NC/"source_build/libblowfish_compat.so")},
  "runtime":{"python":platform.python_version(),"pycryptodome":crypto_version},
  "fable_fixture":fixture,"full_frame_vectors":vectors,"ragged_cases":rows,
  "assertions":{"all_passed":True,"two_arbitrary_ivs_per_cipher":True,"frame_length_546":True,
   "pycrypto_modes_or_distinct_compat_recurrence_equal":True,"whole_frame_suffix_equals_strict_payload":True,"compat_distinct_source_and_conjugation_equal":True,
   "exact_chunk_suffix_payload_index_identity":True,"utf8_partial_chunk_boundary_retained":True,
   "q_equals_block_size_marked_unsupported":True}}
 OUT.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
 print(json.dumps({"identity":IDENTITY,"results_sha256":sha(OUT),"vectors":len(vectors),"ragged_cases":len(rows)},indent=2))
if __name__=="__main__":main()
