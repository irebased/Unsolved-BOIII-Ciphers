#!/usr/bin/env python3
"""Synthetic controls for 8-byte ragged-B all-IV predicates."""
import hashlib,itertools,json,platform,random,subprocess,sys
from pathlib import Path
from Crypto import __version__ as crypto_version
from Crypto.Cipher import Blowfish,DES
HERE=Path(__file__).resolve().parent;OUT=HERE/"controls.json";ROOT=HERE.parents[3]
FB=Path("/private/tmp/rev7-fable-20260909/bytelevel/lib/byteTranspositions.js")
FT=FB.with_name("transpositions.js")
NC=ROOT/"research/rev7-20260909-codex/hex_cfb/native_compat"
sys.path.insert(0,str(HERE));import core
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def valid(data):
 s=0
 for b in data:
  s=core.step(s,b)
  if s is None:return False
 return s==0
def lengths(n,w,c):
 q,r=divmod(n,w)
 if not r:return [q]*w
 return [q+1 if (x<r if c=="first" else x>=w-r) else q for x in range(w)]
def inv(obs,w,order,c):
 ls=lengths(len(obs),w,c);offs=[];z=0
 for n in ls:offs.append(z);z+=n
 out=bytearray(len(obs));pos=0
 for row in range(max(ls)):
  for col in order:
   if row<ls[col]:out[offs[col]+row]=obs[pos];pos+=1
 return bytes(out)
def enc_b(nat,w,order,c):
 ls=lengths(len(nat),w,c);offs=[];z=0
 for n in ls:offs.append(z);z+=n
 out=bytearray()
 for row in range(max(ls)):
  for col in order:
   if row<ls[col]:out.append(nat[offs[col]+row])
 return bytes(out)
def make_plain(n):
 crossing=b"A"*7+bytes.fromhex("e28093")
 rest=(" BETA — GAMMA ‘DELTA’ … END. ").encode()+b" THE AETHER REMEMBERS. "*n
 out=(crossing+rest)[:n]
 assert valid(out) and all(bytes.fromhex(x) in out for x in ("e28093","e28094","e28098","e28099","e280a6"))
 return out
def corrupt(obs,w,rank,cipher):
 p=core.prefix(obs,w,rank);z=core.block(cipher,p[:8])[0]
 out=bytearray(obs);out[rank+8*w]=z;return bytes(out)
def kept(obs,w,cipher):return {j for j in range(w) if not core.inspect(obs,w,j,cipher)["rejected"]}
def fable():
 js=f"""const B=require({json.dumps(str(FB))});const n=14,w=4,o=[2,0,3,1],b=Buffer.from([...Array(n).keys()]);for(const c of ['first','last']){{let m=B.columnarB(n,w,o,c);console.log(JSON.stringify({{c,m,h:B.applyInverseBytes(b,m).toString('hex')}}));}}"""
 rows=[json.loads(x) for x in subprocess.check_output(["node","-e",js],text=True).splitlines()]
 exp={"first":"0105090c03070b0d00040802060a","last":"01050903070b0004080c02060a0d"}
 for x in rows:
  assert x["h"]==exp[x["c"]];assert inv(bytes(range(14)),4,(2,0,3,1),x["c"]).hex()==x["h"]
 return rows
def main():
 if OUT.exists():raise SystemExit("refusing existing "+str(OUT))
 fixture=fable();blocks=(bytes(range(8)),b"00000000",bytes.fromhex("a1b2c3d4e5f60718"))
 blockrows=[]
 for cipher in core.KEYS:
  for b in blocks:
   got=core.block(cipher,b)
   if cipher=="des":ind=DES.new(core.KEYS[cipher],DES.MODE_ECB).encrypt(b)
   elif cipher=="blowfish":ind=Blowfish.new(core.KEYS[cipher],Blowfish.MODE_ECB).encrypt(b)
   else:ind=core.word_reverse(Blowfish.new(b"Zombies",Blowfish.MODE_ECB).encrypt(core.word_reverse(b)))
   assert got==ind
   blockrows.append({"cipher":cipher,"block_hex":b.hex(),"encrypted_hex":got.hex(),"adapter_expected_match":True,
    "comparison_kind":("distinct pinned libmcrypt C versus PyCryptodome word-reversal conjugation" if cipher=="blowfish_compat" else "same PyCryptodome primitive adapter consistency")})
 vector=bytes(range(256))+b" CFB8 vector"
 cfbrows=[]
 for cipher in core.KEYS:
  iv=b"0"*8;ct=core.cfb8(vector,cipher,iv,False);assert core.cfb8(ct,cipher,iv,True)==vector
  if cipher=="des":lib=DES.new(core.KEYS[cipher],DES.MODE_CFB,iv=iv,segment_size=8).encrypt(vector)
  elif cipher=="blowfish":lib=Blowfish.new(core.KEYS[cipher],Blowfish.MODE_CFB,iv=iv,segment_size=8).encrypt(vector)
  else:lib=bytes.fromhex(subprocess.check_output([str(NC/"native_compat"),"--cfb-encrypt","blowfish_compat",vector.hex()],text=True).strip())
  assert ct==lib
  cfbrows.append({"cipher":cipher,"plaintext_sha256":hashlib.sha256(vector).hexdigest(),
   "ciphertext_sha256":hashlib.sha256(ct).hexdigest(),"independent_full_cfb8_match":True,"roundtrip":True})
 rng=random.Random(20260910);ivs=[hashlib.sha256(x).digest()[:8] for x in (b"r8-A",b"r8-B")]
 n=546;plain=make_plain(n);plants=[];tails=[];forced=[]
 for cipher in core.KEYS:
  for w in (3,10,17,60):
   order=list(range(w));rng.shuffle(order);order=tuple(order)
   for ci,conv in enumerate(("first","last")):
    nat=core.cfb8(plain,cipher,ivs[ci],False);obs=enc_b(nat,w,order,conv)
    assert inv(obs,w,order,conv)==nat and kept(obs,w,cipher)==set(range(w))
    crossing_rank=order.index(0);wit=core.inspect(obs,w,crossing_rank,cipher)
    assert wit["suffix_hex"].startswith("80") and not wit["rejected"]
    plants.append({"cipher":cipher,"width":w,"q":n//w,"r":n%w,"convention":conv,
      "iv_hex":ivs[ci].hex(),"order":list(order),"all_ranks_retained":True,
      "utf8_crosses_block_boundary_rank":crossing_rank,"suffix_starts_80":True})
    if n%w:
     changed=bytearray(obs)
     for i in range((n//w)*w,n):changed[i]^=0xa5
     assert [core.prefix(obs,w,j) for j in range(w)]==[core.prefix(changed,w,j) for j in range(w)]
     assert kept(obs,w,cipher)==kept(changed,w,cipher)
     tails.append({"cipher":cipher,"width":w,"convention":conv,"tail_bytes":n%w,"invariant":True})
    rank=w//2;bad=corrupt(obs,w,rank,cipher);bw=core.inspect(bad,w,rank,cipher)
    assert bw["first_failure"]["plaintext_byte"]==0 and rank not in kept(bad,w,cipher)
    assert all(core.prefix(obs,w,j)==core.prefix(bad,w,j) for j in range(w) if j!=rank)
    assert core.evaluate(bad,w,cipher)["complete_every_iv_every_order_exclusion"]
    forced.append({"cipher":cipher,"width":w,"convention":conv,"rank":rank,
      "bad_exact_offset":8,"other_ranks_unchanged":True,"first_failure":bw["first_failure"]})
 small=[]
 for cipher in core.KEYS:
  for w in range(3,7):
   size=20*w+1;pt=make_plain(size)
   for ci,conv in enumerate(("first","last")):
    ct=core.cfb8(pt,cipher,ivs[ci],False);order=list(range(w));rng.shuffle(order);order=tuple(order)
    bad=corrupt(enc_b(ct,w,order,conv),w,w-1,cipher);count=checks=0
    for cand in itertools.permutations(range(w)):
     candidate=inv(bad,w,cand,conv)
     for iv in ivs:
      checks+=1;count+=valid(core.cfb8(candidate,cipher,iv,True))
    assert count==0
    small.append({"cipher":cipher,"width":w,"n":size,"r":1,"convention":conv,
      "orders_times_ivs":checks,"valid_full_plaintexts":0})
 boundary=[]
 for cipher in core.KEYS:
  for conv in ("first","last"):
   order=tuple(range(59,-1,-1));ct=core.cfb8(plain,cipher,ivs[1],False);obs=enc_b(ct,60,order,conv)
   assert kept(obs,60,cipher)==set(range(60));bad=corrupt(obs,60,7,cipher);w=core.inspect(bad,60,7,cipher)
   assert w["suffix_bytes"]==1 and w["first_failure"]["plaintext_byte"]==0
   assert core.evaluate(bad,60,cipher)["complete_every_iv_every_order_exclusion"]
   boundary.append({"cipher":cipher,"convention":conv,"width":60,"q":9,"r":6,
    "positive_all_60_retained":True,"corrupted_rank":7,"corrupted_suffix_hex":w["suffix_hex"]})
 for cipher in core.KEYS:
  u=core.evaluate(bytes(546),61,cipher);assert u["q"]==8 and not u["supported"] and u["unresolved"]
 result={"identity":"ASTRA","target_evaluated":False,"rev7_file_read":False,
  "scope":"Synthetic-only ragged-B 8-byte-block predicates: DES Zombies+NUL, standard Blowfish raw Zombies, historical Blowfish-compat raw Zombies; CFB8; every external 8-byte IV; n546 widths2..60; first/last conventions.",
  "source_hashes":{"core.py":sha(HERE/"core.py"),"controls.py":sha(__file__),
   "fable_transpositions.js":sha(FT),"fable_byteTranspositions.js":sha(FB),
   "compat_source_check.py":sha(NC/"source_check.py"),"compat_source_check_reproduction.json":sha(NC/"source_check_reproduction.json"),
   "compat_c_source":sha(NC/"source/blowfish-compat.c"),"compat_library":sha(NC/"source_build/libblowfish_compat.so"),
   "compat_native":sha(NC/"native_compat")},
  "runtime":{"python":platform.python_version(),"pycryptodome":crypto_version,"node":subprocess.check_output(["node","--version"],text=True).strip()},
  "endpoint":{"states_at_chunk_byte_8":[0,1,2],"utf8_sequences":["e28093","e28094","e28098","e28099","e280a6"],"terminal_zero_required":False},
  "fable_live_fixture":fixture,"block_vectors":blockrows,"cfb8_vectors":cfbrows,
  "valid_plants":plants,"tail_mutation":tails,"forced_offset8":forced,
  "small_exhaustive":small,"width60_boundary":boundary,
  "width61_unsupported":[core.evaluate(bytes(546),61,c) for c in core.KEYS],
  "assertions":{"all_passed":True,"original_compat_source_adapter_checked":True,
   "block_adapter_consistency_and_independent_cfb_modes":True,"utf8_crosses_block_boundary":True,
   "tail_invariance":True,"small_all_orders_two_ivs_fail":True,"width60_supported_width61_unsupported":True}}
 OUT.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
 print(json.dumps({"identity":"ASTRA","sha256":sha(OUT),"plants":len(plants),"small":len(small),"boundary":len(boundary)},indent=2))
if __name__=="__main__":main()
