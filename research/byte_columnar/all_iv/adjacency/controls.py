#!/usr/bin/env python3
"""Synthetic controls for rectangular ordered-chunk adjacency closure."""
import hashlib,itertools,json,platform,random,subprocess,sys
from pathlib import Path
from Crypto import __version__ as crypto_version
from Crypto.Cipher import AES,DES,Blowfish
HERE=Path(__file__).resolve().parent;OUT=HERE/"controls.json";ROOT=HERE.parents[3]
FB=Path("/private/tmp/rev7-fable-20260909/bytelevel/lib/byteTranspositions.js")
sys.path.insert(0,str(HERE));import core
r8=core.r8
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def valid(data):
 s=0
 for x in data:
  s=r8.step(s,x)
  if s is None:return False
 return s==0
def enc_b(natural,w,order):
 q=len(natural)//w;return bytes(natural[col*q+row] for row in range(q) for col in order)
def inv_b(obs,w,order):
 q=len(obs)//w;out=bytearray(len(obs))
 for row in range(q):
  for rank,col in enumerate(order):out[col*q+row]=obs[row*w+rank]
 return bytes(out)
def independent_block(c,b):
 if c=="aes128":return AES.new(b"Zombies"+bytes(9),AES.MODE_ECB).encrypt(b)
 if c=="des":return DES.new(b"Zombies\0",DES.MODE_ECB).encrypt(b)
 if c=="blowfish":return Blowfish.new(b"Zombies",Blowfish.MODE_ECB).encrypt(b)
 t=b[3::-1]+b[7:3:-1];x=Blowfish.new(b"Zombies",Blowfish.MODE_ECB).encrypt(t);return x[3::-1]+x[7:3:-1]
def lib_cfb(data,c,iv,decrypt):
 if c=="aes128":mod=AES;key=b"Zombies"+bytes(9)
 elif c=="des":mod=DES;key=b"Zombies\0"
 elif c=="blowfish":mod=Blowfish;key=b"Zombies"
 else:
  reg=iv;out=bytearray()
  for x in data:
   y=x^independent_block(c,reg)[0];ct=x if decrypt else y;out.append(y);reg=reg[1:]+bytes([ct])
  return bytes(out)
 x=mod.new(key,mod.MODE_CFB,iv=iv,segment_size=8);return x.decrypt(data) if decrypt else x.encrypt(data)
def make_plain(n,q,b):
 out=bytearray(b"A"*n);seqs=[bytes.fromhex(x) for x in ("e28093","e28094","e28098","e28099","e280a6")]
 for p,s in zip((3,20,37,54,71),seqs):out[p:p+3]=s
 if q+b+2<n:out[q+b-1:q+b+2]=bytes.fromhex("e28093")
 assert valid(out);return bytes(out)
def main():
 if OUT.exists():raise SystemExit("refusing existing "+str(OUT))
 js=f"""const B=require({json.dumps(str(FB))});let m=B.columnarB(12,3,[2,0,1],'first'),b=Buffer.from([...Array(12).keys()]);console.log(JSON.stringify({{m,h:B.applyInverseBytes(b,m).toString('hex')}}));"""
 fixture=json.loads(subprocess.check_output(["node","-e",js],text=True));assert fixture["h"]=="0104070a0205080b00030609";assert inv_b(bytes(range(12)),3,(2,0,1)).hex()==fixture["h"]
 specs={"aes128":(16,(39,42)),"des":(8,(78,91)),"blowfish":(8,(78,91)),"blowfish_compat":(8,(78,91))}
 adapter=[]
 for c,(b,_) in specs.items():
  sample=bytes(range(b));got=(AES.new(b"Zombies"+bytes(9),AES.MODE_ECB).encrypt(sample) if c=="aes128" else r8.block(c,sample))
  assert got==independent_block(c,sample)
  iv=b"0"*b;data=bytes(range(128));manual=core.cfb8(data,c,iv,False);mode=lib_cfb(data,c,iv,False);assert manual==mode and lib_cfb(mode,c,iv,True)==data
  adapter.append({"cipher":c,"block_size":b,"block_check_kind":("distinct pinned C versus PyCryptodome conjugation" if c=="blowfish_compat" else "adapter consistency"),
   "manual_cfb8_matches_mode_or_distinct_compat_recurrence":True})
 rng=random.Random(20260910);plants=[];ivchecks=[]
 for c,(b,widths) in specs.items():
  for q in sorted({546//w for w in widths}):
   pair=bytes(rng.randrange(256) for _ in range(2*q));iv1=hashlib.sha256((c+str(q)+"a").encode()).digest()[:b];iv2=hashlib.sha256((c+str(q)+"b").encode()).digest()[:b]
   s=core.suffix(pair,c);assert core.cfb8(pair,c,iv1,True)[b:]==s==core.cfb8(pair,c,iv2,True)[b:]
   ivchecks.append({"cipher":c,"q":q,"suffix_sha256":hashlib.sha256(s).hexdigest(),"two_iv_suffix_equal":True})
  for w in widths:
   q=546//w;plain=make_plain(546,q,b);iv=hashlib.sha256(f"adj-{c}-{w}".encode()).digest()[:b];ct=lib_cfb(plain,c,iv,False)
   order=list(range(w));rng.shuffle(order);order=tuple(order);obs=enc_b(ct,w,order);assert inv_b(obs,w,order)==ct
   g=core.evaluate(obs,w,c);path=[order.index(col) for col in range(w)]
   edge={tuple(x) for x in g["retained_edges"]};assert all((a,z) in edge for a,z in zip(path,path[1:]))
   assert not g["complete_every_iv_order_exclusion"] and g["unresolved"]
   # Natural edge beginning at column 1 starts at plaintext q, intentionally byte 0x80.
   rank1=order.index(1);rank2=order.index(2);wr=next(x for x in g["ordered_pair_witnesses"] if x["from_rank"]==rank1 and x["to_rank"]==rank2)
   assert bytes.fromhex(wr["suffix_hex"])[0]==0x80 and wr["edge_retained"]
   plants.append({"cipher":c,"width":w,"q":q,"iv_hex":iv.hex(),"order_sha256":hashlib.sha256(bytes(order)).hexdigest(),
    "true_path_edges":w-1,"all_true_order_edges_retained":True,"no_false_closure":True,
    "utf8_boundary_edge":[rank1,rank2],"utf8_suffix_starts_80":True,
    "retained_edge_count":len(edge)})
 tiny=[]
 for c,(b,_) in specs.items():
  q=(b//2)+1;assert q<=b<2*q
  for w in range(3,8):
   attempt=0
   while True:
    attempt+=1;obs=bytes(rng.randrange(256) for _ in range(w*q));g=core.evaluate(obs,w,c)
    if g["complete_every_iv_order_exclusion"]:break
    assert attempt<100
   edges={tuple(x) for x in g["retained_edges"]}
   hpaths=[p for p in itertools.permutations(range(w)) if all((a,z) in edges for a,z in zip(p,p[1:]))]
   assert not hpaths
   fullvalid=0;checks=0
   for order in itertools.permutations(range(w)):
    ct=inv_b(obs,w,order)
    for ivtag in (b"tiny-a",b"tiny-b"):
     iv=hashlib.sha256(c.encode()+bytes([w])+ivtag).digest()[:b];checks+=1
     fullvalid+=valid(lib_cfb(ct,c,iv,True))
   assert fullvalid==0
   tiny.append({"cipher":c,"width":w,"q":q,"deterministic_attempts":attempt,"closure_reasons":g["closure_reasons"],
    "zero_indegree":g["zero_indegree_vertices"],"zero_outdegree":g["zero_outdegree_vertices"],
    "weak_components":g["weak_components"],"graph_hamiltonian_paths":0,
    "full_orders_times_ivs_checked":checks,"full_valid_plaintexts":0})
 unsupported=[]
 for c,(b,_) in specs.items():
  q=b//2;n=3*q;u=core.evaluate(bytes(n),3,c);assert not u["supported"] and 2*q<=b
  unsupported.append({"cipher":c,"block_size":b,"q":q,"n":n,"supported":False})
 result={"identity":"ASTRA","target_evaluated":False,"rev7_file_read":False,
  "scope":"Synthetic-only rectangular variant-B necessary ordered-chunk graph; AES widths39/42 and DES/BF/BFcompat widths78/91 prospective; fixed Zombies keys; CFB8; every external IV.",
  "method":{"edge":"A->B iff decrypt(concat(A,B))[b:] retains from FSA states {0,1,2}; no terminal-zero check",
   "support":"q <= b < 2q","closures":["at least two zero-indegree vertices","at least two zero-outdegree vertices","weakly disconnected graph for w>1"],
   "unresolved":"all other graphs; no Hamiltonian search in target method"},
  "source_hashes":{"core.py":sha(HERE/"core.py"),"controls.py":sha(__file__),"audited_ragged8_core.py":sha(HERE.parent/"ragged8/core.py"),
   "fable_byteTranspositions.js":sha(FB)},
  "runtime":{"python":platform.python_version(),"pycryptodome":crypto_version},
  "adapter_controls":adapter,"fable_fixture":fixture,"two_iv_pair_suffix":ivchecks,
  "valid_plants":plants,"tiny_exhaustive_closures":tiny,"unsupported_2q_le_b":unsupported,
  "assertions":{"all_passed":True,"all_true_order_edges_retained":True,"no_valid_plant_false_closure":True,
   "two_iv_suffix_same":True,"utf8_boundary_retained":True,"tiny_graph_and_full_order_enumerations_agree":True,
   "only_declared_closures_used":True}}
 OUT.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
 print(json.dumps({"identity":"ASTRA","sha256":sha(OUT),"plants":len(plants),"tiny":len(tiny)},indent=2))
if __name__=="__main__":main()
