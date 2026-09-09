#!/usr/bin/env python3
"""Synthetic and source-fixture controls; never opens Rev7."""
import hashlib,itertools,json,math,random,sys,time
from dataclasses import asdict
from pathlib import Path
from Crypto import __version__ as crypto_version
from Crypto.Cipher import AES,Blowfish,DES
import core

HERE=Path(__file__).resolve().parent
SOURCE=HERE.parent/"sources"/"ofb8"/"results.json"
OUT=HERE/"controls.json"
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def direct(display,ks,mapping):
 ct=core.decode(display,mapping);plain=bytes(x^y for x,y in zip(ct,ks))
 return plain,all(x in core.RELAXED for x in plain),core.valid_fsa(plain)
def naive(display,ks,seed):
 unknown=sorted(set(range(16))-set(seed));unused=sorted(set(range(16))-set(seed.values()))
 assert len(unknown)==len(unused)==4
 out={}
 for values in itertools.permutations(unused):
  m=[-1]*16
  for k,v in seed.items():m[k]=v
  for k,v in zip(unknown,values):m[k]=v
  plain,relaxed,fsa=direct(display,ks,m)
  if relaxed:out[tuple(m)]=(plain,fsa)
 return out
def packed(solutions):return {tuple(x["mapping"]):(x["plaintext"],x["fsa_valid"]) for x in solutions}
def plant_plain():
 unit=b"ASTRA stream CSP: en"+bytes.fromhex("e28093")+b" em"+bytes.fromhex("e28094")+b" left"+bytes.fromhex("e28098")+b" right"+bytes.fromhex("e28099")+b" Base64 ABCxyz019+/=\r\n"
 return unit*(546//len(unit))+b"A"*(546%len(unit))
def main():
 source=json.loads(SOURCE.read_text());assert len(source["rows"])==12
 source_checks=[]
 for row in source["rows"]:
  cipher=row["cipher"];mod,key=core.specs()[cipher];iv=bytes.fromhex(row["iv_hex"])
  plain=bytes.fromhex(row["plaintext_hex"]);expected=bytes.fromhex(row["ciphertext_hex"])
  got=bytes(x^y for x,y in zip(plain,core.keystream(cipher,"ofb8",iv,len(plain))))
  assert got==expected
  source_checks.append({"cipher":cipher,"iv_kind":row["iv_kind"],"fixture":row["fixture"],
    "ciphertext_sha256":hashlib.sha256(got).hexdigest(),"matches_actual_c_fixture":True})
 assert len(source_checks)==12

 fullblock=[]
 vector=bytes(range(256))+b"full block OFB"
 for cipher,(mod,key) in core.specs().items():
  for iv_name,iv in core.ivs(mod.block_size).items():
   got=bytes(x^y for x,y in zip(vector,core.keystream(cipher,"fullblock_ofb",iv,len(vector))))
   expected=mod.new(key,mod.MODE_OFB,iv=iv).encrypt(vector)
   assert got==expected and mod.new(key,mod.MODE_OFB,iv=iv).decrypt(got)==vector
   fullblock.append({"cipher":cipher,"iv":iv_name,"ciphertext_sha256":hashlib.sha256(got).hexdigest(),
    "pycryptodome_mode_ofb_match":True,"roundtrip":True})

 rng=random.Random(20260910);mapping=list(range(16));rng.shuffle(mapping);plain=plant_plain()
 full=[]
 for cipher,(mod,key) in core.specs().items():
  iv=core.ivs(mod.block_size)["sha1_prefix"]
  for mode in ("ofb8","fullblock_ofb"):
   ks=core.keystream(cipher,mode,iv,len(plain));ct=bytes(x^y for x,y in zip(plain,ks))
   display=core.display_encode(ct,mapping);assert set(display)==set(core.HEX)
   t=time.perf_counter();sol,stats,rel=core.solve(display,ks,1_000_000)
   recovered=[x for x in sol if tuple(x["mapping"])==tuple(mapping) and x["plaintext"]==plain and x["fsa_valid"]]
   pairs=[display[i:i+2] for i in range(0,len(display),2)]
   assert len(set(pairs))<len(pairs) and any(x[0]==x[1] for x in pairs)
   assert recovered and not stats.capped
   assert stats.rejected_weight+stats.terminal_weight==math.factorial(16)
   full.append({"cipher":cipher,"mode":mode,"iv":"sha1_prefix","nodes":stats.nodes,
    "elapsed_seconds":time.perf_counter()-t,"relaxed_survivors":stats.relaxed_complete,
    "fsa_survivors":stats.fsa_complete,"plant_recovered":True,"certificate":stats.rejected_weight+stats.terminal_weight,
    "complete":not stats.capped,"all_16_display_symbols":True,
    "repeated_pair_constraint":len(set(pairs))<len(pairs),
    "same_symbol_pair_constraint":any(x[0]==x[1] for x in pairs)})

 seeded=[]
 for cipher,(mod,key) in core.specs().items():
  iv=core.ivs(mod.block_size)["ascii_zero"]
  for mode in ("ofb8","fullblock_ofb"):
   sample=(b"AB09+/= stream seeded control\r\n"*3);ks=core.keystream(cipher,mode,iv,len(sample));display=core.display_encode(bytes(x^y for x,y in zip(sample,ks)),mapping)
   unknown=set(range(12,16));seed={i:v for i,v in enumerate(mapping) if i not in unknown}
   ns=naive(display,ks,seed);sol,stats,_=core.solve(display,ks,1_000_000,seed)
   assert packed(sol)==ns and not stats.capped
   assert stats.rejected_weight+stats.terminal_weight==math.factorial(4)
   assert tuple(mapping) in ns and ns[tuple(mapping)]==(sample,True)
   seeded.append({"cipher":cipher,"mode":mode,"naive_mapping_count":24,
    "relaxed_survivors":len(ns),"fsa_survivors":sum(v[1] for v in ns.values()),
    "exact_survivor_sets_match":True,"certificate":24,"complete":True,"nodes":stats.nodes})

 # Relaxed byte membership deliberately admits an unterminated historical UTF-8 prefix;
 # the final FSA must reject that planted mapping.
 cipher="aes128";mod,key=core.specs()[cipher];iv=core.ivs(mod.block_size)["nul"]
 trunc=b"ABC\xe2\x80";ks=core.keystream(cipher,"ofb8",iv,len(trunc))
 display=core.display_encode(bytes(x^y for x,y in zip(trunc,ks)),mapping)
 seed={i:v for i,v in enumerate(mapping) if i<12}
 ns=naive(display,ks,seed);sol,stats,_=core.solve(display,ks,1_000_000,seed)
 assert packed(sol)==ns and tuple(mapping) in ns and ns[tuple(mapping)]==(trunc,False)
 truncated={"plaintext_hex":trunc.hex(),"relaxed_accepts_plant":True,"fsa_rejects_unterminated_plant":True,
  "exact_naive_sets_match":True,"certificate":stats.rejected_weight+stats.terminal_weight}

 # Root-pruning witness 1: repeated diagonal pair across every byte keystream.
 empty_display="00"*256;empty_ks=bytes(range(256))
 empty_sol,empty_stats,empty_rel=core.solve(empty_display,empty_ks,1_000_000)
 direct_diagonal_valid=[]
 for value in range(16):
  m=list(range(16));m[0]=value;m[value]=0
  if direct(empty_display,empty_ks,m)[1]:direct_diagonal_valid.append(value)
 assert empty_rel[(0,0)]==set() and not direct_diagonal_valid
 assert not empty_sol and empty_stats.nodes==0 and empty_stats.rejected_weight==math.factorial(16)

 # Each relation below is nonempty and forces 5; allDifferent makes the pair impossible.
 ordered=bytes(sorted(core.RELAXED));segment=bytes(0x55^x for x in ordered)
 clash_display="00"*len(segment)+"11"*len(segment);clash_ks=segment+segment
 clash_sol,clash_stats,clash_rel=core.solve(clash_display,clash_ks,1_000_000)
 assert clash_rel[(0,0)]=={(5,5)} and clash_rel[(1,1)]=={(5,5)}
 direct_distinct_valid=0
 for a in range(16):
  for b in range(16):
   if a==b:continue
   ciphertext=bytes([17*a])*len(segment)+bytes([17*b])*len(segment)
   plaintext=bytes(x^y for x,y in zip(ciphertext,clash_ks))
   if all(x in core.RELAXED for x in plaintext):direct_distinct_valid+=1
 assert direct_distinct_valid==0 and not clash_sol and clash_stats.nodes==0
 assert clash_stats.rejected_weight==math.factorial(16)

 mod,key=core.specs()["aes128"];iv=core.ivs(mod.block_size)["sha1_prefix"]
 cap_plain=plant_plain();cap_ks=core.keystream("aes128","ofb8",iv,len(cap_plain))
 cap_display=core.display_encode(bytes(x^y for x,y in zip(cap_plain,cap_ks)),mapping)
 cap_sol,cap_stats,_=core.solve(cap_display,cap_ks,1)
 cap_cert=cap_stats.rejected_weight+cap_stats.terminal_weight
 assert cap_stats.nodes==1 and cap_stats.capped and cap_stats.terminal_weight==0
 assert cap_cert<math.factorial(16) and not cap_sol
 pruning_controls={"empty_repeated_pair":{"relation_empty":True,"direct_diagonal_assignments_checked":16,"direct_valid":0,"nodes":0,"rejected_weight":empty_stats.rejected_weight,"certificate_complete":True},"singleton_all_different_clash":{"both_relations_nonempty":True,"both_force_value":5,"direct_distinct_assignments_checked":240,"direct_valid":0,"nodes":0,"rejected_weight":clash_stats.rejected_weight,"certificate_complete":True},"cap_one":{"node_limit":1,"nodes":cap_stats.nodes,"capped":True,"terminal_weight":0,"certificate_weight":cap_cert,"expected_weight":math.factorial(16),"certificate_complete":False}}

 result={"identity":"ASTRA","target_evaluated":False,
  "scope":{"modes":["ofb8","fullblock_ofb"],"ciphers":list(core.specs()),
   "iv_kinds":["ascii_zero","nul","sha1_prefix"],"node_limit":1000000,
   "relaxed_bytes":sorted(core.RELAXED),"final_endpoint":"ASCII plus E2 80 93/94/98/99, terminal state zero"},
  "ofb8_actual_c_source_fixtures":source_checks,"fullblock_pycryptodome_controls":fullblock,
  "full16_mixed_utf8_plants":full,"seeded_four_unknown_naive_controls":seeded,
  "truncated_utf8_control":truncated,"root_pruning_and_cap_controls":pruning_controls,
  "proof":{"certificate":"At each MRV assignment every unused value is visited. A support-empty child charges (16-assigned)! completions; surviving children recurse. These disjoint branches plus terminal mappings partition the parent subtree.",
   "support_pruning":"A value is removed only when a pair relation has no supported partner in the neighbor domain, or allDifferent has already consumed it; an empty domain therefore has no bijective completion.",
   "relation_relaxation":"Relations intersect necessary per-position byte membership only. Complete relaxed survivors are separately replayed in original order through the stateful endpoint FSA."},
  "runtime":{"python":sys.version,"pycryptodome":crypto_version},
  "source_hashes":{"core.py":sha(HERE/"core.py"),"controls.py":sha(Path(__file__)),"ofb8_results.json":sha(SOURCE)}}
 if OUT.exists():raise SystemExit("refusing existing controls.json")
 OUT.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
 print(json.dumps({"identity":"ASTRA","target_evaluated":False,"controls_sha256":sha(OUT),
  "full_controls":[{"cipher":x["cipher"],"mode":x["mode"],"nodes":x["nodes"],"seconds":x["elapsed_seconds"],"relaxed":x["relaxed_survivors"],"fsa":x["fsa_survivors"]} for x in full]},indent=2))
if __name__=="__main__":main()
