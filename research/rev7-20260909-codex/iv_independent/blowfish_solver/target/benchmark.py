#!/usr/bin/env python3
"""Read-only verifier and explicit bounded synthetic benchmark for the native solver."""
import argparse,hashlib,json,random,subprocess,time
from pathlib import Path
from Crypto.Cipher import Blowfish
HERE=Path(__file__).resolve().parent;PACKAGE=HERE.parent;LEDGER=HERE/"benchmark.json"
NATIVE=PACKAGE/"native";SOURCE=PACKAGE/"native.cpp";BUILD=PACKAGE/"native_build.json"
LIMIT=1_000_000;KEY=b"Zombies";HEX="0123456789ABCDEF"
EXPECTED_NATIVE="b7f3a187f29705fc21f7a529b7722f9f9d936a4f66715e107ff52acfb11ca433"
EXPECTED_BINARY="23063a1f86329572d0b10a507804210f0743b60f78f65a8366afd9b4ef44583f"
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def encode(data,mapping):
 inv=[0]*16
 for shown,actual in enumerate(mapping):inv[actual]=shown
 return "".join(HEX[inv[x>>4]]+HEX[inv[x&15]] for x in data)
def fixture():
 rng=random.Random(0xBF7A2026);mapping=list(range(16));rng.shuffle(mapping)
 phrase="FULL MAP BENCHMARK – — ‘ ’ … ".encode("utf-8");tail=b"END.\n";room=546-len(tail);body=phrase*(room//len(phrase))+b"X"*(room%len(phrase));plain=body+tail
 iv=bytes.fromhex("0011223344556677");ct=Blowfish.new(KEY,Blowfish.MODE_CFB,iv=iv,segment_size=8).encrypt(plain);display=encode(ct,mapping)
 assert len(plain)==546 and len(display)==1092 and set(display)==set(HEX)
 return mapping,plain,iv,ct,display
def produce():
 assert sha(SOURCE)==EXPECTED_NATIVE and sha(NATIVE)==EXPECTED_BINARY
 mapping,plain,iv,ct,display=fixture();rows=[]
 for backend in ("blowfish","blowfish_compat"):
  started=time.perf_counter();p=subprocess.run([str(NATIVE),backend,str(LIMIT),display,"-"],text=True,capture_output=True,check=True,timeout=120);wall=time.perf_counter()-started;n=json.loads(p.stdout)
  assert n["identity"]=="ASTRA" and n["cipher"]==backend and n["node_limit"]==LIMIT and n["seeded_entries"]==0 and n["expected_completion_weight"]==20922789888000
  assert n["stats"]["nodes"]==LIMIT and n["stats"]["aborted_at_node_limit"] and not n["certificate_complete"]
  assert n["certificate_weight"]+n["unaccounted_mapping_weight"]==n["expected_completion_weight"]
  rows.append({"cipher":backend,"nodes":n["stats"]["nodes"],"ecb_calls":n["ecb_calls"],"native_elapsed_seconds":n["elapsed_seconds"],"process_wall_seconds":wall,"nodes_per_second":n["stats"]["nodes"]/n["elapsed_seconds"],"ecb_calls_per_second":n["ecb_calls"]/n["elapsed_seconds"],"certificate_weight":n["certificate_weight"],"unaccounted_mapping_weight":n["unaccounted_mapping_weight"],"survivors_at_terminals":len(n["solutions"]),"capped_incomplete":True})
 return {"identity":"ASTRA","target_evaluated":False,"rev7_read":False,"scope":"One deterministic 546-byte full-unseeded displayed-hex fixture, evaluated under both native Blowfish backends for exactly 1,000,000 accepted DFS entries each.","fixture":{"generator":"random.Random(0xBF7A2026) mapping; valid five-sequence UTF-8 plaintext; standard Blowfish CFB8; IV 0011223344556677","mapping_display_to_nibble":mapping,"plaintext_sha256":hashlib.sha256(plain).hexdigest(),"ciphertext_sha256":hashlib.sha256(ct).hexdigest(),"display_sha256":hashlib.sha256(display.encode()).hexdigest(),"all_16_display_symbols":True,"bytes":546},"rows":rows,"source_hashes":{"benchmark.py":sha(Path(__file__)),"native.cpp":sha(SOURCE),"native":sha(NATIVE),"native_build.json":sha(BUILD)},"interpretation":"Bounded synthetic host timing only. Both prefixes are deliberately capped and establish neither exhaustive search nor target behavior.","assertions":{"all_passed":True,"both_backends_exactly_one_million_nodes":True,"both_factorial_partitions_exact":True,"both_incomplete":True,"no_target_read_or_evaluation":True}}
def verify():
 d=json.loads(LEDGER.read_text());assert d["identity"]=="ASTRA" and d["target_evaluated"] is False and d["rev7_read"] is False
 assert d["source_hashes"]=={"benchmark.py":sha(Path(__file__)),"native.cpp":sha(SOURCE),"native":sha(NATIVE),"native_build.json":sha(BUILD)}
 assert len(d["rows"])==2 and all(d["assertions"].values()) and all(x["nodes"]==LIMIT and x["capped_incomplete"] for x in d["rows"])
 print(json.dumps({"identity":"ASTRA","verified":True,"read_only":True,"ledger_sha256":sha(LEDGER)},indent=2))
def main():
 p=argparse.ArgumentParser();p.add_argument("--regenerate",type=Path);a=p.parse_args()
 if a.regenerate is None:verify();return
 if a.regenerate.exists():raise SystemExit("refusing existing output: "+str(a.regenerate))
 d=produce();a.regenerate.parent.mkdir(parents=True,exist_ok=True);a.regenerate.write_text(json.dumps(d,indent=2,sort_keys=True)+"\n");print(json.dumps({"identity":"ASTRA","output":str(a.regenerate),"sha256":sha(a.regenerate)},indent=2))
if __name__=="__main__":main()
