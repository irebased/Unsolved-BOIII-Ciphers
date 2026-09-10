#!/usr/bin/env python3
"""Synthetic-only controls for the even-block empty-rectangle certificate."""
from __future__ import annotations
import argparse,hashlib,importlib.util,itertools,json,random
from pathlib import Path
import model
HERE=Path(__file__).resolve().parent;PACKAGE=HERE.parent;PROOF=PACKAGE/"even_period_invariant.py";LEDGER=HERE/"controls.json";SYMS="0123456789ABCDEF";PROOF_SHA="1fa72b75ff59028ed256dbf6853dd44669cd53b07bcce998331e212b65d2a2a2"
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def canonical(x):return json.dumps(x,sort_keys=True,indent=2)+"\n"
def load_proof():
 assert sha(PROOF)==PROOF_SHA;spec=importlib.util.spec_from_file_location("accepted_even_invariant",PROOF);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def slow(edges):
 edge=set(edges);records=[]
 for aset in model.FOURSETS:
  missing=[b for b in model.SYMBOLS if all((a,b) not in edge for a in aset)];records.append((aset,sum(1<<b for b in missing),len(missing)))
 best=max(records,key=lambda x:x[2]);return records,best
def check_graph(name,edges):
 fast=model.analyze(edges);slowrows,best=slow(edges);assert [(tuple(x["row_set"]),int(x["common_missing_columns_mask"],16),x["common_missing_count"]) for x in fast["row_set_records"]]==slowrows;assert fast["max_common_missing_count"]==best[2]
 if fast["witness"]:assert fast["witness"]["all_16_directed_edges_absent"]
 return {"name":name,"analysis":fast,"fast_equals_direct_slow_all_1820":True}
def coord(square):return {s:divmod(i,4) for i,s in enumerate(square)}
def inverse(square):return {(r,c):square[4*r+c] for r in range(4) for c in range(4)}
def decode_two(cipher,cs,ps,period):
 cc=coord(cs);pi=inverse(ps);out=[]
 for start in range(0,len(cipher),period):
  block=cipher[start:start+period];digits=[v for s in block for v in cc[s]];L=len(block);out.extend(pi[(digits[i],digits[L+i])] for i in range(L))
 return "".join(out)
def plaintext(seed):
 text=(f"ASTRA RECTANGLE CONTROL {seed}: EVERY FIXED SQUARE MUST PRESERVE THIS COMPLETE PRINTABLE MESSAGE. ".encode())
 return (text*((546+len(text)-1)//len(text)))[:546]
def construct(plain,cs,ps,period,proof):
 hx=plain.hex().upper();blocks=[]
 for start in range(0,len(hx),period):
  block=hx[start:start+period];assert len(block)%2==0;pairs=[proof.pair_map_two_inverse(block[i],block[i+1],cs,ps) for i in range(0,len(block),2)];blocks.append("".join(a for a,b in pairs)+"".join(b for a,b in pairs))
 return "".join(blocks)
def plant_case(index,period,cs,ps,proof):
 plain=plaintext(index);assert all((b>>4)!=1 for b in plain);cipher=construct(plain,cs,ps,period,proof);assert decode_two(cipher,cs,ps,period)==plain.hex().upper()
 pairs=list(proof.paired_cipher_symbols(cipher,period));mapped="".join(x for a,b in pairs for x in proof.pair_map_two(a,b,cs,ps));assert mapped==plain.hex().upper()
 edges={(int(a,16),int(b,16)) for a,b in pairs};analysis=check_graph(f"plant_{index}",edges)
 pr,pc=coord(ps)["1"];known_a={int(cs[4*pr+i],16) for i in range(4)};known_b={int(cs[4*pc+i],16) for i in range(4)};assert all((a,b) not in edges for a in known_a for b in known_b) and analysis["analysis"]["max_common_missing_count"]>=4
 return {"index":index,"period":period,"cipher_square":cs,"plain_square":ps,"same_square":cs==ps,"plaintext_sha256":hashlib.sha256(plain).hexdigest(),"ciphertext_hex_sha256":hashlib.sha256(cipher.encode()).hexdigest(),"literal_decode_matches":True,"pair_map_matches":True,"known_forbidden_high_nibble":"1","known_missing_rectangle":{"row_set":sorted(known_a),"column_set":sorted(known_b),"all_absent":True},"graph":analysis}
def build():
 proof=load_proof();complete={(a,b) for a in range(16) for b in range(16)};empty=set();A={0,1,2,3};B={4,5,6,7};missing={(a,b) for a in range(16) for b in range(16) if not (a in A and b in B)}
 graphs=[check_graph("complete",complete),check_graph("empty",empty),check_graph("planted_missing_4x4",missing)]
 rng=random.Random(20260911)
 for i in range(4):graphs.append(check_graph(f"random_{i}",{(a,b) for a in range(16) for b in range(16) if rng.randrange(2)}))
 assert graphs[0]["analysis"]["max_common_missing_count"]==0 and graphs[0]["analysis"]["excluded_bag213"]
 assert graphs[1]["analysis"]["max_common_missing_count"]==16 and not graphs[1]["analysis"]["excluded_bag213"]
 assert graphs[2]["analysis"]["max_common_missing_count"]>=4 and graphs[2]["analysis"]["witness"]
 squares=["0123456789ABCDEF","F0E1D2C3B4A59687","89ABCDEF01234567","13579BDF02468ACE","C840D951EA62FB73","5A0FC369D27E18B4"]
 specs=[(16,squares[0],squares[0]),(562,squares[1],squares[2]),(972,squares[3],squares[3]),(16,squares[4],squares[5]),(562,squares[2],squares[4]),(972,squares[5],squares[1])]
 plants=[plant_case(i,*spec,proof) for i,spec in enumerate(specs)]
 return {"identity":"ASTRA","target_evaluated":False,"rev7_read":False,"model":{"symbols":16,"row_set_count":len(model.FOURSETS),"test":"max over each four-symbol A of popcount(intersection of missing out-neighbors); max<4 proves no empty arbitrary A x B rectangle","relaxation":"A and B are allowed to overlap arbitrarily; actual cipher-square row sets are equal or disjoint"},"graph_controls":graphs,"full_546_byte_plants":plants,"source_hashes":{"model.py":sha(HERE/"model.py"),"controls.py":sha(Path(__file__)),"accepted_even_invariant.py":sha(PROOF)},"assertions":{"all_passed":True,"graph_controls":len(graphs)==7,"all_graphs_fast_slow_1820":all(x["fast_equals_direct_slow_all_1820"] for x in graphs),"six_full_plants":len(plants)==6,"all_plants_known_rectangle":all(x["known_missing_rectangle"]["all_absent"] for x in plants),"same_and_distinct_squares":{x["same_square"] for x in plants}=={True,False},"periods":sorted({x["period"] for x in plants})==[16,562,972]}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--regenerate",type=Path);a=ap.parse_args();got=build()
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit(f"refusing existing output: {a.regenerate}")
  a.regenerate.write_text(canonical(got));print(json.dumps({"identity":"ASTRA","output":str(a.regenerate),"sha256":sha(a.regenerate)}));return
 assert got==json.loads(LEDGER.read_text());print(json.dumps({"identity":"ASTRA","verified":True,"ledger_sha256":sha(LEDGER),"graph_controls":7,"plants":6}))
if __name__=="__main__":main()
