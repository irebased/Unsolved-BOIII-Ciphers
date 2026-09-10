#!/usr/bin/env python3
"""Pack/unpack adjacency certificates losslessly without cipher evaluation."""
import argparse,copy,hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];FULL=HERE/"target_results.json";PACKAGE=HERE/"certificate_package.json";MDX=ROOT/"lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
FULL_SHA="d208d2a06218faf16e5caa16bbf13585e39ac7e82b395528e76c20140ec2a6e7";P3={147,148,152,153,166}
H=lambda x:hashlib.sha256(x).hexdigest()
def orientations(v):
 p=[v[i:i+2] for i in range(0,len(v),2)];return {"forward":v,"full_hex_reverse":v[::-1],"byte_reverse":"".join(reversed(p)),"nibble_swap":"".join(x[::-1] for x in p)}
def canonical_orientations():
 t=MDX.read_text();a=t.index("`83 B57B2")+1;b=t.index("`",a);return orientations("".join(t[a:b].split()).upper())
def failure(suffix,b):
 states={0,1,2}
 for off,x in enumerate(suffix):
  before=sorted(states);after=set()
  for s in states:
   if s==0:v=0 if x in {9,10,13} or 32<=x<=126 else (1 if x==226 else None)
   elif s==1:v=2 if x==128 else None
   else:v=0 if x in P3 else None
   if v is not None:after.add(v)
  states=after
  if not states:return [],{"suffix_offset":off,"pair_plaintext_offset":b+off,"plaintext_byte":x,"states_before":before,"states_after":[]}
 return sorted(states),None
def unpack(package):
 assert package["identity"]=="ASTRA" and package["schema"]["bad_edge_row"]==["from_rank","to_rank","suffix_hex"]
 result=copy.deepcopy(package["result"]);O=canonical_orientations()
 for cell in result["cells"]:
  cert=cell["exclusion_certificate"];table=cert.pop("bad_edge_table");obs=bytes.fromhex(O[cell["orientation"]]);w=cell["width"];b=cell["block_size"];rows=[]
  for a,z,hx in table:
   pair=obs[a::w]+obs[z::w];suffix=bytes.fromhex(hx);states,fail=failure(suffix,b);assert not states and fail
   rows.append({"from_rank":a,"to_rank":z,"pair_sha256":H(pair),"suffix_hex":hx,"suffix_sha256":H(suffix),"suffix_bytes":len(suffix),"end_states":[],"edge_retained":False,"first_failure":fail,"two_iv_check":True})
  cert["bad_edge_witnesses"]=rows
 return result
def pack():
 if PACKAGE.exists():raise SystemExit("refusing existing "+str(PACKAGE))
 full=json.loads(FULL.read_text());assert H((json.dumps(full,indent=2,sort_keys=True)+"\n").encode())==FULL_SHA
 result=copy.deepcopy(full)
 for cell in result["cells"]:
  cert=cell["exclusion_certificate"];rows=cert.pop("bad_edge_witnesses");cert["bad_edge_table"]=[[x["from_rank"],x["to_rank"],x["suffix_hex"]] for x in rows]
 package={"identity":"ASTRA","schema":{"version":1,"bad_edge_row":["from_rank","to_rank","suffix_hex"],
  "derivations":{"pair_sha256":"SHA256(canonical-oriented[from_rank::width] || canonical-oriented[to_rank::width])","suffix_sha256":"SHA256(decoded suffix_hex)","suffix_bytes":"len(decoded suffix_hex)","end_states_and_first_failure":"registered five-sequence FSA from states {0,1,2}","edge_retained":False,"two_iv_check":True},
  "reconstruction":"Replace each bad_edge_table with fully derived bad_edge_witnesses; all other result fields are stored verbatim."},"result":result}
 reconstructed=unpack(package);assert reconstructed==full and H((json.dumps(reconstructed,indent=2,sort_keys=True)+"\n").encode())==FULL_SHA
 PACKAGE.write_text(json.dumps(package,sort_keys=True,separators=(",",":"))+"\n")
 print(json.dumps({"identity":"ASTRA","package":str(PACKAGE),"sha256":H(PACKAGE.read_bytes()),"bytes":PACKAGE.stat().st_size,"reconstructed_full_sha256":FULL_SHA},indent=2))
def verify():
 package=json.loads(PACKAGE.read_text());result=unpack(package);assert H((json.dumps(result,indent=2,sort_keys=True)+"\n").encode())==FULL_SHA
 print(json.dumps({"identity":"ASTRA","verified":True,"package_sha256":H(PACKAGE.read_bytes()),"reconstructed_full_sha256":FULL_SHA,"crypto_evaluation":False},indent=2))
def main():
 p=argparse.ArgumentParser();g=p.add_mutually_exclusive_group(required=True);g.add_argument("--pack",action="store_true");g.add_argument("--verify",action="store_true");a=p.parse_args();pack() if a.pack else verify()
if __name__=="__main__":main()
