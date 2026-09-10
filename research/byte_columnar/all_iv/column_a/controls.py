#!/usr/bin/env python3
"""Read-only verifier and explicit synthetic control regenerator for column A."""
import argparse,hashlib,itertools,json,math,platform,random,subprocess,sys,tempfile,importlib.util
from pathlib import Path
from Crypto.Cipher import DES,Blowfish
HERE=Path(__file__).resolve().parent;LEDGER=HERE/"controls.json";FABLE=HERE/"fable";CS=HERE/"compat_source"
sys.path.insert(0,str(HERE));import core
EXPECTED_FABLE={"transpositions.js":"89f2b3c8fa5cd5144d3c2baf2e2d25edb1dcb2f3b0f7a056a506841e6438ccc6","byteTranspositions.js":"c9c09bd405bbe43b853a5efb0e25f58ae67136a5f83653e7c45c3a2f3879b7f0"}
EXPECTED_COMPAT={"blowfish-compat.c":"3584374a6bae4df8899e82d36255bbac0472904aed2095e3c08c57a5dd5b4cad","blowfish.h":"bb4a14ecbd5dc92105b290d9261ed562a980c6e42b0d9b4b56e62b4b6c39665b","COPYING.LIB":"ca0061fc1381a3ab242310e4b3f56389f28e3d460eb2fd822ed7a21c6f030532","libdefs.h":"cdffb7ef7bc27b6eea90b73174077c377d8260ffd111fb8de3c2bbc938e28a31","mcrypt_modules.h":"2fefe3d60795fb19e7a7be1c4cec18a97c069e2471ae61c951706020dcb6c180"}
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def verify_sources():
 assert {n:sha(FABLE/n) for n in EXPECTED_FABLE}==EXPECTED_FABLE
 assert {n:sha(CS/n) for n in EXPECTED_COMPAT}==EXPECTED_COMPAT
def toy_block(block):return (sum((i+3)*x for i,x in enumerate(block))^(block[0]*17)^(block[-1]*29))&255
def oracle(observed,w,b,fn,allowed):
 q=len(observed)//w;sets={};accepted=0
 for slots in itertools.permutations(range(w)):
  ok=all((observed[slots[b]*q+r]^fn(bytes(observed[slots[j]*q+r] for j in range(b)))) in allowed for r in range(q))
  if ok:accepted+=1;sets.setdefault(slots[:b],set()).add(slots[b])
 return sets,accepted
def one_toy(observed,w,b,allowed,label):
 ref=core.scan_first_block_prefixes(observed,w,b,toy_block,allowed);sets,count=oracle(observed,w,b,toy_block,allowed)
 got={tuple(x["first_slots"]):set(x["surviving_ninth_ranks"]) for x in ref["survivor_prefixes"]};assert got==sets
 expected=sum(len(v)*math.factorial(w-b-1) for v in sets.values());assert count==expected
 assert ref["unresolved_completion_weight"]==len(got)*math.factorial(w-b)
 return {"label":label,"block_size":b,"width":w,"rows":len(observed)//w,"observed_hex":observed.hex(),"allowed":sorted(allowed),"prefixes_examined":ref["prefixes_examined"],"rejected_prefixes":ref["rejected_prefixes"],"survivor_prefix_count":ref["survivor_prefix_count"],"accepted_full_permutations_at_ninth_constraint":count,"prefix_sets_exact":True,"factorial_partition_complete":True}
def fable_audit():
 js=f"""const B=require({json.dumps(str(FABLE/'byteTranspositions.js'))});const o=[2,0,1],m=B.columnarA(12,3,o,'first'),b=Buffer.from([...Array(12).keys()]);console.log(JSON.stringify({{mapping:m,inverse:B.applyInverseBytes(b,m).toString('hex')}}));"""
 x=json.loads(subprocess.check_output(["node","-e",js],text=True));order=(2,0,1);slots=core.inverse_order(order);ours=core.invert_variant_a(bytes(range(12)),3,order)
 assert x["inverse"]==ours.hex()=="040800050901060a02070b03" and slots==(1,2,0) and core.observe_variant_a(ours,3,order)==bytes(range(12))
 return {"fable_order":list(order),"slots":list(slots),"mapping":x["mapping"],"inverse_hex":x["inverse"],"matched":True}
def cfb_encrypt(pt,iv,first):
 reg=iv;out=bytearray()
 for x in pt:y=x^first(reg);out.append(y);reg=reg[1:]+bytes([y])
 return bytes(out)
def word_reverse(x):return x[3::-1]+x[7:3:-1]
def conjugated(block):
 return word_reverse(Blowfish.new(b"Zombies",Blowfish.MODE_ECB).encrypt(word_reverse(block)))
def produce():
 verify_sources();fixture=fable_audit();rng=random.Random(20260910);toys=[]
 toys.append(one_toy(bytes(4),2,1,{0},"explicit_all_prefixes_survive_positive"))
 toys.append(one_toy(bytes.fromhex("000102030405"),3,1,{255},"explicit_all_prefixes_reject_negative"))
 assert toys[0]["survivor_prefix_count"]>0 and toys[1]["survivor_prefix_count"]==0
 for b in range(1,4):
  for w in (b+1,b+2):
   for q in (1,2,3):
    observed=bytes(rng.randrange(8) for _ in range(w*q));allowed={x for x in range(8) if rng.randrange(2)} or {rng.randrange(8)}
    toys.append(one_toy(observed,w,b,allowed,"deterministic_random"))
 spec=importlib.util.spec_from_file_location("column_a_build",CS/"build_compat.py");buildmod=importlib.util.module_from_spec(spec);spec.loader.exec_module(buildmod)
 with tempfile.TemporaryDirectory(prefix="column-a-compat-") as td:
  lib=Path(td)/"libblowfish_compat.so";command=buildmod.build(lib);actual=buildmod.load(lib)
  vector_blocks=(bytes(range(8)),b"00000000",bytes.fromhex("a1b2c3d4e5f60718"))
  assert all(actual(b"Zombies",x)==conjugated(x) for x in vector_blocks)
  compiled={"command":["clang","-shared","-fPIC","-O2","-I","compat_source","compat_source/blowfish-compat.c","-o","<temporary>/libblowfish_compat.so"],"compiler_version":subprocess.check_output(["clang","--version"],text=True).splitlines()[0],"temporary_binary_sha256":sha(lib),"distinct_c_vs_conjugation_blocks":len(vector_blocks)}
  width=10;q=16;order=(9,1,7,0,5,8,3,6,2,4);slots=core.inverse_order(order);prefix=slots[:8];ninth=slots[8]
  base=("ALPHA – BETA — GAMMA ‘DELTA’ … END. ").encode();pt=(base*((width*q+len(base)-1)//len(base)))[:width*q]
  assert all(x in core.A105 for x in pt)
  des=DES.new(b"Zombies\0",DES.MODE_ECB);bf=Blowfish.new(b"Zombies",Blowfish.MODE_ECB)
  backs={"des":(lambda x:des.encrypt(x)[0],[bytes.fromhex("0011223344556677"),bytes.fromhex("fedcba9876543210")]),
   "blowfish":(lambda x:bf.encrypt(x)[0],[bytes.fromhex("1020304050607080"),bytes.fromhex("8877665544332211")]),
   "blowfish_compat":(lambda x:actual(b"Zombies",x)[0],[bytes.fromhex("13579bdf2468ace0"),bytes.fromhex("0123456789abcdef")])}
  plants=[]
  for name,(first,ivs) in backs.items():
   for iv in ivs:
    ct=cfb_encrypt(pt,iv,first)
    if name=="des":assert ct==DES.new(b"Zombies\0",DES.MODE_CFB,iv=iv,segment_size=8).encrypt(pt)
    elif name=="blowfish":assert ct==Blowfish.new(b"Zombies",Blowfish.MODE_CFB,iv=iv,segment_size=8).encrypt(pt)
    else:assert ct==cfb_encrypt(pt,iv,lambda x:conjugated(x)[0])
    obs=core.observe_variant_a(ct,width,order);row=core.evaluate_first_block_tuple(obs,width,8,prefix,first,core.A105);assert row["surviving_ninth_ranks"]==[ninth]
    for r in range(q):
     block=bytes(obs[prefix[j]*q+r] for j in range(8));assert block==ct[r*width:r*width+8]
     assert (obs[ninth*q+r]^first(block))==pt[r*width+8]
    plants.append({"backend":name,"iv_hex":iv.hex(),"width":width,"rows":q,"fable_order":list(order),"fixed_first_eight_slots":list(prefix),"true_ninth_rank":ninth,"surviving_ninth_ranks":[ninth],"true_ninth_uniquely_retained":True,"plaintext_sha256":hashlib.sha256(pt).hexdigest(),"ciphertext_sha256":hashlib.sha256(ct).hexdigest(),"observed_sha256":hashlib.sha256(obs).hexdigest(),"all_rows_checked":True})
 out={"identity":"ASTRA","target_evaluated":False,"rev7_read":False,"scope":"Synthetic rectangular FABLE columnarA 8-byte CFB first-block prefix certificate.",
  "definition_audit":fixture,"proof":{"equation":"C[row*w+j] = observed[slots[j]*q+row], slots=inverse(FABLE order)","all_iv":"For w>8, position row*w+8 uses preceding natural ciphertext columns 0..7 and contains no IV bytes.","empty_mask":"Rejects exactly (w-8)! completions; first-eight tuples partition w!."},
  "allowed_bytes":{"count":len(core.A105),"model":"necessary relaxed byte set, not strict UTF-8 FSA"},
  "source_hashes":{"core.py":sha(HERE/"core.py"),"controls.py":sha(Path(__file__)),"build_compat.py":sha(CS/"build_compat.py"),"fable_PROVENANCE.md":sha(FABLE/"PROVENANCE.md"),"compat_PROVENANCE.md":sha(CS/"PROVENANCE.md"),**{"fable/"+n:v for n,v in EXPECTED_FABLE.items()},**{"compat_source/"+n:v for n,v in EXPECTED_COMPAT.items()}},
  "compat_regeneration":compiled,"toy_controls":toys,"toy_control_count":len(toys),"explicit_positive_toy_count":sum(x["label"]=="explicit_all_prefixes_survive_positive" for x in toys),
  "actual_plants":plants,"actual_plant_count":len(plants),"structural_counts":{"13":{"prefixes":math.perm(13,8),"weight":math.factorial(5)},"14":{"prefixes":math.perm(14,8),"weight":math.factorial(6)}},
  "runtime":{"python":platform.python_version(),"pycryptodome":__import__("Crypto").__version__,"node":subprocess.check_output(["node","--version"],text=True).strip()},
  "assertions":{"all_passed":True,"vendored_fable_exact":True,"source_built_compat_distinct_conjugation":True,"toy_oracle_exact":True,"explicit_positive_nonvacuous":True,"six_true_ninth_plants_unique":True,"no_target_read":True}}
 return out
def verify():
 verify_sources();d=json.loads(LEDGER.read_text());assert d["identity"]=="ASTRA" and d["target_evaluated"] is False and d["rev7_read"] is False and d["assertions"]["all_passed"]
 assert d["source_hashes"]["core.py"]==sha(HERE/"core.py") and d["source_hashes"]["controls.py"]==sha(Path(__file__)) and d["source_hashes"]["build_compat.py"]==sha(CS/"build_compat.py")
 assert d["source_hashes"]["fable_PROVENANCE.md"]==sha(FABLE/"PROVENANCE.md") and d["source_hashes"]["compat_PROVENANCE.md"]==sha(CS/"PROVENANCE.md")
 assert d["definition_audit"]==fable_audit() and d["toy_control_count"]==20 and d["explicit_positive_toy_count"]==1 and d["actual_plant_count"]==6
 print(json.dumps({"identity":"ASTRA","verified":True,"ledger_sha256":sha(LEDGER),"read_only":True,"compiled_binary_required":False},indent=2))
def main():
 p=argparse.ArgumentParser();p.add_argument("--regenerate",type=Path);a=p.parse_args()
 if a.regenerate is None:verify();return
 if a.regenerate.exists():raise SystemExit("refusing existing output: "+str(a.regenerate))
 d=produce();a.regenerate.parent.mkdir(parents=True,exist_ok=True);a.regenerate.write_text(json.dumps(d,indent=2,sort_keys=True)+"\n");print(json.dumps({"identity":"ASTRA","output":str(a.regenerate),"sha256":sha(a.regenerate)},indent=2))
if __name__=="__main__":main()
