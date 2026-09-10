#!/usr/bin/env python3
"""Gated 124-cell ragged-B all-IV necessary-prefix target driver."""
import argparse,hashlib,json,math,os,sys
from pathlib import Path
from Crypto.Cipher import AES
HERE=Path(__file__).resolve().parent; REPO=HERE.parents[3]
MDX=REPO/"lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
GATE=HERE/"target_gate.json"; OUTPUT=HERE/"target_results.json"
PRIOR=HERE.parent/"stronger_target_results.json"
IDENTITY="ASTRA"; WIDTHS=tuple(range(2,33))
ORIENTATIONS=("forward","full_hex_reverse","byte_reverse","nibble_swap")
MDX_SHA="085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91"
CIPHER_SHA="5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
KEY=b"Zombies"+bytes(9); IVS=(bytes(16),bytes.fromhex("00112233445566778899aabbccddeeff"))
P3={0x93,0x94,0x98,0x99,0xA6}
ARTIFACTS={"core.py":HERE/"core.py","controls.py":HERE/"controls.py",
 "controls.json":HERE/"controls.json","run_target.py":HERE/"run_target.py",
 "prior_stronger_target_results.json":PRIOR}
def sha_bytes(x):return hashlib.sha256(x).hexdigest()
def sha(p):return sha_bytes(Path(p).read_bytes())
def atomic(path,value):
    t=path.with_name(path.name+".tmp");t.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n");os.replace(t,path)
def extract():
    text=MDX.read_text();a=text.index("`83 B57B2")+1;b=text.index("`",a)
    value="".join(text[a:b].split()).upper()
    assert len(value)==1092 and sha_bytes(value.encode())==CIPHER_SHA
    return value
def orient(value):
    pairs=[value[i:i+2] for i in range(0,len(value),2)]
    return {"forward":value,"full_hex_reverse":value[::-1],
      "byte_reverse":"".join(reversed(pairs)),"nibble_swap":"".join(x[::-1] for x in pairs)}
def ind_step(s,b):
    if s==0:
        if b in {9,10,13} or 32<=b<=126:return 0
        return 1 if b==0xe2 else None
    if s==1:return 2 if b==0x80 else None
    if s==2:return 0 if b in P3 else None
    raise AssertionError
def ind_trace(data):
    states={0,1,2};failure=None
    for off,b in enumerate(data):
        before=sorted(states);states={v for s in states if (v:=ind_step(s,b)) is not None}
        if not states:
            failure={"suffix_offset":off,"chunk_plaintext_offset":16+off,
              "plaintext_byte":b,"states_before":before,"states_after":[]};break
    return sorted(states),failure
def direct_suffix(p):
    e=AES.new(KEY,AES.MODE_ECB)
    return bytes(p[i]^e.encrypt(p[i-16:i])[0] for i in range(16,len(p)))
def library_suffix(p,iv):
    return AES.new(KEY,AES.MODE_CFB,iv=iv,segment_size=8).decrypt(p)[16:]
def require_gate():
    if not GATE.exists():raise SystemExit("missing target_gate.json")
    g=json.loads(GATE.read_text())
    assert g["identity"]==IDENTITY and g["target_evaluated"] is False
    expected={"cipher":"AES-128","key_hex":KEY.hex(),"mode":"CFB8",
      "iv_scope":"every external 16-byte IV","widths":list(WIDTHS),
      "variant":"B","ragged_conventions":["first","last"],
      "orientations":list(ORIENTATIONS),"cell_count":124,
      "prior_covered_cells":8,"new_contexts":116,
      "endpoint_utf8_sequences":["e28093","e28094","e28098","e28099","e280a6"]}
    assert g["scope"]==expected and g["expected_mdx_sha256"]==MDX_SHA
    assert g["expected_ciphertext_sha256"]==CIPHER_SHA and sha(MDX)==MDX_SHA
    for name,p in ARTIFACTS.items():assert g["artifact_hashes"][name]==sha(p),(name,sha(p))
    controls=json.loads((HERE/"controls.json").read_text())
    assert controls["identity"]==IDENTITY and controls["target_evaluated"] is False
    assert controls["rev7_file_read"] is False and controls["assertions"]["all_passed"]
    prior=json.loads(PRIOR.read_text())
    assert prior["identity"]==IDENTITY and prior["target_evaluated"] is True
    assert prior["ciphertext_sha256"]==CIPHER_SHA and len(prior["cells"])==8
    assert all(x["complete_every_iv_every_order_exclusion"] for x in prior["cells"])
    return g,sha(GATE),prior
def independent_witness(observed,w,raw):
    rank=raw["rank"];q=len(observed)//w;p=observed[rank:q*w:w]
    tail=direct_suffix(p)
    assert p.hex()==raw["prefix_hex"] and sha_bytes(p)==raw["prefix_sha256"]
    assert tail.hex()==raw["suffix_hex"] and sha_bytes(tail)==raw["suffix_sha256"]
    assert tail==library_suffix(p,IVS[0])==library_suffix(p,IVS[1])
    states,fail=ind_trace(tail)
    assert states==raw["end_states"] and fail==raw["first_failure"]
    return {"observed_rank":rank,"slice":raw["slice"],
      "guaranteed_prefix_hex":p.hex(),"guaranteed_prefix_sha256":sha_bytes(p),
      "guaranteed_prefix_bytes":len(p),"iv_independent_suffix_hex":tail.hex(),
      "iv_independent_suffix_sha256":sha_bytes(tail),"suffix_bytes":len(tail),
      "two_library_iv_suffixes_match_separate_recurrence":True,
      "end_states":states,"rejected":not states,"first_failure":fail}
def regression(prior,orientation,w,witness,observed_sha):
    if w not in (13,14):return None
    old=next(x for x in prior["cells"] if x["orientation"]==orientation and x["width"]==w)
    assert old["observed_bytes_sha256"]==observed_sha and old["complete_every_iv_every_order_exclusion"]
    ow=next(x for x in old["chunk_witnesses"] if x["observed_rank"]==witness["observed_rank"])
    assert ow["ciphertext_chunk_hex"]==witness["guaranteed_prefix_hex"]
    assert ow["iv_independent_plaintext_suffix_hex"]==witness["iv_independent_suffix_hex"]
    assert ow["chunk_rejected"]==witness["rejected"]
    return {"prior_cell_complete":True,"prior_rejected_rank_replayed":witness["observed_rank"],
      "prefix_and_suffix_exact_match":True}
def selftest():
    g,gh,prior=require_gate()
    sample=bytes(range(42));tail=direct_suffix(sample)
    assert tail==library_suffix(sample,IVS[0])==library_suffix(sample,IVS[1])
    print(json.dumps({"identity":IDENTITY,"target_evaluated":False,"gate_sha256":gh,
      "artifact_hashes_verified":True,"prior_eight_cells_verified":len(prior["cells"]),
      "mdx_bytes_hashed_but_ciphertext_not_parsed":True,"selftest_passed":True},indent=2))
def run():
    if OUTPUT.exists():raise SystemExit("refusing existing "+str(OUTPUT))
    g,gh,prior=require_gate();canonical=extract();oriented=orient(canonical)
    sys.path.insert(0,str(HERE));import core
    result={"identity":IDENTITY,"target_evaluated":True,"scope":g["scope"],
      "gate_sha256":gh,"mdx_sha256":sha(MDX),"ciphertext_sha256":CIPHER_SHA,
      "cells":[],"evaluation_complete":False}
    for oname in ORIENTATIONS:
      oh=oriented[oname];observed=bytes.fromhex(oh)
      assert orient(oh)[oname]==canonical
      for w in WIDTHS:
        raw=core.evaluate(observed,w,True);assert raw["supported"] and raw["q"]==546//w
        checks=[independent_witness(observed,w,x) for x in raw["inspected"]]
        assert len(checks)==raw["ranks_examined"]
        bad=[x for x in checks if x["rejected"]]
        assert bool(bad)==raw["complete_every_iv_every_order_exclusion"]
        if bad:assert len(bad)==1 and bad[0]["observed_rank"]==raw["rejected_rank"]
        weight=math.factorial(w) if bad else 0
        cell={"orientation":oname,"oriented_hex_sha256":sha_bytes(oh.encode()),
          "observed_bytes_sha256":sha_bytes(observed),"width":w,"q":raw["q"],"r":raw["r"],
          "variant":"B","ragged_conventions":["first","last"],"conventions_alias":raw["conventions_alias"],
          "iv_scope":"every external 16-byte IV","ranks_examined":len(checks),
          "examined_chunks":checks,"rejected_rank":raw["rejected_rank"],
          "completion_weight_per_convention":weight,"expected_weight_per_convention":math.factorial(w),
          "weights_across_conventions_not_added":True,
          "complete_every_iv_every_order_exclusion":bool(bad),"unresolved":not bad,
          "prior_width13_14_regression":regression(prior,oname,w,bad[0],sha_bytes(observed)) if bad else None,
          "canonical_reconstruction_from_orientation":True}
        result["cells"].append(cell);atomic(OUTPUT,result)
    assert len(result["cells"])==124
    regress=[x for x in result["cells"] if x["width"] in (13,14)]
    assert len(regress)==8 and all(x["prior_width13_14_regression"] for x in regress)
    result["evaluation_complete"]=True
    result["summary"]={"cells":124,"closed_cells":sum(x["complete_every_iv_every_order_exclusion"] for x in result["cells"]),
      "unresolved_cells":sum(x["unresolved"] for x in result["cells"]),
      "ranks_examined":sum(x["ranks_examined"] for x in result["cells"]),
      "prior_covered_cells_regressed":8,"new_contexts":116,
      "all_cells_closed":all(x["complete_every_iv_every_order_exclusion"] for x in result["cells"])}
    atomic(OUTPUT,result)
    print(json.dumps({"identity":IDENTITY,"output":str(OUTPUT),"sha256":sha(OUTPUT),"summary":result["summary"]},indent=2))
def main():
    p=argparse.ArgumentParser();g=p.add_mutually_exclusive_group(required=True)
    g.add_argument("--selftest",action="store_true");g.add_argument("--run-target",action="store_true")
    a=p.parse_args();selftest() if a.selftest else run()
if __name__=="__main__":main()
