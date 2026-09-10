#!/usr/bin/env python3
"""Gated eight-cell stronger all-IV variant-B target driver."""
from __future__ import annotations
import argparse,hashlib,json,math,os
from pathlib import Path
from Crypto.Cipher import AES

HERE=Path(__file__).resolve().parent
REPO=HERE.parents[2]
MDX=REPO/"lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
GATE=HERE/"stronger_target_gate.json"
OUTPUT=HERE/"stronger_target_results.json"
IDENTITY="ASTRA"
WIDTHS=(13,14)
ORIENTATIONS=("forward","full_hex_reverse","byte_reverse","nibble_swap")
MDX_SHA="085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91"
CIPHER_SHA="5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
KEY=b"Zombies"+bytes(9)
IV_A=bytes(16)
IV_B=bytes.fromhex("00112233445566778899aabbccddeeff")
PUNCT3={0x93,0x94,0x98,0x99,0xA6}
ARTIFACTS={name:HERE/name for name in ("core.py","controls.py","controls.json",
 "stronger.py","stronger_controls.py","stronger_controls.json","run_stronger_target.py")}

def sha(path:Path)->str:return hashlib.sha256(path.read_bytes()).hexdigest()
def sha_bytes(value:bytes)->str:return hashlib.sha256(value).hexdigest()
def atomic_json(path:Path,value:dict)->None:
    tmp=path.with_name(path.name+".tmp")
    tmp.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    os.replace(tmp,path)

def extract()->str:
    text=MDX.read_text(encoding="utf-8")
    start=text.index("`83 B57B2")+1;end=text.index("`",start)
    value="".join(text[start:end].split()).upper()
    assert len(value)==1092 and sha_bytes(value.encode())==CIPHER_SHA
    return value

def orientations(value:str)->dict[str,str]:
    pairs=[value[i:i+2] for i in range(0,len(value),2)]
    return {"forward":value,"full_hex_reverse":value[::-1],
      "byte_reverse":"".join(reversed(pairs)),
      "nibble_swap":"".join(x[::-1] for x in pairs)}

def step(state:int,value:int)->int|None:
    if state==0:
        if value in {9,10,13} or 32<=value<=126:return 0
        if value==0xE2:return 1
        return None
    if state==1:return 2 if value==0x80 else None
    if state==2:return 0 if value in PUNCT3 else None
    raise AssertionError(state)

def independent_trace(suffix:bytes)->tuple[list[int],dict|None]:
    states={0,1,2}
    for offset,value in enumerate(suffix):
        before=sorted(states)
        states={q for state in states for q in [step(state,value)] if q is not None}
        if not states:
            return [],{"suffix_offset":offset,"chunk_relative_plaintext_offset":16+offset,
              "plaintext_byte":value,"states_before":before,"states_after":[]}
    return sorted(states),None

def direct_suffix(chunk:bytes)->bytes:
    assert len(chunk)>=16
    ecb=AES.new(KEY,AES.MODE_ECB)
    return bytes(chunk[i]^ecb.encrypt(chunk[i-16:i])[0] for i in range(16,len(chunk)))

def library_suffix(chunk:bytes,iv:bytes)->bytes:
    return AES.new(KEY,AES.MODE_CFB,iv=iv,segment_size=8).decrypt(chunk)[16:]

def require_gate()->tuple[dict,str]:
    if not GATE.exists():raise SystemExit("missing stronger_target_gate.json")
    gate=json.loads(GATE.read_text())
    assert gate["identity"]==IDENTITY and gate["target_evaluated"] is False
    assert gate["scope"]=={"cipher":"AES-128","key_hex":KEY.hex(),"mode":"CFB8",
      "iv_scope":"every external 16-byte IV","widths":[13,14],"variant":"B",
      "orientations":list(ORIENTATIONS),"cell_count":8,
      "endpoint_utf8_sequences":["e28093","e28094","e28098","e28099","e280a6"]}
    assert gate["expected_mdx_sha256"]==MDX_SHA and gate["expected_ciphertext_sha256"]==CIPHER_SHA
    assert sha(MDX)==MDX_SHA
    for name,path in ARTIFACTS.items():assert gate["artifact_hashes"][name]==sha(path)
    controls=json.loads((HERE/"stronger_controls.json").read_text())
    assert controls["identity"]==IDENTITY and controls["target_evaluated"] is False
    assert controls["rev7_file_read"] is False and controls["assertions"]["all_passed"] is True
    return gate,sha(GATE)

def selftest()->None:
    gate,gate_hash=require_gate()
    sample=bytes(range(42))
    suffix=direct_suffix(sample)
    assert suffix==library_suffix(sample,IV_A)==library_suffix(sample,IV_B)
    print(json.dumps({"identity":IDENTITY,"target_evaluated":False,
      "gate_sha256":gate_hash,"artifact_hashes_verified":True,
      "mdx_bytes_hashed_but_ciphertext_not_parsed":True,"selftest_passed":True},indent=2))

def run_target()->None:
    if OUTPUT.exists():raise SystemExit(f"refusing existing output: {OUTPUT}")
    gate,gate_hash=require_gate()
    canonical=extract();oriented=orientations(canonical)
    result={"identity":IDENTITY,"target_evaluated":True,"scope":gate["scope"],
      "gate_sha256":gate_hash,"mdx_sha256":sha(MDX),
      "ciphertext_sha256":sha_bytes(canonical.encode()),"cells":[],"complete":False}
    import sys
    sys.path.insert(0,str(HERE))
    import core,stronger
    for orientation in ORIENTATIONS:
        oriented_hex=oriented[orientation]
        observed=bytes.fromhex(oriented_hex)
        assert orientations(oriented_hex)[orientation]==canonical
        for width in WIDTHS:
            row=stronger.evaluate_any_bad(observed,width)
            independent=[]
            for witness in row["chunk_witnesses"]:
                rank=witness["observed_rank"];chunk=observed[rank::width]
                suffix=direct_suffix(chunk)
                assert suffix.hex()==witness["iv_independent_plaintext_suffix_hex"]
                assert suffix==library_suffix(chunk,IV_A)==library_suffix(chunk,IV_B)
                end_states,failure=independent_trace(suffix)
                assert end_states==witness["end_state_set"]
                assert failure==witness["first_failure"]
                independent.append({"observed_rank":rank,
                  "ciphertext_chunk_hex":chunk.hex(),"ciphertext_chunk_sha256":sha_bytes(chunk),
                  "iv_independent_plaintext_suffix_hex":suffix.hex(),
                  "iv_independent_plaintext_suffix_sha256":sha_bytes(suffix),
                  "library_two_iv_suffixes_match_direct_recurrence":True,
                  "end_state_set":end_states,"first_failure":failure,
                  "chunk_rejected":failure is not None})
            rejected=[x["observed_rank"] for x in independent if x["chunk_rejected"]]
            assert rejected==row["rejected_chunk_ranks"]
            strong_complete=bool(rejected)
            strong_weight=math.factorial(width) if strong_complete else 0
            assert row["stronger_certificate_weight"]==strong_weight
            cell={"orientation":orientation,
              "oriented_hex_sha256":sha_bytes(oriented_hex.encode()),
              "observed_bytes_sha256":sha_bytes(observed),
              "width":width,"rows":len(observed)//width,"variant":"B",
              "iv_scope":"every external 16-byte IV",
              "chunk_witnesses":independent,"rejected_chunk_ranks":rejected,
              "retained_chunk_ranks":[x["observed_rank"] for x in independent if not x["chunk_rejected"]],
              "original_first_column_rejected_weight":row["original_first_column_rejected_weight"],
              "stronger_certificate_weight":strong_weight,
              "expected_completion_weight":math.factorial(width),
              "complete_every_iv_every_order_exclusion":strong_complete,
              "unresolved":not strong_complete,
              "canonical_reconstruction_from_orientation":True}
            result["cells"].append(cell);atomic_json(OUTPUT,result)
    assert len(result["cells"])==8
    result["complete"]=all(x["complete_every_iv_every_order_exclusion"] for x in result["cells"])
    result["summary"]={"cells":8,
      "complete_every_iv_every_order_exclusions":sum(x["complete_every_iv_every_order_exclusion"] for x in result["cells"]),
      "unresolved_cells":sum(x["unresolved"] for x in result["cells"]),
      "rejected_chunk_witnesses":sum(len(x["rejected_chunk_ranks"]) for x in result["cells"])}
    atomic_json(OUTPUT,result)
    print(json.dumps({"identity":IDENTITY,"output":str(OUTPUT),
      "sha256":sha(OUTPUT),"summary":result["summary"]},indent=2))

def main()->None:
    p=argparse.ArgumentParser();g=p.add_mutually_exclusive_group(required=True)
    g.add_argument("--selftest",action="store_true");g.add_argument("--run-target",action="store_true")
    a=p.parse_args();selftest() if a.selftest else run_target()
if __name__=="__main__":main()
