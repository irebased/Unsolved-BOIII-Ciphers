#!/usr/bin/env python3
"""Gated 16-cell Rev7 byte-column target driver. No target work without --run-target."""
from __future__ import annotations
import argparse, hashlib, json, math, os, subprocess
from pathlib import Path
from Crypto.Cipher import AES

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
MDX = REPO / "lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
GATE = HERE / "target_gate.json"
OUTPUT = HERE / "target_results.json"
BIN = HERE / "native_search"
IDENTITY = "ASTRA"
NODE_LIMIT = 10_000_000
WIDTHS = (13,14)
VARIANTS = ("A","B")
ORIENTATIONS = ("forward","full_hex_reverse","byte_reverse","nibble_swap")
EXPECTED_MDX_SHA256 = "085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91"
EXPECTED_CIPHER_SHA256 = "5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
AES_KEY = b"Zombies" + bytes(9)
AES_IV = b"0"*16
PUNCT3 = {0x93,0x94,0x98,0x99,0xA6}

ARTIFACTS = {
  "core.py": HERE/"core.py",
  "native.cpp": HERE/"native.cpp",
  "native_search": HERE/"native_search",
  "controls.py": HERE/"controls.py",
  "controls.json": HERE/"controls.json",
  "generate_fable_fixtures.js": HERE/"generate_fable_fixtures.js",
  "run_target.py": HERE/"run_target.py",
}

def sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()

def sha(path: Path) -> str:
    return sha_bytes(path.read_bytes())

def atomic_json(path: Path, value: dict) -> None:
    temporary = path.with_name(path.name+".tmp")
    temporary.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    os.replace(temporary,path)

def fsa_step(state: int, value: int) -> int | None:
    if state == 0:
        if value in {9,10,13} or 32 <= value <= 126: return 0
        if value == 0xE2: return 1
        return None
    if state == 1: return 2 if value == 0x80 else None
    if state == 2: return 0 if value in PUNCT3 else None
    raise AssertionError(state)

def fsa_valid(data: bytes) -> bool:
    state = 0
    for value in data:
        state = fsa_step(state,value)
        if state is None: return False
    return state == 0

def orientations(value: str) -> dict[str,str]:
    assert len(value)%2 == 0
    pairs=[value[i:i+2] for i in range(0,len(value),2)]
    return {
      "forward":value,
      "full_hex_reverse":value[::-1],
      "byte_reverse":"".join(reversed(pairs)),
      "nibble_swap":"".join(pair[::-1] for pair in pairs),
    }

def extract_ciphertext() -> str:
    text=MDX.read_text(encoding="utf-8")
    start=text.index("`83 B57B2")+1
    end=text.index("`",start)
    value="".join(text[start:end].split()).upper()
    assert len(value)==1092 and all(c in "0123456789ABCDEF" for c in value)
    assert sha_bytes(value.encode("ascii"))==EXPECTED_CIPHER_SHA256
    return value

def inverse_column(observed: bytes,width: int,order: list[int],variant: str) -> bytes:
    assert len(observed)%width==0 and sorted(order)==list(range(width))
    rows=len(observed)//width
    out=bytearray(len(observed))
    if variant=="A":
        for rank,col in enumerate(order):
            for row in range(rows): out[row*width+col]=observed[rank*rows+row]
    elif variant=="B":
        for row in range(rows):
            for rank,col in enumerate(order): out[col*rows+row]=observed[row*width+rank]
    else: raise AssertionError(variant)
    return bytes(out)

def forward_column(ciphertext: bytes,width: int,order: list[int],variant: str) -> bytes:
    assert len(ciphertext)%width==0 and sorted(order)==list(range(width))
    rows=len(ciphertext)//width
    out=bytearray(len(ciphertext))
    if variant=="A":
        for rank,col in enumerate(order):
            for row in range(rows): out[rank*rows+row]=ciphertext[row*width+col]
    elif variant=="B":
        for row in range(rows):
            for rank,col in enumerate(order): out[row*width+rank]=ciphertext[col*rows+row]
    else: raise AssertionError(variant)
    return bytes(out)

def library_cfb8(data: bytes,decrypt: bool) -> bytes:
    cipher=AES.new(AES_KEY,AES.MODE_CFB,iv=AES_IV,segment_size=8)
    return cipher.decrypt(data) if decrypt else cipher.encrypt(data)

def require_gate() -> tuple[dict,str]:
    if not GATE.exists(): raise SystemExit("missing target_gate.json")
    gate=json.loads(GATE.read_text())
    assert gate["identity"]==IDENTITY and gate["target_evaluated"] is False
    assert gate["scope"]=={
      "cipher":"AES-128","key_hex":AES_KEY.hex(),"iv_hex":AES_IV.hex(),"mode":"CFB8",
      "widths":list(WIDTHS),"variants":list(VARIANTS),"orientations":list(ORIENTATIONS),
      "node_limit_per_cell":NODE_LIMIT,"cell_count":16,
      "endpoint_utf8_sequences":["e28093","e28094","e28098","e28099","e280a6"]}
    assert gate["expected_mdx_sha256"]==EXPECTED_MDX_SHA256
    assert gate["expected_ciphertext_sha256"]==EXPECTED_CIPHER_SHA256
    assert sha(MDX)==EXPECTED_MDX_SHA256
    for name,path in ARTIFACTS.items():
        assert gate["artifact_hashes"][name]==sha(path),(name,sha(path),gate["artifact_hashes"][name])
    controls=json.loads((HERE/"controls.json").read_text())
    assert controls["identity"]==IDENTITY and controls["target_evaluated"] is False
    assert controls["rev7_file_read"] is False and controls["assertions"]["all_passed"] is True
    return gate,sha(GATE)

def native(observed: bytes,width: int,variant: str) -> dict:
    row=json.loads(subprocess.check_output(
      [str(BIN),str(width),variant,str(NODE_LIMIT),observed.hex()],text=True))
    assert row["identity"]==IDENTITY and row["width"]==width and row["variant"]==variant
    assert row["node_limit"]==NODE_LIMIT
    return row

def validate_solution(observed: bytes,width: int,variant: str,solution: dict) -> dict:
    order=solution["order"]
    ciphertext=inverse_column(observed,width,order,variant)
    plaintext=library_cfb8(ciphertext,True)
    assert plaintext.hex()==solution["plaintext_hex"]
    assert fsa_valid(plaintext)
    assert library_cfb8(plaintext,False)==ciphertext
    assert forward_column(ciphertext,width,order,variant)==observed
    return {
      "order":order,
      "plaintext_hex":plaintext.hex(),
      "plaintext_sha256":sha_bytes(plaintext),
      "ciphertext_sha256":sha_bytes(ciphertext),
      "library_cfb8_decrypt_matches_native":True,
      "library_cfb8_reencrypts_exactly":True,
      "column_forward_reconstructs_oriented_bytes":True,
      "strict_fsa_terminal_zero":True,
    }

def selftest() -> None:
    gate,gate_hash=require_gate()
    sample="00112233445566778899AABBCCDDEEFF"
    for name,value in orientations(sample).items():
        assert orientations(value)[name]==sample
    order=[2,0,1]
    raw=bytes(range(12))
    for variant in VARIANTS:
        assert forward_column(inverse_column(raw,3,order,variant),3,order,variant)==raw
    assert fsa_valid(b"OK "+bytes.fromhex("e280a6"))
    assert not fsa_valid(b"OK "+bytes.fromhex("e280"))
    print(json.dumps({"identity":IDENTITY,"target_evaluated":False,
      "gate_sha256":gate_hash,"artifact_hashes_verified":True,
      "mdx_bytes_hashed_but_ciphertext_not_parsed":True,"selftest_passed":True},indent=2))

def run_target() -> None:
    if OUTPUT.exists(): raise SystemExit(f"refusing existing output: {OUTPUT}")
    gate,gate_hash=require_gate()
    canonical=extract_ciphertext()
    oriented=orientations(canonical)
    assert tuple(oriented)==ORIENTATIONS
    result={
      "identity":IDENTITY,"target_evaluated":True,
      "scope":gate["scope"],"gate_sha256":gate_hash,
      "mdx_sha256":sha(MDX),"ciphertext_sha256":sha_bytes(canonical.encode("ascii")),
      "cells":[],"complete":False
    }
    for orientation_name in ORIENTATIONS:
      oriented_hex=oriented[orientation_name]
      observed=bytes.fromhex(oriented_hex)
      assert orientations(oriented_hex)[orientation_name]==canonical
      for width in WIDTHS:
        assert len(observed)%width==0
        for variant in VARIANTS:
          raw=native(observed,width,variant)
          assert raw["accepted_complete"]==len(raw["solutions"])
          expected=math.factorial(width)
          certificate=raw["rejected_weight"]+raw["terminal_weight"]
          assert raw["expected_weight"]==expected and raw["certificate_weight"]==certificate
          complete=(not raw["capped"] and certificate==expected)
          if raw["capped"]: assert certificate<expected
          else: assert complete
          verified=[validate_solution(observed,width,variant,x) for x in raw["solutions"]]
          cell={
            "orientation":orientation_name,"oriented_hex_sha256":sha_bytes(oriented_hex.encode("ascii")),
            "observed_bytes_sha256":sha_bytes(observed),"width":width,"rows":len(observed)//width,
            "variant":variant,"node_limit":NODE_LIMIT,"nodes":raw["nodes"],
            "maximum_depth":raw["maximum_depth"],"rejected_prefix":raw["rejected_prefix"],
            "rejected_full":raw["rejected_full"],"rejected_unterminated":raw["rejected_unterminated"],
            "accepted_complete":raw["accepted_complete"],
            "rejected_weight":raw["rejected_weight"],"terminal_weight":raw["terminal_weight"],
            "certificate_weight":certificate,"expected_weight":expected,
            "capped":raw["capped"],"complete":complete,
            "elapsed_seconds":raw["elapsed_seconds"],"solutions":verified,
            "canonical_reconstruction_from_orientation":True,
          }
          result["cells"].append(cell)
          atomic_json(OUTPUT,result)
    assert len(result["cells"])==16
    result["complete"]=all(x["complete"] for x in result["cells"])
    result["summary"]={
      "cells":16,"complete_cells":sum(x["complete"] for x in result["cells"]),
      "capped_cells":sum(x["capped"] for x in result["cells"]),
      "survivors":sum(len(x["solutions"]) for x in result["cells"]),
      "elapsed_seconds":sum(x["elapsed_seconds"] for x in result["cells"]),
    }
    atomic_json(OUTPUT,result)
    print(json.dumps({"identity":IDENTITY,"output":str(OUTPUT),
      "sha256":sha(OUTPUT),"summary":result["summary"]},indent=2))

def main() -> None:
    parser=argparse.ArgumentParser()
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--selftest",action="store_true")
    group.add_argument("--run-target",action="store_true")
    args=parser.parse_args()
    if args.selftest: selftest()
    else: run_target()

if __name__=="__main__": main()
