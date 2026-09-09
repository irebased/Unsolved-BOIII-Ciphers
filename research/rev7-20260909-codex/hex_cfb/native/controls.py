#!/usr/bin/env python3
"""Synthetic-only equivalence controls for native global-hex-map CFB8 DFS."""
from __future__ import annotations
import hashlib, json, math, random, string, subprocess, sys, time
from dataclasses import asdict
from pathlib import Path

HERE=Path(__file__).resolve().parent
CORE=HERE.parent/"prototype.py"
sys.path.insert(0,str(CORE.parent))
import prototype as p

BIN=HERE/"native_dfs"
BASE64_BYTES=set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")|{9,10,13,32}
ALLOWED_HEX=bytes(sorted(BASE64_BYTES)).hex()
FIELDS=("nodes","rejected_plaintext","complete","maximum_depth","aborted_at_node_limit",
        "rejected_completion_weight","terminal_completion_weight","rejected_unterminated_endpoint")

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def native(cipher,cap,display,seed=None):
    arg=[str(BIN),cipher,str(cap),display,ALLOWED_HEX,
         "-" if not seed else ",".join(f"{k}:{v}" for k,v in sorted(seed.items()))]
    return json.loads(subprocess.check_output(arg,text=True))
def normalize_py(solutions,stats):
    return ({k:getattr(stats,k) for k in FIELDS},
            [{"mapping":list(x["mapping"]),"plaintext_hex":x["plaintext"].hex()} for x in solutions])
def check_equal(cipher,cap,display,seed=None):
    ecb,_key,iv=p.ecb_oracle(cipher)
    ps,pst=p.backtrack(display,ecb,iv,
        lambda state,_pos,value: 0 if value in BASE64_BYTES else None,
        node_limit=cap,seed_mapping=seed)
    py_stats,py_sol=normalize_py(ps,pst); n=native(cipher,cap,display,seed)
    ns={k:n[k] for k in FIELDS}
    assert ns==py_stats,(cipher,cap,ns,py_stats)
    assert n["solutions"]==py_sol,(cipher,cap)
    expected=math.factorial(16-len(seed or {})); certificate=ns["rejected_completion_weight"]+ns["terminal_completion_weight"]
    assert n["expected_completion_weight"]==expected and n["certificate_weight"]==certificate
    assert certificate<=expected and ((certificate==expected)==(not ns["aborted_at_node_limit"]))
    return {"cipher":cipher,"node_limit":cap,"stats":ns,"solution_count":len(py_sol),
            "expected_completion_weight":expected,"certificate_weight":certificate,
            "certificate_complete":certificate==expected,"native_seconds":n["elapsed_seconds"]}

def main():
    assert BIN.exists()
    rng=random.Random(20260910)
    mapping=list(range(16));rng.shuffle(mapping)
    cfb={}
    vector=bytes(range(256))+b"native CFB8 exact roundtrip"
    for cipher in p.cipher_specs():
        ecb,_key,iv=p.ecb_oracle(cipher)
        pyct=p.manual_cfb8(vector,ecb,iv,False)
        nct=bytes.fromhex(subprocess.check_output([str(BIN),"--cfb-encrypt",cipher,vector.hex()],text=True).strip())
        assert nct==pyct==p.library_cfb8(vector,cipher,False)
        npt=bytes.fromhex(subprocess.check_output([str(BIN),"--cfb-decrypt",cipher,nct.hex()],text=True).strip())
        assert npt==vector==p.library_cfb8(pyct,cipher,True)
        cfb[cipher]={"ciphertext_sha256":hashlib.sha256(pyct).hexdigest(),
                     "native_matches_python_manual_and_library":True,"full_byte_roundtrip":True}

    small=[]
    alphabet=bytes(sorted(BASE64_BYTES))
    for ci,cipher in enumerate(p.cipher_specs()):
        ecb,_key,iv=p.ecb_oracle(cipher)
        for attempt in range(100):
            plain=bytes(alphabet[rng.randrange(len(alphabet))] for _ in range(80))
            display=p.display_encode(p.manual_cfb8(plain,ecb,iv,False),mapping)
            if len(set(display))==16: break
        assert len(set(display))==16
        unknown=sorted(set(p.HEX.index(x) for x in display))[-4:]
        seed={i:v for i,v in enumerate(mapping) if i not in unknown}
        row=check_equal(cipher,100000,display,seed)
        row.update({"unknown_symbols":unknown,"expected_mapping_recovered":
                    any(x["mapping"]==mapping and x["plaintext_hex"]==plain.hex()
                        for x in native(cipher,100000,display,seed)["solutions"])})
        assert row["expected_mapping_recovered"]
        small.append(row)

    ecb,_key,iv=p.ecb_oracle("aes128")
    # Deterministic 546-byte Base64 endpoint plant; it uses every displayed symbol.
    plain=bytes(alphabet[rng.randrange(len(alphabet))] for _ in range(546))
    display=p.display_encode(p.manual_cfb8(plain,ecb,iv,False),mapping)
    assert len(set(display))==16
    full=[]
    for cap in (250000,1000000):
        t=time.perf_counter(); row=check_equal("aes128",cap,display); row["python_plus_native_wall_seconds"]=time.perf_counter()-t
        full.append(row)

    compiler=subprocess.check_output(["clang++","--version"],text=True).splitlines()[0]
    openssl=subprocess.check_output(["pkg-config","--modversion","openssl"],text=True).strip()
    result={"identity":"ASTRA","target_evaluated":False,
      "scope":"synthetic-only native/Python exact equivalence; no Rev7 target input is opened",
      "endpoint":{"name":"base64_69","byte_count":len(BASE64_BYTES),"allowed_hex":ALLOWED_HEX},
      "backend":{"compiler":compiler,"cpp_standard":"C++17","optimization":"-O3",
        "openssl_version":openssl,
        "openssl_prefix":"/opt/homebrew/Cellar/openssl@3/3.6.3",
        "link_args":["-lcrypto","-Wl,-rpath,/opt/homebrew/Cellar/openssl@3/3.6.3/lib"],
        "commoncrypto_probe":{"aes128":"accepted","des":"accepted","blowfish_raw7":"rejected_-4310"},
        "selected":"OpenSSL public low-level AES/DES/Blowfish primitives; BF_set_key receives exactly 7 bytes"},
      "source_hashes":{"prototype.py":sha(CORE),"native_dfs.cpp":sha(HERE/"native_dfs.cpp"),
                       "native_dfs_binary":sha(BIN),"controls.py":sha(Path(__file__))},
      "cfb8_controls":cfb,"seeded_four_unknown_exact_equivalence":small,
      "full16_base64_exact_prefix_equivalence":full,
      "assertions":{"all_passed":True,
        "native_stats_weights_solutions_equal_python":True,
        "full16_caps_checked":[250000,1000000]}}
    out=HERE/"controls.json"
    if out.exists(): raise SystemExit("refusing to overwrite controls.json")
    out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"identity":"ASTRA","controls":str(out),"sha256":sha(out),
      "full":full},indent=2))
if __name__=="__main__":main()
