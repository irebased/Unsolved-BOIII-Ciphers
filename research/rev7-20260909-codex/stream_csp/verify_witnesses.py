#!/usr/bin/env python3
"""ASTRA: independent verification of the frozen OFB mapping contradictions."""
import hashlib, importlib.util, itertools, json, math, sys
from pathlib import Path
from Crypto.Cipher import AES, Blowfish, DES
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
LEDGER=HERE/"target_results.json"
LEDGER_SHA="f1d9024065f82e75479c4e03f1c871f9c2e0c661e63c6a42cb6da6594addde87"
ALLOWED={9,10,13}|set(range(32,127))|{0xe2,0x80,0x93,0x94,0x98,0x99}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    out=HERE/"witness_verification.json"
    if out.exists():raise SystemExit("refusing existing verification output")
    assert sha(LEDGER)==LEDGER_SHA
    d=json.loads(LEDGER.read_text())
    assert d["identity"]=="ASTRA" and len(d["cells"])==72
    text=(ROOT/"lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx").read_text()
    start=text.index(chr(96)+"83 B57B2")+1
    s="".join(text[start:text.index(chr(96),start)].split())
    assert hashlib.sha256(s.encode()).hexdigest()=="5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
    orient={"forward":s,"reverse":s[::-1],
      "byte_reverse":"".join(s[i:i+2] for i in range(len(s)-2,-1,-2)),
      "nibble_swap":"".join(s[i+1]+s[i] for i in range(0,len(s),2))}
    source=HERE.parent/"sources"/"ofb8"
    expected={"run.py":"66e719b03625b163e4018a3c7531069a2b51dcb69131842721ce6d6a5fef5bf9",
      "ofb.c":"aec1699eecb37e4791e704d074e88fbe210f62dd75e6c1face8a5fc302ee926d",
      "libdefs.h":"2ee660093968833b62d3c52271683874d401dc988c9d8e9f07ad2fc04f3e7975",
      "mcrypt_modules.h":"2fefe3d60795fb19e7a7be1c4cec18a97c069e2471ae61c951706020dcb6c180"}
    assert {n:sha(source/n) for n in expected}==expected
    spec=importlib.util.spec_from_file_location("historical_ofb8",source/"run.py")
    c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
    command,compiler=c.compile_source()
    models={"aes128":(AES,b"Zombies".ljust(16,b"\0")),
      "blowfish":(Blowfish,b"Zombies"),"des":(DES,b"Zombies".ljust(8,b"\0"))}
    streams={};rows=[];seen=set()
    for row in d["cells"]:
        context=tuple(row[n] for n in ("cipher","mode","iv_kind","orientation"))
        assert context not in seen;seen.add(context)
        cipher,mode,ivkind,o=context;mod,key=models[cipher]
        iv={"ascii_zero":b"0"*mod.block_size,"nul":bytes(mod.block_size),
            "sha1_prefix":hashlib.sha1(b"Zombies").digest()[:mod.block_size]}[ivkind]
        assert row["key_hex"]==key.hex() and row["iv_hex"]==iv.hex()
        kcontext=context[:3]
        if kcontext not in streams:
            if mode=="ofb8":
                ks=c.actual_ofb8(bytes(546),mod,key,iv,False)
            else:
                assert mode=="fullblock_ofb"
                ks=mod.new(key,mod.MODE_OFB,iv=iv).encrypt(bytes(546))
            streams[kcontext]=ks
        ks=streams[kcontext];display=orient[o]
        assert len(ks)==546 and hashlib.sha256(ks).hexdigest()==row["keystream_sha256"]
        assert hashlib.sha256(display.encode()).hexdigest()==row["displayed_sha256"]
        st=row["stats"]
        assert not st["capped"] and st["certificate_weight"]==math.factorial(16)
        assert st["rejected_weight"]+st["terminal_weight"]==math.factorial(16)
        assert row["relaxed_survivor_count"]==row["fsa_survivor_count"]==0 and row["survivors"]==[]
        w=row["unrestricted_fixed_byte_witness"]
        evidence={"cipher":cipher,"mode":mode,"iv_kind":ivkind,"orientation":o}
        if w is not None:
            pos=w["positions"]
            assert len(pos)==len(set(pos)) and all(0<=i<546 for i in pos)
            assert all(display[2*i:2*i+2]==w["display_pair"] for i in pos)
            assert [ks[i] for i in pos]==w["keystream_bytes"]
            survivors=[b for b in range(256) if all((b^ks[i]) in ALLOWED for i in pos)]
            assert survivors==[]
            evidence.update(kind="unrestricted_fixed_byte_contradiction",pair=w["display_pair"],
                positions=pos,keystream_bytes=[ks[i] for i in pos],candidate_bytes_checked=256,survivors=[])
        else:
            assert cipher=="blowfish" and mode=="ofb8" and ivkind=="nul"
            assert ks==bytes(546)
            first_ecb=mod.new(key,mod.MODE_ECB).encrypt(iv)
            assert first_ecb[0]==0
            distinct=len({display[i:i+2] for i in range(0,len(display),2)})
            assert distinct>len(ALLOWED)
            evidence.update(kind="constant_stream_distinct_byte_count",keystream_byte=0,
                distinct_display_bytes=distinct,allowed_plaintext_bytes=len(ALLOWED),
                zero_register_ecb_hex=first_ecb.hex(),
                explanation="With zero keystream, a bijective byte map preserves 226 distinct bytes; 104 allowed bytes cannot contain them.")
        rows.append(evidence)
    assert seen==set(itertools.product(models,("ofb8","fullblock_ofb"),("ascii_zero","nul","sha1_prefix"),orient))
    result={"identity":"ASTRA","target_evaluated":True,"scope":"Independent verification of frozen results; no new key or mapping search.",
      "ledger_sha256":LEDGER_SHA,"verifier_sha256":sha(Path(__file__)),
      "historical_source_hashes":expected,"compile_command":command,"compiler":compiler,
      "independent_streams_verified":len(streams),
      "unrestricted_byte_witnesses_verified":sum(x["kind"]=="unrestricted_fixed_byte_contradiction" for x in rows),
      "bijective_byte_count_contradictions_verified":sum(x["kind"]=="constant_stream_distinct_byte_count" for x in rows),
      "all_72_complete_certificates_checked":True,"rows":rows}
    out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(json.dumps({k:v for k,v in result.items() if k!="rows"},indent=2))
    print("verification_sha256",sha(out))
if __name__=="__main__":main()
