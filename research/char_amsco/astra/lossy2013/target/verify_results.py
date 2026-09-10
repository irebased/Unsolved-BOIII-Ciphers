#!/usr/bin/env python3
"""Independent source-index and empty-prefix certificate verifier for saved lossy-2013 results."""
from __future__ import annotations
from Crypto.Cipher import AES,DES
import hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent
PACKAGE=HERE.parent
ROOT=HERE.parents[4]
RESULT=HERE/"target_results.json"
GATE=HERE/"target_gate.json"
MDX=ROOT/"lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
DATASET=ROOT/"lavender/src/data/ciphers/revelations.json"
RESULT_SHA="95e2fd9023cf6a7ceb4f570d7cec4a4e0191b2aebde002b54e564b15c649a69d"
GATE_SHA="516804c6eb3c99755fee1fd0fe9474824c6a47bbf772c6d9886deb03e6e441b8"
DRIVER_SHA="dfd41b1dfcd5c1f3b62465478fb4ecfda20973a5a29a1c480f9bb4ed277456e9"
MDX_SHA="085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91"
DATASET_SHA="68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e"
TEXT_SHA="5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
CIPHERS=("des","aes128")
IVS=("nul","ascii0")
ORIENTATIONS=("forward","full_hex_reverse","byte_reverse","nibble_swap")
ALLOWED=bytes(range(32,127))
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def orient(value,name):
    if name=="forward":return value
    if name=="full_hex_reverse":return value[::-1]
    pairs=[value[i:i+2] for i in range(0,len(value),2)]
    if name=="byte_reverse":return "".join(reversed(pairs))
    if name=="nibble_swap":return "".join(x[::-1] for x in pairs)
    raise ValueError(name)
def independent_indices(length):
    rows=[];pos=0;cell=0;size=2
    while pos<length:
        row=cell//4;col=cell%4
        while len(rows)<=row:rows.append({})
        take=min(size,length-pos)
        rows[row][int("2013"[col])]=tuple(range(pos,pos+take))
        pos+=take;cell+=1;size=3-size
    out=[]
    for label in range(1,5):
        for row in rows:out.extend(row.get(label,()))
    return out
def reconstruct(observed):
    indices=independent_indices(1310)
    assert len(indices)==len(observed)==1092
    vals=bytearray(655);masks=bytearray(655)
    for char,index in zip(observed,indices):
        nib=int(char,16);byte=index//2
        if index&1:vals[byte]|=nib;masks[byte]|=15
        else:vals[byte]|=nib<<4;masks[byte]|=240
    assert masks==bytes((255,15,255))*218+b"\xff"
    return bytes(vals),bytes(masks)
def primitive(name):
    if name=="des":return DES.new(b"Zombies\0",DES.MODE_ECB),8,b"Zombies\0"
    return AES.new(b"Zombies"+b"\0"*9,AES.MODE_ECB),16,b"Zombies"+b"\0"*9
def iv_for(name,label):
    bs=8 if name=="des" else 16
    return bytes(bs) if label=="nul" else b"0"*bs
def prefix_certificate(cipher,iv,observed):
    vals,masks=reconstruct(observed)
    e,bs,key=primitive(cipher)
    frontier=[bytes(iv)];counts=[];accepted=0;calls=0
    for value,mask in zip(vals,masks):
        nxt=[]
        for reg in frontier:
            stream=e.encrypt(reg)[0];calls+=1
            if mask==255:
                c=value
                if c^stream in ALLOWED:nxt.append(reg[1:]+bytes((c,)))
            else:
                for plain in ALLOWED:
                    c=plain^stream
                    if c&mask==value&mask:nxt.append(reg[1:]+bytes((c,)))
        counts.append(len(nxt));accepted+=len(nxt);frontier=nxt
        if not frontier:break
    return counts,accepted,calls
def canonical():
    assert sha(MDX)==MDX_SHA and sha(DATASET)==DATASET_SHA
    text=MDX.read_text();a=text.index(chr(96)+"83 B57B2")+1;b=text.index(chr(96),a)
    left="".join(text[a:b].split()).upper()
    row=next(x for x in json.loads(DATASET.read_text()) if x.get("id")=="rev7")
    right="".join(row["ciphertext"].split()).upper()
    assert left==right and hashlib.sha256(left.encode()).hexdigest()==TEXT_SHA
    return left
def verify_solution(sol,cipher,iv,observed):
    pt=bytes.fromhex(sol["plaintext_hex"]);ct=bytes.fromhex(sol["ciphertext_hex"])
    assert len(pt)==len(ct)==655 and set(pt)<=set(ALLOWED)
    mod=DES if cipher=="des" else AES
    key=b"Zombies\0" if cipher=="des" else b"Zombies"+b"\0"*9
    assert mod.new(key,mod.MODE_CFB,iv=iv,segment_size=8).decrypt(ct)==pt
    assert mod.new(key,mod.MODE_CFB,iv=iv,segment_size=8).encrypt(pt)==ct
    rebuilt=["?"]*1310
    for char,index in zip(observed,independent_indices(1310)):rebuilt[index]=char
    cthex=ct.hex().upper()
    assert all(char=="?" or char==cthex[i] for i,char in enumerate(rebuilt))
    assert hashlib.sha256(pt).hexdigest()==sol["plaintext_sha256"] and hashlib.sha256(ct).hexdigest()==sol["ciphertext_sha256"]
def main():
    assert sha(RESULT)==RESULT_SHA and sha(GATE)==GATE_SHA and sha(HERE/"run_target.py")==DRIVER_SHA
    gate=json.loads(GATE.read_text())
    assert gate["identity"]=="ASTRA" and not gate["target_evaluated"] and gate["fable_reference"]=="ASTRA message254 on FABLE channel"
    assert gate["driver_sha256"]==DRIVER_SHA and gate["mdx_sha256"]==MDX_SHA and gate["dataset_sha256"]==DATASET_SHA and gate["canonical_text_sha256"]==TEXT_SHA
    for rel,want in gate["dependency_hashes"].items():
        path=PACKAGE/rel.removeprefix("lossy2013/") if rel.startswith("lossy2013/") else (ROOT/"research/char_amsco/astra/amsco_geometry.py" if rel=="cryptool_bug/amsco_geometry.py" else ROOT/"research/char_amsco/astra"/rel)
        assert sha(path)==want,(rel,path)
    for rel,want in gate["target_artifact_hashes"].items():
        assert sha(HERE/rel.removeprefix("target/"))==want
    data=json.loads(RESULT.read_text())
    canonical_hex=canonical()
    expected=[f"cipher={c}|iv={i}|hex={o}" for c in CIPHERS for i in IVS for o in ORIENTATIONS]
    assert [row["id"] for row in data["rows"]]==expected and len(expected)==16
    certs=[]
    for row in data["rows"]:
        observed=orient(canonical_hex,row["orientation"])
        counts,accepted,calls=prefix_certificate(row["cipher"],iv_for(row["cipher"],row["iv"]),observed)
        assert counts==row["frontier_counts"] and counts[-1]==0
        assert len(counts)==row["stopped_after_bytes"] and accepted==row["accepted_states"] and calls==row["block_calls"]
        assert row["complete"] and row["capped_reason"] is None and row["frontier_count_at_stop"]==0
        assert row["solution_count"]==len(row["solutions"])
        for sol in row["solutions"]:verify_solution(sol,row["cipher"],iv_for(row["cipher"],row["iv"]),observed)
        certs.append({"id":row["id"],"first_empty_after_bytes":len(counts),"frontier_counts":counts})
    assert data["summary"]=={"contexts":16,"complete":16,"capped_incomplete":0,"solutions":0,"all_full_solutions_retained":True,"all_retained_solutions_independently_validated":True,"no_scoring_or_pruning_except_caps":True}
    print(json.dumps({"identity":"ASTRA","verified":True,"result_sha256":RESULT_SHA,"contexts":16,"complete":16,"capped":0,"solutions":0,"first_empty_prefix_certificates":certs,"verification":"independent source-index/mask reconstruction and short empty-frontier replay; every retained survivor would be checked"},indent=2,sort_keys=True))
if __name__=="__main__":main()
