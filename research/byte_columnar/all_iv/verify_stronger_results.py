#!/usr/bin/env python3
"""Independent read-only verification of all stronger target chunk witnesses."""
from __future__ import annotations
import hashlib,json,math
from pathlib import Path
from Crypto.Cipher import AES
HERE=Path(__file__).resolve().parent
REPO=HERE.parents[2]
RESULT=HERE/"stronger_target_results.json"
MDX=REPO/"lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
EXPECTED="d45bdb13020a0e0fbb92a1c80417fb58107c96656a1280bc5d3139677c1f83b1"
KEY=b"Zombies"+bytes(9);IVA=bytes(16);IVB=bytes.fromhex("00112233445566778899aabbccddeeff")
LAST={0x93,0x94,0x98,0x99,0xA6}
def sha_bytes(x:bytes)->str:return hashlib.sha256(x).hexdigest()
def step(s:int,b:int)->int|None:
    if s==0:
        if b in {9,10,13} or 32<=b<=126:return 0
        return 1 if b==0xE2 else None
    if s==1:return 2 if b==0x80 else None
    return 0 if s==2 and b in LAST else None
def trace(data:bytes)->tuple[list[int],dict|None]:
    states={0,1,2}
    for i,b in enumerate(data):
        before=sorted(states);states={q for s in states for q in [step(s,b)] if q is not None}
        if not states:return [],{"suffix_offset":i,"chunk_relative_plaintext_offset":16+i,
          "plaintext_byte":b,"states_before":before,"states_after":[]}
    return sorted(states),None
def direct(chunk:bytes)->bytes:
    e=AES.new(KEY,AES.MODE_ECB)
    return bytes(chunk[i]^e.encrypt(chunk[i-16:i])[0] for i in range(16,len(chunk)))
def orient(x:str)->dict[str,str]:
    p=[x[i:i+2] for i in range(0,len(x),2)]
    return {"forward":x,"full_hex_reverse":x[::-1],
      "byte_reverse":"".join(reversed(p)),"nibble_swap":"".join(y[::-1] for y in p)}
def main()->None:
    assert sha_bytes(RESULT.read_bytes())==EXPECTED
    text=MDX.read_text();a=text.index("`83 B57B2")+1;b=text.index("`",a)
    canonical="".join(text[a:b].split()).upper()
    assert sha_bytes(canonical.encode())=="5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
    oriented=orient(canonical);data=json.loads(RESULT.read_text());seen=set();count=0
    for cell in data["cells"]:
        key=(cell["orientation"],cell["width"]);assert key not in seen;seen.add(key)
        observed=bytes.fromhex(oriented[cell["orientation"]]);w=cell["width"]
        assert cell["observed_bytes_sha256"]==sha_bytes(observed)
        assert len(cell["chunk_witnesses"])==w
        for witness in cell["chunk_witnesses"]:
            rank=witness["observed_rank"];chunk=observed[rank::w];suffix=direct(chunk)
            assert witness["ciphertext_chunk_hex"]==chunk.hex()
            assert witness["ciphertext_chunk_sha256"]==sha_bytes(chunk)
            assert witness["iv_independent_plaintext_suffix_hex"]==suffix.hex()
            assert witness["iv_independent_plaintext_suffix_sha256"]==sha_bytes(suffix)
            assert AES.new(KEY,AES.MODE_CFB,iv=IVA,segment_size=8).decrypt(chunk)[16:]==suffix
            assert AES.new(KEY,AES.MODE_CFB,iv=IVB,segment_size=8).decrypt(chunk)[16:]==suffix
            states,failure=trace(suffix)
            assert states==witness["end_state_set"] and failure==witness["first_failure"]
            assert witness["chunk_rejected"]==(failure is not None)
            count+=1
        assert cell["rejected_chunk_ranks"]==list(range(w))
        assert cell["original_first_column_rejected_weight"]==math.factorial(w)
        assert cell["stronger_certificate_weight"]==cell["expected_completion_weight"]==math.factorial(w)
        assert cell["complete_every_iv_every_order_exclusion"] and not cell["unresolved"]
    assert seen=={(o,w) for o in oriented for w in (13,14)}
    assert count==108 and data["summary"]=={"cells":8,
      "complete_every_iv_every_order_exclusions":8,"unresolved_cells":0,
      "rejected_chunk_witnesses":108}
    print(json.dumps({"identity":"ASTRA","independent_verification":True,
      "chunks_verified":count,"cells_verified":8,"result_sha256":EXPECTED},indent=2))
if __name__=="__main__":main()
