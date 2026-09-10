#!/usr/bin/env python3
"""Controls for the stronger any-bad-chunk all-IV variant-B lemma."""
from __future__ import annotations
import hashlib,itertools,json,math,platform,random,sys
from pathlib import Path
from Crypto import __version__ as crypto_version
from Crypto.Cipher import AES

HERE=Path(__file__).resolve().parent
OUT=HERE/"stronger_controls.json"
sys.path.insert(0,str(HERE))
import core,stronger

IDENTITY="ASTRA"
ORIGINAL_CONTROLS=HERE/"controls.json"

def sha(path:Path)->str:return hashlib.sha256(path.read_bytes()).hexdigest()

def valid(data:bytes)->bool:
    return core.propagate({0},data)=={0}

def encrypt(data:bytes,iv:bytes)->bytes:
    return AES.new(core.KEY,AES.MODE_CFB,iv=iv,segment_size=8).encrypt(data)

def vb_encrypt(ciphertext:bytes,width:int,order:tuple[int,...])->bytes:
    rows=len(ciphertext)//width; assert rows*width==len(ciphertext)
    out=bytearray(len(ciphertext))
    for row in range(rows):
        for rank,col in enumerate(order):out[row*width+rank]=ciphertext[col*rows+row]
    return bytes(out)

def vb_inverse(observed:bytes,width:int,order:tuple[int,...])->bytes:
    rows=len(observed)//width; assert rows*width==len(observed)
    out=bytearray(len(observed))
    for row in range(rows):
        for rank,col in enumerate(order):out[col*rows+row]=observed[row*width+rank]
    return bytes(out)

def retained_general(observed:bytes,width:int)->set[int]:
    return {rank for rank in range(width)
      if core.propagate({0,1,2},core.iv_independent_suffix(observed[rank::width]))}

def force_zero(observed:bytes,width:int,rank:int,relative_offset:int=16)->tuple[bytes,dict]:
    assert relative_offset>=16
    chunk=bytearray(observed[rank::width])
    ecb=AES.new(core.KEY,AES.MODE_ECB)
    keystream=ecb.encrypt(bytes(chunk[relative_offset-16:relative_offset]))[0]
    before=chunk[relative_offset]
    chunk[relative_offset]=keystream
    changed=bytearray(observed)
    changed[rank+relative_offset*width]=keystream
    suffix=core.iv_independent_suffix(bytes(chunk))
    assert suffix[relative_offset-16]==0
    return bytes(changed),{"rank":rank,"relative_offset":relative_offset,
      "observed_absolute_offset":rank+relative_offset*width,
      "ciphertext_byte_before":before,"ciphertext_byte_after":keystream,
      "forced_iv_independent_plaintext_byte":0}

def make_plain(length:int)->bytes:
    prefix="ALPHA – BETA — GAMMA ‘DELTA’ … END. ".encode()
    value=prefix+(b" THE AETHER REMEMBERS. "*(length+1))[:length-len(prefix)]
    assert len(value)==length and valid(value)
    return value

def main()->None:
    if OUT.exists():raise SystemExit(f"refusing existing output: {OUT}")
    original=json.loads(ORIGINAL_CONTROLS.read_text())
    assert original["identity"]==IDENTITY and original["target_evaluated"] is False
    assert original["assertions"]["all_passed"] is True

    rng=random.Random(20260910)
    iv_a=hashlib.sha256(b"stronger-control-iv-a").digest()[:16]
    iv_b=hashlib.sha256(b"stronger-control-iv-b").digest()[:16]
    small=[]
    for width in range(3,7):
        rows=20; plaintext=make_plain(width*rows)
        ciphertext=encrypt(plaintext,iv_a)
        order=list(range(width));rng.shuffle(order);order=tuple(order)
        observed=vb_encrypt(ciphertext,width,order)
        bad_rank=(width-1)//2
        corrupted,mutation=force_zero(observed,width,bad_rank,16)
        retained=retained_general(corrupted,width)
        assert bad_rank not in retained and retained==set(range(width))-{bad_rank}
        per_iv={}
        for label,iv in (("iv_a",iv_a),("iv_b",iv_b)):
            survivors=[]
            for candidate in itertools.permutations(range(width)):
                candidate_ct=vb_inverse(corrupted,width,candidate)
                candidate_pt=AES.new(core.KEY,AES.MODE_CFB,iv=iv,segment_size=8).decrypt(candidate_ct)
                if valid(candidate_pt):survivors.append(list(candidate))
            assert not survivors
            per_iv[label]={"iv_hex":iv.hex(),"full_permutations_tested":math.factorial(width),
              "valid_plaintexts":0}
        small.append({"width":width,"rows":rows,"order":list(order),
          "bad_chunk_rank":bad_rank,"retained_other_chunk_ranks":sorted(retained),
          "mutation":mutation,"two_iv_exhaustive_naive":per_iv,
          "any_bad_chunk_implies_all_orders_fail":True})

    plaintext=make_plain(546)
    plant_iv=hashlib.sha256(b"stronger-546-plant-iv").digest()[:16]
    ciphertext=encrypt(plaintext,plant_iv)
    orders={13:(7,0,12,3,9,1,5,11,2,8,4,10,6),
            14:(8,0,13,3,10,1,6,12,2,9,4,11,5,7)}
    large=[]
    for width in (13,14):
        observed=vb_encrypt(ciphertext,width,orders[width])
        valid_row=stronger.evaluate_any_bad(observed,width)
        assert not valid_row["rejected_chunk_ranks"]
        bad_rank=3
        corrupted,mutation=force_zero(observed,width,bad_rank,16)
        row=stronger.evaluate_any_bad(corrupted,width)
        assert row["rejected_chunk_ranks"]==[bad_rank]
        assert row["retained_chunk_ranks"]==[x for x in range(width) if x!=bad_rank]
        assert row["complete_every_iv_every_order_exclusion"]
        assert row["stronger_certificate_weight"]==row["expected_completion_weight"]==math.factorial(width)
        assert row["original_first_column_rejected_weight"]==math.factorial(width-1)
        witness=row["chunk_witnesses"][bad_rank]
        assert witness["first_failure"]["chunk_relative_plaintext_offset"]==16
        assert witness["first_failure"]["plaintext_byte"]==0
        large.append({"width":width,"rows":546//width,"order":list(orders[width]),
          "valid_plant_all_chunks_retained":True,"corruption":mutation,
          "corrupted_observed_sha256":hashlib.sha256(corrupted).hexdigest(),
          "rejected_chunk_rank":bad_rank,
          "other_chunks_retained":row["retained_chunk_ranks"],
          "original_first_column_rejected_weight":row["original_first_column_rejected_weight"],
          "stronger_certificate_weight":row["stronger_certificate_weight"],
          "expected_completion_weight":row["expected_completion_weight"],
          "complete_every_iv_every_order_exclusion":True,
          "rejected_chunk_witness":witness})

    result={"identity":IDENTITY,"target_evaluated":False,"rev7_file_read":False,
      "scope":"Synthetic controls for the stronger any-unavoidable-bad-chunk lemma; rectangular variant B, AES-128 CFB8 fixed Zombies+9NUL key, arbitrary external IV, exact five-sequence endpoint.",
      "lemma":"Every observed rank is one contiguous natural ciphertext chunk under every rectangular variant-B order. If any chunk's IV-independent suffix is invalid from all FSA states reachable after an arbitrary prefix, every full order and every external IV is excluded.",
      "limits":"A clean set of chunks is unresolved. This does not recover an order, IV, or plaintext. It does not cover variant A, ragged columns, other ciphers, prepended-IV framing, or endpoints outside the five-sequence FSA.",
      "source_hashes":{"original_core.py":sha(HERE/"core.py"),
        "original_controls.json":sha(ORIGINAL_CONTROLS),
        "stronger.py":sha(HERE/"stronger.py"),"stronger_controls.py":sha(Path(__file__))},
      "runtime":{"python":platform.python_version(),"pycryptodome":crypto_version},
      "small_width_corrupted_plants":small,
      "width13_14_corrupted_plants":large,
      "assertions":{"all_passed":True,"no_rev7_access":True,
        "other_chunks_remain_retained":True,
        "width3_6_all_permutations_fail_under_two_ivs":True,
        "width13_14_original_partial_vs_stronger_full_weights":True,
        "full_rejected_chunk_bytes_suffix_and_failure_recorded":True}}
    OUT.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"identity":IDENTITY,"output":str(OUT),"sha256":sha(OUT),
      "large":[{"width":x["width"],"old_weight":x["original_first_column_rejected_weight"],
       "strong_weight":x["stronger_certificate_weight"]} for x in large]},indent=2))

if __name__=="__main__":main()
