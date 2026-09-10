#!/usr/bin/env python3
"""Synthetic controls for the rectangular variant-B all-IV prefix predicate."""
from __future__ import annotations
import hashlib,itertools,json,math,platform,random,sys
from pathlib import Path
from Crypto import __version__ as crypto_version
from Crypto.Cipher import AES

HERE=Path(__file__).resolve().parent
OUT=HERE/"controls.json"
FABLE_TRANS=Path("/private/tmp/rev7-fable-20260909/bytelevel/lib/transpositions.js")
FABLE_BYTE=Path("/private/tmp/rev7-fable-20260909/bytelevel/lib/byteTranspositions.js")
sys.path.insert(0,str(HERE))
import core

IDENTITY="ASTRA"

def sha(path:Path)->str: return hashlib.sha256(path.read_bytes()).hexdigest()

def independent_valid(data:bytes)->bool:
    state=0
    last={0x93,0x94,0x98,0x99,0xA6}
    for value in data:
        if state==0:
            if value in {9,10,13} or 32<=value<=126: state=0
            elif value==0xE2: state=1
            else: return False
        elif state==1:
            if value==0x80: state=2
            else: return False
        else:
            if value in last: state=0
            else: return False
    return state==0

def encrypt(data:bytes,iv:bytes)->bytes:
    return AES.new(core.KEY,AES.MODE_CFB,iv=iv,segment_size=8).encrypt(data)

def variant_b_encrypt(ciphertext:bytes,width:int,order:tuple[int,...])->bytes:
    assert len(ciphertext)%width==0 and sorted(order)==list(range(width))
    rows=len(ciphertext)//width
    out=bytearray(len(ciphertext))
    for row in range(rows):
        for rank,col in enumerate(order):
            out[row*width+rank]=ciphertext[col*rows+row]
    return bytes(out)

def variant_b_inverse(observed:bytes,width:int,order:tuple[int,...])->bytes:
    assert len(observed)%width==0 and sorted(order)==list(range(width))
    rows=len(observed)//width
    out=bytearray(len(observed))
    for row in range(rows):
        for rank,col in enumerate(order):
            out[col*rows+row]=observed[row*width+rank]
    return bytes(out)

def retained_general(observed:bytes,width:int)->set[int]:
    assert len(observed)%width==0 and len(observed)//width>core.BLOCK_SIZE
    kept=set()
    for rank in range(width):
        chunk=observed[rank::width]
        suffix=core.iv_independent_suffix(chunk)
        if core.propagate({0,1,2},suffix): kept.add(rank)
    return kept

def make_plain(length:int)->bytes:
    prefix="ALPHA – BETA — GAMMA ‘DELTA’ … END. ".encode("utf-8")
    value=prefix+(b" THE AETHER REMEMBERS. "*(length+1))[:length-len(prefix)]
    assert len(value)==length and independent_valid(value)
    return value

def main()->None:
    if OUT.exists(): raise SystemExit(f"refusing existing output: {OUT}")
    assert core.KEY==b"Zombies"+bytes(9) and core.BLOCK_SIZE==16

    # Exact FABLE variant-B fixture: byteTranspositions.js over observed 00..0b.
    fixture_observed=bytes(range(12)); fixture_order=(2,0,1)
    fixture_inverse=variant_b_inverse(fixture_observed,3,fixture_order)
    assert fixture_inverse.hex()=="0104070a0205080b00030609"
    assert variant_b_encrypt(fixture_inverse,3,fixture_order)==fixture_observed

    rng=random.Random(20260910)
    arbitrary_ct=bytes(rng.randrange(256) for _ in range(42))
    iv_a=bytes(16)
    iv_b=bytes.fromhex("00112233445566778899aabbccddeeff")
    dec_a=core.cfb8_decrypt(arbitrary_ct,iv_a)
    dec_b=core.cfb8_decrypt(arbitrary_ct,iv_b)
    direct=core.iv_independent_suffix(arbitrary_ct)
    assert dec_a[16:]==dec_b[16:]==direct

    boundary=[]
    boundary_plaintexts=[
      b"A"*15+bytes.fromhex("e28093")+b"B"*(42-18),
      b"A"*14+bytes.fromhex("e28093")+b"C"*(42-17),
    ]
    # First suffix begins 80 in case 1; it begins 93 in case 2.
    for index,plaintext in enumerate(boundary_plaintexts):
        assert len(plaintext)==42 and independent_valid(plaintext)
        ciphertext=encrypt(plaintext,iv_b)
        suffix=core.iv_independent_suffix(ciphertext)
        expected_lead=(0x80,0x93)[index]
        assert suffix[0]==expected_lead
        assert not core.propagate({0},suffix)
        ending=core.propagate({0,1,2},suffix)
        assert ending
        boundary.append({"case":("suffix_starts_80","suffix_starts_punctuation")[index],
          "suffix_first_byte":suffix[0],"normal_state_only_rejects":True,
          "all_reachable_boundary_states_retain":True,"ending_states":sorted(ending),
          "ciphertext_sha256":hashlib.sha256(ciphertext).hexdigest()})

    small=[]
    for width in range(3,7):
        rows=20
        plaintext=make_plain(width*rows)
        iv=hashlib.sha256(f"small-{width}".encode()).digest()[:16]
        ciphertext=encrypt(plaintext,iv)
        order=list(range(width)); rng.shuffle(order); order=tuple(order)
        observed=variant_b_encrypt(ciphertext,width,order)
        assert variant_b_inverse(observed,width,order)==ciphertext
        retained=retained_general(observed,width)
        full_valid=[]
        for candidate in itertools.permutations(range(width)):
            candidate_ct=variant_b_inverse(observed,width,candidate)
            candidate_pt=AES.new(core.KEY,AES.MODE_CFB,iv=iv,segment_size=8).decrypt(candidate_ct)
            if independent_valid(candidate_pt):
                full_valid.append({"order":list(candidate),"first_column_rank":candidate.index(0),
                                   "plaintext_sha256":hashlib.sha256(candidate_pt).hexdigest()})
        valid_ranks={x["first_column_rank"] for x in full_valid}
        assert full_valid and tuple(full_valid[0]["order"])==order
        assert valid_ranks<=retained
        small.append({"width":width,"rows":rows,"order":list(order),
          "retained_first_column_ranks":sorted(retained),
          "full_valid_permutation_count":len(full_valid),
          "full_valid_first_column_ranks":sorted(valid_ranks),
          "independent_full_valid_ranks_subset_of_necessary_retained":True})

    plant_plain=make_plain(546)
    assert all(bytes.fromhex(x) in plant_plain for x in ("e28093","e28094","e28098","e28099","e280a6"))
    plant_iv=hashlib.sha256(b"ASTRA arbitrary external IV plant").digest()[:16]
    plant_ct=encrypt(plant_plain,plant_iv)
    orders={13:(7,0,12,3,9,1,5,11,2,8,4,10,6),
            14:(8,0,13,3,10,1,6,12,2,9,4,11,5,7)}
    plants=[]
    for width in (13,14):
        observed=variant_b_encrypt(plant_ct,width,orders[width])
        row=core.evaluate(observed,width)
        truth_rank=orders[width].index(0)
        assert truth_rank in row["retained_ranks"]
        plants.append({"width":width,"rows":546//width,"order":list(orders[width]),
          "arbitrary_iv_hex":plant_iv.hex(),"correct_first_column_rank":truth_rank,
          "retained_first_column_ranks":row["retained_ranks"],
          "correct_first_column_retained":True,
          "rejected_completion_weight":row["rejected_completion_weight"],
          "expected_completion_weight":row["expected_completion_weight"],
          "complete_every_iv_exclusion":row["complete_every_iv_exclusion"],
          "observed_sha256":hashlib.sha256(observed).hexdigest()})

    random_observed=bytes(rng.randrange(256) for _ in range(546))
    contradictions=[]
    for width in (13,14):
        row=core.evaluate(random_observed,width)
        assert not row["retained_ranks"] and row["complete_every_iv_exclusion"]
        assert row["rejected_completion_weight"]==row["expected_completion_weight"]==math.factorial(width)
        contradictions.append(row)

    result={"identity":IDENTITY,"target_evaluated":False,"rev7_file_read":False,
      "scope":"Synthetic-only necessary-prefix controls for all external 16-byte IVs; AES-128 CFB8 fixed key Zombies plus nine NULs; rectangular variant B widths 13/14; strict five-sequence endpoint.",
      "claim_boundary":"A rejected first-column rank eliminates (w-1)! full orders for every external IV. A retained rank is only an unresolved first-column class, not a plaintext, IV, or full-permutation survivor. No terminal-state-zero check is made at the column boundary.",
      "source_hashes":{"core.py":sha(HERE/"core.py"),"controls.py":sha(Path(__file__)),
        "fable_transpositions.js":sha(FABLE_TRANS),"fable_byteTranspositions.js":sha(FABLE_BYTE)},
      "runtime":{"python":platform.python_version(),"pycryptodome":crypto_version},
      "cipher":{"name":"AES-128","key_hex":core.KEY.hex(),"block_size":16},
      "endpoint":{"start_state_set_at_byte_16":[0,1,2],
        "utf8_sequences":["e28093","e28094","e28098","e28099","e280a6"],
        "terminal_zero_required_at_column_boundary":False},
      "fable_variant_b_fixture":{"n":12,"width":3,"order":list(fixture_order),
        "inverse_hex":fixture_inverse.hex(),"exact_match":True},
      "iv_independence":{"ciphertext_bytes":42,"iv_a_hex":iv_a.hex(),"iv_b_hex":iv_b.hex(),
        "ciphertext_sha256":hashlib.sha256(arbitrary_ct).hexdigest(),
        "suffix_sha256":hashlib.sha256(direct).hexdigest(),"suffix_bytes":len(direct),
        "two_library_decryptions_and_direct_recurrence_equal_after_byte16":True},
      "boundary_state_controls":boundary,
      "small_width_naive_controls":small,
      "width13_14_arbitrary_iv_plants":plants,
      "deterministic_random_complete_contradictions":{"seed":20260910,
        "observed_sha256":hashlib.sha256(random_observed).hexdigest(),"rows":contradictions},
      "assertions":{"all_passed":True,"no_rev7_access":True,
        "iv_independent_suffix_verified":True,"correct_plant_first_columns_retained":True,
        "small_naive_full_valid_subset_verified":True,
        "random_all_iv_factorial_certificates_complete":True}}
    OUT.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"identity":IDENTITY,"controls":str(OUT),"sha256":sha(OUT),
      "plants":plants,"random_complete":[x["complete_every_iv_exclusion"] for x in contradictions]},indent=2))

if __name__=="__main__":main()
