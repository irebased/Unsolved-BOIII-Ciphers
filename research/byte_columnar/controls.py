#!/usr/bin/env python3
"""Controls only for native/reference byte-column permutation DFS; no Rev7 access."""
from __future__ import annotations
import dataclasses, hashlib, json, math, platform, random, subprocess, sys, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
import core

IDENTITY = "ASTRA"
BIN = HERE / "native_search"
OUT = HERE / "controls.json"
FABLE_TRANS = Path("/private/tmp/rev7-fable-20260909/bytelevel/lib/transpositions.js")
FABLE_BYTE = Path("/private/tmp/rev7-fable-20260909/bytelevel/lib/byteTranspositions.js")
REV9_CONTROL = REPO / "research/rev7-20260909-codex/sources/rev9_source/controls.json"
LIMIT = 10_000_000
STAT_FIELDS = tuple(dataclasses.asdict(core.Stats()).keys())

def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def native(observed: bytes, width: int, variant: str, cap: int = LIMIT) -> dict:
    return json.loads(subprocess.check_output(
        [str(BIN), str(width), variant, str(cap), observed.hex()], text=True))

def solution_key(row: dict) -> tuple:
    return tuple(row["order"]), row["plaintext_hex"]

def native_stats(row: dict) -> dict:
    return {key: row[key] for key in STAT_FIELDS}

def make_plain(length: int, unicode5: bool) -> bytes:
    if unicode5:
        prefix = "ALPHA – BETA — GAMMA ‘DELTA’ … END. ".encode("utf-8")
    else:
        prefix = b"THE AETHER REMEMBERS THE CHILDREN. "
    assert len(prefix) <= length
    filler = (b" THE AETHER REMEMBERS. " * (length + 1))[:length-len(prefix)]
    value = prefix + filler
    assert len(value) == length and core.fsa_valid(value)
    return value

def old4_valid(data: bytes) -> bool:
    state = 0
    old_last = {0x93, 0x94, 0x98, 0x99}
    for value in data:
        if state == 0:
            state = 0 if value in {9,10,13} or 32 <= value <= 126 else (1 if value == 0xE2 else -1)
        elif state == 1:
            state = 2 if value == 0x80 else -1
        else:
            state = 0 if value in old_last else -1
        if state < 0:
            return False
    return state == 0

def main() -> None:
    if OUT.exists():
        raise SystemExit(f"refusing existing output: {OUT}")
    assert BIN.exists()
    assert core.AES_KEY == b"Zombies" + bytes(9) and core.AES_IV == b"0"*16

    # Fixed fixtures produced by FABLE byteTranspositions.js over bytes 00..0b.
    fixture_order = (2,0,1)
    fixture_observed = bytes(range(12))
    fixture_expected = {
        "A": "040800050901060a02070b03",
        "B": "0104070a0205080b00030609",
    }
    fable_fixture = {}
    for variant, expected in fixture_expected.items():
        got = core.transpose_inverse(fixture_observed,3,fixture_order,variant).hex()
        assert got == expected
        assert core.transpose_encrypt(bytes.fromhex(got),3,fixture_order,variant) == fixture_observed
        fable_fixture[variant] = {"expected_inverse_hex":expected,"matched":True}

    rng = random.Random(20260910)
    small = []
    for width in range(3,7):
        order = list(range(width)); rng.shuffle(order); order = tuple(order)
        plaintext = make_plain(width*12, False)
        ciphertext = core.cfb8(plaintext, False)
        for variant in ("A","B"):
            observed = core.transpose_encrypt(ciphertext,width,order,variant)
            assert core.transpose_inverse(observed,width,order,variant) == ciphertext
            reference = core.search(observed,width,variant,1_000_000)
            direct = core.naive(observed,width,variant)
            native_row = native(observed,width,variant,1_000_000)
            assert native_stats(native_row) == dataclasses.asdict(reference.stats)
            assert sorted(map(solution_key,native_row["solutions"])) == sorted(map(solution_key,reference.solutions))
            assert sorted(map(solution_key,direct)) == sorted(map(solution_key,reference.solutions))
            assert native_row["certificate_weight"] == native_row["expected_weight"] == math.factorial(width)
            assert not native_row["capped"]
            assert any(tuple(x["order"]) == order and bytes.fromhex(x["plaintext_hex"]) == plaintext
                       for x in native_row["solutions"])
            small.append({"width":width,"variant":variant,"order":list(order),
                          "stats":native_stats(native_row),"solution_count":len(direct),
                          "naive_reference_native_sets_equal":True,
                          "roundtrip_inverse":True})

    orders = {
        13:(7,0,12,3,9,1,5,11,2,8,4,10,6),
        14:(8,0,13,3,10,1,6,12,2,9,4,11,5,7),
    }
    registered_plain = make_plain(546,True)
    assert all(seq in registered_plain for seq in
               (bytes.fromhex("e28093"),bytes.fromhex("e28094"),bytes.fromhex("e28098"),
                bytes.fromhex("e28099"),bytes.fromhex("e280a6")))
    registered = []
    ct = core.cfb8(registered_plain,False)
    for width in (13,14):
        for variant in ("A","B"):
            observed = core.transpose_encrypt(ct,width,orders[width],variant)
            assert core.transpose_inverse(observed,width,orders[width],variant) == ct
            row = native(observed,width,variant,LIMIT)
            assert not row["capped"]
            assert row["certificate_weight"] == row["expected_weight"] == math.factorial(width)
            truth = [x for x in row["solutions"] if tuple(x["order"]) == orders[width]]
            assert len(truth)==1 and bytes.fromhex(truth[0]["plaintext_hex"]) == registered_plain
            assert len(row["solutions"]) == 1
            registered.append({"width":width,"variant":variant,"order":list(orders[width]),
                "observed_sha256":hashlib.sha256(observed).hexdigest(),
                "plaintext_sha256":hashlib.sha256(registered_plain).hexdigest(),
                "stats":native_stats(row),"certificate_weight":row["certificate_weight"],
                "expected_weight":row["expected_weight"],"elapsed_seconds":row["elapsed_seconds"],
                "truth_recovered":True,"unique_solution":True})

    random_observed = bytes(rng.randrange(256) for _ in range(546))
    random_rows = []
    for width in (13,14):
        for variant in ("A","B"):
            row = native(random_observed,width,variant,LIMIT)
            assert not row["capped"] and not row["solutions"]
            assert row["certificate_weight"] == row["expected_weight"] == math.factorial(width)
            random_rows.append({"width":width,"variant":variant,"stats":native_stats(row),
                "certificate_weight":row["certificate_weight"],"expected_weight":row["expected_weight"],
                "elapsed_seconds":row["elapsed_seconds"],"solution_count":0})

    capped_observed = core.transpose_encrypt(ct,14,orders[14],"A")
    capped = native(capped_observed,14,"A",1)
    assert capped["capped"] and capped["nodes"] == 1
    assert capped["certificate_weight"] < capped["expected_weight"]

    rev9 = json.loads(REV9_CONTROL.read_text())
    rev9_bytes = bytes.fromhex(rev9["rev9_full_chain"]["final_hex"])
    assert rev9_bytes[134:137] == bytes.fromhex("e280a6")
    assert not old4_valid(rev9_bytes)
    assert core.fsa_valid(rev9_bytes)
    assert not core.fsa_valid(b"OK "+bytes.fromhex("e2"))
    assert not core.fsa_valid(b"OK "+bytes.fromhex("e280"))

    compiler = subprocess.check_output(["clang++","--version"],text=True).splitlines()[0]
    openssl = subprocess.check_output(["pkg-config","--modversion","openssl"],text=True).strip()
    result = {
      "identity":IDENTITY,
      "target_evaluated":False,
      "rev7_file_read":False,
      "scope":"Synthetic equal-column byte transposition controls only; AES-128 CFB8, key Zombies NUL-padded to 16, ASCII-zero IV, widths 13/14, exact five-punctuation UTF-8 FSA.",
      "definitions":{
        "order":"order[k] is the natural column emitted at observed rank k, matching the cited FABLE implementation",
        "variant_A":"pre-transposition bytes row-major; observed bytes are contiguous column chunks in order",
        "variant_B":"pre-transposition bytes are contiguous natural-column chunks; observed bytes are row-major with columns visited in order",
        "node":"accepted-prefix DFS entry including root and complete entries",
        "certificate":"rejected assignment charges factorial(unassigned); accepted complete candidate charges one; capped certificate weight is a lower bound only",
      },
      "endpoint":{"ascii":[9,10,13,"32..126"],"utf8_sequences":["e28093","e28094","e28098","e28099","e280a6"],"strict_terminal_state_zero":True},
      "backend":{"compiler":compiler,"cpp_standard":"C++17","optimization":"-O3",
        "openssl_version":openssl,"primitive":"OpenSSL AES_set_encrypt_key/AES_encrypt"},
      "source_hashes":{"core.py":sha(HERE/"core.py"),"native.cpp":sha(HERE/"native.cpp"),
        "native_search":sha(BIN),"controls.py":sha(Path(__file__)),
        "fable_transpositions.js":sha(FABLE_TRANS),"fable_byteTranspositions.js":sha(FABLE_BYTE),
        "rev9_source_controls.json":sha(REV9_CONTROL)},
      "fable_fixed_inverse_fixture":fable_fixture,
      "small_width_3_to_6_exact_comparisons":small,
      "width_13_14_registered_five_utf8_plants":registered,
      "deterministic_random_546_byte_control":{"seed":20260910,
        "observed_sha256":hashlib.sha256(random_observed).hexdigest(),"rows":random_rows},
      "cap_semantics_control":{"width":14,"variant":"A","node_limit":1,
        "stats":native_stats(capped),"certificate_weight":capped["certificate_weight"],
        "expected_weight":capped["expected_weight"],"lower_bound_only":True},
      "rev9_endpoint_control":{"source_control_sha256":sha(REV9_CONTROL),
        "plaintext_sha256":hashlib.sha256(rev9_bytes).hexdigest(),"ellipsis_byte_offset":134,
        "old_four_sequence_fsa_accepts":False,"five_sequence_fsa_accepts":True,
        "truncated_e2_rejected":True,"truncated_e280_rejected":True},
      "assertions":{"all_passed":True,"no_rev7_input_access":True,
        "small_naive_reference_native_exact":True,"large_plants_unique_and_exhaustive":True,
        "random_controls_exhaustive_zero_survivors":True}
    }
    OUT.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"identity":IDENTITY,"controls":str(OUT),"sha256":sha(OUT),
      "registered":[{"width":x["width"],"variant":x["variant"],"nodes":x["stats"]["nodes"],
      "seconds":x["elapsed_seconds"]} for x in registered]},indent=2))

if __name__ == "__main__":
    main()
