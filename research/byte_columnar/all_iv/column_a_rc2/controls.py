#!/usr/bin/env python3
"""Synthetic-only RC2 controls for the rectangular column-A prefix engine."""
from __future__ import annotations
import argparse
import ctypes
import hashlib
import itertools
import json
import math
import platform
import random
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
COLUMN_A = HERE.parent / "column_a"
CORE = COLUMN_A / "core.py"
PROOF_LEDGER = COLUMN_A / "controls.json"
OUTPUT = HERE / "controls.json"
EXPECTED = {
    CORE: "1deda1788e9d9a49140325c7e0f7ce3eb53aa7d05e8e44590be4076da0bae472",
    PROOF_LEDGER: "2fb68eff8b80fb120ca972a29ead64268f03057c10c00156fd49152e0cf62bea",
    HERE / "source/rc2.c": "37c9398507cea1685255da9550f5a3a55b529b66e1bbc9a35e1996fecae7dc19",
    HERE / "source/rc2.h": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    HERE / "source/COPYING.LIB": "ca0061fc1381a3ab242310e4b3f56389f28e3d460eb2fd822ed7a21c6f030532",
    HERE / "source_build/libdefs.h": "556ec4fcebae614cd90d05a2fead50d9355ff39f65b44c8f4044c7f209074c6e",
    HERE / "source_build/mcrypt_modules.h": "2fefe3d60795fb19e7a7be1c4cec18a97c069e2471ae61c951706020dcb6c180",
    HERE / "native.cpp": "3c634ea5fa32caa146c2a078f85abdbc98984675744e7ffcf1977355e455a1cd",
}

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def verify_sources():
    for path, expected in EXPECTED.items():
        assert sha(path) == expected, (path, sha(path), expected)

def normalized(command, temporary):
    root = str(temporary)
    return [part.replace(root, "<TMP>") for part in command]

def compile_temporary(directory):
    obj = directory / "rc2.o"
    shared = directory / "librc2.so"
    binary = directory / "native_search"
    inc_build = str(HERE / "source_build")
    inc_source = str(HERE / "source")
    rc2 = str(HERE / "source/rc2.c")
    commands = [
        ["clang", "-O2", "-I" + inc_build, "-I" + inc_source, "-c", rc2, "-o", str(obj)],
        ["clang", "-shared", "-fPIC", "-O2", "-I" + inc_build, "-I" + inc_source, rc2, "-o", str(shared)],
        ["clang++", "-std=c++17", "-O3", str(HERE / "native.cpp"), str(obj), "-o", str(binary)],
    ]
    outputs = []
    for command in commands:
        completed = subprocess.run(command, check=True, capture_output=True, text=True)
        outputs.append({"command": normalized(command, directory), "stdout": completed.stdout, "stderr": completed.stderr})
    return obj, shared, binary, outputs

class SourceRC2:
    def __init__(self, shared, key):
        self.lib = ctypes.CDLL(str(shared))
        self.set_key = self.lib.rc2_LTX__mcrypt_set_key
        self.set_key.argtypes = [ctypes.POINTER(ctypes.c_uint16), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint]
        self.set_key.restype = ctypes.c_int
        self.encrypt_fn = self.lib.rc2_LTX__mcrypt_encrypt
        self.encrypt_fn.argtypes = [ctypes.POINTER(ctypes.c_uint16), ctypes.POINTER(ctypes.c_uint16)]
        self.encrypt_fn.restype = None
        self.schedule = (ctypes.c_uint16 * 64)()
        key_array = (ctypes.c_ubyte * len(key)).from_buffer_copy(key)
        assert self.set_key(self.schedule, key_array, len(key)) == 0
    def encrypt(self, block):
        assert len(block) == 8
        words = (ctypes.c_uint16 * 4).from_buffer_copy(block)
        self.encrypt_fn(self.schedule, words)
        return bytes(words)

def native(binary, *args, check=True):
    return subprocess.run([str(binary), *map(str, args)], check=check, capture_output=True, text=True)

def native_block(binary, block):
    return bytes.fromhex(native(binary, "--block", "rc2", block.hex()).stdout.strip())

def native_cfb(binary, action, iv, data):
    return bytes.fromhex(native(binary, action, "rc2", iv.hex(), data.hex()).stdout.strip())

def native_search(binary, width, limit, observed, count_only=False):
    args = ["--search", "rc2", width, limit, observed.hex()]
    if count_only:
        args.append("--count-only")
    return json.loads(native(binary, *args).stdout)

def cfb_manual(data, iv, encrypt_block, decrypt=False):
    register = iv
    output = bytearray()
    for value in data:
        transformed = encrypt_block(register)
        result = value ^ transformed[0]
        ciphertext = value if decrypt else result
        output.append(result)
        register = register[1:] + bytes([ciphertext])
    return bytes(output)

def fnv_survivors(rows):
    value = 14695981039346656037
    for row in rows:
        for item in row["first_slots"]:
            value ^= item; value = value * 1099511628211 & ((1 << 64) - 1)
        for item in row["surviving_ninth_ranks"]:
            value ^= item; value = value * 1099511628211 & ((1 << 64) - 1)
        value ^= 0xff; value = value * 1099511628211 & ((1 << 64) - 1)
    return f"{value:016x}"

def simplified(row):
    return [{"first_slots": x["first_slots"], "surviving_ninth_ranks": x["surviving_ninth_ranks"]} for x in row["survivor_prefixes"]]

def compare_search(actual, reference, complete):
    survivors = simplified(reference)
    assert actual["survivor_prefixes"] == survivors
    for key in ("prefixes_examined", "rejected_prefixes", "survivor_prefix_count",
                "completion_weight_per_prefix", "rejected_completion_weight",
                "expected_completion_weight", "block_calls", "rows_checked", "candidate_tests"):
        assert actual[key] == reference[key], (key, actual[key], reference[key])
    unresolved = reference.get("unresolved_examined_completion_weight", reference.get("unresolved_completion_weight"))
    assert actual["unresolved_examined_completion_weight"] == unresolved
    assert actual["survivor_digest_fnv1a64"] == fnv_survivors(survivors)
    assert actual["factorial_partition_complete"]
    if complete:
        assert actual["complete_scan"] and actual["unexamined_prefixes"] == actual["unexamined_completion_weight"] == 0
    else:
        assert actual["unexamined_prefixes"] == reference["unexamined_prefixes"]
        assert actual["unexamined_completion_weight"] == reference["unexamined_completion_weight"]
    return survivors

def prefix_reference(core, observed, width, limit, first):
    survivors = []
    rejected = block_calls = rows_checked = candidate_tests = 0
    for prefix in itertools.islice(itertools.permutations(range(width), 8), limit):
        row = core.evaluate_first_block_tuple(observed, width, 8, prefix, first, core.A105)
        block_calls += row["block_calls"]; rows_checked += row["rows_checked"]
        candidate_tests += row["candidate_tests"]
        if row["empty_candidate_mask"]: rejected += 1
        else: survivors.append(row)
    completion = math.factorial(width - 8)
    total = math.perm(width, 8)
    unexamined = total - limit
    return {
        "survivor_prefixes": survivors, "prefixes_examined": limit,
        "rejected_prefixes": rejected, "survivor_prefix_count": len(survivors),
        "completion_weight_per_prefix": completion,
        "rejected_completion_weight": rejected * completion,
        "unresolved_examined_completion_weight": len(survivors) * completion,
        "unexamined_prefixes": unexamined,
        "unexamined_completion_weight": unexamined * completion,
        "expected_completion_weight": math.factorial(width),
        "block_calls": block_calls, "rows_checked": rows_checked,
        "candidate_tests": candidate_tests,
    }

def regenerate(output):
    verify_sources()
    proof = json.loads(PROOF_LEDGER.read_text())
    assert proof["identity"] == "ASTRA" and proof["target_evaluated"] is False
    import importlib.util
    from Crypto.Cipher import ARC2
    import Crypto
    spec = importlib.util.spec_from_file_location("column_a_core", CORE)
    core = importlib.util.module_from_spec(spec); spec.loader.exec_module(core)
    with tempfile.TemporaryDirectory(prefix="column-a-rc2-") as temporary_name:
        temporary = Path(temporary_name)
        obj, shared, binary, build_rows = compile_temporary(temporary)
        fixed_key = b"Zombies"
        source_fixed = SourceRC2(shared, fixed_key)
        independent_fixed = ARC2.new(fixed_key, ARC2.MODE_ECB, effective_keylen=1024)

        # Source KAT and varied keys/blocks against an independent implementation.
        source_key = bytes((j * 2 + 10) % 256 for j in range(128))
        kat_plain = bytes(range(8))
        kat = SourceRC2(shared, source_key).encrypt(kat_plain)
        assert kat.hex() == "becbe4c8e6237a14"
        rng = random.Random(0xA2C21024)
        varied = []
        keys = (b"abcde", fixed_key, bytes(range(16)), bytes(range(128)))
        blocks = [bytes(range(8)), bytes([255]) * 8]
        blocks += [bytes(rng.randrange(256) for _ in range(8)) for _ in range(30)]
        for key in keys:
            actual_source = SourceRC2(shared, key)
            independent = ARC2.new(key, ARC2.MODE_ECB, effective_keylen=1024)
            outputs = []
            for block in blocks:
                actual = actual_source.encrypt(block)
                expected = independent.encrypt(block)
                assert actual == expected
                outputs.append({"block_hex": block.hex(), "ciphertext_hex": actual.hex()})
            varied.append({"key_hex": key.hex(), "key_length": len(key), "effective_keylen": 1024,
                           "vector_count": len(outputs), "vectors": outputs, "all_match": True})
        native_vectors = []
        for row in varied[1]["vectors"]:
            block = bytes.fromhex(row["block_hex"])
            actual = native_block(binary, block)
            assert actual.hex() == row["ciphertext_hex"]
            native_vectors.append(row)

        # Complete full-byte CFB8 checks under two IVs.
        all_bytes = bytes(range(256))
        cfb_rows = []
        for iv in (b"0" * 8, bytes.fromhex("0011223344556677")):
            source_ciphertext = cfb_manual(all_bytes, iv, source_fixed.encrypt)
            independent_mode = ARC2.new(fixed_key, ARC2.MODE_CFB, iv=iv, segment_size=8).encrypt(all_bytes)
            encrypted = native_cfb(binary, "--cfb-encrypt", iv, all_bytes)
            decrypted = native_cfb(binary, "--cfb-decrypt", iv, encrypted)
            assert source_ciphertext == independent_mode == encrypted and decrypted == all_bytes
            cfb_rows.append({"iv_hex": iv.hex(), "plaintext_hex": all_bytes.hex(),
                             "ciphertext_hex": encrypted.hex(),
                             "ciphertext_sha256": hashlib.sha256(encrypted).hexdigest(),
                             "source_manual_independent_mode_native_match": True,
                             "native_roundtrip": True})

        first = lambda block: independent_fixed.encrypt(block)[0]
        # Complete width-9 planted checks under both IVs.
        width = 9; rows = 5
        order = (8, 1, 7, 0, 5, 3, 6, 2, 4)
        slots = core.inverse_order(order); truth_prefix = slots[:8]; truth_ninth = slots[8]
        phrase = "ALPHA – BETA — GAMMA ‘DELTA’ … END. ".encode("utf-8")
        plaintext = (phrase * ((width * rows + len(phrase) - 1) // len(phrase)))[:width * rows]
        assert all(value in core.A105 for value in plaintext)
        complete_rows = []
        for iv in (b"0" * 8, bytes.fromhex("0011223344556677")):
            ciphertext = ARC2.new(fixed_key, ARC2.MODE_CFB, iv=iv, segment_size=8).encrypt(plaintext)
            observed = core.observe_variant_a(ciphertext, width, order)
            reference = core.scan_first_block_prefixes(observed, width, 8, first, core.A105)
            actual = native_search(binary, width, math.perm(width, 8), observed)
            survivors = compare_search(actual, reference, True)
            truth = [x for x in survivors if tuple(x["first_slots"]) == truth_prefix]
            assert len(truth) == 1 and truth_ninth in truth[0]["surviving_ninth_ranks"]
            assert actual["rejected_prefixes"] > 0 and actual["survivor_prefix_count"] > 0
            complete_rows.append({"width": width, "rows": rows, "iv_hex": iv.hex(),
                                  "fable_order": list(order), "truth_first_slots": list(truth_prefix),
                                  "truth_ninth_rank": truth_ninth, "observed_hex": observed.hex(),
                                  "observed_sha256": hashlib.sha256(observed).hexdigest(),
                                  "prefixes_examined": actual["prefixes_examined"],
                                  "rejected_prefixes": actual["rejected_prefixes"],
                                  "survivor_prefix_count": actual["survivor_prefix_count"],
                                  "block_calls": actual["block_calls"], "candidate_tests": actual["candidate_tests"],
                                  "survivor_digest_fnv1a64": actual["survivor_digest_fnv1a64"],
                                  "truth_retained": True, "exact_ordered_sets_and_counters": True,
                                  "factorial_partition_complete": True, "elapsed_seconds": actual["elapsed_seconds"]})

        # Short wider cases include multiple-candidate masks and cap accounting.
        short_rng = random.Random(0xA105C02A)
        wider = []
        for width in (10, 13, 14):
            observed = bytes(short_rng.randrange(256) for _ in range(width * 2))
            limit = 1_000
            reference = prefix_reference(core, observed, width, limit, first)
            actual = native_search(binary, width, limit, observed)
            survivors = compare_search(actual, reference, False)
            multiple = sum(len(x["surviving_ninth_ranks"]) > 1 for x in survivors)
            assert actual["rejected_prefixes"] > 0 and actual["survivor_prefix_count"] > 0 and multiple > 0
            assert actual["unexamined_prefixes"] == math.perm(width, 8) - limit
            assert actual["rejected_completion_weight"] + actual["unresolved_examined_completion_weight"] + actual["unexamined_completion_weight"] == math.factorial(width)
            wider.append({"width": width, "rows": 2, "prefix_budget": limit,
                          "observed_hex": observed.hex(), "observed_sha256": hashlib.sha256(observed).hexdigest(),
                          "rejected_prefixes": actual["rejected_prefixes"],
                          "survivor_prefix_count": actual["survivor_prefix_count"],
                          "multiple_candidate_prefix_count": multiple,
                          "unexamined_prefixes": actual["unexamined_prefixes"],
                          "block_calls": actual["block_calls"], "candidate_tests": actual["candidate_tests"],
                          "survivor_digest_fnv1a64": actual["survivor_digest_fnv1a64"],
                          "exact_ordered_sets_and_counters": True, "factorial_partition_complete": True})

        # Invalid CLI cases.
        invalid = []
        cases = [
            ["--block", "unknown", "0000000000000000"], ["--block", "rc2", "00"],
            ["--cfb-encrypt", "rc2", "00", "00"], ["--search", "rc2", "8", "1", "00" * 8],
            ["--search", "rc2", "0", "1", "00"], ["--search", "rc2", "9", "0", "00" * 9],
            ["--search", "rc2", "9", "1", "00" * 10],
        ]
        for args in cases:
            completed = native(binary, *args, check=False)
            assert completed.returncode != 0 and completed.stderr.strip()
            invalid.append({"arguments": args, "returncode": completed.returncode, "stderr": completed.stderr.strip()})

        # Representative public synthetic million-prefix samples.
        fixture_rng = random.Random(0xC01A2C2)
        fixture = bytes(fixture_rng.randrange(256) for _ in range(546))
        benchmarks = []
        for width in (13, 14):
            actual = native_search(binary, width, 1_000_000, fixture, count_only=True)
            assert actual["prefixes_examined"] == 1_000_000 and not actual["complete_scan"]
            assert not actual["survivors_retained"] and actual["survivor_prefixes"] == []
            assert actual["rejected_completion_weight"] + actual["unresolved_examined_completion_weight"] + actual["unexamined_completion_weight"] == math.factorial(width)
            rate = actual["prefixes_examined"] / actual["elapsed_seconds"]
            benchmarks.append({**{key: actual[key] for key in (
                "width", "rows", "prefix_limit", "total_prefixes", "prefixes_examined",
                "rejected_prefixes", "survivor_prefix_count", "completion_weight_per_prefix",
                "rejected_completion_weight", "unresolved_examined_completion_weight",
                "unexamined_prefixes", "unexamined_completion_weight", "expected_completion_weight",
                "factorial_partition_complete", "complete_scan", "block_calls", "rows_checked",
                "candidate_tests", "survivor_digest_fnv1a64", "survivors_retained", "elapsed_seconds")},
                "native_output": actual,
                "prefixes_per_second": rate,
                "linear_full_prefix_time_estimate_seconds": actual["total_prefixes"] / rate,
                "estimate_limit": "Linear projection from the first lexicographic million on one synthetic fixture; target early-stop distribution and host performance can differ."})

        compiler = subprocess.check_output(["clang++", "--version"], text=True).splitlines()[0]
        result = {
            "identity": "ASTRA", "target_evaluated": False, "rev7_read": False,
            "scope": "Synthetic-only source-backed RC2 column-A prefix engine; raw seven-byte Zombies, effective 1024-bit schedule, A105; no target, IV/order/plaintext recovery, or other context.",
            "algorithm": {"enumeration": "lexicographic first-eight observed-rank tuples",
                          "candidate_mask": "unused ninth ranks intersected across all rows",
                          "rejected_weight": "(width-8)! per empty-mask tuple",
                          "survivor_meaning": "unresolved first-eight tuple plus possible ninth ranks only",
                          "cap_accounting": "rejected examined + unresolved examined + unexamined weights partition width!"},
            "source_kat": {"key_formula": "(j*2+10)%256 for 128 bytes", "plaintext_hex": kat_plain.hex(),
                           "ciphertext_hex": kat.hex(), "matches_source_embedded_kat": True},
            "varied_key_block_vectors": varied,
            "fixed_raw7_native_block_vectors": native_vectors,
            "full_256_byte_cfb8_two_iv": cfb_rows,
            "complete_width9_planted_python_native_parity": complete_rows,
            "bounded_wider_multiple_candidate_parity": wider,
            "invalid_input_controls": invalid,
            "benchmark_fixture": {"generator": "Python random.Random(0xC01A2C2), 546 calls to randrange(256)",
                                  "observed_hex": fixture.hex(), "sha256": hashlib.sha256(fixture).hexdigest(),
                                  "prefix_budget_per_width": 1_000_000},
            "bounded_benchmarks": benchmarks,
            "key_convention": {"input_key_hex": fixed_key.hex(), "input_length": 7,
                               "source_metadata_supported_count": 0, "source_metadata_max_bytes": 128,
                               "effective_bits": 1024,
                               "evidence": "libmcrypt passes raw length 7; rc2.c expands raw seed to 128 bytes and has effective-size reduction stripped"},
            "source_provenance": {"repository": "https://github.com/Distrotech/libmcrypt",
                                  "commit": "3bd338e2f808e985f5b229a7642d48c26615993f",
                                  "compiled_historical_source_unmodified": True,
                                  "hashes": {str(path.relative_to(HERE)): value for path, value in EXPECTED.items() if path.is_relative_to(HERE)},
                                  "frozen_column_a_core": EXPECTED[CORE], "frozen_column_a_proof_ledger": EXPECTED[PROOF_LEDGER]},
            "build": {"temporary": True, "commands": build_rows, "compiler": compiler,
                      "python": platform.python_version(), "pycryptodome": Crypto.__version__,
                      "temporary_object_sha256_machine_evidence": sha(obj),
                      "temporary_shared_sha256_machine_evidence": sha(shared),
                      "temporary_binary_sha256_machine_evidence": sha(binary),
                      "controls_source_sha256": sha(Path(__file__)),
                      "portable_commands": [
                          "clang -O2 -Isource_build -Isource -c source/rc2.c -o /tmp/rc2.o",
                          "clang -shared -fPIC -O2 -Isource_build -Isource source/rc2.c -o /tmp/librc2.so",
                          "clang++ -std=c++17 -O3 native.cpp /tmp/rc2.o -o /tmp/native_search"]},
            "assertions": {"all_passed": True, "source_hashes_pinned": True,
                           "source_kat_passed": True, "varied_keys_blocks_match_arc2_1024": True,
                           "fixed_raw7_native_blocks_match": True, "two_full_cfb8_streams_match_and_roundtrip": True,
                           "complete_width9_exact_sets_counters_and_plants": True,
                           "bounded_wider_multiple_candidate_sets_and_accounting": True,
                           "invalid_inputs_rejected": True, "no_target_read_or_evaluation": True},
        }
        output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        return result

def verify_existing():
    verify_sources()
    data = json.loads(OUTPUT.read_text())
    assert data["identity"] == "ASTRA" and data["target_evaluated"] is False and data["rev7_read"] is False
    assert data["assertions"]["all_passed"] is True
    assert data["build"]["controls_source_sha256"] == sha(Path(__file__))
    assert data["source_provenance"]["frozen_column_a_core"] == EXPECTED[CORE]
    assert data["source_provenance"]["frozen_column_a_proof_ledger"] == EXPECTED[PROOF_LEDGER]
    assert len(data["varied_key_block_vectors"]) == 4
    assert all(row["vector_count"] == 32 and row["all_match"] for row in data["varied_key_block_vectors"])
    assert len(data["full_256_byte_cfb8_two_iv"]) == 2
    assert len(data["complete_width9_planted_python_native_parity"]) == 2
    assert len(data["bounded_wider_multiple_candidate_parity"]) == 3
    print(json.dumps({"identity": "ASTRA", "verified": True, "read_only": True,
                      "compiled_binary_or_crypto_required": False, "ledger_sha256": sha(OUTPUT)}, indent=2))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--regenerate", type=Path)
    args = parser.parse_args()
    if args.regenerate is None:
        verify_existing(); return
    if args.regenerate.exists():
        raise SystemExit("refusing existing output: " + str(args.regenerate))
    result = regenerate(args.regenerate)
    print(json.dumps({"identity": "ASTRA", "target_evaluated": False,
                      "output": str(args.regenerate), "sha256": sha(args.regenerate),
                      "complete_width9": [{"iv": row["iv_hex"], "survivors": row["survivor_prefix_count"],
                                           "seconds": row["elapsed_seconds"]} for row in result["complete_width9_planted_python_native_parity"]],
                      "benchmarks": [{"width": row["width"], "seconds": row["elapsed_seconds"],
                                      "full_projection_seconds": row["linear_full_prefix_time_estimate_seconds"]} for row in result["bounded_benchmarks"]]}, indent=2))

if __name__ == "__main__":
    main()
