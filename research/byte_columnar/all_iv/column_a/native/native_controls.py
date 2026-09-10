#!/usr/bin/env python3
"""Synthetic-only native controls for the column-A first-block certificate."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import itertools
import json
import math
import platform
import random
import subprocess
import sys
import tempfile
from pathlib import Path

DES = Blowfish = Crypto = None

HERE = Path(__file__).resolve().parent
COLUMN = HERE.parent
REPO = HERE.parents[4]
BINARY = HERE / "native_search"
OUTPUT = HERE / "native_controls.json"
sys.path.insert(0, str(COLUMN))
import core  # noqa: E402

PROOF_LEDGER = COLUMN / "controls.json"
COMPAT_SOURCE = COLUMN / "compat_source"
COMPAT_NATIVE = REPO / "research/rev7-20260909-codex/hex_cfb/native_compat"
EXPECTED = {
    COLUMN / "core.py": "1deda1788e9d9a49140325c7e0f7ce3eb53aa7d05e8e44590be4076da0bae472",
    PROOF_LEDGER: "2fb68eff8b80fb120ca972a29ead64268f03057c10c00156fd49152e0cf62bea",
    COMPAT_SOURCE / "build_compat.py": "6c0ab4888febcf87d45515bd4ad8b34f11a85edb05d0cb99ad1f75b8dd24f0aa",
    COMPAT_SOURCE / "blowfish-compat.c": "3584374a6bae4df8899e82d36255bbac0472904aed2095e3c08c57a5dd5b4cad",
    COMPAT_SOURCE / "blowfish.h": "bb4a14ecbd5dc92105b290d9261ed562a980c6e42b0d9b4b56e62b4b6c39665b",
    COMPAT_SOURCE / "COPYING.LIB": "ca0061fc1381a3ab242310e4b3f56389f28e3d460eb2fd822ed7a21c6f030532",
    COMPAT_SOURCE / "libdefs.h": "cdffb7ef7bc27b6eea90b73174077c377d8260ffd111fb8de3c2bbc938e28a31",
    COMPAT_SOURCE / "mcrypt_modules.h": "2fefe3d60795fb19e7a7be1c4cec18a97c069e2471ae61c951706020dcb6c180",
    REPO / "research/rev7-20260909-codex/hex_cfb/native_text5/native_text5.cpp": "81bd9902f3f5fb0585214c2c93117523426cdc61edb524334d64412d4a5d724f",
    REPO / "research/rev7-20260909-codex/hex_cfb/native_compat/native_compat.cpp": "c8527d2bf43494944475a20e0ffc8a99358243c8f188d394335af4ec9b0f8cb7",
}
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def verify_sources():
    for path, expected in EXPECTED.items():
        assert sha(path) == expected, (path, sha(path), expected)

def native(*args, check=True):
    return subprocess.run([str(BINARY), *map(str, args)], text=True, capture_output=True, check=check)

def native_block(backend, block):
    return bytes.fromhex(native("--block", backend, block.hex()).stdout.strip())

def native_cfb(action, backend, iv, data):
    return bytes.fromhex(native(action, backend, iv.hex(), data.hex()).stdout.strip())

def native_search(backend, width, limit, observed, count_only=False):
    args = ["--search", backend, width, limit, observed.hex()]
    if count_only:
        args.append("--count-only")
    return json.loads(native(*args).stdout)

def word_reverse(block):
    return block[3::-1] + block[7:3:-1]

des_ecb = None
bf_ecb = None
COMPAT_ACTUAL_BYTES = None

def block_bytes(backend, block):
    if backend == "des":
        return des_ecb.encrypt(block)
    if backend == "blowfish":
        return bf_ecb.encrypt(block)
    if backend == "blowfish_compat":
        actual = COMPAT_ACTUAL_BYTES(block)
        conjugated = word_reverse(bf_ecb.encrypt(word_reverse(block)))
        assert actual == conjugated
        return actual
    raise ValueError(backend)

def block_first(backend):
    return lambda block: block_bytes(backend, block)[0]

def produce(output_path):
    global COMPAT_ACTUAL_BYTES, DES, Blowfish, Crypto, des_ecb, bf_ecb
    from Crypto.Cipher import DES as CryptoDES, Blowfish as CryptoBlowfish
    import Crypto as CryptoModule
    DES, Blowfish, Crypto = CryptoDES, CryptoBlowfish, CryptoModule
    des_ecb = DES.new(b"Zombies\0", DES.MODE_ECB)
    bf_ecb = Blowfish.new(b"Zombies", Blowfish.MODE_ECB)
    verify_sources()
    assert BINARY.exists(), "build native_search before regenerating controls"
    proof = json.loads(PROOF_LEDGER.read_text())
    assert proof["identity"] == "ASTRA" and proof["target_evaluated"] is False
    spec = importlib.util.spec_from_file_location("column_a_compat_build", COMPAT_SOURCE / "build_compat.py")
    build_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(build_module)
    temporary = tempfile.TemporaryDirectory(prefix="column-a-native-compat-")
    compatibility_library = Path(temporary.name) / "libblowfish_compat.so"
    compatibility_command = build_module.build(compatibility_library)
    compatibility_actual = build_module.load(compatibility_library)
    COMPAT_ACTUAL_BYTES = lambda block: compatibility_actual(b"Zombies", block)
    rng = random.Random(20260910)
    block_vectors = []
    blocks = [bytes(range(8)), bytes([255] * 8)]
    blocks.extend(bytes(rng.randrange(256) for _ in range(8)) for _ in range(30))
    for backend in ("des", "blowfish", "blowfish_compat"):
        for index, block in enumerate(blocks):
            expected = block_bytes(backend, block)
            actual = native_block(backend, block)
            assert actual == expected
            block_vectors.append({
                "backend": backend,
                "index": index,
                "input_hex": block.hex(),
                "output_hex": actual.hex(),
                "match": True,
            })

    def manual_cfb_encrypt(plaintext, iv, backend):
        register = iv
        output = bytearray()
        for value in plaintext:
            ciphertext = value ^ block_bytes(backend, register)[0]
            output.append(ciphertext)
            register = register[1:] + bytes([ciphertext])
        return bytes(output)

    cfb_vectors = []
    all_bytes = bytes(range(256))
    ivs = {
        "des": bytes.fromhex("0011223344556677"),
        "blowfish": bytes.fromhex("1020304050607080"),
        "blowfish_compat": bytes.fromhex("13579bdf2468ace0"),
    }
    for backend, iv in ivs.items():
        expected = manual_cfb_encrypt(all_bytes, iv, backend)
        if backend == "des":
            assert expected == DES.new(b"Zombies\0", DES.MODE_CFB, iv=iv, segment_size=8).encrypt(all_bytes)
        elif backend == "blowfish":
            assert expected == Blowfish.new(b"Zombies", Blowfish.MODE_CFB, iv=iv, segment_size=8).encrypt(all_bytes)
        encrypted = native_cfb("--cfb-encrypt", backend, iv, all_bytes)
        decrypted = native_cfb("--cfb-decrypt", backend, iv, encrypted)
        assert encrypted == expected and decrypted == all_bytes
        cfb_vectors.append({
            "backend": backend,
            "iv_hex": iv.hex(),
            "plaintext_sha256": hashlib.sha256(all_bytes).hexdigest(),
            "ciphertext_hex": encrypted.hex(),
            "ciphertext_sha256": hashlib.sha256(encrypted).hexdigest(),
            "native_encrypt_matches_independent": True,
            "native_decrypt_roundtrip": True,
            "standard_library_mode_match": backend != "blowfish_compat",
            "compat_actual_c_and_word_conjugation_match": backend == "blowfish_compat",
        })

    # Direct historical-C equality has now covered all ECB vectors and the
    # complete 256-byte CFB8 stream.  Use the independently checked
    # PyCryptodome word-conjugation for larger scans because the historical
    # helper intentionally rekeys on every block call.
    COMPAT_ACTUAL_BYTES = lambda block: word_reverse(bf_ecb.encrypt(word_reverse(block)))

    def fnv_survivors(rows):
        value = 14695981039346656037
        for row in rows:
            for item in row["first_slots"]:
                value ^= item
                value = (value * 1099511628211) & ((1 << 64) - 1)
            for item in row["surviving_ninth_ranks"]:
                value ^= item
                value = (value * 1099511628211) & ((1 << 64) - 1)
            value ^= 0xff
            value = (value * 1099511628211) & ((1 << 64) - 1)
        return f"{value:016x}"

    # Complete width-9 scans: planted truth plus deliberate varied nonzero masks.
    width = 9
    rows = 5
    order = (8, 1, 7, 0, 5, 3, 6, 2, 4)
    slots = core.inverse_order(order)
    truth_prefix = slots[:8]
    truth_ninth = slots[8]
    phrase = "ALPHA – BETA — GAMMA ‘DELTA’ … END. ".encode("utf-8")
    plaintext = (phrase * ((width * rows + len(phrase) - 1) // len(phrase)))[:width * rows]
    assert len(plaintext) == width * rows and all(value in core.A105 for value in plaintext)
    complete_rows = []
    for backend, iv in ivs.items():
        ciphertext = manual_cfb_encrypt(plaintext, iv, backend)
        observed = core.observe_variant_a(ciphertext, width, order)
        reference = core.scan_first_block_prefixes(
            observed, width, 8, block_first(backend), core.A105
        )
        actual = native_search(backend, width, math.perm(width, 8), observed)
        reference_survivors = [
            {
                "first_slots": row["first_slots"],
                "surviving_ninth_ranks": row["surviving_ninth_ranks"],
            }
            for row in reference["survivor_prefixes"]
        ]
        assert actual["survivor_prefixes"] == reference_survivors
        for key in (
            "prefixes_examined", "rejected_prefixes", "survivor_prefix_count",
            "completion_weight_per_prefix", "rejected_completion_weight",
            "expected_completion_weight", "block_calls", "rows_checked", "candidate_tests"
        ):
            expected = reference[key]
            assert actual[key] == expected, (backend, key, actual[key], expected)
        assert actual["unresolved_examined_completion_weight"] == reference["unresolved_completion_weight"]
        assert actual["unexamined_prefixes"] == actual["unexamined_completion_weight"] == 0
        assert actual["factorial_partition_complete"] and actual["complete_scan"]
        assert actual["rejected_prefixes"] > 0
        assert actual["survivor_digest_fnv1a64"] == fnv_survivors(reference_survivors)
        truth = [
            row for row in actual["survivor_prefixes"]
            if tuple(row["first_slots"]) == truth_prefix
        ]
        assert len(truth) == 1 and truth_ninth in truth[0]["surviving_ninth_ranks"]
        distinct_nonzero_masks = {
            tuple(row["surviving_ninth_ranks"]) for row in actual["survivor_prefixes"]
        }
        assert len(distinct_nonzero_masks) >= 3
        complete_rows.append({
            "backend": backend,
            "width": width,
            "rows": rows,
            "fable_order": list(order),
            "truth_first_slots": list(truth_prefix),
            "truth_ninth_rank": truth_ninth,
            "observed_hex": observed.hex(),
            "observed_sha256": hashlib.sha256(observed).hexdigest(),
            "prefixes_examined": actual["prefixes_examined"],
            "rejected_prefixes": actual["rejected_prefixes"],
            "survivor_prefix_count": actual["survivor_prefix_count"],
            "distinct_nonzero_candidate_masks": len(distinct_nonzero_masks),
            "block_calls": actual["block_calls"],
            "candidate_tests": actual["candidate_tests"],
            "survivor_digest_fnv1a64": actual["survivor_digest_fnv1a64"],
            "exact_python_native_prefix_and_candidate_sets": True,
            "truth_retained": True,
            "factorial_partition_complete": True,
            "elapsed_seconds": actual["elapsed_seconds"],
        })

    # Bounded wider-width parity checks exercise intersections with more than
    # one surviving unused rank, comparing ordered sets, counters, and weights.
    def python_prefix_sample(backend, width, limit, observed):
        survivors = []
        rejected = block_calls = rows_checked = candidate_tests = 0
        for prefix in itertools.islice(itertools.permutations(range(width), 8), limit):
            row = core.evaluate_first_block_tuple(
                observed, width, 8, prefix, block_first(backend), core.A105
            )
            block_calls += row["block_calls"]
            rows_checked += row["rows_checked"]
            candidate_tests += row["candidate_tests"]
            if row["empty_candidate_mask"]:
                rejected += 1
            else:
                survivors.append({
                    "first_slots": row["first_slots"],
                    "surviving_ninth_ranks": row["surviving_ninth_ranks"],
                })
        completion = math.factorial(width - 8)
        total_prefixes = math.perm(width, 8)
        unexamined = total_prefixes - limit
        return {
            "survivor_prefixes": survivors,
            "prefixes_examined": limit,
            "rejected_prefixes": rejected,
            "survivor_prefix_count": len(survivors),
            "completion_weight_per_prefix": completion,
            "rejected_completion_weight": rejected * completion,
            "unresolved_examined_completion_weight": len(survivors) * completion,
            "unexamined_prefixes": unexamined,
            "unexamined_completion_weight": unexamined * completion,
            "expected_completion_weight": math.factorial(width),
            "block_calls": block_calls,
            "rows_checked": rows_checked,
            "candidate_tests": candidate_tests,
        }

    short_rng = random.Random(0xA105C01A)
    bounded_multiple = []
    for width in (10, 13, 14):
        observed = bytes(short_rng.randrange(256) for _ in range(width * 2))
        limit = 1_000
        reference = python_prefix_sample("des", width, limit, observed)
        actual = native_search("des", width, limit, observed)
        assert actual["survivor_prefixes"] == reference["survivor_prefixes"]
        for key in (
            "prefixes_examined", "rejected_prefixes", "survivor_prefix_count",
            "completion_weight_per_prefix", "rejected_completion_weight",
            "unresolved_examined_completion_weight", "unexamined_prefixes",
            "unexamined_completion_weight", "expected_completion_weight",
            "block_calls", "rows_checked", "candidate_tests",
        ):
            assert actual[key] == reference[key], (width, key, actual[key], reference[key])
        assert actual["factorial_partition_complete"]
        assert actual["survivor_digest_fnv1a64"] == fnv_survivors(reference["survivor_prefixes"])
        multiple = sum(
            len(row["surviving_ninth_ranks"]) > 1
            for row in reference["survivor_prefixes"]
        )
        assert actual["rejected_prefixes"] > 0 and actual["survivor_prefix_count"] > 0
        assert multiple > 0
        bounded_multiple.append({
            "backend": "des",
            "width": width,
            "rows": 2,
            "prefix_budget": limit,
            "observed_hex": observed.hex(),
            "observed_sha256": hashlib.sha256(observed).hexdigest(),
            "rejected_prefixes": actual["rejected_prefixes"],
            "survivor_prefix_count": actual["survivor_prefix_count"],
            "multiple_candidate_prefix_count": multiple,
            "block_calls": actual["block_calls"],
            "candidate_tests": actual["candidate_tests"],
            "survivor_digest_fnv1a64": actual["survivor_digest_fnv1a64"],
            "exact_ordered_python_native_survivors_and_counters": True,
            "factorial_partition_complete": True,
        })

    # Invalid-input behavior.
    invalid_cases = []
    commands = [
        ["--block", "unknown", "0000000000000000"],
        ["--block", "des", "00"],
        ["--cfb-encrypt", "des", "00", "00"],
        ["--search", "des", "8", "1", "0000000000000000"],
        ["--search", "des", "0", "1", "00"],
        ["--search", "des", "9", "0", "00" * 9],
        ["--search", "des", "9", "1", "00" * 10],
    ]
    for command in commands:
        result = native(*command, check=False)
        assert result.returncode != 0 and result.stderr.strip()
        invalid_cases.append({
            "arguments": command,
            "returncode": result.returncode,
            "stderr": result.stderr.strip(),
        })

    # Public deterministic random fixture and bounded performance sample.
    fixture_rng = random.Random(0xC01A2026)
    fixture = bytes(fixture_rng.randrange(256) for _ in range(546))
    benchmark_limit = 1_000_000
    benchmarks = []
    for width in (13, 14):
        row = native_search("des", width, benchmark_limit, fixture, count_only=True)
        assert row["prefixes_examined"] == benchmark_limit
        assert not row["complete_scan"]
        assert not row["survivors_retained"] and not row["survivor_prefixes"]
        assert row["rejected_prefixes"] + row["survivor_prefix_count"] == benchmark_limit
        assert (
            row["rejected_completion_weight"]
            + row["unresolved_examined_completion_weight"]
            + row["unexamined_completion_weight"]
            == row["expected_completion_weight"] == math.factorial(width)
        )
        prefix_rate = row["prefixes_examined"] / row["elapsed_seconds"]
        block_rate = row["block_calls"] / row["elapsed_seconds"]
        benchmarks.append({
            **{key: row[key] for key in (
                "backend", "width", "rows", "prefix_limit", "total_prefixes",
                "prefixes_examined", "rejected_prefixes", "survivor_prefix_count",
                "completion_weight_per_prefix", "rejected_completion_weight",
                "unresolved_examined_completion_weight", "unexamined_prefixes",
                "unexamined_completion_weight", "expected_completion_weight",
                "factorial_partition_complete", "complete_scan", "block_calls",
                "rows_checked", "candidate_tests", "survivor_digest_fnv1a64",
                "survivors_retained", "elapsed_seconds"
            )},
            "prefixes_per_second": prefix_rate,
            "block_calls_per_second": block_rate,
            "linear_full_prefix_time_estimate_seconds": row["total_prefixes"] / prefix_rate,
            "estimate_limit": (
                "Linear projection from the first lexicographic prefix budget on one synthetic "
                "fixture; early-stop distribution and machine performance can differ in a full run."
            ),
        })

    compiler = subprocess.check_output(["clang++", "--version"], text=True).splitlines()[0]
    openssl_version = subprocess.check_output(["pkg-config", "--modversion", "openssl"], text=True).strip()
    build_command = (
        "clang++ -std=c++17 -O3 -Wno-deprecated-declarations "
        "-I/opt/homebrew/Cellar/openssl@3/3.6.3/include "
        "research/byte_columnar/all_iv/column_a/native/native.cpp "
        "-L/opt/homebrew/Cellar/openssl@3/3.6.3/lib -lcrypto "
        "-o research/byte_columnar/all_iv/column_a/native/native_search"
    )
    out = {
        "identity": "ASTRA",
        "target_evaluated": False,
        "rev7_read": False,
        "scope": (
            "Synthetic-only native implementation and controls for rectangular FABLE columnarA, "
            "DES/Blowfish/Blowfish-compat fixed Zombies key conventions, A105, first-eight prefix "
            "and ninth-rank feasibility. No target, IV/order/plaintext recovery, or new cipher context."
        ),
        "algorithm": {
            "enumeration": "lexicographic distinct observed-rank tuples for natural columns 0..7",
            "candidate_mask": "unused ranks intersected across rows for natural column 8",
            "early_stop": "stop tuple when candidate mask becomes empty",
            "rejected_weight": "(width-8)! complete orders for each empty-mask tuple",
            "survivor_meaning": "unresolved first-eight tuple plus possible ninth ranks only",
            "cap": "prefix budget; examined rejected + examined unresolved + unexamined weights partition width!",
        },
        "block_vectors": block_vectors,
        "block_vector_count": len(block_vectors),
        "full_cfb8_vectors": cfb_vectors,
        "complete_width9_python_native_parity": complete_rows,
        "bounded_multiple_candidate_python_native_parity": bounded_multiple,
        "invalid_input_controls": invalid_cases,
        "benchmark_fixture": {
            "generator": "Python random.Random(0xC01A2026), 546 calls to randrange(256)",
            "observed_hex": fixture.hex(),
            "sha256": hashlib.sha256(fixture).hexdigest(),
            "backend": "des",
            "prefix_budget_per_width": benchmark_limit,
        },
        "bounded_benchmarks": benchmarks,
        "build": {
            "command": build_command,
            "compiler": compiler,
            "openssl": openssl_version,
            "native_source_sha256": sha(HERE / "native.cpp"),
            "local_binary_sha256": sha(BINARY),
            "local_binary_note": "Machine-specific evidence only; rebuild from native.cpp for portability.",
            "python": platform.python_version(),
            "pycryptodome": Crypto.__version__,
        },
        "assertions": {
            "all_passed": True,
            "all_96_block_vectors_match_independent_implementations": True,
            "all_three_full_cfb8_vectors_match_and_roundtrip": True,
            "complete_width9_prefix_and_candidate_sets_match_python": True,
            "all_complete_controls_have_nonzero_survivors": True,
            "candidate_masks_vary": True,
            "short_bounded_multiple_candidate_masks": True,
            "invalid_inputs_rejected": True,
            "bounded_benchmark_factorial_partitions_exact": True,
            "no_target_read_or_evaluation": True,
        },
    }
    out["source_provenance"] = {
        "proof_controls_json": EXPECTED[PROOF_LEDGER],
        "frozen_python_core": EXPECTED[COLUMN / "core.py"],
        "compat_source": {str(path.relative_to(COLUMN)): expected for path, expected in EXPECTED.items() if path.is_relative_to(COMPAT_SOURCE)},
        "reviewed_native_sources_adapted": {
            "native_text5.cpp": EXPECTED[REPO / "research/rev7-20260909-codex/hex_cfb/native_text5/native_text5.cpp"],
            "native_compat.cpp": EXPECTED[REPO / "research/rev7-20260909-codex/hex_cfb/native_compat/native_compat.cpp"],
        },
    }
    out["compat_temporary_build"] = {
        "command": compatibility_command,
        "binary_sha256_machine_evidence": sha(compatibility_library),
        "temporary_directory": True,
    }
    out["build"]["native_controls_source_sha256"] = sha(Path(__file__))
    out["build"]["portable_command"] = "clang++ -std=c++17 -O3 -Wno-deprecated-declarations $(pkg-config --cflags openssl) research/byte_columnar/all_iv/column_a/native/native.cpp $(pkg-config --libs openssl) -o research/byte_columnar/all_iv/column_a/native/native_search"
    output_path.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
    temporary.cleanup()
    return out

def verify_existing():
    verify_sources()
    data = json.loads(OUTPUT.read_text())
    assert data["identity"] == "ASTRA"
    assert data["target_evaluated"] is False and data["rev7_read"] is False
    assert data["assertions"]["all_passed"]
    assert data["source_provenance"]["proof_controls_json"] == EXPECTED[PROOF_LEDGER]
    assert data["build"]["native_source_sha256"] == sha(HERE / "native.cpp")
    assert data["build"]["native_controls_source_sha256"] == sha(Path(__file__))
    assert data["block_vector_count"] == 96
    assert len(data["full_cfb8_vectors"]) == 3
    assert len(data["complete_width9_python_native_parity"]) == 3
    assert all(row["rejected_prefixes"] > 0 and row["survivor_prefix_count"] > 0 for row in data["complete_width9_python_native_parity"])
    assert data["assertions"]["short_bounded_multiple_candidate_masks"]
    print(json.dumps({
        "identity": "ASTRA",
        "verified": True,
        "read_only": True,
        "compiled_binary_or_crypto_required": False,
        "ledger_sha256": sha(OUTPUT),
    }, indent=2))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--regenerate", type=Path)
    args = parser.parse_args()
    if args.regenerate is None:
        verify_existing()
        return
    if args.regenerate.exists():
        raise SystemExit(f"refusing existing output: {args.regenerate}")
    result = produce(args.regenerate)
    print(json.dumps({
        "identity": "ASTRA",
        "target_evaluated": False,
        "output": str(args.regenerate),
        "sha256": sha(args.regenerate),
        "complete_rows": [
            {
                "backend": row["backend"],
                "survivors": row["survivor_prefix_count"],
                "distinct_masks": row["distinct_nonzero_candidate_masks"],
                "seconds": row["elapsed_seconds"],
            }
            for row in result["complete_width9_python_native_parity"]
        ],
        "benchmarks": [
            {
                "width": row["width"],
                "examined": row["prefixes_examined"],
                "seconds": row["elapsed_seconds"],
                "estimated_full_seconds": row["linear_full_prefix_time_estimate_seconds"],
            }
            for row in result["bounded_benchmarks"]
        ],
    }, indent=2))

if __name__ == "__main__":
    main()
