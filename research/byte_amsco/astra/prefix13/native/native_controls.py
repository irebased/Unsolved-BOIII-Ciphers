#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import itertools
import json
import math
import platform
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
NATIVE_CPP = HERE / "native.cpp"
LEDGER = HERE / "native_controls.json"
PREFIX = HERE.parent
PROOF = PREFIX / "proof.py"
PROOF_LEDGER = PREFIX / "controls.json"
RESEARCH = HERE.parents[3]
COLUMN_NATIVE = RESEARCH / "byte_columnar/all_iv/column_a/native"
COLUMN_RC2 = RESEARCH / "byte_columnar/all_iv/column_a_rc2"
RUNTIME = RESEARCH / "rev7-20260909-codex/iv_independent/cascade/runtime"
IDENTITY = "ASTRA"

PINS = {
    "prefix13/proof.py": "2b349a27f9bed45c3e114fc1210fa5ecfac377c51e616f25ef8abfa3ab71efb2",
    "prefix13/controls.json": "7729b861b73e2326bffb33caf1ba2951278bc8d1d0accee2b61973bed3c10de7",
    "column_a/native/native.cpp": "960cdbaf643ca531728e2c6eeb337a5834842de9773c3a256319e9720bef1b07",
    "column_a/native/native_controls.json": "7b29daceb19899a6de3ad21954a0793513d324064c0bb169f66683f248ce5fb3",
    "column_a_rc2/source/rc2.c": "37c9398507cea1685255da9550f5a3a55b529b66e1bbc9a35e1996fecae7dc19",
    "column_a_rc2/source/rc2.h": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "column_a_rc2/source/COPYING.LIB": "ca0061fc1381a3ab242310e4b3f56389f28e3d460eb2fd822ed7a21c6f030532",
    "column_a_rc2/source_build/libdefs.h": "556ec4fcebae614cd90d05a2fead50d9355ff39f65b44c8f4044c7f209074c6e",
    "column_a_rc2/source_build/mcrypt_modules.h": "2fefe3d60795fb19e7a7be1c4cec18a97c069e2471ae61c951706020dcb6c180",
    "column_a_rc2/controls.json": "7330bad3670745ef659dd597a3385ee06b7225b17eadb997a0e80519ac3abb9f",
    "cascade/runtime/runtime.py": "8b7899fc7aedb2de04cb900876987e6b3385922d4e2e53c913562659913818f4",
    "cascade/runtime/controls.json": "483fa566e1030e489f5bb2958bcada9f1f95762f83104b7b9e8437c360787ee5",
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pin_paths():
    return {
        "prefix13/proof.py": PROOF,
        "prefix13/controls.json": PROOF_LEDGER,
        "column_a/native/native.cpp": COLUMN_NATIVE / "native.cpp",
        "column_a/native/native_controls.json": COLUMN_NATIVE / "native_controls.json",
        "column_a_rc2/source/rc2.c": COLUMN_RC2 / "source/rc2.c",
        "column_a_rc2/source/rc2.h": COLUMN_RC2 / "source/rc2.h",
        "column_a_rc2/source/COPYING.LIB": COLUMN_RC2 / "source/COPYING.LIB",
        "column_a_rc2/source_build/libdefs.h": COLUMN_RC2 / "source_build/libdefs.h",
        "column_a_rc2/source_build/mcrypt_modules.h": COLUMN_RC2 / "source_build/mcrypt_modules.h",
        "column_a_rc2/controls.json": COLUMN_RC2 / "controls.json",
        "cascade/runtime/runtime.py": RUNTIME / "runtime.py",
        "cascade/runtime/controls.json": RUNTIME / "controls.json",
    }


def verify_pins():
    for label, path in pin_paths().items():
        got = sha(path)
        if got != PINS[label]:
            raise AssertionError((label, got, PINS[label]))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def normalized(command, temporary: Path):
    root = str(temporary)
    return [part.replace(root, "<TMP>") for part in command]


def openssl_flags():
    completed = subprocess.run(["pkg-config", "--cflags", "--libs", "openssl"], check=True, capture_output=True, text=True)
    return shlex.split(completed.stdout.strip()), subprocess.check_output(["pkg-config", "--modversion", "openssl"], text=True).strip()


def build_temporary(directory: Path):
    directory.mkdir(parents=True, exist_ok=True)
    obj = directory / "rc2.o"
    binary = directory / "native_search"
    if obj.exists() or binary.exists():
        raise FileExistsError("refusing existing build output")
    source = COLUMN_RC2 / "source/rc2.c"
    include_build = COLUMN_RC2 / "source_build"
    include_source = COLUMN_RC2 / "source"
    flags, openssl_version = openssl_flags()
    commands = [
        ["clang", "-O2", "-I" + str(include_build), "-I" + str(include_source), "-c", str(source), "-o", str(obj)],
        ["clang++", "-std=c++17", "-O3", "-Wno-deprecated-declarations", str(NATIVE_CPP), str(obj), "-o", str(binary), *flags],
    ]
    evidence = []
    for command in commands:
        completed = subprocess.run(command, check=True, capture_output=True, text=True)
        evidence.append({"command": normalized(command, directory), "stdout": completed.stdout, "stderr": completed.stderr})
    return binary, {
        "commands": evidence,
        "object_sha256": sha(obj),
        "binary_sha256": sha(binary),
        "compiler": subprocess.check_output(["clang++", "--version"], text=True).splitlines()[0],
        "openssl_version": openssl_version,
    }


def native(binary: Path, *args, check=True):
    return subprocess.run([str(binary), *map(str, args)], check=check, capture_output=True, text=True)


def native_block(binary, backend, block):
    return bytes.fromhex(native(binary, "--block", backend, block.hex()).stdout.strip())


def native_cfb(binary, operation, backend, iv, data):
    return bytes.fromhex(native(binary, operation, backend, iv.hex(), data.hex()).stdout.strip())


def native_search(binary, backend, width, start, limit, observed, count_only=False):
    args = ["--search", backend, width, start, limit, observed.hex()]
    if count_only:
        args.append("--count-only")
    return json.loads(native(binary, *args).stdout)


def native_evaluate(binary, backend, width, start, observed, assignment):
    return json.loads(native(binary, "--evaluate", backend, width, start, observed.hex(), ",".join(map(str, assignment))).stdout)


def word_reverse(value: bytes) -> bytes:
    return value[3::-1] + value[7:3:-1]


def references():
    from Crypto.Cipher import ARC2, Blowfish, DES
    key = b"Zombies"
    des = DES.new(key + b"\0", DES.MODE_ECB)
    blowfish = Blowfish.new(key, Blowfish.MODE_ECB)
    rc2 = ARC2.new(key, ARC2.MODE_ECB, effective_keylen=1024)
    return {
        "des": des.encrypt,
        "blowfish": blowfish.encrypt,
        "blowfish_compat": lambda block: word_reverse(blowfish.encrypt(word_reverse(block))),
        "rc2": rc2.encrypt,
    }


def cfb8(data, iv, block, decrypt=False):
    reg = iv
    out = bytearray()
    for value in data:
        transformed = value ^ block(reg)[0]
        ciphertext = value if decrypt else transformed
        out.append(transformed)
        reg = reg[1:] + bytes([ciphertext])
    return bytes(out)


def oracle_forward(data: bytes, width: int, order: tuple[int, ...], start: int) -> bytes:
    cells = []
    offset = 0
    size = start
    while offset < len(data):
        take = min(size, len(data) - offset)
        cells.append(data[offset:offset + take])
        offset += take
        size = 3 - size
    out = bytearray()
    for column in order:
        for cell_number, cell in enumerate(cells):
            if cell_number % width == column:
                out.extend(cell)
    return bytes(out)


def assignment_from_order(order):
    return tuple(order.index(column) for column in range(6))


def fnv(rows):
    value = 14695981039346656037
    for row in rows:
        for item in row["assignment"]:
            value ^= item
            value = value * 1099511628211 & ((1 << 64) - 1)
        for item in bytes.fromhex(row["plaintext_ninth_hex"]):
            value ^= item
            value = value * 1099511628211 & ((1 << 64) - 1)
        value ^= 0xFF
        value = value * 1099511628211 & ((1 << 64) - 1)
    return f"{value:016x}"


def python_scan(proof, observed, width, start, limit, block):
    survivors = []
    rejected = block_calls = 0
    for assignment in itertools.islice(itertools.permutations(range(width), 6), limit):
        accepted, values = proof.evaluate_prefix(observed, width, start, assignment, block)
        block_calls += len(values)
        if accepted:
            survivors.append({"assignment": list(assignment), "plaintext_ninth_hex": bytes(values).hex()})
        else:
            rejected += 1
    total = math.perm(width, 6)
    weight = math.factorial(width - 6)
    unexamined = total - limit
    return {
        "survivor_prefixes": survivors,
        "prefixes_examined": limit,
        "rejected_prefixes": rejected,
        "survivor_prefix_count": len(survivors),
        "completion_weight_per_prefix": weight,
        "rejected_completion_weight": rejected * weight,
        "unresolved_examined_completion_weight": len(survivors) * weight,
        "unexamined_prefixes": unexamined,
        "unexamined_completion_weight": unexamined * weight,
        "expected_completion_weight": math.factorial(width),
        "block_calls": block_calls,
        "rows_checked": block_calls,
    }


def compare(actual, expected, complete):
    assert actual["survivor_prefixes"] == expected["survivor_prefixes"]
    for key in (
        "prefixes_examined", "rejected_prefixes", "survivor_prefix_count",
        "completion_weight_per_prefix", "rejected_completion_weight",
        "unresolved_examined_completion_weight", "unexamined_prefixes",
        "unexamined_completion_weight", "expected_completion_weight",
        "block_calls", "rows_checked",
    ):
        assert actual[key] == expected[key], (key, actual[key], expected[key])
    assert actual["survivor_digest_fnv1a64"] == fnv(expected["survivor_prefixes"])
    assert actual["factorial_partition_complete"]
    assert actual["complete_scan"] is complete
    assert actual["survivors_retained"]
    return expected["survivor_prefixes"]


def plaintext_for(n):
    phrase = b"ASTRA AMSCO PREFIX CONTROL: 0123456789, punctuation.\n"
    return (phrase * ((n + len(phrase) - 1) // len(phrase)))[:n]


def regenerate(output: Path):
    if output.exists():
        raise SystemExit(f"refusing to overwrite {output}")
    verify_pins()
    proof = load_module("astra_prefix13_proof_native_control", PROOF)
    refs = references()
    from Crypto.Cipher import ARC2, Blowfish, DES
    with tempfile.TemporaryDirectory(prefix="astra-prefix13-native-") as temporary_name:
        temporary = Path(temporary_name)
        binary, build = build_temporary(temporary)

        # Fixed key block and complete 256-byte CFB8 validation.
        blocks = [bytes((i * 31 + j * 17 + 9) & 255 for j in range(8)) for i in range(64)]
        block_rows = []
        cfb_rows = []
        for backend, block in refs.items():
            outputs = []
            for value in blocks:
                actual = native_block(binary, backend, value)
                expected = block(value)
                assert actual == expected
                outputs.append(actual)
            block_rows.append({"backend": backend, "vectors": len(outputs), "digest": hashlib.sha256(b"".join(outputs)).hexdigest(), "all_match": True})
            allbytes = bytes(range(256))
            for suite, iv in enumerate((bytes(range(8)), bytes.fromhex("f0e0d0c0b0a09080"))):
                expected = cfb8(allbytes, iv, block)
                actual = native_cfb(binary, "--cfb-encrypt", backend, iv, allbytes)
                recovered = native_cfb(binary, "--cfb-decrypt", backend, iv, actual)
                assert actual == expected and recovered == allbytes
                if backend == "des":
                    assert actual == DES.new(b"Zombies\0", DES.MODE_CFB, iv=iv, segment_size=8).encrypt(allbytes)
                elif backend == "blowfish":
                    assert actual == Blowfish.new(b"Zombies", Blowfish.MODE_CFB, iv=iv, segment_size=8).encrypt(allbytes)
                elif backend == "rc2":
                    assert actual == ARC2.new(b"Zombies", ARC2.MODE_CFB, iv=iv, segment_size=8, effective_keylen=1024).encrypt(allbytes)
                cfb_rows.append({"backend": backend, "suite": suite, "iv_hex": iv.hex(), "ciphertext_sha256": hashlib.sha256(actual).hexdigest(), "roundtrip": True, "native_manual_match": True})

        exact_rows = []
        orders = {
            7: (4, 0, 6, 2, 5, 1, 3),
            9: (8, 1, 7, 0, 5, 3, 6, 2, 4),
        }
        for backend_index, (backend, block) in enumerate(refs.items()):
            for width, rows in ((7, 4), (9, 2)):
                n = 3 * width * rows // 2
                plaintext = plaintext_for(n)
                assert set(plaintext) <= proof.A105
                order = orders[width]
                truth = assignment_from_order(order)
                for start in (1, 2):
                    iv = bytes((backend_index * 41 + width * 7 + start * 53 + i * 19) & 255 for i in range(8))
                    ciphertext = cfb8(plaintext, iv, block)
                    observed = oracle_forward(ciphertext, width, order, start)
                    limit = math.perm(width, 6)
                    expected = python_scan(proof, observed, width, start, limit, block)
                    actual = native_search(binary, backend, width, start, limit, observed)
                    survivors = compare(actual, expected, True)
                    truth_rows = [row for row in survivors if tuple(row["assignment"]) == truth]
                    assert len(truth_rows) == 1
                    assert actual["rejected_prefixes"] > 0 and actual["survivor_prefix_count"] > 0
                    exact_rows.append({
                        "backend": backend, "width": width, "rows": rows, "start": start,
                        "iv_hex": iv.hex(), "order": list(order), "truth_assignment": list(truth),
                        "observed_sha256": hashlib.sha256(observed).hexdigest(),
                        "prefixes_examined": actual["prefixes_examined"],
                        "rejected_prefixes": actual["rejected_prefixes"],
                        "survivor_prefix_count": actual["survivor_prefix_count"],
                        "completion_weight_per_prefix": actual["completion_weight_per_prefix"],
                        "block_calls": actual["block_calls"],
                        "survivor_digest_fnv1a64": actual["survivor_digest_fnv1a64"],
                        "truth_retained": True, "exact_ordered_survivor_tuples_and_bytes": True,
                        "exact_counters_weights_and_digest": True,
                        "elapsed_seconds": actual["elapsed_seconds"],
                    })

        bounded_rows = []
        width = 13
        rows = 28
        n = 546
        order = (7, 0, 12, 4, 9, 2, 11, 5, 1, 8, 3, 10, 6)
        truth = assignment_from_order(order)
        limit = 4096
        for backend_index, (backend, block) in enumerate(refs.items()):
            for start in (1, 2):
                plaintext = plaintext_for(n)
                iv = bytes((backend_index * 29 + start * 71 + i * 23) & 255 for i in range(8))
                ciphertext = cfb8(plaintext, iv, block)
                observed = oracle_forward(ciphertext, width, order, start)
                expected = python_scan(proof, observed, width, start, limit, block)
                actual = native_search(binary, backend, width, start, limit, observed)
                survivors = compare(actual, expected, False)
                # The chosen nonidentity truth is outside this deterministic prefix,
                # so separately test its exact computed tuple with the native block API.
                truth_accepted, truth_values = proof.evaluate_prefix(observed, width, start, truth, block)
                native_truth = native_evaluate(binary, backend, width, start, observed, truth)
                assert truth_accepted and len(truth_values) == 28
                assert native_truth["accepted"] and bytes.fromhex(native_truth["plaintext_ninth_hex"]) == bytes(truth_values)
                assert native_truth["block_calls"] == 28
                assert actual["rejected_prefixes"] > 0
                bounded_rows.append({
                    "backend": backend, "width": width, "rows": rows, "start": start,
                    "iv_hex": iv.hex(), "order": list(order), "truth_assignment": list(truth),
                    "truth_plaintext_ninth_hex": bytes(truth_values).hex(),
                    "truth_retained_separate_exact_check": True,
                    "native_truth_plaintext_ninth_exact": True,
                    "bounded_prefixes": limit, "rejected_prefixes": actual["rejected_prefixes"],
                    "survivor_prefix_count": actual["survivor_prefix_count"],
                    "unexamined_prefixes": actual["unexamined_prefixes"],
                    "completion_weight_per_prefix": actual["completion_weight_per_prefix"],
                    "block_calls": actual["block_calls"],
                    "survivor_digest_fnv1a64": actual["survivor_digest_fnv1a64"],
                    "exact_ordered_survivor_tuples_and_bytes": True,
                    "exact_counters_weights_and_digest": True,
                    "elapsed_seconds": actual["elapsed_seconds"],
                })

        benchmark_rows = []
        total_projection = 0.0
        benchmark_limit = 1_000_000
        for backend_index, backend in enumerate(refs):
            for start in (1, 2):
                observed = bytes((backend_index * 43 + start * 59 + i * 31 + 17) & 255 for i in range(546))
                actual = native_search(binary, backend, 13, start, benchmark_limit, observed, count_only=True)
                assert actual["prefixes_examined"] == benchmark_limit
                assert actual["unexamined_prefixes"] == math.perm(13, 6) - benchmark_limit
                rate = benchmark_limit / actual["elapsed_seconds"]
                context_seconds = math.perm(13, 6) / rate
                total_projection += 4 * context_seconds
                benchmark_rows.append({
                    "backend": backend, "start": start, "prefixes": benchmark_limit,
                    "seconds": actual["elapsed_seconds"], "prefixes_per_second": rate,
                    "projected_seconds_one_full_context": context_seconds,
                    "block_calls": actual["block_calls"], "rejected_prefixes": actual["rejected_prefixes"],
                    "survivor_prefix_count": actual["survivor_prefix_count"],
                    "unexamined_prefixes": actual["unexamined_prefixes"],
                    "factorial_partition_complete": True,
                    "count_only": True,
                })

        invalid = []
        cases = [
            ["--search", "des", "8", "1", "1", "00" * 24],
            ["--search", "des", "7", "1", "1", "00" * 20],
            ["--search", "des", "7", "3", "1", "00" * 42],
            ["--search", "des", "7", "1", "0", "00" * 42],
            ["--search", "unknown", "7", "1", "1", "00" * 42],
            ["--search", "des", "7", "1", "1", "0"],
        ]
        for args in cases:
            completed = native(binary, *args, check=False)
            assert completed.returncode != 0
            invalid.append({"args": args[:6], "returncode_nonzero": True, "stderr": completed.stderr.strip()})

        result = {
            "identity": IDENTITY,
            "target_evaluated": False,
            "rev7_file_read": False,
            "scope": "Synthetic-only native first-six byte-AMSCO prefix engine controls for four fixed-key 8-byte CFB8 backends.",
            "model": {
                "backends": ["des", "blowfish", "blowfish_compat", "rc2"],
                "keys": {"des": "Zombies + NUL", "blowfish": "raw Zombies", "blowfish_compat": "raw Zombies", "rc2": "raw Zombies, effective 1024 bits"},
                "widths_supported": [7, 9, 11, 13],
                "starts": [1, 2],
                "allowed_bytes": 105,
                "prefix_slots": 6,
                "completion_weight": "(width-6)!",
                "survivors": "Every retained six-rank tuple plus all computed row-ninth plaintext bytes.",
            },
            "source_pins": PINS,
            "source_runtime_evidence": {
                "distrotech_commit": "3bd338e2f808e985f5b229a7642d48c26615993f",
                "historical_rc2_source": "column_a_rc2/source/rc2.c",
                "standard_and_compat_wrappers": "source-pinned semantics from column_a/native controls",
            },
            "build": build,
            "block_vectors": block_rows,
            "full_byte_cfb8": cfb_rows,
            "complete_width7_width9": exact_rows,
            "bounded_width13": bounded_rows,
            "benchmark": {
                "method": "One million deterministic synthetic prefixes for every backend/start; count-only affects output retention only.",
                "rows": benchmark_rows,
                "prospective_contexts": 32,
                "prospective_total_prefixes": 4 * 2 * 4 * math.perm(13, 6),
                "projected_total_native_seconds": total_projection,
                "limits": "Linear host projection only; excludes process startup, input orientation, result verification, and survivor handling.",
            },
            "invalid_inputs": invalid,
            "environment": {"python": sys.version, "platform": platform.platform()},
            "artifact_hashes": {"native.cpp": sha(NATIVE_CPP), "native_controls.py": sha(Path(__file__))},
            "assertions": {
                "all_passed": True,
                "source_pins_verified": True,
                "native_block_matches_independent": True,
                "full_byte_cfb8_matches_independent": True,
                "complete_width7_width9_exact_python_parity": True,
                "bounded_width13_exact_python_parity": True,
                "retained_and_rejected_plants": True,
                "all_survivors_retained_in_parity_controls": True,
                "factorial_and_cap_accounting": True,
                "invalid_inputs_rejected": True,
                "no_target": True,
            },
        }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"identity": IDENTITY, "written": str(output), "sha256": sha(output), "benchmark": result["benchmark"], "build_binary_sha256": result["build"]["binary_sha256"]}, indent=2))


def verify_default(path: Path):
    verify_pins()
    data = json.loads(path.read_text())
    assert data["identity"] == IDENTITY and not data["target_evaluated"] and not data["rev7_file_read"]
    assert data["artifact_hashes"] == {"native.cpp": sha(NATIVE_CPP), "native_controls.py": sha(Path(__file__))}
    assert data["source_pins"] == PINS
    assert data["model"]["backends"] == ["des", "blowfish", "blowfish_compat", "rc2"]
    assert len(data["block_vectors"]) == 4 and len(data["full_byte_cfb8"]) == 8
    assert len(data["complete_width7_width9"]) == 16 and len(data["bounded_width13"]) == 8
    assert all(x["exact_ordered_survivor_tuples_and_bytes"] for x in data["complete_width7_width9"])
    assert all(x["exact_ordered_survivor_tuples_and_bytes"] for x in data["bounded_width13"])
    assert data["benchmark"]["prospective_contexts"] == 32
    assert data["benchmark"]["prospective_total_prefixes"] == 39_536_640
    assert len(data["benchmark"]["rows"]) == 8
    assert len(data["invalid_inputs"]) == 6
    assert all(data["assertions"].values())
    print(json.dumps({"identity": IDENTITY, "verified": True, "ledger_sha256": sha(path), "target_evaluated": False, "verification_scope": "standard-library source and structural integrity only; no compile, crypto, or search replay"}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--regenerate", type=Path)
    parser.add_argument("--ledger", type=Path, default=LEDGER)
    args = parser.parse_args()
    if args.regenerate:
        regenerate(args.regenerate)
    else:
        verify_default(args.ledger)


if __name__ == "__main__":
    main()
