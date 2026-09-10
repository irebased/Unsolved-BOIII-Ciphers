#!/usr/bin/env python3
"""Frozen-gate target driver for the column-A every-IV necessary constraint."""
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import subprocess
import time

HERE = Path(__file__).resolve().parent
COLUMN = HERE.parent
ROOT = HERE.parents[4]
GATE = HERE / "target_gate.json"
MDX = ROOT / "lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
MDX_SHA = "085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91"
TEXT_SHA = "5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
BACKENDS = ("des", "blowfish", "blowfish_compat")
WIDTHS = (13, 14)
ORIENTATIONS = ("forward", "full_hex_reverse", "byte_reverse", "nibble_swap")
REQUIRED = (
    "core.py", "controls.py", "controls.json",
    "compat_source/build_compat.py", "compat_source/blowfish-compat.c",
    "compat_source/blowfish.h", "compat_source/libdefs.h", "compat_source/mcrypt_modules.h",
    "native/native.cpp", "native/native_controls.py", "native/native_controls.json",
    "native/native_search",
)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def scope():
    return {
        "identity": "ASTRA", "cells": 24, "decoded_bytes": 546,
        "backends": list(BACKENDS), "widths": list(WIDTHS),
        "orientations": list(ORIENTATIONS), "block_size": 8,
        "key_hex": {"des": "5a6f6d6269657300", "blowfish": "5a6f6d62696573", "blowfish_compat": "5a6f6d62696573"},
        "mode": "CFB8", "external_iv": "every eight-byte IV; neither recovered nor searched",
        "variant": "rectangular FABLE columnarA; slots is inverse of FABLE order",
        "equation": "C[row*w+j] = observed[slots[j]*q+row]",
        "constraint": "At natural column 8, intersect unused observed ranks across all rows using A105; IV-independent preceding ciphertext columns 0..7",
        "alphabet": sorted({9, 10, 13} | set(range(32, 127)) | {0x80, 0x93, 0x94, 0x98, 0x99, 0xa6, 0xe2}),
        "endpoint_limit": "necessary relaxed byte filter only; no full plaintext or strict UTF-8 claim",
        "prefix_limits": {str(w): math.perm(w, 8) for w in WIDTHS},
        "prefix_total_across_cells": 2075673600,
        "completion_weight_per_prefix": {str(w): math.factorial(w-8) for w in WIDTHS},
        "enumeration": "fresh complete lexicographic first-eight rank tuples per case",
        "survivors": "retain every exact first-eight tuple and ninth-rank candidate set, independently replay every retained mask",
        "closure": "a cell closes only after a complete scan with zero surviving prefixes; otherwise it remains unresolved",
        "overwrite_policy": "refuse existing completed cells or combined result; no automatic rerun",
    }

def require_gate():
    gate = json.loads(GATE.read_text())
    assert gate["identity"] == "ASTRA" and gate["target_evaluated"] is False
    assert gate["scope"] == scope() and gate["driver_sha256"] == sha(Path(__file__))
    assert set(gate["artifact_hashes"]) == set(REQUIRED)
    for rel, expected in gate["artifact_hashes"].items():
        assert sha(COLUMN / rel) == expected, rel
    assert sha(MDX) == MDX_SHA and gate["mdx_sha256"] == MDX_SHA
    assert gate["canonical_text_sha256"] == TEXT_SHA
    proof = json.loads((COLUMN / "controls.json").read_text())
    native = json.loads((COLUMN / "native/native_controls.json").read_text())
    for ledger in (proof, native):
        assert ledger["identity"] == "ASTRA" and ledger["target_evaluated"] is False
        assert ledger["rev7_read"] is False and ledger["assertions"]["all_passed"] is True
    return gate, sha(GATE)

def canonical_orientations():
    text = MDX.read_text()
    start = text.index("`83 B57B2") + 1
    end = text.index("`", start)
    canonical = "".join(text[start:end].split()).upper()
    assert len(canonical) == 1092 and hashlib.sha256(canonical.encode()).hexdigest() == TEXT_SHA
    pairs = [canonical[i:i+2] for i in range(0, len(canonical), 2)]
    return dict(zip(ORIENTATIONS, (canonical, canonical[::-1], "".join(reversed(pairs)), "".join(x[::-1] for x in pairs))))

def replay_survivors(backend, width, observed, result):
    from Crypto.Cipher import DES, Blowfish
    spec = importlib.util.spec_from_file_location("column_a_reference", COLUMN / "core.py")
    core = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(core)
    if backend == "des":
        ecb = DES.new(b"Zombies\0", DES.MODE_ECB)
    else:
        ecb = Blowfish.new(b"Zombies", Blowfish.MODE_ECB)
    def reverse_words(b):
        return b[3::-1] + b[7:3:-1]
    def first(block):
        if backend == "blowfish_compat":
            return reverse_words(ecb.encrypt(reverse_words(block)))[0]
        return ecb.encrypt(block)[0]
    seen = set()
    for row in result["survivor_prefixes"]:
        prefix = tuple(row["first_slots"])
        assert prefix not in seen
        seen.add(prefix)
        expected = core.evaluate_first_block_tuple(observed, width, 8, prefix, first)
        assert not expected["empty_candidate_mask"]
        assert row["surviving_ninth_ranks"] == expected["surviving_ninth_ranks"]
    assert len(seen) == result["survivor_prefix_count"]
    return {"identity": "ASTRA", "exact_masks_replayed": len(seen), "reference": "Python prefix model with independent PyCryptodome blocks and established compatibility conjugation", "full_orders_or_plaintext_recovered": False}

def validate_result(result, backend, width):
    total = math.perm(width, 8)
    weight = math.factorial(width-8)
    assert result["identity"] == "ASTRA" and result["backend"] == backend
    assert result["width"] == width and result["rows"] == 546 // width
    assert result["prefix_limit"] == result["total_prefixes"] == result["prefixes_examined"] == total
    assert result["rejected_prefixes"] + result["survivor_prefix_count"] == total
    assert result["survivors_retained"] is True and len(result["survivor_prefixes"]) == result["survivor_prefix_count"]
    assert result["complete_scan"] is True and result["factorial_partition_complete"] is True
    assert result["unexamined_prefixes"] == result["unexamined_completion_weight"] == 0
    assert result["completion_weight_per_prefix"] == weight
    assert result["rejected_completion_weight"] == result["rejected_prefixes"] * weight
    assert result["unresolved_examined_completion_weight"] == result["survivor_prefix_count"] * weight
    assert result["expected_completion_weight"] == math.factorial(width)
    assert result["rejected_completion_weight"] + result["unresolved_examined_completion_weight"] == math.factorial(width)
    assert result["block_calls"] == result["rows_checked"] >= total
    assert result["candidate_tests"] >= result["block_calls"]

def write_new(path, value):
    if path.exists():
        raise RuntimeError("refusing existing result " + str(path))
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("x") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(temporary, path)

def run():
    gate, gate_sha = require_gate()
    cell_dir = HERE / "target_cells"
    output = HERE / "target_results.json"
    if output.exists() or (cell_dir.exists() and any(cell_dir.iterdir())):
        raise RuntimeError("refusing existing target output; inspect completed work instead of rerunning")
    cell_dir.mkdir(exist_ok=True)
    orientations = canonical_orientations()
    rows = []
    for backend in BACKENDS:
        for width in WIDTHS:
            for orientation in ORIENTATIONS:
                observed = bytes.fromhex(orientations[orientation])
                started = time.monotonic()
                command = [str(COLUMN / "native/native_search"), "--search", backend, str(width), str(math.perm(width, 8)), observed.hex()]
                completed = subprocess.run(command, check=True, capture_output=True, text=True)
                result = json.loads(completed.stdout)
                validate_result(result, backend, width)
                replay = replay_survivors(backend, width, observed, result)
                closed = result["survivor_prefix_count"] == 0 and result["rejected_prefixes"] == math.perm(width, 8)
                cell = {"identity": "ASTRA", "backend": backend, "width": width, "orientation": orientation,
                    "observed_sha256": hashlib.sha256(observed).hexdigest(), "gate_sha256": gate_sha,
                    "driver_sha256": sha(Path(__file__)), "native": result, "survivor_replay": replay,
                    "complete_every_iv_order_exclusion": closed, "unresolved": not closed,
                    "wall_seconds": time.monotonic() - started}
                write_new(cell_dir / f"{backend}_w{width}_{orientation}.json", cell)
                rows.append(cell)
                print(json.dumps({"identity": "ASTRA", "completed_cells": len(rows), "backend": backend, "width": width, "orientation": orientation, "closed": closed, "survivor_prefixes": result["survivor_prefix_count"]}), flush=True)
    assert len(rows) == 24
    assert sum(row["native"]["prefixes_examined"] for row in rows) == 2075673600
    combined = {"identity": "ASTRA", "target_evaluated": True, "evaluation_complete": True,
        "scope": scope(), "gate_sha256": gate_sha, "artifact_hashes": gate["artifact_hashes"],
        "cells": rows, "summary": {"cells": 24, "closed_cells": sum(row["complete_every_iv_order_exclusion"] for row in rows),
        "unresolved_cells": sum(row["unresolved"] for row in rows), "prefixes_examined": 2075673600,
        "survivor_prefixes": sum(row["native"]["survivor_prefix_count"] for row in rows)}}
    write_new(output, combined)
    print(json.dumps({"identity": "ASTRA", "complete": True, "summary": combined["summary"], "result_sha256": sha(output)}), flush=True)

def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--selftest", action="store_true")
    mode.add_argument("--run-target", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        _gate, gate_sha = require_gate()
        print(json.dumps({"identity": "ASTRA", "target_evaluated": False, "selftest": True, "gate_sha256": gate_sha, "target_handling": "MDX bytes hashed only; ciphertext not extracted, oriented or evaluated", "scope": scope()}, indent=2))
    else:
        run()

if __name__ == "__main__":
    main()
