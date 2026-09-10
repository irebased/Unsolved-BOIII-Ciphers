#!/usr/bin/env python3
"""Read-only integrity/accounting replay for the completed column-A ledger.

This does not repeat the native prefix enumeration.  It validates the frozen
inputs, cell identities, zero-survivor certificates, and exact factorial
accounting recorded by the controlled enumerator.
"""
import argparse
import hashlib
import itertools
import json
import math
from pathlib import Path

HERE = Path(__file__).resolve().parent
COLUMN = HERE.parent
ROOT = HERE.parents[4]
RESULT = HERE / "target_results.json"
GATE = HERE / "target_gate.json"
DRIVER = HERE / "run_target.py"
MDX = ROOT / "lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
RESULT_SHA = "7ecf4315867eb5cb9ebaa8b3a907fdb476245520ea0f4115063d0c9addb85617"
GATE_SHA = "81563be8c6c2c8b87c6afa2ec733d6e476a196bc6c5002dfce6c33cb8902021b"
DRIVER_SHA = "de193398bb315e2315ace0e2538711d32a9e3543023a6ecf1fbbce9b9a61c7de"
MDX_SHA = "085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91"
TEXT_SHA = "5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
BACKENDS = ("des", "blowfish", "blowfish_compat")
WIDTHS = (13, 14)
ORIENTATIONS = ("forward", "full_hex_reverse", "byte_reverse", "nibble_swap")
EXPECTED_SUMS = {
    "prefixes": 2_075_673_600,
    "block_calls": 6_607_624_222,
    "candidate_tests": 20_058_449_558,
}

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def canonical_orientations():
    text = MDX.read_text()
    start = text.index("`83 B57B2") + 1
    end = text.index("`", start)
    canonical = "".join(text[start:end].split()).upper()
    assert len(canonical) == 1092
    assert hashlib.sha256(canonical.encode()).hexdigest() == TEXT_SHA
    pairs = [canonical[i:i + 2] for i in range(0, len(canonical), 2)]
    values = (
        canonical,
        canonical[::-1],
        "".join(reversed(pairs)),
        "".join(pair[::-1] for pair in pairs),
    )
    return dict(zip(ORIENTATIONS, values))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-local-cells", action="store_true")
    args = parser.parse_args()

    assert sha(RESULT) == RESULT_SHA
    assert sha(GATE) == GATE_SHA
    assert sha(DRIVER) == DRIVER_SHA
    assert sha(MDX) == MDX_SHA
    result = json.loads(RESULT.read_text())
    gate = json.loads(GATE.read_text())
    assert gate["identity"] == "ASTRA" and gate["target_evaluated"] is False
    assert gate["driver_sha256"] == DRIVER_SHA
    assert gate["mdx_sha256"] == MDX_SHA
    assert gate["canonical_text_sha256"] == TEXT_SHA
    assert result["identity"] == "ASTRA" and result["target_evaluated"] is True
    assert result["evaluation_complete"] is True and result["gate_sha256"] == GATE_SHA
    assert result["scope"] == gate["scope"]
    assert result["artifact_hashes"] == gate["artifact_hashes"]

    # Check every published source/control artifact.  The local executable is
    # deliberately optional; its recorded hash must instead agree with the
    # frozen native-controls machine-evidence field.
    for rel, expected in gate["artifact_hashes"].items():
        if rel == "native/native_search":
            continue
        assert sha(COLUMN / rel) == expected, rel
    native_controls = json.loads((COLUMN / "native/native_controls.json").read_text())
    recorded_binary = gate["artifact_hashes"]["native/native_search"]
    assert native_controls["build"]["local_binary_sha256"] == recorded_binary
    assert native_controls["build"]["native_source_sha256"] == gate["artifact_hashes"]["native/native.cpp"]
    assert native_controls["build"]["native_controls_source_sha256"] == gate["artifact_hashes"]["native/native_controls.py"]
    assert native_controls["identity"] == "ASTRA" and native_controls["target_evaluated"] is False
    assert native_controls["assertions"]["all_passed"] is True

    orientations = canonical_orientations()
    expected_ids = list(itertools.product(BACKENDS, WIDTHS, ORIENTATIONS))
    cells = result["cells"]
    assert len(cells) == len(expected_ids) == 24
    sums = {"prefixes": 0, "block_calls": 0, "candidate_tests": 0}
    closed = 0
    expected_files = set()
    for cell, (backend, width, orientation) in zip(cells, expected_ids):
        assert cell["identity"] == "ASTRA"
        assert (cell["backend"], cell["width"], cell["orientation"]) == (backend, width, orientation)
        assert cell["gate_sha256"] == GATE_SHA and cell["driver_sha256"] == DRIVER_SHA
        observed = bytes.fromhex(orientations[orientation])
        assert len(observed) == 546
        assert cell["observed_sha256"] == hashlib.sha256(observed).hexdigest()
        native = cell["native"]
        n = math.perm(width, 8)
        completion = math.factorial(width - 8)
        assert native["identity"] == "ASTRA" and native["backend"] == backend
        assert native["width"] == width and native["rows"] == 546 // width
        assert native["prefix_limit"] == native["total_prefixes"] == n
        assert native["prefixes_examined"] == native["rejected_prefixes"] == n
        assert native["survivor_prefix_count"] == 0 and native["survivor_prefixes"] == []
        assert native["survivors_retained"] is True
        assert native["complete_scan"] is True and native["factorial_partition_complete"] is True
        assert native["completion_weight_per_prefix"] == completion
        assert native["rejected_completion_weight"] == n * completion == math.factorial(width)
        assert native["unresolved_examined_completion_weight"] == 0
        assert native["unexamined_prefixes"] == native["unexamined_completion_weight"] == 0
        assert native["expected_completion_weight"] == math.factorial(width)
        assert native["block_calls"] == native["rows_checked"] >= n
        assert native["candidate_tests"] >= native["block_calls"]
        assert cell["complete_every_iv_order_exclusion"] is True and cell["unresolved"] is False
        assert cell["survivor_replay"]["exact_masks_replayed"] == 0
        assert cell["survivor_replay"]["full_orders_or_plaintext_recovered"] is False
        sums["prefixes"] += native["prefixes_examined"]
        sums["block_calls"] += native["block_calls"]
        sums["candidate_tests"] += native["candidate_tests"]
        closed += 1
        filename = f"{backend}_w{width}_{orientation}.json"
        expected_files.add(filename)
        if args.check_local_cells:
            assert json.loads((HERE / "target_cells" / filename).read_text()) == cell

    assert sums == EXPECTED_SUMS
    assert result["summary"] == {
        "cells": 24,
        "closed_cells": 24,
        "unresolved_cells": 0,
        "prefixes_examined": EXPECTED_SUMS["prefixes"],
        "survivor_prefixes": 0,
    }
    if args.check_local_cells:
        assert {p.name for p in (HERE / "target_cells").iterdir()} == expected_files

    print(json.dumps({
        "identity": "ASTRA",
        "verified": True,
        "verification_kind": "read-only source integrity, canonical orientation, identifier, and finite-accounting certificate replay; not a second prefix search",
        "result_sha256": RESULT_SHA,
        "gate_sha256": GATE_SHA,
        "cells": 24,
        "closed_cells": closed,
        "prefixes_examined_and_rejected": sums["prefixes"],
        "survivor_prefixes": 0,
        "block_calls_recorded": sums["block_calls"],
        "candidate_tests_recorded": sums["candidate_tests"],
        "local_cell_files_checked": args.check_local_cells,
        "compiled_binary_or_crypto_required": False,
        "binary_integrity": "recorded gate hash agrees with frozen native-controls build evidence; local executable not required",
    }, indent=2))

if __name__ == "__main__":
    main()
