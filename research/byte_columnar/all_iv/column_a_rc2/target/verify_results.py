#!/usr/bin/env python3
"""Read-only integrity and accounting replay for the RC2 column-A result.

This does not repeat the 691,891,200-prefix native search.
"""
import argparse
import hashlib
import itertools
import json
import math
from pathlib import Path

HERE = Path(__file__).resolve().parent
PACKAGE = HERE.parent
ROOT = HERE.parents[4]
RESULT = HERE / "target_results.json"
GATE = HERE / "target_gate.json"
MDX = ROOT / "lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
RESULT_SHA = "8c8b94ed9def1daacfc04e25aa03f4c25a89568ab29072a6672c49dde766e9de"
GATE_SHA = "191240f56bcdea2233fece19cfa5f429c4296463f2a081bba8899152b4de642b"
DRIVER_SHA = "deea54124124bae750ba57a35ebed6c5770e4f861ed25ae3aed6a7c660b1ab9a"
BUILD_HELPER_SHA = "a9f65c9c4781844dc984bc6f03d9f473d7e7360d3f11ddf094531e8cfe884d43"
GATE_BUILDER_SHA = "f1f6844532f3f08cec015c19f85e6585dd4b52da3c2e30ed31abc5054e985a87"
TARGET_README_SHA = "8b03b875f47a7223d6c08956ed7a38cb36dc20db62a093022e616ee03613fd8d"
MDX_SHA = "085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91"
TEXT_SHA = "5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
BINARY_SHA = "679844dc071cce779d86667f1b8e55c5175045840d7b47044312f28dfdfd4b3b"
OBJECT_SHA = "022a0517d79e7dfc9566ca3cf04462a7ffb62aaf9f2d4d0d8edb2ca0a2803b4e"
WIDTHS = (13, 14)
ORIENTATIONS = ("forward", "full_hex_reverse", "byte_reverse", "nibble_swap")
EXPECTED_SUMS = {"prefixes": 691_891_200, "block_calls": 2_202_549_490, "candidate_tests": 6_686_103_593}
EMPTY_FNV1A64 = "cbf29ce484222325"

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def artifact_path(rel):
    return PACKAGE / rel

def orientations():
    text = MDX.read_text()
    start = text.index("`83 B57B2") + 1
    end = text.index("`", start)
    canonical = "".join(text[start:end].split()).upper()
    assert len(canonical) == 1092
    assert hashlib.sha256(canonical.encode()).hexdigest() == TEXT_SHA
    pairs = [canonical[i:i + 2] for i in range(0, len(canonical), 2)]
    return dict(zip(ORIENTATIONS, (canonical, canonical[::-1], "".join(reversed(pairs)), "".join(x[::-1] for x in pairs))))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-local-cells", action="store_true")
    args = parser.parse_args()

    assert sha(RESULT) == RESULT_SHA
    assert sha(GATE) == GATE_SHA
    assert sha(HERE / "run_target.py") == DRIVER_SHA
    assert sha(HERE / "build_native.py") == BUILD_HELPER_SHA
    assert sha(HERE / "prepare_gate.py") == GATE_BUILDER_SHA
    assert sha(HERE / "README.md") == TARGET_README_SHA
    assert sha(MDX) == MDX_SHA
    gate = json.loads(GATE.read_text())
    result = json.loads(RESULT.read_text())
    assert gate["identity"] == "ASTRA" and gate["target_evaluated"] is False
    assert gate["driver_sha256"] == DRIVER_SHA
    assert gate["build_helper_sha256"] == BUILD_HELPER_SHA
    assert gate["gate_builder_sha256"] == GATE_BUILDER_SHA
    assert gate["target_readme_sha256"] == TARGET_README_SHA
    assert gate["mdx_sha256"] == MDX_SHA and gate["canonical_text_sha256"] == TEXT_SHA
    assert gate["expected_binary_sha256"] == BINARY_SHA
    assert gate["expected_object_sha256"] == OBJECT_SHA
    for rel, expected in gate["artifact_hashes"].items():
        assert sha(artifact_path(rel)) == expected, rel

    assert result["identity"] == "ASTRA" and result["target_evaluated"] is True
    assert result["evaluation_complete"] is True and result["gate_sha256"] == GATE_SHA
    assert result["scope"] == gate["scope"] and result["artifact_hashes"] == gate["artifact_hashes"]
    controls = json.loads((PACKAGE / "controls.json").read_text())
    assert controls["identity"] == "ASTRA" and controls["target_evaluated"] is False and controls["rev7_read"] is False
    assert controls["assertions"]["all_passed"] is True
    assert controls["build"]["temporary_binary_sha256_machine_evidence"] == BINARY_SHA
    assert controls["build"]["temporary_object_sha256_machine_evidence"] == OBJECT_SHA

    build = result["build_provenance"]
    assert build["identity"] == "ASTRA" and build["temporary_build"] is True
    assert build["published_binary_required"] is False
    assert build["binary_sha256"] == BINARY_SHA and build["object_sha256"] == OBJECT_SHA
    source_hashes = {k: v for k, v in gate["artifact_hashes"].items()
                     if k == "native.cpp" or k.startswith("source/") or k.startswith("source_build/")}
    assert build["source_hashes"] == source_hashes
    assert len(build["commands"]) == 2
    assert build["commands"][0]["command"][0] == "clang"
    assert build["commands"][1]["command"][0] == "clang++"
    assert build["commands"][0]["command"][-1] == "<TMP>/rc2.o"
    assert build["commands"][1]["command"][-1] == "<TMP>/native_search"

    oriented = orientations()
    expected_ids = list(itertools.product(WIDTHS, ORIENTATIONS))
    assert len(result["cells"]) == len(expected_ids) == 8
    expected_files = set()
    sums = {"prefixes": 0, "block_calls": 0, "candidate_tests": 0}
    for cell, (width, orientation) in zip(result["cells"], expected_ids):
        assert cell["identity"] == "ASTRA" and cell["cipher"] == "rc2"
        assert (cell["width"], cell["orientation"]) == (width, orientation)
        assert cell["gate_sha256"] == GATE_SHA and cell["driver_sha256"] == DRIVER_SHA
        assert cell["binary_sha256"] == BINARY_SHA
        observed = bytes.fromhex(oriented[orientation])
        assert len(observed) == 546
        assert cell["observed_sha256"] == hashlib.sha256(observed).hexdigest()
        native = cell["native"]
        n = math.perm(width, 8); weight = math.factorial(width - 8)
        assert native["identity"] == "ASTRA" and native["backend"] == "rc2"
        assert native["width"] == width and native["rows"] == 546 // width
        assert native["prefix_limit"] == native["total_prefixes"] == n
        assert native["prefixes_examined"] == native["rejected_prefixes"] == n
        assert native["survivor_prefix_count"] == 0 and native["survivor_prefixes"] == []
        assert native["survivors_retained"] is True
        assert native["complete_scan"] is True and native["factorial_partition_complete"] is True
        assert native["completion_weight_per_prefix"] == weight
        assert native["rejected_completion_weight"] == n * weight == math.factorial(width)
        assert native["unresolved_examined_completion_weight"] == 0
        assert native["unexamined_prefixes"] == native["unexamined_completion_weight"] == 0
        assert native["expected_completion_weight"] == math.factorial(width)
        assert native["block_calls"] == native["rows_checked"] >= n
        assert native["candidate_tests"] >= native["block_calls"]
        assert native["survivor_digest_fnv1a64"] == EMPTY_FNV1A64
        assert cell["complete_every_iv_order_exclusion"] is True and cell["unresolved"] is False
        replay = cell["survivor_replay"]
        assert replay["identity"] == "ASTRA" and replay["exact_masks_replayed"] == 0 and replay["checked"] == []
        assert replay["full_orders_iv_or_plaintext_recovered"] is False
        sums["prefixes"] += native["prefixes_examined"]
        sums["block_calls"] += native["block_calls"]
        sums["candidate_tests"] += native["candidate_tests"]
        filename = f"rc2_w{width}_{orientation}.json"
        expected_files.add(filename)
        if args.check_local_cells:
            assert json.loads((HERE / "target_cells" / filename).read_text()) == cell

    assert sums == EXPECTED_SUMS
    assert result["summary"] == {"cells": 8, "closed_cells": 8, "unresolved_cells": 0,
                                 "prefixes_examined": EXPECTED_SUMS["prefixes"], "survivor_prefixes": 0}
    if args.check_local_cells:
        assert {x.name for x in (HERE / "target_cells").iterdir()} == expected_files

    print(json.dumps({"identity": "ASTRA", "verified": True,
                      "verification_kind": "read-only source/build integrity, canonical orientation, identifier, and finite-accounting replay; not a second prefix search",
                      "result_sha256": RESULT_SHA, "gate_sha256": GATE_SHA,
                      "cells": 8, "closed_cells": 8,
                      "prefixes_examined_and_rejected": sums["prefixes"], "survivor_prefixes": 0,
                      "block_calls_recorded": sums["block_calls"],
                      "candidate_tests_recorded": sums["candidate_tests"],
                      "local_cell_files_checked": args.check_local_cells,
                      "compiled_binary_or_crypto_required": False,
                      "binary_integrity": "result and gate hashes agree with frozen controls build evidence; local executable not required"}, indent=2))

if __name__ == "__main__":
    main()
