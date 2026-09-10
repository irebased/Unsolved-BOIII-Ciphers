#!/usr/bin/env python3
"""Portable result integrity/accounting verifier; does not rerun the 39.5M-prefix search."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path

HERE = Path(__file__).resolve().parent
RESULT = HERE / "target_results.json"
GATE = HERE / "target_gate.json"
DRIVER = HERE / "run_target.py"
MDX = HERE.parents[5] / "lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
RESULT_SHA = "61fff04ed7d8e61f2d74986c086357606c8b9e2877667184ea4d008928329541"
GATE_SHA = "4edfe5ffbced9ca4167f106a9b0c577257cd7292e047f1ffd4d634e808c9880c"
DRIVER_SHA = "166edaadd98a95abfa6c6336652be4d2218491d548335f6714d048c7e491fa59"
MDX_SHA = "085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91"
TEXT_SHA = "5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
BINARY_SHA = "704f5f431b0b92136624eaba960605f2a652e8818a42b86a8a44e14566722b04"
OBJECT_SHA = "022a0517d79e7dfc9566ca3cf04462a7ffb62aaf9f2d4d0d8edb2ca0a2803b4e"
BACKENDS = ("des", "blowfish", "blowfish_compat", "rc2")
STARTS = (1, 2)
ORIENTATIONS = ("forward", "full_hex_reverse", "byte_reverse", "nibble_swap")
PREFIXES = math.perm(13, 6)
WEIGHT = math.factorial(7)
FULL = math.factorial(13)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_driver():
    assert sha(DRIVER) == DRIVER_SHA
    spec = importlib.util.spec_from_file_location("astra_prefix13_result_driver", DRIVER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def orientations():
    assert sha(MDX) == MDX_SHA
    text = MDX.read_text()
    start = text.index("`83 B57B2") + 1
    end = text.index("`", start)
    canonical = "".join(text[start:end].split()).upper()
    assert len(canonical) == 1092 and hashlib.sha256(canonical.encode()).hexdigest() == TEXT_SHA
    pairs = [canonical[i:i + 2] for i in range(0, len(canonical), 2)]
    return {
        "forward": bytes.fromhex(canonical),
        "full_hex_reverse": bytes.fromhex(canonical[::-1]),
        "byte_reverse": bytes.fromhex("".join(reversed(pairs))),
        "nibble_swap": bytes.fromhex("".join(pair[::-1] for pair in pairs)),
    }


def main(check_local_cells: bool = False):
    assert sha(RESULT) == RESULT_SHA
    assert sha(GATE) == GATE_SHA
    driver = load_driver()
    gated, validated_gate_sha = driver.require_gate()
    assert validated_gate_sha == GATE_SHA
    gate = json.loads(GATE.read_text())
    result = json.loads(RESULT.read_text())
    assert gate == gated
    assert gate["identity"] == "ASTRA" and gate["target_evaluated"] is False
    assert gate["driver_sha256"] == DRIVER_SHA
    assert gate["mdx_sha256"] == MDX_SHA and gate["canonical_text_sha256"] == TEXT_SHA
    assert gate["expected_binary_sha256"] == BINARY_SHA and gate["expected_object_sha256"] == OBJECT_SHA
    assert gate["artifact_hashes"] == driver.EXPECTED_ARTIFACTS
    assert set(driver.ARTIFACTS) == set(driver.EXPECTED_ARTIFACTS)
    for label, path in driver.ARTIFACTS.items():
        assert sha(path) == gate["artifact_hashes"][label], label

    assert result["identity"] == "ASTRA" and result["target_evaluated"] is True
    assert result["evaluation_complete"] is True
    assert result["gate_sha256"] == GATE_SHA
    assert result["scope"] == gate["scope"] == driver.scope()
    assert result["artifact_hashes"] == gate["artifact_hashes"]
    build = result["build_provenance"]
    assert build["temporary_build"] is True and build["published_binary_required"] is False
    assert build["binary_sha256"] == BINARY_SHA and build["object_sha256"] == OBJECT_SHA
    assert len(build["commands"]) == 2
    assert all("<TMP>" in " ".join(row["command"]) for row in build["commands"])

    oriented = orientations()
    expected_ids = [
        f"{backend}-start{start}-{orientation}-w13"
        for backend in BACKENDS for start in STARTS for orientation in ORIENTATIONS
    ]
    assert [cell["cell_id"] for cell in result["cells"]] == expected_ids

    block_calls = native_seconds = wall_seconds = 0
    cell_dir = HERE / "target_cells"
    for cell, cell_id in zip(result["cells"], expected_ids):
        backend, start_label, orientation, _width = cell_id.split("-", 3)
        start = int(start_label.removeprefix("start"))
        native = cell["native"]
        assert cell["identity"] == "ASTRA"
        assert cell["backend"] == backend and cell["start"] == start and cell["orientation"] == orientation
        assert cell["gate_sha256"] == GATE_SHA and cell["driver_sha256"] == DRIVER_SHA
        assert cell["binary_sha256"] == BINARY_SHA
        assert cell["observed_sha256"] == hashlib.sha256(oriented[orientation]).hexdigest()
        assert cell["complete_every_iv_order_exclusion"] is True and cell["unresolved"] is False
        assert native["identity"] == "ASTRA" and native["backend"] == backend
        assert native["width"] == 13 and native["start"] == start
        assert native["rows"] == 28 and native["chunk_bytes"] == 42
        assert native["prefix_limit"] == native["total_prefixes"] == native["prefixes_examined"] == PREFIXES
        assert native["rejected_prefixes"] == PREFIXES
        assert native["survivor_prefix_count"] == 0 and native["survivor_prefixes"] == []
        assert native["survivors_retained"] is True
        assert native["unexamined_prefixes"] == native["unexamined_completion_weight"] == 0
        assert native["completion_weight_per_prefix"] == WEIGHT
        assert native["rejected_completion_weight"] == FULL
        assert native["unresolved_examined_completion_weight"] == 0
        assert native["expected_completion_weight"] == FULL
        assert native["factorial_partition_complete"] is True and native["complete_scan"] is True
        assert native["survivor_digest_fnv1a64"] == "cbf29ce484222325"
        assert native["block_calls"] == native["rows_checked"] >= PREFIXES
        replay = cell["survivor_replay"]
        assert replay["identity"] == "ASTRA" and replay["replayed_survivors"] == 0
        assert replay["exact_assignments_and_plaintext_ninth_bytes"] is True
        assert replay["full_orders_or_iv_or_full_plaintext_recovered"] is False
        if check_local_cells:
            atomic = json.loads((cell_dir / f"{cell_id}.json").read_text())
            assert atomic == cell
        block_calls += native["block_calls"]
        native_seconds += native["elapsed_seconds"]
        wall_seconds += cell["wall_seconds"]

    summary = result["summary"]
    assert summary["cells"] == summary["closed_cells"] == 32
    assert summary["unresolved_cells"] == 0
    assert summary["prefixes_examined"] == summary["rejected_prefixes"] == 32 * PREFIXES == 39_536_640
    assert summary["survivor_prefixes"] == 0
    assert summary["block_calls"] == block_calls == 67_022_745
    assert summary["native_elapsed_seconds"] == native_seconds
    assert summary["wall_seconds"] == wall_seconds
    print(json.dumps({
        "identity": "ASTRA",
        "verified": True,
        "result_sha256": RESULT_SHA,
        "result_bytes": RESULT.stat().st_size,
        "cells": 32,
        "prefixes_examined": 39_536_640,
        "rejected_prefixes": 39_536_640,
        "survivors": 0,
        "unexamined_prefixes": 0,
        "block_calls": block_calls,
        "local_atomic_cells_checked": check_local_cells,
        "verification_scope": "standard-library gate/source, orientation, combined-cell, and factorial-accounting replay; not a second prefix enumeration",
    }, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-local-cells", action="store_true")
    args = parser.parse_args()
    main(args.check_local_cells)
