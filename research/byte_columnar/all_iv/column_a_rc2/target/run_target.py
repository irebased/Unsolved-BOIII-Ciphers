#!/usr/bin/env python3
"""Frozen-gate RC2 column-A target driver; selftest hashes MDX only."""
import argparse
import hashlib
import importlib.util
import itertools
import json
import math
import os
from pathlib import Path
import subprocess
import tempfile
import time

HERE = Path(__file__).resolve().parent
PACKAGE = HERE.parent
COLUMN_A = PACKAGE.parent / "column_a"
ROOT = HERE.parents[4]
GATE = HERE / "target_gate.json"
MDX = ROOT / "lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
MDX_SHA = "085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91"
TEXT_SHA = "5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
WIDTHS = (13, 14)
ORIENTATIONS = ("forward", "full_hex_reverse", "byte_reverse", "nibble_swap")
EXPECTED_BINARY_SHA = "679844dc071cce779d86667f1b8e55c5175045840d7b47044312f28dfdfd4b3b"
EXPECTED_OBJECT_SHA = "022a0517d79e7dfc9566ca3cf04462a7ffb62aaf9f2d4d0d8edb2ca0a2803b4e"
REQUIRED = {
    "README.md": "5ed12b4a71c2b86fa6fc539ace2700c2ac100401cb68be1e1a93bb976182ccbd",
    "REPORT.md": "f137e95e333f62e20775a334137538fbc875e0e31f81b9bf8b5c46ae382beb27",
    "controls.py": "c9c32b8a3e95699e42c6edd961928b85a51098a42e966639d85826b4650d4006",
    "controls.json": "7330bad3670745ef659dd597a3385ee06b7225b17eadb997a0e80519ac3abb9f",
    "native.cpp": "3c634ea5fa32caa146c2a078f85abdbc98984675744e7ffcf1977355e455a1cd",
    "source/rc2.c": "37c9398507cea1685255da9550f5a3a55b529b66e1bbc9a35e1996fecae7dc19",
    "source/rc2.h": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "source/COPYING.LIB": "ca0061fc1381a3ab242310e4b3f56389f28e3d460eb2fd822ed7a21c6f030532",
    "source_build/libdefs.h": "556ec4fcebae614cd90d05a2fead50d9355ff39f65b44c8f4044c7f209074c6e",
    "source_build/mcrypt_modules.h": "2fefe3d60795fb19e7a7be1c4cec18a97c069e2471ae61c951706020dcb6c180",
    "../column_a/core.py": "1deda1788e9d9a49140325c7e0f7ce3eb53aa7d05e8e44590be4076da0bae472",
    "../column_a/controls.json": "2fb68eff8b80fb120ca972a29ead64268f03057c10c00156fd49152e0cf62bea",
}

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def artifact_path(rel):
    return PACKAGE / rel

def scope():
    return {
        "identity": "ASTRA", "cells": 8, "decoded_bytes": 546,
        "cipher": "historical source-backed RC2", "key_hex": b"Zombies".hex(),
        "key_length": 7, "effective_keylen": 1024, "block_size": 8,
        "mode": "CFB8", "external_iv": "every eight-byte IV; neither recovered nor searched",
        "widths": list(WIDTHS), "orientations": list(ORIENTATIONS),
        "variant": "rectangular FABLE columnarA; slots is inverse of FABLE order",
        "equation": "C[row*w+j] = observed[slots[j]*q+row]",
        "constraint": "At natural column 8, intersect unused observed ranks across all rows using A105; IV-independent preceding ciphertext columns 0..7",
        "alphabet": sorted({9, 10, 13} | set(range(32, 127)) | {0x80, 0x93, 0x94, 0x98, 0x99, 0xa6, 0xe2}),
        "endpoint_limit": "necessary relaxed byte filter only; no full plaintext or strict UTF-8 claim",
        "prefix_limits": {str(w): math.perm(w, 8) for w in WIDTHS},
        "prefix_total_across_cells": 691_891_200,
        "completion_weight_per_prefix": {str(w): math.factorial(w - 8) for w in WIDTHS},
        "enumeration": "fresh complete lexicographic first-eight rank tuples per case",
        "survivors": "retain every exact first-eight tuple and ninth-rank candidate set; independently replay every retained mask with PyCryptodome ARC2/1024",
        "closure": "a cell closes only after complete scan with zero surviving prefixes; otherwise unresolved",
        "overwrite_policy": "refuse existing cells or combined result; no automatic rerun",
    }

def require_gate():
    gate = json.loads(GATE.read_text())
    assert gate["identity"] == "ASTRA" and gate["target_evaluated"] is False
    assert gate["authorization"] == "FABLE preregistration plus separate root GO required"
    assert gate["target_readme_sha256"] == sha(HERE / "README.md")
    assert gate["gate_builder_sha256"] == sha(HERE / "prepare_gate.py")
    assert gate["scope"] == scope()
    assert gate["driver_sha256"] == sha(Path(__file__))
    assert gate["build_helper_sha256"] == sha(HERE / "build_native.py")
    assert gate["artifact_hashes"] == REQUIRED
    assert gate["expected_binary_sha256"] == EXPECTED_BINARY_SHA
    assert gate["expected_object_sha256"] == EXPECTED_OBJECT_SHA
    for rel, expected in REQUIRED.items():
        assert sha(artifact_path(rel)) == expected, rel
    assert sha(MDX) == MDX_SHA and gate["mdx_sha256"] == MDX_SHA
    assert gate["canonical_text_sha256"] == TEXT_SHA
    controls = json.loads((PACKAGE / "controls.json").read_text())
    assert controls["identity"] == "ASTRA" and controls["target_evaluated"] is False and controls["rev7_read"] is False
    assert controls["assertions"]["all_passed"] is True
    assert controls["build"]["temporary_binary_sha256_machine_evidence"] == EXPECTED_BINARY_SHA
    assert controls["build"]["temporary_object_sha256_machine_evidence"] == EXPECTED_OBJECT_SHA
    return gate, sha(GATE)

def canonical_orientations():
    text = MDX.read_text()
    start = text.index("`83 B57B2") + 1
    end = text.index("`", start)
    canonical = "".join(text[start:end].split()).upper()
    assert len(canonical) == 1092 and hashlib.sha256(canonical.encode()).hexdigest() == TEXT_SHA
    pairs = [canonical[i:i + 2] for i in range(0, len(canonical), 2)]
    return dict(zip(ORIENTATIONS, (canonical, canonical[::-1], "".join(reversed(pairs)), "".join(x[::-1] for x in pairs))))

def load_core():
    spec = importlib.util.spec_from_file_location("column_a_core", COLUMN_A / "core.py")
    core = importlib.util.module_from_spec(spec); spec.loader.exec_module(core)
    return core

def replay_survivors(width, observed, native):
    from Crypto.Cipher import ARC2
    core = load_core()
    ecb = ARC2.new(b"Zombies", ARC2.MODE_ECB, effective_keylen=1024)
    seen = set(); checked = []
    for row in native["survivor_prefixes"]:
        prefix = tuple(row["first_slots"])
        assert len(prefix) == 8 and len(set(prefix)) == 8 and prefix not in seen
        seen.add(prefix)
        expected = core.evaluate_first_block_tuple(observed, width, 8, prefix, lambda block: ecb.encrypt(block)[0], core.A105)
        assert not expected["empty_candidate_mask"]
        assert row["surviving_ninth_ranks"] == expected["surviving_ninth_ranks"]
        checked.append({"first_slots": list(prefix), "surviving_ninth_ranks": row["surviving_ninth_ranks"],
                        "independent_arc2_1024_exact_mask": True})
    assert len(seen) == native["survivor_prefix_count"]
    return {"identity": "ASTRA", "exact_masks_replayed": len(checked), "checked": checked,
            "reference": "PyCryptodome ARC2 effective_keylen=1024 plus frozen Python column-A tuple evaluator",
            "full_orders_iv_or_plaintext_recovered": False}

def validate_native(native, width):
    n = math.perm(width, 8); weight = math.factorial(width - 8)
    assert native["identity"] == "ASTRA" and native["backend"] == "rc2"
    assert native["width"] == width and native["rows"] == 546 // width
    assert native["prefix_limit"] == native["total_prefixes"] == native["prefixes_examined"] == n
    assert native["rejected_prefixes"] + native["survivor_prefix_count"] == n
    assert native["survivors_retained"] is True and len(native["survivor_prefixes"]) == native["survivor_prefix_count"]
    assert native["complete_scan"] is True and native["factorial_partition_complete"] is True
    assert native["unexamined_prefixes"] == native["unexamined_completion_weight"] == 0
    assert native["completion_weight_per_prefix"] == weight
    assert native["rejected_completion_weight"] == native["rejected_prefixes"] * weight
    assert native["unresolved_examined_completion_weight"] == native["survivor_prefix_count"] * weight
    assert native["expected_completion_weight"] == math.factorial(width)
    assert native["rejected_completion_weight"] + native["unresolved_examined_completion_weight"] == math.factorial(width)
    assert native["block_calls"] == native["rows_checked"] >= n
    assert native["candidate_tests"] >= native["block_calls"]

def write_new(path, value):
    if path.exists():
        raise RuntimeError("refusing existing output " + str(path))
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("x") as handle:
        json.dump(value, handle, indent=2, sort_keys=True); handle.write("\n")
    os.replace(temporary, path)

def normalize_build(record, temporary):
    prefix = str(temporary)
    rows = []
    for row in record["commands"]:
        rows.append({**row, "command": [part.replace(prefix, "<TMP>") for part in row["command"]]})
    return {"identity": "ASTRA", "source_hashes": record["source_hashes"], "commands": rows,
            "object_sha256": record["object_sha256"], "binary_sha256": record["binary_sha256"],
            "temporary_build": True, "published_binary_required": False}

def run():
    gate, gate_sha = require_gate()
    output = HERE / "target_results.json"
    cell_dir = HERE / "target_cells"
    if output.exists() or (cell_dir.exists() and any(cell_dir.iterdir())):
        raise RuntimeError("refusing existing target output; inspect completed work instead of rerunning")
    cell_dir.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="column-a-rc2-target-") as temporary_name:
        temporary = Path(temporary_name)
        spec = importlib.util.spec_from_file_location("rc2_build", HERE / "build_native.py")
        builder = importlib.util.module_from_spec(spec); spec.loader.exec_module(builder)
        build = builder.build(temporary)
        assert build["object_sha256"] == EXPECTED_OBJECT_SHA
        assert build["binary_sha256"] == EXPECTED_BINARY_SHA
        binary = Path(build["binary"])
        build_provenance = normalize_build(build, temporary)
        orientations = canonical_orientations()
        cells = []
        for width in WIDTHS:
            for orientation in ORIENTATIONS:
                observed = bytes.fromhex(orientations[orientation])
                started = time.monotonic()
                command = [str(binary), "--search", "rc2", str(width), str(math.perm(width, 8)), observed.hex()]
                completed = subprocess.run(command, check=True, capture_output=True, text=True)
                native = json.loads(completed.stdout)
                validate_native(native, width)
                replay = replay_survivors(width, observed, native)
                closed = native["survivor_prefix_count"] == 0 and native["rejected_prefixes"] == math.perm(width, 8)
                cell = {"identity": "ASTRA", "cipher": "rc2", "width": width, "orientation": orientation,
                        "observed_sha256": hashlib.sha256(observed).hexdigest(), "gate_sha256": gate_sha,
                        "driver_sha256": sha(Path(__file__)), "binary_sha256": build["binary_sha256"],
                        "native": native, "survivor_replay": replay,
                        "complete_every_iv_order_exclusion": closed, "unresolved": not closed,
                        "wall_seconds": time.monotonic() - started}
                write_new(cell_dir / f"rc2_w{width}_{orientation}.json", cell)
                cells.append(cell)
                print(json.dumps({"identity": "ASTRA", "completed_cells": len(cells), "width": width,
                                  "orientation": orientation, "closed": closed,
                                  "survivor_prefixes": native["survivor_prefix_count"]}), flush=True)
        assert len(cells) == 8
        assert sum(x["native"]["prefixes_examined"] for x in cells) == 691_891_200
        combined = {"identity": "ASTRA", "target_evaluated": True, "evaluation_complete": True,
                    "scope": scope(), "gate_sha256": gate_sha, "artifact_hashes": gate["artifact_hashes"],
                    "build_provenance": build_provenance, "cells": cells,
                    "summary": {"cells": 8,
                                "closed_cells": sum(x["complete_every_iv_order_exclusion"] for x in cells),
                                "unresolved_cells": sum(x["unresolved"] for x in cells),
                                "prefixes_examined": 691_891_200,
                                "survivor_prefixes": sum(x["native"]["survivor_prefix_count"] for x in cells)}}
        write_new(output, combined)
    print(json.dumps({"identity": "ASTRA", "complete": True, "summary": combined["summary"],
                      "result_sha256": sha(output)}), flush=True)

def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--selftest", action="store_true")
    mode.add_argument("--run-target", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        _gate, gate_sha = require_gate()
        print(json.dumps({"identity": "ASTRA", "target_evaluated": False, "selftest": True,
                          "gate_sha256": gate_sha,
                          "target_handling": "MDX bytes hashed only; ciphertext not extracted, oriented, or evaluated",
                          "scope": scope()}, indent=2))
    else:
        run()

if __name__ == "__main__":
    main()
