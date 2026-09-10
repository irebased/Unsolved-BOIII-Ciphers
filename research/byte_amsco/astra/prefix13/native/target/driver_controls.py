#!/usr/bin/env python3
"""Synthetic controls for the inert prefix13 target driver's execute_cell path."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import math
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
DRIVER = HERE / "run_target.py"
BUILDER = HERE / "build_native.py"
LEDGER = HERE / "driver_controls.json"
IDENTITY = "ASTRA"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def regenerate(output: Path):
    if output.exists():
        raise SystemExit(f"refusing to overwrite {output}")
    driver = load("astra_prefix13_inert_driver_control", DRIVER)
    builder = load("astra_prefix13_inert_builder_control", BUILDER)
    native_controls = load("astra_prefix13_native_control_helpers", driver.NATIVE / "native_controls.py")
    refs = native_controls.references()
    width = 7
    rows = 4
    n = 3 * width * rows // 2
    order = (4, 0, 6, 2, 5, 1, 3)
    truth = tuple(order.index(column) for column in range(6))
    plaintext = native_controls.plaintext_for(n)
    records = []
    with tempfile.TemporaryDirectory(prefix="astra-prefix13-driver-control-") as temporary_name:
        temporary = Path(temporary_name)
        build = builder.build(temporary)
        binary = Path(build["binary"])
        for backend, start in (("des", 1), ("rc2", 2)):
            block = refs[backend]
            iv = bytes((start * 61 + i * 29 + len(backend)) & 255 for i in range(8))
            ciphertext = native_controls.cfb8(plaintext, iv, block)
            observed = native_controls.oracle_forward(ciphertext, width, order, start)
            # execute_cell is the exact function used by the future target.
            original_width = driver.WIDTH
            original_n = driver.N
            original_prefixes = driver.PREFIXES
            original_weight = driver.WEIGHT
            try:
                driver.WIDTH = width
                driver.N = n
                driver.PREFIXES = math.perm(width, 6)
                driver.WEIGHT = math.factorial(width - 6)
                native, replay, command = driver.execute_cell(binary, backend, start, observed, driver.PREFIXES)
            finally:
                driver.WIDTH = original_width
                driver.N = original_n
                driver.PREFIXES = original_prefixes
                driver.WEIGHT = original_weight
            truth_rows = [row for row in native["survivor_prefixes"] if tuple(row["assignment"]) == truth]
            assert len(truth_rows) == 1
            assert native["rejected_prefixes"] > 0 and native["survivor_prefix_count"] > 0
            assert native["prefixes_examined"] == math.factorial(width)
            assert native["completion_weight_per_prefix"] == 1
            assert replay["replayed_survivors"] == native["survivor_prefix_count"]
            records.append({
                "backend": backend,
                "start": start,
                "width": width,
                "rows": rows,
                "order": list(order),
                "truth_assignment": list(truth),
                "observed_sha256": hashlib.sha256(observed).hexdigest(),
                "prefixes_examined": native["prefixes_examined"],
                "rejected_prefixes": native["rejected_prefixes"],
                "survivor_prefix_count": native["survivor_prefix_count"],
                "block_calls": native["block_calls"],
                "survivor_digest_fnv1a64": native["survivor_digest_fnv1a64"],
                "truth_retained": True,
                "all_survivors_independently_replayed": True,
                "same_execute_cell_path": True,
                "command_shape": ["<TMP>/native_search", "--search", backend, str(width), str(start), str(math.factorial(width)), "<OBSERVED_HEX>"],
            })
        build_record = {
            "binary_sha256": build["binary_sha256"],
            "object_sha256": build["object_sha256"],
            "compiler": build["compiler"],
            "openssl_version": build["openssl_version"],
            "commands": [{**row, "command": [part.replace(str(temporary), "<TMP>") for part in row["command"]]} for row in build["commands"]],
            "temporary_build": True,
        }
    result = {
        "identity": IDENTITY,
        "target_evaluated": False,
        "rev7_file_read": False,
        "scope": "Synthetic-only callback controls for the inert width13 target driver's execute_cell path.",
        "records": records,
        "build": build_record,
        "artifact_hashes": {
            "run_target.py": sha(DRIVER),
            "build_native.py": sha(BUILDER),
            "native.cpp": sha(driver.NATIVE / "native.cpp"),
            "native_controls.json": sha(driver.NATIVE / "native_controls.json"),
            "prefix13/proof.py": sha(driver.PREFIX / "proof.py"),
        },
        "environment": {"python": sys.version},
        "assertions": {
            "all_passed": True,
            "temporary_build_exact": build_record["binary_sha256"] == driver.EXPECTED_BINARY_SHA and build_record["object_sha256"] == driver.EXPECTED_OBJECT_SHA,
            "same_execute_cell_path": True,
            "complete_width7_cells": True,
            "positive_and_rejected_prefixes": True,
            "all_survivors_independently_replayed": True,
            "factorial_accounting": True,
            "no_target": True,
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"identity": IDENTITY, "written": str(output), "sha256": sha(output), "records": records}, indent=2))


def verify_default(path: Path):
    data = json.loads(path.read_text())
    assert data["identity"] == IDENTITY and not data["target_evaluated"] and not data["rev7_file_read"]
    expected = {
        "run_target.py": sha(DRIVER),
        "build_native.py": sha(BUILDER),
        "native.cpp": sha(HERE.parent / "native.cpp"),
        "native_controls.json": sha(HERE.parent / "native_controls.json"),
        "prefix13/proof.py": sha(HERE.parent.parent / "proof.py"),
    }
    assert data["artifact_hashes"] == expected
    assert len(data["records"]) == 2
    assert [(row["backend"], row["start"]) for row in data["records"]] == [("des", 1), ("rc2", 2)]
    assert all(row["same_execute_cell_path"] and row["truth_retained"] and row["rejected_prefixes"] > 0 and row["survivor_prefix_count"] > 0 for row in data["records"])
    assert all(data["assertions"].values())
    print(json.dumps({"identity": IDENTITY, "verified": True, "ledger_sha256": sha(path), "target_evaluated": False, "verification_scope": "standard-library integrity and structural checks; no compile or callback replay"}, sort_keys=True))


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
