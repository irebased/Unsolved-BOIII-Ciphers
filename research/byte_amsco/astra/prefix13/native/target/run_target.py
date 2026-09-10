#!/usr/bin/env python3
"""Inert frozen-gate driver for width-13 first-six byte-AMSCO necessary filtering."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import subprocess
import tempfile
import time

HERE = Path(__file__).resolve().parent
NATIVE = HERE.parent
PREFIX = NATIVE.parent
RESEARCH = HERE.parents[4]
ROOT = HERE.parents[5]
GATE = HERE / "target_gate.json"
MDX = ROOT / "lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
MDX_SHA = "085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91"
TEXT_SHA = "5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
EXPECTED_BINARY_SHA = "704f5f431b0b92136624eaba960605f2a652e8818a42b86a8a44e14566722b04"
EXPECTED_OBJECT_SHA = "022a0517d79e7dfc9566ca3cf04462a7ffb62aaf9f2d4d0d8edb2ca0a2803b4e"
BACKENDS = ("des", "blowfish", "blowfish_compat", "rc2")
STARTS = (1, 2)
ORIENTATIONS = ("forward", "full_hex_reverse", "byte_reverse", "nibble_swap")
WIDTH = 13
N = 546
PREFIXES = math.perm(WIDTH, 6)
WEIGHT = math.factorial(WIDTH - 6)

ARTIFACTS = {
    "base/core.py": PREFIX.parent / "core.py",
    "base/controls.py": PREFIX.parent / "controls.py",
    "base/controls.json": PREFIX.parent / "controls.json",
    "prefix13/proof.py": PREFIX / "proof.py",
    "prefix13/controls.py": PREFIX / "controls.py",
    "prefix13/controls.json": PREFIX / "controls.json",
    "prefix13/README.md": PREFIX / "README.md",
    "prefix13/REPORT.md": PREFIX / "REPORT.md",
    "native/native.cpp": NATIVE / "native.cpp",
    "native/native_controls.py": NATIVE / "native_controls.py",
    "native/native_controls.json": NATIVE / "native_controls.json",
    "native/README.md": NATIVE / "README.md",
    "native/PROVENANCE.md": NATIVE / "PROVENANCE.md",
    "native/REPORT.md": NATIVE / "REPORT.md",
    "column_a/native/native.cpp": RESEARCH / "byte_columnar/all_iv/column_a/native/native.cpp",
    "column_a/native/native_controls.json": RESEARCH / "byte_columnar/all_iv/column_a/native/native_controls.json",
    "column_a_rc2/source/rc2.c": RESEARCH / "byte_columnar/all_iv/column_a_rc2/source/rc2.c",
    "column_a_rc2/source/rc2.h": RESEARCH / "byte_columnar/all_iv/column_a_rc2/source/rc2.h",
    "column_a_rc2/source/COPYING.LIB": RESEARCH / "byte_columnar/all_iv/column_a_rc2/source/COPYING.LIB",
    "column_a_rc2/source_build/libdefs.h": RESEARCH / "byte_columnar/all_iv/column_a_rc2/source_build/libdefs.h",
    "column_a_rc2/source_build/mcrypt_modules.h": RESEARCH / "byte_columnar/all_iv/column_a_rc2/source_build/mcrypt_modules.h",
    "column_a_rc2/controls.json": RESEARCH / "byte_columnar/all_iv/column_a_rc2/controls.json",
    "cascade/runtime/runtime.py": RESEARCH / "rev7-20260909-codex/iv_independent/cascade/runtime/runtime.py",
    "cascade/runtime/controls.json": RESEARCH / "rev7-20260909-codex/iv_independent/cascade/runtime/controls.json",
}
EXPECTED_ARTIFACTS = {
    "base/core.py": "2e7b413cb01396c8c6c97f21ad4a1e46939c3c1488c27e1c48bed8e24a48b990",
    "base/controls.py": "b187ab27bbde490399333c19ddf62f8cb13f514b90fb50614cb231b4a5f65ad0",
    "base/controls.json": "767d651729055d1d6fa202e8983635d3afafd46d06729924569db7260ed21175",
    "prefix13/proof.py": "2b349a27f9bed45c3e114fc1210fa5ecfac377c51e616f25ef8abfa3ab71efb2",
    "prefix13/controls.py": "4a0b02045783d88ae1979afd197176ff36a405802bdf5310519fa5f9a91ea2b9",
    "prefix13/controls.json": "7729b861b73e2326bffb33caf1ba2951278bc8d1d0accee2b61973bed3c10de7",
    "prefix13/README.md": "9ab08cf666cbf6aaa9c7af15e5620464f04ce78c3b6ae8f393abe634e76affdb",
    "prefix13/REPORT.md": "50237d417f4a937fc8272fa9186050c117c62c72a8de5cf9fb72a59e721ac0e5",
    "native/native.cpp": "f9c731e222381597dcb03d00155549f12fb6d82923975b13f2a18d3c05e631d0",
    "native/native_controls.py": "901def5c5a4f329354611d9930f55b441619ae9fb2ff219aed0e560329b4221d",
    "native/native_controls.json": "97eb5e5783c8c0aedfe98c27e112da8ffb2a641fa284a6ff3690de867be62766",
    "native/README.md": "a0cef8fe9152a88257a947c5db8218277cbaccef0a5c612857d6a5898013b04f",
    "native/PROVENANCE.md": "1602c3cce8a67d1883761fa57b0c294d3c9c95413f5335e7eb7f5037de4614fe",
    "native/REPORT.md": "b14940702f7189dff6a6c86f8f739ae929324d32dbcf27e1030c273929f1b2d8",
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


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def scope():
    return {
        "identity": "ASTRA",
        "cells": 32,
        "decoded_bytes": N,
        "width": WIDTH,
        "rows": 28,
        "observed_chunk_bytes": 42,
        "backends": list(BACKENDS),
        "starts": list(STARTS),
        "orientations": list(ORIENTATIONS),
        "keys": {
            "des": "Zombies + NUL",
            "blowfish": "raw seven-byte Zombies",
            "blowfish_compat": "raw seven-byte Zombies",
            "rc2": "raw seven-byte Zombies, effective 1024 bits",
        },
        "mode": "CFB8",
        "external_iv": "every eight-byte IV; neither recovered nor searched",
        "variant": "inverse byte-unit AMSCO with continuous alternating 1/2-byte cells",
        "assignment": "six distinct observed 42-byte chunk ranks assigned to natural columns 0..5",
        "constraint": "first six natural cells fix nine ciphertext bytes per row; test the ninth CFB8 plaintext byte against A105",
        "alphabet": sorted({9, 10, 13} | set(range(32, 127)) | {0x80, 0x93, 0x94, 0x98, 0x99, 0xA6, 0xE2}),
        "endpoint_limit": "necessary relaxed byte filter only; retained prefix is not a full order or plaintext",
        "prefixes_per_cell": PREFIXES,
        "prefixes_total": 32 * PREFIXES,
        "completion_weight_per_prefix": WEIGHT,
        "full_order_weight_per_cell": math.factorial(WIDTH),
        "enumeration": "complete fresh lexicographic P(13,6) per cell; no cap and no resume",
        "survivors": "retain every six-rank prefix and all 28 computed ninth plaintext bytes; independently replay each",
        "closure": "cell closes only if every prefix rejects; otherwise unresolved",
        "overwrite_policy": "refuse any existing cell or combined output",
    }


def require_artifacts():
    assert set(ARTIFACTS) == set(EXPECTED_ARTIFACTS)
    for label, path in ARTIFACTS.items():
        got = sha(path)
        if got != EXPECTED_ARTIFACTS[label]:
            raise AssertionError((label, got, EXPECTED_ARTIFACTS[label]))


def require_gate():
    gate = json.loads(GATE.read_text())
    assert gate["identity"] == "ASTRA" and gate["target_evaluated"] is False
    assert gate["authorization"] == "FABLE preregistration plus separate root GO required"
    assert gate["scope"] == scope()
    assert gate["driver_sha256"] == sha(Path(__file__))
    assert gate["target_readme_sha256"] == sha(HERE / "README.md")
    assert gate["build_helper_sha256"] == sha(HERE / "build_native.py")
    assert gate["driver_controls_source_sha256"] == sha(HERE / "driver_controls.py")
    assert gate["driver_controls_ledger_sha256"] == sha(HERE / "driver_controls.json")
    assert gate["gate_builder_sha256"] == sha(HERE / "prepare_gate.py")
    assert gate["artifact_hashes"] == EXPECTED_ARTIFACTS
    require_artifacts()
    assert sha(MDX) == MDX_SHA and gate["mdx_sha256"] == MDX_SHA
    assert gate["canonical_text_sha256"] == TEXT_SHA
    controls = json.loads((NATIVE / "native_controls.json").read_text())
    driver_controls = json.loads((HERE / "driver_controls.json").read_text())
    for ledger in (controls, driver_controls):
        assert ledger["identity"] == "ASTRA" and ledger["target_evaluated"] is False
        assert ledger["rev7_file_read"] is False and all(ledger["assertions"].values())
    assert controls["build"]["binary_sha256"] == EXPECTED_BINARY_SHA
    assert controls["build"]["object_sha256"] == EXPECTED_OBJECT_SHA
    assert driver_controls["build"]["binary_sha256"] == EXPECTED_BINARY_SHA
    assert driver_controls["build"]["object_sha256"] == EXPECTED_OBJECT_SHA
    return gate, sha(GATE)


def canonical_orientations():
    text = MDX.read_text()
    start = text.index("`83 B57B2") + 1
    end = text.index("`", start)
    canonical = "".join(text[start:end].split()).upper()
    assert len(canonical) == 1092
    assert hashlib.sha256(canonical.encode()).hexdigest() == TEXT_SHA
    pairs = [canonical[i:i + 2] for i in range(0, len(canonical), 2)]
    return {
        "forward": canonical,
        "full_hex_reverse": canonical[::-1],
        "byte_reverse": "".join(reversed(pairs)),
        "nibble_swap": "".join(pair[::-1] for pair in pairs),
    }


def independent_replay(backend: str, start: int, observed: bytes, result: dict):
    proof = load_module("astra_prefix13_target_proof", PREFIX / "proof.py")
    controls = load_module("astra_prefix13_target_refs", NATIVE / "native_controls.py")
    block = controls.references()[backend]
    seen = set()
    previous = None
    for row in result["survivor_prefixes"]:
        assignment = tuple(row["assignment"])
        assert len(assignment) == 6 and len(set(assignment)) == 6
        assert all(0 <= value < WIDTH for value in assignment)
        assert assignment not in seen
        if previous is not None:
            assert previous < assignment
        previous = assignment
        seen.add(assignment)
        accepted, values = proof.evaluate_prefix(observed, WIDTH, start, assignment, block)
        assert accepted
        assert row["plaintext_ninth_hex"] == bytes(values).hex()
        assert len(values) == 2 * len(observed) // (3 * WIDTH)
    assert len(seen) == result["survivor_prefix_count"]
    assert result["survivor_digest_fnv1a64"] == controls.fnv(result["survivor_prefixes"])
    return {
        "identity": "ASTRA",
        "replayed_survivors": len(seen),
        "reference": "accepted Python prefix13 formula plus PyCryptodome/compatibility-conjugation block reference",
        "exact_assignments_and_plaintext_ninth_bytes": True,
        "full_orders_or_iv_or_full_plaintext_recovered": False,
    }


def validate_native(result: dict, backend: str, start: int, prefix_limit: int):
    assert result["identity"] == "ASTRA" and result["backend"] == backend
    assert result["width"] == WIDTH and result["start"] == start
    expected_rows = 2 * N // (3 * WIDTH)
    assert result["rows"] == expected_rows and result["chunk_bytes"] == 3 * expected_rows // 2
    assert result["prefix_limit"] == prefix_limit
    assert result["prefixes_examined"] == prefix_limit
    assert result["total_prefixes"] == PREFIXES
    assert result["rejected_prefixes"] + result["survivor_prefix_count"] == prefix_limit
    assert result["survivors_retained"] is True
    assert len(result["survivor_prefixes"]) == result["survivor_prefix_count"]
    assert result["completion_weight_per_prefix"] == WEIGHT
    assert result["rejected_completion_weight"] == result["rejected_prefixes"] * WEIGHT
    assert result["unresolved_examined_completion_weight"] == result["survivor_prefix_count"] * WEIGHT
    unexamined = PREFIXES - prefix_limit
    assert result["unexamined_prefixes"] == unexamined
    assert result["unexamined_completion_weight"] == unexamined * WEIGHT
    assert result["expected_completion_weight"] == math.factorial(WIDTH)
    assert result["rejected_completion_weight"] + result["unresolved_examined_completion_weight"] + result["unexamined_completion_weight"] == math.factorial(WIDTH)
    assert result["factorial_partition_complete"] is True
    assert result["complete_scan"] is (prefix_limit == PREFIXES)
    assert result["block_calls"] == result["rows_checked"] >= prefix_limit


def execute_cell(binary: Path, backend: str, start: int, observed: bytes, prefix_limit: int = PREFIXES):
    if backend not in BACKENDS or start not in STARTS:
        raise ValueError("unregistered cell")
    if len(observed) != N:
        raise ValueError("observed bytes must have length 546")
    if not 1 <= prefix_limit <= PREFIXES:
        raise ValueError("prefix limit")
    command = [str(binary), "--search", backend, str(WIDTH), str(start), str(prefix_limit), observed.hex()]
    completed = subprocess.run(command, check=True, capture_output=True, text=True)
    result = json.loads(completed.stdout)
    validate_native(result, backend, start, prefix_limit)
    replay = independent_replay(backend, start, observed, result)
    return result, replay, command


def write_new(path: Path, value):
    if path.exists():
        raise RuntimeError("refusing existing output " + str(path))
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("x") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(temporary, path)


def normalize_build(record: dict, temporary: Path):
    prefix = str(temporary)
    commands = []
    for row in record["commands"]:
        commands.append({**row, "command": [part.replace(prefix, "<TMP>") for part in row["command"]]})
    return {
        "temporary_build": True,
        "published_binary_required": False,
        "commands": commands,
        "object_sha256": record["object_sha256"],
        "binary_sha256": record["binary_sha256"],
        "compiler": record["compiler"],
        "openssl_version": record["openssl_version"],
    }


def run_target():
    gate, gate_sha = require_gate()
    output = HERE / "target_results.json"
    cell_dir = HERE / "target_cells"
    if output.exists() or (cell_dir.exists() and any(cell_dir.iterdir())):
        raise RuntimeError("refusing existing target output; no resume or automatic rerun")
    cell_dir.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="astra-prefix13-target-") as temporary_name:
        temporary = Path(temporary_name)
        builder = load_module("astra_prefix13_target_build", HERE / "build_native.py")
        build = builder.build(temporary)
        assert build["binary_sha256"] == EXPECTED_BINARY_SHA
        assert build["object_sha256"] == EXPECTED_OBJECT_SHA
        binary = Path(build["binary"])
        orientations = canonical_orientations()
        cells = []
        for backend in BACKENDS:
            for start in STARTS:
                for orientation in ORIENTATIONS:
                    observed = bytes.fromhex(orientations[orientation])
                    began = time.monotonic()
                    native, replay, command = execute_cell(binary, backend, start, observed)
                    closed = native["survivor_prefix_count"] == 0 and native["rejected_prefixes"] == PREFIXES
                    cell_id = f"{backend}-start{start}-{orientation}-w13"
                    cell = {
                        "identity": "ASTRA",
                        "cell_id": cell_id,
                        "backend": backend,
                        "start": start,
                        "orientation": orientation,
                        "observed_sha256": hashlib.sha256(observed).hexdigest(),
                        "gate_sha256": gate_sha,
                        "driver_sha256": sha(Path(__file__)),
                        "binary_sha256": build["binary_sha256"],
                        "native": native,
                        "survivor_replay": replay,
                        "complete_every_iv_order_exclusion": closed,
                        "unresolved": not closed,
                        "wall_seconds": time.monotonic() - began,
                    }
                    write_new(cell_dir / f"{cell_id}.json", cell)
                    cells.append(cell)
                    print(json.dumps({"identity": "ASTRA", "completed_cells": len(cells), "cell_id": cell_id, "closed": closed, "survivors": native["survivor_prefix_count"]}), flush=True)
        assert len(cells) == 32
        assert sum(cell["native"]["prefixes_examined"] for cell in cells) == 39_536_640
        combined = {
            "identity": "ASTRA",
            "target_evaluated": True,
            "evaluation_complete": True,
            "scope": scope(),
            "gate_sha256": gate_sha,
            "artifact_hashes": gate["artifact_hashes"],
            "build_provenance": normalize_build(build, temporary),
            "cells": cells,
            "summary": {
                "cells": 32,
                "closed_cells": sum(cell["complete_every_iv_order_exclusion"] for cell in cells),
                "unresolved_cells": sum(cell["unresolved"] for cell in cells),
                "prefixes_examined": sum(cell["native"]["prefixes_examined"] for cell in cells),
                "rejected_prefixes": sum(cell["native"]["rejected_prefixes"] for cell in cells),
                "survivor_prefixes": sum(cell["native"]["survivor_prefix_count"] for cell in cells),
                "block_calls": sum(cell["native"]["block_calls"] for cell in cells),
                "native_elapsed_seconds": sum(cell["native"]["elapsed_seconds"] for cell in cells),
                "wall_seconds": sum(cell["wall_seconds"] for cell in cells),
            },
        }
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
        print(json.dumps({
            "identity": "ASTRA",
            "target_evaluated": False,
            "selftest": True,
            "gate_sha256": gate_sha,
            "target_handling": "MDX bytes hashed only; ciphertext not extracted, oriented, or evaluated",
            "scope": scope(),
        }, indent=2))
    else:
        run_target()


if __name__ == "__main__":
    main()
