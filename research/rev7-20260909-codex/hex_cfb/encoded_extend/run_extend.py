#!/usr/bin/env python3
"""Base64-only 3M-node extension for global-hex-permutation + CFB8.

Controls and target execution are explicit. The target is inaccessible until
both the prior encoded gate and this driver's source-specific gate validate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys
from dataclasses import asdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
HEX_CFB = HERE.parent
ENCODED = HEX_CFB / "encoded"
REPO = HERE.parents[3]
sys.path.insert(0, str(ENCODED))
sys.path.insert(0, str(HEX_CFB))
import prototype as core  # noqa: E402
import run_encoded as prior  # noqa: E402

IDENTITY = "ASTRA"
NODE_LIMIT = 3_000_000
PRIOR_LIMIT = 1_000_000
FULL_WEIGHT = math.factorial(16)
ALLOWED = set(prior.ENDPOINTS["base64"])
CIPHERS = tuple(prior.CIPHERS)
ORIENTATIONS = tuple(prior.ORIENTATIONS)
REV7_SOURCE = prior.REV7_SOURCE
EXPECTED_REV7_SHA256 = prior.EXPECTED_REV7_SHA256


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def atomic_json(path: Path, value: dict) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def transition(state: int, _position: int, value: int):
    assert state == 0
    return 0 if value in ALLOWED else None


def stats_record(stats, cap: int) -> dict:
    value = asdict(stats)
    certificate = stats.rejected_completion_weight + stats.terminal_completion_weight
    complete = not stats.aborted_at_node_limit
    if complete:
        assert certificate == FULL_WEIGHT
    else:
        assert stats.nodes == cap and certificate < FULL_WEIGHT
    value.update({
        "node_limit": cap,
        "node_definition": "DFS entries; one ECB call for each nonterminal accepted-prefix entry",
        "certificate_weight": certificate,
        "expected_factorial_weight": FULL_WEIGHT,
        "search_status": "complete" if complete else "capped",
        "certificate_complete": complete and certificate == FULL_WEIGHT,
    })
    return value


def raw_prior_stats(row: dict) -> dict:
    keys = set(asdict(core.SearchStats()))
    return {key: row[key] for key in keys}


def prior_gate() -> tuple[dict, str]:
    data, digest = prior.require_frozen_controls()
    assert digest == sha256_bytes((ENCODED / "controls.json").read_bytes())
    assert data["source_hashes"]["prototype_py_sha256"] == sha256_bytes((HEX_CFB / "prototype.py").read_bytes())
    assert data["source_hashes"]["run_encoded_py_sha256"] == sha256_bytes((ENCODED / "run_encoded.py").read_bytes())
    assert len(data["endpoints"]["base64"]) == 69
    assert data["ciphers"] == list(CIPHERS)
    assert data["orientations"] == list(ORIENTATIONS)
    fallback = data["explicit_seeded_fallbacks"].get("base64")
    assert fallback and fallback["seeded_mapping_entries"] == 12
    assert fallback["plant_recovered"] and fallback["stats"]["certificate_complete"]
    return data, digest


def control_gate() -> dict:
    old, old_digest = prior_gate()
    plaintext, mapping, _ciphertext, displayed = prior.deterministic_fixture("base64", "aes128")
    assert len(plaintext) == 546 and len(set(displayed)) == 16
    ecb, _key, iv = core.ecb_oracle("aes128")

    prefix_solutions, prefix_stats = core.backtrack(
        displayed, ecb, iv, transition, node_limit=PRIOR_LIMIT)
    old_row = old["full_unseeded_aes_gates"]["base64"]
    assert asdict(prefix_stats) == raw_prior_stats(old_row["stats"])
    assert len(prefix_solutions) == old_row["survivor_count_seen"]
    assert (mapping in {tuple(solution["mapping"]) for solution in prefix_solutions}) == old_row["plant_recovered"]

    extended_solutions, extended_stats = core.backtrack(
        displayed, ecb, iv, transition, node_limit=NODE_LIMIT)
    plant_recovered = any(tuple(solution["mapping"]) == mapping and solution["plaintext"] == plaintext
                          for solution in extended_solutions)
    validated = [prior.validate_solution(displayed, "aes128", ALLOWED, solution)
                 for solution in extended_solutions]
    fallback = old["explicit_seeded_fallbacks"]["base64"]
    if not plant_recovered:
        assert extended_stats.aborted_at_node_limit
        assert fallback["plant_recovered"] and fallback["stats"]["certificate_complete"]

    return {
        "identity": IDENTITY,
        "target_evaluated": False,
        "scope": {
            "endpoint": "base64",
            "allowed_bytes": sorted(ALLOWED),
            "allowed_byte_count": len(ALLOWED),
            "ciphers": list(CIPHERS),
            "orientations": list(ORIENTATIONS),
            "target_cells": 12,
            "node_limit_per_cell": NODE_LIMIT,
            "restart_semantics": "Every 3M target cell restarts at the root; prior 1M work is a repeated prefix and is never added to weights or nodes.",
        },
        "prior_gate": {
            "identity": IDENTITY,
            "controls_sha256": old_digest,
            "prototype_py_sha256": sha256_bytes((HEX_CFB / "prototype.py").read_bytes()),
            "run_encoded_py_sha256": sha256_bytes((ENCODED / "run_encoded.py").read_bytes()),
            "validated": True,
        },
        "initial_1m_prefix_consistency": {
            "identity": IDENTITY,
            "exact_raw_stats_match": True,
            "exact_survivor_count_match": True,
            "exact_plant_recovery_flag_match": True,
            "stats": stats_record(prefix_stats, PRIOR_LIMIT),
        },
        "full_unseeded_aes_base64_3m": {
            "identity": IDENTITY,
            "plaintext_length": len(plaintext),
            "plaintext_sha256": sha256_bytes(plaintext),
            "displayed_sha256": sha256_bytes(displayed.encode("ascii")),
            "all_16_display_symbols": set(displayed) == set(core.HEX),
            "planted_mapping": list(mapping),
            "plant_recovered": plant_recovered,
            "survivor_count_seen": len(extended_solutions),
            "validated_survivor_count": len(validated),
            "stats": stats_record(extended_stats, NODE_LIMIT),
        },
        "prior_seeded_fallback_support": {
            "identity": IDENTITY,
            "label": "prior 12-seeded/4-unknown control only; not an unseeded search",
            "plant_recovered": fallback["plant_recovered"],
            "certificate_complete": fallback["stats"]["certificate_complete"],
            "certificate_weight": fallback["stats"]["certificate_weight"],
        },
        "source_hashes": {
            "prototype_py_sha256": sha256_bytes((HEX_CFB / "prototype.py").read_bytes()),
            "prior_driver_sha256": sha256_bytes((ENCODED / "run_encoded.py").read_bytes()),
            "run_extend_py_sha256": sha256_bytes(Path(__file__).read_bytes()),
            "rev7_mdx_file_sha256": sha256_bytes(REV7_SOURCE.read_bytes()),
        },
        "runtime": {"python": sys.version, "pycryptodome": core.crypto_version},
    }


def require_controls() -> tuple[dict, str]:
    prior_data, prior_digest = prior_gate()
    path = HERE / "controls.json"
    if not path.exists():
        raise SystemExit(f"target blocked: missing extension controls: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["identity"] == IDENTITY and data["target_evaluated"] is False
    assert data["scope"] == {
        "endpoint": "base64",
        "allowed_bytes": sorted(ALLOWED),
        "allowed_byte_count": 69,
        "ciphers": list(CIPHERS),
        "orientations": list(ORIENTATIONS),
        "target_cells": 12,
        "node_limit_per_cell": NODE_LIMIT,
        "restart_semantics": "Every 3M target cell restarts at the root; prior 1M work is a repeated prefix and is never added to weights or nodes.",
    }
    assert data["prior_gate"]["controls_sha256"] == prior_digest
    assert data["prior_gate"]["validated"]
    assert data["initial_1m_prefix_consistency"]["exact_raw_stats_match"]
    assert data["initial_1m_prefix_consistency"]["exact_survivor_count_match"]
    assert data["initial_1m_prefix_consistency"]["exact_plant_recovery_flag_match"]
    three = data["full_unseeded_aes_base64_3m"]
    assert three["all_16_display_symbols"]
    if not three["plant_recovered"]:
        assert three["stats"]["search_status"] == "capped"
        support = data["prior_seeded_fallback_support"]
        assert support["plant_recovered"] and support["certificate_complete"]
        assert support["certificate_weight"] == math.factorial(4)
    assert data["source_hashes"] == {
        "prototype_py_sha256": sha256_bytes((HEX_CFB / "prototype.py").read_bytes()),
        "prior_driver_sha256": sha256_bytes((ENCODED / "run_encoded.py").read_bytes()),
        "run_extend_py_sha256": sha256_bytes(Path(__file__).read_bytes()),
        "rev7_mdx_file_sha256": sha256_bytes(REV7_SOURCE.read_bytes()),
    }
    return data, sha256_bytes(path.read_bytes())


def undo_orientation(value: str, name: str) -> str:
    if name == "forward":
        return value
    if name == "reverse":
        return value[::-1]
    if name == "byte_reverse":
        pairs = [value[i:i + 2] for i in range(0, len(value), 2)]
        return "".join(reversed(pairs))
    if name == "nibble_swap":
        return "".join(value[i:i + 2][::-1] for i in range(0, len(value), 2))
    raise ValueError(name)


def extract_rev7() -> str:
    text = REV7_SOURCE.read_text(encoding="utf-8")
    start = text.index("`83 B57B2") + 1
    end = text.index("`", start)
    value = "".join(text[start:end].split()).upper()
    assert len(value) == 1092 and sha256_bytes(value.encode("ascii")) == EXPECTED_REV7_SHA256
    oriented = core.orientations(value)
    assert tuple(oriented) == ORIENTATIONS
    assert all(undo_orientation(candidate, name) == value for name, candidate in oriented.items())
    return value


def run_target(output: Path, checkpoint: Path, resume: bool) -> None:
    if output.exists():
        raise SystemExit(f"refusing existing target output: {output}")
    _controls, controls_digest = require_controls()
    rev7 = extract_rev7()
    sources = {
        "prototype_py_sha256": sha256_bytes((HEX_CFB / "prototype.py").read_bytes()),
        "prior_driver_sha256": sha256_bytes((ENCODED / "run_encoded.py").read_bytes()),
        "run_extend_py_sha256": sha256_bytes(Path(__file__).read_bytes()),
    }
    configuration = {
        "identity": IDENTITY,
        "ciphertext_sha256": sha256_bytes(rev7.encode("ascii")),
        "endpoint": "base64",
        "allowed_bytes": sorted(ALLOWED),
        "allowed_byte_count": 69,
        "ciphers": list(CIPHERS),
        "orientations": list(ORIENTATIONS),
        "node_limit_per_cell": NODE_LIMIT,
        "restart_semantics": "Fresh root traversal to 3M; prior 1M prefix is repeated and not added.",
        "prior_controls_sha256": sha256_bytes((ENCODED / "controls.json").read_bytes()),
        "extension_controls_sha256": controls_digest,
        "source_hashes": sources,
    }
    if checkpoint.exists():
        if not resume:
            raise SystemExit(f"refusing existing checkpoint without --resume: {checkpoint}")
        result = json.loads(checkpoint.read_text(encoding="utf-8"))
        assert result["configuration"] == configuration
    else:
        if resume:
            raise SystemExit(f"--resume requested but checkpoint absent: {checkpoint}")
        result = {"identity": IDENTITY, "target_evaluated": True,
                  "configuration": configuration, "cells": []}
    completed = {(row["cipher"], row["orientation"]) for row in result["cells"]}
    oriented = core.orientations(rev7)
    for cipher_name in CIPHERS:
        ecb, _key, iv = core.ecb_oracle(cipher_name)
        for orientation in ORIENTATIONS:
            cell_key = (cipher_name, orientation)
            if cell_key in completed:
                continue
            displayed = oriented[orientation]
            solutions, stats = core.backtrack(
                displayed, ecb, iv, transition, node_limit=NODE_LIMIT)
            validated = [prior.validate_solution(displayed, cipher_name, ALLOWED, solution)
                         for solution in solutions]
            row = {
                "identity": IDENTITY,
                "endpoint": "base64",
                "cipher": cipher_name,
                "orientation": orientation,
                "displayed_sha256": sha256_bytes(displayed.encode("ascii")),
                "survivor_count": len(validated),
                "survivors": validated,
                "stats": stats_record(stats, NODE_LIMIT),
                "source_hashes": sources,
                "extension_controls_sha256": controls_digest,
            }
            result["cells"].append(row)
            atomic_json(checkpoint, result)
            print(json.dumps({"checkpointed_cell": cell_key,
                              "status": row["stats"]["search_status"],
                              "nodes": row["stats"]["nodes"],
                              "certificate_weight": row["stats"]["certificate_weight"],
                              "survivors": len(validated)}, sort_keys=True), flush=True)
    assert len(result["cells"]) == 12
    result["complete_cells"] = sum(row["stats"]["certificate_complete"] for row in result["cells"])
    result["capped_cells"] = 12 - result["complete_cells"]
    result["all_cells_present"] = True
    atomic_json(output, result)


def main() -> None:
    parser = argparse.ArgumentParser()
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--controls", action="store_true")
    actions.add_argument("--run-target", action="store_true")
    parser.add_argument("--controls-output", type=Path, default=HERE / "controls.json")
    parser.add_argument("--target-output", type=Path, default=HERE / "target_results.json")
    parser.add_argument("--checkpoint", type=Path, default=HERE / "target_checkpoint.json")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    if args.controls:
        if args.resume:
            parser.error("--resume is target-only")
        if args.controls_output.exists():
            raise SystemExit(f"refusing existing controls output: {args.controls_output}")
        result = control_gate()
        atomic_json(args.controls_output, result)
        print(json.dumps({"identity": IDENTITY, "target_evaluated": False,
                          "controls_sha256": sha256_bytes(args.controls_output.read_bytes()),
                          "source_hashes": result["source_hashes"]}, indent=2, sort_keys=True))
    else:
        run_target(args.target_output, args.checkpoint, args.resume)


if __name__ == "__main__":
    main()
