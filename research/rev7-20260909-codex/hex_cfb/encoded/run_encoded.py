#!/usr/bin/env python3
"""Exact global-hex-permutation + CFB8 scans for five encoded endpoints.

The default action is synthetic controls. Rev 7 is read only with the explicit
--run-target flag. Target cells are checkpointed atomically and never overwrite
an existing final result.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
import os
import random
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Iterable, Sequence

HERE = Path(__file__).resolve().parent
HEX_CFB = HERE.parent
RESEARCH = HEX_CFB.parent
REPO = HERE.parents[3]
sys.path.insert(0, str(HEX_CFB))
import prototype as core  # noqa: E402

IDENTITY = "ASTRA"
NODE_LIMIT = 1_000_000
FULL_WEIGHT = math.factorial(16)
CONTROL_BYTES = {9, 10, 13, 32}
ENDPOINTS = {
    "bacon_ab": CONTROL_BYTES | set(b"AB"),
    "octal": CONTROL_BYTES | set(b"01234567"),
    "decimal": CONTROL_BYTES | set(b"0123456789"),
    "uppercase_hex": CONTROL_BYTES | set(b"0123456789ABCDEF"),
    "base64": CONTROL_BYTES | set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="),
}
CIPHERS = tuple(core.cipher_specs())
ORIENTATIONS = ("forward", "reverse", "byte_reverse", "nibble_swap")
REV7_SOURCE = REPO / "lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
EXPECTED_REV7_SHA256 = "5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def atomic_json(path: Path, value: dict) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def transition_for(allowed: set[int]):
    def transition(state: int, _position: int, value: int):
        assert state == 0
        return 0 if value in allowed else None
    return transition


def decode_display(displayed: str, mapping: Sequence[int]) -> bytes:
    assert len(mapping) == 16 and sorted(mapping) == list(range(16))
    return bytes((mapping[core.HEX.index(displayed[i])] << 4) |
                 mapping[core.HEX.index(displayed[i + 1])]
                 for i in range(0, len(displayed), 2))


def validate_solution(displayed: str, cipher_name: str, allowed: set[int], solution: dict) -> dict:
    mapping = tuple(solution["mapping"])
    plaintext = solution["plaintext"]
    ciphertext = decode_display(displayed, mapping)
    library_plaintext = core.library_cfb8(ciphertext, cipher_name, decrypt=True)
    ecb, _key, iv = core.ecb_oracle(cipher_name)
    assert plaintext == library_plaintext
    assert core.manual_cfb8(ciphertext, ecb, iv, decrypt=True) == plaintext
    assert core.library_cfb8(plaintext, cipher_name, decrypt=False) == ciphertext
    assert core.display_encode(ciphertext, mapping) == displayed
    assert all(value in allowed for value in plaintext)
    return {
        "mapping_display_to_nibble": list(mapping),
        "plaintext_hex": plaintext.hex(),
        "plaintext_sha256": sha256_bytes(plaintext),
        "ciphertext_sha256": sha256_bytes(ciphertext),
        "library_cfb8_validated": True,
        "manual_cfb8_validated": True,
        "exact_display_reconstruction": True,
    }


def deterministic_fixture(endpoint: str, cipher_name: str = "aes128"):
    seed = int.from_bytes(hashlib.sha256(("ASTRA-ENCODED-" + endpoint).encode()).digest()[:8], "big")
    rng = random.Random(seed)
    alphabet = sorted(ENDPOINTS[endpoint])
    plaintext = bytes(rng.choice(alphabet) for _ in range(546))
    mapping = list(range(16))
    rng.shuffle(mapping)
    ciphertext = core.library_cfb8(plaintext, cipher_name, decrypt=False)
    displayed = core.display_encode(ciphertext, mapping)
    assert len(displayed) == 1092 and set(displayed) == set(core.HEX)
    return plaintext, tuple(mapping), ciphertext, displayed


def solution_dict(solutions: Iterable[dict]):
    return {tuple(solution["mapping"]): solution["plaintext"] for solution in solutions}


def naive_seeded(displayed: str, cipher_name: str, allowed: set[int], seed_mapping: dict[int, int]):
    unknown_symbols = sorted(set(range(16)) - set(seed_mapping))
    unused_values = sorted(set(range(16)) - set(seed_mapping.values()))
    assert len(unknown_symbols) == len(unused_values) == 4
    survivors = {}
    rejected = 0
    for values in itertools.permutations(unused_values):
        mapping = [-1] * 16
        for symbol, value in seed_mapping.items():
            mapping[symbol] = value
        for symbol, value in zip(unknown_symbols, values):
            mapping[symbol] = value
        ciphertext = decode_display(displayed, mapping)
        plaintext = core.library_cfb8(ciphertext, cipher_name, decrypt=True)
        if all(value in allowed for value in plaintext):
            survivors[tuple(mapping)] = plaintext
        else:
            rejected += 1
    assert rejected + len(survivors) == math.factorial(4)
    return survivors, rejected


def stats_record(stats, seeded_count: int) -> dict:
    value = asdict(stats)
    certificate = stats.rejected_completion_weight + stats.terminal_completion_weight
    expected = math.factorial(16 - seeded_count)
    complete = not stats.aborted_at_node_limit
    if complete:
        assert certificate == expected
    else:
        assert certificate < expected
    value.update({
        "node_limit": NODE_LIMIT,
        "node_definition": "DFS entries; one ECB call for each nonterminal accepted-prefix entry",
        "certificate_weight": certificate,
        "expected_factorial_weight": expected,
        "search_status": "complete" if complete else "capped",
        "certificate_complete": complete and certificate == expected,
    })
    return value


def control_gate() -> dict:
    full_gates = {}
    seeded_fallbacks = {}
    naive_checks = {}
    for endpoint, allowed in ENDPOINTS.items():
        plaintext, planted_mapping, _ciphertext, displayed = deterministic_fixture(endpoint, "aes128")
        ecb, _key, iv = core.ecb_oracle("aes128")
        solutions, stats = core.backtrack(
            displayed, ecb, iv, transition_for(allowed), node_limit=NODE_LIMIT)
        survivors = solution_dict(solutions)
        plant_recovered = survivors.get(planted_mapping) == plaintext
        full_gates[endpoint] = {
            "identity": IDENTITY,
            "cipher": "aes128",
            "plaintext_length": len(plaintext),
            "plaintext_sha256": sha256_bytes(plaintext),
            "displayed_sha256": sha256_bytes(displayed.encode("ascii")),
            "all_16_display_symbols": set(displayed) == set(core.HEX),
            "planted_mapping": list(planted_mapping),
            "plant_recovered": plant_recovered,
            "survivor_count_seen": len(survivors),
            "stats": stats_record(stats, 0),
        }
        if endpoint != "base64":
            assert plant_recovered
        if not plant_recovered:
            assert endpoint == "base64" and stats.aborted_at_node_limit
            unknown = set(range(12, 16))
            seed = {symbol: value for symbol, value in enumerate(planted_mapping) if symbol not in unknown}
            fallback_solutions, fallback_stats = core.backtrack(
                displayed, ecb, iv, transition_for(allowed), node_limit=NODE_LIMIT,
                seed_mapping=seed)
            fallback = solution_dict(fallback_solutions)
            assert fallback.get(planted_mapping) == plaintext
            seeded_fallbacks[endpoint] = {
                "identity": IDENTITY,
                "label": "seeded 12-symbol control gate; not an unseeded search",
                "seeded_mapping_entries": 12,
                "unknown_mapping_entries": 4,
                "plant_recovered": True,
                "survivor_count": len(fallback),
                "stats": stats_record(fallback_stats, 12),
            }

        naive_checks[endpoint] = {}
        for cipher_name in CIPHERS:
            plaintext_c, mapping_c, _ciphertext_c, displayed_c = deterministic_fixture(endpoint, cipher_name)
            unknown = set(range(12, 16))
            seed = {symbol: value for symbol, value in enumerate(mapping_c) if symbol not in unknown}
            ecb_c, _key_c, iv_c = core.ecb_oracle(cipher_name)
            fast_solutions, fast_stats = core.backtrack(
                displayed_c, ecb_c, iv_c, transition_for(allowed),
                node_limit=NODE_LIMIT, seed_mapping=seed)
            fast = solution_dict(fast_solutions)
            naive, naive_rejected = naive_seeded(displayed_c, cipher_name, allowed, seed)
            assert fast == naive
            assert fast.get(mapping_c) == plaintext_c
            assert not fast_stats.aborted_at_node_limit
            assert fast_stats.rejected_completion_weight == naive_rejected
            assert fast_stats.terminal_completion_weight == len(naive)
            naive_checks[endpoint][cipher_name] = {
                "identity": IDENTITY,
                "unknown_mapping_entries": 4,
                "all_24_mappings_checked": True,
                "mapping_plaintext_sets_equal": True,
                "survivor_count": len(fast),
                "naive_rejected_mappings": naive_rejected,
                "backtrack_rejected_weight": fast_stats.rejected_completion_weight,
                "backtrack_terminal_weight": fast_stats.terminal_completion_weight,
                "stats": stats_record(fast_stats, 12),
            }

    return {
        "identity": IDENTITY,
        "target_evaluated": False,
        "node_limit": NODE_LIMIT,
        "endpoints": {name: sorted(values) for name, values in ENDPOINTS.items()},
        "nesting_note": "Each endpoint is searched and certified separately; no negative result is inferred from a superset endpoint.",
        "ciphers": list(CIPHERS),
        "orientations": list(ORIENTATIONS),
        "full_unseeded_aes_gates": full_gates,
        "explicit_seeded_fallbacks": seeded_fallbacks,
        "naive_four_unknown_checks": naive_checks,
        "runtime": {
            "python": sys.version,
            "pycryptodome": core.crypto_version,
        },
        "source_hashes": {
            "prototype_py_sha256": sha256_bytes((HEX_CFB / "prototype.py").read_bytes()),
            "run_encoded_py_sha256": sha256_bytes(Path(__file__).read_bytes()),
        },
    }


def require_frozen_controls() -> tuple[dict, str]:
    path = HERE / "controls.json"
    if not path.exists():
        raise SystemExit(f"target blocked: required frozen controls absent: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    current_sources = {
        "prototype_py_sha256": sha256_bytes((HEX_CFB / "prototype.py").read_bytes()),
        "run_encoded_py_sha256": sha256_bytes(Path(__file__).read_bytes()),
    }
    assert data["identity"] == IDENTITY
    assert data["target_evaluated"] is False
    assert data["node_limit"] == NODE_LIMIT
    assert data["endpoints"] == {name: sorted(values) for name, values in ENDPOINTS.items()}
    assert data["ciphers"] == list(CIPHERS)
    assert data["orientations"] == list(ORIENTATIONS)
    assert data["source_hashes"] == current_sources

    full = data["full_unseeded_aes_gates"]
    assert set(full) == set(ENDPOINTS)
    for endpoint in ("bacon_ab", "octal", "decimal", "uppercase_hex"):
        row = full[endpoint]
        assert row["plant_recovered"]
        assert row["all_16_display_symbols"]
        assert row["stats"]["certificate_complete"]
        assert row["stats"]["certificate_weight"] == FULL_WEIGHT
    base64_full = full["base64"]
    base64_full_ok = (base64_full["plant_recovered"] and
                      base64_full["stats"]["certificate_complete"] and
                      base64_full["stats"]["certificate_weight"] == FULL_WEIGHT)
    if not base64_full_ok:
        fallback = data["explicit_seeded_fallbacks"].get("base64")
        assert fallback is not None
        assert fallback["seeded_mapping_entries"] == 12
        assert fallback["unknown_mapping_entries"] == 4
        assert fallback["plant_recovered"]
        assert fallback["stats"]["certificate_complete"]
        assert fallback["stats"]["certificate_weight"] == math.factorial(4)

    naive = data["naive_four_unknown_checks"]
    assert set(naive) == set(ENDPOINTS)
    checked = 0
    for endpoint in ENDPOINTS:
        assert set(naive[endpoint]) == set(CIPHERS)
        for cipher_name in CIPHERS:
            row = naive[endpoint][cipher_name]
            assert row["unknown_mapping_entries"] == 4
            assert row["all_24_mappings_checked"]
            assert row["mapping_plaintext_sets_equal"]
            assert row["stats"]["certificate_complete"]
            assert row["stats"]["certificate_weight"] == math.factorial(4)
            assert row["backtrack_rejected_weight"] + row["backtrack_terminal_weight"] == math.factorial(4)
            checked += 1
    assert checked == 15
    return data, sha256_bytes(path.read_bytes())


def extract_rev7() -> str:
    text = REV7_SOURCE.read_text(encoding="utf-8")
    start = text.index("`83 B57B2") + 1
    end = text.index("`", start)
    value = "".join(text[start:end].split()).upper()
    assert len(value) == 1092 and sha256_bytes(value.encode("ascii")) == EXPECTED_REV7_SHA256
    return value


def run_target(output: Path, checkpoint: Path, resume: bool) -> None:
    if output.exists():
        raise SystemExit(f"refusing existing target output: {output}")
    _controls, controls_sha256 = require_frozen_controls()
    source_hashes = {
        "prototype_py_sha256": sha256_bytes((HEX_CFB / "prototype.py").read_bytes()),
        "run_encoded_py_sha256": sha256_bytes(Path(__file__).read_bytes()),
    }
    rev7 = extract_rev7()
    configuration = {
        "identity": IDENTITY,
        "ciphertext_sha256": sha256_bytes(rev7.encode("ascii")),
        "node_limit_per_cell": NODE_LIMIT,
        "endpoints": {name: sorted(values) for name, values in ENDPOINTS.items()},
        "ciphers": list(CIPHERS),
        "orientations": list(ORIENTATIONS),
        "source_hashes": source_hashes,
        "controls_sha256": controls_sha256,
        "control_gate_required": True,
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
    completed_keys = {(row["endpoint"], row["cipher"], row["orientation"])
                      for row in result["cells"]}
    oriented = core.orientations(rev7)
    for endpoint, allowed in ENDPOINTS.items():
        for cipher_name in CIPHERS:
            ecb, _key, iv = core.ecb_oracle(cipher_name)
            for orientation in ORIENTATIONS:
                cell_key = (endpoint, cipher_name, orientation)
                if cell_key in completed_keys:
                    continue
                displayed = oriented[orientation]
                solutions, stats = core.backtrack(
                    displayed, ecb, iv, transition_for(allowed), node_limit=NODE_LIMIT)
                validated = [validate_solution(displayed, cipher_name, allowed, solution)
                             for solution in solutions]
                row = {
                    "identity": IDENTITY,
                    "endpoint": endpoint,
                    "detector": "exact stateless membership in the named byte alphabet",
                    "allowed_bytes": sorted(allowed),
                    "node_limit": NODE_LIMIT,
                    "source_hashes": source_hashes,
                    "cipher": cipher_name,
                    "orientation": orientation,
                    "displayed_sha256": sha256_bytes(displayed.encode("ascii")),
                    "survivor_count": len(validated),
                    "survivors": validated,
                    "stats": stats_record(stats, 0),
                }
                result["cells"].append(row)
                atomic_json(checkpoint, result)
                print(json.dumps({"checkpointed_cell": cell_key,
                                  "status": row["stats"]["search_status"],
                                  "nodes": row["stats"]["nodes"],
                                  "certificate_weight": row["stats"]["certificate_weight"],
                                  "survivors": len(validated)}, sort_keys=True), flush=True)
    assert len(result["cells"]) == len(ENDPOINTS) * len(CIPHERS) * len(ORIENTATIONS)
    result["all_cells_present"] = True
    result["complete_cells"] = sum(row["stats"]["certificate_complete"] for row in result["cells"])
    result["capped_cells"] = len(result["cells"]) - result["complete_cells"]
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
            raise SystemExit(f"refusing existing control output: {args.controls_output}")
        result = control_gate()
        atomic_json(args.controls_output, result)
        print(json.dumps({
            "identity": IDENTITY,
            "target_evaluated": False,
            "controls_output": str(args.controls_output),
            "controls_sha256": sha256_bytes(args.controls_output.read_bytes()),
            "source_hashes": result["source_hashes"],
        }, indent=2, sort_keys=True))
    else:
        run_target(args.target_output, args.checkpoint, args.resume)


if __name__ == "__main__":
    main()
