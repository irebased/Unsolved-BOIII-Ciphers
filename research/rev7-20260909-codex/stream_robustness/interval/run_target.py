#!/usr/bin/env python3
"""Frozen driver for the 96-cell contiguous-erasure robustness grid."""
import argparse
import bisect
import hashlib
import json
import os
import time
from pathlib import Path

from interval import shortest_feasible_intervals

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
ROBUST = HERE.parent
GATE_PATH = HERE / "target_gate.json"
OUTPUT_PATH = HERE / "target_results.json"
CHECKPOINT_PATH = HERE / "target_checkpoint.json"
ALLOWED = {9, 10, 13} | set(range(32, 127)) | {0xE2, 0x80, 0x93, 0x94, 0x98, 0x99, 0xA6}
ALL_CANDIDATES_MASK = (1 << 256) - 1
ID_KEYS = ("dataset", "cipher", "mode", "iv_kind", "orientation", "key_hex", "iv_hex")

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def atomic_json(path, value):
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, path)

def load_gate():
    gate = json.loads(GATE_PATH.read_text())
    assert gate["identity"] == "ASTRA"
    assert gate["target_evaluated"] is False
    assert gate["scope"]["cell_count"] == 96
    assert gate["scope"]["candidate_domain_size"] == 256
    assert gate["scope"]["allowed_output_byte_count"] == 105
    assert gate["scope"]["mapping"] == "arbitrary fixed noninjective displayed-pair-to-byte map"
    assert gate["scope"]["coordinates"] == "half-open intervals in each oriented decoded-byte sequence"
    assert gate["scope"]["single_contiguous_region"] is True
    assert gate["artifacts"]["run_target.py"] == sha(Path(__file__))
    for relative, expected in gate["artifacts"].items():
        if relative == "run_target.py":
            continue
        assert sha(REPO / relative) == expected, (relative, sha(REPO / relative), expected)
    return gate

def extract_orientations(mdx_path):
    text = mdx_path.read_text()
    start = text.index("`83 B57B2") + 1
    end = text.index("`", start)
    raw = "".join(text[start:end].split()).upper()
    assert len(raw) == 1092
    assert hashlib.sha256(raw.encode()).hexdigest() == (
        "5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
    )
    byte_pairs = [raw[i:i + 2] for i in range(0, len(raw), 2)]
    return {
        "forward": raw,
        "reverse": raw[::-1],
        "byte_reverse": "".join(reversed(byte_pairs)),
        "nibble_swap": "".join(pair[::-1] for pair in byte_pairs),
    }

def class_tables(pairs, keystream):
    occurrence_masks = {}
    for position, (symbol, key_byte) in enumerate(zip(pairs, keystream)):
        mask = 0
        for candidate in range(256):
            if (candidate ^ key_byte) in ALLOWED:
                mask |= 1 << candidate
        occurrence_masks.setdefault(symbol, []).append((position, mask))
    tables = {}
    for symbol, rows in occurrence_masks.items():
        positions = [position for position, _ in rows]
        prefix = [ALL_CANDIDATES_MASK]
        for _, mask in rows:
            prefix.append(prefix[-1] & mask)
        suffix = [ALL_CANDIDATES_MASK] * (len(rows) + 1)
        for index in range(len(rows) - 1, -1, -1):
            suffix[index] = suffix[index + 1] & rows[index][1]
        tables[symbol] = (positions, prefix, suffix)
    return tables

def interval_masks(tables, left, right):
    masks = {}
    for symbol, (positions, prefix, suffix) in tables.items():
        before = bisect.bisect_left(positions, left)
        after = bisect.bisect_left(positions, right)
        masks[symbol] = prefix[before] & suffix[after]
    return masks

def certificate(tables, n, shortest, expected_intervals):
    pair_count = len(tables)
    shorter = None
    if shortest > 0:
        length = shortest - 1
        starts = n - length + 1
        empty_mask_total = 0
        for left in range(starts):
            masks = interval_masks(tables, left, left + length)
            empty = sum(mask == 0 for mask in masks.values())
            assert empty > 0
            empty_mask_total += empty
        shorter = {
            "length": length,
            "intervals_checked": starts,
            "pair_masks_checked": starts * pair_count,
            "infeasible_intervals": starts,
            "total_empty_pair_masks": empty_mask_total,
        }
    starts = n - shortest + 1
    feasible = []
    empty_mask_total = 0
    for left in range(starts):
        masks = interval_masks(tables, left, left + shortest)
        empty = sum(mask == 0 for mask in masks.values())
        empty_mask_total += empty
        if empty == 0:
            feasible.append((left, left + shortest))
    assert feasible == list(expected_intervals)
    return {
        "method": "per-class occurrence masks with prefix/suffix 256-bit intersections and bisected interval endpoints",
        "pair_class_count": pair_count,
        "shorter_boundary": shorter,
        "minimum_boundary": {
            "length": shortest,
            "intervals_checked": starts,
            "pair_masks_checked": starts * pair_count,
            "feasible_intervals": len(feasible),
            "infeasible_intervals": starts - len(feasible),
            "total_empty_pair_masks": empty_mask_total,
        },
        "minimality_reason": (
            "If any shorter interval were feasible, it could be extended within the sequence "
            "to a feasible interval of length L-1; every length L-1 interval was checked."
            if shortest > 0 else
            "A feasible zero-length interval is minimal by definition."
        ),
    }

def validate_representative(pairs, keystream, interval, witness):
    left, right = interval
    mapping = dict(witness)
    assert set(mapping) == set(pairs)
    checks = 0
    for position, symbol in enumerate(pairs):
        if not (left <= position < right):
            assert (mapping[symbol] ^ keystream[position]) in ALLOWED
            checks += 1
    return {
        "interval": [left, right],
        "map": {str(symbol): candidate for symbol, candidate in witness},
        "outside_positions_checked": checks,
        "mapping_is_injective": len(set(mapping.values())) == len(mapping),
        "injectivity_required": False,
    }

def run():
    gate = load_gate()
    if OUTPUT_PATH.exists():
        raise SystemExit(f"refusing existing final output: {OUTPUT_PATH}")
    robustness_path = ROBUST / "robustness.json"
    summary_path = ROBUST / "robustness_summary.json"
    ledger = json.loads(robustness_path.read_text())
    compact = json.loads(summary_path.read_text())
    assert ledger["identity"] == compact["identity"] == "ASTRA"
    assert ledger["cell_count"] == compact["cell_count"] == 96
    assert compact["ledger_sha256"] == sha(robustness_path)
    assert ledger["allowed_output_bytes"]["total"] == len(ALLOWED) == 105
    assert ledger["source_hashes"] == compact["source_hashes"]
    assert ledger["source_hashes"] == gate["frozen_source_hashes"]
    assert compact["zero_stream_context_count"] == 4
    assert compact["zero_stream_arbitrary_fixed_map_invalid"] == 0
    assert compact["contexts"] == [
        {key: cell[key] for key in (
            "dataset", "cipher", "mode", "iv_kind", "orientation", "key_hex", "iv_hex",
            "displayed_sha256", "arbitrary_fixed_map_invalid_lower_bound", "pair_count",
            "min_pair_invalid", "max_pair_invalid", "keystream_sha256"
        )}
        for cell in ledger["cells"]
    ]

    orientations = extract_orientations(
        REPO / "lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
    )
    configuration = {
        "identity": "ASTRA",
        "cell_count": 96,
        "allowed_output_bytes": ledger["allowed_output_bytes"],
        "candidate_domain_size": 256,
        "mapping": "arbitrary fixed noninjective displayed-pair-to-byte map",
        "interval_coordinates": "half-open [start,end) in each oriented decoded-byte sequence",
        "single_contiguous_region": True,
        "source_hashes": gate["artifacts"],
        "frozen_source_hashes": gate["frozen_source_hashes"],
        "gate_sha256": sha(GATE_PATH),
        "driver_sha256": sha(Path(__file__)),
    }
    configuration_sha = hashlib.sha256(
        json.dumps(configuration, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    completed = []
    if CHECKPOINT_PATH.exists():
        checkpoint = json.loads(CHECKPOINT_PATH.read_text())
        assert checkpoint["identity"] == "ASTRA"
        assert checkpoint["configuration_sha256"] == configuration_sha
        completed = checkpoint["cells"]
    expected_ids = [tuple(cell[key] for key in ID_KEYS) for cell in ledger["cells"]]
    assert len(expected_ids) == len(set(expected_ids)) == 96
    assert [tuple(cell[key] for key in ID_KEYS) for cell in completed] == expected_ids[:len(completed)]

    for source_cell in ledger["cells"][len(completed):]:
        started = time.perf_counter()
        display = orientations[source_cell["orientation"]]
        pairs = [display[i:i + 2] for i in range(0, len(display), 2)]
        assert len(pairs) == 546
        assert hashlib.sha256(display.encode()).hexdigest() == source_cell["displayed_sha256"]
        expected_positions = {}
        for position, symbol in enumerate(pairs):
            expected_positions.setdefault(symbol, []).append(position)
        assert [
            (row["display_pair"], row["positions"])
            for row in source_cell["pair_metrics"]
        ] == sorted(expected_positions.items())
        keystream = bytes.fromhex(source_cell["keystream_hex"])
        assert len(keystream) == 546
        assert hashlib.sha256(keystream).hexdigest() == source_cell["keystream_sha256"]
        zero_stream = keystream == bytes(546)
        assert zero_stream == (source_cell["arbitrary_fixed_map_invalid_lower_bound"] == 0)

        result = shortest_feasible_intervals(pairs, keystream, ALLOWED)
        tables = class_tables(pairs, keystream)
        cert = certificate(tables, len(pairs), result.length, result.intervals)
        representative = validate_representative(
            pairs, keystream, result.intervals[0], result.witnesses[0]
        )
        cell = {
            **{key: source_cell[key] for key in ID_KEYS},
            "identity": "ASTRA",
            "displayed_sha256": source_cell["displayed_sha256"],
            "keystream_sha256": source_cell["keystream_sha256"],
            "sequence_length": len(pairs),
            "pair_class_count": len(tables),
            "source_arbitrary_fixed_map_invalid_lower_bound": source_cell["arbitrary_fixed_map_invalid_lower_bound"],
            "zero_stream_arbitrary_map_context": zero_stream,
            "shortest_contiguous_span_bytes": result.length,
            "minimizing_interval_count": len(result.intervals),
            "minimizing_intervals": [list(interval) for interval in result.intervals],
            "representative_arbitrary_map": representative,
            "certificate": cert,
            "elapsed_seconds": time.perf_counter() - started,
            "interpretation": (
                "minimum necessary span for one contiguous ignored/corrupt region under this "
                "fixed-map stream/alphabet context; not a count of altered bytes"
            ),
        }
        completed.append(cell)
        atomic_json(CHECKPOINT_PATH, {
            "identity": "ASTRA",
            "target_evaluated": True,
            "configuration_sha256": configuration_sha,
            "cells": completed,
        })
        print(json.dumps({
            "completed": len(completed),
            "cell": list(expected_ids[len(completed) - 1]),
            "shortest_span": result.length,
            "minimizing_intervals": len(result.intervals),
        }), flush=True)

    spans = [cell["shortest_contiguous_span_bytes"] for cell in completed]
    assert sum(cell["zero_stream_arbitrary_map_context"] for cell in completed) == 4
    assert sum(cell["shortest_contiguous_span_bytes"] == 0 for cell in completed) == 4
    output = {
        "identity": "ASTRA",
        "target_evaluated": True,
        "status": "complete",
        "configuration": configuration,
        "cells": completed,
        "summary": {
            "cell_count": len(completed),
            "minimum_span_range": [min(spans), max(spans)],
            "zero_span_cells": sum(span == 0 for span in spans),
            "all_cells_independently_certified": True,
            "all_source_stream_hashes_matched": True,
        },
        "scope_limit": (
            "Bounds one contiguous region in oriented decoded-byte coordinates under arbitrary "
            "noninjective fixed maps; does not count altered bytes or cover injectivity, multiple "
            "regions, insertion/deletion, alternate streams, keys, IVs, or CFB."
        ),
    }
    atomic_json(OUTPUT_PATH, output)
    CHECKPOINT_PATH.unlink()
    print(json.dumps({
        "identity": "ASTRA",
        "output": str(OUTPUT_PATH),
        "sha256": sha(OUTPUT_PATH),
        "summary": output["summary"],
    }, indent=2))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-target", action="store_true")
    args = parser.parse_args()
    gate = load_gate()
    if not args.run_target:
        print(json.dumps({
            "identity": "ASTRA",
            "target_evaluated": False,
            "gate_sha256": sha(GATE_PATH),
            "driver_sha256": sha(Path(__file__)),
            "artifact_hashes_verified": len(gate["artifacts"]),
            "note": "self-test hashes target-bearing artifacts but does not parse or evaluate them",
        }, indent=2))
        return
    run()

if __name__ == "__main__":
    main()
