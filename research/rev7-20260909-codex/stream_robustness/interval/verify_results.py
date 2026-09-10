#!/usr/bin/env python3
"""Read-only certificate replay for the frozen interval target result.

This replays the prefix/suffix candidate-mask certificate used by the target
driver. It is an independent read-only result verifier, not a third search
algorithm and not a cryptographic stream reconstruction.
"""
import bisect
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
ROBUST = HERE.parent
RESULT = HERE / "target_results.json"
GATE = HERE / "target_gate.json"
N = 546
ALLOWED = {9, 10, 13} | set(range(32, 127)) | {0xE2, 0x80, 0x93, 0x94, 0x98, 0x99, 0xA6}
ALL_MASK = (1 << 256) - 1
ID_KEYS = ("dataset", "cipher", "mode", "iv_kind", "orientation", "key_hex", "iv_hex")
EXPECTED_RESULT = "6a891c17eee5274ea48ec78a1fcc158178cf4043621ba8bc17a50afd167cbe00"
EXPECTED_GATE = "285e8f20e641fd3153220611550e188e780348abf224c126f8825330afee5177"
EXPECTED_RAW = "5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
EXPECTED_ARTIFACTS = {
    "run_target.py": "42b1429579dd6b8647f956981a6a5a0031eca6999900860d3b0d991f2b54b6bb",
    "research/rev7-20260909-codex/stream_robustness/interval/interval.py": "03fd7e3fb18c94e721e6e648f84fa315d8e491b306d53b2dffef6a8245061919",
    "research/rev7-20260909-codex/stream_robustness/interval/controls.py": "9489457179cc7cf447f6f798221fd65b525e672ababd3f64e248b83ae5b93628",
    "research/rev7-20260909-codex/stream_robustness/interval/controls.json": "98a6fc705f39b68c3322aa9b82b5a227ca12684165c54b136a31f1df6a56d5fd",
    "research/rev7-20260909-codex/stream_robustness/interval/README.md": "fe1ae69bcd38e9b6ca612690a4b4dc9a1f8c216d39ed4e6e06ff5d4853593fab",
    "research/rev7-20260909-codex/stream_robustness/robustness.json": "22e4297ab94da5ebd530e5b7ec0be2299678edf8ac2ea2c1b1b82bfc4e0b2c3a",
    "research/rev7-20260909-codex/stream_robustness/robustness_summary.json": "7c10d4d79049f640180a9c759e3eae1bd2fc17437654dbbd6ff93088852fe2c6",
    "research/rev7-20260909-codex/stream_robustness/robustness.py": "09b0ae3d288c1aa390a2ca817a0511abf419cf3bd2208b03911cb0598b8ff0d5",
    "research/rev7-20260909-codex/stream_robustness/verifier.py": "5f9ca599b3a35cab0f5d5c37d37f3fa88f57c602cd32a4c7050101c1981c9e83",
    "research/rev7-20260909-codex/stream_csp/target_results.json": "f1d9024065f82e75479c4e03f1c871f9c2e0c661e63c6a42cb6da6594addde87",
    "research/rev7-20260909-codex/stream_csp/witness_verification.json": "07e61bdfbc777e43a36902720ef70b295a117953707653dc97060df372bf2c1c",
    "research/rev7-20260909-codex/stream_csp_compat/target_results.json": "598dfa8ec497321f62f1b4f445de4f642f755ef0fb51c9d2164c708145aad7f2",
    "research/rev7-20260909-codex/stream_csp_compat/verification.json": "1937e53cdbb0487e8ff95326f3a1a131d7402eb3374d0556030f2508ef2d35d6",
    "research/rev7-20260909-codex/hex_cfb/prototype.py": "416e25dea93945f3634a77a41ebebb22906a58e97fdcbbbb7f44d27f7f2a511b",
    "research/rev7-20260909-codex/stream_csp_compat/compat_stream.py": "f0f5eab61e2940aada5ee92828d2fc8474b99e4d68ec10b63053190d0bddd38c",
    "lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx": "085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91",
}
EXPECTED_SOURCE_HASHES = {
    "stream_target": "f1d9024065f82e75479c4e03f1c871f9c2e0c661e63c6a42cb6da6594addde87",
    "stream_ledger": "07e61bdfbc777e43a36902720ef70b295a117953707653dc97060df372bf2c1c",
    "compat_target": "598dfa8ec497321f62f1b4f445de4f642f755ef0fb51c9d2164c708145aad7f2",
    "compat_ledger": "1937e53cdbb0487e8ff95326f3a1a131d7402eb3374d0556030f2508ef2d35d6",
    "rev7_mdx": "085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91",
    "canonical_text_sha256": EXPECTED_RAW,
    "prototype.py": "416e25dea93945f3634a77a41ebebb22906a58e97fdcbbbb7f44d27f7f2a511b",
    "compat_stream.py": "f0f5eab61e2940aada5ee92828d2fc8474b99e4d68ec10b63053190d0bddd38c",
}

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def orientations():
    mdx = REPO / "lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
    text = mdx.read_text()
    start = text.index("`83 B57B2") + 1
    end = text.index("`", start)
    raw = "".join(text[start:end].split()).upper()
    assert len(raw) == 2 * N
    assert hashlib.sha256(raw.encode()).hexdigest() == EXPECTED_RAW
    byte_pairs = [raw[i:i + 2] for i in range(0, len(raw), 2)]
    return {
        "forward": raw,
        "reverse": raw[::-1],
        "byte_reverse": "".join(reversed(byte_pairs)),
        "nibble_swap": "".join(pair[::-1] for pair in byte_pairs),
    }

def build_tables(pairs, keystream):
    rows = {}
    for position, (symbol, key_byte) in enumerate(zip(pairs, keystream)):
        mask = 0
        for candidate in range(256):
            if (candidate ^ key_byte) in ALLOWED:
                mask |= 1 << candidate
        rows.setdefault(symbol, []).append((position, mask))
    tables = {}
    for symbol, occurrences in rows.items():
        positions = [position for position, _ in occurrences]
        prefix = [ALL_MASK]
        for _, mask in occurrences:
            prefix.append(prefix[-1] & mask)
        suffix = [ALL_MASK] * (len(occurrences) + 1)
        for index in range(len(occurrences) - 1, -1, -1):
            suffix[index] = suffix[index + 1] & occurrences[index][1]
        tables[symbol] = (positions, prefix, suffix)
    return tables

def masks_outside(tables, left, right):
    answer = {}
    for symbol, (positions, prefix, suffix) in tables.items():
        before = bisect.bisect_left(positions, left)
        after = bisect.bisect_left(positions, right)
        answer[symbol] = prefix[before] & suffix[after]
    return answer

def replay_length(tables, length):
    feasible = []
    empty_total = 0
    count = N - length + 1
    for left in range(count):
        masks = masks_outside(tables, left, left + length)
        empty = sum(mask == 0 for mask in masks.values())
        empty_total += empty
        if empty == 0:
            feasible.append([left, left + length])
    return {
        "length": length,
        "intervals_checked": count,
        "pair_masks_checked": count * len(tables),
        "feasible_intervals": feasible,
        "infeasible_intervals": count - len(feasible),
        "total_empty_pair_masks": empty_total,
    }

assert sha(RESULT) == EXPECTED_RESULT
assert sha(GATE) == EXPECTED_GATE
gate = json.loads(GATE.read_text())
assert gate["identity"] == "ASTRA" and gate["target_evaluated"] is False
assert gate["artifacts"] == EXPECTED_ARTIFACTS
assert gate["frozen_source_hashes"] == EXPECTED_SOURCE_HASHES
for relative, expected in EXPECTED_ARTIFACTS.items():
    path = HERE / relative if relative == "run_target.py" else REPO / relative
    assert sha(path) == expected, (relative, sha(path), expected)

target = json.loads(RESULT.read_text())
robustness_path = ROBUST / "robustness.json"
compact_path = ROBUST / "robustness_summary.json"
robustness = json.loads(robustness_path.read_text())
compact = json.loads(compact_path.read_text())
assert target["identity"] == robustness["identity"] == compact["identity"] == "ASTRA"
assert target["target_evaluated"] is True and target["status"] == "complete"
assert target["configuration"]["gate_sha256"] == EXPECTED_GATE
assert target["configuration"]["driver_sha256"] == EXPECTED_ARTIFACTS["run_target.py"]
assert target["configuration"]["source_hashes"] == EXPECTED_ARTIFACTS
assert target["configuration"]["frozen_source_hashes"] == EXPECTED_SOURCE_HASHES
assert robustness["source_hashes"] == compact["source_hashes"] == EXPECTED_SOURCE_HASHES
assert compact["ledger_sha256"] == sha(robustness_path)
assert len(target["cells"]) == len(robustness["cells"]) == 96
assert [tuple(cell[key] for key in ID_KEYS) for cell in target["cells"]] == [
    tuple(cell[key] for key in ID_KEYS) for cell in robustness["cells"]
]
assert len({tuple(cell[key] for key in ID_KEYS) for cell in target["cells"]}) == 96

displays = orientations()
aggregate = {
    "l_minus_1_intervals": 0,
    "l_intervals": 0,
    "l_minus_1_pair_masks": 0,
    "l_pair_masks": 0,
}
for cell, source in zip(target["cells"], robustness["cells"]):
    display = displays[cell["orientation"]]
    assert hashlib.sha256(display.encode()).hexdigest() == cell["displayed_sha256"] == source["displayed_sha256"]
    pairs = [display[i:i + 2] for i in range(0, len(display), 2)]
    keystream = bytes.fromhex(source["keystream_hex"])
    assert len(keystream) == N
    assert hashlib.sha256(keystream).hexdigest() == cell["keystream_sha256"] == source["keystream_sha256"]
    tables = build_tables(pairs, keystream)
    assert cell["pair_class_count"] == len(tables) == source["pair_count"] == 226
    length = cell["shortest_contiguous_span_bytes"]
    intervals = cell["minimizing_intervals"]
    assert len(intervals) == cell["minimizing_interval_count"]
    assert all(0 <= left <= right <= N and right - left == length for left, right in intervals)

    minimum = replay_length(tables, length)
    stored_minimum = cell["certificate"]["minimum_boundary"]
    assert minimum["feasible_intervals"] == intervals
    for key in ("length", "intervals_checked", "pair_masks_checked", "infeasible_intervals", "total_empty_pair_masks"):
        assert minimum[key] == stored_minimum[key]
    assert len(minimum["feasible_intervals"]) == stored_minimum["feasible_intervals"]
    aggregate["l_intervals"] += minimum["intervals_checked"]
    aggregate["l_pair_masks"] += minimum["pair_masks_checked"]

    if length == 0:
        assert cell["certificate"]["shorter_boundary"] is None
    else:
        shorter = replay_length(tables, length - 1)
        assert not shorter["feasible_intervals"]
        stored_shorter = cell["certificate"]["shorter_boundary"]
        for key in ("length", "intervals_checked", "pair_masks_checked", "infeasible_intervals", "total_empty_pair_masks"):
            assert shorter[key] == stored_shorter[key]
        aggregate["l_minus_1_intervals"] += shorter["intervals_checked"]
        aggregate["l_minus_1_pair_masks"] += shorter["pair_masks_checked"]

    representative = cell["representative_arbitrary_map"]
    assert representative["interval"] == intervals[0]
    mapping = representative["map"]
    assert set(mapping) == set(pairs)
    assert representative["injectivity_required"] is False
    assert representative["mapping_is_injective"] == (len(set(mapping.values())) == len(mapping))
    left, right = representative["interval"]
    outside_checks = 0
    for position, symbol in enumerate(pairs):
        if not (left <= position < right):
            assert (mapping[symbol] ^ keystream[position]) in ALLOWED
            outside_checks += 1
    assert outside_checks == representative["outside_positions_checked"] == N - length
    zero_stream = keystream == bytes(N)
    assert cell["zero_stream_arbitrary_map_context"] == zero_stream
    assert cell["source_arbitrary_fixed_map_invalid_lower_bound"] == source["arbitrary_fixed_map_invalid_lower_bound"]

nonzero = [cell for cell in target["cells"] if not cell["zero_stream_arbitrary_map_context"]]
zero = [cell for cell in target["cells"] if cell["zero_stream_arbitrary_map_context"]]
nonzero_range = [
    min(cell["shortest_contiguous_span_bytes"] for cell in nonzero),
    max(cell["shortest_contiguous_span_bytes"] for cell in nonzero),
]
assert len(nonzero) == 92 and nonzero_range == [163, 292]
assert all(cell["minimizing_interval_count"] == 1 for cell in nonzero)
assert len(zero) == 4
assert all(cell["shortest_contiguous_span_bytes"] == 0 for cell in zero)
assert all(cell["minimizing_interval_count"] == N + 1 for cell in zero)
assert target["summary"] == {
    "cell_count": 96,
    "minimum_span_range": [0, 292],
    "zero_span_cells": 4,
    "all_cells_independently_certified": True,
    "all_source_stream_hashes_matched": True,
}
assert aggregate == {
    "l_minus_1_intervals": 27832,
    "l_intervals": 29928,
    "l_minus_1_pair_masks": 6290032,
    "l_pair_masks": 6763728,
}

max_decoded_positions_from_128_symbols = (128 + 1) // 2 + 1
assert max_decoded_positions_from_128_symbols == 65
all_nonzero_exceed_65 = all(cell["shortest_contiguous_span_bytes"] > 65 for cell in nonzero)
assert all_nonzero_exceed_65

print(json.dumps({
    "identity": "ASTRA",
    "verification": "read-only replay of the frozen prefix/suffix-mask certificate path",
    "result_sha256": EXPECTED_RESULT,
    "verified_ordered_contexts": 96,
    "verified_minimizing_intervals_and_representative_maps": 96,
    "certificate_counts": aggregate,
    "nonzero_streams": {
        "cells": len(nonzero),
        "minimum_span_range": nonzero_range,
        "all_minimum_spans_exceed_65": all_nonzero_exceed_65,
    },
    "zero_streams": {
        "cells": len(zero),
        "minimum_span": 0,
        "minimizing_empty_intervals_per_cell": N + 1,
        "mapping_model": "arbitrary noninjective",
    },
    "contiguous_128_hex_symbols": {
        "maximum_intersected_decoded_byte_positions": max_decoded_positions_from_128_symbols,
        "consequence": (
            "Within the frozen OFB stream, A105, and arbitrary fixed-map assumptions, one contiguous "
            "128-symbol region is shorter than every nonzero-stream necessary byte span."
        ),
    },
    "crypto_reconstructed": False,
    "compiled_binary_used": False,
}, indent=2, sort_keys=True))
